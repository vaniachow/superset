# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import logging
from typing import Optional

from .devin_client import create_session as devin_create_session, get_session
from .github_client import add_issue_comment, close_issue
from .models import CveRecord, PackageFinding, ScanState, SerializedFinding
from .reporter import Reporter
from .state_manager import save_state

log = logging.getLogger(__name__)

MAX_RETRIES = 3


def _rebuild_findings(state: ScanState) -> dict[str, PackageFinding]:
    """Reconstruct PackageFindings from serialized state for requeue logic."""
    result: dict[str, PackageFinding] = {}
    for fp, sf in state.findings.items():
        # Create a minimal CveRecord from the serialized form
        record = CveRecord(
            package_name=sf.package_name,
            ecosystem=sf.ecosystem,  # type: ignore[arg-type]
            installed_version=sf.installed_version,
            fixed_version=sf.fixed_version,
            cve_ids=sf.all_cve_ids,
            severity=sf.max_severity,  # type: ignore[arg-type]
            description=sf.description,
            aliases=[],
        )
        result[fp] = PackageFinding(
            package_name=sf.package_name,
            ecosystem=sf.ecosystem,  # type: ignore[arg-type]
            installed_version=sf.installed_version,
            fixed_version=sf.fixed_version,
            records=[record],
        )
    return result


def poll_sessions(
    state: ScanState,
    github_repo: str,
    github_token: str,
    devin_api_key: str,
    gist_id: Optional[str],
) -> None:
    """
    Poll all tracked Devin sessions and update GitHub issues with outcomes.

    Session status handling:
      - finished + PR URL  → comment PR link on issue, close issue
      - finished + no PR   → comment warning, leave issue open
      - blocked            → comment blocking message, leave open for human
      - expired, attempts < MAX_RETRIES → requeue new session, increment attempt count
      - expired, attempts >= MAX_RETRIES → comment max-retries reached, leave open
      - working/resumed    → skip (still in progress)
    """
    reporter = Reporter()
    findings_by_fp = _rebuild_findings(state)

    # Collect unique session_ids to avoid polling the same session multiple times
    # when multiple fingerprints map to the same session
    seen_sessions: dict[str, list[str]] = {}  # session_id -> [fingerprints]
    for fp, session_id in state.session_map.items():
        seen_sessions.setdefault(session_id, []).append(fp)

    if not seen_sessions:
        log.info("No active sessions to monitor")
        return

    log.info("Polling %d Devin sessions", len(seen_sessions))

    for session_id, fps in seen_sessions.items():
        # Use the first fingerprint to look up the issue number
        issue_number = next(
            (state.issue_map[fp] for fp in fps if fp in state.issue_map), None
        )
        if issue_number is None:
            log.warning("No issue number found for session %s — skipping", session_id)
            continue

        try:
            session = get_session(session_id, devin_api_key)
        except Exception as exc:
            log.error("Failed to poll session %s: %s", session_id, exc)
            reporter.log_event("session_poll_error", {
                "session_id": session_id,
                "error": str(exc),
            })
            continue

        reporter.log_event("session_polled", {
            "session_id": session_id,
            "status_enum": session.status_enum,
            "issue_number": issue_number,
        })

        status = session.status_enum

        if status == "finished":
            pr_url = session.pull_request_url
            if pr_url:
                comment = (
                    f"Devin session [`{session_id}`](https://app.devin.ai/sessions/{session_id}) "
                    f"has **finished** and created a pull request:\n\n"
                    f"**{pr_url}**\n\n"
                    f"Please review and merge the PR. Close this issue manually once merged."
                )
                add_issue_comment(issue_number, github_repo, github_token, comment)
                # Do NOT close the issue here — the PR still needs review and merge.
                # Closing prematurely would hide the vulnerability if the PR is rejected.
                reporter.log_event("session_finished", {
                    "session_id": session_id,
                    "pr_url": pr_url,
                    "issue_number": issue_number,
                })
            else:
                # Finished but no PR — needs human review
                structured = session.structured_output or {}
                detail = structured.get("changes_summary", "No summary available.")
                comment = (
                    f"Devin session [`{session_id}`](https://app.devin.ai/sessions/{session_id}) "
                    f"has **finished** but no pull request was found.\n\n"
                    f"**Details from Devin**: {detail}\n\n"
                    f"Please review the session and open a PR manually if needed."
                )
                add_issue_comment(issue_number, github_repo, github_token, comment)
                reporter.log_event("session_finished_no_pr", {
                    "session_id": session_id,
                    "issue_number": issue_number,
                })

        elif status == "blocked":
            comment = (
                f"Devin session [`{session_id}`](https://app.devin.ai/sessions/{session_id}) "
                f"is **blocked** and needs human intervention.\n\n"
                f"**Status**: `{session.status}`\n\n"
                f"Please visit the Devin session to unblock it."
            )
            add_issue_comment(issue_number, github_repo, github_token, comment)
            reporter.log_event("session_blocked", {
                "session_id": session_id,
                "reason": session.status,
                "issue_number": issue_number,
            })

        elif status == "expired":
            # Use max attempts across all fingerprints for this session
            attempts = max(
                (state.session_attempts.get(fp, 1) for fp in fps),
                default=1,
            )
            if attempts < MAX_RETRIES:
                # Requeue: find any PackageFinding for these fingerprints
                finding = next(
                    (findings_by_fp[fp] for fp in fps if fp in findings_by_fp), None
                )
                if finding:
                    issue_url = f"https://github.com/{github_repo}/issues/{issue_number}"
                    try:
                        new_session_id = devin_create_session(
                            finding, issue_url, github_repo, devin_api_key
                        )
                        for fp in fps:
                            state.session_map[fp] = new_session_id
                            state.session_attempts[fp] = attempts + 1
                        comment = (
                            f"Devin session `{session_id}` expired. "
                            f"Retrying (attempt {attempts + 1}/{MAX_RETRIES}).\n\n"
                            f"New session: [`{new_session_id}`](https://app.devin.ai/sessions/{new_session_id})"
                        )
                        add_issue_comment(issue_number, github_repo, github_token, comment)
                        reporter.log_event("session_requeued", {
                            "old_session_id": session_id,
                            "new_session_id": new_session_id,
                            "attempt": attempts + 1,
                            "issue_number": issue_number,
                        })
                    except Exception as exc:
                        log.error("Failed to requeue session for issue #%d: %s", issue_number, exc)
                else:
                    log.warning("Cannot requeue session %s — no PackageFinding in state", session_id)
            else:
                comment = (
                    f"Devin session `{session_id}` expired and the maximum number of retries "
                    f"({MAX_RETRIES}) has been reached.\n\n"
                    f"This issue requires **manual remediation**. Please fix the vulnerability "
                    f"described above and open a PR manually."
                )
                add_issue_comment(issue_number, github_repo, github_token, comment)
                reporter.log_event("session_max_retries", {
                    "session_id": session_id,
                    "issue_number": issue_number,
                    "attempts": attempts,
                })

        else:
            # working, resumed, suspend_requested, etc. — still in progress
            log.info("Session %s status=%s — still in progress", session_id, status)

    save_state(state, gist_id, github_token)
    reporter.print_summary(state)
