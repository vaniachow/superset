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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .devin_client import create_session
from .github_client import create_issue
from .models import ScanState, SerializedFinding
from .reporter import Reporter
from .scanner import group_by_package, run_npm_audit, run_pip_audit
from .state_manager import compute_new_findings, load_state, save_state

log = logging.getLogger(__name__)


def run_pipeline(
    repo_root: Path,
    github_repo: str,
    github_token: str,
    devin_api_key: Optional[str],
    devin_org_id: Optional[str],
    gist_id: Optional[str],
    gist_token: Optional[str] = None,
    dry_run: bool = False,
) -> ScanState:
    """
    Main pipeline:
      1. Load previous state
      2. Scan (pip-audit + npm audit)
      3. Diff against previous state
      4. For each new finding: create GitHub issue + start Devin session
      5. Persist updated state
      6. Print observability summary
    """
    reporter = Reporter()

    # ── 1. Load state ─────────────────────────────────────────────────────────
    state = load_state(gist_id, gist_token or github_token)
    reporter.log_event("state_loaded", {
        "previous_fingerprints": len(state.fingerprints),
        "open_sessions": len(state.session_map),
    })

    # ── 2. Scan ───────────────────────────────────────────────────────────────
    pip_records = []
    npm_records = []

    try:
        pip_records = run_pip_audit(repo_root)
    except Exception as exc:
        log.error("pip-audit scan failed: %s", exc)
        reporter.log_event("scan_error", {"ecosystem": "pip", "error": str(exc)})

    try:
        npm_records = run_npm_audit(repo_root)
    except Exception as exc:
        log.error("npm audit scan failed: %s", exc)
        reporter.log_event("scan_error", {"ecosystem": "npm", "error": str(exc)})

    all_records = pip_records + npm_records
    reporter.log_event("scan_complete", {
        "pip_findings": len(pip_records),
        "npm_findings": len(npm_records),
        "total": len(all_records),
    })

    # ── 3. Diff ───────────────────────────────────────────────────────────────
    new_records = compute_new_findings(all_records, state)
    reporter.log_event("diff_complete", {
        "new_findings": len(new_records),
        "known_findings": len(all_records) - len(new_records),
    })

    if not new_records:
        log.info("No new CVE findings. Nothing to do.")
        state.scan_timestamp = datetime.now(timezone.utc).isoformat()
        if not dry_run:
            save_state(state, gist_id, gist_token or github_token)
        reporter.print_summary(state)
        return state

    # ── 4. Create issues and Devin sessions ───────────────────────────────────
    new_findings = group_by_package(new_records)
    log.info("Processing %d new package findings", len(new_findings))

    # Track fingerprints that failed issue creation so they are NOT persisted
    # as "known" — they must be retried on the next run.
    failed_fingerprints: set[str] = set()

    for finding in new_findings:
        fps = finding.fingerprints

        # Skip if we already have an open issue for all fingerprints in this finding
        if all(fp in state.issue_map for fp in fps):
            log.info("Issue already exists for all CVEs in %s/%s — skipping",
                     finding.ecosystem, finding.package_name)
            continue

        if dry_run:
            log.info(
                "[DRY RUN] Would create issue for %s/%s (%s)",
                finding.ecosystem, finding.package_name, ", ".join(finding.all_cve_ids),
            )
            reporter.log_event("dry_run_finding", {
                "package": finding.package_name,
                "ecosystem": finding.ecosystem,
                "cve_ids": finding.all_cve_ids,
                "severity": finding.max_severity,
            })
            continue

        # Create GitHub issue
        try:
            issue_number = create_issue(finding, github_repo, github_token)
            issue_url = f"https://github.com/{github_repo}/issues/{issue_number}"
            for fp in fps:
                state.issue_map[fp] = issue_number
            reporter.log_event("issue_created", {
                "package": finding.package_name,
                "ecosystem": finding.ecosystem,
                "issue_number": issue_number,
                "issue_url": issue_url,
                "cve_ids": finding.all_cve_ids,
                "severity": finding.max_severity,
            })
        except Exception as exc:
            log.error("Failed to create issue for %s/%s: %s",
                      finding.ecosystem, finding.package_name, exc)
            reporter.log_event("issue_error", {
                "package": finding.package_name,
                "ecosystem": finding.ecosystem,
                "error": str(exc),
            })
            # Mark these fingerprints as failed so they are excluded from the
            # persisted fingerprint set and retried on the next run.
            failed_fingerprints.update(fps)
            continue

        # Start Devin session
        if devin_api_key and devin_org_id:
            try:
                session_id = create_session(finding, issue_url, github_repo, devin_api_key, devin_org_id)
                for fp in fps:
                    state.session_map[fp] = session_id
                    state.session_attempts[fp] = state.session_attempts.get(fp, 0) + 1
                # Persist the finding so monitor can requeue expired sessions
                serialized = SerializedFinding(
                    package_name=finding.package_name,
                    ecosystem=finding.ecosystem,
                    installed_version=finding.installed_version,
                    fixed_version=finding.fixed_version,
                    all_cve_ids=finding.all_cve_ids,
                    max_severity=finding.max_severity,
                    description=finding.records[0].description if finding.records else "",
                )
                for fp in fps:
                    state.findings[fp] = serialized
                reporter.log_event("devin_session_started", {
                    "package": finding.package_name,
                    "ecosystem": finding.ecosystem,
                    "session_id": session_id,
                    "issue_number": issue_number,
                    "devin_url": f"https://app.devin.ai/sessions/{session_id}",
                })
            except Exception as exc:
                log.error("Failed to start Devin session for %s/%s: %s",
                          finding.ecosystem, finding.package_name, exc)
                reporter.log_event("devin_session_error", {
                    "package": finding.package_name,
                    "ecosystem": finding.ecosystem,
                    "error": str(exc),
                    "issue_number": issue_number,
                })
        else:
            log.warning(
                "DEVIN_API_KEY or DEVIN_ORG_ID not set — skipping session for %s/%s",
                finding.ecosystem, finding.package_name,
            )

    # ── 5. Persist state ──────────────────────────────────────────────────────
    # Exclude fingerprints whose issue creation failed — they must be retried.
    state.fingerprints = list(
        {r.fingerprint for r in all_records} - failed_fingerprints
    )
    state.scan_timestamp = datetime.now(timezone.utc).isoformat()

    if not dry_run:
        save_state(state, gist_id, gist_token or github_token)

    # ── 6. Summary ────────────────────────────────────────────────────────────
    reporter.print_summary(state)
    return state
