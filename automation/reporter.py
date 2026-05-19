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

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from .models import ScanState


class Reporter:
    """
    Observability layer for the CVE remediation pipeline.

    Every event is written as a structured JSON line to stderr.
    This format is compatible with GitHub Actions logs, Datadog, Splunk,
    and any line-based log aggregator.

    At the end of a run, print_summary() writes a Markdown table to
    $GITHUB_STEP_SUMMARY (visible as a tab on the Actions run page).
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def log_event(self, event_type: str, data: dict[str, Any]) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **data,
        }
        self._events.append(entry)
        print(json.dumps(entry), file=sys.stderr, flush=True)

    def _count(self, event_type: str) -> int:
        return sum(1 for e in self._events if e.get("event") == event_type)

    def _count_events_with_field(self, event_type: str, field: str) -> int:
        """Count events of event_type where field is present and truthy."""
        return sum(
            1 for e in self._events
            if e.get("event") == event_type and e.get(field)
        )

    def print_summary(self, state: ScanState) -> None:
        """Write Markdown run summary. Output goes to GITHUB_STEP_SUMMARY or stdout."""
        new_findings = self._count("issue_created")
        sessions_started = self._count("devin_session_started")
        sessions_finished = self._count("session_finished")
        prs_created = self._count_events_with_field("session_finished", "pr_url")
        sessions_blocked = self._count("session_blocked")
        sessions_requeued = self._count("session_requeued")
        sessions_maxretry = self._count("session_max_retries")
        scan_errors = self._count("scan_error")

        md = f"""## CVE Remediation Run Summary

| Metric | Value |
|---|---|
| Scan timestamp | `{state.scan_timestamp}` |
| Total tracked fingerprints | `{len(state.fingerprints)}` |
| New findings this run | `{new_findings}` |
| GitHub issues created | `{new_findings}` |
| Devin sessions started | `{sessions_started}` |
| Sessions finished | `{sessions_finished}` |
| Pull requests created | `{prs_created}` |
| Sessions blocked (need human) | `{sessions_blocked}` |
| Sessions requeued (expired) | `{sessions_requeued}` |
| Sessions at max retries | `{sessions_maxretry}` |
| Scan errors | `{scan_errors}` |

"""
        if sessions_started > 0:
            md += "### Active Sessions\n\n"
            md += "| Package | Ecosystem | Session ID | Issue |\n"
            md += "|---|---|---|---|\n"
            for e in self._events:
                if e.get("event") == "devin_session_started":
                    pkg = e.get("package", "")
                    eco = e.get("ecosystem", "")
                    sid = e.get("session_id", "")
                    issue = e.get("issue_number", "")
                    md += f"| `{pkg}` | `{eco}` | `{sid}` | #{issue} |\n"
            md += "\n"

        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as f:
                f.write(md)
        else:
            print(md)
