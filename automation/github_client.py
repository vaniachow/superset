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

import requests

from .models import PackageFinding
from .utils import with_retries

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
ISSUE_LABELS = ["security", "dependencies", "automated"]


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


@with_retries(max_attempts=3, base_delay=10)
def create_issue(finding: PackageFinding, repo: str, github_token: str) -> int:
    """Create a GitHub issue for a PackageFinding. Returns the issue number."""
    title = _render_title(finding)
    body = _render_body(finding)
    resp = requests.post(
        f"{GITHUB_API}/repos/{repo}/issues",
        headers=_headers(github_token),
        json={"title": title, "body": body, "labels": ISSUE_LABELS},
        timeout=30,
    )
    resp.raise_for_status()
    number: int = resp.json()["number"]
    log.info("Created issue #%d: %s", number, title)
    return number


@with_retries(max_attempts=3, base_delay=10)
def add_issue_comment(issue_number: int, repo: str, github_token: str, body: str) -> None:
    resp = requests.post(
        f"{GITHUB_API}/repos/{repo}/issues/{issue_number}/comments",
        headers=_headers(github_token),
        json={"body": body},
        timeout=30,
    )
    resp.raise_for_status()
    log.info("Commented on issue #%d", issue_number)


@with_retries(max_attempts=3, base_delay=10)
def close_issue(issue_number: int, repo: str, github_token: str) -> None:
    resp = requests.patch(
        f"{GITHUB_API}/repos/{repo}/issues/{issue_number}",
        headers=_headers(github_token),
        json={"state": "closed", "state_reason": "completed"},
        timeout=30,
    )
    resp.raise_for_status()
    log.info("Closed issue #%d", issue_number)


# ── Issue templates ───────────────────────────────────────────────────────────

def _render_title(finding: PackageFinding) -> str:
    cves = finding.all_cve_ids
    if cves:
        display = ", ".join(cves[:3])
        suffix = f" (+{len(cves) - 3} more)" if len(cves) > 3 else ""
        return f"[Security] {finding.ecosystem}/{finding.package_name}: {display}{suffix}"
    return f"[Security] {finding.ecosystem}/{finding.package_name}: vulnerability found"


def _render_body(finding: PackageFinding) -> str:
    severity_badge = f"`{finding.max_severity}`"
    fix_line = (
        f"`{finding.fixed_version}`"
        if finding.fixed_version
        else "_no fix available yet — monitor for upstream release_"
    )

    rows = []
    for r in finding.records:
        cve = r.cve_ids[0] if r.cve_ids else (r.aliases[0] if r.aliases else "advisory")
        rows.append(f"| `{cve}` | `{r.severity}` | {r.description or '_no description_'} |")
    cve_table = "\n".join(rows) if rows else "_No individual CVE details available._"

    return f"""## Vulnerability Report

| Field | Value |
|---|---|
| **Package** | `{finding.package_name}` ({finding.ecosystem}) |
| **Installed version** | `{finding.installed_version}` |
| **Recommended fix** | {fix_line} |
| **Max severity** | {severity_badge} |

### CVE Details

| CVE ID | Severity | Description |
|---|---|---|
{cve_table}

### Remediation Plan

This issue was opened automatically by the CVE-remediation pipeline.
A Devin session will be started shortly to:
1. Update the dependency version in the appropriate manifest
2. Recompile pinned requirements
3. Run tests to confirm no breakage
4. Open a pull request

_Do not close this issue manually — it will be closed automatically when a fix PR is merged._

---
*Opened by the automated CVE-remediation pipeline · Labels: security, dependencies, automated*
"""
