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
from pathlib import Path
from string import Template
from typing import Optional

import requests

from .models import DevinSession, PackageFinding
from .utils import with_retries

log = logging.getLogger(__name__)

DEVIN_API = "https://api.devin.ai/v3"


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


@with_retries(max_attempts=3, base_delay=10)
def create_session(
    finding: PackageFinding,
    issue_url: str,
    repo: str,
    devin_api_key: str,
    devin_org_id: str,
) -> str:
    """Start a Devin session to fix a vulnerability. Returns session_id."""
    prompt = _build_prompt(finding, issue_url, repo)

    payload = {
        "prompt": prompt,
    }

    resp = requests.post(
        f"{DEVIN_API}/organizations/{devin_org_id}/sessions",
        headers=_headers(devin_api_key),
        json=payload,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    session_id: str = data["session_id"]
    session_url: str = data.get("url", "")
    log.info(
        "Started Devin session %s for %s/%s | %s",
        session_id, finding.ecosystem, finding.package_name, session_url,
    )
    return session_id


def get_session(session_id: str, devin_api_key: str, devin_org_id: str) -> DevinSession:
    """Fetch current state of a Devin session."""
    resp = requests.get(
        f"{DEVIN_API}/organizations/{devin_org_id}/sessions/{session_id}",
        headers=_headers(devin_api_key),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    # v3 returns pull_requests as an array of {pr_url, pr_state} objects
    pr_url: Optional[str] = None
    pull_requests = data.get("pull_requests") or []
    if isinstance(pull_requests, list) and pull_requests:
        pr_url = pull_requests[0].get("pr_url") or pull_requests[0].get("url")

    status: str = data.get("status", "running")

    return DevinSession(
        session_id=data["session_id"],
        status=status,
        status_enum=status,  # type: ignore[arg-type]
        pull_request_url=pr_url,
        structured_output=None,
        updated_at=data.get("updated_at", ""),
    )


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(finding: PackageFinding, issue_url: str, repo: str) -> str:
    prompts_dir = Path(__file__).parent / "prompts"
    if finding.ecosystem == "pip":
        template = (prompts_dir / "python_upgrade.txt").read_text(encoding="utf-8")
    else:
        template = (prompts_dir / "npm_upgrade.txt").read_text(encoding="utf-8")

    description = finding.records[0].description if finding.records else ""
    cve_ids = ", ".join(finding.all_cve_ids) if finding.all_cve_ids else "advisory"

    # Use string.Template ($var syntax) so literal braces in code examples
    # inside the template are never misinterpreted as format placeholders.
    return Template(template).safe_substitute(
        package_name=finding.package_name,
        installed_version=finding.installed_version,
        fixed_version=finding.fixed_version or "latest",
        cve_ids=cve_ids,
        max_severity=finding.max_severity,
        description=description,
        issue_url=issue_url,
        repo=repo,
    )
