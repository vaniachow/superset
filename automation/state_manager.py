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
import logging
from dataclasses import asdict, fields
from datetime import datetime, timezone
from typing import Optional

import requests

from .models import CveRecord, ScanState, SerializedFinding

log = logging.getLogger(__name__)

GIST_FILENAME = "cve_scan_state.json"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _empty_state() -> ScanState:
    return ScanState(
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        fingerprints=[],
        issue_map={},
        session_map={},
        session_attempts={},
    )


def _state_to_dict(state: ScanState) -> dict:
    return asdict(state)


def _state_from_dict(data: dict) -> ScanState:
    known_fields = {f.name for f in fields(ScanState)}
    kwargs = {k: v for k, v in data.items() if k in known_fields}
    # Deserialize nested SerializedFinding dicts
    raw_findings = kwargs.get("findings", {})
    if isinstance(raw_findings, dict):
        sf_fields = {f.name for f in fields(SerializedFinding)}
        kwargs["findings"] = {
            fp: SerializedFinding(**{k: v for k, v in sf.items() if k in sf_fields})
            for fp, sf in raw_findings.items()
            if isinstance(sf, dict)
        }
    return ScanState(**kwargs)


# ── Gist persistence ──────────────────────────────────────────────────────────

def _gist_headers(github_token: str) -> dict:
    return {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def load_state_from_gist(gist_id: str, github_token: str) -> ScanState:
    resp = requests.get(
        f"https://api.github.com/gists/{gist_id}",
        headers=_gist_headers(github_token),
        timeout=30,
    )
    resp.raise_for_status()
    content = resp.json()["files"][GIST_FILENAME]["content"]
    return _state_from_dict(json.loads(content))


def save_state_to_gist(state: ScanState, gist_id: str, github_token: str) -> None:
    payload = {
        "files": {
            GIST_FILENAME: {"content": json.dumps(_state_to_dict(state), indent=2)}
        }
    }
    resp = requests.patch(
        f"https://api.github.com/gists/{gist_id}",
        headers=_gist_headers(github_token),
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()


# ── Public interface ──────────────────────────────────────────────────────────

def load_state(gist_id: Optional[str], github_token: Optional[str]) -> ScanState:
    """Load state from Gist. Falls back to empty state on any error."""
    if gist_id and github_token:
        try:
            state = load_state_from_gist(gist_id, github_token)
            log.info("Loaded state from Gist %s (%d fingerprints)", gist_id, len(state.fingerprints))
            return state
        except Exception as exc:
            log.warning("Could not load state from Gist (%s) — starting fresh", exc)
    else:
        log.info("SCAN_STATE_GIST_ID not set — starting from empty state")
    return _empty_state()


def save_state(state: ScanState, gist_id: Optional[str], github_token: Optional[str]) -> None:
    """Persist state to Gist. Logs on failure but does not raise."""
    if gist_id and github_token:
        try:
            save_state_to_gist(state, gist_id, github_token)
            log.info("State saved to Gist %s", gist_id)
        except Exception as exc:
            log.error("Failed to save state to Gist: %s", exc)
    else:
        log.warning("State not persisted (SCAN_STATE_GIST_ID unset)")


# ── Diff ──────────────────────────────────────────────────────────────────────

def compute_new_findings(
    current_records: list[CveRecord],
    previous_state: ScanState,
) -> list[CveRecord]:
    """Return only records whose fingerprint was not in the previous scan."""
    known = set(previous_state.fingerprints)
    new = [r for r in current_records if r.fingerprint not in known]
    log.info(
        "Diff: %d total findings, %d known, %d new",
        len(current_records), len(known), len(new),
    )
    return new
