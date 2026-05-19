# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from automation.models import CveRecord, ScanState


def _make_record(pkg: str, cve: str, eco: str = "pip") -> CveRecord:
    return CveRecord(pkg, eco, "1.0.0", "2.0.0", [cve], "HIGH", "desc", [])


def _make_state(fingerprints: list[str]) -> ScanState:
    return ScanState(
        scan_timestamp="2026-05-18T06:00:00+00:00",
        fingerprints=fingerprints,
        issue_map={},
        session_map={},
        session_attempts={},
    )


class TestComputeNewFindings:
    def test_returns_all_when_state_empty(self):
        from automation.state_manager import compute_new_findings

        record = _make_record("urllib3", "CVE-2026-21441")
        state = _make_state([])
        result = compute_new_findings([record], state)
        assert len(result) == 1

    def test_excludes_known_fingerprint(self):
        from automation.state_manager import compute_new_findings

        record = _make_record("urllib3", "CVE-2026-21441")
        state = _make_state([record.fingerprint])
        result = compute_new_findings([record], state)
        assert result == []

    def test_includes_new_with_existing_known(self):
        from automation.state_manager import compute_new_findings

        old_record = _make_record("urllib3", "CVE-2026-21441")
        new_record = _make_record("werkzeug", "CVE-2026-27199")
        state = _make_state([old_record.fingerprint])
        result = compute_new_findings([old_record, new_record], state)
        assert len(result) == 1
        assert result[0].package_name == "werkzeug"

    def test_handles_empty_records(self):
        from automation.state_manager import compute_new_findings

        state = _make_state(["pip:urllib3:CVE-X"])
        result = compute_new_findings([], state)
        assert result == []


class TestFingerprint:
    def test_fingerprint_is_stable(self):
        r1 = _make_record("urllib3", "CVE-2026-21441")
        r2 = _make_record("urllib3", "CVE-2026-21441")
        assert r1.fingerprint == r2.fingerprint

    def test_fingerprint_differs_by_ecosystem(self):
        pip_r = _make_record("semver", "CVE-X", eco="pip")
        npm_r = _make_record("semver", "CVE-X", eco="npm")
        assert pip_r.fingerprint != npm_r.fingerprint

    def test_fingerprint_differs_by_cve(self):
        r1 = _make_record("urllib3", "CVE-A")
        r2 = _make_record("urllib3", "CVE-B")
        assert r1.fingerprint != r2.fingerprint

    def test_fingerprint_format(self):
        r = _make_record("urllib3", "CVE-2026-21441")
        assert r.fingerprint == "pip:urllib3:CVE-2026-21441"


class TestLoadState:
    def test_returns_empty_state_when_no_gist_id(self):
        from automation.state_manager import load_state

        state = load_state(None, None)
        assert state.fingerprints == []
        assert state.issue_map == {}

    def test_returns_empty_state_on_gist_error(self):
        from automation.state_manager import load_state

        with patch("automation.state_manager.load_state_from_gist", side_effect=Exception("network error")):
            state = load_state("fake-gist-id", "fake-token")

        assert state.fingerprints == []

    def test_loads_from_gist_when_configured(self):
        from automation.state_manager import load_state

        expected = ScanState(
            scan_timestamp="2026-05-17T00:00:00+00:00",
            fingerprints=["pip:urllib3:CVE-2026-21441"],
            issue_map={"pip:urllib3:CVE-2026-21441": 42},
            session_map={},
            session_attempts={},
        )
        with patch("automation.state_manager.load_state_from_gist", return_value=expected):
            state = load_state("gist-id", "token")

        assert state.fingerprints == ["pip:urllib3:CVE-2026-21441"]
        assert state.issue_map == {"pip:urllib3:CVE-2026-21441": 42}
