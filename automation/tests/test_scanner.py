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
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _mock_result(stdout: str, returncode: int = 1) -> MagicMock:
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout = stdout
    m.returncode = returncode
    m.stderr = ""
    return m


class TestRunPipAudit:
    def test_parses_vulnerability(self, tmp_path):
        req_file = tmp_path / "requirements" / "base.txt"
        req_file.parent.mkdir()
        req_file.write_text("urllib3==2.5.0\n")

        fixture = (FIXTURES / "pip_audit_sample.json").read_text()
        with patch("subprocess.run", return_value=_mock_result(fixture)):
            from automation.scanner import run_pip_audit
            records = run_pip_audit(tmp_path)

        assert len(records) == 2
        urllib3 = next(r for r in records if r.package_name == "urllib3")
        assert urllib3.ecosystem == "pip"
        assert urllib3.installed_version == "2.5.0"
        assert urllib3.fixed_version == "2.6.3"
        assert "CVE-2026-21441" in urllib3.cve_ids
        assert urllib3.severity == "HIGH"

    def test_extracts_cve_from_aliases(self, tmp_path):
        req_file = tmp_path / "requirements" / "base.txt"
        req_file.parent.mkdir()
        req_file.write_text("urllib3==2.5.0\n")

        fixture = (FIXTURES / "pip_audit_sample.json").read_text()
        with patch("subprocess.run", return_value=_mock_result(fixture)):
            from automation.scanner import run_pip_audit
            records = run_pip_audit(tmp_path)

        werkzeug = next(r for r in records if r.package_name == "werkzeug")
        # CVE-2026-27199 is the primary ID, not in aliases
        assert "CVE-2026-27199" in werkzeug.cve_ids

    def test_empty_vulns_skipped(self, tmp_path):
        req_file = tmp_path / "requirements" / "base.txt"
        req_file.parent.mkdir()
        req_file.write_text("requests==2.32.0\n")

        fixture = (FIXTURES / "pip_audit_sample.json").read_text()
        with patch("subprocess.run", return_value=_mock_result(fixture)):
            from automation.scanner import run_pip_audit
            records = run_pip_audit(tmp_path)

        assert all(r.package_name != "requests" for r in records)

    def test_returns_empty_when_no_req_file(self, tmp_path):
        from automation.scanner import run_pip_audit
        records = run_pip_audit(tmp_path)
        assert records == []

    def test_returns_empty_on_json_error(self, tmp_path):
        req_file = tmp_path / "requirements" / "base.txt"
        req_file.parent.mkdir()
        req_file.write_text("foo==1.0\n")

        with patch("subprocess.run", return_value=_mock_result("not-json")):
            from automation.scanner import run_pip_audit
            records = run_pip_audit(tmp_path)

        assert records == []


class TestRunNpmAudit:
    def test_parses_vulnerability(self, tmp_path):
        frontend = tmp_path / "superset-frontend"
        frontend.mkdir()

        fixture = (FIXTURES / "npm_audit_sample.json").read_text()
        with patch("subprocess.run", return_value=_mock_result(fixture)):
            from automation.scanner import run_npm_audit
            records = run_npm_audit(tmp_path)

        assert len(records) == 2
        lodash = next(r for r in records if r.package_name == "lodash")
        assert lodash.ecosystem == "npm"
        assert lodash.fixed_version == "4.17.21"
        assert lodash.severity == "HIGH"

    def test_extracts_cve_from_advisory_url(self, tmp_path):
        frontend = tmp_path / "superset-frontend"
        frontend.mkdir()

        fixture = (FIXTURES / "npm_audit_sample.json").read_text()
        with patch("subprocess.run", return_value=_mock_result(fixture)):
            from automation.scanner import run_npm_audit
            records = run_npm_audit(tmp_path)

        semver = next(r for r in records if r.package_name == "semver")
        assert "CVE-2022-25883" in semver.cve_ids

    def test_returns_empty_when_no_frontend_dir(self, tmp_path):
        from automation.scanner import run_npm_audit
        records = run_npm_audit(tmp_path)
        assert records == []


class TestGroupByPackage:
    def test_groups_multiple_cves_per_package(self):
        from automation.models import CveRecord
        from automation.scanner import group_by_package

        r1 = CveRecord("urllib3", "pip", "2.5.0", "2.6.3", ["CVE-A"], "HIGH", "", [])
        r2 = CveRecord("urllib3", "pip", "2.5.0", "2.7.0", ["CVE-B"], "MEDIUM", "", [])
        r3 = CveRecord("werkzeug", "pip", "3.1.5", "3.1.6", ["CVE-C"], "LOW", "", [])

        findings = group_by_package([r1, r2, r3])
        assert len(findings) == 2

        urllib3 = next(f for f in findings if f.package_name == "urllib3")
        assert len(urllib3.records) == 2
        assert urllib3.fixed_version == "2.7.0"  # highest version wins
        assert urllib3.max_severity == "HIGH"

    def test_separates_pip_and_npm(self):
        from automation.models import CveRecord
        from automation.scanner import group_by_package

        pip_r = CveRecord("semver", "pip", "1.0", "2.0", ["CVE-X"], "HIGH", "", [])
        npm_r = CveRecord("semver", "npm", "1.0", "2.0", ["CVE-X"], "HIGH", "", [])

        findings = group_by_package([pip_r, npm_r])
        assert len(findings) == 2
        ecosystems = {f.ecosystem for f in findings}
        assert ecosystems == {"pip", "npm"}
