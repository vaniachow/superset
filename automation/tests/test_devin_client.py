# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automation.models import CveRecord, PackageFinding


def _make_pip_finding() -> PackageFinding:
    record = CveRecord(
        package_name="urllib3",
        ecosystem="pip",
        installed_version="2.5.0",
        fixed_version="2.6.3",
        cve_ids=["CVE-2026-21441"],
        severity="HIGH",
        description="Decompression bomb bypass on redirects",
        aliases=[],
    )
    return PackageFinding(
        package_name="urllib3",
        ecosystem="pip",
        installed_version="2.5.0",
        fixed_version="2.6.3",
        records=[record],
    )


def _make_npm_finding() -> PackageFinding:
    record = CveRecord(
        package_name="lodash",
        ecosystem="npm",
        installed_version="<4.17.21",
        fixed_version="4.17.21",
        cve_ids=[],
        severity="HIGH",
        description="Prototype pollution",
        aliases=["GHSA-xxxx"],
    )
    return PackageFinding(
        package_name="lodash",
        ecosystem="npm",
        installed_version="<4.17.21",
        fixed_version="4.17.21",
        records=[record],
    )


class TestCreateSession:
    def test_returns_session_id(self):
        from automation.devin_client import create_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "session_id": "ses_abc123",
            "url": "https://app.devin.ai/sessions/ses_abc123",
        }

        with patch("requests.post", return_value=mock_resp):
            session_id = create_session(
                _make_pip_finding(),
                "https://github.com/apache/superset/issues/1",
                "apache/superset",
                "apk_test_key",
            )

        assert session_id == "ses_abc123"

    def test_includes_cve_remediation_tag(self):
        from automation.devin_client import create_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "ses_xyz", "url": "https://app.devin.ai/sessions/ses_xyz"}

        with patch("requests.post", return_value=mock_resp) as mock_post:
            create_session(
                _make_pip_finding(),
                "https://github.com/apache/superset/issues/1",
                "apache/superset",
                "apk_test_key",
            )

        payload = mock_post.call_args[1]["json"]
        assert "cve-remediation" in payload["tags"]
        assert "pip" in payload["tags"]
        assert "urllib3" in payload["tags"]

    def test_includes_structured_output_schema(self):
        from automation.devin_client import create_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"session_id": "ses_xyz", "url": ""}

        with patch("requests.post", return_value=mock_resp) as mock_post:
            create_session(
                _make_pip_finding(),
                "https://github.com/apache/superset/issues/1",
                "apache/superset",
                "apk_test_key",
            )

        payload = mock_post.call_args[1]["json"]
        assert "structured_output_schema" in payload
        assert "pr_url" in payload["structured_output_schema"]["properties"]


class TestBuildPrompt:
    def test_python_prompt_contains_package_name(self):
        from automation.devin_client import _build_prompt

        prompt = _build_prompt(
            _make_pip_finding(),
            "https://github.com/apache/superset/issues/1",
            "apache/superset",
        )
        assert "urllib3" in prompt
        assert "2.6.3" in prompt
        assert "CVE-2026-21441" in prompt
        assert "requirements/base.in" in prompt

    def test_npm_prompt_contains_package_name(self):
        from automation.devin_client import _build_prompt

        prompt = _build_prompt(
            _make_npm_finding(),
            "https://github.com/apache/superset/issues/2",
            "apache/superset",
        )
        assert "lodash" in prompt
        assert "4.17.21" in prompt
        assert "overrides" in prompt

    def test_python_prompt_contains_compile_command(self):
        from automation.devin_client import _build_prompt

        prompt = _build_prompt(
            _make_pip_finding(),
            "https://github.com/apache/superset/issues/1",
            "apache/superset",
        )
        assert "uv-pip-compile.sh" in prompt

    def test_prompt_contains_issue_url(self):
        from automation.devin_client import _build_prompt

        issue_url = "https://github.com/apache/superset/issues/42"
        prompt = _build_prompt(_make_pip_finding(), issue_url, "apache/superset")
        assert issue_url in prompt


class TestGetSession:
    def test_parses_finished_with_pr(self):
        from automation.devin_client import get_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "session_id": "ses_abc",
            "status": "Session complete",
            "status_enum": "finished",
            "pull_request": {"url": "https://github.com/apache/superset/pull/999"},
            "structured_output": None,
            "updated_at": "2026-05-18T12:00:00Z",
        }

        with patch("requests.get", return_value=mock_resp):
            session = get_session("ses_abc", "apk_key")

        assert session.status_enum == "finished"
        assert session.pull_request_url == "https://github.com/apache/superset/pull/999"

    def test_parses_pr_from_structured_output(self):
        from automation.devin_client import get_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "session_id": "ses_abc",
            "status": "done",
            "status_enum": "finished",
            "pull_request": None,
            "structured_output": {"pr_url": "https://github.com/apache/superset/pull/888"},
            "updated_at": "2026-05-18T12:00:00Z",
        }

        with patch("requests.get", return_value=mock_resp):
            session = get_session("ses_abc", "apk_key")

        assert session.pull_request_url == "https://github.com/apache/superset/pull/888"
