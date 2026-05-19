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


def _make_finding(pkg: str = "urllib3", eco: str = "pip") -> PackageFinding:
    record = CveRecord(
        package_name=pkg,
        ecosystem=eco,
        installed_version="2.5.0",
        fixed_version="2.6.3",
        cve_ids=["CVE-2026-21441"],
        severity="HIGH",
        description="Decompression bomb bypass",
        aliases=["GHSA-xxxx"],
    )
    return PackageFinding(
        package_name=pkg,
        ecosystem=eco,
        installed_version="2.5.0",
        fixed_version="2.6.3",
        records=[record],
    )


class TestCreateIssue:
    def test_posts_to_github_api(self):
        from automation.github_client import create_issue

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"number": 99}

        with patch("requests.post", return_value=mock_resp) as mock_post:
            number = create_issue(_make_finding(), "apache/superset", "token")

        assert number == 99
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "apache/superset" in call_kwargs[0][0]  # URL

    def test_includes_required_labels(self):
        from automation.github_client import create_issue

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"number": 1}

        with patch("requests.post", return_value=mock_resp) as mock_post:
            create_issue(_make_finding(), "apache/superset", "token")

        payload = mock_post.call_args[1]["json"]
        assert "security" in payload["labels"]
        assert "dependencies" in payload["labels"]
        assert "automated" in payload["labels"]

    def test_title_includes_package_and_cve(self):
        from automation.github_client import create_issue, _render_title

        finding = _make_finding()
        title = _render_title(finding)
        assert "urllib3" in title
        assert "CVE-2026-21441" in title
        assert "[Security]" in title

    def test_body_includes_severity_and_fix_version(self):
        from automation.github_client import _render_body

        finding = _make_finding()
        body = _render_body(finding)
        assert "HIGH" in body
        assert "2.6.3" in body
        assert "urllib3" in body

    def test_npm_finding_title(self):
        from automation.github_client import _render_title

        finding = _make_finding(pkg="lodash", eco="npm")
        title = _render_title(finding)
        assert "npm/lodash" in title


class TestAddIssueComment:
    def test_posts_comment(self):
        from automation.github_client import add_issue_comment

        mock_resp = MagicMock()
        with patch("requests.post", return_value=mock_resp) as mock_post:
            add_issue_comment(42, "apache/superset", "token", "hello")

        assert "42" in mock_post.call_args[0][0]  # issue number in URL
        assert mock_post.call_args[1]["json"]["body"] == "hello"
