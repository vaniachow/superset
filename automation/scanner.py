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
import subprocess
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .models import CveRecord, Ecosystem, PackageFinding, Severity

log = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
}


def _normalize_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.lower(), "UNKNOWN")


def run_pip_audit(repo_root: Path) -> list[CveRecord]:
    """
    Run pip-audit against requirements/base.txt and return normalized findings.

    pip-audit exits with code 1 when vulnerabilities are found — that is expected
    behaviour and is not treated as an error. A non-zero exit code that produces
    no parseable stdout is treated as a scan failure and returns an empty list.

    pip-audit --format json output structure (v2.7+):
      {
        "dependencies": [
          {
            "name": "urllib3",
            "version": "2.5.0",
            "vulns": [
              {
                "id": "PYSEC-2026-...",
                "aliases": ["CVE-2026-21441", "GHSA-xxxx"],
                "description": "...",
                "fix_versions": ["2.6.3"],
                "severity": "HIGH"
              }
            ]
          }
        ]
      }
    """
    req_file = repo_root / "requirements" / "base.txt"
    if not req_file.exists():
        log.warning("requirements/base.txt not found at %s — skipping pip scan", req_file)
        return []

    result = subprocess.run(
        [
            "pip-audit",
            "--format", "json",
            "--requirement", str(req_file),
            "--no-deps",
        ],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )

    stdout = result.stdout.strip()
    if not stdout:
        log.error("pip-audit produced no output (exit %d): %s", result.returncode, result.stderr[:500])
        return []

    try:
        data: dict[str, Any] = json.loads(stdout)
    except json.JSONDecodeError as exc:
        log.error("Failed to parse pip-audit output: %s", exc)
        return []

    records: list[CveRecord] = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            aliases: list[str] = vuln.get("aliases", [])
            # Primary ID may be PYSEC-*, CVE-*, or GHSA-*
            primary_id: str = vuln.get("id", "")
            # Collect all CVE IDs from primary + aliases
            cve_ids = [
                aid for aid in ([primary_id] + aliases)
                if aid.startswith("CVE-")
            ]
            fix_versions: list[str] = vuln.get("fix_versions", [])
            records.append(CveRecord(
                package_name=dep["name"],
                ecosystem="pip",
                installed_version=dep["version"],
                fixed_version=fix_versions[0] if fix_versions else None,
                cve_ids=cve_ids,
                severity=_normalize_severity(vuln.get("severity", "UNKNOWN")),
                description=vuln.get("description", "")[:500],
                aliases=aliases,
            ))

    log.info("pip-audit: %d vulnerable packages found", len({r.package_name for r in records}))
    return records


def run_npm_audit(repo_root: Path) -> list[CveRecord]:
    """
    Run npm audit in superset-frontend/ and return normalized findings.

    npm audit exits with code 1 when vulnerabilities are found — expected.

    npm audit --json output structure (npm v7+):
      {
        "vulnerabilities": {
          "lodash": {
            "name": "lodash",
            "severity": "high",
            "via": [
              {
                "source": 1234567,
                "url": "https://github.com/advisories/GHSA-...",
                "title": "Prototype pollution",
                "severity": "high"
              }
            ],
            "range": "<4.17.21",
            "fixAvailable": {"name": "lodash", "version": "4.17.21"}
          }
        }
      }
    """
    frontend_dir = repo_root / "superset-frontend"
    if not frontend_dir.exists():
        log.warning("superset-frontend/ not found — skipping npm scan")
        return []

    result = subprocess.run(
        ["npm", "audit", "--json"],
        capture_output=True,
        text=True,
        cwd=frontend_dir,
    )

    stdout = result.stdout.strip()
    if not stdout:
        log.error("npm audit produced no output (exit %d): %s", result.returncode, result.stderr[:500])
        return []

    try:
        data: dict[str, Any] = json.loads(stdout)
    except json.JSONDecodeError as exc:
        log.error("Failed to parse npm audit output: %s", exc)
        return []

    records: list[CveRecord] = []
    for pkg_name, vuln in data.get("vulnerabilities", {}).items():
        cve_ids: list[str] = []
        aliases: list[str] = []
        description = ""
        severity = _normalize_severity(vuln.get("severity", "UNKNOWN"))

        for via_entry in vuln.get("via", []):
            if not isinstance(via_entry, dict):
                # Transitive reference — a string package name
                continue
            url = via_entry.get("url", "")
            # Extract CVE IDs from advisory URLs.
            # Split on "/" then strip query strings so "CVE-2021-1234?ref=x"
            # does not corrupt the ID.
            if "CVE-" in url:
                # e.g. https://nvd.nist.gov/vuln/detail/CVE-2021-23337
                for part in url.split("/"):
                    clean = part.split("?")[0].split("#")[0]
                    if clean.startswith("CVE-"):
                        cve_ids.append(clean)
            ghsa = via_entry.get("ghsa", "") or ""
            if ghsa:
                aliases.append(ghsa)
            if not description:
                description = via_entry.get("title", "")[:500]

        fix_info = vuln.get("fixAvailable", {})
        fixed_version: str | None = None
        if isinstance(fix_info, dict):
            fixed_version = fix_info.get("version")

        records.append(CveRecord(
            package_name=pkg_name,
            ecosystem="npm",
            installed_version=vuln.get("range", "unknown"),
            fixed_version=fixed_version,
            cve_ids=cve_ids,
            severity=severity,
            description=description,
            aliases=aliases,
        ))

    log.info("npm audit: %d vulnerable packages found", len(records))
    return records


def _version_gt(a: str, b: str) -> bool:
    """Return True if version string a is semantically greater than b."""
    try:
        return Version(a) > Version(b)
    except InvalidVersion:
        return a > b  # fall back to lexicographic if unparseable


def group_by_package(records: list[CveRecord]) -> list[PackageFinding]:
    """Group CveRecords into PackageFindings (one per package per ecosystem)."""
    groups: dict[str, PackageFinding] = {}
    for record in records:
        key = f"{record.ecosystem}:{record.package_name}"
        if key not in groups:
            groups[key] = PackageFinding(
                package_name=record.package_name,
                ecosystem=record.ecosystem,
                installed_version=record.installed_version,
                fixed_version=record.fixed_version,
                records=[],
            )
        groups[key].records.append(record)
        # Use the highest known fixed version (compare semantically, not lexically)
        if record.fixed_version and (
            not groups[key].fixed_version
            or _version_gt(record.fixed_version, groups[key].fixed_version)
        ):
            groups[key].fixed_version = record.fixed_version
    return list(groups.values())
