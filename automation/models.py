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

from dataclasses import dataclass, field
from typing import Literal, Optional

Ecosystem = Literal["pip", "npm"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SessionStatus = Literal["working", "blocked", "expired", "finished",
                        "suspend_requested", "suspend_requested_frontend",
                        "resume_requested", "resume_requested_frontend", "resumed"]


@dataclass
class CveRecord:
    """Normalized finding from pip-audit or npm audit."""
    package_name: str
    ecosystem: Ecosystem
    installed_version: str
    fixed_version: Optional[str]
    cve_ids: list[str]
    severity: Severity
    description: str
    aliases: list[str]

    @property
    def fingerprint(self) -> str:
        """Stable deduplication key: ecosystem:package:sorted-CVEs."""
        cves = ",".join(sorted(self.cve_ids)) if self.cve_ids else "no-cve"
        return f"{self.ecosystem}:{self.package_name}:{cves}"


@dataclass
class PackageFinding:
    """All CVE records for a single package — maps to one GitHub issue."""
    package_name: str
    ecosystem: Ecosystem
    installed_version: str
    fixed_version: Optional[str]
    records: list[CveRecord] = field(default_factory=list)

    @property
    def all_cve_ids(self) -> list[str]:
        ids: list[str] = []
        for r in self.records:
            ids.extend(r.cve_ids)
        return sorted(set(ids))

    @property
    def max_severity(self) -> Severity:
        order: list[Severity] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        for level in order:
            if any(r.severity == level for r in self.records):
                return level
        return "UNKNOWN"

    @property
    def fingerprints(self) -> list[str]:
        return [r.fingerprint for r in self.records]


@dataclass
class SerializedFinding:
    """Minimal serializable form of a PackageFinding stored in ScanState."""
    package_name: str
    ecosystem: str
    installed_version: str
    fixed_version: Optional[str]
    all_cve_ids: list[str]
    max_severity: str
    description: str


@dataclass
class ScanState:
    """Full snapshot written to GitHub Gist after every run."""
    scan_timestamp: str
    fingerprints: list[str]
    issue_map: dict[str, int]              # fingerprint -> GitHub issue number
    session_map: dict[str, str]            # fingerprint -> Devin session_id
    session_attempts: dict[str, int]       # fingerprint -> retry count
    # Serialized findings keyed by the first fingerprint for the package.
    # Populated by the scan command; used by monitor to requeue expired sessions.
    findings: dict[str, SerializedFinding] = field(default_factory=dict)


@dataclass
class DevinSession:
    """Snapshot returned by GET /v1/sessions/{session_id}."""
    session_id: str
    status: str
    status_enum: SessionStatus
    pull_request_url: Optional[str]
    structured_output: Optional[dict]
    updated_at: str
