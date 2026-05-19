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

"""
CVE Remediation Automation CLI

Usage:
  python -m automation scan             # Scan, diff, create issues, start Devin sessions
  python -m automation scan --dry-run   # Scan and report only — no issues or sessions created
  python -m automation monitor          # Poll Devin sessions, update GitHub issues

Environment variables:
  GITHUB_TOKEN        (required) GitHub token with issues:write permission
  GITHUB_REPOSITORY   Repository in "owner/repo" format (default: apache/superset)
  DEVIN_API_KEY       Devin API key — if absent, sessions are not started
  SCAN_STATE_GIST_ID  Secret GitHub Gist ID for cross-run state persistence
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)


def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"ERROR: required environment variable '{name}' is not set", file=sys.stderr)
        sys.exit(1)
    return val


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m automation",
        description="CVE-driven dependency upgrade automation for Apache Superset",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan, diff, create issues, start Devin sessions")
    scan_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would happen without creating issues or sessions",
    )

    sub.add_parser("monitor", help="Poll Devin sessions and update GitHub issues")

    args = parser.parse_args()

    # Repo root is the parent of this automation/ package
    repo_root = Path(__file__).parent.parent

    github_token = _require_env("GITHUB_TOKEN")
    github_repo = os.environ.get("GITHUB_REPOSITORY", "apache/superset").strip()
    devin_api_key = os.environ.get("DEVIN_API_KEY", "").strip() or None
    gist_id = os.environ.get("SCAN_STATE_GIST_ID", "").strip() or None

    if args.command == "scan":
        from .orchestrator import run_pipeline
        run_pipeline(
            repo_root=repo_root,
            github_repo=github_repo,
            github_token=github_token,
            devin_api_key=devin_api_key,
            gist_id=gist_id,
            dry_run=args.dry_run,
        )

    elif args.command == "monitor":
        if not devin_api_key:
            print("ERROR: DEVIN_API_KEY is required for the monitor command", file=sys.stderr)
            sys.exit(1)
        from .state_manager import load_state
        from .monitor import poll_sessions
        state = load_state(gist_id, github_token)
        # findings_by_fp is empty here; requeue will be a no-op if finding isn't cached.
        # In a future iteration this could be populated from a serialized findings store.
        poll_sessions(
            state=state,
            github_repo=github_repo,
            github_token=github_token,
            devin_api_key=devin_api_key,
            gist_id=gist_id,
        )


if __name__ == "__main__":
    main()
