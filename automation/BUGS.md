# Automation Bug Tracker

Bugs identified during code review. Work through in order — check off each when fixed.

---

## Correctness

- [x] **B1** `scanner.py:232` — Version comparison uses string ordering, not semver. `"2.10.0" > "2.9.0"` is `False` as strings. Use integer tuple comparison.
  - Fixed: added `_version_gt()` using `packaging.version.Version`; falls back to lexicographic for unparseable strings. Added `packaging>=24.0` to `requirements.txt`.

- [x] **B2** `monitor.py:101-102` — Issue closed immediately when Devin reports `finished`, before the PR is reviewed or merged. Should leave open until PR is merged, or at minimum not claim it will auto-close on merge.
  - Fixed: removed `close_issue()` call. Comment now says "Please review and merge the PR. Close this issue manually once merged."

- [x] **B3** `orchestrator.py:177` — Fingerprint added to state even when GitHub issue creation fails. Failed packages are silently skipped on all future runs.
  - Fixed: introduced `failed_fingerprints: set[str]`. Fingerprints are added to this set on `issue_error` and excluded when updating `state.fingerprints`.

- [x] **B4** `scanner.py:188-190` — CVE ID extracted from npm advisory URL by splitting on `/`, but query strings (e.g. `CVE-2021-1234?ref=npm`) corrupt the ID and break fingerprinting.
  - Fixed: each URL segment is stripped of `?...` and `#...` before CVE prefix check.

## Design

- [x] **B5** `__main__.py:109` — `findings_by_fp={}` is always empty, making the entire requeue-on-expiry path in `monitor.py` dead code. `MAX_RETRIES` never fires.
  - Fixed: added `SerializedFinding` dataclass and `ScanState.findings` field. Orchestrator populates it when sessions start. Monitor calls `_rebuild_findings(state)` instead of accepting an empty dict. Removed the `findings_by_fp` parameter from `poll_sessions`.

- [x] **B6** `models.py:91` — `DevinSession.status_enum` is typed `str` despite `SessionStatus` Literal being defined. Typos in status comparisons are unchecked.
  - Fixed: field type changed to `SessionStatus`.

- [x] **B7** `devin_client.py:152` — `str.format()` on npm prompt template containing `{{...}}` escaped braces. Any future code example with single braces silently raises `KeyError`. Switch to `string.Template`.
  - Fixed: both templates converted to `$var` syntax; `_build_prompt` now uses `Template(...).safe_substitute(...)`. Literal braces in code blocks no longer require escaping.

## Code Smells

- [x] **B8** `devin_client.py:121` — `list_sessions()` is dead code; never called by any module.
  - Fixed: deleted.

- [x] **B9** `reporter.py:71` — `_count_where(event_type, key)` checks for truthiness of `key`, not equality. Name implies key-value match.
  - Fixed: renamed to `_count_events_with_field(event_type, field)` with a clarifying docstring.

- [x] **B10** `devin_client.py:82-83` — `resp.json()` called twice on the same response object.
  - Fixed: `data = resp.json()` assigned once; both fields read from `data`.
