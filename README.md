# Apache Superset — CVE Remediation Fork

This is a fork of [Apache Superset](https://github.com/apache/superset) used to demonstrate automated CVE remediation powered by the [Devin API](https://docs.devin.ai).

An event-driven automation scans Superset's Python (pip) and JavaScript (npm) dependencies, opens GitHub issues for every vulnerability found, and dispatches Devin sessions to create pull requests that fix them.

The automation source code lives in a separate repository: **[superset-cve-automation](https://github.com/vaniachow/superset-cve-automation)**

---

## Vulnerabilities Identified and Remediated

### Python (pip) — via `pip-audit`

| Package | Installed | Fix | CVE(s) | Issue | PR |
|---|---|---|---|---|---|
| flask | 2.3.3 | 3.1.3 | CVE-2026-27205 | [#50](https://github.com/vaniachow/superset/issues/50) | [#89](https://github.com/vaniachow/superset/pull/89) |
| pyjwt | 2.12.0 | 2.12.1 | CVE-2025-45768 | [#51](https://github.com/vaniachow/superset/issues/51) | [#121](https://github.com/vaniachow/superset/pull/121) |
| flask-cors | 6.0.2 | — | CVE-2024-1681 | [#52](https://github.com/vaniachow/superset/issues/52) | [#109](https://github.com/vaniachow/superset/pull/109) |
| idna | 3.10 | 3.15 | CVE-2026-45409 | [#53](https://github.com/vaniachow/superset/issues/53) | [#111](https://github.com/vaniachow/superset/pull/111) |
| mako | 1.3.11 | 1.3.12 | CVE-2026-44307 | [#54](https://github.com/vaniachow/superset/issues/54) | [#114](https://github.com/vaniachow/superset/pull/114) |
| markdown | 3.8.1 | 3.10.2 | CVE-2025-69534 | [#55](https://github.com/vaniachow/superset/issues/55) | [#112](https://github.com/vaniachow/superset/pull/112) |
| paramiko | 3.5.1 | 5.0.0 | CVE-2026-44405 | [#56](https://github.com/vaniachow/superset/issues/56) | [#108](https://github.com/vaniachow/superset/pull/108) |
| pyarrow | 20.0.0 | 23.0.1 | CVE-2026-25087 | [#57](https://github.com/vaniachow/superset/issues/57) | [#110](https://github.com/vaniachow/superset/pull/110) |
| urllib3 | 2.6.3 | 2.7.0 | CVE-2026-44431, CVE-2026-44432 | [#58](https://github.com/vaniachow/superset/issues/58) | [#123](https://github.com/vaniachow/superset/pull/123) |

### JavaScript (npm) — via `npm audit`

| Package | Issue | PR |
|---|---|---|
| @istanbuljs/nyc-config-typescript | [#133](https://github.com/vaniachow/superset/issues/133) | [#148](https://github.com/vaniachow/superset/pull/148) |
| @storybook/addon-essentials | [#137](https://github.com/vaniachow/superset/issues/137) | [#157](https://github.com/vaniachow/superset/pull/157) |
| @storybook/test-runner | [#138](https://github.com/vaniachow/superset/issues/138) | [#153](https://github.com/vaniachow/superset/pull/153) |
| http-proxy-agent | [#102](https://github.com/vaniachow/superset/issues/102) | [#116](https://github.com/vaniachow/superset/pull/116) |
| jest-environment-jsdom | [#104](https://github.com/vaniachow/superset/issues/104) | [#119](https://github.com/vaniachow/superset/pull/119) |
| jest-junit | [#140](https://github.com/vaniachow/superset/issues/140) | [#151](https://github.com/vaniachow/superset/pull/151) |
| jsdom | [#105](https://github.com/vaniachow/superset/issues/105) | [#120](https://github.com/vaniachow/superset/pull/120) |
| nyc | [#142](https://github.com/vaniachow/superset/issues/142) | [#156](https://github.com/vaniachow/superset/pull/156) |
| webpack-dev-server | [#147](https://github.com/vaniachow/superset/issues/147) | [#149](https://github.com/vaniachow/superset/pull/149) |

## How It Works

1. **Scan** — `pip-audit` and `npm audit` run against Superset's dependency manifests
2. **Diff** — New findings are compared against previous state (stored in a GitHub Gist) to avoid duplicate issues
3. **Issue** — A structured GitHub issue is created per vulnerable package with CVE IDs, installed/fixed versions, and severity
4. **Devin session** — The automation starts a Devin session with a detailed prompt specifying exactly which files to edit, how to verify the fix, and what PR format to use
5. **Monitor** — A follow-up step polls Devin sessions and comments PR links back on the originating issues

All issues are labeled `security`, `dependencies`, `automated` and can be filtered in the [Issues tab](https://github.com/vaniachow/superset/issues?q=label%3Asecurity).

## Related

- **Automation source code**: [vaniachow/superset-cve-automation](https://github.com/vaniachow/superset-cve-automation)
