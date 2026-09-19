# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut
automatically from [Conventional Commits](https://www.conventionalcommits.org/).

## [1.0.0](https://github.com/TobiasVeiga00/claude-security-audit/compare/v1.0.0...v1.0.0) (2026-09-19)


### Features

* deterministic audit engine with CVSS, coverage and authorization gate ([f97e25b](https://github.com/TobiasVeiga00/claude-security-audit/commit/f97e25b84b7bde524e8448950df85b5f59648a3d))
* skills, domain agents, importers and hooks ([439c5c2](https://github.com/TobiasVeiga00/claude-security-audit/commit/439c5c22f89b3544c21eac527979d95448ab6bda))


### Bug Fixes

* **ci:** drop redundant type:module so node -e inline checks work ([8f6c2ca](https://github.com/TobiasVeiga00/claude-security-audit/commit/8f6c2caf8aeccf829b4f1474514ef94cbfe6cab3))
* **ci:** run tests via a shell-expanded glob for Node 18 and 20 ([7a41110](https://github.com/TobiasVeiga00/claude-security-audit/commit/7a4111054e2f5fb806aefb248d26aa1aa782d395))


### Miscellaneous

* bootstrap first release at 1.0.0 ([bc52f36](https://github.com/TobiasVeiga00/claude-security-audit/commit/bc52f36f6b66c35f1eaaeef762ddd1f7945b80fe))

## 1.0.0

The first release.

### Features

- End-to-end security auditing across web, API, mobile, network, wireless,
  cloud, code, secrets, dependencies, IaC, containers and LLM applications.
- Token-optimised attack-surface mapper: 95–99% reduction on real repositories.
- Deterministic CVSS v3.1 and v4.0 scoring, validated against published NVD
  scores, with risk fusion over EPSS, CISA KEV and reachability.
- Falsifiable coverage ledger and a three-verdict finding model with a
  no-severity `needs-validation` state.
- Authorization gate: static analysis is always allowed; intrusive testing
  requires written, target-matched rules of engagement.
- Adversarial validation — the auditor that finds a candidate never confirms it.
- Professional reporting in Markdown, printable HTML, SARIF 2.1.0, CSV and JSON.
- Live threat-intelligence queries (EPSS, NVD, OSV) and a daily automated
  refresh of vendored KEV, ATT&CK, CWE Top 25 and CVSS tables.
- Scanner importers for SARIF, Semgrep, gitleaks, TruffleHog, Trivy, Grype,
  osv-scanner, Checkov, KICS, Bandit, npm audit and Nuclei.
