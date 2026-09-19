# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut
automatically from [Conventional Commits](https://www.conventionalcommits.org/).

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
