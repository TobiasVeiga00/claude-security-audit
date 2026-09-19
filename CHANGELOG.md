# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut
automatically from [Conventional Commits](https://www.conventionalcommits.org/).

## [1.3.0](https://github.com/TobiasVeiga00/claude-security-audit/compare/v1.2.0...v1.3.0) (2026-09-19)


### Features

* **importers:** native Prowler (OCSF) importer ([ec2d94a](https://github.com/TobiasVeiga00/claude-security-audit/commit/ec2d94a8c772b4c5d350460d6951783984b053d7))


### Bug Fixes

* **skills:** make inline preambles shell-neutral for Windows/PowerShell ([23eb35a](https://github.com/TobiasVeiga00/claude-security-audit/commit/23eb35ae3019358419af12f44704aabcc44a050d))

## [1.2.0](https://github.com/TobiasVeiga00/claude-security-audit/compare/v1.1.0...v1.2.0) (2026-09-19)


### Features

* **signals:** detect sinks in Rust, shell and PowerShell ([2c47c7d](https://github.com/TobiasVeiga00/claude-security-audit/commit/2c47c7dd54059115a7990086ded4e993a42faa50))

## [1.1.0](https://github.com/TobiasVeiga00/claude-security-audit/compare/v1.0.1...v1.1.0) (2026-09-19)


### Features

* **ledger:** expose incremental diff and a CI severity gate ([e6dfa5d](https://github.com/TobiasVeiga00/claude-security-audit/commit/e6dfa5dc9f436d19a598f2b2aa946846e5b70110))
* **web,cloud:** add CSRF, client-side integrity and IMDSv2 coverage ([5ca6932](https://github.com/TobiasVeiga00/claude-security-audit/commit/5ca69324d8144a95ce9039c08bcc6381a5400066))


### Bug Fixes

* **intel:** body-timeout, KEV availability, materiality memory and CI on bot PRs ([3702ce9](https://github.com/TobiasVeiga00/claude-security-audit/commit/3702ce96dd61535c30572e3b2679c34b0e5d666c))
* **report,docs:** correct LLM Top 10 edition, harden report, fix skill args ([7cea633](https://github.com/TobiasVeiga00/claude-security-audit/commit/7cea63322936a1024d9540bce7a8a06c2af3c3aa))
* **surface,skills:** honor audit-domain nouns and allow advertised intrusive tools ([aa71fd0](https://github.com/TobiasVeiga00/claude-security-audit/commit/aa71fd03bf6ae64130feb73ece315fd24fc3454d))
* **surface:** resolve the token budget defensively so the audit never aborts ([3e525bf](https://github.com/TobiasVeiga00/claude-security-audit/commit/3e525bfee742dbcb3981b545b2126623d320c814))

## [1.0.1](https://github.com/TobiasVeiga00/claude-security-audit/compare/v1.0.0...v1.0.1) (2026-09-19)


### Bug Fixes

* **cvss:** correct v4.0 Safety level and rounding, and parser edge cases ([abfd0c3](https://github.com/TobiasVeiga00/claude-security-audit/commit/abfd0c385f654869aab27362d15f7da70ea98b84))
* **gate:** close five authorization-gate bypasses found by audit ([93765b0](https://github.com/TobiasVeiga00/claude-security-audit/commit/93765b022a4514080d8d2fed1c68e427fd4c5854))
* **ledger:** correct finding merge, verdicts and coverage invariants ([30eef52](https://github.com/TobiasVeiga00/claude-security-audit/commit/30eef523ee31e24de4882bf8063d109c8995540f))
* remove stray e.gz dump and correct crossed agent domain labels ([d00354d](https://github.com/TobiasVeiga00/claude-security-audit/commit/d00354da638009a91351b3da0807f9918897c65c))
* **scan:** ReDoS, broken regexes, credential leaks and importer robustness ([15547a2](https://github.com/TobiasVeiga00/claude-security-audit/commit/15547a2935256002e78de41ae65d42a4c054d000))

## 1.0.0 (2026-09-19)

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
