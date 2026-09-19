<div align="center">

# Claude Security Audit

**A complete security auditor for [Claude Code](https://claude.com/claude-code) — web, API, mobile, cloud, wireless, code, secrets, dependencies, IaC, containers and LLM apps, in one plugin.**

It reads your attack surface, hunts with domain specialists, refutes its own findings, ranks them by real-world exploitation, and writes you a report you can hand to a client.

[![CI](https://github.com/TobiasVeiga00/claude-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/TobiasVeiga00/claude-security-audit/actions/workflows/ci.yml)
[![Threat intel](https://github.com/TobiasVeiga00/claude-security-audit/actions/workflows/refresh-intel.yml/badge.svg)](https://github.com/TobiasVeiga00/claude-security-audit/actions/workflows/refresh-intel.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-da7756.svg)](https://code.claude.com/docs/en/plugins)

</div>

---

## Install

```
/plugin marketplace add TobiasVeiga00/claude-security-audit
/plugin install security-audit@claude-security-audit
```

That is it. No dependencies to install, no API key required. It runs on Windows,
macOS and Linux, because every script is zero-dependency Node.

> An optional free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
> raises the CVE lookup rate limit. Set it in the plugin config if you have one.

## Use

```
/security-audit:audit
```

Answer four questions once (scope, depth, domains, report format), then walk
away. When it finishes you have a report in `.security-audit/report/` as
Markdown, printable HTML, SARIF and CSV.

That single command orchestrates everything below. You can also run any piece on
its own:

| Command | What it does |
| --- | --- |
| `/security-audit:audit` | The full assessment, end to end. |
| `/security-audit:code` | Secure code review — injection, access control, crypto, deserialization. |
| `/security-audit:web` | OWASP Top 10 2025 web assessment. |
| `/security-audit:api` | OWASP API Top 10 — BOLA, mass assignment, resource abuse. |
| `/security-audit:mobile` | OWASP MASVS/MASTG for Android and iOS. |
| `/security-audit:cloud` | Terraform, Kubernetes, cloud posture (CIS-aligned). |
| `/security-audit:deps` | Supply chain — vulnerable dependencies, ranked by exploitability. |
| `/security-audit:secrets` | Committed credentials, plus the correct leak response. |
| `/security-audit:llm` | Prompt injection and agentic risk (OWASP GenAI 2026). |
| `/security-audit:network` | Network and Wi-Fi assessment (scope-gated). |
| `/security-audit:scope` | Define rules of engagement before any active testing. |
| `/security-audit:report` | Regenerate the report from the current findings. |
| `/security-audit:fix` | Generate and apply remediation patches, with a safety gate. |

## Why it is different

**It is cheap to run on a real repository.** A deterministic pass ranks your
whole attack surface against a signal database and hands the model only the files
that matter — a **95–99% token reduction** on a large codebase — so you get depth
without paying to read a tree of framework code.

**It refuses to inflate a report.** Every finding must state who crosses which
trust boundary, past which control, with what concrete result. Anything it cannot
prove is filed as `needs-validation` **with no severity** — a lead, honestly
labelled, never a padded "medium". A separate adversarial validator receives each
candidate cold and tries to *refute* it; the finder never confirms its own work.

**It ranks by what will actually be exploited.** Severity is CVSS. *Priority*
fuses that with [EPSS](https://www.first.org/epss) exploit probability, [CISA
KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) membership,
and reachability. A medium under active exploitation outranks a high in
unreachable code, and the report says exactly why.

**Its coverage claim is falsifiable.** "We audited it" is worthless. The plugin
plans the audit as units of *surface × trust boundary × attack class*, drives
each to a terminal state, and requires a reason for anything it did not examine.
The report discloses coverage honestly — a gap is a gap, not a silent omission.

**It scores CVSS correctly.** v3.1 exactly to the FIRST specification; v4.0 using
FIRST's official MacroVector tables, validated against published NVD scores — and
it refuses to guess a score when the tables are absent rather than invent one.

**It will not test what you are not allowed to test.** Static analysis of your
own code is always free. Anything that puts a packet on a wire — a scan, a fuzz,
a Wi-Fi capture — is blocked unless your written rules of engagement authorize
that exact target. The authorized path is the easy one; the unauthorized one does
not run.

**Its knowledge base stays current on its own.** A daily GitHub Action refreshes
CISA KEV, MITRE ATT&CK, the CWE Top 25 and the CVSS tables, and tracks OWASP
edition changes — so the plugin's frameworks do not quietly go stale between
releases.

## What a finding looks like

Each finding carries its boundary, its evidence, its exploitation signal and a
concrete fix:

- **CVSS 9.8**, priority **100/100 (P0)** — *SQL injection in the user lookup*
- `src/api/users.js:6` · CWE-89 · CVE-2021-44228
- **CISA KEV: exploited in the wild** · EPSS 100%
- Evidence, reproduction, and a suggested patch, all in the report.

Reports render as a clean, printable HTML document (Ctrl+P → PDF), a diffable
Markdown file, SARIF 2.1.0 for GitHub code scanning, and a formula-injection-safe
CSV for your tracker.

## Standards it speaks

OWASP **Top 10 2025**, **API Top 10 2023**, **ASVS 5.0**, **WSTG 4.2**, **MASVS
2.1 / MASTG 2.0**, **GenAI LLM Top 10 2026**, **Agentic Top 10**, and **CI/CD Top
10** · MITRE **ATT&CK v19**, **CWE Top 25 (2025)**, **CAPEC** · **CVSS v3.1 and
v4.0** · **EPSS** · **CISA KEV** · **NIST CSF 2.0** and **SP 800-115** · **CIS
Controls v8.1** and Benchmarks · **PCI DSS 4.0.1**, **ISO 27001:2022**, **SOC 2**.

## How it works

```
  your target
      │
      ▼
  surface.mjs ──► ranks the attack surface, returns a shortlist in a token budget
      │
      ▼
  coverage plan ──► units of surface × boundary × attack class, each falsifiable
      │
      ▼
  domain specialists (parallel subagents) ──► hunt, return compact findings
      │
      ▼
  exploit-validator ──► refutes each candidate; survivors are confirmed
      │
      ▼
  intel enrich ──► attaches KEV + EPSS, re-ranks on real exploitation
      │
      ▼
  report ──► Markdown · HTML · SARIF · CSV · JSON
```

Full method: [`references/methodology.md`](references/methodology.md).
False-positive discipline: [`references/false-positives.md`](references/false-positives.md).

## Not a replacement for judgement

This plugin finds and explains; it does not certify. Absence of findings is not
proof of security. It treats the code you point it at as trusted enough to read,
and does not sandbox execution — for genuinely untrusted code, isolate the
session. And it audits only what you are authorized to audit; that authorization
remains yours. See [SECURITY.md](SECURITY.md).

## Contributing

The most valuable contribution is **fewer false positives**. See
[CONTRIBUTING.md](CONTRIBUTING.md). Data licensing and attributions are in
[ATTRIBUTION.md](ATTRIBUTION.md).

## License

[MIT](LICENSE). Vendored security data remains under its own terms — see
[ATTRIBUTION.md](ATTRIBUTION.md).
