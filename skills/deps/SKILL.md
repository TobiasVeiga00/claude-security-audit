---
name: deps
description: Software supply chain audit — known-vulnerable dependencies ranked by real exploitability, SBOM generation, typosquatting and install-script risk, and lockfile integrity. Use for "check my dependencies", "SCA scan", "am I affected by CVE-X", "supply chain review", "generate an SBOM".
argument-hint: "[path]"
allowed-tools: Read, Glob, Grep, Write, Bash(node:*), Bash(git:*), Bash(osv-scanner:*), Bash(trivy:*), Bash(grype:*), Bash(syft:*), Bash(cdxgen:*), Bash(npm:*), Bash(pip-audit:*), Bash(govulncheck:*)
---

# Supply chain security

**OWASP A03:2025 — Software Supply Chain Failures.** Promoted and broadened in
the 2025 edition: it is no longer just "outdated components", it covers the
whole path from a package author to your running artefact.

Manifests and lockfiles found:
!`node -e "
const fs=require('fs'),path=require('path');
const names=['package.json','package-lock.json','yarn.lock','pnpm-lock.yaml','requirements.txt','poetry.lock','uv.lock','Pipfile.lock','go.mod','go.sum','Cargo.lock','pom.xml','build.gradle','build.gradle.kts','composer.lock','Gemfile.lock','pubspec.lock','Package.resolved','mix.lock','packages.lock.json'];
const found=names.filter(n=>fs.existsSync(n));
console.log(found.length?found.join('\n'):'(none at root — search subdirectories)');
"`

Tooling:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/tools.mjs" --domain dependencies --missing 2>&1 | head -10`

---

## Step 1 — Scan the lockfile, not the manifest

A manifest says `^4.17.0`. A lockfile says what is actually installed. Always
scan the lockfile; scanning a range produces fiction.

```bash
osv-scanner scan source --format json --output .security-audit/osv.json . 2>/dev/null
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool osv-scanner --file .security-audit/osv.json
```

Alternatives with a native importer: `trivy fs --format json` (`--tool trivy`),
`grype -o json` (`--tool grype`), `npm audit --json` (`--tool npm-audit`).
`pip-audit` and `govulncheck` have no native importer — emit SARIF
(`pip-audit -f sarif`, `govulncheck -format sarif`) and import with
`--tool sarif`.

Prefer `pip-audit` over `safety` for Python — `safety`'s full database is now
commercially gated.

## Step 2 — Rank by exploitability, not by count

A raw SCA report is useless: hundreds of advisories, most irrelevant. The
ranking is the value you add.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" enrich
```

That attaches CISA KEV membership and EPSS probability to every CVE and
re-ranks. Then apply judgement in this order:

1. **Actively exploited (KEV).** Non-negotiable, regardless of CVSS. The floor
   is P0.
2. **High EPSS** (above roughly 10%). Exploitation is likely in the near term.
3. **Reachable.** Is the vulnerable *function* actually called? `govulncheck`
   proves this for Go; for other ecosystems, grep for the affected API before
   escalating. An unreachable critical outranks nothing.
4. **Exposure.** A vulnerability in a build-time dev dependency is not the same
   as one in a request-handling path.
5. **Transitive depth.** You may not be able to upgrade directly; note the
   dependent that pins it.

Report the ones that matter with reasons, and give the rest as a count. Twelve
explained findings beat four hundred listed ones.

## Step 3 — Beyond known CVEs

Known vulnerabilities are the easy half. The 2025 category exists because of the
other half:

- **Install scripts.** `postinstall`, `preinstall`, `setup.py` executing at
  install time. This is the primary npm and PyPI attack vector — code running on
  developer machines and CI runners before anyone reviews it.
- **Typosquatting and slopsquatting.** Names one edit from a popular package,
  or plausible-sounding packages that do not exist upstream and were registered
  by someone else. Check anything unfamiliar against its download count and
  publication date.
- **Maintainer risk.** Single-maintainer packages, recent ownership transfer,
  a long-dormant package suddenly publishing.
- **Integrity.** Does the lockfile carry hashes, and are they verified on
  install? Is the registry pinned? Are git dependencies pinned to a commit
  rather than a branch?
- **Vendored and bundled code** that no scanner sees because it is not in a
  manifest.
- **CI actions** pinned to a tag rather than a commit SHA — a tag can be moved.

## Step 4 — SBOM

Generate one when the engagement wants an artefact, or when the client has
regulatory obligations:

```bash
syft . -o cyclonedx-json=.security-audit/sbom.cdx.json
# or
cdxgen -o .security-audit/sbom.cdx.json
```

An SBOM is not a security control on its own. Its value is answering "am I
affected?" in minutes the next time something like Log4Shell lands.

## Step 5 — Answering "am I affected by CVE-X"

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" cve CVE-2021-44228
node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" package --ecosystem npm --name lodash --version 4.17.15
```

Then answer three questions in order, and do not stop at the first:
is the package present · is the installed version in the affected range ·
is the vulnerable code path reachable from an entry point.

## Recording

`domain: "dependencies"`, `location.package` and `location.version`, the CVE
list, and a remediation that names the **exact fixed version**. If no fix
exists, say so and give the mitigation.
