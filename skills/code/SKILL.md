---
name: code
description: Secure code review — hunts injection, deserialization, access control, cryptography, memory-safety (native/unsafe code) and unsafe-sink defects in application source, anchored to CWE and OWASP. Use for "review this code for security", "SAST", "is this code vulnerable", "secure code review", "check for injection", "buffer overflow".
argument-hint: "[path] [--changed-only]"
allowed-tools: Read, Glob, Grep, Write, Agent, Bash(node:*), Bash(git:*), Bash(semgrep:*), Bash(opengrep:*), Bash(bandit:*), Bash(gosec:*), Bash(brakeman:*), Bash(njsscan:*)
---

# Secure code review

Hunt defects in first-party source. Read
`${CLAUDE_PLUGIN_ROOT}/references/methodology.md` and
`${CLAUDE_PLUGIN_ROOT}/references/false-positives.md` first — the evidence bar
and the exclusions are what make this output worth reading.

## Attack surface

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/surface.mjs" $ARGUMENTS --budget 160000 --json .security-audit/surface.json --summary`

Available tooling:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/tools.mjs" --domain code --missing 2>&1`

---

## Method

Work from the surface map's hotspots. Each carries the sinks already located and
the line they sit on, so you start from evidence rather than from a search.

For each hotspot, work the boundary contract from
`references/methodology.md`: name the actor, the input, the control, the
crossing, and the concrete result. **All five, or it is not a finding.**

### Trace direction

Start at the **sink**, walk backwards to the source. It is far cheaper than
walking forwards from every entry point, and it fails fast: if no untrusted
input can reach the sink, you are done in one file.

1. Locate the sink (the map gives you these).
2. Identify what flows into its dangerous argument.
3. Walk back through assignments, parameters and calls.
4. At each hop ask: is there validation, escaping, parameterisation or an
   allowlist here? Most "missing checks" live one layer up — go and look before
   you report.
5. If you reach a request, a file, an environment boundary or a third party
   without a control, you have a crossing.

### What to hunt, by weight

Ordered by what actually produces confirmed findings in real code:

**Injection (CWE-89, -78, -94, -77, -917, -1336)** — SQL built by concatenation
or interpolation; `exec`/`system` with a shell string; template rendering of
user input; expression-language evaluation; `eval` and its relatives. Check
whether the interpolated part is a *value* (parameterisable) or an *identifier*
(needs an allowlist — a bound parameter cannot help you there).

**Access control (CWE-862, -863, -639, -284)** — the top of the 2025 CWE list and
the hardest for a scanner to find, which makes it the highest-value thing you
personally look for. For each handler that reads or writes a record:
- Is there an authorization check at all?
- Does it check the *object*, or only that someone is logged in? An `id` taken
  from the request and used without an ownership check is IDOR.
- Multi-tenant: is the tenant taken from the session, or from the request?
  Taking it from the request is the bug.

**Deserialization (CWE-502)** — `pickle`, `Marshal`, `ObjectInputStream`,
`BinaryFormatter`, `yaml.load` without a safe loader, Jackson polymorphic typing.
Trace whether the byte stream can be attacker-influenced.

**Authentication and session (CWE-287, -306, -384)** — JWT decoded without
verification, algorithm not pinned, `none` accepted, weak or hardcoded secret;
session identifiers from a non-cryptographic PRNG; missing re-authentication on
privilege change; password comparison that is not constant time.

**Cryptography (CWE-327, -328, -338, -321)** — MD5 or SHA-1 for passwords,
signatures or integrity (**not** for cache keys or ETags — see the exclusions);
ECB mode; static or reused IVs; `Math.random`, `rand()` or `math/rand` for
anything security-relevant; hardcoded keys.

**Memory safety, native code (CWE-120, -121, -122, -125, -787, -416, -415, -134,
-190)** — in C, C++, Objective-C and `unsafe` Rust/Go: unbounded copies
(`strcpy`, `strcat`, `sprintf`, `gets`, `scanf`), stack and heap buffer
overflow, out-of-bounds read/write, use-after-free and double-free, a non-literal
format string, and integer overflow or truncation feeding an allocation size or
a bounds check. The surface map's `c.overflow`, `c.memory`, `c.format-string` and
`c.int-overflow` sinks locate these; then prove the attacker controls the length,
index or count that overflows. Here a crash is the *floor*, not the finding —
trace to attacker-influenced memory or a controlled write primitive.

**Path and file handling (CWE-22, -434)** — user-controlled paths without a
resolved-root check; uploads without content-type *and* extension *and* size
validation; archive extraction without a traversal guard.

**SSRF (CWE-918)** — now folded into OWASP A01:2025. Outbound requests with a
user-influenced destination. Check for allowlists, and whether redirects are
followed.

**Exceptional conditions (CWE-703, OWASP A10:2025)** — new in the 2025 Top 10.
Error paths that fail open, swallowed exceptions around security checks,
discarded return values from verification functions, `catch` blocks that
continue as though nothing happened.

### Language specifics

Load only the one you need:

- JavaScript / TypeScript → [references/javascript.md](references/javascript.md)
- Python → [references/python.md](references/python.md)
- Java / Kotlin → [references/jvm.md](references/jvm.md)
- Go → [references/go.md](references/go.md)
- PHP, Ruby, C#, C/C++ → [references/other-languages.md](references/other-languages.md)

## Scanners

Run what is installed. Parse the output through the importer so the raw report
never enters the conversation:

```bash
semgrep --config auto --json -o .security-audit/semgrep.json . 2>/dev/null
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool semgrep --file .security-audit/semgrep.json
```

`bandit` has a native importer (`--tool bandit`). For `gosec`, `brakeman`,
`njsscan` and any other analyser, emit SARIF and import that — it is the
universal path:

```bash
gosec -fmt sarif -out .security-audit/gosec.sarif ./... 2>/dev/null
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool sarif --file .security-audit/gosec.sarif
```

The importers that exist are: `sarif`, `semgrep`, `gitleaks`, `trufflehog`,
`trivy`, `grype`, `osv-scanner`, `checkov`, `kics`, `prowler`, `bandit`,
`npm-audit`, `nuclei`. Everything else routes through `--tool sarif`.

Scanner output is a **starting point, not a finding**. Every imported result is
`tentative` until you read the code and confirm the boundary. Triage them with
the same gate you apply to your own candidates.

## Recording

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" add --file candidates.json
```

Each finding needs, at minimum: `title`, `severity`, `domain: "code"`, `cwe`,
`location` with file and line, a `boundary` object, a code `evidence` entry, and
a `remediation.summary` that names the specific change.

Prefer a suggested patch when the fix is unambiguous — put a unified diff in
`remediation.patch`.

## Before you finish

- Mark your coverage units, with evidence:
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/coverage.mjs" mark <id> --state covered --evidence <files>`
- Report what you did **not** examine and why. That sentence is worth more than
  three more low-severity findings.
