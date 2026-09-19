---
name: secrets
description: Find committed credentials and handle a leak properly — detection across the working tree and git history, sample-versus-live triage, and the revoke-rotate-purge-audit response. Use for "check for secrets", "did I commit an API key", "scan for credentials", "I leaked a token".
argument-hint: "[path] [--history]"
allowed-tools: Read, Glob, Grep, Write, Bash(node:*), Bash(git:*), Bash(gitleaks:*), Bash(trufflehog:*)
---

# Secret detection and leak response

Two different jobs, and the second matters more. Finding a committed credential
is easy. Handling it correctly is where people get it wrong — usually by
deleting the line and believing that fixed it.

Tooling available:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/tools.mjs" --domain secrets --missing 2>&1 | head -8`

---

## Step 1 — Detect

The attack-surface mapper already carries high-confidence provider-prefix
matches with line numbers and redacted values:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/surface.mjs" . --budget 120000 --json .security-audit/surface.json
```

Extend with a dedicated scanner when one is present:

```bash
gitleaks detect --source . --report-format json --report-path .security-audit/gitleaks.json --no-banner
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool gitleaks --file .security-audit/gitleaks.json
```

**History matters more than the working tree.** A credential removed in a later
commit is still in every clone that already exists:

```bash
gitleaks detect --source . --log-opts="--all" --report-format json --report-path .security-audit/gitleaks-history.json
```

TruffleHog additionally *verifies* — it authenticates against the provider to
prove a key is live. That is enormously useful for triage, and it is an active
action against a third party. Only run it against credentials you are authorized
to test:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "trufflehog filesystem ."
trufflehog filesystem . --json --only-verified > .security-audit/trufflehog.jsonl
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool trufflehog --file .security-audit/trufflehog.jsonl
```

## Step 2 — Triage: is it actually a secret?

Most raw scanner output is noise. Sort each hit.

**Not a finding**

- Published documentation samples. `AKIAIOSFODNN7EXAMPLE` is in AWS's own docs.
- Placeholders: `YOUR_API_KEY`, `xxxx`, `<token>`, `${VAR}`, `changeme`.
- Keys that are publishable by design: Stripe `pk_`, Firebase web config,
  public analytics ids, OAuth *client ids* (the client *secret* is different).
- Test fixtures, unless the credential is real and reaches a real system.
- Hashes and checksums that happen to match a token shape.

**A finding**

- Anything matching a provider's *secret* prefix with plausible entropy.
- Database URIs carrying a password.
- Private keys: `-----BEGIN ... PRIVATE KEY-----`.
- Any of the above in git history, even when removed from `HEAD`.

The surface mapper flags likely samples with `likelySample: true` and downgrades
them rather than dropping them, so a real key that happens to resemble a sample
still reaches you. Check those yourself rather than trusting the flag.

## Step 3 — Respond, in this order

If a live credential was committed, the order is not negotiable. Rotating
without revoking leaves the old credential working.

1. **Revoke at the provider.** Immediately — before the git surgery, before
   telling anyone. An unrevoked key is an open door.
2. **Issue a replacement** and load it from the environment or a managed secret
   store. Never from a tracked file.
3. **Audit provider logs** for use of the exposed credential: source addresses,
   time range, actions taken. Everyone skips this step, and it is the one that
   tells you whether you had an incident or a near miss.
4. **Purge from history** with `git filter-repo` or BFG, coordinated with
   everyone holding a clone, then force-push. Do this *last*: it is disruptive
   and on its own it reduces no risk.
5. **Prevent recurrence**: a pre-commit hook, a CI history scan, and a
   `.gitignore` entry for the file that carried it.

> If the repository is public, or ever was, assume the credential was harvested
> within minutes — automated scrapers watch the public firehose. Treat it as
> compromised, not as at risk.

## Step 4 — Record

Every secret finding takes `domain: "secrets"`, `cwe: ["CWE-798"]` (or
`CWE-321` for a private key), `severity: "critical"` for a live credential, and
remediation steps in the order above.

**Never write the credential into the ledger or the report.** The importers and
the surface mapper redact to first four and last four characters. Keep it that
way: a security report that leaks the secret it is reporting is a farce.

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" add --file candidates.json
```

## Prevention worth recommending

- `gitleaks protect --staged` as a pre-commit hook.
- A CI job scanning full history on pull requests.
- Provider-side push protection where it exists.
- Short-lived, scoped credentials over long-lived ones. A key that expires in an
  hour turns a leak into a non-event.
