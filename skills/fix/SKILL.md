---
name: fix
description: Generate and apply remediation patches for confirmed findings, one at a time, each with a behaviour-change gate and a regression test. Use for "fix the findings", "patch the vulnerabilities", "remediate P0 and P1", "generate fixes for the audit".
argument-hint: "[finding ID or --tier P0,P1]"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash(node:*), Bash(git:*)
---

# Remediation

Fix confirmed findings — carefully, one at a time, and never in a way that trades
a security bug for a functional one.

Open findings, highest priority first:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" list --status open --limit 25 2>&1`

---

## What you may fix

Only findings that are `confirmed`. A `needs-validation` lead is unproven — fixing
it is guessing. A `tentative` scanner hit has not been checked. Confirm first, or
do not touch it.

Work in priority order: P0, then P1, then down. Do the highest-impact fixes while
attention and review are freshest.

## The three-part gate

Before writing a single patch, commit to proving all three. A patch that fails
any of them does not get applied.

1. **It addresses this finding.** The specific boundary crossing is closed —
   not worked around, not hidden, closed.
2. **It introduces no new vulnerability.** You are editing security-sensitive
   code; the classic failure is fixing an injection by adding a filter that is
   itself bypassable. Re-audit your own change.
3. **It changes nothing else.** Behaviour is otherwise identical. **A change to
   which inputs the code accepts is a behaviour change** — if a valid request now
   gets rejected, that is a regression, not a fix.

## Per finding

1. **Read the finding and its context.**
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" show <ID>
   ```
   Read the actual code around it, not just the excerpt in the ledger.

2. **Choose the real fix, not the pattern-matcher's fix.**
   - SQL injection → a parameterised query or a quoted identifier allowlist,
     never a blocklist of "bad characters".
   - XSS → contextual output encoding, or the framework's escaping, never manual
     tag stripping.
   - Missing authorization → the check at the right layer, verifying the *object*
     and the *tenant*, not a flag bolted onto the handler.
   - Weak crypto → the platform's vetted primitive with correct parameters,
     never a hand-rolled construction.
   - Hardcoded secret → removal plus rotation (route to `/security-audit:secrets`
     for the response), never obfuscation.

3. **Write a regression test.** The test must fail before the fix and pass after.
   The malicious input is rejected or neutralised; a representative legitimate
   input still works. Without this test, a later refactor silently reopens the
   hole.

4. **Apply, then verify.** Make the edit, run the test, and run the project's
   existing suite to catch the behaviour changes you did not intend.

5. **Record it.**
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" status <ID> fixed \
     --note "Parameterised the query at src/db/users.js:42; added a regression test asserting the injection payload is treated as data."
   ```

## What not to do

- **Do not commit or push** unless the user explicitly asks. Make the changes;
  let them review.
- **Do not batch unrelated fixes into one change.** One finding, one reviewable
  unit. A reviewer who cannot isolate a security fix cannot trust it.
- **Do not "fix" by suppression** — deleting the finding, adding a scanner
  ignore comment, or narrowing scope so it falls out of view. If a finding is
  genuinely not exploitable, mark it `rejected` with the evidence, in the
  ledger, not with a silent code comment.
- **Do not upgrade a dependency past a major version to fix a CVE** without
  flagging the breaking-change risk. Sometimes the right answer is a backport or
  a mitigation, and that is the user's call to make.

## When a fix is not yours to make

Some findings need a decision, not a patch: accepting a risk, changing an
architecture, upgrading across a breaking boundary, rotating a production
credential. For those, write the recommendation into the finding's remediation
and leave the decision to the user. Say so plainly rather than forcing a patch
that papers over it.
