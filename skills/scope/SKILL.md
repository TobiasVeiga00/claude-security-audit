---
name: scope
description: Define or inspect the rules of engagement for an audit — authorized targets, exclusions, permitted activity and the authorization record. Required before any active testing, wireless work, or scanning of a live host. Use for "set up scope", "rules of engagement", "am I allowed to scan X", "authorize this pentest".
argument-hint: "[show | init | check \"<command>\"]"
allowed-tools: Read, Write, AskUserQuestion, Bash(node:*)
---

# Rules of engagement

Static analysis of code already on disk is always allowed. Everything that puts
a packet on a wire goes through this document first.

This is not ceremony. Scanning a host you were not asked to test is, depending
on jurisdiction, a crime — and it is the fastest way for an audit to become the
incident. The gate exists to make the authorized path the easy one.

Current state:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" show 2>&1`

---

## Dry-run a command

If the user asked whether something is permitted — `check "<command>"` — just
answer:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "nmap -sV app.example.com"
```

Report the decision, the activity class, and the exact reason. If it is denied,
say what would need to change.

## Establishing scope

Ask these in **one** `AskUserQuestion` call:

1. **What is your relationship to the target?**
   - *I own it* — your own code, your own infrastructure.
   - *I have a signed engagement* — pentest, audit, consultancy.
   - *It is in a bug bounty programme* — scope comes from the programme rules.
   - *Internal assessment* — your employer's assets, with a mandate.

2. **What is in scope?** Domains, hosts, IP ranges, repositories, cloud
   accounts, mobile app identifiers, wireless SSIDs and BSSIDs.

3. **What is explicitly out of scope?** Almost every real engagement has
   exclusions — a payment subsystem, a third-party host, a production database.
   Ask for them; people forget to volunteer them.

4. **What activity is permitted?**
   - `passiveRecon` — DNS, certificate transparency, public sources.
   - `activeTesting` — port scanning, web scanning, fuzzing.
   - `exploitation` — proving a vulnerability by using it.
   - `denialOfService` — almost always false. Confirm explicitly if true.

Then write it:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" init \
  --name "Acme Q3 assessment" --client "Acme" --type authorized-pentest --until 2026-12-31

node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" add-target \
  --domains acme.com,api.acme.com --ip-ranges 203.0.113.0/24

node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" exclude \
  --domains payments.acme.com --note "Third-party processor; contractually out of scope."

node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" allow --rules passiveRecon,activeTesting

node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" authorize \
  --by "Jane Okafor, CISO" --reference "SOW-2026-114" --until 2026-12-31
```

`--by` and `--reference` are both required. An authorization nobody can trace
back to a document is not an authorization.

## Self-owned targets

`--type self-owned` grants authorization immediately and enables passive recon,
on the operator's assertion that they own the asset. Active testing and
exploitation still have to be turned on deliberately.

State plainly, once: *this records your assertion of ownership; it does not
verify it, and it does not substitute for permission from anyone else whose
systems or data are involved.*

## Wireless is different

Radio attacks reach every device in range, not only the one you meant. So:

- Wireless work needs `targets.wireless.ssids` or `.bssids` declared explicitly.
- Every SSID and BSSID on a command line must be one that was declared.
- Deauthentication is a denial of service. It needs `denialOfService: true`,
  and it affects bystanders on shared spectrum. Say so before enabling it.

## What this cannot do

The gate checks your declared scope against your commands. It cannot verify that
your authorization is genuine, that the document says what you think it says, or
that the target is who you believe it is. Those remain yours.

If the user pushes to disable the gate: comply if they insist, tell them once
what it protects against, and record it in the scope document so the report
reflects how the engagement was actually run.
