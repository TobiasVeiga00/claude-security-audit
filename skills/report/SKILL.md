---
name: report
description: Generate the professional audit report from the current findings ledger — an executive summary, prioritised findings, a remediation roadmap and framework mapping, in Markdown, printable HTML, SARIF, CSV or JSON. Use for "generate the security report", "write up the findings", "export the audit", "give me a PDF-ready report".
argument-hint: "[--format markdown,html,sarif] [--min-severity medium]"
allowed-tools: Read, Write, Bash(node:*)
---

# Audit report

Turn the findings ledger into the deliverable. A security report is read by three
people at once — an executive who needs the posture in thirty seconds, an
engineer who needs the exact line and the fix, and an auditor who will challenge
every claim. The generated report serves all three; do not average them.

Current ledger:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" stats 2>&1`

Coverage:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/coverage.mjs" summary 2>&1`

---

## Before you generate

Three checks. Skipping them produces a report that reads well and misleads.

1. **Enrich with exploitation signal**, so priority reflects reality:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" enrich
   ```

2. **Validate coverage.** A report makes an implicit claim about what was
   examined. If the ledger has unresolved units, the claim is false:
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/coverage.mjs" validate
   ```
   Fix the ledger if this fails. Do not generate a report over an invalid one.

3. **Confirm triage is done.** Anything still `tentative` that you have not
   personally checked should be either confirmed, rejected, or moved to
   `needs-validation` with a blocker. A report is not a dumping ground for
   unreviewed scanner output.

## Generate

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/report.mjs" \
  --format markdown,html,sarif --out .security-audit/report/security-audit-report \
  --client "<client>" --auditor "<name>" --classification CONFIDENTIAL
```

| Format | Use |
| --- | --- |
| `markdown` | The working document — diffable, reviewable in a PR. |
| `html` | Self-contained and printable. `Ctrl+P` in a browser gives a clean PDF; no dependency needed. |
| `sarif` | SARIF 2.1.0 — upload to GitHub code scanning to see findings inline on the code. |
| `csv` | For the client's existing remediation tracker. Formula-injection safe. |
| `json` | The full machine-readable model. |

## What the report contains

Generated for you, in this order: engagement metadata and classification;
executive summary with the risk posture and severity counts; scope and rules of
engagement; methodology and the severity/priority model; the findings, each with
its boundary, evidence, reproduction and remediation; a separate **needs-validation**
section carrying no severity; the remediation roadmap by priority tier; and the
framework mapping (OWASP, CWE, ATT&CK, MASVS, WSTG).

## Reporting posture — non-negotiable

- **No invented findings.** "No findings at this depth in this scope" is a real
  and valuable result. State it with the coverage disclosure that makes it
  meaningful.
- **No severity on unproven leads.** They go in the needs-validation section
  with a named blocker.
- **No live credentials.** Everything is redacted to first four and last four
  characters, in the ledger and the report both.
- **Coverage stated honestly.** Quote the disclosure line verbatim. Units not
  examined are not assertions of safety, and the report says so.

## After generating

Give the user, in the chat, at most fifteen lines: the posture, the counts, the
two or three things to fix first, the coverage line, and the paths to the files.
The report is the deliverable; your message is the pointer to it.
