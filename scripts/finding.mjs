#!/usr/bin/env node
/**
 * Finding ledger CLI.
 *
 * This is how every auditor - model or human - writes into the audit. Findings
 * arrive as JSON rather than prose, which is what keeps the orchestrator's
 * context small and the report reproducible.
 *
 * Usage:
 *   node finding.mjs add --file candidates.json        # array or single object
 *   echo '{...}' | node finding.mjs add -              # from stdin
 *   node finding.mjs list [--severity high] [--domain code] [--status open]
 *   node finding.mjs status <ID> <status> [--note "..."]
 *   node finding.mjs stats
 *   node finding.mjs show <ID>
 *   node finding.mjs import --tool semgrep --file results.json
 */

import fs from 'node:fs';
import path from 'node:path';
import { FindingStore, STATUSES, VERDICTS } from './lib/findings.mjs';
import { parseArgs, emit, fail, readJson } from './lib/util.mjs';
import { importScannerOutput, SUPPORTED_IMPORTERS } from './lib/importers.mjs';

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  const args = parseArgs();
  const command = args._[0];
  const cwd = args.cwd ? path.resolve(String(args.cwd)) : process.cwd();
  const store = new FindingStore(cwd);

  switch (command) {
    case 'add': {
      let payload;
      if (args.file && args.file !== '-') {
        payload = readJson(path.resolve(String(args.file)));
      } else {
        const raw = await readStdin();
        if (!raw.trim()) fail('no JSON on stdin. Pass --file <path> or pipe a finding object.');
        try { payload = JSON.parse(raw); } catch (err) { fail(`invalid JSON on stdin: ${err.message}`); }
      }

      const findings = Array.isArray(payload) ? payload : [payload];
      const problems = findings.flatMap(validateShape);
      if (problems.length) fail(`rejected ${problems.length} malformed finding(s):\n  - ${problems.join('\n  - ')}`);

      const result = store.add(findings, { scanId: args.scan ? String(args.scan) : null });
      emit({ ...result, ledger: store.file });
      break;
    }

    case 'list': {
      const all = store.query({
        severity: args.severity,
        domain: args.domain ? String(args.domain).split(',') : undefined,
        status: args.status ? String(args.status).split(',') : undefined,
        minPriority: args.priority ? Number(args.priority) : undefined,
        tool: args.tool,
      });
      // `--limit N` caps the output cross-platform, so skill preambles do not
      // depend on a POSIX `| head` that fails under PowerShell.
      const limit = args.limit !== undefined ? Number(args.limit) : undefined;
      const rows = Number.isFinite(limit) && limit >= 0 ? all.slice(0, limit) : all;
      if (args.json) { emit(rows); break; }
      if (rows.length === 0) { process.stdout.write('No findings match.\n'); break; }
      for (const f of rows) {
        const sev = (f.severity ?? f.verdict).padEnd(8);
        const tier = (f.risk?.tier ?? '--').padEnd(3);
        process.stdout.write(`${f.id}  ${sev} ${tier} ${f.domain.padEnd(13)} ${f.title}\n`);
      }
      const suffix = rows.length < all.length ? ` of ${all.length}` : '';
      process.stdout.write(`\n${rows.length}${suffix} finding(s).\n`);
      break;
    }

    case 'show': {
      const id = args._[1];
      if (!id) fail('usage: finding.mjs show <ID>');
      const found = store.load().find((f) => f.id === id || f.fingerprint === id);
      if (!found) fail(`no finding with id ${id}`);
      emit(found);
      break;
    }

    case 'status': {
      const [, id, status] = args._;
      if (!id || !status) fail(`usage: finding.mjs status <ID> <${STATUSES.join('|')}> [--note "..."]`);
      if (!STATUSES.includes(status)) fail(`unknown status "${status}". Valid: ${STATUSES.join(', ')}`);
      // A bare `--note` yields the boolean true; require a real, non-empty reason.
      const note = typeof args.note === 'string' ? args.note.trim() : '';
      if (['false-positive', 'rejected', 'accepted-risk'].includes(status) && !note) {
        fail(`status "${status}" requires --note "<what you checked>". A dismissal without a reason is not reviewable.`);
      }
      const updated = store.setStatus(id, status, { note, by: args.by ? String(args.by) : 'auditor', confidence: args.confidence ? String(args.confidence) : undefined });
      if (!updated) fail(`no finding with id ${id}`);
      emit({ id: updated.id, status: updated.status, verdict: updated.verdict, note });
      break;
    }

    case 'stats':
      emit(store.stats());
      break;

    case 'import': {
      const tool = args.tool ? String(args.tool) : null;
      const file = args.file ? path.resolve(String(args.file)) : null;
      if (!tool || !file) {
        fail(`usage: finding.mjs import --tool <${SUPPORTED_IMPORTERS.join('|')}> --file <results>`);
      }
      if (!fs.existsSync(file)) fail(`no such file: ${file}`);
      const findings = importScannerOutput(tool, fs.readFileSync(file, 'utf8'), { root: cwd });
      const result = store.add(findings, { scanId: args.scan ? String(args.scan) : `${tool}-${Date.now()}` });
      emit({ tool, parsed: findings.length, ...result });
      break;
    }

    case 'diff': {
      const [, previous, current] = args._;
      if (!previous || !current) fail('usage: finding.mjs diff <previousScanId> <currentScanId> [--fail-on-new]');
      const brief = (f) => ({ id: f.id, severity: f.severity, tier: f.risk?.tier ?? null, domain: f.domain, title: f.title, location: f.location });
      const d = store.diff(String(previous), String(current));
      emit({
        previousScanId: String(previous),
        currentScanId: String(current),
        introduced: d.introduced.map(brief),
        resolved: d.resolved.map(brief),
        persisting: d.persisting.length,
      });
      // For pipelines that must not regress: a new finding fails the step.
      if (args['fail-on-new'] && d.introduced.length) process.exit(2);
      break;
    }

    case 'gate': {
      const threshold = args['fail-on'] ? String(args['fail-on']) : 'high';
      const valid = ['critical', 'high', 'medium', 'low', 'info'];
      if (!valid.includes(threshold)) fail(`unknown --fail-on severity "${threshold}". Valid: ${valid.join(', ')}`);
      const blocking = store.blocking(threshold);
      const bySeverity = {};
      for (const f of blocking) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      emit({ failOn: threshold, blocking: blocking.length, bySeverity, ids: blocking.map((f) => f.id) });
      // Exit 2 (distinct from a usage error) so CI can gate on open findings.
      if (blocking.length) process.exit(2);
      break;
    }

    default:
      process.stderr.write([
        'usage: finding.mjs <command>',
        '',
        '  add --file <json> | -            add findings (array or single object)',
        '  import --tool <t> --file <f>     parse scanner output into findings',
        '  list [--severity] [--domain]     list findings, highest priority first',
        '  show <ID>                        full detail for one finding',
        '  status <ID> <status> --note ...  record a triage verdict',
        '  stats                            counts by severity, domain and status',
        '  diff <prevScan> <currScan>       what changed between two scans (--fail-on-new)',
        '  gate --fail-on <severity>        exit non-zero if an open finding is >= severity (CI)',
        '',
        `  statuses: ${STATUSES.join(', ')}`,
        `  verdicts: ${VERDICTS.join(', ')}`,
        `  importers: ${SUPPORTED_IMPORTERS.join(', ')}`,
        '',
      ].join('\n'));
      process.exit(1);
  }
}

/** Reject findings that cannot possibly be reviewed, with an actionable message. */
function validateShape(finding, index) {
  const problems = [];
  const label = finding?.title ? `"${String(finding.title).slice(0, 50)}"` : `#${index}`;

  if (finding === null || typeof finding !== 'object' || Array.isArray(finding)) {
    return [`#${index}: each finding must be a JSON object`];
  }
  if (!finding.title) problems.push(`${label}: title is required`);
  if (!finding.location || typeof finding.location !== 'object' || Array.isArray(finding.location)
    || Object.values(finding.location).every((v) => v == null)) {
    problems.push(`${label}: a location object is required — a finding nobody can navigate to is not actionable`);
  }
  // A lead is a lead whether it was declared via `verdict` or via `status`.
  const isLead = finding.verdict === 'needs-validation' || finding.status === 'needs-validation';
  if (isLead) {
    if (!(finding.blockers ?? []).length) {
      problems.push(`${label}: a needs-validation lead requires blockers — name the fact you could not reach`);
    }
  } else if (!finding.description && !finding.impact && !finding.boundary?.result) {
    // A boundary whose `result` slot is filled already states the consequence,
    // which is exactly what a description or impact would carry.
    problems.push(`${label}: a confirmed finding needs a description, an impact statement, or a boundary.result`);
  }
  return problems;
}

main().catch((err) => {
  process.stderr.write(`finding: ${err.message}\n`);
  process.exit(1);
});
