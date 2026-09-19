#!/usr/bin/env node
/**
 * Coverage ledger CLI.
 *
 * Turns "we audited it" into a claim a reader can argue with.
 *
 * Usage:
 *   node coverage.mjs plan --surface .security-audit/surface.json --profile standard
 *   node coverage.mjs list [--state planned]
 *   node coverage.mjs mark <UNIT-ID> --state covered --evidence src/a.ts,src/b.ts
 *   node coverage.mjs dirs --scanned src,lib --set-aside "docs=documentation only"
 *   node coverage.mjs validate
 *   node coverage.mjs summary
 */

import path from 'node:path';
import { CoverageLedger, planFromSurface, PROFILES, STATES } from './lib/coverage.mjs';
import { parseArgs, emit, fail, readJson } from './lib/util.mjs';

const args = parseArgs();
const command = args._[0];
const cwd = args.cwd ? path.resolve(String(args.cwd)) : process.cwd();
const ledger = new CoverageLedger(cwd);

const list = (value) => (value ? String(value).split(',').map((s) => s.trim()).filter(Boolean) : []);

switch (command) {
  case 'plan': {
    const surfaceFile = args.surface
      ? path.resolve(String(args.surface))
      : path.join(cwd, '.security-audit', 'surface.json');
    const surface = readJson(surfaceFile, null);
    if (!surface) fail(`no surface map at ${surfaceFile}. Run scripts/surface.mjs --json <path> first.`);

    const profile = String(args.profile ?? 'standard');
    if (!PROFILES[profile]) fail(`unknown profile "${profile}". Valid: ${Object.keys(PROFILES).join(', ')}`);

    const units = planFromSurface(surface, { profile });
    const result = ledger.plan(units, { profile, scanId: surface.scanId });
    ledger.save();
    emit({ ...result, profile, note: PROFILES[profile].description, ledger: ledger.file });
    break;
  }

  case 'list': {
    const state = args.state ? String(args.state) : null;
    const units = ledger.data.units.filter((u) => !state || u.state === state);
    if (args.json) { emit(units); break; }
    for (const u of units) {
      process.stdout.write(`${u.state.padEnd(13)} ${u.attackClass.padEnd(28)} ${u.surface.padEnd(20)} ${u.subsystem}\n`);
      process.stdout.write(`${' '.repeat(13)} ${u.id}\n`);
    }
    process.stdout.write(`\n${units.length} unit(s).\n`);
    break;
  }

  case 'mark': {
    const id = args._[1];
    if (!id) fail(`usage: coverage.mjs mark <UNIT-ID> --state <${STATES.join('|')}> [--reason "..."] [--evidence a,b] [--findings ID1,ID2]`);
    try {
      const unit = ledger.update(id, {
        state: args.state ? String(args.state) : undefined,
        reason: args.reason ? String(args.reason) : '',
        evidence: list(args.evidence),
        findings: list(args.findings),
      });
      ledger.save();
      emit(unit);
    } catch (err) {
      fail(err.message);
    }
    break;
  }

  case 'dirs': {
    const setAside = {};
    for (const entry of [].concat(args['set-aside'] ?? [])) {
      for (const pair of String(entry).split(',')) {
        const eq = pair.indexOf('=');
        if (eq === -1) continue;
        setAside[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
      }
    }
    const accounting = ledger.accountDirectories(cwd, { scanned: list(args.scanned), setAside });
    ledger.save();
    emit(accounting);
    break;
  }

  case 'validate': {
    const report = ledger.validate();
    emit({ ...report, summary: ledger.summary() });
    if (!report.ok) {
      process.stderr.write(`\n${report.errors.length} coverage problem(s). A coverage claim is not credible until every unit is resolved.\n`);
      process.exit(1);
    }
    break;
  }

  case 'summary':
    emit({ ...ledger.summary(), disclosure: ledger.disclosure() });
    break;

  default:
    process.stderr.write([
      'usage: coverage.mjs <command>',
      '',
      '  plan --surface <json> [--profile quick|standard|deep]',
      '  list [--state <state>] [--json]',
      '  mark <UNIT-ID> --state <state> [--reason] [--evidence] [--findings]',
      '  dirs --scanned a,b --set-aside "docs=documentation only"',
      '  validate                 exits non-zero while any unit is unresolved',
      '  summary                  counts plus a quotable coverage disclosure',
      '',
      `  states:   ${STATES.join(', ')}`,
      `  profiles: ${Object.keys(PROFILES).join(', ')}`,
      '',
    ].join('\n'));
    process.exit(1);
}
