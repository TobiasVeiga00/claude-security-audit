import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { FindingStore, normalizeFinding } from '../scripts/lib/findings.mjs';
import { CoverageLedger } from '../scripts/lib/coverage.mjs';
import { parseArgs } from '../scripts/lib/util.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sa-ledger-'));
const base = (over = {}) => ({
  title: 'X', severity: 'high', domain: 'code',
  location: { file: 'a.js', symbol: 'f' }, description: 'd', ...over,
});

/* ---------------------------------------------------------------- *
 * Finding ledger — regressions from the Fable audit.
 * ---------------------------------------------------------------- */

test('a human dismissal can be reverted, and triage history is preserved', () => {
  const store = new FindingStore(tmp());
  store.add([base()]);
  const id = store.load()[0].id;

  store.setStatus(id, 'false-positive', { note: 'not exploitable' });
  let f = store.load()[0];
  assert.equal(f.status, 'false-positive');
  assert.equal(f.verdict, 'rejected');
  assert.equal(f.severity, null, 'a rejected finding carries no severity');

  store.setStatus(id, 'open', { note: 'reopening after review' });
  f = store.load()[0];
  assert.equal(f.status, 'open', 'a dismissal must be revertable');
  assert.equal(f.verdict, 'confirmed');
  assert.equal(f.triage.length, 2, 'triage history survives reload');
});

test('a human verdict survives a later machine re-detection', () => {
  const store = new FindingStore(tmp());
  store.add([base()]);
  const id = store.load()[0].id;
  store.setStatus(id, 'false-positive', { note: 'checked; safe' });
  store.add([base({ source: { tool: 'semgrep', rule: 'x' } })]);
  assert.equal(store.load()[0].status, 'false-positive', 'the re-scan must not reopen it');
});

test('a validator confirmation raises confidence off the tentative default', () => {
  const store = new FindingStore(tmp());
  store.add([base()]);
  const id = store.load()[0].id;
  assert.equal(store.load()[0].confidence, 'tentative', 'findings default to tentative');
  store.setStatus(id, 'triaged', { confidence: 'firm', note: 'held on all axes' });
  assert.equal(store.load()[0].confidence, 'firm', 'a confirmation raises confidence');
  store.setStatus(id, 'triaged', { confidence: 'bogus', note: 'x' });
  assert.equal(store.load()[0].confidence, 'firm', 'an invalid confidence value is ignored, not applied');
});

test('two rule-less findings in the same file do not collide', () => {
  const a = normalizeFinding({ title: 'Hardcoded AWS key', severity: 'high', domain: 'secrets', location: { file: 'src/config.js' } });
  const b = normalizeFinding({ title: 'Debug flag enabled', severity: 'medium', domain: 'secrets', location: { file: 'src/config.js' } });
  assert.notEqual(a.fingerprint, b.fingerprint);
});

test('merged severity and priority tier never disagree', () => {
  const store = new FindingStore(tmp());
  store.add([base({ title: 'Y', severity: 'critical', location: { file: 'b.js', symbol: 'g' }, cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })]);
  store.add([base({ title: 'Y', severity: 'low', location: { file: 'b.js', symbol: 'g' }, source: { tool: 's', rule: '' }, description: '' })]);
  const f = store.load()[0];
  assert.equal(f.severity, 'critical', 'the higher severity wins');
  assert.ok(['P0', 'P1'].includes(f.risk.tier), `tier ${f.risk.tier} must match critical severity`);
});

test('a minimal re-scan does not blank human-written detail', () => {
  const store = new FindingStore(tmp());
  store.add([base({ title: 'Z', location: { file: 'c.js', symbol: 'h' }, description: 'rich description', impact: 'real impact', remediation: { summary: 'do the fix' } })]);
  store.add([base({ title: 'Z', location: { file: 'c.js', symbol: 'h' }, description: '', source: { tool: 's', rule: '' } })]);
  const f = store.load()[0];
  assert.equal(f.description, 'rich description');
  assert.equal(f.remediation.summary, 'do the fix');
});

test('rejected and accepted-risk are excluded from the open count', () => {
  const store = new FindingStore(tmp());
  store.add([base({ title: 'A', location: { file: 'a.js', symbol: 'a' } }), base({ title: 'B', location: { file: 'b.js', symbol: 'b' } })]);
  const [a, b] = store.load();
  store.setStatus(a.id, 'rejected', { note: 'disproven' });
  store.setStatus(b.id, 'accepted-risk', { note: 'business accepts it' });
  const s = store.stats();
  assert.equal(s.open, 0);
  assert.equal(s.rejected, 1);
  assert.equal(s.acceptedRisk, 1);
});

test('the CI gate blocks on open findings at or above the threshold, and nothing else', () => {
  const store = new FindingStore(tmp());
  store.add([
    base({ title: 'crit', severity: 'critical', location: { file: 'a.js', symbol: 'a' } }),
    base({ title: 'high', severity: 'high', location: { file: 'b.js', symbol: 'b' } }),
    base({ title: 'med', severity: 'medium', location: { file: 'c.js', symbol: 'c' } }),
  ]);
  assert.equal(store.blocking('high').length, 2, 'critical + high block at --fail-on high');
  assert.equal(store.blocking('critical').length, 1, 'only critical blocks at --fail-on critical');
  assert.equal(store.blocking('medium').length, 3, 'the medium is included at --fail-on medium');

  // A dismissed or accepted finding must not fail a pipeline.
  const high = store.load().find((f) => f.title === 'high');
  store.setStatus(high.id, 'accepted-risk', { note: 'business accepts it' });
  assert.equal(store.blocking('high').length, 1, 'an accepted-risk finding no longer blocks');
});

test('a .auditignore suppression clears the gate by fingerprint, and expiry re-enables it', () => {
  const dir = tmp();
  const store = new FindingStore(dir);
  store.add([base({ title: 'crit', severity: 'critical', location: { file: 'a.js', symbol: 'a' } })]);
  const f = store.load()[0];
  assert.equal(store.blocking('high').length, 1, 'blocks before suppression');

  store.addSuppression({ fingerprint: f.fingerprint, reason: 'accepted', expires: '2999-01-01' });
  assert.equal(store.blocking('high').length, 0, 'an active suppression clears the gate');

  fs.writeFileSync(path.join(dir, '.auditignore'), JSON.stringify([{ fingerprint: f.fingerprint, reason: 'x', expires: '2000-01-01' }]));
  assert.equal(store.blocking('high').length, 1, 'an expired suppression no longer hides the finding');

  fs.writeFileSync(path.join(dir, '.auditignore'), JSON.stringify([{ fingerprint: 'a-different-fingerprint', reason: 'x' }]));
  assert.equal(store.blocking('high').length, 1, 'suppression is scoped to the exact fingerprint');
});

test('diff reports findings introduced, persisting and resolved between scans', () => {
  const store = new FindingStore(tmp());
  store.add([
    base({ title: 'old', location: { file: 'a.js', symbol: 'a' } }),
    base({ title: 'gone', location: { file: 'b.js', symbol: 'b' } }),
  ], { scanId: 'scan-1' });
  store.add([
    base({ title: 'old', location: { file: 'a.js', symbol: 'a' } }),
    base({ title: 'new', location: { file: 'c.js', symbol: 'c' } }),
  ], { scanId: 'scan-2' });

  const d = store.diff('scan-1', 'scan-2');
  assert.deepEqual(d.introduced.map((f) => f.title), ['new']);
  assert.deepEqual(d.resolved.map((f) => f.title), ['gone']);
  assert.deepEqual(d.persisting.map((f) => f.title), ['old']);
});

test('a rejected verdict carries no severity or risk', () => {
  const f = normalizeFinding({ title: 'x', verdict: 'rejected', severity: 'critical', kev: true, domain: 'code', location: { file: 'a.js' } });
  assert.equal(f.severity, null);
  assert.equal(f.risk, null);
});

test('the code skeleton distinguishes a string literal from an identifier', () => {
  const a = normalizeFinding({ title: 'x', domain: 'code', location: { file: 'a.js' }, evidence: [{ type: 'code', content: 'exec("ls -la")' }], source: { tool: 't', rule: 'r' } });
  const b = normalizeFinding({ title: 'x', domain: 'code', location: { file: 'a.js' }, evidence: [{ type: 'code', content: 'query(userInput)' }], source: { tool: 't', rule: 'r' } });
  assert.notEqual(a.fingerprint, b.fingerprint);
});

test('a truncated final ledger line does not swallow the next finding', () => {
  const dir = tmp();
  const store = new FindingStore(dir);
  store.add([base({ title: 'first', location: { file: 'a.js', symbol: 'a' } })]);
  // Simulate a crash mid-append: a partial line with no trailing newline.
  fs.appendFileSync(store.file, '{"partial": true, "fingerp');
  store.add([base({ title: 'second', location: { file: 'b.js', symbol: 'b' } })]);
  const titles = store.load().map((f) => f.title).sort();
  assert.ok(titles.includes('second'), 'the finding after a truncated line must still load');
});

/* ---------------------------------------------------------------- *
 * Coverage ledger.
 * ---------------------------------------------------------------- */

test('update() enforces reason, evidence and candidate-findings invariants', () => {
  const ledger = new CoverageLedger(tmp());
  ledger.data.units = [{ id: 'u1', surface: 'http-api', boundary: 'anonymous-to-application', attackClass: 'injection', state: 'planned', evidence: [], findings: [] }];
  assert.throws(() => ledger.update('u1', { state: 'blocked' }), /reason/);
  assert.throws(() => ledger.update('u1', { state: 'covered' }), /evidence/);
  assert.throws(() => ledger.update('u1', { state: 'candidate', evidence: ['a.js'] }), /finding/);
  ledger.update('u1', { state: 'candidate', evidence: ['a.js'], findings: ['SA-1'] });
  assert.equal(ledger.data.units[0].state, 'candidate');
});

test('a reason is required afresh when moving between reason-bearing states', () => {
  const ledger = new CoverageLedger(tmp());
  ledger.data.units = [{ id: 'u1', surface: 'cli', boundary: 'cli', attackClass: 'injection', state: 'planned', evidence: [], findings: [] }];
  ledger.update('u1', { state: 'deferred', reason: 'no time' });
  assert.throws(() => ledger.update('u1', { state: 'out-of-scope' }), /fresh reason/);
});

test('a directory named constructor is not treated as set-aside by the prototype', () => {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'constructor'));
  const ledger = new CoverageLedger(dir);
  const acct = ledger.accountDirectories(dir, {});
  assert.equal(acct.find((r) => r.directory === 'constructor').disposition, 'unaccounted');
});

test('a corrupted coverage ledger is not silently reset', () => {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, '.security-audit'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.security-audit', 'coverage.json'), '{ truncated');
  assert.throws(() => new CoverageLedger(dir), /not valid JSON/);
});

/* ---------------------------------------------------------------- *
 * Arg parser.
 * ---------------------------------------------------------------- */

test('a repeated flag collects its values into an array', () => {
  const args = parseArgs(['--set-aside', 'a=x', '--set-aside', 'b=y']);
  assert.deepEqual(args['set-aside'], ['a=x', 'b=y']);
  assert.equal(parseArgs(['--json', 'out.json']).json, 'out.json', 'a single flag stays a scalar');
});
