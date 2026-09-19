import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { mapSurface } from '../scripts/surface.mjs';
import { planFromSurface, CoverageLedger } from '../scripts/lib/coverage.mjs';

const FIXTURE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'vulnerable-app',
);

const map = mapSurface(FIXTURE, { budget: 200000, top: 50 });
const hotspot = (suffix) => map.hotspots.find((h) => h.file.endsWith(suffix));
const sinkIds = (suffix) => (hotspot(suffix)?.sinks ?? []).map((s) => s.id);

/* ---------------------------------------------------------------- */

test('the stack and relevant domains are detected', () => {
  for (const marker of ['node', 'docker', 'terraform']) {
    assert.ok(map.stack.markers.includes(marker), `expected stack marker ${marker}`);
  }
  for (const domain of ['code', 'iac', 'container', 'secrets', 'dependencies']) {
    assert.ok(map.suggestedDomains.includes(domain), `expected domain ${domain}`);
  }
});

test('dangerous sinks are located in application code', () => {
  assert.ok(sinkIds('src/api/users.js').includes('js.sqli'), 'string-built SQL');
  assert.ok(sinkIds('src/api/users.js').includes('js.ssrf'), 'user-controlled outbound request');
  assert.ok(sinkIds('src/auth/session.js').includes('js.jwt'), 'jwt.decode without verify');
  assert.ok(sinkIds('src/auth/session.js').includes('js.weak-crypto'), 'deprecated cipher factory');
});

test('infrastructure and container misconfiguration are located', () => {
  assert.ok(sinkIds('infra/main.tf').includes('tf.open-ingress'));
  assert.ok(sinkIds('infra/main.tf').includes('tf.public-bucket'));
  const docker = sinkIds('Dockerfile');
  for (const id of ['docker.latest', 'docker.secret', 'docker.insecure-fetch', 'docker.pipe-shell', 'docker.root']) {
    assert.ok(docker.includes(id), `expected ${id}`);
  }
});

/**
 * Regression: line numbers were computed against the whole file buffer rather
 * than the match offset, so every hit collapsed onto line 1.
 */
test('line numbers point at the actual match, not line 1', () => {
  const secrets = map.secretCandidates.filter((s) => s.file.endsWith('production.env'));
  assert.equal(secrets.length, 3);
  assert.deepEqual(secrets.map((s) => s.line).sort((a, b) => a - b), [1, 2, 3]);

  const jwt = hotspot('src/auth/session.js').sinks.find((s) => s.id === 'js.jwt');
  const crypto = hotspot('src/auth/session.js').sinks.find((s) => s.id === 'js.weak-crypto');
  assert.ok(jwt.line > 1 && crypto.line > jwt.line, 'sinks must carry distinct, ordered line numbers');
});

test('published example credentials are downgraded, real-looking ones are not', () => {
  const byProvider = Object.fromEntries(map.secretCandidates.map((s) => [s.provider, s]));
  assert.equal(byProvider.AWS.likelySample, true, 'AKIAIOSFODNN7EXAMPLE is AWS documentation');
  assert.equal(byProvider.AWS.severity, 'low');
  assert.equal(byProvider.Database.likelySample, false);
  assert.equal(byProvider.Database.severity, 'critical');
});

test('credentials are never echoed in full', () => {
  for (const secret of map.secretCandidates) {
    assert.ok(secret.redacted.includes('****'), 'every secret must be redacted');
    assert.ok(!secret.redacted.includes('hunter2'), 'the password must not survive redaction');
  }
});

test('test files are excluded from the attack surface by default', () => {
  assert.equal(hotspot('tests/users.test.js'), undefined);
  assert.ok(map.inventory.skipped.tests >= 1);

  const withTests = mapSurface(FIXTURE, { budget: 200000, includeTests: true });
  assert.ok(
    withTests.hotspots.some((h) => h.file.endsWith('tests/users.test.js')),
    '--include-tests must bring them back',
  );
});

test('the selection stays inside its token budget', () => {
  // The whole fixture fits in a couple of thousand tokens, so the budget only
  // bites once it is smaller than a single file.
  const tight = mapSurface(FIXTURE, { budget: 250, top: 50 });
  assert.ok(tight.budget.usedTokens <= 250, `used ${tight.budget.usedTokens} of 250`);
  assert.ok(tight.hotspots.length < map.hotspots.length, 'a smaller budget must select fewer files');

  const capped = mapSurface(FIXTURE, { budget: 200000, top: 2 });
  assert.equal(capped.hotspots.length, 2, '--top caps the selection independently of the budget');
});

test('output is deterministic across runs', () => {
  const again = mapSurface(FIXTURE, { budget: 200000, top: 50 });
  assert.deepEqual(
    map.hotspots.map((h) => [h.file, h.score]),
    again.hotspots.map((h) => [h.file, h.score]),
  );
});

/* ---------------------------------------------------------------- *
 * Coverage ledger
 * ---------------------------------------------------------------- */

test('a coverage plan is derived from the surface map and bounded by profile', () => {
  const quick = planFromSurface(map, { profile: 'quick' });
  const standard = planFromSurface(map, { profile: 'standard' });
  assert.ok(quick.length > 0);
  assert.ok(quick.length <= 25, 'the quick profile is capped');
  assert.ok(standard.length >= quick.length);
  for (const unit of standard) {
    assert.equal(unit.state, 'planned');
    assert.ok(unit.surface && unit.boundary && unit.attackClass);
  }
});

test('the ledger refuses unjustified dispositions', () => {
  const ledger = new CoverageLedger(FIXTURE);
  ledger.data.units = [];
  ledger.plan(planFromSurface(map, { profile: 'quick' }));
  const id = ledger.data.units[0].id;

  assert.throws(
    () => ledger.update(id, { state: 'blocked' }),
    /requires a reason/,
    'not looking at something must be justified',
  );
  assert.throws(
    () => ledger.update(id, { state: 'covered' }),
    /requires evidence/,
    'claiming coverage must be backed by what was read',
  );

  ledger.update(id, { state: 'covered', evidence: ['src/api/users.js'] });
  assert.equal(ledger.data.units[0].state, 'covered');
});

test('validation fails while any unit is unresolved', () => {
  const ledger = new CoverageLedger(FIXTURE);
  ledger.data.units = [];
  ledger.data.directoryAccounting = [];
  ledger.plan(planFromSurface(map, { profile: 'quick' }));

  let report = ledger.validate();
  assert.equal(report.ok, false);
  assert.ok(report.errors.some((e) => /terminal state/.test(e)));

  for (const unit of ledger.data.units) {
    ledger.update(unit.id, { state: 'deferred', reason: 'fixture' });
  }
  report = ledger.validate();
  assert.equal(report.ok, true, report.errors.join('; '));
  assert.match(ledger.disclosure(), /not assertions of safety/);
});
