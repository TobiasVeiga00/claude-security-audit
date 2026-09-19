import test from 'node:test';
import assert from 'node:assert/strict';

import { scoreV31, validateV40, severityBand, normalizeSeverity, fuseRisk, roundUp1 } from '../scripts/lib/cvss.mjs';
import { scoreV40, macroVector, loadTables } from '../scripts/lib/cvss4.mjs';

/* ------------------------------------------------------------------ *
 * CVSS v3.1 - exact, per the FIRST specification
 * ------------------------------------------------------------------ */

test('CVSS v3.1 base scores match the specification', () => {
  const cases = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', 5.9],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
  ];
  for (const [vector, expected] of cases) {
    const result = scoreV31(vector);
    assert.equal(result.ok, true, `${vector}: ${result.error ?? ''}`);
    assert.equal(result.base, expected, vector);
  }
});

test('CVSS v3.1 temporal scoring applies E, RL and RC', () => {
  // 9.8 * E:P(0.94) * RL:O(0.95) * RC:C(1.0) = 8.7514 -> roundUp -> 8.8
  const r = scoreV31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C');
  assert.equal(r.temporal, 8.8);
  assert.equal(r.temporalSeverity, 'high');
});

test('roundUp1 uses integer arithmetic, not float rounding', () => {
  assert.equal(roundUp1(4.02), 4.1);
  assert.equal(roundUp1(4.0), 4.0);
  assert.equal(roundUp1(8.7514), 8.8);
  assert.equal(roundUp1(0.0), 0.0);
});

test('malformed vectors are rejected rather than guessed at', () => {
  assert.equal(scoreV31('not a vector').ok, false);
  assert.equal(scoreV31('CVSS:3.1/AV:N/AC:L').ok, false, 'missing base metrics');
  assert.equal(scoreV31('CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok, false, 'invalid value');
  assert.equal(scoreV31('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P').ok, false, 'unsupported version');
});

/* ------------------------------------------------------------------ *
 * CVSS v4.0
 * ------------------------------------------------------------------ */

test('CVSS v4.0 vectors are validated structurally', () => {
  assert.equal(validateV40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').ok, true);
  assert.equal(validateV40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H').ok, false, 'missing base metrics');
  assert.equal(validateV40('CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').ok, false, 'invalid value');
  assert.equal(validateV40('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').ok, false, 'wrong version');
});

test('CVSS v4.0 MacroVector derivation', () => {
  const mv = (v) => macroVector(Object.fromEntries(
    v.replace('CVSS:4.0/', '').split('/').map((p) => p.split(':')),
  ));
  assert.equal(mv('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'), '000100');
  assert.equal(mv('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), '000200');
  assert.equal(mv('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N'), '212201');
});

/**
 * These expected values were cross-checked against the official base scores
 * that NVD/CNAs publish for real CVEs, not derived from this implementation.
 */
test('CVSS v4.0 scores match FIRST\'s published values', { skip: loadTables() ? false : 'v4 tables not vendored yet (run intel-sync --only cvss)' }, () => {
  const cases = [
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 10.0],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3],
    ['CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 8.5],
    ['CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N', 1.0],
    ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0.0],
  ];
  for (const [vector, expected] of cases) {
    const r = scoreV40(vector);
    assert.equal(r.ok, true, `${vector}: ${r.reason ?? ''}`);
    assert.equal(r.score, expected, vector);
  }
});

test('CVSS v4.0 refuses to guess when the official tables are absent', () => {
  const r = scoreV40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', {
    tablesPath: '/nonexistent/v4-tables.json',
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /lookup tables are not present/);
});

/* ------------------------------------------------------------------ *
 * Severity and risk fusion
 * ------------------------------------------------------------------ */

test('severity bands follow the CVSS qualitative scale', () => {
  assert.equal(severityBand(9.8), 'critical');
  assert.equal(severityBand(9.0), 'critical');
  assert.equal(severityBand(8.9), 'high');
  assert.equal(severityBand(7.0), 'high');
  assert.equal(severityBand(4.0), 'medium');
  assert.equal(severityBand(0.1), 'low');
  assert.equal(severityBand(0), 'info');
});

test('scanner severity spellings normalise onto one scale', () => {
  assert.equal(normalizeSeverity('CRITICAL'), 'critical');
  assert.equal(normalizeSeverity('Blocker'), 'critical');
  assert.equal(normalizeSeverity('error'), 'high');
  assert.equal(normalizeSeverity('WARNING'), 'medium');
  assert.equal(normalizeSeverity('note'), 'low');
  assert.equal(normalizeSeverity('unknown'), 'info');
  assert.equal(normalizeSeverity(7.5), 'high');
  assert.equal(normalizeSeverity(null), 'info');
});

test('risk fusion ranks real-world exploitability above raw severity', () => {
  const exploitedMedium = fuseRisk({ severity: 'medium', kev: true, epss: 0.9, exposure: 'internet' });
  const theoreticalHigh = fuseRisk({ severity: 'high', kev: false, epss: 0.001, exposure: 'local', reachable: false });
  assert.ok(
    exploitedMedium.priority > theoreticalHigh.priority,
    'a medium under active exploitation must outrank an unreachable local high',
  );
  assert.equal(exploitedMedium.tier, 'P0');
});

test('proven unreachability demotes a finding and says why', () => {
  const reachable = fuseRisk({ severity: 'high', reachable: true });
  const unreachable = fuseRisk({ severity: 'high', reachable: false });
  assert.ok(unreachable.priority < reachable.priority);
  assert.ok(unreachable.rationale.some((r) => /not reachable/.test(r)));
});

test('priority stays inside 0..100 under extreme inputs', () => {
  const max = fuseRisk({ severity: 'critical', kev: true, epss: 1, exposure: 'internet', reachable: true, dataClass: 'secrets' });
  const min = fuseRisk({ severity: 'info', exposure: 'local', reachable: false, dataClass: 'public' });
  assert.ok(max.priority <= 100 && max.priority >= 0);
  assert.ok(min.priority <= 100 && min.priority >= 0);
});

/* ------------------------------------------------------------------ *
 * Regressions from the Fable scoring-core audit.
 * ------------------------------------------------------------------ */

test('CVSS v4.0 scores vectors that use the Safety level (MSI:S / MSA:S)', {
  skip: loadTables() ? false : 'v4 tables not vendored yet',
}, () => {
  const r = scoreV40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MSI:S');
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.score, 10.0);
});

test('CVSS v4.0 rounds half up like FIRST, not toward the binary expansion', {
  skip: loadTables() ? false : 'v4 tables not vendored yet',
}, () => {
  // Raw 5.05 must round to 5.1 (toFixed(1) sent it to 5.0).
  const r = scoreV40('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:H/SI:H/SA:N');
  assert.equal(r.score, 5.1);
});

test('validateV40 accepts modified metrics: MSI:S, MSA:S and M*:X', () => {
  const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  assert.equal(validateV40(`${base}/MSI:S`).ok, true);
  assert.equal(validateV40(`${base}/MSA:S`).ok, true);
  assert.equal(validateV40(`${base}/MAV:X`).ok, true);
  assert.equal(validateV40(`${base}/MSI:Z`).ok, false, 'a bogus modified value is still rejected');
});

test('CVSS v3.1 rejects an invalid Scope value rather than defaulting to Unchanged', () => {
  assert.equal(scoreV31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H').ok, false);
});

test('normalizeSeverity maps a numeric CVSS string to its band, not info', () => {
  assert.equal(normalizeSeverity('9.8'), 'critical');
  assert.equal(normalizeSeverity('7.5'), 'high');
  assert.equal(normalizeSeverity('4.0'), 'medium');
  assert.equal(normalizeSeverity('3'), 'medium', 'the 0-5 ordinal table still wins for a bare digit');
  assert.equal(normalizeSeverity('nonsense'), 'info');
});

test('fuseRisk normalises an EPSS value expressed as a percentage', () => {
  const asPercent = fuseRisk({ severity: 'high', epss: 97.4 });
  const asProbability = fuseRisk({ severity: 'high', epss: 0.974 });
  assert.equal(asPercent.priority, asProbability.priority);
  assert.ok(asPercent.rationale.some((r) => /97\.4%/.test(r)));
});
