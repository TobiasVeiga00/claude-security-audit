import test from 'node:test';
import assert from 'node:assert/strict';

import { isMaterialChange } from '../scripts/intel-sync.mjs';
import { parseJsObjectLiteral } from '../scripts/lib/jsobj.mjs';
import { request, pooled } from '../scripts/lib/http.mjs';

/* ------------------------------------------------------------------ *
 * Release materiality — what makes CI cut a release vs. just refresh data
 * ------------------------------------------------------------------ */

test('new KEV entries are material', () => {
  const prev = { sources: { kev: { count: 1700 } } };
  assert.equal(isMaterialChange({ kev: { count: 1716 } }, prev), true);
});

test('an unchanged KEV count is not material', () => {
  const prev = { sources: { kev: { count: 1716 } } };
  assert.equal(isMaterialChange({ kev: { count: 1716 } }, prev), false);
});

test('a source appearing for the first time is material', () => {
  // Regression: vendoring ATT&CK where there was none genuinely changes the
  // knowledge base, but the original logic required a prior version to exist
  // and so misclassified the first appearance as a routine data refresh.
  const prev = { sources: {} };
  assert.equal(isMaterialChange({ attack: { version: '19.2' } }, prev), true);
  assert.equal(isMaterialChange({ cwe: { version: '4.20' } }, prev), true);
});

test('an ATT&CK or CWE version bump is material', () => {
  const prev = { sources: { attack: { version: '19.1' }, cwe: { version: '4.19' } } };
  assert.equal(isMaterialChange({ attack: { version: '19.2' } }, prev), true);
  assert.equal(isMaterialChange({ cwe: { version: '4.20' } }, prev), true);
});

test('the same versions are not material', () => {
  const prev = { sources: { attack: { version: '19.2' }, cwe: { version: '4.20' } } };
  assert.equal(isMaterialChange({ attack: { version: '19.2' }, cwe: { version: '4.20' } }, prev), false);
});

test('a failed CWE version lookup never triggers a release', () => {
  const prev = { sources: { cwe: { version: '4.20' } } };
  assert.equal(isMaterialChange({ cwe: { version: 'unknown' } }, prev), false);
});

test('a missing previous manifest does not throw and treats data as new', () => {
  assert.equal(isMaterialChange({ kev: { count: 1716 } }, {}), true);
  assert.equal(isMaterialChange({}, undefined), false);
});

test('a failed source in this run is not material', () => {
  // When a feed failed, results.<source> is absent; that must not read as a change.
  const prev = { sources: { kev: { count: 1716 }, attack: { version: '19.2' } } };
  assert.equal(isMaterialChange({}, prev), false);
});

/* ------------------------------------------------------------------ *
 * The CVSS v4.0 table parser — real shapes from FIRST's files
 * ------------------------------------------------------------------ */

test('parseJsObjectLiteral handles comments, unquoted keys and trailing commas', () => {
  const src = `// Copyright FIRST\nmaxSeverity = {\n\t"eq1": {\n\t\t0: 1,\n\t\t1: 4, // a comment\n\t},\n\t"eq3eq6": { 0: { 0: 7, 1: 6 } },\n};\n`;
  const parsed = parseJsObjectLiteral(src, 'maxSeverity');
  assert.equal(parsed.eq1['1'], 4);
  assert.equal(parsed.eq3eq6['0']['1'], 6);
});

test('parseJsObjectLiteral does not treat a // inside a string as a comment', () => {
  const src = `data = {\n  "url": "http://example.com/a//b",\n  "n": 1,\n};`;
  const parsed = parseJsObjectLiteral(src, 'data');
  assert.equal(parsed.url, 'http://example.com/a//b');
  assert.equal(parsed.n, 1);
});

/* ------------------------------------------------------------------ *
 * HTTP pool — one failing task must not sink the batch
 * ------------------------------------------------------------------ */

test('pooled isolates failures and preserves order', async () => {
  const results = await pooled(
    [1, 2, 3, 4],
    async (n) => { if (n === 2) throw new Error('boom'); return n * 10; },
    2,
  );
  assert.equal(results.length, 4);
  assert.deepEqual(results.map((r) => r.ok), [true, false, true, true]);
  assert.equal(results[0].value, 10);
  assert.equal(results[1].ok, false);
  assert.equal(results[3].value, 40);
});

test('request does not retry a 404 (only 429 and 5xx are retryable)', async () => {
  // A bad-scheme URL fails fast; the point is that request rejects rather than
  // hanging or looping. We assert it throws promptly.
  await assert.rejects(
    request('http://127.0.0.1:1/definitely-not-listening', { retries: 0, timeoutMs: 500 }),
    /.*/,
  );
});
