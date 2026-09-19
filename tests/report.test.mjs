import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { FindingStore } from '../scripts/lib/findings.mjs';
import { buildModel, renderMarkdown, renderHtml, renderSarif, renderCsv, riskPosture } from '../scripts/report.mjs';

const SAMPLE = [
  {
    title: 'SQL injection in the user lookup endpoint',
    severity: 'critical', confidence: 'confirmed', domain: 'code',
    cwe: 89, owasp: ['A03:2021 Injection'], attack: ['T1190'],
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epss: 0.72, kev: false,
    location: { file: 'src/api/users.js', startLine: 42, symbol: 'getUserById' },
    description: 'The identifier from the request path is concatenated into a SQL statement.',
    impact: 'An unauthenticated caller can read or modify any row in the users table.',
    evidence: [{ type: 'code', label: 'Vulnerable sink', content: 'db.query("SELECT * FROM users WHERE id=" + req.params.id)' }],
    reproduction: ["Send GET /api/users/1'%20OR%20'1'='1", 'Observe that every user row is returned.'],
    remediation: {
      summary: 'Use a parameterised query.',
      steps: ['Replace concatenation with a bound parameter.', 'Add a regression test asserting the payload is rejected.'],
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
      effort: 'small',
      patch: '-db.query("SELECT * FROM users WHERE id=" + req.params.id)\n+db.query("SELECT * FROM users WHERE id = $1", [req.params.id])',
    },
    source: { tool: 'semgrep', rule: 'js.sqli.concat' },
    exposure: 'internet', reachable: true, dataClass: 'pii',
  },
  {
    title: 'Hardcoded cloud credential committed to the repository',
    severity: 'critical', confidence: 'firm', domain: 'secrets', cwe: 798,
    location: { file: 'config/production.env', startLine: 3 },
    description: 'A long-lived access key is stored in a tracked file.',
    impact: 'Anyone with repository read access holds production credentials.',
    remediation: { summary: 'Revoke the key, rotate it, and move the secret to a managed store.', effort: 'medium' },
    source: { tool: 'gitleaks', rule: 'aws-access-key' },
  },
  {
    title: 'Dependency affected by a known exploited vulnerability',
    severity: 'high', confidence: 'confirmed', domain: 'dependencies',
    cve: ['CVE-2021-44228'], cwe: 502, kev: true, epss: 0.97,
    location: { package: 'log4j-core', version: '2.14.1', ecosystem: 'Maven' },
    description: 'The bundled version is vulnerable to remote code execution through JNDI lookup.',
    remediation: { summary: 'Upgrade to a fixed release.', effort: 'small' },
    source: { tool: 'osv-scanner', rule: 'GHSA-jfh8-c2jp-5v3q' },
    exposure: 'internet',
  },
  {
    title: 'Cross-site scripting through an unescaped template value',
    severity: 'medium', confidence: 'tentative', domain: 'web', cwe: 79,
    wstg: ['WSTG-INPV-01'],
    location: { url: 'https://app.example.com/search', parameter: 'q' },
    description: 'The search term is reflected without contextual escaping.',
    remediation: { summary: 'Escape on output using the template engine defaults.', effort: 'trivial' },
    source: { tool: 'manual review', rule: '' },
  },
  {
    // Adversarial content: this must never execute or break the markup.
    title: 'Reflected payload <script>alert(1)</script> & "quoted" | piped',
    severity: 'low', confidence: 'tentative', domain: 'web', cwe: 79,
    location: { file: 'src/views/search.ejs', startLine: 7 },
    description: 'Report-rendering hardening probe.',
    evidence: [{ type: 'code', content: '</code></pre><img src=x onerror=alert(1)>' }],
    remediation: { summary: 'n/a', effort: 'trivial' },
    source: { tool: 'fixture', rule: 'xss.render.probe' },
  },
];

function seed() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sa-report-'));
  const store = new FindingStore(dir);
  store.add(SAMPLE, { scanId: 'scan-test' });
  return { dir, store };
}

function model() {
  const { store } = seed();
  return buildModel(store.load(), {
    scope: {
      engagement: { name: 'Fixture engagement', client: 'Acme', auditor: 'Test' },
      authorization: { reference: 'SOW-1' },
      targets: { domains: ['example.com'], hosts: [], ipRanges: [], wireless: { ssids: [], bssids: [] } },
      outOfScope: { hosts: [], domains: [], ipRanges: [], notes: [] },
      rules: { staticAnalysis: true, activeTesting: false },
    },
    meta: {},
  });
}

/* ---------------------------------------------------------------- */

test('the model aggregates severity, tiers and framework coverage', () => {
  const m = model();
  assert.equal(m.totals.open, 5);
  assert.equal(m.bySeverity.critical.length, 2);
  assert.equal(m.totals.knownExploited, 1);
  assert.ok(m.frameworks.cwe['CWE-89']);
  assert.ok(m.frameworks.attack['T1190']);
  assert.ok(m.tools.includes('semgrep'));
});

test('risk posture escalates on critical findings', () => {
  assert.equal(riskPosture(model()).label, 'CRITICAL');
});

test('the KEV dependency outranks a higher-severity finding without exploit signal', () => {
  const m = model();
  const kev = m.findings.find((f) => f.kev);
  const xss = m.findings.find((f) => f.severity === 'medium');
  assert.ok(
    kev.risk.priority > xss.risk.priority,
    'a known-exploited high should outrank an unexploited medium',
  );
  assert.equal(kev.risk.tier, 'P0');
});

test('markdown renders every section and escapes table-breaking characters', () => {
  const md = renderMarkdown(model());
  for (const heading of [
    '## 1. Executive summary', '## 2. Scope and rules of engagement',
    '## 3. Methodology', '## 4. Findings', '## 5. Remediation roadmap',
  ]) {
    assert.ok(md.includes(heading), `missing ${heading}`);
  }
  assert.ok(md.includes('CISA KEV'));
  // A pipe inside a title must not split the summary table row. Count only
  // UNescaped pipes: `\|` is a literal pipe inside a cell, not a delimiter.
  const summaryRow = md.split('\n').find((l) => l.startsWith('| [SA-') && l.includes('piped'));
  assert.ok(summaryRow, 'adversarial title should appear in the findings table');
  assert.ok(summaryRow.includes('\\|'), 'the literal pipe must be escaped');
  assert.equal(
    summaryRow.split(/(?<!\\)\|/).length, 7,
    'escaped pipe must not create an extra cell',
  );
});

test('section numbering has no duplicates or gaps regardless of which sections appear', () => {
  const numbers = (md) => md.split('\n')
    .map((l) => /^## (\d+)\. /.exec(l))
    .filter(Boolean)
    .map((m) => Number(m[1]));

  // With a needs-validation section present.
  const withLeads = numbers(renderMarkdown(model()));
  assert.deepEqual(withLeads, [...withLeads].sort((a, b) => a - b), 'sections must be in order');
  assert.equal(new Set(withLeads).size, withLeads.length, 'no duplicate section numbers');
  assert.deepEqual(withLeads, withLeads.map((_, i) => i + 1), 'no gaps in numbering');

  // Without one: build a model whose only findings are confirmed.
  const { store } = seed();
  const confirmedOnly = buildModel(
    store.load().filter((f) => f.verdict !== 'needs-validation'),
    { scope: null, meta: {} },
  );
  const md = renderMarkdown(confirmedOnly);
  const withoutLeads = numbers(md);
  assert.equal(new Set(withoutLeads).size, withoutLeads.length, 'no duplicates without a leads section');
  assert.ok(!md.includes('## 5. Needs validation'));
});

test('html escapes attacker-controlled content everywhere it is embedded', () => {
  const html = renderHtml(model());
  assert.ok(!html.includes('<script>alert(1)</script>'), 'title payload must be escaped');
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'), 'evidence payload must be escaped');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('&lt;/code&gt;&lt;/pre&gt;'), 'evidence must not break out of its pre block');
  // Structural sanity.
  assert.ok(html.startsWith('<!DOCTYPE html>'));
  assert.ok(html.includes('@media print'));
  assert.ok(html.includes('prefers-color-scheme: dark'));
});

test('sarif output is well formed and carries GitHub security severity', () => {
  const sarif = renderSarif(model(), '1.0.0');
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'claude-security-audit');
  assert.ok(run.tool.driver.rules.length > 0);
  assert.equal(run.results.length, 5);

  for (const result of run.results) {
    assert.ok(result.ruleId, 'every result needs a ruleId');
    assert.ok(['error', 'warning', 'note'].includes(result.level));
    assert.ok(result.locations?.[0]?.physicalLocation?.artifactLocation?.uri);
    assert.ok(result.partialFingerprints?.securityAuditFingerprint);
  }
  for (const rule of run.tool.driver.rules) {
    assert.ok(rule.properties['security-severity'], 'GitHub needs security-severity to rank alerts');
  }
  // Must survive a round trip as strict JSON.
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(sarif)));
});

test('csv neutralises spreadsheet formula injection', () => {
  const m = model();
  m.findings[0].title = '=HYPERLINK("http://evil","click")';
  const csv = renderCsv(m);
  assert.ok(csv.includes(`"'=HYPERLINK`), 'a leading = must be prefixed so Excel does not evaluate it');
  assert.ok(csv.split('\n')[0].startsWith('id,severity,priority'));
});

test('markdown code fences survive backticks inside evidence', () => {
  const { store } = seed();
  store.add([{
    title: 'Fence probe', severity: 'low', domain: 'code',
    location: { file: 'a.md', symbol: 'probe' },
    evidence: [{ type: 'code', content: '```\nnested fence\n```' }],
    source: { tool: 'fixture', rule: 'fence.probe' },
  }], { scanId: 'scan-test' });

  const md = renderMarkdown(buildModel(store.load(), { scope: null, meta: {} }));
  assert.ok(md.includes('````'), 'nested fences require a longer outer fence');
});

/* ------------------------------------------------------------------ *
 * Report-hardening regressions (Fable report/docs audit).
 * ------------------------------------------------------------------ */

test('markdown neutralises block-injection and non-http references', () => {
  const { store } = seed();
  store.add([{
    title: 'MD probe', severity: 'high', domain: 'code', cwe: 89,
    location: { file: 'a.js', symbol: 'p' },
    description: 'fine line\n## Injected heading\n- injected list item',
    remediation: { summary: 'do it', references: ['javascript:alert(1)', 'https://good.example/fix'] },
    source: { tool: 'fixture', rule: 'md.probe' },
  }], { scanId: 'scan-test' });
  const md = renderMarkdown(buildModel(store.load(), { scope: null, meta: {} }));
  assert.ok(!/\n## Injected heading/.test(md), 'a heading in a description must not inject a section');
  assert.ok(!md.includes('javascript:alert'), 'a non-http reference must not be rendered');
  assert.ok(md.includes('https://good.example/fix'), 'an http reference is kept');
});

test('the HTML report never emits a javascript: href', () => {
  const { store } = seed();
  store.add([{
    title: 'href probe', severity: 'medium', domain: 'web', cwe: 79,
    location: { url: 'https://x/y', parameter: 'q' }, description: 'x',
    remediation: { summary: 'y', references: ['javascript:alert(1)'] },
    source: { tool: 'fixture', rule: 'href.probe' },
  }], { scanId: 'scan-test' });
  const html = renderHtml(buildModel(store.load(), { scope: null, meta: {} }));
  assert.ok(!html.includes('href="javascript:'));
});

test('SARIF gives a shared CWE rule generic metadata, not one finding title', () => {
  const { store } = seed();
  store.add([
    { title: 'First injection here', severity: 'high', domain: 'code', cwe: 89, location: { file: 'a.js', symbol: 'a' }, description: 'first', source: { tool: '', rule: '' } },
    { title: 'Totally different second', severity: 'low', domain: 'code', cwe: 89, location: { file: 'b.js', symbol: 'b' }, description: 'second', source: { tool: '', rule: '' } },
  ], { scanId: 'scan-test' });
  const sarif = renderSarif(buildModel(store.load(), { scope: null, meta: {} }), '1.0.1');
  const rule = sarif.runs[0].tool.driver.rules.find((r) => r.id === 'CWE-89');
  assert.equal(rule.name, 'CWE-89 weakness', 'the rule name is generic, not a specific finding title');
  assert.equal(sarif.runs[0].results.filter((r) => r.ruleId === 'CWE-89').length, 2);
});
