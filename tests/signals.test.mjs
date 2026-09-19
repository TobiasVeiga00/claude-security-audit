import test from 'node:test';
import assert from 'node:assert/strict';

import { SINK_SIGNALS, PATH_SIGNALS, SECRET_PATTERNS } from '../scripts/lib/signals.mjs';
import { importScannerOutput } from '../scripts/lib/importers.mjs';

const sink = (lang, id) => SINK_SIGNALS[lang].find((s) => s.id === id);
const pathSig = (id) => PATH_SIGNALS.find((s) => s.id === id);
const hits = (re, s) => { re.lastIndex = 0; return re.test(s); };

/* ------------------------------------------------------------------ *
 * ReDoS — the SQLi rules must be linear on hostile input.
 * ------------------------------------------------------------------ */

test('the SQL sink rules do not backtrack catastrophically', () => {
  for (const [lang, id] of [['javascript', 'js.sqli'], ['python', 'py.sqli'], ['ruby', 'rb.sqli']]) {
    const evil = `.query("${'SELECT '.repeat(40000)}"`;
    const start = Date.now();
    sink(lang, id).re.lastIndex = 0;
    sink(lang, id).re.test(evil);
    const ms = Date.now() - start;
    assert.ok(ms < 200, `${id} took ${ms}ms on 280KB — possible ReDoS`);
  }
});

/* ------------------------------------------------------------------ *
 * Regressions: rules that never matched, or matched too much.
 * ------------------------------------------------------------------ */

test('the generated tag does not swallow real source', () => {
  const re = pathSig('generated').re;
  for (const ok of ['src/password-generator.js', 'src/token_gen.py', 'lib/general.js', 'src/genesis.ts', 'src/gender.py']) {
    assert.equal(hits(re, ok), false, `${ok} must not be tagged generated`);
  }
  for (const gen of ['vendor/lib.js', 'app/api.pb.go', 'dist/app.min.js']) {
    assert.equal(hits(re, gen), true, `${gen} should be tagged generated`);
  }
});

test('the llm path signal matches LLM code but not a user-agent or blockchain file', () => {
  const re = pathSig('llm').re;
  for (const ok of ['src/llm/completion.js', 'lib/prompt.py', 'app/openai-client.ts', 'rag/vectorstore.js']) {
    assert.equal(hits(re, ok), true, `${ok} should be tagged llm`);
  }
  for (const no of ['src/user-agent.js', 'src/blockchain.js', 'src/toolchain.ts']) {
    assert.equal(hits(re, no), false, `${no} must not be tagged llm`);
  }
});

test('py.eval does not fire on re.compile but does on eval', () => {
  const re = sink('python', 'py.eval').re;
  assert.equal(hits(re, 'pattern = re.compile(r"x")'), false);
  assert.equal(hits(re, 'eval(user_input)'), true);
});

test('go.error-ignored matches a discarded verification result', () => {
  const re = sink('go', 'go.error-ignored').re;
  assert.equal(hits(re, 'ok, _ := s.Authenticate(u)'), true);
  assert.equal(hits(re, '_ = tok.Verify()'), true);
});

test('c.memory use-after-free requires the same variable, not any free()', () => {
  const re = sink('c', 'c.memory').re;
  assert.equal(hits(re, 'free(p);\nfoo();\nuse(p);'), true);
  assert.equal(hits(re, 'memcpy(a, b, n);'), true, 'unbounded memory ops still match');
});

test('docker.latest catches an untagged base with a stage alias', () => {
  assert.equal(hits(sink('dockerfile', 'docker.latest').re, 'FROM ubuntu AS build'), true);
});

test('gha.unpinned flags a version tag but not a 40-char SHA', () => {
  const re = sink('yaml', 'gha.unpinned').re;
  assert.equal(hits(re, 'uses: actions/checkout@v4.1.1'), true);
  assert.equal(hits(re, `uses: actions/checkout@${'a'.repeat(40)}`), false);
});

test('the OpenAI secret pattern does not also match an Anthropic key', () => {
  const openai = SECRET_PATTERNS.find((p) => p.id === 'openai-key');
  openai.re.lastIndex = 0;
  assert.equal(openai.re.test(`sk-ant-api03-${'a'.repeat(30)}`), false);
  openai.re.lastIndex = 0;
  assert.equal(openai.re.test(`sk-proj-${'a'.repeat(40)}`), true);
});

/* ------------------------------------------------------------------ *
 * Importers — defensive parsing, secret redaction, kind mapping.
 * ------------------------------------------------------------------ */

test('importers degrade to an empty list on schema drift instead of throwing', () => {
  const cases = [
    ['sarif', '{"runs":{}}'],
    ['sarif', '{"runs":[{"results":{}}]}'],
    ['semgrep', '{"results":{}}'],
    ['trivy', '{"Results":{}}'],
    ['grype', '{"matches":{}}'],
    ['osv-scanner', '{"results":[{"packages":{}}]}'],
    ['kics', '{"queries":[{"files":{}}]}'],
    ['prowler', '{"findings":{}}'],
    ['prowler', '[null]'],
    ['gitleaks', '[null]'],
    ['nuclei', 'not json at all'],
  ];
  for (const [tool, raw] of cases) {
    assert.doesNotThrow(() => importScannerOutput(tool, raw), `${tool} threw on ${raw}`);
  }
});

test('prowler json-ocsf imports FAILs, skips PASSes, and reads OCSF severity', () => {
  const raw = JSON.stringify([
    {
      status_code: 'FAIL',
      severity_id: 4,
      finding_info: { title: 'S3 bucket is public', desc: 'Bucket allows public read', uid: 'prowler-s3-1' },
      resources: [{ uid: 'arn:aws:s3:::my-bucket', region: 'us-east-1', type: 'AwsS3Bucket' }],
      cloud: { provider: 'aws' },
      remediation: { desc: 'Block public access', references: ['https://docs.aws.amazon.com/s3'] },
      unmapped: { check_id: 's3_bucket_public_access' },
    },
    {
      status_code: 'PASS',
      severity_id: 1,
      finding_info: { title: 'Passing check' },
      resources: [{ uid: 'arn:aws:s3:::ok' }],
    },
  ]);
  const findings = importScannerOutput('prowler', raw);
  assert.equal(findings.length, 1, 'only the FAIL becomes a finding');
  const [f] = findings;
  assert.equal(f.title, 'S3 bucket is public');
  assert.equal(f.severity, 'high', 'OCSF severity_id 4 maps to high');
  assert.equal(f.domain, 'cloud');
  assert.equal(f.location.resource, 'arn:aws:s3:::my-bucket');
  assert.equal(f.location.region, 'us-east-1');
  assert.equal(f.location.provider, 'aws');
  assert.equal(f.source.rule, 's3_bucket_public_access');
});

test('SARIF result kinds map correctly', () => {
  const one = (kind) => importScannerOutput('sarif', JSON.stringify({
    runs: [{ results: [{ ruleId: 'x', kind, message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.js' } } }] }] }],
  }));
  assert.equal(one('pass').length, 0, 'a pass is not a finding');
  assert.equal(one('notApplicable').length, 0);
  assert.equal(one('informational')[0].verdict, 'needs-validation');
  assert.equal(one('fail')[0].verdict, 'confirmed');
});

test('a bandit hardcoded-password finding redacts the credential and reads its CWE', () => {
  const raw = JSON.stringify({ results: [{ test_id: 'B105', issue_text: 'hardcoded', issue_cwe: { id: 259 }, filename: 'a.py', code: 'PASSWORD = "hunter2"' }] });
  const [f] = importScannerOutput('bandit', raw);
  assert.deepEqual(f.cwe, ['CWE-259']);
  assert.ok(!JSON.stringify(f.evidence).includes('hunter2'), 'the credential must be redacted');
});

test('a CodeQL-style zero-padded CWE normalises to match the plugin ids', () => {
  const raw = JSON.stringify({
    runs: [{ tool: { driver: { rules: [{ id: 'r', properties: { tags: ['external/cwe/cwe-079'] } }] } }, results: [{ ruleId: 'r', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.js' } } }] }] }],
  });
  assert.deepEqual(importScannerOutput('sarif', raw)[0].cwe, ['CWE-79']);
});

test('nuclei and trufflehog accept a JSON array as well as NDJSON', () => {
  const arr = importScannerOutput('nuclei', '[{"template-id":"x","info":{"name":"n","severity":"high"}}]');
  assert.equal(arr.length, 1);
  assert.equal(arr[0].title, 'n');
});
