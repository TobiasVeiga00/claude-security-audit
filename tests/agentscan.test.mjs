import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanAgents } from '../scripts/agentscan.mjs';

const FIXTURE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'agent-surface',
);

const scan = scanAgents(FIXTURE);
const ids = new Set(scan.risks.map((r) => r.id));

test('agentscan discovers the agent-config surface', () => {
  assert.ok(scan.inventory.configsFound >= 4, 'finds mcp, instruction, hooks and skill configs');
  const kinds = new Set(scan.discovered.map((d) => d.kind));
  for (const k of ['mcp', 'instruction', 'hooks', 'skill']) {
    assert.ok(kinds.has(k), `expected to classify a ${k} config`);
  }
});

test('malicious MCP servers are flagged and a clean one is not', () => {
  assert.ok(ids.has('mcp.remote'), 'a remote MCP endpoint');
  assert.ok(ids.has('mcp.unpinned'), 'an unpinned npx package');
  assert.ok(ids.has('mcp.shell-exec'), 'a shell run as an MCP server');
  assert.ok(ids.has('mcp.secret'), 'a credential literal in env');
  // The "clean" server (pinned-by-path, env via ${...}) must raise nothing.
  const cleanRisks = scan.risks.filter((r) => r.server === 'clean');
  assert.equal(cleanRisks.length, 0, 'a clean server must not be flagged');
});

test('a discovered credential is redacted, never echoed', () => {
  assert.ok(
    !JSON.stringify(scan).includes('EXAMPLE_placeholder_do_not_use_012345'),
    'the credential value must never appear in the output',
  );
});

test('tool poisoning, concealment and prompt injection are detected in prompts', () => {
  assert.ok(ids.has('agent.injection'), 'instruction-override in a skill');
  assert.ok(ids.has('agent.system-leak'), 'a system-prompt exfiltration attempt');
  assert.ok(ids.has('agent.conceal'), 'a hide-from-the-user directive');
});

test('a download-and-execute hook and an unrestricted tool grant are flagged', () => {
  assert.ok(ids.has('agent.hook-download-exec'), 'a curl|bash hook');
  assert.ok(ids.has('agent.broad-tools'), 'an unrestricted Bash grant');
});

test('risks are ranked with the highest severity first', () => {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  for (let i = 1; i < scan.risks.length; i++) {
    assert.ok(
      rank[scan.risks[i - 1].severity] >= rank[scan.risks[i].severity],
      'risks must be sorted by descending severity',
    );
  }
});
