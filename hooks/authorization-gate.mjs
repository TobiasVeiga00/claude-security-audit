#!/usr/bin/env node
/**
 * PreToolUse gate for Bash.
 *
 * Static analysis runs freely. Anything that puts packets on a wire is checked
 * against the engagement's rules before it executes, and denied with an
 * actionable reason when it is not covered.
 *
 * The gate fails OPEN on internal errors: a bug in this script must never brick
 * a user's shell. It fails CLOSED on scope questions, which is the only place
 * where being wrong is expensive.
 */

import { evaluateCommand } from '../scripts/lib/scope.mjs';

function respond(payload) {
  process.stdout.write(JSON.stringify(payload));
  process.exit(0);
}

function allow() {
  respond({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
  });
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

try {
  const raw = await readStdin();
  if (!raw.trim()) process.exit(0);

  const input = JSON.parse(raw);
  const command = input?.tool_input?.command;
  if (typeof command !== 'string' || !command.trim()) process.exit(0);

  const cwd = input?.cwd || process.cwd();
  const verdict = evaluateCommand(command, cwd);

  if (verdict.decision === 'allow') {
    // Stay silent unless the command was genuinely intrusive and authorized,
    // so the transcript records why it was permitted.
    if (verdict.class && !['none', 'local'].includes(verdict.class)) {
      respond({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          permissionDecisionReason: verdict.reason,
        },
        systemMessage: `[scope] ${verdict.class} authorized against ${verdict.targets.join(', ') || 'declared wireless scope'}`,
      });
    }
    process.exit(0);
  }

  respond({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: [
        `Blocked by the security-audit authorization gate.`,
        ``,
        `Activity class : ${verdict.class}`,
        `Tool(s)        : ${verdict.tools.join(', ') || 'n/a'}`,
        `Target(s)      : ${verdict.targets.join(', ') || 'n/a'}`,
        ``,
        verdict.reason,
        ``,
        `If this target IS authorized, record it with /security-audit:scope and retry.`,
        `Testing a system without written permission is not a technicality - it is the`,
        `line between an audit and an intrusion.`,
      ].join('\n'),
    },
  });
} catch (err) {
  // Never block on a gate malfunction; surface it instead.
  process.stderr.write(`authorization-gate: ${err.message}\n`);
  allow();
}
