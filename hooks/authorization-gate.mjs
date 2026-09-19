#!/usr/bin/env node
/**
 * PreToolUse gate for Bash.
 *
 * Static analysis runs freely. Anything that puts packets on a wire is checked
 * against the engagement's rules before it executes, and denied with an
 * actionable reason when it is not covered.
 *
 * Failure policy: a bug in this gate must never brick an ordinary shell, so a
 * plain command (git, npm, a build) is allowed even if evaluation throws. But a
 * command that even looks intrusive fails CLOSED on any malfunction — a gate
 * error must not become a scanning bypass.
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

function deny(reason) {
  respond({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  });
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * A cheap "does this look intrusive at all" check, used only on the error path.
 * If evaluateCommand throws, we must not fail open for a command that mentions a
 * scanner or exploitation tool.
 */
const INTRUSIVE_HINT = /(^|[\s;&|/\('"`])(nmap|masscan|rustscan|naabu|zmap|nuclei|nikto|sqlmap|commix|xsser|tplmap|hydra|medusa|ncrack|patator|aircrack-ng|airodump-ng|aireplay-ng|airmon-ng|airbase-ng|wifite|hcxdumptool|reaver|bully|pixiewps|bettercap|kismet|wifiphisher|eaphammer|metasploit|msfconsole|msfvenom|beef|responder|crackmapexec|netexec|nxc|impacket|evil-winrm|mimikatz|bloodhound|kerbrute|hping3|slowloris|goldeneye|slowhttptest|gobuster|ffuf|feroxbuster|dirb|dirsearch|wfuzz|wpscan|joomscan|whatweb|zap|zap-cli|amass|katana|hakrawler|arjun|sslyze|sslscan|testssl|testssl\.sh|enum4linux|smbclient|rpcclient|ldapsearch|snmpwalk|hashcat|john|ophcrack|frida|objection|drozer|mdk3|mdk4|prowler|scoutsuite|pacu|cloudfox|kube-bench|kubescape|openvas|nessus|lynis)($|[\s;&|/\('"`])/i;

// Keep the raw input in module scope so the error path can inspect it without
// re-reading the already-consumed stdin stream.
let rawInput = '{}';

try {
  rawInput = await readStdin();
  if (!rawInput.trim()) process.exit(0);

  const input = JSON.parse(rawInput);
  let command = input?.tool_input?.command;

  // A Bash command is normally a string; coerce an exec-form array rather than
  // silently allowing it, and ignore anything else empty.
  if (Array.isArray(command)) command = command.join(' ');
  if (typeof command !== 'string' || !command.trim()) process.exit(0);

  const cwd = input?.cwd || process.cwd();
  const verdict = evaluateCommand(command, cwd);

  if (verdict.decision === 'allow') {
    // Stay silent unless the command was genuinely intrusive and authorized, so
    // the transcript records why it was permitted.
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

  if (verdict.decision === 'ask') {
    respond({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: verdict.reason,
      },
    });
  }

  deny([
    'Blocked by the security-audit authorization gate.',
    '',
    `Activity class : ${verdict.class}`,
    `Tool(s)        : ${verdict.tools.join(', ') || 'n/a'}`,
    `Target(s)      : ${verdict.targets.join(', ') || 'n/a'}`,
    '',
    verdict.reason,
    '',
    'If this target IS authorized, record it with /security-audit:scope and retry.',
    'Testing a system without written permission is not a technicality - it is the',
    'line between an audit and an intrusion.',
  ].join('\n'));
} catch (err) {
  process.stderr.write(`authorization-gate: ${err.message}\n`);
  // Fail CLOSED for anything that looks intrusive; allow ordinary commands.
  let command = '';
  try {
    const parsed = JSON.parse(rawInput)?.tool_input?.command;
    command = Array.isArray(parsed) ? parsed.join(' ') : String(parsed ?? '');
  } catch { /* unparseable: treat as non-intrusive plain command */ }

  if (INTRUSIVE_HINT.test(command)) {
    deny('The authorization gate could not evaluate this command and it references an intrusive tool, so it was denied as a precaution. Re-run it in a form the gate can parse, or declare scope with /security-audit:scope.');
  }
  allow();
}
