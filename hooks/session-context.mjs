#!/usr/bin/env node
/**
 * SessionStart hook.
 *
 * Speaks only when it has something actionable to say. A plugin that greets
 * you on every single session start is a plugin people uninstall, so the
 * default path here is total silence.
 *
 * It surfaces three things, and nothing else:
 *   1. An audit already in progress in this project, with its open P0/P1 count.
 *   2. Rules of engagement that are active or have expired.
 *   3. Vendored intelligence that has gone stale enough to mislead.
 */

import fs from 'node:fs';
import path from 'node:path';

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

try {
  const raw = await readStdin();
  const input = raw.trim() ? JSON.parse(raw) : {};
  const cwd = input?.cwd || process.cwd();
  const home = path.join(cwd, '.security-audit');

  // Nothing set up here: stay quiet. Most sessions are not audits.
  if (!fs.existsSync(home)) process.exit(0);

  const notes = [];

  /* -- open findings -- */
  const ledger = path.join(home, 'findings.jsonl');
  if (fs.existsSync(ledger)) {
    const byFingerprint = new Map();
    for (const line of fs.readFileSync(ledger, 'utf8').split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        if (record?.fingerprint) byFingerprint.set(record.fingerprint, record);
      } catch { /* a truncated line must not break the session */ }
    }
    const open = [...byFingerprint.values()]
      .filter((f) => !['false-positive', 'fixed', 'duplicate', 'needs-validation'].includes(f.status));
    const p0 = open.filter((f) => f.risk?.tier === 'P0').length;
    const p1 = open.filter((f) => f.risk?.tier === 'P1').length;
    const leads = [...byFingerprint.values()].filter((f) => f.verdict === 'needs-validation').length;

    if (open.length > 0) {
      const parts = [`${open.length} open security finding${open.length === 1 ? '' : 's'} in this project`];
      if (p0) parts.push(`${p0} P0`);
      if (p1) parts.push(`${p1} P1`);
      if (leads) parts.push(`${leads} awaiting validation`);
      notes.push(`${parts.join(', ')}. Run /security-audit:report for the current picture.`);
    }
  }

  /* -- rules of engagement -- */
  const scope = readJson(path.join(home, 'scope.json'));
  if (scope?.authorization?.granted) {
    const endsAt = scope.engagement?.endsAt ? Date.parse(scope.engagement.endsAt) : null;
    if (endsAt && Date.now() > endsAt) {
      notes.push(`The engagement "${scope.engagement?.name || 'unnamed'}" expired on ${scope.engagement.endsAt}. Active testing is blocked until it is re-authorized.`);
    } else if (endsAt) {
      const daysLeft = Math.ceil((endsAt - Date.now()) / 86400000);
      if (daysLeft <= 3) {
        notes.push(`The engagement "${scope.engagement?.name || 'unnamed'}" ends in ${daysLeft} day${daysLeft === 1 ? '' : 's'}.`);
      }
    }
  }

  /* -- intelligence freshness -- */
  const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT
    ?? path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
  const manifest = readJson(path.join(pluginRoot, 'intel', 'MANIFEST.json'));
  if (manifest?.generatedAt) {
    const ageDays = (Date.now() - Date.parse(manifest.generatedAt)) / 86400000;
    if (ageDays > 14) {
      notes.push(`Vendored threat intelligence is ${Math.round(ageDays)} days old. Update the plugin, or run its intel-sync, before relying on KEV or ATT&CK data.`);
    }
  }

  if (notes.length === 0) process.exit(0);

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'SessionStart',
      additionalContext: `[security-audit] ${notes.join(' ')}`,
    },
  }));
} catch {
  // A broken hook must never block a session from starting.
  process.exit(0);
}
