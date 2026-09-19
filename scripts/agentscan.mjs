#!/usr/bin/env node
/**
 * Agent supply-chain scanner.
 *
 * The fastest-growing security surface in 2026 is not the application — it is the
 * developer's own agent: the MCP servers, plugins, skills, hooks and instruction
 * files that a coding agent loads and trusts. A poisoned tool description, an
 * unpinned MCP server, a hook that pipes a remote script into a shell, or a skill
 * that quietly exfiltrates data all execute with the agent's authority.
 *
 * This mirrors surface.mjs for that surface: it discovers the agent-config files
 * under a target, analyses each against a signal database, and returns a ranked
 * list of risks for a specialist to confirm — deterministically, without spending
 * a token on files that carry no signal.
 *
 * Usage:
 *   node agentscan.mjs [root] [--json out.json] [--summary]
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  walk, posix, parseArgs, emit, fail, nowIso, shortHash, DEFAULT_IGNORE_DIRS,
} from './lib/util.mjs';

/* ------------------------------------------------------------------ *
 * Discovery — which files make up the agent surface
 * ------------------------------------------------------------------ */

/** Classify a repo-relative path into an agent-config kind, or null. */
function classify(rel) {
  const p = rel.toLowerCase();
  const base = path.basename(p);
  if (base === '.mcp.json' || base === 'mcp.json') return 'mcp';
  if (/[\/](plugin|marketplace)\.json$/.test(p) && p.includes('.claude-plugin')) return 'manifest';
  if (base === 'settings.json' || base === 'settings.local.json') return p.includes('.claude') ? 'settings' : null;
  if (base === 'hooks.json') return 'hooks';
  if (['claude.md', 'agents.md', 'gemini.md'].includes(base)) return 'instruction';
  if (['.cursorrules', '.windsurfrules', '.clinerules'].includes(base)) return 'instruction';
  if (base === 'copilot-instructions.md') return 'instruction';
  if (base === 'skill.md') return 'skill';
  if (/(^|[\/])agents[\/][^\/]+\.md$/.test(p)) return 'agent';
  return null;
}

/* ------------------------------------------------------------------ *
 * Signals
 * ------------------------------------------------------------------ */

// Text patterns for instruction/description content (skills, CLAUDE.md, agent
// prompts, and MCP tool descriptions). These are the tool-poisoning and
// prompt-injection surface.
const TEXT_SIGNALS = [
  { id: 'agent.injection', re: /\b(ignore|disregard|forget)\s+(all\s+)?(your\s+|the\s+|previous\s+|prior\s+|above\s+)+(instructions|rules|prompt|guidance)\b/i, severity: 'high', cwe: 'CWE-77', hint: 'instruction-override (prompt injection / tool poisoning)' },
  { id: 'agent.system-leak', re: /\b(print|reveal|repeat|show|output|expose)\b[^\n.]{0,40}\b(system\s*prompt|your\s+instructions|initial\s+prompt)\b/i, severity: 'high', cwe: 'CWE-200', hint: 'attempt to exfiltrate the system prompt' },
  { id: 'agent.conceal', re: /\b(do\s*not|don't|never)\b[^\n.]{0,30}\b(tell|inform|mention|notify|show|reveal to)\b[^\n.]{0,20}\b(the\s+)?(user|human|operator)\b/i, severity: 'high', cwe: 'CWE-1039', hint: 'directive to hide actions from the user' },
  { id: 'agent.exfil', re: /\b(send|post|upload|exfiltrate|transmit|leak)\b[^\n]{0,60}\b(https?:\/\/|to\s+the\s+following\s+(url|endpoint|server))/i, severity: 'high', cwe: 'CWE-200', hint: 'instruction to send data to an external endpoint' },
  { id: 'agent.hidden-unicode', re: /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/, severity: 'high', cwe: 'CWE-1007', hint: 'zero-width or bidirectional characters hiding instructions' },
];

// A value that looks like a real, long-lived credential (so we never echo it).
const SECRET_RE = /\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|[A-Za-z0-9_\-]{32,})\b/;
const SECRET_KEY_RE = /(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key|access[_-]?key)/i;

function redact(value) {
  const s = String(value);
  if (s.length <= 8) return `${s.slice(0, 2)}${'*'.repeat(Math.max(0, s.length - 2))}`;
  return `${s.slice(0, 4)}${'*'.repeat(6)}${s.slice(-2)}`;
}

/* ------------------------------------------------------------------ *
 * Analysis
 * ------------------------------------------------------------------ */

function lineOf(content, index) {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

function scanText(content, rel, risks, { context = 'instruction' } = {}) {
  for (const sig of TEXT_SIGNALS) {
    sig.re.lastIndex = 0;
    const m = sig.re.exec(content);
    if (!m) continue;
    risks.push({
      id: sig.id,
      severity: sig.severity,
      cwe: sig.cwe,
      hint: sig.hint,
      file: rel,
      line: lineOf(content, m.index),
      context,
      excerpt: content.slice(Math.max(0, m.index - 10), m.index + 90).replace(/\s+/g, ' ').trim(),
    });
  }
}

/** Pull the mcpServers/servers map out of an MCP or settings document. */
function mcpServersOf(doc) {
  if (!doc || typeof doc !== 'object') return {};
  return doc.mcpServers ?? doc.servers ?? {};
}

const REMOTE_RUNNERS = new Set(['npx', 'npx.cmd', 'uvx', 'bunx', 'pnpm', 'dlx']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'pwsh']);

function scanMcp(doc, rel, risks) {
  const servers = mcpServersOf(doc);
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;
    const command = String(cfg.command ?? '');
    const cmdBase = path.basename(command).toLowerCase();
    const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
    const at = (id, severity, cwe, hint, extra = {}) => risks.push({ id, severity, cwe, hint, file: rel, server: name, context: 'mcp', ...extra });

    // A remote (SSE/HTTP) MCP server is a trust boundary: your prompts and tool
    // results cross the network to a third party.
    const url = String(cfg.url ?? cfg.href ?? '');
    if (/^(https?|wss?):\/\//i.test(url)) {
      at('mcp.remote', 'medium', 'CWE-829', 'remote MCP endpoint — prompts and results leave the machine', { excerpt: url });
    }

    // A shell invoked as a "server" runs arbitrary code with the agent's rights.
    if (SHELLS.has(cmdBase) && args.some((a) => /^(-c|\/c|-command)$/i.test(a))) {
      at('mcp.shell-exec', 'high', 'CWE-78', 'MCP server is a shell running an inline command');
    }

    // npx/uvx of a package with no version pin (or @latest) is a mutable
    // supply chain — the code you run can change under you.
    if (REMOTE_RUNNERS.has(cmdBase)) {
      const pkg = args.find((a) => a && !a.startsWith('-'));
      if (pkg && (!/@\d+\.\d+\.\d+/.test(pkg) || /@latest$/.test(pkg))) {
        at('mcp.unpinned', 'medium', 'CWE-1357', 'MCP server package is unpinned or @latest — a moving target', { excerpt: pkg });
      }
    }

    // A URL passed to node/python is a download-and-execute.
    if (args.some((a) => /^https?:\/\//i.test(a))) {
      at('mcp.remote-code', 'high', 'CWE-494', 'MCP server fetches and runs code from a URL');
    }

    // Secrets sitting in env/headers as literals.
    for (const bag of ['env', 'headers']) {
      const obj = cfg[bag];
      if (obj && typeof obj === 'object') {
        for (const [k, v] of Object.entries(obj)) {
          if (typeof v === 'string' && (SECRET_KEY_RE.test(k) || SECRET_RE.test(v)) && v.length >= 12 && !/^\$\{?[A-Z_]+\}?$/.test(v) && !v.includes('${')) {
            at('mcp.secret', 'high', 'CWE-798', `credential literal in ${bag}.${k}`, { excerpt: `${k}=${redact(v)}` });
          }
        }
      }
    }

    // Any tool/description text on the server is prompt-injection surface.
    const desc = [cfg.description, cfg.instructions, ...(Array.isArray(cfg.tools) ? cfg.tools.map((t) => t?.description) : [])]
      .filter((s) => typeof s === 'string').join('\n');
    if (desc) scanText(desc, rel, risks, { context: 'mcp-description' });
  }
}

const BROAD_TOOL_RE = /(^|[,\s])(Bash|\*)(\s*,|\s*$)|Bash\(\s*\*\s*\)/;

function scanManifestOrSettings(doc, rel, risks) {
  // Broad, unrestricted tool grants (excessive agency).
  const inspectTools = (val, where) => {
    const s = Array.isArray(val) ? val.join(',') : String(val ?? '');
    if (BROAD_TOOL_RE.test(s)) {
      risks.push({ id: 'agent.broad-tools', severity: 'medium', cwe: 'CWE-269', hint: `unrestricted tool grant in ${where} (least privilege)`, file: rel, context: 'permissions', excerpt: s.slice(0, 80) });
    }
  };
  if (doc && typeof doc === 'object') {
    if (doc.allowedTools || doc.allowed_tools) inspectTools(doc.allowedTools ?? doc.allowed_tools, 'allowedTools');
    if (doc.permissions?.allow) inspectTools(doc.permissions.allow, 'permissions.allow');
  }
}

function scanHooks(doc, rel, risks) {
  const text = JSON.stringify(doc ?? {});
  // A hook that pipes a remote fetch into a shell is a download-and-execute that
  // runs on every matching tool event.
  if (/(curl|wget|iwr|Invoke-WebRequest)[^"']*\|\s*(sudo\s+)?(ba)?sh|Invoke-Expression|\|\s*iex\b/i.test(text)) {
    risks.push({ id: 'agent.hook-download-exec', severity: 'high', cwe: 'CWE-494', hint: 'hook downloads and executes remote code on a tool event', file: rel, context: 'hook' });
  }
}

/* ------------------------------------------------------------------ *
 * Orchestration
 * ------------------------------------------------------------------ */

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function scanAgents(root) {
  const absRoot = path.resolve(root);
  const started = Date.now();
  const files = walk(absRoot, { ignoreDirs: DEFAULT_IGNORE_DIRS });

  const discovered = [];
  const risks = [];

  for (const relRaw of files) {
    const rel = posix(relRaw);
    const kind = classify(rel);
    if (!kind) continue;
    const abs = path.join(absRoot, relRaw);
    let content;
    try {
      const stat = fs.statSync(abs);
      if (stat.size > 512 * 1024) continue; // configs and prompts are small
      content = fs.readFileSync(abs, 'utf8');
    } catch { continue; }
    discovered.push({ file: rel, kind });

    if (kind === 'mcp' || kind === 'settings') {
      try { scanMcp(JSON.parse(content), rel, risks); } catch { /* not valid JSON */ }
      if (kind === 'settings') { try { scanManifestOrSettings(JSON.parse(content), rel, risks); } catch { /* */ } }
    } else if (kind === 'manifest') {
      try { scanManifestOrSettings(JSON.parse(content), rel, risks); } catch { /* */ }
    } else if (kind === 'hooks') {
      try { scanHooks(JSON.parse(content), rel, risks); } catch { /* */ }
    } else {
      // instruction / skill / agent prompt: text analysis, plus a frontmatter
      // allowed-tools check for skills and agents.
      scanText(content, rel, risks, { context: kind });
      // Only a skill's `allowed-tools` grant is judged for over-breadth: a bare
      // `Bash` there means the skill should have scoped it. An agent's `tools:`
      // grant is conventionally broad (that is how an agent runs commands), so
      // flagging it is noise, not a finding.
      const fm = content.match(/^---\n([\s\S]*?)\n---/);
      if (fm && kind === 'skill') {
        const tools = fm[1].match(/^allowed-tools:\s*(.+)$/mi);
        if (tools) scanManifestOrSettings({ allowedTools: tools[1] }, rel, risks);
      }
    }
  }

  risks.sort((a, b) => (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0) || a.file.localeCompare(b.file));

  const bySeverity = {};
  for (const r of risks) bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
  const byKind = {};
  for (const d of discovered) byKind[d.kind] = (byKind[d.kind] ?? 0) + 1;

  return {
    scanId: `agentscan-${shortHash(`${absRoot}:${started}`, 8)}`,
    generatedAt: nowIso(),
    root: posix(absRoot),
    durationMs: Date.now() - started,
    discovered,
    inventory: { configsFound: discovered.length, byKind },
    risks,
    summary: { total: risks.length, bySeverity },
  };
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('agentscan.mjs')) {
  const args = parseArgs();
  const root = args._[0] ?? process.cwd();
  const result = scanAgents(root);

  if (args.json) {
    const out = path.resolve(String(args.json));
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, JSON.stringify(result, null, 2));
    process.stderr.write(`agent surface written to ${posix(out)}\n`);
  }

  if (args.summary || !args.json) {
    const s = result.summary;
    const sev = ['critical', 'high', 'medium', 'low', 'info'].filter((k) => s.bySeverity[k]).map((k) => `${s.bySeverity[k]} ${k}`).join(', ') || 'none';
    process.stdout.write([
      `${result.scanId}  (${result.durationMs} ms)`,
      `agent configs: ${result.inventory.configsFound} (${Object.entries(result.inventory.byKind).map(([k, n]) => `${k}:${n}`).join(' ') || 'none'})`,
      `risks: ${s.total} (${sev})`,
      ...result.risks.slice(0, 20).map((r) => `  [${r.severity}] ${r.id}  ${r.file}${r.server ? ` · ${r.server}` : ''}${r.line ? `:${r.line}` : ''} — ${r.hint}`),
    ].join('\n') + '\n');
  }

  if (!args.json && args.full) emit(result);
}
