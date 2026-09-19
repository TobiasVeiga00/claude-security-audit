/**
 * Shared primitives for the Claude Security Audit toolchain.
 *
 * Design rules for everything under scripts/:
 *   - Zero runtime dependencies. Node >= 18 built-ins only.
 *   - Deterministic: same input produces byte-identical output.
 *   - Cross-platform: never shell out for something Node can do.
 *   - Quiet by default. Machine-readable on stdout, diagnostics on stderr.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

export const IS_WINDOWS = process.platform === 'win32';

/* ------------------------------------------------------------------ *
 * Hashing and identity
 * ------------------------------------------------------------------ */

export function sha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

/** Short, stable, collision-resistant-enough id for findings and cache keys. */
export function shortHash(input, length = 12) {
  return sha256(input).slice(0, length);
}

/* ------------------------------------------------------------------ *
 * Filesystem
 * ------------------------------------------------------------------ */

export function readJson(file, fallback = undefined) {
  try {
    // Strip a UTF-8 BOM: PowerShell 5.1 and Notepad prepend one, and JSON.parse
    // rejects it — which would silently turn a hand-edited scope.json into
    // "no scope" through the fallback path.
    return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    if (fallback !== undefined) return fallback;
    throw new Error(`Cannot read JSON at ${file}: ${err.message}`);
  }
}

export function writeJson(file, data, { pretty = true } = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const body = pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
  fs.writeFileSync(file, body + '\n', 'utf8');
  return file;
}

export function readLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0);
}

export function appendLine(file, line) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, line + '\n', 'utf8');
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Normalize to forward slashes so findings are identical across platforms. */
export function posix(p) {
  return p.split(path.sep).join('/');
}

/* ------------------------------------------------------------------ *
 * Directory walking
 * ------------------------------------------------------------------ */

/** Directories that never contain first-party source worth auditing. */
export const DEFAULT_IGNORE_DIRS = new Set([
  '.git', '.hg', '.svn', '.idea', '.vscode', '.vs',
  'node_modules', 'bower_components', 'jspm_packages',
  'vendor', 'Pods', 'Carthage', '.gradle', '.m2',
  'dist', 'build', 'out', 'target', 'bin', 'obj',
  '.next', '.nuxt', '.svelte-kit', '.output', '.parcel-cache', '.turbo',
  '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox',
  'venv', '.venv', 'site-packages',
  'coverage', '.nyc_output', 'htmlcov',
  '.terraform', '.serverless', '.aws-sam', 'cdk.out',
  '.cache', 'tmp', 'temp',
]);

/** Extensions that are binary or generated; reading them burns tokens for nothing. */
export const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.avif',
  '.mp3', '.mp4', '.avi', '.mov', '.webm', '.wav', '.ogg', '.flac',
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.so', '.dylib', '.dll', '.exe', '.o', '.a', '.class', '.pyc', '.pyo',
  '.wasm', '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
  '.map',
]);

/**
 * Walk a directory tree, yielding relative POSIX paths.
 * Bounded by maxFiles so a runaway monorepo cannot hang the audit.
 */
export function walk(root, {
  ignoreDirs = DEFAULT_IGNORE_DIRS,
  maxFiles = 200000,
  maxDepth = 25,
  followSymlinks = false,
} = {}) {
  const results = [];
  const seen = new Set();

  const visit = (dir, depth) => {
    if (depth > maxDepth || results.length >= maxFiles) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory: skip it, never abort the whole walk
    }
    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (ignoreDirs.has(entry.name)) continue;
        visit(full, depth + 1);
      } else if (entry.isSymbolicLink()) {
        if (!followSymlinks) continue;
        let real;
        try { real = fs.realpathSync(full); } catch { continue; }
        if (seen.has(real)) continue;
        seen.add(real);
        results.push(posix(path.relative(root, full)));
      } else if (entry.isFile()) {
        results.push(posix(path.relative(root, full)));
      }
    }
  };

  visit(root, 0);
  return results;
}

/* ------------------------------------------------------------------ *
 * Token accounting
 * ------------------------------------------------------------------ */

/**
 * Cheap token estimate. We deliberately do not ship a tokenizer:
 * a byte-ratio heuristic lands within roughly 10% for source code and costs
 * nothing. Code is denser than prose, so it uses a lower chars-per-token ratio.
 */
export function estimateTokens(text, { code = true } = {}) {
  if (!text) return 0;
  const chars = typeof text === 'string' ? text.length : String(text).length;
  return Math.ceil(chars / (code ? 3.4 : 4.0));
}

export function estimateFileTokens(file) {
  try {
    const { size } = fs.statSync(file);
    return Math.ceil(size / 3.4);
  } catch {
    return 0;
  }
}

/* ------------------------------------------------------------------ *
 * CLI plumbing
 * ------------------------------------------------------------------ */

/** Minimal, predictable argv parser: --key value, --key=value, --flag, positionals. */
export function parseArgs(argv = process.argv.slice(2)) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--') { out._.push(...argv.slice(i + 1)); break; }
    if (token.startsWith('--')) {
      const body = token.slice(2);
      const eq = body.indexOf('=');
      if (eq !== -1) {
        out[body.slice(0, eq)] = body.slice(eq + 1);
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        out[body] = argv[++i];
      } else {
        out[body] = true;
      }
    } else {
      out._.push(token);
    }
  }
  return out;
}

export function fail(message, code = 1) {
  process.stderr.write(`error: ${message}\n`);
  process.exit(code);
}

export function emit(data) {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
}

/* ------------------------------------------------------------------ *
 * Workspace resolution
 * ------------------------------------------------------------------ */

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Where the plugin itself lives. Claude Code sets CLAUDE_PLUGIN_ROOT for us. */
export function pluginRoot() {
  if (process.env.CLAUDE_PLUGIN_ROOT) return process.env.CLAUDE_PLUGIN_ROOT;
  return path.resolve(HERE, '..', '..'); // scripts/lib -> repo root
}

/** Per-project audit state. Never written inside the plugin itself. */
export function auditHome(cwd = process.cwd()) {
  return path.join(cwd, '.security-audit');
}

export function nowIso() {
  return new Date().toISOString();
}

export function hostFingerprint() {
  return {
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    host: os.hostname(),
  };
}
