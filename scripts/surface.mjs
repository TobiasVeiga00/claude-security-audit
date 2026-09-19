#!/usr/bin/env node
/**
 * Attack-surface mapper.
 *
 * This is the single most important script in the plugin. It answers, without
 * spending a token: "out of everything here, what must a security auditor
 * actually read?"
 *
 * It walks the target once, classifies every file, scores it against the signal
 * database, and returns a ranked shortlist that fits a declared token budget.
 * The model then reads dozens of files instead of thousands - typically a
 * 95-99% reduction - and still sees the places where defects actually live.
 *
 * Usage:
 *   node surface.mjs [root] [--budget 180000] [--domain web] [--json out.json]
 *                    [--top 120] [--include-tests] [--changed-only] [--since HEAD~1]
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  walk, posix, estimateTokens, readJson, parseArgs, emit, shortHash,
  nowIso, fail, BINARY_EXT, DEFAULT_IGNORE_DIRS,
} from './lib/util.mjs';
import {
  LANG_BY_EXT, PATH_SIGNALS, SINK_SIGNALS, SECRET_PATTERNS, SECRET_ALLOWLIST,
  STACK_MARKERS, FRAMEWORK_MARKERS, LOCKFILES,
} from './lib/signals.mjs';

/** Files larger than this are almost always generated; we sample rather than read. */
const MAX_CONTENT_BYTES = 512 * 1024;
const SAMPLE_BYTES = 64 * 1024;

/* ------------------------------------------------------------------ *
 * Classification
 * ------------------------------------------------------------------ */

function languageOf(file) {
  const base = path.basename(file);
  if (/^Dockerfile(\..+)?$/i.test(base) || /\.dockerfile$/i.test(base)) return 'dockerfile';
  if (/^Makefile$/i.test(base)) return 'make';
  if (/^\.env(\..+)?$/i.test(base)) return 'dotenv';
  if (/^(Gemfile|Rakefile|Podfile|Fastfile|Brewfile)$/i.test(base)) return 'ruby';
  return LANG_BY_EXT[path.extname(base).toLowerCase()] ?? null;
}

function pathScore(file) {
  let score = 0;
  const tags = new Set();
  const reasons = [];
  for (const signal of PATH_SIGNALS) {
    if (signal.re.test(file)) {
      score += signal.weight;
      signal.tags.forEach((t) => tags.add(t));
      reasons.push(signal.id);
    }
  }
  return { score, tags: [...tags], reasons };
}

/** Which sink rule sets apply to a file. YAML files get CI/k8s rules too. */
function sinkSetsFor(language, file) {
  const sets = [];
  if (language && SINK_SIGNALS[language]) sets.push([language, SINK_SIGNALS[language]]);
  if (language === 'typescript' && SINK_SIGNALS.javascript) sets.push(['javascript', SINK_SIGNALS.javascript]);
  if (language === 'scala' || language === 'groovy') sets.push(['java', SINK_SIGNALS.java]);
  if (language === 'objc') sets.push(['c', SINK_SIGNALS.c]);
  if (language === 'cpp') sets.push(['c', SINK_SIGNALS.c]);
  if (language === 'json' && /(docker-compose|\.github|k8s|kube)/i.test(file)) sets.push(['yaml', SINK_SIGNALS.yaml]);
  return sets;
}

/**
 * Line lookup over a file's newline offsets.
 *
 * Built lazily and only for files that actually matched something, then binary
 * searched. Scanning from the start of the buffer for every match turns a large
 * file with many hits into quadratic work, which is exactly the case that hurts
 * on a big repository.
 */
function makeLineIndex(content) {
  let offsets = null;
  return (index) => {
    if (offsets === null) {
      offsets = [];
      for (let i = 0; i < content.length; i++) {
        if (content.charCodeAt(i) === 10) offsets.push(i);
      }
    }
    let lo = 0;
    let hi = offsets.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (offsets[mid] < index) lo = mid + 1;
      else hi = mid;
    }
    return lo + 1;
  };
}

/* ------------------------------------------------------------------ *
 * Content analysis
 * ------------------------------------------------------------------ */

function analyzeContent(absolute, relative, language, size) {
  const result = { sinks: [], secrets: [], sampled: false };
  let content;
  try {
    if (size > MAX_CONTENT_BYTES) {
      const fd = fs.openSync(absolute, 'r');
      try {
        const buffer = Buffer.alloc(SAMPLE_BYTES);
        const read = fs.readSync(fd, buffer, 0, SAMPLE_BYTES, 0);
        content = buffer.toString('utf8', 0, read);
      } finally {
        fs.closeSync(fd); // in finally so a read error cannot leak the fd
      }
      result.sampled = true;
    } else {
      content = fs.readFileSync(absolute, 'utf8');
    }
  } catch {
    return result;
  }

  // A NUL byte in the first chunk means this is binary despite its extension.
  if (content.indexOf('\u0000') !== -1) return result;

  const lineOf = makeLineIndex(content);

  for (const [setName, rules] of sinkSetsFor(language, relative)) {
    for (const rule of rules) {
      if (rule.weight === 0) continue; // structural rules are evaluated elsewhere
      rule.re.lastIndex = 0;
      const match = rule.re.exec(content);
      if (!match) continue;
      result.sinks.push({
        id: rule.id,
        set: setName,
        line: lineOf(match.index),
        cwe: rule.cwe,
        hint: rule.hint,
        weight: rule.weight,
        // Rules whose whole purpose is to find a credential (CWE-798/-522/-321)
        // or a logged secret (CWE-532) must not print the value into the audit
        // JSON, so their excerpts are masked the same way the secret pass is.
        excerpt: maskSecrets(excerptAt(content, match.index), rule.cwe),
      });
    }
  }

  for (const pattern of SECRET_PATTERNS) {
    pattern.re.lastIndex = 0;
    let match;
    let hits = 0;
    while ((match = pattern.re.exec(content)) !== null && hits < 5) {
      hits++;
      const value = match[1] ?? match[0];
      const looksLikeSample = SECRET_ALLOWLIST.some((re) => re.test(match[0]));
      result.secrets.push({
        id: pattern.id,
        provider: pattern.provider,
        cwe: pattern.cwe,
        severity: looksLikeSample ? 'low' : pattern.severity,
        line: lineOf(match.index),
        // Never echo a live credential into the audit trail.
        redacted: redact(value),
        entropy: Number(shannonEntropy(value).toFixed(2)),
        likelySample: looksLikeSample,
      });
      if (pattern.re.lastIndex === match.index) pattern.re.lastIndex++;
    }
  }

  // Dockerfiles without any USER directive run as root.
  if (language === 'dockerfile' && !/^\s*USER\s+\S+/im.test(content)) {
    result.sinks.push({
      id: 'docker.root', set: 'dockerfile', line: 1, cwe: 'CWE-250',
      hint: 'no USER directive - container runs as root', weight: 24, excerpt: '',
    });
  }

  return result;
}

function excerptAt(content, index, radius = 90) {
  const start = Math.max(0, index - 10);
  return content.slice(start, Math.min(content.length, index + radius)).replace(/\s+/g, ' ').trim();
}

/** Mask the value after `=`/`:` for a credential/secret-class rule's excerpt. */
const SECRET_CWES = new Set(['CWE-798', 'CWE-522', 'CWE-321', 'CWE-532', 'CWE-259']);
function maskSecrets(excerpt, cwe) {
  if (!SECRET_CWES.has(cwe)) return excerpt;
  return excerpt.replace(/([=:]\s*["'`]?)([^\s"'`]{6,})/g, (_, lead, value) => `${lead}${value.slice(0, 2)}${'*'.repeat(6)}`);
}

function redact(value) {
  const str = String(value);
  if (str.length <= 10) return `${str.slice(0, 2)}${'*'.repeat(Math.max(0, str.length - 2))}`;
  return `${str.slice(0, 4)}${'*'.repeat(8)}${str.slice(-4)} (len ${str.length})`;
}

function shannonEntropy(str) {
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/* ------------------------------------------------------------------ *
 * Stack detection
 * ------------------------------------------------------------------ */

function detectStack(root, files) {
  const fileSet = new Set(files.map((f) => path.basename(f)));
  const markers = [];
  const domains = new Set();

  for (const marker of STACK_MARKERS) {
    if (fileSet.has(marker.file)) {
      markers.push(marker.stack);
      marker.domains.forEach((d) => domains.add(d));
    }
  }

  const frameworks = [];
  const pkgPath = path.join(root, 'package.json');
  if (fs.existsSync(pkgPath)) {
    // `readJson(pkgPath, {})` returns null for a file whose content is literally
    // `null`, which then crashed on `.dependencies`; guard the type.
    const raw = readJson(pkgPath, {});
    const pkg = raw && typeof raw === 'object' ? raw : {};
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    for (const [name, meta] of Object.entries(FRAMEWORK_MARKERS)) {
      if (deps[name]) {
        frameworks.push({ name, version: deps[name], ...meta });
        meta.domains.forEach((d) => domains.add(d));
      }
    }
  }
  for (const manifest of ['requirements.txt', 'pyproject.toml', 'Pipfile', 'go.mod', 'pom.xml', 'build.gradle', 'composer.json', 'Gemfile']) {
    const file = path.join(root, manifest);
    if (!fs.existsSync(file)) continue;
    let body = '';
    try { body = fs.readFileSync(file, 'utf8').toLowerCase(); } catch { continue; }
    for (const [name, meta] of Object.entries(FRAMEWORK_MARKERS)) {
      if (frameworks.some((f) => f.name === name)) continue;
      // Boundary classes include the delimiters real manifests use: `>` and `:`
      // before the name (Maven `<artifactId>`, Gradle `group:name`), and `/`
      // after it (Composer `laravel/framework`).
      if (new RegExp(`(^|[\\s"'\\[,/>:])${escapeRe(name)}([\\s"'\\]=<>~^,:/]|$)`, 'm').test(body)) {
        frameworks.push({ name, version: null, ...meta });
        meta.domains.forEach((d) => domains.add(d));
      }
    }
  }

  const languages = {};
  for (const file of files) {
    const lang = languageOf(file);
    if (!lang) continue;
    languages[lang] = (languages[lang] ?? 0) + 1;
  }

  return {
    markers: [...new Set(markers)],
    frameworks,
    languages: Object.fromEntries(Object.entries(languages).sort((a, b) => b[1] - a[1]).slice(0, 15)),
    domains: [...domains],
  };
}

function escapeRe(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* ------------------------------------------------------------------ *
 * Git signals
 * ------------------------------------------------------------------ */

function gitChangedFiles(root, since) {
  try {
    // `--relative` makes git emit paths relative to `root`, matching the
    // walker's relative paths. Without it, on a subdirectory root every path
    // mismatched and `--changed-only` silently dropped everything.
    const out = execFileSync('git', ['diff', '--name-only', '--relative', `${since}...HEAD`], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
    return new Set(out.split(/\r?\n/).filter(Boolean).map(posix));
  } catch {
    return null;
  }
}

/** Files touched recently are both riskier and more relevant to review. */
function gitChurn(root, days = 90) {
  try {
    const out = execFileSync(
      'git',
      ['log', `--since=${days}.days.ago`, '--name-only', '--relative', '--pretty=format:'],
      { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 32 * 1024 * 1024 },
    );
    const counts = new Map();
    for (const line of out.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const key = posix(line.trim());
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  } catch {
    return new Map();
  }
}

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

export function mapSurface(root, options = {}) {
  const {
    budget: rawBudget = 180000,
    top: rawTop = 120,
    includeTests = false,
    domain = null,
    changedOnly = false,
    since = 'HEAD~1',
  } = options;
  // Defend against a non-numeric budget/top from a programmatic caller so
  // usedTokens can never become NaN and the cap can never be disabled silently.
  const budget = Number.isFinite(Number(rawBudget)) && Number(rawBudget) > 0 ? Number(rawBudget) : 180000;
  const top = Number.isFinite(Number(rawTop)) && Number(rawTop) > 0 ? Number(rawTop) : 120;

  const absRoot = path.resolve(root);
  const started = Date.now();
  const allFiles = walk(absRoot);

  const changed = changedOnly ? gitChangedFiles(absRoot, since) : null;
  const churn = gitChurn(absRoot);

  const stack = detectStack(absRoot, allFiles);

  const candidates = [];
  const skipped = { binary: 0, generated: 0, tests: 0, oversized: 0, unreadable: 0, notChanged: 0 };
  let totalBytes = 0;
  let totalEstTokens = 0;

  for (const rel of allFiles) {
    const ext = path.extname(rel).toLowerCase();
    if (BINARY_EXT.has(ext)) { skipped.binary++; continue; }

    const abs = path.join(absRoot, rel);
    let size;
    try { size = fs.statSync(abs).size; } catch { skipped.unreadable++; continue; }
    totalBytes += size;
    const estTokens = Math.ceil(size / 3.4);
    totalEstTokens += estTokens;

    if (changed && !changed.has(rel)) { skipped.notChanged++; continue; }

    const { score: pScore, tags, reasons } = pathScore(rel);
    if (!includeTests && tags.includes('test')) { skipped.tests++; continue; }
    if (tags.includes('generated')) { skipped.generated++; continue; }

    const language = languageOf(rel);
    const analysis = analyzeContent(abs, rel, language, size);

    let score = pScore;
    for (const sink of analysis.sinks) score += sink.weight;
    for (const secret of analysis.secrets) {
      score += secret.likelySample ? 4 : { critical: 60, high: 40, medium: 20, low: 8 }[secret.severity] ?? 10;
    }

    const touches = churn.get(rel) ?? 0;
    if (touches > 0) score += Math.min(12, 3 + Math.log2(touches) * 3);

    // Very large files cost a lot to read; require a stronger reason.
    if (estTokens > 8000) score -= Math.min(30, (estTokens - 8000) / 1000);

    if (score <= 0 && analysis.sinks.length === 0 && analysis.secrets.length === 0) continue;

    candidates.push({
      file: rel,
      language,
      bytes: size,
      estTokens,
      score: Math.round(score),
      tags,
      pathSignals: reasons,
      sinks: analysis.sinks.map(({ weight, ...rest }) => rest),
      secrets: analysis.secrets,
      churn90d: touches,
      sampled: analysis.sampled,
    });
  }

  candidates.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file));

  // Apply the domain filter BEFORE the budget fill, so the budget is spent on
  // the files the caller actually asked for rather than filtered away after.
  const domainFilter = domain ? new Set([].concat(domain)) : null;
  const inScope = domainFilter
    ? candidates.filter((c) => c.tags.some((t) => domainFilter.has(t)) || c.sinks.some((s) => domainFilter.has(s.set)))
    : candidates;

  // Fill the budget greedily by score. A file whose estimate alone exceeds the
  // per-file cap is skipped rather than accounted as `cap` while really costing
  // its full size — that made usedTokens and the reduction percentage fiction.
  const filtered = [];
  let used = 0;
  const perFileCap = Math.max(4000, Math.floor(budget / 12));
  for (const candidate of inScope) {
    if (filtered.length >= top) break;
    const cost = Math.min(candidate.estTokens, perFileCap);
    // A file larger than the cap is read only via sampling; accept it only if
    // it was sampled, so a huge unsampled file cannot understate the budget.
    if (candidate.estTokens > perFileCap && !candidate.sampled) continue;
    if (used + cost > budget) continue;
    filtered.push(candidate);
    used += cost;
  }

  const manifests = allFiles.filter((f) => LOCKFILES.includes(path.basename(f)));

  const secretHits = candidates
    .flatMap((c) => c.secrets.map((s) => ({ file: c.file, ...s })))
    .sort((a, b) => Number(a.likelySample) - Number(b.likelySample))
    .slice(0, 100);

  return {
    scanId: `scan-${shortHash(`${absRoot}:${started}`, 8)}`,
    generatedAt: nowIso(),
    root: posix(absRoot),
    durationMs: Date.now() - started,
    stack,
    inventory: {
      filesWalked: allFiles.length,
      filesConsidered: candidates.length,
      totalBytes,
      estTokensIfReadEntirely: totalEstTokens,
      skipped,
    },
    budget: {
      requestedTokens: budget,
      usedTokens: used,
      filesSelected: filtered.length,
      reductionPercent: totalEstTokens > 0
        ? Number((100 - (used / totalEstTokens) * 100).toFixed(2))
        : 0,
    },
    hotspots: filtered,
    manifests,
    secretCandidates: secretHits,
    suggestedDomains: suggestDomains(stack, candidates),
  };
}

function suggestDomains(stack, candidates) {
  const domains = new Set(stack.domains);
  const has = (tag) => candidates.some((c) => c.tags.includes(tag) || c.sinks.some((s) => s.id.startsWith(tag)));
  if (has('entrypoint')) { domains.add('web'); domains.add('api'); }
  if (has('iac') || has('tf')) domains.add('iac');
  if (has('k8s') || has('docker')) domains.add('container');
  if (candidates.some((c) => c.secrets.length)) domains.add('secrets');
  if (candidates.some((c) => ['kotlin', 'swift', 'dart', 'objc'].includes(c.language))) domains.add('mobile');
  if (candidates.some((c) => c.tags.includes('ci'))) domains.add('dependencies');
  domains.add('code');
  return [...domains];
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('surface.mjs')) {
  const args = parseArgs();
  const root = args._[0] ?? process.cwd();
  const numeric = (value, fallback, label) => {
    if (value === undefined) return fallback;
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) fail(`--${label} must be a positive number, got "${value}"`);
    return n;
  };
  const result = mapSurface(root, {
    budget: numeric(args.budget, 180000, 'budget'),
    top: numeric(args.top, 120, 'top'),
    includeTests: args['include-tests'] === true,
    domain: args.domain ?? null,
    changedOnly: args['changed-only'] === true,
    since: args.since ?? 'HEAD~1',
  });

  if (args.json) {
    fs.mkdirSync(path.dirname(path.resolve(String(args.json))), { recursive: true });
    fs.writeFileSync(String(args.json), JSON.stringify(result, null, 2));
    process.stderr.write(`surface map written to ${args.json}\n`);
  }

  if (args.summary) {
    const b = result.budget;
    const i = result.inventory;
    process.stdout.write(
      [
        `scan ${result.scanId}  (${result.durationMs} ms)`,
        `stack: ${result.stack.markers.join(', ') || 'unknown'}`,
        `languages: ${Object.entries(result.stack.languages).slice(0, 6).map(([k, v]) => `${k}:${v}`).join(' ')}`,
        `walked ${i.filesWalked} files (~${i.estTokensIfReadEntirely.toLocaleString()} tokens if read whole)`,
        `selected ${b.filesSelected} files (~${b.usedTokens.toLocaleString()} tokens) => ${b.reductionPercent}% reduction`,
        `secret candidates: ${result.secretCandidates.length}`,
        `suggested domains: ${result.suggestedDomains.join(', ')}`,
      ].join('\n') + '\n',
    );
  } else if (!args.json) {
    emit(result);
  }
}
