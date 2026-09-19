/**
 * The finding store.
 *
 * Every auditor - human, model or CLI scanner - writes into one append-only
 * JSONL ledger at `.security-audit/findings.jsonl`. That single choice buys us:
 *
 *   - Deduplication across tools that report the same defect differently.
 *   - Incremental re-audits: a finding keeps its id, history and triage verdict
 *     across runs, so "what changed since last time" is a cheap diff.
 *   - Token economy: subagents return compact finding objects instead of prose,
 *     and the orchestrator never has to re-read raw scanner output.
 *   - Auditable provenance: every finding records the tool and rule that raised
 *     it, so a client can challenge any line of the report.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  shortHash, readLines, appendLine, ensureDir, auditHome, nowIso, posix,
} from './util.mjs';
import { normalizeSeverity, severityRank, fuseRisk, scoreV31 } from './cvss.mjs';

export const DOMAINS = [
  'web', 'api', 'mobile', 'network', 'wireless', 'cloud', 'code',
  'secrets', 'dependencies', 'iac', 'container', 'llm', 'identity', 'process',
];

export const CONFIDENCE = ['tentative', 'firm', 'confirmed'];

/**
 * A finding carries exactly one verdict.
 *
 *   confirmed        the boundary crossing and its consequence were both shown.
 *   needs-validation a source-grounded hypothesis blocked by a fact this audit
 *                    could not reach - deployment config, a runtime value, a
 *                    third-party behaviour. It is NOT a low-confidence
 *                    vulnerability, and it deliberately carries NO severity.
 *   rejected         investigated and disproven.
 *
 * Keeping `needs-validation` separate is what stops a report from inflating:
 * an unproven lead reported as a "medium" is how audits lose their credibility.
 */
export const VERDICTS = ['confirmed', 'needs-validation', 'rejected'];

export const STATUSES = [
  'open', 'triaged', 'needs-validation', 'false-positive', 'rejected',
  'accepted-risk', 'fixed', 'retest-pending', 'duplicate',
];

/** Statuses that must never be counted or scored as a live vulnerability. */
export const NON_VULNERABLE_STATUSES = new Set(['false-positive', 'rejected', 'duplicate']);

/* ------------------------------------------------------------------ *
 * Fingerprinting
 * ------------------------------------------------------------------ */

/**
 * A fingerprint must survive the edits a codebase goes through between audits
 * while still separating genuinely different defects.
 *
 * It therefore hashes the *semantic* identity of a finding and deliberately
 * excludes everything volatile:
 *   - line numbers change on every unrelated edit above the defect;
 *   - identifier names change on every refactor or rename;
 *   - string literals and numbers change when payloads or config change.
 *
 * What remains is: domain, rule, CWE, the containing file/host/package, the
 * enclosing symbol when known, and - only as a last resort - the structural
 * skeleton of the offending code.
 */
export function fingerprint(finding) {
  const loc = finding.location ?? {};
  const container =
    loc.file ? posix(loc.file)
      : loc.url ? stripVolatileUrlParts(loc.url)
        : loc.package ? `pkg:${loc.package}`
          : loc.host ? `${loc.host}:${loc.port ?? ''}`
            : '';

  // A named symbol is a far better discriminator than a code snippet, because
  // it survives edits inside the function body.
  const discriminator = loc.symbol
    ? `sym:${loc.symbol}`
    : loc.parameter
      ? `param:${loc.parameter}`
      : codeSkeleton(finding.evidence?.find((e) => e.type === 'code')?.content ?? '');

  // `||` not `??`: normalizeFinding sets source.rule to '' when a producer omits
  // it, and an empty rule must fall through to the title so two rule-less
  // findings in the same file do not collide on domain+CWE+file alone.
  const rule = finding.source?.rule || finding.title || '';
  const cwe = (finding.cwe ?? []).slice().sort().join(',');

  return shortHash([finding.domain ?? '', rule, cwe, container, discriminator].join('\u0000'), 16);
}

/**
 * Reduce a code snippet to its structural skeleton: every identifier becomes a
 * single placeholder, literals collapse, whitespace disappears. Renaming a
 * variable therefore does NOT create a duplicate finding, while a structurally
 * different sink still produces a different key.
 */
function codeSkeleton(code) {
  if (!code) return '';
  // Placeholders are non-identifier glyphs so the identifier pass cannot re-tag
  // them: with letter placeholders, the `S`/`N` markers matched the identifier
  // regex and every literal collapsed into `I`, making `exec("ls")` and
  // `exec(userInput)` indistinguishable.
  return code
    .replace(/\r\n/g, '\n')
    .replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '\u0001')  // string literals
    .replace(/\b\d+(?:\.\d+)?\b/g, '\u0002')              // numeric literals
    .replace(/[A-Za-z_$][A-Za-z0-9_$]*/g, '\u0003')       // identifiers and keywords
    .replace(/\u0003(?:\u0003)+/g, '\u0003')              // collapse runs
    .replace(/\s+/g, '')
    .slice(0, 300);
}

function stripVolatileUrlParts(url) {
  try {
    const u = new URL(url);
    // Query values and fragments are usually payload noise, not identity.
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return url;
  }
}

/* ------------------------------------------------------------------ *
 * Normalisation
 * ------------------------------------------------------------------ */

const EMPTY_REMEDIATION = { summary: '', steps: [], references: [], effort: 'medium', patch: null };

/**
 * Accept a loosely-shaped finding from any producer and return the canonical
 * form. Unknown fields are preserved under `extra` rather than dropped, so a
 * scanner-specific detail is never lost.
 */
export function normalizeFinding(input, { scanId = null } = {}) {
  const known = new Set([
    'id', 'fingerprint', 'title', 'verdict', 'severity', 'confidence', 'domain', 'category',
    'cwe', 'owasp', 'masvs', 'wstg', 'asvs', 'attack', 'cve', 'cvss', 'epss', 'kev',
    'location', 'evidence', 'description', 'impact', 'reproduction', 'remediation',
    'risk', 'status', 'source', 'firstSeen', 'lastSeen', 'scanId', 'seenIn', 'tags', 'extra',
    'boundary', 'blockers', 'validationPlan', 'exposure', 'reachable', 'dataClass',
    'triage', 'corroboratedBy',
  ]);

  const verdict = VERDICTS.includes(input.verdict)
    ? input.verdict
    : (input.status === 'needs-validation' ? 'needs-validation'
      : input.status === 'rejected' ? 'rejected'
        : 'confirmed');

  const cvss = normalizeCvss(input.cvss);

  /**
   * A lead that still needs validation, or one that was rejected, has no
   * severity by construction. Any severity a producer attached is dropped
   * rather than carried, because a number on an unproven or disproven claim is
   * the number readers remember.
   */
  const scored = verdict === 'confirmed';
  const severity = scored
    ? (input.severity != null
      ? normalizeSeverity(input.severity)
      : (cvss?.base != null ? normalizeSeverity(cvss.base) : 'info'))
    : null;

  const finding = {
    id: input.id ?? null,
    fingerprint: input.fingerprint ?? null,
    title: String(input.title ?? 'Untitled finding').trim(),
    verdict,
    severity,
    confidence: CONFIDENCE.includes(input.confidence) ? input.confidence : 'tentative',
    domain: DOMAINS.includes(input.domain) ? input.domain : 'code',
    category: input.category ?? '',
    cwe: toArray(input.cwe).map(normalizeCwe).filter(Boolean),
    owasp: toArray(input.owasp),
    masvs: toArray(input.masvs),
    wstg: toArray(input.wstg),
    asvs: toArray(input.asvs),
    attack: toArray(input.attack),
    cve: toArray(input.cve).map((c) => String(c).toUpperCase()),
    cvss,
    epss: typeof input.epss === 'number' ? input.epss : null,
    kev: input.kev === true,
    location: normalizeLocation(input.location),
    evidence: toArray(input.evidence).map(normalizeEvidence).filter(Boolean),
    description: String(input.description ?? '').trim(),
    impact: String(input.impact ?? '').trim(),
    reproduction: toArray(input.reproduction).map(String),
    remediation: { ...EMPTY_REMEDIATION, ...(input.remediation ?? {}) },
    /**
     * The boundary contract. A finding that cannot name who crosses what, past
     * which control, with what observable result, is a code smell - not a
     * vulnerability. Recording it explicitly makes that claim reviewable.
     */
    boundary: input.boundary ? {
      actor: input.boundary.actor ?? '',
      input: input.boundary.input ?? '',
      control: input.boundary.control ?? '',
      crossing: input.boundary.crossing ?? '',
      result: input.boundary.result ?? '',
    } : null,
    blockers: toArray(input.blockers).map(String),
    validationPlan: toArray(input.validationPlan).map(String),
    status: verdict === 'needs-validation' ? 'needs-validation'
      : verdict === 'rejected' ? 'false-positive'
        : (STATUSES.includes(input.status) ? input.status : 'open'),
    // The fusion inputs are persisted so risk can be recomputed on merge and
    // during intel enrichment, rather than defaulting to "unknown" every time.
    exposure: input.exposure ?? null,
    reachable: typeof input.reachable === 'boolean' ? input.reachable : null,
    dataClass: input.dataClass ?? null,
    source: {
      tool: input.source?.tool ?? 'claude-security-audit',
      rule: input.source?.rule ?? '',
      raw: input.source?.raw ?? null,
    },
    firstSeen: input.firstSeen ?? nowIso(),
    lastSeen: nowIso(),
    scanId: input.scanId ?? scanId,
    seenIn: unique([...(toArray(input.seenIn)), input.scanId ?? scanId].filter(Boolean)),
    triage: input.triage,
    tags: toArray(input.tags).map(String),
  };

  const extra = {};
  for (const [key, value] of Object.entries(input)) {
    if (!known.has(key)) extra[key] = value;
  }
  if (Object.keys(extra).length) finding.extra = extra;

  finding.fingerprint ??= fingerprint(finding);
  finding.id ??= `SA-${finding.fingerprint.slice(0, 10).toUpperCase()}`;

  if (finding.triage === undefined) delete finding.triage;

  // A lead or a rejected finding gets no priority score: ranking it would
  // reintroduce the severity we just refused to assign.
  finding.risk = scored
    ? (input.risk ?? fuseRisk({
      severity: finding.severity,
      epss: finding.epss,
      kev: finding.kev,
      exposure: finding.exposure ?? inferExposure(finding),
      reachable: finding.reachable,
      dataClass: finding.dataClass,
    }))
    : null;

  return finding;
}

function toArray(value) {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function normalizeCwe(value) {
  const str = String(value).trim().toUpperCase();
  const match = /(\d+)/.exec(str);
  return match ? `CWE-${match[1]}` : null;
}

function normalizeCvss(value) {
  if (!value) return null;
  if (typeof value === 'string') {
    const scored = scoreV31(value);
    return scored.ok
      ? { vector: scored.vector, base: scored.base, version: scored.version, temporal: scored.temporal ?? null }
      : { vector: value, base: null, version: null, temporal: null };
  }
  if (typeof value === 'object') {
    if (value.vector && value.base == null) {
      const scored = scoreV31(value.vector);
      if (scored.ok) return { vector: scored.vector, base: scored.base, version: scored.version, temporal: scored.temporal ?? null };
    }
    return {
      vector: value.vector ?? null,
      base: typeof value.base === 'number' ? value.base : null,
      version: value.version ?? null,
      temporal: typeof value.temporal === 'number' ? value.temporal : null,
    };
  }
  return null;
}

function normalizeLocation(loc) {
  const base = {
    file: null, startLine: null, endLine: null, symbol: null,
    url: null, host: null, port: null, parameter: null,
    package: null, version: null, ecosystem: null,
    resource: null, region: null, ssid: null, bssid: null,
  };
  if (!loc) return base;
  const out = { ...base, ...loc };
  if (out.file) out.file = posix(String(out.file));
  return out;
}

function normalizeEvidence(item) {
  if (!item) return null;
  if (typeof item === 'string') return { type: 'note', label: '', content: item };
  return {
    type: item.type ?? 'note',
    label: item.label ?? '',
    content: typeof item.content === 'string' ? item.content : JSON.stringify(item.content ?? ''),
    redacted: item.redacted === true,
  };
}

function inferExposure(finding) {
  const loc = finding.location ?? {};
  if (loc.url || loc.host) return 'internet';
  if (['cloud', 'api', 'web'].includes(finding.domain)) return 'internet';
  if (['mobile', 'container', 'iac'].includes(finding.domain)) return 'internal';
  return 'unknown';
}

/* ------------------------------------------------------------------ *
 * Store
 * ------------------------------------------------------------------ */

export class FindingStore {
  constructor(cwd = process.cwd()) {
    this.home = auditHome(cwd);
    this.file = path.join(this.home, 'findings.jsonl');
  }

  load() {
    const byFingerprint = new Map();
    for (const line of readLines(this.file)) {
      let record;
      try { record = JSON.parse(line); } catch { continue; }
      if (!record?.fingerprint) continue;
      // Later records win; the ledger is append-only and replayed in order.
      const previous = byFingerprint.get(record.fingerprint);
      byFingerprint.set(record.fingerprint, previous ? mergeFinding(previous, record) : record);
    }
    return [...byFingerprint.values()];
  }

  /**
   * Append findings, merging with anything already known.
   * Returns a summary so a caller can report "3 new, 12 unchanged" cheaply.
   */
  add(findings, { scanId = null } = {}) {
    ensureDir(this.home);
    const existing = new Map(this.load().map((f) => [f.fingerprint, f]));
    const result = { added: 0, updated: 0, unchanged: 0, ids: [] };

    for (const raw of toArray(findings)) {
      const incoming = normalizeFinding(raw, { scanId });
      const prior = existing.get(incoming.fingerprint);

      if (!prior) {
        appendLine(this.file, JSON.stringify(incoming));
        existing.set(incoming.fingerprint, incoming);
        result.added++;
        result.ids.push(incoming.id);
        continue;
      }

      const merged = mergeFinding(prior, incoming);
      if (JSON.stringify(stripVolatile(merged)) === JSON.stringify(stripVolatile(prior))) {
        result.unchanged++;
        continue;
      }
      appendLine(this.file, JSON.stringify(merged));
      existing.set(merged.fingerprint, merged);
      result.updated++;
      result.ids.push(merged.id);
    }

    return result;
  }

  query({ severity, domain, status, minPriority, tool, since } = {}) {
    let rows = this.load();
    if (severity) {
      const floor = severityRank(severity);
      rows = rows.filter((f) => severityRank(f.severity) >= floor);
    }
    if (domain) {
      const wanted = new Set(toArray(domain));
      rows = rows.filter((f) => wanted.has(f.domain));
    }
    if (status) {
      const wanted = new Set(toArray(status));
      rows = rows.filter((f) => wanted.has(f.status));
    }
    if (typeof minPriority === 'number') {
      rows = rows.filter((f) => (f.risk?.priority ?? 0) >= minPriority);
    }
    if (tool) rows = rows.filter((f) => f.source?.tool === tool);
    if (since) rows = rows.filter((f) => f.lastSeen >= since);
    return rows.sort(byPriorityDesc);
  }

  setStatus(id, status, { note = '', by = 'auditor' } = {}) {
    if (!STATUSES.includes(status)) throw new Error(`unknown status "${status}"`);
    const target = this.load().find((f) => f.id === id || f.fingerprint === id);
    if (!target) return null;

    // A status change is a human record: it wins over any later re-scan, and it
    // moves the verdict (and therefore severity) in lockstep so the report never
    // shows a severity on a lead or a dismissed finding.
    const verdict = status === 'needs-validation' ? 'needs-validation'
      : (status === 'false-positive' || status === 'rejected') ? 'rejected'
        : ['fixed', 'accepted-risk', 'triaged', 'open', 'retest-pending', 'duplicate'].includes(status)
          ? (target.verdict === 'needs-validation' || target.verdict === 'rejected' ? 'confirmed' : target.verdict)
          : target.verdict;

    const scored = verdict === 'confirmed';
    const updated = {
      ...target,
      op: 'status',              // marks this as a deliberate human record
      status,
      verdict,
      severity: scored ? (target.severity ?? 'info') : null,
      risk: scored ? (target.risk ?? fuseRisk({
        severity: target.severity ?? 'info',
        epss: target.epss,
        kev: target.kev,
        exposure: target.exposure ?? undefined,
        reachable: target.reachable,
        dataClass: target.dataClass,
      })) : null,
      lastSeen: nowIso(),
      triage: [...(target.triage ?? []), { at: nowIso(), status, note, by }],
    };
    appendLine(this.file, JSON.stringify(updated));
    return updated;
  }

  stats() {
    const rows = this.load();
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byDomain = {};
    const byStatus = {};
    for (const f of rows) {
      // Unvalidated leads are counted on their own axis, never as severities.
      if (f.severity && counts[f.severity] !== undefined) counts[f.severity]++;
      byDomain[f.domain] = (byDomain[f.domain] ?? 0) + 1;
      byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
    }
    // Open = a live vulnerability still needing work. A dismissed, fixed,
    // accepted, duplicate or rejected finding, and an unvalidated lead, are not.
    const open = rows.filter((f) => f.verdict === 'confirmed'
      && !NON_VULNERABLE_STATUSES.has(f.status)
      && !['fixed', 'accepted-risk'].includes(f.status));
    return {
      total: rows.length,
      open: open.length,
      needsValidation: rows.filter((f) => f.verdict === 'needs-validation').length,
      rejected: rows.filter((f) => f.verdict === 'rejected').length,
      acceptedRisk: rows.filter((f) => f.status === 'accepted-risk').length,
      bySeverity: counts,
      byDomain,
      byStatus,
      p0: open.filter((f) => f.risk?.tier === 'P0').length,
      p1: open.filter((f) => f.risk?.tier === 'P1').length,
    };
  }

  /**
   * Findings introduced in one scan versus another. Uses the per-finding
   * `seenIn` scan list rather than the single `scanId`, because a finding that
   * persists unchanged keeps its original scanId while still being present in
   * later scans.
   */
  diff(previousScanId, currentScanId) {
    const rows = this.load();
    const inScan = (f, id) => (f.seenIn ?? [f.scanId]).includes(id);
    const current = rows.filter((f) => inScan(f, currentScanId));
    return {
      introduced: current.filter((f) => !inScan(f, previousScanId)),
      persisting: current.filter((f) => inScan(f, previousScanId)),
      resolved: rows.filter((f) => inScan(f, previousScanId) && !inScan(f, currentScanId)),
    };
  }

  exists() {
    return fs.existsSync(this.file);
  }
}

/**
 * Merge an incoming record onto the prior one during ledger replay.
 *
 * The ledger is append-only, so `load()` replays every record for a fingerprint
 * in order. Two kinds of record arrive:
 *   - a human status record (`op: 'status'`, written by setStatus), which is a
 *     deliberate triage verdict; and
 *   - a scanner re-detection (written by add()), which must never overwrite a
 *     human verdict or wipe human-written detail.
 */
function mergeFinding(prior, incoming) {
  const incomingIsHuman = incoming.op === 'status';

  // A human record's verdict and status are authoritative. Otherwise validation
  // is one-way (a proven finding stays proven), but a human dismissal or
  // reopening always wins.
  let verdict;
  let status;
  let triage;
  if (incomingIsHuman) {
    verdict = incoming.verdict;
    status = incoming.status;
    triage = incoming.triage ?? prior.triage; // setStatus writes the full array
  } else if (prior.op === 'status') {
    // A prior human verdict outranks a later machine re-detection.
    verdict = prior.verdict;
    status = prior.status;
    triage = prior.triage;
  } else {
    verdict = prior.verdict === 'confirmed' || incoming.verdict === 'confirmed'
      ? 'confirmed'
      : (incoming.verdict ?? prior.verdict);
    status = incoming.status ?? prior.status;
    triage = incoming.triage ?? prior.triage;
  }

  const scored = verdict === 'confirmed';
  const severity = scored
    ? (severityRank(prior.severity) >= severityRank(incoming.severity) ? prior.severity : incoming.severity)
    : null;

  // Prefer non-empty values so a minimal re-scan never blanks human-written or
  // richer prior detail.
  const keepRicher = (a, b) => (isMeaningful(b) ? b : a);
  const keepRicherText = (a, b) => (String(b ?? '').trim() ? b : a);

  const merged = {
    ...prior,
    ...incoming,
    id: prior.id,
    firstSeen: prior.firstSeen,
    verdict,
    status,
    op: incomingIsHuman ? 'status' : (prior.op ?? undefined),
    confidence: highestConfidence(prior.confidence, incoming.confidence),
    severity,
    boundary: incoming.boundary ?? prior.boundary,
    description: keepRicherText(prior.description, incoming.description),
    impact: keepRicherText(prior.impact, incoming.impact),
    cvss: keepRicher(prior.cvss, incoming.cvss),
    epss: incoming.epss ?? prior.epss,
    kev: incoming.kev || prior.kev,
    exposure: incoming.exposure ?? prior.exposure,
    reachable: typeof incoming.reachable === 'boolean' ? incoming.reachable : prior.reachable,
    dataClass: incoming.dataClass ?? prior.dataClass,
    reproduction: (incoming.reproduction ?? []).length ? incoming.reproduction : prior.reproduction,
    remediation: mergeRemediation(prior.remediation, incoming.remediation),
    cwe: unique([...(prior.cwe ?? []), ...(incoming.cwe ?? [])]),
    owasp: unique([...(prior.owasp ?? []), ...(incoming.owasp ?? [])]),
    masvs: unique([...(prior.masvs ?? []), ...(incoming.masvs ?? [])]),
    wstg: unique([...(prior.wstg ?? []), ...(incoming.wstg ?? [])]),
    attack: unique([...(prior.attack ?? []), ...(incoming.attack ?? [])]),
    cve: unique([...(prior.cve ?? []), ...(incoming.cve ?? [])]),
    evidence: dedupeEvidence([...(prior.evidence ?? []), ...(incoming.evidence ?? [])]),
    tags: unique([...(prior.tags ?? []), ...(incoming.tags ?? [])]),
    seenIn: unique([...(prior.seenIn ?? [prior.scanId].filter(Boolean)), ...(incoming.seenIn ?? [incoming.scanId].filter(Boolean))]),
    corroboratedBy: unique([
      ...(prior.corroboratedBy ?? [prior.source?.tool].filter(Boolean)),
      incoming.source?.tool,
    ].filter(Boolean)),
  };
  if (triage) merged.triage = triage; else delete merged.triage;

  // Recompute risk from the resolved severity so priority and severity never
  // disagree (a low re-detection of a critical must not carry a P4 tier).
  merged.risk = scored
    ? fuseRisk({
      severity: merged.severity,
      epss: merged.epss,
      kev: merged.kev,
      exposure: merged.exposure ?? inferExposure(merged),
      reachable: merged.reachable,
      dataClass: merged.dataClass,
    })
    : null;

  return merged;
}

function isMeaningful(value) {
  if (value == null) return false;
  if (typeof value === 'object') return Object.keys(value).length > 0 && Object.values(value).some((v) => v != null && v !== '');
  return String(value).trim() !== '';
}

function mergeRemediation(prior = {}, incoming = {}) {
  return {
    summary: String(incoming.summary ?? '').trim() ? incoming.summary : (prior.summary ?? ''),
    steps: (incoming.steps ?? []).length ? incoming.steps : (prior.steps ?? []),
    references: unique([...(prior.references ?? []), ...(incoming.references ?? [])]),
    effort: incoming.effort ?? prior.effort ?? 'medium',
    patch: incoming.patch ?? prior.patch ?? null,
  };
}

function highestConfidence(a, b) {
  return CONFIDENCE.indexOf(a) >= CONFIDENCE.indexOf(b) ? a : b;
}

function unique(list) {
  return [...new Set(list.filter(Boolean))];
}

function dedupeEvidence(items) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = `${item.type}\u0000${item.content?.slice(0, 200)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out.slice(0, 12); // evidence is for proof, not for volume
}

function stripVolatile(finding) {
  // Fields that legitimately change on every re-scan of an unchanged finding
  // are excluded from the "did anything change?" comparison, so an identical
  // re-detection appends nothing.
  const { lastSeen, scanId, seenIn, risk, ...rest } = finding;
  return rest;
}

export function byPriorityDesc(a, b) {
  const pa = a.risk?.priority ?? 0;
  const pb = b.risk?.priority ?? 0;
  if (pb !== pa) return pb - pa;
  const sa = severityRank(a.severity);
  const sb = severityRank(b.severity);
  if (sb !== sa) return sb - sa;
  return String(a.id).localeCompare(String(b.id));
}
