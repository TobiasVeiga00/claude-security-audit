/**
 * The coverage ledger.
 *
 * "We audited the application" is not a claim anyone can check. "We planned 84
 * units of surface x boundary x attack class, covered 79, deferred 3 with
 * reasons and blocked 2 because the deployment config was unavailable" is.
 *
 * The ledger exists to make a coverage claim FALSIFIABLE. Every unit must reach
 * a terminal state, and the states that mean "we did not look" must carry a
 * reason. A reader can then argue with the plan instead of trusting the
 * conclusion - which is the whole point of an audit.
 *
 * It also does the unglamorous accounting that catches the classic mistake:
 * a top-level directory nobody opened because nobody noticed it existed.
 */

import fs from 'node:fs';
import path from 'node:path';
import { auditHome, readJson, writeJson, nowIso, shortHash, ensureDir } from './util.mjs';

/* ------------------------------------------------------------------ *
 * Taxonomy
 * ------------------------------------------------------------------ */

/** Where untrusted input can arrive. */
export const SURFACES = [
  'http-api', 'web-ui', 'graphql', 'websocket', 'rpc',
  'cli', 'ipc', 'file-parser', 'message-queue', 'scheduled-job',
  'database', 'cache', 'object-storage',
  'cloud-control-plane', 'container-runtime', 'ci-pipeline',
  'mobile-app', 'wireless-radio', 'third-party-dependency', 'llm-prompt',
];

/** Who is on each side of the line being tested. */
export const BOUNDARIES = [
  'anonymous-to-application',
  'user-to-other-user',
  'user-to-admin',
  'tenant-to-tenant',
  'application-to-operating-system',
  'application-to-internal-network',
  'build-to-runtime',
  'third-party-to-application',
  'client-to-server-trust',
  'sandbox-escape',
];

/** What kind of defect is being hunted. */
export const ATTACK_CLASSES = [
  'injection', 'cross-site-scripting', 'deserialization', 'template-injection',
  'authentication', 'session-management', 'access-control', 'business-logic',
  'cryptography', 'secrets-management', 'transport-security',
  'input-validation', 'path-traversal', 'file-upload',
  'server-side-request-forgery', 'xml-external-entity', 'cross-site-request-forgery',
  'open-redirect', 'race-condition', 'resource-exhaustion', 'memory-safety',
  'supply-chain', 'configuration', 'logging-and-monitoring', 'data-exposure',
  'prompt-injection', 'platform-integration', 'wireless-protocol',
];

export const STATES = [
  'planned',      // identified, not started
  'in-progress',  // being worked
  'covered',      // examined; requires evidence
  'candidate',    // produced one or more findings
  'blocked',      // could not examine; requires a reason
  'deferred',     // deliberately postponed; requires a reason
  'out-of-scope', // excluded by the engagement; requires a reason
];

const TERMINAL_STATES = new Set(['covered', 'candidate', 'blocked', 'deferred', 'out-of-scope']);
const REASON_REQUIRED = new Set(['blocked', 'deferred', 'out-of-scope']);
const EVIDENCE_REQUIRED = new Set(['covered', 'candidate']);

/** Breadth and redundancy change with the profile. The evidence bar never does. */
export const PROFILES = {
  quick: { maxUnits: 25, description: 'Highest-signal surfaces only. A pre-merge sanity pass, not an audit.' },
  standard: { maxUnits: 90, description: 'Every surface that carries untrusted input, one pass each.' },
  deep: { maxUnits: 400, description: 'Full matrix including low-yield combinations and a second pass on high-value boundaries.' },
};

/* ------------------------------------------------------------------ *
 * Ledger
 * ------------------------------------------------------------------ */

export function ledgerPath(cwd = process.cwd()) {
  return path.join(auditHome(cwd), 'coverage.json');
}

export function unitId({ surface, boundary, attackClass, subsystem }) {
  return `${surface}/${boundary}/${attackClass}/${shortHash(subsystem ?? '', 6)}`;
}

export function createUnit({ surface, boundary, attackClass, subsystem, rationale = '' }) {
  return {
    id: unitId({ surface, boundary, attackClass, subsystem }),
    surface,
    boundary,
    attackClass,
    subsystem: subsystem ?? '',
    rationale,
    state: 'planned',
    reason: '',
    evidence: [],
    findings: [],
    updatedAt: nowIso(),
  };
}

export class CoverageLedger {
  constructor(cwd = process.cwd()) {
    this.cwd = cwd;
    this.file = ledgerPath(cwd);
    this.data = readJson(this.file, null) ?? {
      version: 1,
      scanId: null,
      profile: 'standard',
      createdAt: nowIso(),
      updatedAt: nowIso(),
      directoryAccounting: [],
      units: [],
    };
  }

  save() {
    this.data.updatedAt = nowIso();
    ensureDir(path.dirname(this.file));
    writeJson(this.file, this.data);
    return this.file;
  }

  plan(units, { profile = 'standard', scanId = null } = {}) {
    this.data.profile = profile;
    if (scanId) this.data.scanId = scanId;
    const existing = new Map(this.data.units.map((u) => [u.id, u]));
    let added = 0;
    for (const unit of units) {
      if (existing.has(unit.id)) continue;
      existing.set(unit.id, unit);
      added++;
    }
    this.data.units = [...existing.values()];
    return { added, total: this.data.units.length };
  }

  /**
   * Record the disposition of a unit. The invariants that make the ledger
   * worth anything are enforced here, not left to the caller's discipline.
   */
  update(id, { state, reason = '', evidence = [], findings = [] } = {}) {
    const unit = this.data.units.find((u) => u.id === id);
    if (!unit) throw new Error(`unknown coverage unit "${id}"`);
    if (state && !STATES.includes(state)) throw new Error(`unknown state "${state}"`);

    if (state && REASON_REQUIRED.has(state) && !reason && !unit.reason) {
      throw new Error(`state "${state}" requires a reason: why was ${id} not examined?`);
    }
    const mergedEvidence = [...new Set([...(unit.evidence ?? []), ...evidence])];
    if (state && EVIDENCE_REQUIRED.has(state) && mergedEvidence.length === 0) {
      throw new Error(`state "${state}" requires evidence: what was actually read or run for ${id}?`);
    }

    Object.assign(unit, {
      state: state ?? unit.state,
      reason: reason || unit.reason,
      evidence: mergedEvidence,
      findings: [...new Set([...(unit.findings ?? []), ...findings])],
      updatedAt: nowIso(),
    });
    return unit;
  }

  /**
   * Account for every top-level directory in the target. A directory that was
   * never opened and never consciously set aside is the commonest way an audit
   * silently misses an entire component.
   */
  accountDirectories(root, { scanned = [], setAside = {} } = {}) {
    const entries = fs.readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
      .map((e) => e.name)
      .sort();

    this.data.directoryAccounting = entries.map((name) => ({
      directory: name,
      disposition: scanned.includes(name) ? 'scanned'
        : setAside[name] ? 'set-aside'
          : 'unaccounted',
      reason: setAside[name] ?? '',
    }));

    return this.data.directoryAccounting;
  }

  /**
   * Validate the ledger. Returns a report rather than throwing, so a caller can
   * present every problem at once instead of the first one.
   */
  validate() {
    const errors = [];
    const warnings = [];

    for (const unit of this.data.units) {
      if (!SURFACES.includes(unit.surface)) warnings.push(`${unit.id}: unknown surface "${unit.surface}"`);
      if (!BOUNDARIES.includes(unit.boundary)) warnings.push(`${unit.id}: unknown boundary "${unit.boundary}"`);
      if (!ATTACK_CLASSES.includes(unit.attackClass)) warnings.push(`${unit.id}: unknown attack class "${unit.attackClass}"`);

      if (!TERMINAL_STATES.has(unit.state)) {
        errors.push(`${unit.id}: still "${unit.state}" — every unit must reach a terminal state before a coverage claim is made`);
      }
      if (REASON_REQUIRED.has(unit.state) && !unit.reason) {
        errors.push(`${unit.id}: state "${unit.state}" without a reason`);
      }
      if (EVIDENCE_REQUIRED.has(unit.state) && (unit.evidence ?? []).length === 0) {
        errors.push(`${unit.id}: state "${unit.state}" without evidence`);
      }
      if (unit.state === 'candidate' && (unit.findings ?? []).length === 0) {
        errors.push(`${unit.id}: marked "candidate" but no finding id is attached`);
      }
    }

    for (const row of this.data.directoryAccounting ?? []) {
      if (row.disposition === 'unaccounted') {
        errors.push(`directory "${row.directory}" was neither scanned nor explicitly set aside`);
      }
    }

    return { ok: errors.length === 0, errors, warnings };
  }

  summary() {
    const byState = {};
    for (const unit of this.data.units) byState[unit.state] = (byState[unit.state] ?? 0) + 1;

    const examined = (byState.covered ?? 0) + (byState.candidate ?? 0);
    const total = this.data.units.length;

    return {
      profile: this.data.profile,
      total,
      byState,
      examined,
      coveragePercent: total ? Number(((examined / total) * 100).toFixed(1)) : 0,
      notExamined: {
        blocked: byState.blocked ?? 0,
        deferred: byState.deferred ?? 0,
        outOfScope: byState['out-of-scope'] ?? 0,
      },
      directories: this.data.directoryAccounting ?? [],
    };
  }

  /** A short, honest paragraph a report can quote verbatim. */
  disclosure() {
    const s = this.summary();
    const parts = [
      `Coverage was planned as ${s.total} unit${s.total === 1 ? '' : 's'} of surface x trust boundary x attack class under the "${s.profile}" profile.`,
      `${s.examined} were examined (${s.coveragePercent}%).`,
    ];
    const gaps = [];
    if (s.notExamined.blocked) gaps.push(`${s.notExamined.blocked} blocked`);
    if (s.notExamined.deferred) gaps.push(`${s.notExamined.deferred} deferred`);
    if (s.notExamined.outOfScope) gaps.push(`${s.notExamined.outOfScope} out of scope`);
    if (gaps.length) {
      parts.push(`${gaps.join(', ')}; each is listed with its reason in the coverage ledger.`);
    }
    parts.push('Units that were not examined are not assertions of safety.');
    return parts.join(' ');
  }
}

/* ------------------------------------------------------------------ *
 * Planning from an attack-surface map
 * ------------------------------------------------------------------ */

/**
 * Which attack classes are worth planning for a given surface. Planning the
 * full cartesian product would produce mostly nonsense units and dilute the
 * coverage number until it means nothing.
 */
const RELEVANT = {
  'http-api': ['injection', 'access-control', 'authentication', 'session-management', 'input-validation', 'server-side-request-forgery', 'business-logic', 'data-exposure', 'resource-exhaustion'],
  'web-ui': ['cross-site-scripting', 'cross-site-request-forgery', 'open-redirect', 'session-management', 'access-control', 'data-exposure'],
  graphql: ['access-control', 'injection', 'resource-exhaustion', 'data-exposure', 'business-logic'],
  websocket: ['authentication', 'access-control', 'input-validation', 'resource-exhaustion'],
  rpc: ['deserialization', 'access-control', 'input-validation'],
  cli: ['injection', 'path-traversal', 'input-validation'],
  ipc: ['platform-integration', 'access-control', 'deserialization'],
  'file-parser': ['deserialization', 'xml-external-entity', 'memory-safety', 'path-traversal', 'resource-exhaustion', 'file-upload'],
  'message-queue': ['deserialization', 'access-control', 'input-validation'],
  'scheduled-job': ['injection', 'access-control', 'configuration'],
  database: ['injection', 'access-control', 'cryptography', 'data-exposure'],
  cache: ['data-exposure', 'access-control', 'configuration'],
  'object-storage': ['access-control', 'configuration', 'data-exposure'],
  'cloud-control-plane': ['access-control', 'configuration', 'secrets-management', 'logging-and-monitoring'],
  'container-runtime': ['configuration', 'sandbox-escape', 'supply-chain', 'secrets-management'],
  'ci-pipeline': ['supply-chain', 'secrets-management', 'injection', 'access-control'],
  'mobile-app': ['platform-integration', 'cryptography', 'data-exposure', 'transport-security', 'secrets-management', 'authentication'],
  'wireless-radio': ['wireless-protocol', 'authentication', 'cryptography', 'transport-security'],
  'third-party-dependency': ['supply-chain'],
  'llm-prompt': ['prompt-injection', 'access-control', 'data-exposure', 'resource-exhaustion'],
};

const DEFAULT_BOUNDARY = {
  'http-api': 'anonymous-to-application',
  'web-ui': 'anonymous-to-application',
  graphql: 'user-to-other-user',
  websocket: 'anonymous-to-application',
  rpc: 'third-party-to-application',
  cli: 'application-to-operating-system',
  ipc: 'sandbox-escape',
  'file-parser': 'third-party-to-application',
  'message-queue': 'third-party-to-application',
  'scheduled-job': 'application-to-operating-system',
  database: 'user-to-other-user',
  cache: 'tenant-to-tenant',
  'object-storage': 'anonymous-to-application',
  'cloud-control-plane': 'user-to-admin',
  'container-runtime': 'sandbox-escape',
  'ci-pipeline': 'build-to-runtime',
  'mobile-app': 'client-to-server-trust',
  'wireless-radio': 'anonymous-to-application',
  'third-party-dependency': 'third-party-to-application',
  'llm-prompt': 'third-party-to-application',
};

/** Translate a surface map into a concrete, bounded coverage plan. */
export function planFromSurface(surfaceMap, { profile = 'standard' } = {}) {
  const limit = PROFILES[profile]?.maxUnits ?? PROFILES.standard.maxUnits;
  const surfaces = inferSurfaces(surfaceMap);
  const units = [];

  for (const { surface, subsystems } of surfaces) {
    const classes = RELEVANT[surface] ?? ['input-validation'];
    const boundary = DEFAULT_BOUNDARY[surface] ?? 'anonymous-to-application';
    const take = profile === 'quick' ? classes.slice(0, 3) : classes;

    for (const subsystem of subsystems.slice(0, profile === 'deep' ? 12 : 4)) {
      for (const attackClass of take) {
        units.push(createUnit({
          surface,
          boundary,
          attackClass,
          subsystem,
          rationale: `${surface} surface detected in ${subsystem}`,
        }));
      }
    }
  }

  return units.slice(0, limit);
}

function inferSurfaces(surfaceMap) {
  const byS = new Map();
  const push = (surface, subsystem) => {
    if (!byS.has(surface)) byS.set(surface, new Set());
    byS.get(surface).add(subsystem);
  };

  const dirOf = (file) => {
    const parts = String(file).split('/');
    return parts.length > 1 ? parts.slice(0, Math.min(2, parts.length - 1)).join('/') : '.';
  };

  for (const hot of surfaceMap.hotspots ?? []) {
    const dir = dirOf(hot.file);
    const tags = new Set(hot.tags ?? []);
    const sinks = (hot.sinks ?? []).map((s) => s.id);

    if (tags.has('entrypoint')) { push('http-api', dir); }
    if (tags.has('authn') || tags.has('authz')) push('http-api', dir);
    if (sinks.some((s) => s.includes('xss') || s.includes('dom'))) push('web-ui', dir);
    if (sinks.some((s) => s.includes('sqli') || s.includes('nosqli'))) push('database', dir);
    if (sinks.some((s) => s.includes('deserialize') || s.includes('pickle') || s.includes('xxe'))) push('file-parser', dir);
    if (tags.has('iac')) push('cloud-control-plane', dir);
    if (tags.has('ci')) push('ci-pipeline', dir);
    if (hot.language === 'dockerfile' || sinks.some((s) => s.startsWith('k8s.') || s.startsWith('docker.'))) push('container-runtime', dir);
    if (['kotlin', 'swift', 'objc', 'dart'].includes(hot.language)) push('mobile-app', dir);
    if ((hot.secrets ?? []).length) push('object-storage', dir);
  }

  for (const domain of surfaceMap.suggestedDomains ?? []) {
    if (domain === 'dependencies') push('third-party-dependency', 'manifests');
    if (domain === 'llm') push('llm-prompt', 'prompts');
    if (domain === 'api') push('http-api', 'api');
    if (domain === 'web') push('web-ui', 'web');
  }

  if (byS.size === 0) push('http-api', '.');

  return [...byS.entries()].map(([surface, subsystems]) => ({
    surface,
    subsystems: [...subsystems].sort(),
  }));
}
