/**
 * CVSS scoring and risk fusion.
 *
 * Scope decision, stated plainly because a wrong number in a security report is
 * worse than no number:
 *
 *   - CVSS v3.1 base + temporal scores are computed EXACTLY, per the FIRST
 *     specification (https://www.first.org/cvss/v3.1/specification-document).
 *     This is what NVD publishes for the overwhelming majority of CVEs.
 *   - CVSS v4.0 vectors are parsed and validated, but not scored locally.
 *     v4.0 scoring requires FIRST's official MacroVector lookup table plus a
 *     distance-interpolation pass; reimplementing it from memory would risk
 *     silently wrong severities. The vector is preserved verbatim and any
 *     authoritative score supplied by a feed is carried through untouched.
 *   - Prioritisation does not rely on CVSS alone. `fuseRisk()` combines base
 *     severity with EPSS exploit probability, CISA KEV membership and
 *     deployment exposure, which is what actually drives remediation order.
 */

/* ------------------------------------------------------------------ *
 * CVSS v3.1
 * ------------------------------------------------------------------ */

const V31_METRICS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 }, // scope Unchanged
    C: { N: 0.85, L: 0.68, H: 0.5 },  // scope Changed
  },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 'U', C: 'C' },
  C: { H: 0.56, L: 0.22, N: 0.0 },
  I: { H: 0.56, L: 0.22, N: 0.0 },
  A: { H: 0.56, L: 0.22, N: 0.0 },
};

const V31_TEMPORAL = {
  E: { X: 1.0, H: 1.0, F: 0.97, P: 0.94, U: 0.91 },
  RL: { X: 1.0, U: 1.0, W: 0.97, T: 0.96, O: 0.95 },
  RC: { X: 1.0, C: 1.0, R: 0.96, U: 0.92 },
};

const V31_REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

/**
 * CVSS v3.1 Roundup: smallest number with one decimal place that is greater
 * than or equal to the input. Implemented with integer arithmetic exactly as
 * the specification's Appendix A requires, to avoid float drift.
 */
export function roundUp1(value) {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function parseVector(vector) {
  if (typeof vector !== 'string' || !vector.includes('/')) {
    return { ok: false, error: 'not a CVSS vector string' };
  }
  const parts = vector.trim().split('/').filter(Boolean);
  const head = parts[0];
  const versionMatch = /^CVSS:(\d+\.\d+)$/.exec(head);
  const version = versionMatch ? versionMatch[1] : null;
  const metricParts = versionMatch ? parts.slice(1) : parts;

  const metrics = {};
  for (const part of metricParts) {
    const idx = part.indexOf(':');
    if (idx === -1) return { ok: false, error: `malformed metric "${part}"` };
    metrics[part.slice(0, idx)] = part.slice(idx + 1);
  }
  return { ok: true, version, metrics, vector: vector.trim() };
}

/**
 * Compute CVSS v3.1 base score (and temporal score when E/RL/RC are present).
 * Returns null when the vector is not a scoreable v3.x vector.
 */
export function scoreV31(vector) {
  const parsed = parseVector(vector);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  if (parsed.version && !parsed.version.startsWith('3')) {
    return { ok: false, error: `unsupported version CVSS:${parsed.version}` };
  }
  const m = parsed.metrics;

  for (const key of V31_REQUIRED) {
    if (!(key in m)) return { ok: false, error: `missing base metric ${key}` };
  }

  const scope = m.S === 'C' ? 'C' : 'U';
  const av = V31_METRICS.AV[m.AV];
  const ac = V31_METRICS.AC[m.AC];
  const pr = V31_METRICS.PR[scope][m.PR];
  const ui = V31_METRICS.UI[m.UI];
  const c = V31_METRICS.C[m.C];
  const i = V31_METRICS.I[m.I];
  const a = V31_METRICS.A[m.A];

  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) {
    return { ok: false, error: 'invalid base metric value' };
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scope === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av * ac * pr * ui;

  let base;
  if (impact <= 0) {
    base = 0.0;
  } else if (scope === 'U') {
    base = roundUp1(Math.min(impact + exploitability, 10));
  } else {
    base = roundUp1(Math.min(1.08 * (impact + exploitability), 10));
  }

  const result = {
    ok: true,
    version: parsed.version || '3.1',
    vector: parsed.vector,
    base,
    severity: severityBand(base),
    impactSubscore: Number(impact.toFixed(4)),
    exploitabilitySubscore: Number(exploitability.toFixed(4)),
  };

  const hasTemporal = ['E', 'RL', 'RC'].some((k) => k in m);
  if (hasTemporal) {
    const e = V31_TEMPORAL.E[m.E ?? 'X'];
    const rl = V31_TEMPORAL.RL[m.RL ?? 'X'];
    const rc = V31_TEMPORAL.RC[m.RC ?? 'X'];
    if (e !== undefined && rl !== undefined && rc !== undefined) {
      result.temporal = roundUp1(base * e * rl * rc);
      result.temporalSeverity = severityBand(result.temporal);
    }
  }

  return result;
}

/* ------------------------------------------------------------------ *
 * CVSS v4.0 - validation only, deliberately
 * ------------------------------------------------------------------ */

const V40_VALUES = {
  AV: ['N', 'A', 'L', 'P'], AC: ['L', 'H'], AT: ['N', 'P'],
  PR: ['N', 'L', 'H'], UI: ['N', 'P', 'A'],
  VC: ['H', 'L', 'N'], VI: ['H', 'L', 'N'], VA: ['H', 'L', 'N'],
  SC: ['H', 'L', 'N'], SI: ['H', 'L', 'N'], SA: ['H', 'L', 'N'],
  E: ['X', 'A', 'P', 'U'],
  CR: ['X', 'H', 'M', 'L'], IR: ['X', 'H', 'M', 'L'], AR: ['X', 'H', 'M', 'L'],
  S: ['X', 'N', 'P'], AU: ['X', 'N', 'Y'], R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'], RE: ['X', 'L', 'M', 'H'], U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
};
const V40_REQUIRED = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

export function validateV40(vector) {
  const parsed = parseVector(vector);
  if (!parsed.ok) return { ok: false, error: parsed.error };
  if (parsed.version !== '4.0') return { ok: false, error: 'not a CVSS:4.0 vector' };

  for (const key of V40_REQUIRED) {
    if (!(key in parsed.metrics)) return { ok: false, error: `missing base metric ${key}` };
  }
  for (const [key, value] of Object.entries(parsed.metrics)) {
    const base = key.startsWith('M') ? key.slice(1) : key;
    const allowed = V40_VALUES[base];
    if (allowed && !allowed.includes(value)) {
      return { ok: false, error: `invalid value ${key}:${value}` };
    }
  }
  return {
    ok: true,
    version: '4.0',
    vector: parsed.vector,
    metrics: parsed.metrics,
    scored: false,
    note: 'CVSS:4.0 vector validated. Numeric score must come from an authoritative source (NVD/CNA) or FIRST\'s official calculator.',
  };
}

/* ------------------------------------------------------------------ *
 * Severity bands and normalisation
 * ------------------------------------------------------------------ */

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

export function severityBand(score) {
  if (score === null || score === undefined) return 'info';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0.0) return 'low';
  return 'info';
}

/** Map the many severity spellings found in scanner output onto our scale. */
export function normalizeSeverity(raw) {
  if (raw === null || raw === undefined) return 'info';
  if (typeof raw === 'number') return severityBand(raw);
  const value = String(raw).trim().toLowerCase();
  const table = {
    critical: 'critical', crit: 'critical', blocker: 'critical', '5': 'critical',
    high: 'high', error: 'high', severe: 'high', major: 'high', '4': 'high',
    medium: 'medium', moderate: 'medium', warning: 'medium', warn: 'medium', minor: 'medium', '3': 'medium',
    low: 'low', note: 'low', '2': 'low',
    info: 'info', informational: 'info', information: 'info', unknown: 'info', none: 'info', '1': 'info', '0': 'info',
  };
  return table[value] ?? 'info';
}

export function severityRank(severity) {
  const idx = SEVERITIES.indexOf(normalizeSeverity(severity));
  return idx === -1 ? 0 : idx;
}

/* ------------------------------------------------------------------ *
 * Risk fusion - what actually drives remediation order
 * ------------------------------------------------------------------ */

/**
 * Fuse CVSS severity with real-world exploitation signals.
 *
 * Inputs (all optional except severity):
 *   severity   - our normalised band, or a CVSS base score
 *   epss       - EPSS probability in [0,1] (FIRST exploit prediction)
 *   kev        - true when the CVE is in the CISA Known Exploited catalog
 *   exposure   - 'internet' | 'internal' | 'local' | 'unknown'
 *   reachable  - true when static analysis proved the vulnerable path is reachable
 *   dataClass  - 'pii' | 'secrets' | 'financial' | 'phi' | 'public' | undefined
 *
 * Returns a 0-100 priority with a human-readable rationale, so a report can
 * always explain WHY something was ranked where it was.
 */
export function fuseRisk({
  severity,
  epss = null,
  kev = false,
  exposure = 'unknown',
  reachable = null,
  dataClass = null,
} = {}) {
  const band = typeof severity === 'number' ? severityBand(severity) : normalizeSeverity(severity);
  const baseScore = { critical: 80, high: 62, medium: 40, low: 20, info: 5 }[band];

  let score = baseScore;
  const rationale = [`base severity ${band} (${baseScore})`];

  if (kev) {
    score += 18;
    rationale.push('+18 listed in CISA KEV (confirmed exploitation in the wild)');
  }

  if (typeof epss === 'number' && epss >= 0) {
    // EPSS is heavily skewed toward zero, so weight the tail, not the mean.
    let bonus = 0;
    if (epss >= 0.5) bonus = 14;
    else if (epss >= 0.1) bonus = 9;
    else if (epss >= 0.01) bonus = 4;
    if (bonus) {
      score += bonus;
      rationale.push(`+${bonus} EPSS ${(epss * 100).toFixed(1)}% exploitation probability`);
    }
  }

  const exposureDelta = { internet: 10, internal: 0, local: -10, unknown: -2 }[exposure] ?? -2;
  if (exposureDelta !== 0) {
    score += exposureDelta;
    rationale.push(`${exposureDelta > 0 ? '+' : ''}${exposureDelta} ${exposure} exposure`);
  }

  if (reachable === true) {
    score += 8;
    rationale.push('+8 vulnerable path proven reachable');
  } else if (reachable === false) {
    score -= 22;
    rationale.push('-22 vulnerable code not reachable from any entry point');
  }

  const dataDelta = { secrets: 10, phi: 8, financial: 8, pii: 6, public: -4 }[dataClass] ?? 0;
  if (dataDelta !== 0) {
    score += dataDelta;
    rationale.push(`${dataDelta > 0 ? '+' : ''}${dataDelta} ${dataClass} data in scope`);
  }

  /**
   * CISA KEV is not just another signal to add points for. A listing means the
   * vulnerability is being exploited right now - which is why the catalogue
   * carries binding federal remediation deadlines. It therefore sets a FLOOR
   * on priority rather than a bonus that a low base severity can dilute.
   *
   * The one exception is proven unreachability: if the vulnerable path cannot
   * be reached in this deployment, the exploitation happening elsewhere does
   * not apply here, and the floor is not imposed.
   */
  if (kev && reachable !== false) {
    const floor = exposure === 'local' ? 65 : 85;
    if (score < floor) {
      rationale.push(`floor ${floor} applied: a KEV listing means active exploitation, which outranks base severity`);
      score = floor;
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    priority: score,
    tier: score >= 85 ? 'P0' : score >= 65 ? 'P1' : score >= 40 ? 'P2' : score >= 20 ? 'P3' : 'P4',
    severity: band,
    rationale,
  };
}

/** Suggested remediation SLA per priority tier, aligned with common policy. */
export const SLA_DAYS = { P0: 1, P1: 7, P2: 30, P3: 90, P4: 180 };
