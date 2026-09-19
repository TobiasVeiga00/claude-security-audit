/**
 * CVSS v4.0 scoring, using FIRST's official tables.
 *
 * v4.0 does not have a closed-form formula. A vector is reduced to a
 * six-digit MacroVector (EQ1..EQ6), that class has a published score, and the
 * final score interpolates between that class and the next-lower ones in
 * proportion to how severe this particular vector is within its class.
 *
 * Reimplementing that from memory would be reckless, so this module refuses to
 * guess: it operates only on the authoritative tables vendored from
 * https://github.com/FIRSTdotorg/cvss-v4-calculator (BSD-2-Clause) by
 * intel-sync. With no tables present it returns a clear "unavailable" rather
 * than an approximation, because a plausible-looking wrong severity is worse
 * for a report than an honest gap.
 */

import path from 'node:path';
import fs from 'node:fs';
import { parseVector } from './cvss.mjs';
import { pluginRoot, readJson } from './util.mjs';

/* ------------------------------------------------------------------ *
 * Metric levels - "how bad is this value", per the specification
 * ------------------------------------------------------------------ */

const LEVELS = {
  AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0.0, L: 0.1, H: 0.2 },
  UI: { N: 0.0, P: 0.1, A: 0.2 },
  AC: { L: 0.0, H: 0.1 },
  AT: { N: 0.0, P: 0.1 },
  VC: { H: 0.0, L: 0.1, N: 0.2 },
  VI: { H: 0.0, L: 0.1, N: 0.2 },
  VA: { H: 0.0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { H: 0.1, L: 0.2, N: 0.3 },
  SA: { H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0.0, M: 0.1, L: 0.2 },
  IR: { H: 0.0, M: 0.1, L: 0.2 },
  AR: { H: 0.0, M: 0.1, L: 0.2 },
};

/**
 * Resolve a metric, honouring modified (M*) overrides and the defaults that
 * apply when a metric is Not Defined.
 */
function metric(metrics, name) {
  const modified = metrics[`M${name}`];
  if (modified && modified !== 'X') return modified;

  const value = metrics[name];
  if (value && value !== 'X') return value;

  // Specification defaults for Not Defined.
  if (['CR', 'IR', 'AR'].includes(name)) return 'H';
  if (name === 'E') return 'A';
  return value ?? 'X';
}

/* ------------------------------------------------------------------ *
 * MacroVector
 * ------------------------------------------------------------------ */

export function macroVector(m) {
  const AV = metric(m, 'AV'), PR = metric(m, 'PR'), UI = metric(m, 'UI');
  const AC = metric(m, 'AC'), AT = metric(m, 'AT');
  const VC = metric(m, 'VC'), VI = metric(m, 'VI'), VA = metric(m, 'VA');
  const SC = metric(m, 'SC'), SI = metric(m, 'SI'), SA = metric(m, 'SA');
  const MSI = m.MSI ?? 'X', MSA = m.MSA ?? 'X';
  const E = metric(m, 'E');
  const CR = metric(m, 'CR'), IR = metric(m, 'IR'), AR = metric(m, 'AR');

  // EQ1: exploitability of reaching the system
  const eq1 = (AV === 'N' && PR === 'N' && UI === 'N') ? '0'
    : ((AV === 'N' || PR === 'N' || UI === 'N') && AV !== 'P') ? '1'
      : '2';

  // EQ2: conditions attached to the attack
  const eq2 = (AC === 'L' && AT === 'N') ? '0' : '1';

  // EQ3: impact on the vulnerable system
  const eq3 = (VC === 'H' && VI === 'H') ? '0'
    : (VC === 'H' || VI === 'H' || VA === 'H') ? '1'
      : '2';

  // EQ4: impact on subsequent systems
  const eq4 = (MSI === 'S' || MSA === 'S') ? '0'
    : (SC === 'H' || SI === 'H' || SA === 'H') ? '1'
      : '2';

  // EQ5: exploit maturity
  const eq5 = E === 'A' ? '0' : E === 'P' ? '1' : E === 'U' ? '2' : '0';

  // EQ6: environmental requirements against vulnerable-system impact
  const eq6 = ((CR === 'H' && VC === 'H') || (IR === 'H' && VI === 'H') || (AR === 'H' && VA === 'H'))
    ? '0' : '1';

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
}

/* ------------------------------------------------------------------ *
 * Tables
 * ------------------------------------------------------------------ */

let cached = null;

export function loadTables(explicitPath = null) {
  if (cached && !explicitPath) return cached;
  const file = explicitPath ?? path.join(pluginRoot(), 'intel', 'cvss', 'v4-tables.json');
  if (!fs.existsSync(file)) return null;
  const tables = readJson(file, null);
  if (!tables?.lookup || !tables?.maxComposed || !tables?.maxSeverity) return null;
  if (!explicitPath) cached = tables;
  return tables;
}

/* ------------------------------------------------------------------ *
 * Scoring
 * ------------------------------------------------------------------ */

/**
 * Score a CVSS:4.0 vector.
 * @returns {{ok:true, score:number, macroVector:string, severity:string}}
 *        | {ok:false, reason:string}
 */
export function scoreV40(vector, { tablesPath = null } = {}) {
  const parsed = parseVector(vector);
  if (!parsed.ok) return { ok: false, reason: parsed.error };
  if (parsed.version !== '4.0') return { ok: false, reason: 'not a CVSS:4.0 vector' };

  const tables = loadTables(tablesPath);
  if (!tables) {
    return {
      ok: false,
      reason: 'CVSS v4.0 lookup tables are not present. Run `node scripts/intel-sync.mjs --only cvss` to vendor them from FIRST.',
    };
  }

  const m = parsed.metrics;

  // No impact anywhere means no score, regardless of exploitability.
  const noImpact = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => metric(m, k) === 'N');
  if (noImpact) return { ok: true, score: 0.0, macroVector: macroVector(m), severity: 'None', interpolated: false };

  const mv = macroVector(m);
  const base = tables.lookup[mv];
  if (base === undefined) return { ok: false, reason: `MacroVector ${mv} is absent from the lookup table` };

  const eq = mv.split('').map(Number);
  const [eq1, eq2, eq3, eq4, eq5, eq6] = eq;

  const lookup = (v) => {
    const value = tables.lookup[v];
    return value === undefined ? NaN : value;
  };

  /* -- scores of the next-lower MacroVector along each equivalence class -- */
  const lowerEq1 = eq1 < 2 ? lookup(`${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`) : NaN;
  const lowerEq2 = eq2 < 1 ? lookup(`${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`) : NaN;
  const lowerEq4 = eq4 < 2 ? lookup(`${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`) : NaN;
  const lowerEq5 = eq5 < 2 ? lookup(`${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`) : NaN;

  // EQ3 and EQ6 are not independent, so their descent is handled jointly.
  let lowerEq3eq6;
  if (eq3 === 1 && eq6 === 1) lowerEq3eq6 = lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
  else if (eq3 === 0 && eq6 === 1) lowerEq3eq6 = lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
  else if (eq3 === 1 && eq6 === 0) lowerEq3eq6 = lookup(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`);
  else if (eq3 === 0 && eq6 === 0) {
    const a = lookup(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`);
    const b = lookup(`${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`);
    lowerEq3eq6 = Math.max(Number.isNaN(a) ? -Infinity : a, Number.isNaN(b) ? -Infinity : b);
    if (lowerEq3eq6 === -Infinity) lowerEq3eq6 = NaN;
  } else lowerEq3eq6 = NaN;

  /* -- how severe this vector is inside its own class -- */
  const maxes = {
    eq1: tables.maxComposed.eq1[String(eq1)] ?? [],
    eq2: tables.maxComposed.eq2[String(eq2)] ?? [],
    eq3eq6: (tables.maxComposed.eq3[String(eq3)]?.[String(eq6)]) ?? [],
    eq4: tables.maxComposed.eq4[String(eq4)] ?? [],
    eq5: tables.maxComposed.eq5[String(eq5)] ?? [],
  };

  // The specification takes the cartesian product of each class's maximal
  // vectors and selects the first combination this vector does not exceed.
  const candidates = [];
  for (const a of maxes.eq1) {
    for (const b of maxes.eq2) {
      for (const c of maxes.eq3eq6) {
        for (const d of maxes.eq4) {
          for (const e of maxes.eq5) candidates.push(a + b + c + d + e);
        }
      }
    }
  }

  const severityDistances = {};
  let matched = false;
  for (const candidate of candidates) {
    const maxMetrics = Object.fromEntries(
      candidate.split('/').filter(Boolean).map((part) => part.split(':')),
    );
    const distances = {};
    let valid = true;
    for (const key of ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR']) {
      if (maxMetrics[key] === undefined) continue;
      const here = LEVELS[key][metric(m, key)];
      const there = LEVELS[key][maxMetrics[key]];
      if (here === undefined || there === undefined) { valid = false; break; }
      const distance = Number(((here - there) * 10).toFixed(6)) / 10;
      if (distance < 0) { valid = false; break; }
      distances[key] = distance;
    }
    if (valid) { Object.assign(severityDistances, distances); matched = true; break; }
  }
  if (!matched) return { ok: false, reason: `no maximal vector dominates ${vector}` };

  const sum = (keys) => keys.reduce((total, key) => total + (severityDistances[key] ?? 0), 0);
  const currentDistance = {
    eq1: sum(['AV', 'PR', 'UI']),
    eq2: sum(['AC', 'AT']),
    eq3eq6: sum(['VC', 'VI', 'VA', 'CR', 'IR', 'AR']),
    eq4: sum(['SC', 'SI', 'SA']),
    eq5: 0,
  };

  const maxSeverity = {
    eq1: (tables.maxSeverity.eq1[String(eq1)] ?? 0) * 0.1,
    eq2: (tables.maxSeverity.eq2[String(eq2)] ?? 0) * 0.1,
    eq3eq6: ((tables.maxSeverity.eq3eq6?.[String(eq3)]?.[String(eq6)]) ?? 0) * 0.1,
    eq4: (tables.maxSeverity.eq4[String(eq4)] ?? 0) * 0.1,
    eq5: (tables.maxSeverity.eq5?.[String(eq5)] ?? 0) * 0.1,
  };

  const available = { eq1: base - lowerEq1, eq2: base - lowerEq2, eq3eq6: base - lowerEq3eq6, eq4: base - lowerEq4, eq5: base - lowerEq5 };

  let steps = 0;
  let total = 0;
  for (const key of ['eq1', 'eq2', 'eq3eq6', 'eq4', 'eq5']) {
    const distance = available[key];
    if (!Number.isFinite(distance)) continue;
    const max = maxSeverity[key];
    if (!max) continue;
    total += distance * (currentDistance[key] / max);
    steps++;
  }

  let score = steps === 0 ? base : base - total / steps;
  score = Math.max(0, Math.min(10, score));
  score = Number(score.toFixed(1));

  return {
    ok: true,
    score,
    macroVector: mv,
    macroVectorScore: base,
    severity: qualitative(score),
    interpolated: steps > 0,
    tableSource: tables.upstream,
  };
}

export function qualitative(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0.0) return 'Low';
  return 'None';
}
