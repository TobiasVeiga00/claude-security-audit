#!/usr/bin/env node
/**
 * Threat-intelligence query and enrichment.
 *
 * Answers the questions that decide remediation order, cheaply:
 *   - Is this CVE being exploited in the wild right now?      (CISA KEV, vendored)
 *   - How likely is exploitation in the next 30 days?         (FIRST EPSS, live)
 *   - What does the authoritative record say?                 (NVD, live)
 *   - Is this exact package version affected?                 (OSV.dev, live)
 *   - What technique or weakness does this map to?            (ATT&CK / CWE, vendored)
 *
 * `enrich` is the one that matters most in practice: it walks the finding
 * ledger, attaches exploitation signals to every CVE it mentions, and lets the
 * risk model re-rank the report on evidence instead of on severity alone.
 *
 * Usage:
 *   node intel.mjs cve CVE-2021-44228
 *   node intel.mjs package --ecosystem npm --name lodash --version 4.17.20
 *   node intel.mjs attack T1190
 *   node intel.mjs cwe 89
 *   node intel.mjs enrich [--cwd .]
 *   node intel.mjs status
 */

import fs from 'node:fs';
import path from 'node:path';
import { getJson, request, pooled } from './lib/http.mjs';
import { FindingStore } from './lib/findings.mjs';
import { fuseRisk } from './lib/cvss.mjs';
import { parseArgs, emit, readJson, pluginRoot, fail, nowIso } from './lib/util.mjs';

const ENDPOINTS = {
  epss: (cves) => `https://api.first.org/data/v1/epss?cve=${cves.join(',')}&pretty=false&envelope=false`,
  nvd: (cve) => `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`,
  osvQuery: 'https://api.osv.dev/v1/query',
  osvBatch: 'https://api.osv.dev/v1/querybatch',
};

function intelDir() {
  return path.join(pluginRoot(), 'intel');
}

/* ------------------------------------------------------------------ *
 * Vendored lookups
 * ------------------------------------------------------------------ */

let kevIndex = null;
export function kevLookup(cve) {
  if (kevIndex === null) {
    const file = path.join(intelDir(), 'kev', 'index.json');
    // Distinguish "not listed" from "the vendored KEV file is missing". Reading
    // an absent file as {} made every CVE look not-exploited, so enrich() would
    // flip kev:true to false and demote confirmed-exploitation findings.
    kevIndex = fs.existsSync(file) ? readJson(file, null) : null;
  }
  if (kevIndex === null) return { listed: false, unavailable: true };
  const entry = kevIndex[String(cve).toUpperCase()];
  if (!entry) return { listed: false };
  return { listed: true, dateAdded: entry.d, remediationDue: entry.due, ransomware: entry.r === 1 };
}

export function attackLookup(id) {
  const wanted = String(id).toUpperCase();
  for (const domain of ['enterprise-attack', 'mobile-attack', 'ics-attack']) {
    const file = path.join(intelDir(), 'attack', `${domain}.json`);
    if (!fs.existsSync(file)) continue;
    const data = readJson(file, null);
    const technique = data?.techniques?.find((t) => t.id === wanted);
    if (technique) return { ...technique, domain, catalogVersion: data.version };
  }
  return null;
}

export function cweLookup(id) {
  const wanted = `CWE-${String(id).replace(/\D/g, '')}`;
  const file = path.join(intelDir(), 'cwe', 'top25.json');
  const data = readJson(file, null);
  const entry = data?.entries?.find((e) => e.id === wanted);
  return entry
    ? { ...entry, inTop25: true, edition: data.edition }
    : { id: wanted, inTop25: false, url: `https://cwe.mitre.org/data/definitions/${wanted.replace('CWE-', '')}.html` };
}

/* ------------------------------------------------------------------ *
 * Live lookups
 * ------------------------------------------------------------------ */

/** EPSS in batches. The API takes comma-separated ids, so one call covers many. */
export async function epssLookup(cves) {
  const unique = [...new Set(cves.map((c) => String(c).toUpperCase()))].filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  if (unique.length === 0) return {};

  const out = {};
  const batches = [];
  for (let i = 0; i < unique.length; i += 100) batches.push(unique.slice(i, i + 100));

  const results = await pooled(batches, async (batch) => getJson(ENDPOINTS.epss(batch)), 2);
  for (const result of results) {
    if (!result.ok) continue;
    for (const row of result.value?.data ?? result.value ?? []) {
      if (row?.cve) out[row.cve] = { epss: Number(row.epss), percentile: Number(row.percentile), date: row.date };
    }
  }
  return out;
}

export async function nvdLookup(cve, { apiKey = process.env.NVD_API_KEY } = {}) {
  const data = await getJson(ENDPOINTS.nvd(cve), {
    headers: apiKey ? { apiKey } : {},
    // Without a key NVD allows 5 requests per 30 seconds; be patient, not greedy.
    retries: 3,
  });
  const record = data?.vulnerabilities?.[0]?.cve;
  if (!record) return null;

  const v40 = record.metrics?.cvssMetricV40?.[0]?.cvssData;
  const v31 = record.metrics?.cvssMetricV31?.find((m) => m.type === 'Primary')?.cvssData
    ?? record.metrics?.cvssMetricV31?.[0]?.cvssData;

  return {
    id: record.id,
    status: record.vulnStatus,
    published: record.published,
    lastModified: record.lastModified,
    description: record.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
    cwe: [...new Set((record.weaknesses ?? []).flatMap((w) => (w.description ?? []).map((d) => d.value)).filter((v) => /^CWE-\d+$/.test(v)))],
    cvss: v40
      ? { version: '4.0', base: v40.baseScore, severity: v40.baseSeverity, vector: v40.vectorString }
      : v31
        ? { version: '3.1', base: v31.baseScore, severity: v31.baseSeverity, vector: v31.vectorString }
        : null,
    kevFromNvd: record.cisaExploitAdd ? { dateAdded: record.cisaExploitAdd, due: record.cisaActionDue } : null,
    references: (record.references ?? []).slice(0, 10).map((r) => r.url),
  };
}

export async function osvQuery({ ecosystem, name, version, commit }) {
  const body = commit
    ? { commit }
    : { package: { name, ecosystem }, ...(version ? { version } : {}) };

  const response = await request(ENDPOINTS.osvQuery, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await response.json();

  return (data.vulns ?? []).map((v) => ({
    id: v.id,
    aliases: v.aliases ?? [],
    cve: (v.aliases ?? []).filter((a) => a.startsWith('CVE-')),
    summary: v.summary ?? '',
    published: v.published,
    severity: v.database_specific?.severity ?? null,
    cvssVectors: (v.severity ?? []).map((s) => s.score),
    cwe: v.database_specific?.cwe_ids ?? [],
    fixed: (v.affected ?? [])
      .flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).filter((e) => e.fixed).map((e) => e.fixed)))
      .filter(Boolean),
    references: (v.references ?? []).slice(0, 5).map((r) => r.url),
  }));
}

/* ------------------------------------------------------------------ *
 * Enrichment
 * ------------------------------------------------------------------ */

/**
 * Walk the ledger, attach exploitation signals to every CVE-bearing finding,
 * and re-run risk fusion so the report's ordering reflects reality.
 */
export async function enrich(cwd) {
  const store = new FindingStore(cwd);
  if (!store.exists()) fail(`no finding ledger at ${store.file}`);

  const findings = store.load();
  const cves = [...new Set(findings.flatMap((f) => f.cve ?? []))];
  if (cves.length === 0) {
    return { enriched: 0, cves: 0, note: 'No findings reference a CVE; nothing to enrich.' };
  }

  const epss = await epssLookup(cves);

  const kevUnavailable = kevAvailability().unavailable;

  const updates = [];
  for (const finding of findings) {
    if (!(finding.cve ?? []).length) continue;
    if (finding.verdict && finding.verdict !== 'confirmed') continue; // leads/rejected carry no risk

    const kevHit = finding.cve.map(kevLookup).find((k) => k.listed);
    const scores = finding.cve.map((c) => epss[c]?.epss).filter((v) => typeof v === 'number');
    const worstEpss = scores.length ? Math.max(...scores) : null;

    // Only ever flip `kev` when the KEV data was actually available. When it is
    // missing, keep whatever the finding already knew rather than demoting it.
    const nextKev = kevUnavailable ? finding.kev : kevHit?.listed === true;

    const changed = nextKev !== finding.kev
      || (worstEpss !== null && worstEpss !== finding.epss);
    if (!changed) continue;

    updates.push({
      ...finding,
      kev: nextKev,
      epss: worstEpss ?? finding.epss,
      tags: [...new Set([...(finding.tags ?? []), ...(kevHit?.ransomware ? ['ransomware-campaign'] : [])])],
      // The fusion inputs live on the finding itself (persisted since the ledger
      // fix), so re-ranking keeps the exposure/reachability the original score
      // used instead of collapsing everything to "unknown".
      risk: fuseRisk({
        severity: finding.severity,
        epss: worstEpss ?? finding.epss,
        kev: nextKev,
        exposure: finding.exposure ?? finding.extra?.exposure ?? undefined,
        reachable: typeof finding.reachable === 'boolean' ? finding.reachable : (finding.extra?.reachable ?? null),
        dataClass: finding.dataClass ?? finding.extra?.dataClass ?? null,
      }),
    });
  }

  if (updates.length) store.add(updates, { scanId: `intel-${Date.now()}` });

  return {
    cves: cves.length,
    enriched: updates.length,
    nowKev: updates.filter((u) => u.kev).length,
    escalatedToP0: updates.filter((u) => u.risk?.tier === 'P0').length,
    ...(kevUnavailable ? { warning: 'Vendored KEV data is missing; exploitation status was not updated. Run scripts/intel-sync.mjs --only kev.' } : {}),
  };
}

/** Whether the KEV index is available at all, checked once per enrich run. */
function kevAvailability() {
  const probe = kevLookup('CVE-0000-0000');
  return { unavailable: probe.unavailable === true };
}

/* ------------------------------------------------------------------ *
 * Status
 * ------------------------------------------------------------------ */

export function status() {
  const manifest = readJson(path.join(intelDir(), 'MANIFEST.json'), null);
  if (!manifest) {
    return {
      available: false,
      message: 'No vendored intelligence found. Run `node scripts/intel-sync.mjs` or reinstall the plugin.',
    };
  }
  const ageHours = (Date.now() - Date.parse(manifest.generatedAt)) / 3600000;
  return {
    available: true,
    generatedAt: manifest.generatedAt,
    ageHours: Number(ageHours.toFixed(1)),
    stale: ageHours > 24 * 8,
    sources: manifest.sources,
    failures: manifest.failures ?? [],
  };
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

async function main() {
  const args = parseArgs();
  const command = args._[0];

  switch (command) {
    case 'cve': {
      const cve = args._[1] ?? args.cve;
      if (!cve) fail('usage: intel.mjs cve CVE-YYYY-NNNNN');
      const [epss, nvd] = await Promise.all([
        epssLookup([cve]).catch(() => ({})),
        nvdLookup(cve).catch((err) => ({ error: err.message })),
      ]);
      const kev = kevLookup(cve);
      const risk = fuseRisk({
        severity: nvd?.cvss?.base ?? 'info',
        epss: epss[String(cve).toUpperCase()]?.epss ?? null,
        kev: kev.listed,
        exposure: 'internet',
      });
      emit({ cve, kev, epss: epss[String(cve).toUpperCase()] ?? null, nvd, suggestedPriority: risk });
      break;
    }

    case 'package': {
      const name = args.name ?? args._[1];
      if (!name) fail('usage: intel.mjs package --ecosystem npm --name lodash [--version 4.17.20]');
      const vulns = await osvQuery({ ecosystem: args.ecosystem ?? 'npm', name, version: args.version });
      const cves = [...new Set(vulns.flatMap((v) => v.cve))];
      const epss = cves.length ? await epssLookup(cves).catch(() => ({})) : {};
      emit({
        package: { name, ecosystem: args.ecosystem ?? 'npm', version: args.version ?? null },
        count: vulns.length,
        vulnerabilities: vulns.map((v) => ({
          ...v,
          kev: v.cve.map(kevLookup).find((k) => k.listed) ?? { listed: false },
          epss: v.cve.map((c) => epss[c]).find(Boolean) ?? null,
        })),
      });
      break;
    }

    case 'attack': {
      const id = args._[1] ?? args.id;
      if (!id) fail('usage: intel.mjs attack T1190');
      const technique = attackLookup(id);
      if (!technique) fail(`technique ${id} not found. Vendored ATT&CK data may be missing; run intel-sync.`);
      emit(technique);
      break;
    }

    case 'cwe': {
      const id = args._[1] ?? args.id;
      if (!id) fail('usage: intel.mjs cwe 89');
      emit(cweLookup(id));
      break;
    }

    case 'enrich': {
      const cwd = args.cwd ? path.resolve(String(args.cwd)) : process.cwd();
      emit(await enrich(cwd));
      break;
    }

    case 'status':
      emit(status());
      break;

    default:
      process.stderr.write([
        'usage: intel.mjs <command>',
        '',
        '  cve <CVE-ID>                              exploitation status, EPSS and the NVD record',
        '  package --ecosystem <e> --name <n> [--version <v>]   OSV vulnerabilities for a package',
        '  attack <TECHNIQUE-ID>                     MITRE ATT&CK technique detail',
        '  cwe <ID>                                  CWE detail and Top 25 standing',
        '  enrich [--cwd <dir>]                      attach KEV and EPSS to every CVE in the ledger',
        '  status                                    freshness of the vendored intelligence',
        '',
      ].join('\n'));
      process.exit(1);
  }
}

if (process.argv[1]?.endsWith('intel.mjs')) {
  main().catch((err) => {
    process.stderr.write(`intel: ${err.message}\n`);
    process.exit(1);
  });
}
