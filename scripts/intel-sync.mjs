#!/usr/bin/env node
/**
 * Intelligence sync.
 *
 * Run by CI on a schedule. Refreshes the slow-moving reference data that this
 * plugin vendors, and records the versions of everything it depends on.
 *
 * Deliberate split:
 *   VENDORED  data that changes weekly-to-yearly and is small enough to ship:
 *             CISA KEV, an ATT&CK technique digest, CWE Top 25, CVSS v4 tables,
 *             framework release versions.
 *   LIVE      data that changes daily and is per-CVE: EPSS, NVD enrichment,
 *             OSV package queries. Fetched at audit time by intel.mjs.
 *
 * Vendoring the whole of EPSS or NVD would bloat the repository, go stale
 * between releases, and buy nothing: those APIs are fast and need no key.
 *
 * Output is CANONICAL - keys sorted, volatile timestamps quarantined in
 * MANIFEST.json - so an unchanged upstream produces a byte-identical file and
 * therefore no pull request.
 *
 * Usage: node intel-sync.mjs [--only kev,attack,cwe,cvss,frameworks] [--out ./intel]
 */

import fs from 'node:fs';
import path from 'node:path';
import { getJson, getText, pooled } from './lib/http.mjs';
import { parseJsObjectLiteral } from './lib/jsobj.mjs';
import { parseArgs, writeJson, nowIso, sha256, ensureDir } from './lib/util.mjs';

const SOURCES = {
  kev: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
  attackIndex: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json',
  attackBundle: (domain, version) =>
    `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/${domain}/${domain}-${version}.json`,
  cweVersion: 'https://cwe-api.mitre.org/api/v1/cwe/version',
  cweWeakness: (ids) => `https://cwe-api.mitre.org/api/v1/cwe/weakness/${ids.join(',')}`,
  cvssLookup: 'https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/main/cvss_lookup.js',
  cvssMaxComposed: 'https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/main/max_composed.js',
  cvssMaxSeverity: 'https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/main/max_severity.js',
  nucleiStats: 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/TEMPLATES-STATS.json',
};

/**
 * The 2025 CWE Top 25, published 2025-12-11 and republished by MITRE as view
 * CWE-1435. Ranks are pinned here; names and descriptions are fetched so they
 * track the current CWE catalog rather than drifting.
 */
const CWE_TOP25_2025 = [
  79,   // 1  Cross-site Scripting
  89,   // 2  SQL Injection
  352,  // 3  Cross-Site Request Forgery
  862,  // 4  Missing Authorization
  787,  // 5  Out-of-bounds Write
  22,   // 6  Path Traversal
  416,  // 7  Use After Free
  125,  // 8  Out-of-bounds Read
  78,   // 9  OS Command Injection
  94,   // 10 Code Injection
  120,  // 11 Classic Buffer Overflow
  434,  // 12 Unrestricted Upload of File with Dangerous Type
  476,  // 13 NULL Pointer Dereference
  121,  // 14 Stack-based Buffer Overflow
  502,  // 15 Deserialization of Untrusted Data
  122,  // 16 Heap-based Buffer Overflow
  863,  // 17 Incorrect Authorization
  20,   // 18 Improper Input Validation
  284,  // 19 Improper Access Control
  200,  // 20 Exposure of Sensitive Information
  306,  // 21 Missing Authentication for Critical Function
  918,  // 22 Server-Side Request Forgery
  77,   // 23 Command Injection
  639,  // 24 Authorization Bypass Through User-Controlled Key
  770,  // 25 Allocation of Resources Without Limits or Throttling
];

/* ------------------------------------------------------------------ *
 * Feeds
 * ------------------------------------------------------------------ */

async function syncKev(outDir) {
  const raw = await getJson(SOURCES.kev);
  // Structured fields only. The free-text description and requiredAction make
  // up most of the catalogue's size and are not read at audit time, so they are
  // dropped to keep the shipped plugin lean; the authoritative text is one NVD
  // lookup away.
  const vulnerabilities = (raw.vulnerabilities ?? [])
    .map((v) => ({
      cve: v.cveID,
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      cwes: v.cwes ?? [],
    }))
    .sort((a, b) => a.cve.localeCompare(b.cve));

  // An index keyed by CVE makes the common lookup O(1) without loading the list.
  const index = Object.fromEntries(vulnerabilities.map((v) => [v.cve, {
    d: v.dateAdded, r: v.ransomware ? 1 : 0, due: v.dueDate,
  }]));

  writeJson(path.join(outDir, 'kev', 'catalog.json'), {
    source: 'CISA Known Exploited Vulnerabilities Catalog',
    license: 'CC0 1.0 Universal (public domain)',
    catalogVersion: raw.catalogVersion,
    count: vulnerabilities.length,
    vulnerabilities,
  });
  writeJson(path.join(outDir, 'kev', 'index.json'), index, { pretty: false });

  return { count: vulnerabilities.length, version: raw.catalogVersion };
}

async function syncAttack(outDir) {
  const index = await getJson(SOURCES.attackIndex);
  const result = { domains: {}, version: null };

  for (const collection of index.collections ?? []) {
    const domain = /enterprise/i.test(collection.name) ? 'enterprise-attack'
      : /mobile/i.test(collection.name) ? 'mobile-attack'
        : /ics/i.test(collection.name) ? 'ics-attack' : null;
    if (!domain) continue;

    const latest = [...(collection.versions ?? [])]
      .sort((a, b) => compareVersions(b.version, a.version))[0];
    if (!latest) continue;
    result.version = result.version
      ? (compareVersions(latest.version, result.version) > 0 ? latest.version : result.version)
      : latest.version;

    const bundle = await getJson(SOURCES.attackBundle(domain, latest.version));

    // A full STIX bundle is tens of megabytes. We keep only what an auditor
    // cites: the technique, its tactics, platforms and a one-line summary.
    const tactics = new Map();
    for (const obj of bundle.objects ?? []) {
      if (obj.type !== 'x-mitre-tactic') continue;
      const ref = (obj.external_references ?? []).find((r) => r.source_name === 'mitre-attack');
      if (ref) tactics.set(obj.x_mitre_shortname, { id: ref.external_id, name: obj.name });
    }

    const techniques = [];
    for (const obj of bundle.objects ?? []) {
      if (obj.type !== 'attack-pattern' || obj.revoked || obj.x_mitre_deprecated) continue;
      const ref = (obj.external_references ?? []).find((r) => r.source_name === 'mitre-attack');
      if (!ref?.external_id) continue;
      techniques.push({
        id: ref.external_id,
        name: obj.name,
        subtechnique: obj.x_mitre_is_subtechnique === true,
        tactics: (obj.kill_chain_phases ?? [])
          .filter((p) => p.kill_chain_name === 'mitre-attack')
          .map((p) => tactics.get(p.phase_name)?.id ?? p.phase_name),
        platforms: obj.x_mitre_platforms ?? [],
        summary: firstSentence(obj.description ?? ''),
        url: ref.url,
      });
    }
    techniques.sort((a, b) => a.id.localeCompare(b.id));

    writeJson(path.join(outDir, 'attack', `${domain}.json`), {
      source: 'MITRE ATT&CK',
      notice: '(c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.',
      domain,
      version: latest.version,
      tactics: [...tactics.values()].sort((a, b) => a.id.localeCompare(b.id)),
      techniqueCount: techniques.length,
      techniques,
    });

    result.domains[domain] = { version: latest.version, techniques: techniques.length };
  }

  return result;
}

async function syncCwe(outDir) {
  let version = 'unknown';
  try {
    const meta = await getJson(SOURCES.cweVersion);
    version = meta?.ContentVersion ?? meta?.version ?? 'unknown';
  } catch {
    process.stderr.write('  warning: CWE version endpoint unavailable\n');
  }

  // The API caps how many ids one call may carry; chunk conservatively.
  const chunks = chunk(CWE_TOP25_2025, 10);
  const responses = await pooled(chunks, (ids) => getJson(SOURCES.cweWeakness(ids)), 2);

  const byId = new Map();
  for (const response of responses) {
    if (!response.ok) {
      process.stderr.write(`  warning: CWE chunk failed: ${response.error.message}\n`);
      continue;
    }
    for (const weakness of response.value?.Weaknesses ?? []) {
      byId.set(Number(weakness.ID), {
        id: `CWE-${weakness.ID}`,
        name: weakness.Name,
        abstraction: weakness.Abstraction,
        summary: firstSentence(stripTags(weakness.Description ?? '')),
        url: `https://cwe.mitre.org/data/definitions/${weakness.ID}.html`,
      });
    }
  }

  const top25 = CWE_TOP25_2025.map((id, position) => ({
    rank: position + 1,
    ...(byId.get(id) ?? { id: `CWE-${id}`, name: '', abstraction: '', summary: '', url: `https://cwe.mitre.org/data/definitions/${id}.html` }),
  }));

  writeJson(path.join(outDir, 'cwe', 'top25.json'), {
    source: 'MITRE CWE Top 25 Most Dangerous Software Weaknesses',
    notice: 'Copyright (c) 2006-2026, The MITRE Corporation. CWE and the CWE logo are trademarks of The MITRE Corporation.',
    edition: 2025,
    view: 'CWE-1435',
    catalogVersion: version,
    entries: top25,
  });

  return { version, entries: top25.length, resolved: byId.size };
}

/**
 * Vendor FIRST's official CVSS v4.0 tables. They are BSD-2-Clause, which is
 * compatible with this repository's MIT licence provided the copyright notice
 * survives - so it is preserved verbatim in the output.
 *
 * The files are bare JS global assignments, not JSON and not modules, so the
 * assignment prefix is stripped and the remainder parsed.
 */
async function syncCvss(outDir) {
  const [lookupBody, composedBody, severityBody] = await Promise.all([
    getText(SOURCES.cvssLookup),
    getText(SOURCES.cvssMaxComposed),
    getText(SOURCES.cvssMaxSeverity),
  ]);

  const payload = {
    source: 'FIRST.org CVSS v4.0 calculator',
    notice: 'Copyright FIRST, Red Hat, and contributors. SPDX-License-Identifier: BSD-2-Clause',
    upstream: 'https://github.com/FIRSTdotorg/cvss-v4-calculator',
    lookup: parseJsObjectLiteral(lookupBody, 'cvssLookup_global'),
    maxComposed: parseJsObjectLiteral(composedBody, 'maxComposed'),
    maxSeverity: parseJsObjectLiteral(severityBody, 'maxSeverity'),
  };

  writeJson(path.join(outDir, 'cvss', 'v4-tables.json'), payload, { pretty: false });
  return { macrovectors: Object.keys(payload.lookup).length };
}

/**
 * Track the frameworks the methodology cites, so the plugin can tell a user
 * "your guidance references OWASP ASVS 5.0.0" instead of silently drifting.
 *
 * OWASP repositories are inconsistent: Top 10 and API Security publish no
 * usable releases, so those are detected by directory, not by tag.
 */
async function syncFrameworks(outDir) {
  const gh = async (endpoint) => getJson(`https://api.github.com/${endpoint}`, {
    headers: {
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
  });

  const frameworks = {};

  const latestRelease = async (key, repo, filter = () => true) => {
    try {
      const releases = await gh(`repos/${repo}/releases?per_page=30`);
      const match = releases.filter((r) => !r.draft && !r.prerelease && filter(r))[0];
      if (match) frameworks[key] = { repo, version: match.tag_name, releasedAt: match.published_at, url: match.html_url };
    } catch (err) {
      process.stderr.write(`  warning: ${key} release lookup failed: ${err.message}\n`);
    }
  };

  // ASVS republishes a rolling "latest" tag for bleeding edge; ignore it.
  await latestRelease('owasp-asvs', 'OWASP/ASVS', (r) => /_release$/.test(r.tag_name));
  await latestRelease('owasp-mastg', 'OWASP/mastg');
  await latestRelease('owasp-masvs', 'OWASP/masvs');
  await latestRelease('owasp-wstg', 'OWASP/wstg');
  await latestRelease('nuclei-templates', 'projectdiscovery/nuclei-templates');

  for (const [key, repo] of [['owasp-top10', 'OWASP/Top10'], ['owasp-api-top10', 'OWASP/API-Security']]) {
    try {
      const contents = await gh(`repos/${repo}/contents`);
      const years = contents
        .filter((entry) => entry.type === 'dir' && /^\d{4}$/.test(entry.name))
        .map((entry) => Number(entry.name))
        .sort((a, b) => b - a);
      if (years.length) frameworks[key] = { repo, version: String(years[0]), detectedBy: 'directory' };
    } catch (err) {
      process.stderr.write(`  warning: ${key} lookup failed: ${err.message}\n`);
    }
  }

  try {
    const stats = await getJson(SOURCES.nucleiStats);
    frameworks['nuclei-template-stats'] = {
      total: (stats.severity ?? []).reduce((sum, s) => sum + (s.count ?? 0), 0),
      bySeverity: Object.fromEntries((stats.severity ?? []).map((s) => [s.name, s.count])),
    };
  } catch { /* optional */ }

  writeJson(path.join(outDir, 'frameworks.json'), {
    description: 'Upstream versions of the methodology frameworks this plugin references.',
    note: 'Only identifiers and version numbers are recorded. OWASP prose is CC-BY-SA and is linked, never vendored.',
    frameworks,
  });

  return frameworks;
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function firstSentence(text) {
  const clean = stripTags(String(text)).replace(/\s+/g, ' ').trim();
  const match = /^(.{0,280}?[.!?])(\s|$)/.exec(clean);
  return (match ? match[1] : clean.slice(0, 280)).trim();
}

function stripTags(text) {
  return String(text).replace(/<[^>]+>/g, '').replace(/\(Citation:[^)]*\)/g, '');
}

function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function chunk(list, size) {
  const out = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

function hashTree(dir) {
  const files = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name !== 'MANIFEST.json') files.push(full);
    }
  };
  walk(dir);
  return Object.fromEntries(
    files.map((file) => [
      path.relative(dir, file).split(path.sep).join('/'),
      sha256(fs.readFileSync(file)).slice(0, 16),
    ]),
  );
}

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

async function main() {
  const args = parseArgs();
  const outDir = path.resolve(String(args.out ?? path.join(process.cwd(), 'intel')));
  const only = args.only ? new Set(String(args.only).split(',').map((s) => s.trim())) : null;
  const want = (name) => !only || only.has(name);

  ensureDir(outDir);

  const previous = fs.existsSync(path.join(outDir, 'MANIFEST.json'))
    ? JSON.parse(fs.readFileSync(path.join(outDir, 'MANIFEST.json'), 'utf8'))
    : { checksums: {} };

  const results = {};
  const failures = [];

  const tasks = [
    ['kev', () => syncKev(outDir)],
    ['attack', () => syncAttack(outDir)],
    ['cwe', () => syncCwe(outDir)],
    ['cvss', () => syncCvss(outDir)],
    ['frameworks', () => syncFrameworks(outDir)],
  ];

  for (const [name, task] of tasks) {
    if (!want(name)) continue;
    process.stderr.write(`syncing ${name}...\n`);
    try {
      results[name] = await task();
      process.stderr.write(`  ok\n`);
    } catch (err) {
      failures.push({ source: name, error: err.message });
      process.stderr.write(`  FAILED: ${err.message}\n`);
    }
  }

  const checksums = hashTree(outDir);
  const changed = Object.entries(checksums)
    .filter(([file, hash]) => previous.checksums?.[file] !== hash)
    .map(([file]) => file);
  const removed = Object.keys(previous.checksums ?? {}).filter((file) => !(file in checksums));

  /**
   * Materiality decides whether CI cuts a release or just refreshes data.
   * New exploited-in-the-wild entries, a new ATT&CK catalog or a new CWE Top 25
   * change what the plugin knows. Checksum churn on a description does not.
   */
  const material = Boolean(
    results.kev && previous.sources?.kev?.count !== undefined && results.kev.count > previous.sources.kev.count,
  ) || Boolean(
    results.attack && previous.sources?.attack?.version && results.attack.version !== previous.sources.attack.version,
  ) || Boolean(
    results.cwe && previous.sources?.cwe?.version && results.cwe.version !== previous.sources.cwe.version,
  );

  writeJson(path.join(outDir, 'MANIFEST.json'), {
    generatedAt: nowIso(),
    sources: results,
    failures,
    checksums,
  });

  const summary = {
    changedFiles: changed,
    removedFiles: removed,
    material,
    failures,
    newKevEntries: results.kev && previous.sources?.kev?.count !== undefined
      ? results.kev.count - previous.sources.kev.count
      : null,
    sources: results,
  };

  process.stdout.write(JSON.stringify(summary, null, 2) + '\n');

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, [
      `changed=${changed.length > 0}`,
      `material=${material}`,
      `failures=${failures.length}`,
      `summary=${JSON.stringify(summary.sources).replace(/\n/g, ' ')}`,
    ].join('\n') + '\n');
  }

  // A partial failure is not a pipeline failure: stale-but-present intel beats
  // a red build that blocks every other refresh.
  if (failures.length === tasks.filter(([n]) => want(n)).length) process.exit(1);
}

main().catch((err) => {
  process.stderr.write(`intel-sync failed: ${err.stack ?? err.message}\n`);
  process.exit(1);
});
