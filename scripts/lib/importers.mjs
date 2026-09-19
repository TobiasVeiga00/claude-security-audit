/**
 * Scanner output importers.
 *
 * Raw scanner output is enormous, repetitive, and almost entirely irrelevant.
 * Pasting a Trivy report into a conversation can cost tens of thousands of
 * tokens to convey a dozen facts.
 *
 * These importers parse that output deterministically into canonical findings,
 * so the model reasons about a compact list and never sees the noise. That is
 * a large part of why this plugin is cheap to run.
 *
 * Every importer is defensive: scanner schemas change between releases, and a
 * missing field must degrade the finding, never throw away the run.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { posix } from './util.mjs';
import { normalizeSeverity } from './cvss.mjs';

export const SUPPORTED_IMPORTERS = [
  'sarif', 'semgrep', 'gitleaks', 'trufflehog', 'trivy', 'grype',
  'osv-scanner', 'checkov', 'bandit', 'npm-audit', 'nuclei', 'kics', 'prowler',
];

export function importScannerOutput(tool, raw, { root = process.cwd() } = {}) {
  const parse = () => {
    try { return JSON.parse(raw); } catch { return null; }
  };

  switch (tool) {
    case 'sarif': return fromSarif(parse(), root);
    case 'semgrep': return fromSemgrep(parse(), root);
    case 'gitleaks': return fromGitleaks(parse(), root);
    case 'trufflehog': return fromTrufflehog(raw, root);
    case 'trivy': return fromTrivy(parse(), root);
    case 'grype': return fromGrype(parse());
    case 'osv-scanner': return fromOsvScanner(parse(), root);
    case 'checkov': return fromCheckov(parse(), root);
    case 'kics': return fromKics(parse(), root);
    case 'prowler': return fromProwler(parse());
    case 'bandit': return fromBandit(parse(), root);
    case 'npm-audit': return fromNpmAudit(parse());
    case 'nuclei': return fromNuclei(raw);
    default:
      throw new Error(`unsupported importer "${tool}". Supported: ${SUPPORTED_IMPORTERS.join(', ')}`);
  }
}

// Defensive coercion helpers: a scanner schema changes between releases, and a
// missing or wrong-typed field must degrade one finding, never throw away the
// whole import.
const arr = (value) => (Array.isArray(value) ? value : []);
const str = (value) => (typeof value === 'string' ? value : (value == null ? '' : String(value)));

const rel = (file, root) => {
  if (!file) return null;
  let clean = String(file);
  if (clean.startsWith('file://')) {
    try { clean = fileURLToPath(clean); } catch { clean = clean.replace(/^file:\/\//, ''); }
  } else {
    try { clean = decodeURIComponent(clean); } catch { /* leave as-is */ }
  }
  return posix(path.isAbsolute(clean) ? path.relative(root, clean) : clean);
};

// Accepts "CWE-79", "cwe-079", "external/cwe/cwe-079" or a bare number, and
// normalises to CWE-<n> without a leading zero, so a scanner's zero-padded form
// matches the plugin's own CWE ids.
const cweFrom = (values) => [...new Set(
  [].concat(values ?? [])
    .flatMap((v) => str(v).match(/(\d+)/g) ?? [])
    .map((digits) => `CWE-${parseInt(digits, 10)}`),
)];

/**
 * Mask a credential in imported evidence when the finding is secret-class, so a
 * secret scanner's output routed through a code-shaped importer does not leak
 * the credential the way the dedicated secret importers avoid.
 */
function safeEvidence(content, { secret = false } = {}) {
  const text = str(content);
  if (!text) return [];
  return [{ type: 'code', content: secret ? redact(text) : text.slice(0, 1200) }];
}

function looksSecret(domain, ruleId) {
  return domain === 'secrets' || /secret|password|token|credential|api[_-]?key/i.test(str(ruleId));
}

/**
 * Parse tool output that is normally newline-delimited JSON but is sometimes a
 * JSON array (`jq -s`, `-je`, pretty-printed). Returns an array of objects,
 * never throwing on a bad line.
 */
function ndjson(raw) {
  const text = str(raw).trim();
  if (!text) return [];
  if (text[0] === '[') {
    try { const parsed = JSON.parse(text); return Array.isArray(parsed) ? parsed : []; } catch { /* fall through to line parsing */ }
  }
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try { out.push(JSON.parse(t)); } catch { /* skip a malformed line */ }
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * SARIF 2.1.0 - the universal format
 * ------------------------------------------------------------------ */

// SARIF result kinds that are not a live vulnerability, and how to treat them.
const SARIF_KIND_DROP = new Set(['pass', 'notApplicable']);
const SARIF_KIND_REVIEW = new Set(['review', 'open', 'informational']);

function fromSarif(data, root) {
  const out = [];

  for (const run of arr(data?.runs)) {
    const toolName = str(run?.tool?.driver?.name) || 'sarif';
    const rules = new Map(arr(run?.tool?.driver?.rules).filter((r) => r?.id).map((r) => [r.id, r]));

    for (const result of arr(run?.results)) {
      if (!result || typeof result !== 'object') continue;
      // A suppressed result is not a live finding.
      if (arr(result.suppressions).some((s) => s?.status !== 'rejected')) continue;
      const kind = result.kind;
      if (SARIF_KIND_DROP.has(kind)) continue;
      const isReview = SARIF_KIND_REVIEW.has(kind);

      const rule = rules.get(result.ruleId) ?? {};
      const loc = result.locations?.[0]?.physicalLocation ?? {};
      const rawSecSev = rule.properties?.['security-severity'];
      const securitySeverity = rawSecSev == null ? NaN : Number(rawSecSev);
      const domain = guessDomain(arr(rule.properties?.tags), str(loc.artifactLocation?.uri));

      out.push({
        title: str(result.message?.text).split('\n')[0]?.slice(0, 160)
          || str(rule.shortDescription?.text)
          || str(result.ruleId)
          || 'SARIF result',
        severity: Number.isFinite(securitySeverity)
          ? normalizeSeverity(securitySeverity)
          : sarifLevelToSeverity(result.level ?? rule.defaultConfiguration?.level),
        verdict: isReview ? 'needs-validation' : 'confirmed',
        confidence: { 'very-high': 'confirmed', high: 'firm', medium: 'tentative', low: 'tentative' }[rule.properties?.precision] ?? 'tentative',
        domain,
        cwe: cweFrom(rule.properties?.tags),
        description: str(rule.fullDescription?.text) || str(result.message?.text),
        location: {
          file: rel(loc.artifactLocation?.uri, root),
          startLine: loc.region?.startLine ?? null,
          endLine: loc.region?.endLine ?? null,
        },
        evidence: safeEvidence(loc.region?.snippet?.text, { secret: looksSecret(domain, result.ruleId) }),
        remediation: { summary: str(rule.help?.text), references: [rule.helpUri].filter(Boolean) },
        blockers: isReview ? ['Reported by the scanner as requiring human review'] : [],
        source: { tool: toolName, rule: str(result.ruleId) },
      });
    }
  }
  return out;
}

const sarifLevelToSeverity = (level) =>
  ({ error: 'high', warning: 'medium', note: 'low', none: 'info' })[level] ?? 'info';

/* ------------------------------------------------------------------ *
 * Per-tool importers
 * ------------------------------------------------------------------ */

function fromSemgrep(data, root) {
  return arr(data?.results).filter((r) => r && typeof r === 'object').map((r) => {
    const extra = r.extra ?? {};
    const meta = extra.metadata ?? {};
    const domain = guessDomain([].concat(meta.category ?? [], meta.technology ?? []), str(r.path));
    return {
      title: (str(extra.message) || str(r.check_id) || 'Semgrep finding').split('\n')[0].slice(0, 160),
      severity: normalizeSeverity(meta.impact ?? extra.severity),
      confidence: { HIGH: 'firm', MEDIUM: 'tentative', LOW: 'tentative' }[meta.confidence] ?? 'tentative',
      domain,
      cwe: cweFrom(meta.cwe),
      owasp: [].concat(meta.owasp ?? []),
      description: str(extra.message),
      location: { file: rel(r.path, root), startLine: r.start?.line ?? null, endLine: r.end?.line ?? null },
      evidence: safeEvidence(extra.lines, { secret: looksSecret(domain, r.check_id) }),
      remediation: { summary: str(extra.fix), references: [].concat(meta.references ?? []) },
      source: { tool: 'semgrep', rule: str(r.check_id) },
    };
  });
}

function fromGitleaks(data, root) {
  return (Array.isArray(data) ? data : []).filter((r) => r && typeof r === 'object').map((r) => ({
    title: `Secret detected: ${r.RuleID ?? r.Description ?? 'unknown rule'}`,
    severity: 'critical',
    confidence: 'firm',
    domain: 'secrets',
    cwe: ['CWE-798'],
    description: r.Description ?? 'A credential-shaped value was found in tracked content.',
    impact: 'Anyone with read access to this repository holds this credential. Treat it as compromised and rotate it.',
    location: { file: rel(r.File, root), startLine: r.StartLine ?? null, endLine: r.EndLine ?? null },
    evidence: [{ type: 'note', label: 'Match', content: redact(r.Secret ?? r.Match ?? ''), redacted: true }],
    remediation: {
      summary: 'Revoke and rotate the credential, then remove it from history and move it to a managed secret store.',
      steps: [
        'Revoke the credential at the provider immediately — rotation alone does not help if it already leaked.',
        'Issue a replacement and load it from the environment or a secret manager.',
        'Purge it from git history (git filter-repo or BFG) and force-push with the team coordinated.',
        'Audit provider logs for use of the exposed credential.',
      ],
      effort: 'medium',
    },
    tags: r.Commit ? [`commit:${String(r.Commit).slice(0, 12)}`] : [],
    source: { tool: 'gitleaks', rule: r.RuleID ?? '' },
  }));
}

function fromTrufflehog(raw, root) {
  // TruffleHog emits newline-delimited JSON, but a `jq -s` or array export is
  // common too; ndjson() accepts either.
  return ndjson(raw).flatMap((r) => {
    if (!r || typeof r !== 'object') return [];
    const meta = r.SourceMetadata?.Data ?? {};
    const filesystem = meta.Filesystem ?? meta.Git ?? {};
    const verified = r.Verified === true;
    return [{
      title: `${verified ? 'Verified live secret' : 'Secret detected'}: ${r.DetectorName ?? 'unknown'}`,
      severity: 'critical',
      confidence: verified ? 'confirmed' : 'firm',
      domain: 'secrets',
      cwe: ['CWE-798'],
      description: verified
        ? 'TruffleHog authenticated against the provider with this credential, so it is live right now.'
        : 'A credential-shaped value matched a provider detector but was not verified.',
      location: { file: rel(filesystem.file ?? filesystem.path, root), startLine: filesystem.line ?? null },
      evidence: [{ type: 'note', content: redact(r.Raw ?? ''), redacted: true }],
      remediation: { summary: 'Revoke, rotate, purge from history, and audit provider logs for use.', effort: 'medium' },
      tags: verified ? ['verified-live'] : [],
      source: { tool: 'trufflehog', rule: r.DetectorName ?? '' },
    }];
  });
}

function fromTrivy(data, root) {
  const out = [];
  for (const result of arr(data?.Results)) {
    for (const v of arr(result.Vulnerabilities)) {
      out.push({
        title: `${v.PkgName}@${v.InstalledVersion}: ${v.Title ?? v.VulnerabilityID}`,
        severity: normalizeSeverity(v.Severity),
        confidence: 'firm',
        domain: 'dependencies',
        cve: [v.VulnerabilityID].filter((id) => /^CVE-/.test(id)),
        cwe: cweFrom(v.CweIDs),
        cvss: v.CVSS?.nvd?.V3Vector ?? v.CVSS?.redhat?.V3Vector ?? null,
        description: v.Description ?? '',
        location: { package: v.PkgName, version: v.InstalledVersion, ecosystem: result.Type, file: rel(result.Target, root) },
        remediation: {
          summary: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later.` : 'No fixed version is published yet; assess mitigations or replace the dependency.',
          references: (v.References ?? []).slice(0, 5),
          effort: v.FixedVersion ? 'small' : 'large',
        },
        source: { tool: 'trivy', rule: v.VulnerabilityID ?? '' },
      });
    }
    for (const m of arr(result.Misconfigurations)) {
      out.push({
        title: m.Title ?? m.ID,
        severity: normalizeSeverity(m.Severity),
        confidence: 'firm',
        domain: /dockerfile|image/i.test(result.Type ?? '') ? 'container' : 'iac',
        description: m.Description ?? '',
        location: { file: rel(result.Target, root), startLine: m.CauseMetadata?.StartLine ?? null, resource: m.CauseMetadata?.Resource ?? null },
        remediation: { summary: m.Resolution ?? '', references: (m.References ?? []).slice(0, 5) },
        source: { tool: 'trivy', rule: m.ID ?? '' },
      });
    }
    for (const sec of arr(result.Secrets)) {
      out.push({
        title: `Secret detected: ${str(sec.RuleID) || str(sec.Title)}`,
        severity: 'critical',
        confidence: 'firm',
        domain: 'secrets',
        cwe: ['CWE-798'],
        location: { file: rel(result.Target, root), startLine: sec.StartLine ?? null },
        evidence: [{ type: 'note', content: redact(sec.Match ?? ''), redacted: true }],
        remediation: { summary: 'Revoke, rotate and purge from history.', effort: 'medium' },
        source: { tool: 'trivy', rule: str(sec.RuleID) },
      });
    }
  }
  return out;
}

function fromGrype(data) {
  return arr(data?.matches).filter((m) => m && typeof m === 'object').map((m) => {
    const v = m.vulnerability ?? {};
    const artifact = m.artifact ?? {};
    return {
      title: `${artifact.name}@${artifact.version}: ${v.id}`,
      severity: normalizeSeverity(v.severity),
      confidence: 'firm',
      domain: 'dependencies',
      cve: [v.id].filter((id) => /^CVE-/.test(id)),
      cvss: v.cvss?.[0]?.vector ?? null,
      description: v.description ?? '',
      location: { package: artifact.name, version: artifact.version, ecosystem: artifact.type },
      remediation: {
        summary: (m.vulnerability?.fix?.versions ?? []).length
          ? `Upgrade to ${m.vulnerability.fix.versions.join(' or ')}.`
          : 'No fix is published yet.',
        references: [v.dataSource].filter(Boolean),
      },
      source: { tool: 'grype', rule: v.id ?? '' },
    };
  });
}

function fromOsvScanner(data, root) {
  const out = [];
  for (const result of arr(data?.results)) {
    const source = result.source?.path;
    for (const pkg of arr(result.packages)) {
      for (const v of arr(pkg.vulnerabilities)) {
        const cves = (v.aliases ?? []).filter((a) => a.startsWith('CVE-'));
        out.push({
          title: `${pkg.package?.name}@${pkg.package?.version}: ${v.summary ?? v.id}`,
          severity: normalizeSeverity(v.database_specific?.severity ?? 'medium'),
          confidence: 'firm',
          domain: 'dependencies',
          cve: cves,
          cwe: cweFrom(v.database_specific?.cwe_ids),
          cvss: (v.severity ?? []).find((s) => /CVSS_V3|CVSS_V4/.test(s.type))?.score ?? null,
          description: v.details?.slice(0, 1500) ?? v.summary ?? '',
          location: { package: pkg.package?.name, version: pkg.package?.version, ecosystem: pkg.package?.ecosystem, file: rel(source, root) },
          remediation: { summary: 'Upgrade to a version outside the affected range.', references: (v.references ?? []).slice(0, 5).map((r) => r.url) },
          source: { tool: 'osv-scanner', rule: v.id ?? '' },
        });
      }
    }
  }
  return out;
}

function fromCheckov(data, root) {
  const blocks = Array.isArray(data) ? data : [data];
  const out = [];
  for (const block of blocks) {
    for (const check of arr(block?.results?.failed_checks)) {
      out.push({
        title: check.check_name ?? check.check_id,
        severity: normalizeSeverity(check.severity ?? 'medium'),
        confidence: 'firm',
        domain: /kubernetes|dockerfile/i.test(block.check_type ?? '') ? 'container' : 'iac',
        description: check.check_name ?? '',
        location: {
          file: rel(check.file_path, root),
          startLine: check.file_line_range?.[0] ?? null,
          endLine: check.file_line_range?.[1] ?? null,
          resource: check.resource ?? null,
        },
        evidence: arr(check.code_block).length
          ? safeEvidence(arr(check.code_block).map((l) => (Array.isArray(l) ? l[1] : l)).join(''), { secret: /secret|CKV_SECRET/i.test(str(check.check_id)) })
          : [],
        remediation: { summary: check.guideline ?? '', references: [check.guideline].filter(Boolean) },
        source: { tool: 'checkov', rule: check.check_id ?? '' },
      });
    }
  }
  return out;
}

function fromKics(data, root) {
  const out = [];
  for (const query of arr(data?.queries)) {
    for (const file of arr(query.files)) {
      out.push({
        title: query.query_name ?? 'KICS finding',
        severity: normalizeSeverity(query.severity),
        confidence: 'firm',
        domain: 'iac',
        cwe: cweFrom(query.cwe),
        description: query.description ?? '',
        location: { file: rel(file.file_name, root), startLine: file.line ?? null, resource: file.resource_name ?? null },
        evidence: file.actual_value ? [{ type: 'note', content: `expected: ${file.expected_value}\nactual: ${file.actual_value}` }] : [],
        remediation: { summary: file.expected_value ? `Expected: ${file.expected_value}` : '', references: [query.query_url].filter(Boolean) },
        source: { tool: 'kics', rule: query.query_id ?? '' },
      });
    }
  }
  return out;
}

// OCSF severity_id -> our scale. Prowler's json-ocsf carries both a numeric id
// and a string; the id is authoritative when present.
const OCSF_SEVERITY = { 0: 'info', 1: 'info', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical', 6: 'critical' };

/**
 * Prowler `-M json-ocsf` (the cloud skill's recommended output). An array of
 * OCSF Detection Findings; only FAILs are findings. Defensive against the field
 * drift between Prowler 3/4/5 — a missing field degrades one finding, never the
 * whole import.
 */
function fromProwler(data) {
  const findings = Array.isArray(data) ? data : arr(data?.findings);
  const out = [];
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const status = str(f.status_code || f.status).toUpperCase();
    if (status && status !== 'FAIL' && status !== 'FAILURE') continue;
    const info = f.finding_info ?? {};
    const resource = arr(f.resources)[0] ?? {};
    const unmapped = f.unmapped ?? {};
    const cloud = f.cloud ?? {};
    const severity = OCSF_SEVERITY[f.severity_id] ?? normalizeSeverity(str(f.severity) || 'medium');
    const detail = str(f.status_detail || f.risk_details || f.message);
    out.push({
      title: str(info.title || unmapped.check_title || f.message || 'Prowler finding'),
      severity: normalizeSeverity(severity),
      confidence: 'firm',
      domain: 'cloud',
      description: str(info.desc || f.risk_details || f.message),
      location: {
        resource: str(resource.uid || resource.name) || null,
        region: str(resource.region || cloud.region || f.region) || null,
        provider: str(cloud.provider || unmapped.provider) || null,
      },
      evidence: detail ? [{ type: 'note', content: detail.slice(0, 500) }] : [],
      remediation: {
        summary: str(f.remediation?.desc || f.remediation?.description),
        references: arr(f.remediation?.references).map(str).filter(Boolean),
      },
      source: { tool: 'prowler', rule: str(unmapped.check_id || f.metadata?.event_code || info.uid) },
    });
  }
  return out;
}

function fromBandit(data, root) {
  return arr(data?.results).filter((r) => r && typeof r === 'object').map((r) => ({
    title: str(r.issue_text) || str(r.test_name) || 'Bandit finding',
    severity: normalizeSeverity(r.issue_severity),
    confidence: { HIGH: 'firm', MEDIUM: 'tentative', LOW: 'tentative' }[r.issue_confidence] ?? 'tentative',
    domain: 'code',
    // bandit's issue_cwe.id is a bare integer; cweFrom now accepts that.
    cwe: cweFrom(r.issue_cwe?.id),
    description: str(r.issue_text),
    location: { file: rel(r.filename, root), startLine: r.line_number ?? null },
    // A B105/B106/B107 (hardcoded password) finding's code IS the secret.
    evidence: safeEvidence(r.code, { secret: /B10[567]/.test(str(r.test_id)) }),
    remediation: { references: [r.more_info].filter(Boolean) },
    source: { tool: 'bandit', rule: str(r.test_id) },
  }));
}

function fromNpmAudit(data) {
  const out = [];
  for (const [name, advisory] of Object.entries(data?.vulnerabilities ?? {})) {
    const via = (advisory.via ?? []).filter((v) => typeof v === 'object');
    for (const entry of via.length ? via : [{ title: `Vulnerable dependency ${name}`, url: '' }]) {
      out.push({
        title: `${name}: ${entry.title ?? 'known vulnerability'}`,
        severity: normalizeSeverity(entry.severity ?? advisory.severity),
        confidence: 'firm',
        domain: 'dependencies',
        cve: (entry.cve ? [entry.cve] : []).concat(entry.cves ?? []),
        cwe: cweFrom(entry.cwe),
        cvss: entry.cvss?.vectorString ?? null,
        description: entry.title ?? '',
        location: { package: name, version: advisory.range ?? null, ecosystem: 'npm' },
        remediation: {
          summary: advisory.fixAvailable ? 'A fix is available; run `npm audit fix` or upgrade the dependent package.' : 'No fix is available; assess replacement.',
          references: [entry.url].filter(Boolean),
        },
        source: { tool: 'npm-audit', rule: String(entry.source ?? name) },
      });
    }
  }
  return out;
}

function fromNuclei(raw) {
  return ndjson(raw).flatMap((r) => {
    if (!r || typeof r !== 'object') return [];
    const info = r.info ?? {};
    return [{
      title: str(info.name) || str(r['template-id']) || 'Nuclei finding',
      severity: normalizeSeverity(info.severity),
      confidence: 'firm',
      domain: 'web',
      cve: [].concat(info.classification?.['cve-id'] ?? []).map((c) => String(c).toUpperCase()),
      cwe: cweFrom(info.classification?.['cwe-id']),
      cvss: info.classification?.['cvss-metrics'] ?? null,
      description: str(info.description),
      location: { url: r['matched-at'] ?? r.host ?? null, host: r.host ?? null },
      evidence: arr(r['extracted-results']).length
        ? [{ type: 'response', content: arr(r['extracted-results']).join('\n').slice(0, 1200) }]
        : [],
      remediation: { summary: str(info.remediation), references: [].concat(info.reference ?? []) },
      source: { tool: 'nuclei', rule: str(r['template-id']) },
    }];
  });
}

/* ------------------------------------------------------------------ */

function redact(value) {
  const str = String(value ?? '');
  if (!str) return '';
  if (str.length <= 10) return `${str.slice(0, 2)}${'*'.repeat(8)}`;
  return `${str.slice(0, 4)}${'*'.repeat(8)}${str.slice(-4)} (length ${str.length})`;
}

function guessDomain(tags, file) {
  const haystack = `${[].concat(tags ?? []).join(' ')} ${file ?? ''}`.toLowerCase();
  if (/secret|credential|token|password/.test(haystack)) return 'secrets';
  if (/terraform|cloudformation|\.tf|iac|helm/.test(haystack)) return 'iac';
  if (/docker|kubernetes|k8s|container/.test(haystack)) return 'container';
  if (/dependency|package|sca|supply/.test(haystack)) return 'dependencies';
  if (/android|ios|swift|kotlin|mobile/.test(haystack)) return 'mobile';
  if (/aws|azure|gcp|cloud/.test(haystack)) return 'cloud';
  if (/api|graphql|openapi/.test(haystack)) return 'api';
  if (/xss|csrf|browser|dom/.test(haystack)) return 'web';
  if (/llm|prompt|genai/.test(haystack)) return 'llm';
  return 'code';
}
