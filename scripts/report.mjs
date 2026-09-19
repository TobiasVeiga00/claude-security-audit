#!/usr/bin/env node
/**
 * Report renderer.
 *
 * Takes the finding ledger and produces the deliverable, in the formats an
 * engagement actually needs:
 *
 *   markdown  the working document, diffable and reviewable in a PR
 *   html      a self-contained, printable report (Ctrl+P gives a clean PDF)
 *   sarif     SARIF 2.1.0, so GitHub code scanning shows findings inline
 *   json      the machine-readable record
 *   csv       for the remediation tracker the client already uses
 *
 * A security report is read by three audiences at once - an executive who
 * needs the risk posture in thirty seconds, an engineer who needs the exact
 * line and the fix, and an auditor who needs to challenge every claim. The
 * structure below serves all three rather than averaging them.
 *
 * Usage:
 *   node report.mjs --format markdown,html,sarif --out ./security-report
 */

import fs from 'node:fs';
import path from 'node:path';
import { FindingStore, byPriorityDesc } from './lib/findings.mjs';
import { SLA_DAYS, severityRank } from './lib/cvss.mjs';
import { loadScope } from './lib/scope.mjs';
import { parseArgs, readJson, nowIso, ensureDir, fail } from './lib/util.mjs';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_COLOR = {
  critical: '#b3123c',
  high: '#d64518',
  medium: '#b8860b',
  low: '#2a7ab0',
  info: '#6b7280',
};

/* ------------------------------------------------------------------ *
 * Escaping - a report full of attacker-controlled strings must not
 * become the next injection vector.
 * ------------------------------------------------------------------ */

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeMd(value) {
  // Neutralise the characters that would break out of a table cell or a heading.
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function fence(content, lang = '') {
  const body = String(content ?? '');
  // Pick a fence longer than any run of backticks inside the content.
  const longest = (body.match(/`+/g) ?? ['']).reduce((a, b) => (b.length > a.length ? b : a), '');
  const ticks = '`'.repeat(Math.max(3, longest.length + 1));
  return `${ticks}${lang}\n${body}\n${ticks}`;
}

function csvCell(value) {
  const str = String(value ?? '').replace(/\r?\n/g, ' ');
  // Defuse spreadsheet formula injection: a cell starting with =, +, -, @ is
  // executed by Excel and Sheets when the client opens the tracker.
  const guarded = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
  return `"${guarded.replace(/"/g, '""')}"`;
}

/* ------------------------------------------------------------------ *
 * Aggregation
 * ------------------------------------------------------------------ */

function buildModel(findings, { scope, meta }) {
  const live = findings.filter((f) => !['false-positive', 'duplicate'].includes(f.status));

  // Unvalidated leads never enter the severity counts, the roadmap or the
  // posture calculation. They get their own section, without a severity, so a
  // reader can tell "we proved this" from "we suspect this" at a glance.
  const needsValidation = live.filter((f) => f.verdict === 'needs-validation');
  const open = live.filter((f) => f.verdict !== 'needs-validation');

  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, []]));
  for (const f of open) (bySeverity[f.severity] ??= []).push(f);

  const byTier = { P0: [], P1: [], P2: [], P3: [], P4: [] };
  for (const f of open) (byTier[f.risk?.tier ?? 'P4'] ??= []).push(f);

  const byDomain = {};
  for (const f of open) (byDomain[f.domain] ??= []).push(f);

  const frameworks = { owasp: {}, cwe: {}, attack: {}, masvs: {}, wstg: {} };
  for (const f of open) {
    for (const key of ['owasp', 'cwe', 'attack', 'masvs', 'wstg']) {
      for (const id of f[key] ?? []) {
        (frameworks[key][id] ??= []).push(f.id);
      }
    }
  }

  const tools = [...new Set(open.flatMap((f) => [f.source?.tool, ...(f.corroboratedBy ?? [])]).filter(Boolean))];

  const exploited = open.filter((f) => f.kev);
  const confirmed = open.filter((f) => f.confidence === 'confirmed');

  return {
    meta: {
      title: meta.title ?? 'Security Audit Report',
      client: scope?.engagement?.client || meta.client || '',
      engagement: scope?.engagement?.name || meta.engagement || '',
      auditor: scope?.engagement?.auditor || meta.auditor || '',
      generatedAt: nowIso(),
      reference: scope?.authorization?.reference || '',
      window: scope?.engagement?.startsAt && scope?.engagement?.endsAt
        ? `${scope.engagement.startsAt} to ${scope.engagement.endsAt}`
        : '',
      classification: meta.classification ?? 'CONFIDENTIAL',
    },
    scope,
    totals: {
      all: findings.length,
      open: open.length,
      needsValidation: needsValidation.length,
      falsePositives: findings.filter((f) => f.status === 'false-positive').length,
      fixed: findings.filter((f) => f.status === 'fixed').length,
      accepted: findings.filter((f) => f.status === 'accepted-risk').length,
      knownExploited: exploited.length,
      confirmed: confirmed.length,
    },
    bySeverity,
    byTier,
    byDomain,
    frameworks,
    tools,
    findings: open.sort(byPriorityDesc),
    needsValidation,
  };
}

function riskPosture(model) {
  const s = model.bySeverity;
  if (s.critical.length > 0 || model.totals.knownExploited > 0) {
    return {
      label: 'CRITICAL',
      color: SEVERITY_COLOR.critical,
      statement: 'The target carries defects that a motivated attacker can exploit now. Treat remediation as an incident, not as backlog.',
    };
  }
  if (s.high.length > 2) {
    return {
      label: 'HIGH',
      color: SEVERITY_COLOR.high,
      statement: 'Multiple high-severity weaknesses are present. A chained attack is realistic and remediation should pre-empt the next release.',
    };
  }
  if (s.high.length > 0) {
    return {
      label: 'ELEVATED',
      color: SEVERITY_COLOR.high,
      statement: 'At least one high-severity weakness is present. It should be closed inside the current sprint.',
    };
  }
  if (s.medium.length > 0) {
    return {
      label: 'MODERATE',
      color: SEVERITY_COLOR.medium,
      statement: 'No critical exposure was identified. The remaining issues weaken defence in depth and should be scheduled.',
    };
  }
  return {
    label: 'LOW',
    color: SEVERITY_COLOR.low,
    statement: 'No significant exposure was identified within the declared scope and methodology. Absence of findings is not proof of absence of defects.',
  };
}

/* ------------------------------------------------------------------ *
 * Markdown
 * ------------------------------------------------------------------ */

function renderMarkdown(model) {
  const { meta, totals } = model;
  const posture = riskPosture(model);
  const out = [];
  const p = (...lines) => out.push(...lines);

  p(`# ${meta.title}`, '');
  p(`> **${meta.classification}** — this document describes unremediated security defects.`, '');

  const facts = [
    ['Client', meta.client],
    ['Engagement', meta.engagement],
    ['Authorization ref.', meta.reference],
    ['Test window', meta.window],
    ['Auditor', meta.auditor],
    ['Generated', meta.generatedAt],
  ].filter(([, v]) => v);
  if (facts.length) {
    p('| Field | Value |', '| --- | --- |');
    for (const [k, v] of facts) p(`| ${k} | ${escapeMd(v)} |`);
    p('');
  }

  /* -------- 1. Executive summary -------- */
  p('## 1. Executive summary', '');
  p(`**Overall risk posture: ${posture.label}**`, '');
  p(posture.statement, '');

  p('| Severity | Open findings |', '| --- | --- |');
  for (const sev of SEVERITY_ORDER) {
    p(`| ${sev[0].toUpperCase() + sev.slice(1)} | ${model.bySeverity[sev].length} |`);
  }
  p(`| **Total** | **${totals.open}** |`, '');

  const headline = [];
  if (totals.knownExploited > 0) {
    headline.push(`- **${totals.knownExploited}** finding(s) involve vulnerabilities that CISA lists as actively exploited in the wild. These are not theoretical.`);
  }
  if (model.byTier.P0.length > 0) {
    headline.push(`- **${model.byTier.P0.length}** finding(s) are P0: fix within ${SLA_DAYS.P0} day.`);
  }
  if (model.byTier.P1.length > 0) {
    headline.push(`- **${model.byTier.P1.length}** finding(s) are P1: fix within ${SLA_DAYS.P1} days.`);
  }
  if (totals.falsePositives > 0) {
    headline.push(`- ${totals.falsePositives} candidate(s) were triaged and dismissed as false positives; they are excluded from the counts above.`);
  }
  if (headline.length) p(...headline, '');

  if (model.bySeverity.critical.length || model.bySeverity.high.length) {
    p('### What to fix first', '');
    const top = [...model.bySeverity.critical, ...model.bySeverity.high].slice(0, 8);
    for (const f of top) {
      p(`1. **${escapeMd(f.title)}** (${f.id}, ${f.risk?.tier ?? 'P?'}) — ${escapeMd(truncate(f.impact || f.description, 200))}`);
    }
    p('');
  }

  /* -------- 2. Scope -------- */
  p('## 2. Scope and rules of engagement', '');
  if (model.scope) {
    const t = model.scope.targets ?? {};
    const rows = [
      ['Repositories', (t.repos ?? []).join(', ')],
      ['Hosts', (t.hosts ?? []).join(', ')],
      ['Domains', (t.domains ?? []).join(', ')],
      ['IP ranges', (t.ipRanges ?? []).join(', ')],
      ['Cloud accounts', (t.cloudAccounts ?? []).join(', ')],
      ['Mobile apps', (t.mobileApps ?? []).join(', ')],
      ['Wireless', [...(t.wireless?.ssids ?? []), ...(t.wireless?.bssids ?? [])].join(', ')],
    ].filter(([, v]) => v);
    if (rows.length) {
      p('**In scope**', '', '| Asset class | Targets |', '| --- | --- |');
      for (const [k, v] of rows) p(`| ${k} | ${escapeMd(v)} |`);
      p('');
    }
    const oos = model.scope.outOfScope ?? {};
    const oosList = [...(oos.hosts ?? []), ...(oos.domains ?? []), ...(oos.ipRanges ?? [])];
    if (oosList.length) p(`**Explicitly out of scope:** ${escapeMd(oosList.join(', '))}`, '');
    if ((oos.notes ?? []).length) p(...oos.notes.map((n) => `> ${escapeMd(n)}`), '');

    const rules = model.scope.rules ?? {};
    p('**Permitted activity**', '');
    for (const [rule, allowed] of Object.entries(rules)) {
      if (typeof allowed !== 'boolean') continue;
      p(`- ${allowed ? 'Permitted' : 'Not permitted'}: ${humanize(rule)}`);
    }
    p('');
  } else {
    p('_No rules-of-engagement document was recorded for this audit. Findings below derive from static analysis of supplied artefacts only._', '');
  }

  /* -------- 3. Methodology -------- */
  p('## 3. Methodology', '');
  p('The assessment followed a structured, evidence-first methodology. Every finding below is anchored to a concrete location and, where the class of defect allows it, to reproducible evidence. Findings that could not be corroborated were downgraded or dismissed rather than reported.', '');
  const usedFrameworks = Object.entries(model.frameworks)
    .filter(([, map]) => Object.keys(map).length > 0)
    .map(([name]) => FRAMEWORK_LABEL[name] ?? name);
  if (usedFrameworks.length) {
    p(`**Reference frameworks applied:** ${usedFrameworks.join(', ')}.`, '');
  }
  if (model.tools.length) {
    p(`**Tooling:** ${escapeMd(model.tools.join(', '))}.`, '');
  }
  p('**Severity model.** Severity follows CVSS qualitative bands. Remediation *priority* additionally fuses exploit-prediction scoring (EPSS), confirmed in-the-wild exploitation (CISA KEV), exposure of the affected component and, where determinable, reachability of the vulnerable path. A medium-severity defect on an internet-facing path with a public exploit outranks a high-severity defect in unreachable code, and the report orders work accordingly.', '');

  p('| Priority | Meaning | Remediation target |', '| --- | --- | --- |');
  for (const [tier, days] of Object.entries(SLA_DAYS)) {
    p(`| ${tier} | ${TIER_MEANING[tier]} | ${days} day${days === 1 ? '' : 's'} |`);
  }
  p('');

  p('**Limitations.** This assessment reflects the state of the target at the time of testing and the scope declared in section 2. It does not certify the absence of vulnerabilities. Areas excluded from scope were not examined and no assurance is offered over them.', '');

  /* -------- 4. Findings -------- */
  p('## 4. Findings', '');
  if (model.findings.length === 0) {
    p('No findings remained open after triage.', '');
  } else {
    p('| ID | Severity | Priority | Finding | Location |', '| --- | --- | --- | --- | --- |');
    for (const f of model.findings) {
      p(`| [${f.id}](#${anchor(f)}) | ${f.severity} | ${f.risk?.tier ?? ''} | ${escapeMd(f.title)} | ${escapeMd(locationLabel(f))} |`);
    }
    p('');
    for (const f of model.findings) p(...renderFindingMarkdown(f));
  }

  /* -------- 5. Needs validation -------- */
  if (model.needsValidation.length) {
    p('## 5. Needs validation', '');
    p('Each entry below is a **source-grounded hypothesis that this audit could not settle**, because confirming it depends on a fact outside the artefacts in scope — a deployment setting, a runtime value, or the behaviour of a third party.', '');
    p('**These carry no severity on purpose.** They are not low-confidence vulnerabilities; they are open questions. Assigning a number to an unproven claim is how a report loses the reader\'s trust. Resolve the blocker and the lead becomes either a finding or a dismissal.', '');
    p('| ID | Lead | Location | Blocked by | How to settle it |', '| --- | --- | --- | --- | --- |');
    for (const f of model.needsValidation) {
      p(`| ${f.id} | ${escapeMd(f.title)} | ${escapeMd(locationLabel(f))} | ${escapeMd((f.blockers ?? []).join('; ') || 'not stated')} | ${escapeMd((f.validationPlan ?? []).join('; ') || 'not stated')} |`);
    }
    p('');
    for (const f of model.needsValidation) {
      p(`#### ${f.id} — ${escapeMd(f.title)}`, '');
      if (f.description) p(f.description, '');
      if (f.boundary) {
        p('| Boundary element | Claim |', '| --- | --- |');
        for (const [key, label] of [
          ['actor', 'Lower-trust actor'], ['input', 'Accepted input or action'],
          ['control', 'Control that should stop it'], ['crossing', 'Boundary crossed'],
          ['result', 'Observable result'],
        ]) {
          if (f.boundary[key]) p(`| ${label} | ${escapeMd(f.boundary[key])} |`);
        }
        p('');
      }
      const ev = (f.evidence ?? []).filter((e) => e.content);
      for (const item of ev) p(fence(item.content, evidenceLang(item.type)), '');
    }
  }

  /* -------- 6. Roadmap -------- */
  p(`## ${model.needsValidation.length ? 6 : 5}. Remediation roadmap`, '');
  for (const tier of ['P0', 'P1', 'P2', 'P3', 'P4']) {
    const items = model.byTier[tier] ?? [];
    if (!items.length) continue;
    p(`### ${tier} — within ${SLA_DAYS[tier]} day${SLA_DAYS[tier] === 1 ? '' : 's'}`, '');
    for (const f of items) {
      const effort = f.remediation?.effort ? ` _(effort: ${f.remediation.effort})_` : '';
      p(`- **${f.id}** ${escapeMd(f.title)}${effort} — ${escapeMd(truncate(f.remediation?.summary || 'See finding detail.', 180))}`);
    }
    p('');
  }

  /* -------- 6. Framework coverage -------- */
  const frameworkSections = Object.entries(model.frameworks).filter(([, map]) => Object.keys(map).length);
  if (frameworkSections.length) {
    p('## 6. Framework mapping', '');
    for (const [key, map] of frameworkSections) {
      p(`### ${FRAMEWORK_LABEL[key] ?? key}`, '', '| Reference | Findings |', '| --- | --- |');
      for (const [id, ids] of Object.entries(map).sort()) {
        p(`| ${escapeMd(id)} | ${ids.join(', ')} |`);
      }
      p('');
    }
  }

  p('---', '');
  p(`_Generated by [claude-security-audit](https://github.com/TobiasVeiga00/claude-security-audit) on ${meta.generatedAt}._`);

  return out.join('\n');
}

const FRAMEWORK_LABEL = {
  owasp: 'OWASP', cwe: 'CWE (Common Weakness Enumeration)',
  attack: 'MITRE ATT&CK', masvs: 'OWASP MASVS', wstg: 'OWASP WSTG',
};

const TIER_MEANING = {
  P0: 'Exploitable now, or confirmed exploited in the wild',
  P1: 'Serious and reachable; exploitation is realistic',
  P2: 'Material weakness; exploitation needs conditions',
  P3: 'Defence-in-depth gap',
  P4: 'Informational / hardening opportunity',
};

function renderFindingMarkdown(f) {
  const out = [];
  const p = (...lines) => out.push(...lines);

  p(`### ${f.id} — ${escapeMd(f.title)}`, '');

  const tags = [
    `**Severity:** ${f.severity}`,
    `**Priority:** ${f.risk?.tier ?? 'n/a'} (${f.risk?.priority ?? 0}/100)`,
    `**Confidence:** ${f.confidence}`,
    `**Domain:** ${f.domain}`,
  ];
  if (f.cvss?.base != null) tags.push(`**CVSS:** ${f.cvss.base}${f.cvss.vector ? ` \`${f.cvss.vector}\`` : ''}`);
  if (f.epss != null) tags.push(`**EPSS:** ${(f.epss * 100).toFixed(1)}%`);
  if (f.kev) tags.push('**CISA KEV:** yes — exploited in the wild');
  p(tags.join(' · '), '');

  const refs = [
    ...(f.cwe ?? []).map((c) => `[${c}](https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html)`),
    ...(f.owasp ?? []),
    ...(f.attack ?? []).map((t) => `[${t}](https://attack.mitre.org/techniques/${t.replace('.', '/')}/)`),
    ...(f.masvs ?? []), ...(f.wstg ?? []), ...(f.asvs ?? []),
    ...(f.cve ?? []).map((c) => `[${c}](https://nvd.nist.gov/vuln/detail/${c})`),
  ];
  if (refs.length) p(`**Classification:** ${refs.join(', ')}`, '');

  p(`**Location:** \`${locationLabel(f)}\``, '');

  if (f.description) p('**Description**', '', f.description, '');
  if (f.impact) p('**Impact**', '', f.impact, '');

  if (f.risk?.rationale?.length) {
    p('<details><summary>How this priority was derived</summary>', '');
    for (const reason of f.risk.rationale) p(`- ${escapeMd(reason)}`);
    p('', '</details>', '');
  }

  const evidence = (f.evidence ?? []).filter((e) => e.content);
  if (evidence.length) {
    p('**Evidence**', '');
    for (const item of evidence) {
      if (item.label) p(`*${escapeMd(item.label)}*`, '');
      p(fence(item.content, evidenceLang(item.type)), '');
    }
  }

  if ((f.reproduction ?? []).length) {
    p('**Reproduction**', '');
    f.reproduction.forEach((step, i) => p(`${i + 1}. ${step}`));
    p('');
  }

  p('**Remediation**', '');
  if (f.remediation?.summary) p(f.remediation.summary, '');
  if ((f.remediation?.steps ?? []).length) {
    f.remediation.steps.forEach((step, i) => p(`${i + 1}. ${step}`));
    p('');
  }
  if (f.remediation?.patch) p('_Suggested patch_', '', fence(f.remediation.patch, 'diff'), '');
  if ((f.remediation?.references ?? []).length) {
    p('**References**', '');
    for (const ref of f.remediation.references) p(`- ${ref}`);
    p('');
  }

  p(`_Detected by ${escapeMd(f.source?.tool ?? 'manual review')}${f.source?.rule ? ` (rule \`${escapeMd(f.source.rule)}\`)` : ''}. First seen ${f.firstSeen}._`, '');
  p('---', '');
  return out;
}

function evidenceLang(type) {
  return { code: '', request: 'http', response: 'http', command: 'bash', log: '' }[type] ?? '';
}

function locationLabel(f) {
  const l = f.location ?? {};
  if (l.file) return l.startLine ? `${l.file}:${l.startLine}` : l.file;
  if (l.url) return l.url;
  if (l.package) return `${l.package}${l.version ? `@${l.version}` : ''}`;
  if (l.host) return `${l.host}${l.port ? `:${l.port}` : ''}`;
  if (l.resource) return l.resource;
  if (l.ssid) return `SSID ${l.ssid}`;
  return 'n/a';
}

function anchor(f) {
  return `${f.id}--${(f.title ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
}

function truncate(str, n) {
  const s = String(str ?? '').replace(/\s+/g, ' ').trim();
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

function humanize(key) {
  return key.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase()).trim();
}

/* ------------------------------------------------------------------ *
 * HTML
 * ------------------------------------------------------------------ */

function renderHtml(model) {
  const posture = riskPosture(model);
  const { meta } = model;

  const severityBars = SEVERITY_ORDER.map((sev) => {
    const count = model.bySeverity[sev].length;
    const max = Math.max(1, ...SEVERITY_ORDER.map((s) => model.bySeverity[s].length));
    return `<div class="bar-row">
      <span class="bar-label">${sev}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${(count / max) * 100}%;background:${SEVERITY_COLOR[sev]}"></span></span>
      <span class="bar-count">${count}</span>
    </div>`;
  }).join('');

  const findingCards = model.findings.map((f) => {
    const refs = [
      ...(f.cwe ?? []), ...(f.owasp ?? []), ...(f.attack ?? []),
      ...(f.masvs ?? []), ...(f.wstg ?? []), ...(f.cve ?? []),
    ].map((r) => `<span class="chip">${escapeHtml(r)}</span>`).join('');

    const evidence = (f.evidence ?? []).filter((e) => e.content).map((e) => `
      ${e.label ? `<p class="evidence-label">${escapeHtml(e.label)}</p>` : ''}
      <pre><code>${escapeHtml(e.content)}</code></pre>`).join('');

    const steps = (f.remediation?.steps ?? []).map((s) => `<li>${escapeHtml(s)}</li>`).join('');
    const repro = (f.reproduction ?? []).map((s) => `<li>${escapeHtml(s)}</li>`).join('');
    const rationale = (f.risk?.rationale ?? []).map((s) => `<li>${escapeHtml(s)}</li>`).join('');
    const references = (f.remediation?.references ?? [])
      .map((r) => `<li><a href="${escapeHtml(r)}" rel="noopener noreferrer">${escapeHtml(r)}</a></li>`).join('');

    return `
    <article class="finding" id="${escapeHtml(f.id)}">
      <header>
        <span class="sev" style="background:${SEVERITY_COLOR[f.severity]}">${escapeHtml(f.severity)}</span>
        <span class="tier">${escapeHtml(f.risk?.tier ?? '')}</span>
        <h3>${escapeHtml(f.id)} — ${escapeHtml(f.title)}</h3>
      </header>
      <dl class="meta">
        <div><dt>Location</dt><dd><code>${escapeHtml(locationLabel(f))}</code></dd></div>
        <div><dt>Confidence</dt><dd>${escapeHtml(f.confidence)}</dd></div>
        <div><dt>Domain</dt><dd>${escapeHtml(f.domain)}</dd></div>
        ${f.cvss?.base != null ? `<div><dt>CVSS</dt><dd>${escapeHtml(String(f.cvss.base))} <code>${escapeHtml(f.cvss.vector ?? '')}</code></dd></div>` : ''}
        ${f.epss != null ? `<div><dt>EPSS</dt><dd>${(f.epss * 100).toFixed(1)}%</dd></div>` : ''}
        ${f.kev ? '<div><dt>CISA KEV</dt><dd class="kev">Exploited in the wild</dd></div>' : ''}
        <div><dt>Priority</dt><dd>${escapeHtml(String(f.risk?.priority ?? 0))}/100</dd></div>
      </dl>
      ${refs ? `<p class="chips">${refs}</p>` : ''}
      ${f.description ? `<h4>Description</h4><p>${escapeHtml(f.description)}</p>` : ''}
      ${f.impact ? `<h4>Impact</h4><p>${escapeHtml(f.impact)}</p>` : ''}
      ${evidence ? `<h4>Evidence</h4>${evidence}` : ''}
      ${repro ? `<h4>Reproduction</h4><ol>${repro}</ol>` : ''}
      <h4>Remediation</h4>
      ${f.remediation?.summary ? `<p>${escapeHtml(f.remediation.summary)}</p>` : ''}
      ${steps ? `<ol>${steps}</ol>` : ''}
      ${f.remediation?.patch ? `<pre class="patch"><code>${escapeHtml(f.remediation.patch)}</code></pre>` : ''}
      ${references ? `<h4>References</h4><ul>${references}</ul>` : ''}
      ${rationale ? `<details><summary>How this priority was derived</summary><ul>${rationale}</ul></details>` : ''}
      <footer>Detected by ${escapeHtml(f.source?.tool ?? 'manual review')}${f.source?.rule ? ` · rule <code>${escapeHtml(f.source.rule)}</code>` : ''} · first seen ${escapeHtml(f.firstSeen)}</footer>
    </article>`;
  }).join('');

  const roadmap = ['P0', 'P1', 'P2', 'P3', 'P4'].map((tier) => {
    const items = model.byTier[tier] ?? [];
    if (!items.length) return '';
    return `<section class="tier-block">
      <h3>${tier} <small>within ${SLA_DAYS[tier]} day${SLA_DAYS[tier] === 1 ? '' : 's'} — ${escapeHtml(TIER_MEANING[tier])}</small></h3>
      <ul>${items.map((f) => `<li><a href="#${escapeHtml(f.id)}">${escapeHtml(f.id)}</a> ${escapeHtml(f.title)}</li>`).join('')}</ul>
    </section>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(meta.title)}</title>
<style>
:root {
  --bg: #ffffff; --fg: #16181d; --muted: #5c6370; --line: #e3e6ea;
  --card: #fbfcfd; --accent: #1f3a5f; --code-bg: #f5f7f9;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14161a; --fg: #e8eaed; --muted: #9aa1ab; --line: #2a2e35;
    --card: #1b1e24; --accent: #8fb4e3; --code-bg: #1f232a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 48px 16px 96px; }
h1 { font-size: 2.1rem; line-height: 1.2; margin: 0 0 .3em; letter-spacing: -.02em; }
h2 { font-size: 1.45rem; margin: 3rem 0 1rem; padding-bottom: .4rem; border-bottom: 2px solid var(--line); }
h3 { font-size: 1.12rem; margin: 0 0 .6rem; }
h4 { font-size: .95rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 1.4rem 0 .4rem; }
p { margin: 0 0 1rem; }
code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: .87em; background: var(--code-bg); padding: .12em .35em; border-radius: 3px; }
pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; overflow-x: auto; }
pre code { background: none; padding: 0; font-size: .82rem; line-height: 1.5; }
a { color: var(--accent); }
.classification { display: inline-block; font-size: .72rem; font-weight: 700; letter-spacing: .12em; padding: .3em .7em; border: 1px solid currentColor; border-radius: 3px; color: #b3123c; margin-bottom: 1rem; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin: 1.5rem 0 2rem; }
.facts div { background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 10px 13px; }
.facts dt { font-size: .7rem; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }
.facts dd { margin: .2rem 0 0; font-weight: 600; font-size: .92rem; word-break: break-word; }
.posture { border-left: 5px solid ${posture.color}; background: var(--card); padding: 18px 22px; border-radius: 0 6px 6px 0; margin: 0 0 2rem; }
.posture .label { font-size: 1.35rem; font-weight: 700; color: ${posture.color}; letter-spacing: .02em; }
.bars { margin: 1.5rem 0; }
.bar-row { display: grid; grid-template-columns: 76px 1fr 44px; align-items: center; gap: 12px; margin-bottom: 7px; }
.bar-label { font-size: .8rem; text-transform: capitalize; color: var(--muted); }
.bar-track { background: var(--line); height: 11px; border-radius: 6px; overflow: hidden; }
.bar-fill { display: block; height: 100%; border-radius: 6px; min-width: 2px; }
.bar-count { font-variant-numeric: tabular-nums; font-weight: 700; text-align: right; font-size: .9rem; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0 1.6rem; font-size: .88rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.finding { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 22px 24px; margin: 0 0 1.6rem; }
.finding > header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 1rem; }
.finding > header h3 { flex: 1 1 320px; margin: 0; }
.sev { color: #fff; font-size: .68rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; padding: .28em .65em; border-radius: 3px; }
.tier { font-size: .72rem; font-weight: 700; color: var(--muted); border: 1px solid var(--line); padding: .22em .55em; border-radius: 3px; }
dl.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 0 0 1rem; }
dl.meta dt { font-size: .68rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
dl.meta dd { margin: .15rem 0 0; font-size: .87rem; word-break: break-word; }
dl.meta .kev { color: #b3123c; font-weight: 700; }
.chips { margin: 0 0 1rem; }
.chip { display: inline-block; font-size: .72rem; background: var(--code-bg); border: 1px solid var(--line); border-radius: 12px; padding: .18em .7em; margin: 0 5px 5px 0; }
.evidence-label { font-size: .8rem; color: var(--muted); font-style: italic; margin: .8rem 0 .3rem; }
.finding footer { margin-top: 1.3rem; padding-top: .8rem; border-top: 1px solid var(--line); font-size: .78rem; color: var(--muted); }
details { margin: 1rem 0; } summary { cursor: pointer; font-size: .85rem; color: var(--muted); }
.tier-block { margin-bottom: 1.5rem; } .tier-block small { font-weight: 400; color: var(--muted); font-size: .8rem; }
.footer-note { margin-top: 4rem; padding-top: 1.2rem; border-top: 1px solid var(--line); font-size: .8rem; color: var(--muted); }
@media print {
  body { background: #fff; color: #000; font-size: 11pt; }
  .wrap { max-width: none; padding: 0; }
  .finding { break-inside: avoid; page-break-inside: avoid; border: 1px solid #ccc; }
  h2 { break-after: avoid; } pre { white-space: pre-wrap; word-break: break-word; }
  a { color: #000; text-decoration: underline; }
}
@media (max-width: 600px) {
  .wrap { padding: 28px 16px 64px; } h1 { font-size: 1.6rem; }
  .bar-row { grid-template-columns: 62px 1fr 36px; }
}
</style>
</head>
<body>
<div class="wrap">
  <span class="classification">${escapeHtml(meta.classification)}</span>
  <h1>${escapeHtml(meta.title)}</h1>

  <dl class="facts">
    ${[['Client', meta.client], ['Engagement', meta.engagement], ['Authorization', meta.reference],
       ['Test window', meta.window], ['Auditor', meta.auditor], ['Generated', meta.generatedAt]]
      .filter(([, v]) => v)
      .map(([k, v]) => `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`).join('')}
  </dl>

  <h2>1. Executive summary</h2>
  <div class="posture">
    <div class="label">Overall risk posture: ${escapeHtml(posture.label)}</div>
    <p style="margin:.5rem 0 0">${escapeHtml(posture.statement)}</p>
  </div>

  <div class="bars">${severityBars}</div>

  <table>
    <tr><th>Open findings</th><td>${model.totals.open}</td></tr>
    <tr><th>Confirmed (validated)</th><td>${model.totals.confirmed}</td></tr>
    <tr><th>Known exploited (CISA KEV)</th><td>${model.totals.knownExploited}</td></tr>
    <tr><th>Dismissed as false positives</th><td>${model.totals.falsePositives}</td></tr>
    <tr><th>Accepted risk</th><td>${model.totals.accepted}</td></tr>
  </table>

  <h2>2. Remediation roadmap</h2>
  ${roadmap || '<p>No open findings.</p>'}

  <h2>3. Findings</h2>
  ${findingCards || '<p>No findings remained open after triage.</p>'}

  ${model.needsValidation.length ? `
  <h2>4. Needs validation</h2>
  <p>Each entry below is a <strong>source-grounded hypothesis this audit could not settle</strong>, because confirming it depends on a fact outside the artefacts in scope — a deployment setting, a runtime value, or a third party's behaviour.</p>
  <p><strong>These carry no severity on purpose.</strong> They are not low-confidence vulnerabilities; they are open questions. Resolve the blocker and each becomes either a finding or a dismissal.</p>
  <table>
    <thead><tr><th>ID</th><th>Lead</th><th>Location</th><th>Blocked by</th><th>How to settle it</th></tr></thead>
    <tbody>
    ${model.needsValidation.map((f) => `<tr>
      <td><code>${escapeHtml(f.id)}</code></td>
      <td>${escapeHtml(f.title)}</td>
      <td><code>${escapeHtml(locationLabel(f))}</code></td>
      <td>${escapeHtml((f.blockers ?? []).join('; ') || 'not stated')}</td>
      <td>${escapeHtml((f.validationPlan ?? []).join('; ') || 'not stated')}</td>
    </tr>`).join('')}
    </tbody>
  </table>` : ''}

  <p class="footer-note">
    Severity follows CVSS qualitative bands. Priority additionally fuses EPSS exploit prediction,
    CISA KEV membership, component exposure and path reachability.
    This assessment reflects the target at the time of testing and the declared scope;
    it does not certify the absence of vulnerabilities.<br><br>
    Generated by <a href="https://github.com/TobiasVeiga00/claude-security-audit" rel="noopener noreferrer">claude-security-audit</a>
    on ${escapeHtml(meta.generatedAt)}.
  </p>
</div>
</body>
</html>`;
}

/* ------------------------------------------------------------------ *
 * SARIF 2.1.0
 * ------------------------------------------------------------------ */

function renderSarif(model, version) {
  const rules = new Map();
  for (const f of model.findings) {
    const ruleId = f.source?.rule || f.cwe?.[0] || f.id;
    if (rules.has(ruleId)) continue;
    rules.set(ruleId, {
      id: ruleId,
      name: f.title,
      shortDescription: { text: truncate(f.title, 120) },
      fullDescription: { text: f.description || f.title },
      help: {
        text: f.remediation?.summary || 'See the audit report for remediation guidance.',
        markdown: [
          f.description, f.impact ? `\n**Impact.** ${f.impact}` : '',
          f.remediation?.summary ? `\n**Remediation.** ${f.remediation.summary}` : '',
        ].filter(Boolean).join('\n'),
      },
      defaultConfiguration: { level: sarifLevel(f.severity) },
      properties: {
        tags: [f.domain, ...(f.cwe ?? []), ...(f.owasp ?? []), ...(f.attack ?? [])].filter(Boolean),
        'security-severity': String(f.cvss?.base ?? securitySeverity(f.severity)),
        precision: { confirmed: 'very-high', firm: 'high', tentative: 'medium' }[f.confidence] ?? 'medium',
      },
    });
  }

  const results = model.findings.map((f) => {
    const loc = f.location ?? {};
    const result = {
      ruleId: f.source?.rule || f.cwe?.[0] || f.id,
      level: sarifLevel(f.severity),
      message: { text: `${f.title}${f.impact ? ` — ${truncate(f.impact, 240)}` : ''}` },
      partialFingerprints: { securityAuditFingerprint: f.fingerprint },
      properties: {
        findingId: f.id,
        priority: f.risk?.priority ?? 0,
        tier: f.risk?.tier ?? 'P4',
        kev: f.kev === true,
        epss: f.epss,
        confidence: f.confidence,
      },
    };
    if (loc.file) {
      result.locations = [{
        physicalLocation: {
          artifactLocation: { uri: loc.file },
          region: {
            startLine: Math.max(1, loc.startLine ?? 1),
            ...(loc.endLine ? { endLine: loc.endLine } : {}),
          },
        },
      }];
    } else {
      const label = locationLabel(f);
      result.locations = [{
        physicalLocation: { artifactLocation: { uri: label === 'n/a' ? 'unknown' : label } },
      }];
    }
    return result;
  });

  /**
   * Unvalidated leads are emitted with SARIF `kind: "review"` rather than a
   * severity level. GitHub renders them as items needing human judgement
   * instead of as alerts, which is exactly what they are.
   */
  for (const f of model.needsValidation ?? []) {
    const ruleId = f.source?.rule || f.cwe?.[0] || f.id;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.title,
        shortDescription: { text: truncate(f.title, 120) },
        fullDescription: { text: f.description || f.title },
        defaultConfiguration: { level: 'none' },
        properties: { tags: [f.domain, 'needs-validation'], precision: 'medium' },
      });
    }
    const loc = f.location ?? {};
    results.push({
      ruleId,
      kind: 'review',
      level: 'none',
      message: {
        text: `${f.title} — unvalidated lead. Blocked by: ${(f.blockers ?? []).join('; ') || 'not stated'}.`,
      },
      partialFingerprints: { securityAuditFingerprint: f.fingerprint },
      properties: { findingId: f.id, verdict: 'needs-validation' },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: loc.file || locationLabel(f) || 'unknown' },
          ...(loc.startLine ? { region: { startLine: Math.max(1, loc.startLine) } } : {}),
        },
      }],
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'claude-security-audit',
          informationUri: 'https://github.com/TobiasVeiga00/claude-security-audit',
          version,
          semanticVersion: version,
          rules: [...rules.values()],
        },
      },
      results,
      invocations: [{ executionSuccessful: true, endTimeUtc: model.meta.generatedAt }],
    }],
  };
}

function sarifLevel(severity) {
  return { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }[severity] ?? 'note';
}

function securitySeverity(severity) {
  return { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.0 }[severity] ?? 0;
}

/* ------------------------------------------------------------------ *
 * CSV
 * ------------------------------------------------------------------ */

function renderCsv(model) {
  const header = [
    'id', 'severity', 'priority', 'tier', 'sla_days', 'confidence', 'domain',
    'title', 'location', 'cwe', 'owasp', 'attack', 'cve', 'cvss', 'epss', 'kev',
    'status', 'remediation', 'effort', 'tool', 'rule', 'first_seen',
  ];
  const rows = model.findings.map((f) => [
    f.id, f.severity, f.risk?.priority ?? 0, f.risk?.tier ?? '', SLA_DAYS[f.risk?.tier ?? 'P4'],
    f.confidence, f.domain, f.title, locationLabel(f),
    (f.cwe ?? []).join(' '), (f.owasp ?? []).join(' '), (f.attack ?? []).join(' '), (f.cve ?? []).join(' '),
    f.cvss?.base ?? '', f.epss ?? '', f.kev ? 'yes' : 'no',
    f.status, f.remediation?.summary ?? '', f.remediation?.effort ?? '',
    f.source?.tool ?? '', f.source?.rule ?? '', f.firstSeen,
  ]);
  return [header.join(','), ...rows.map((r) => r.map(csvCell).join(','))].join('\n');
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function main() {
  const args = parseArgs();
  const cwd = args.cwd ? path.resolve(String(args.cwd)) : process.cwd();
  const formats = String(args.format ?? 'markdown,html,sarif,json,csv').split(',').map((s) => s.trim()).filter(Boolean);
  const outBase = path.resolve(String(args.out ?? path.join(cwd, '.security-audit', 'report', 'security-audit-report')));

  const store = new FindingStore(cwd);
  if (!store.exists()) {
    fail(`No findings ledger at ${store.file}. Run an audit before generating a report.`);
  }

  let findings = store.load();
  if (args['min-severity']) {
    const floor = severityRank(String(args['min-severity']));
    findings = findings.filter((f) => severityRank(f.severity) >= floor);
  }

  const pkgVersion = readJson(
    path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '.claude-plugin', 'plugin.json'),
    { version: '0.0.0' },
  ).version;

  const model = buildModel(findings, {
    scope: loadScope(cwd),
    meta: {
      title: args.title ? String(args.title) : undefined,
      client: args.client ? String(args.client) : undefined,
      auditor: args.auditor ? String(args.auditor) : undefined,
      classification: args.classification ? String(args.classification) : undefined,
    },
  });

  ensureDir(path.dirname(outBase));
  const written = [];

  for (const format of formats) {
    switch (format) {
      case 'markdown': case 'md': {
        const file = `${outBase}.md`;
        fs.writeFileSync(file, renderMarkdown(model), 'utf8');
        written.push(file);
        break;
      }
      case 'html': {
        const file = `${outBase}.html`;
        fs.writeFileSync(file, renderHtml(model), 'utf8');
        written.push(file);
        break;
      }
      case 'sarif': {
        const file = `${outBase}.sarif`;
        fs.writeFileSync(file, JSON.stringify(renderSarif(model, pkgVersion), null, 2), 'utf8');
        written.push(file);
        break;
      }
      case 'json': {
        const file = `${outBase}.json`;
        fs.writeFileSync(file, JSON.stringify(model, null, 2), 'utf8');
        written.push(file);
        break;
      }
      case 'csv': {
        const file = `${outBase}.csv`;
        fs.writeFileSync(file, renderCsv(model), 'utf8');
        written.push(file);
        break;
      }
      default:
        process.stderr.write(`warning: unknown format "${format}" ignored\n`);
    }
  }

  process.stdout.write(JSON.stringify({
    generated: written,
    posture: riskPosture(model).label,
    totals: model.totals,
    bySeverity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, model.bySeverity[s].length])),
  }, null, 2) + '\n');
}

export { buildModel, renderMarkdown, renderHtml, renderSarif, renderCsv, riskPosture };

if (process.argv[1]?.endsWith('report.mjs')) main();
