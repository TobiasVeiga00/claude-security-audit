#!/usr/bin/env node
/**
 * Security tool detection.
 *
 * The audit adapts to what is actually installed rather than demanding a
 * specific toolchain. This script reports what is present, what is missing,
 * and exactly how to install each gap - so the model never invents a command
 * for a binary that is not there, and never silently skips a check without
 * saying so in the report.
 *
 * The catalogue reflects upstream reality as of 2026-09: archived and
 * superseded projects are recorded as such, with their replacement, because
 * recommending a dead scanner is worse than recommending none.
 *
 * Usage: node tools.mjs [--domain code,secrets] [--json] [--missing]
 */

import { execFileSync } from 'node:child_process';
import { parseArgs, emit, IS_WINDOWS } from './lib/util.mjs';

/**
 * `check` is the argument list used to prove the binary answers. Everything is
 * invoked through execFile with an argument array - never a shell string - so
 * a hostile PATH entry cannot turn detection into command injection.
 */
export const CATALOGUE = [
  /* ---------------- code / SAST ---------------- */
  { id: 'semgrep', domain: 'code', purpose: 'Multi-language pattern-based static analysis', bin: 'semgrep', check: ['--version'], install: { brew: 'brew install semgrep', pipx: 'pipx install semgrep' }, note: 'Engine is LGPL-2.1, but the official rule packs carry a restrictive licence. Use Opengrep if you redistribute rules.' },
  { id: 'opengrep', domain: 'code', purpose: 'Fully open fork of Semgrep CE, rule-compatible', bin: 'opengrep', check: ['--version'], install: { sh: 'curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash' } },
  { id: 'bandit', domain: 'code', purpose: 'Python static analysis', bin: 'bandit', check: ['--version'], install: { pipx: 'pipx install bandit' } },
  { id: 'gosec', domain: 'code', purpose: 'Go static analysis', bin: 'gosec', check: ['--version'], install: { go: 'go install github.com/securego/gosec/v2/cmd/gosec@latest' } },
  { id: 'brakeman', domain: 'code', purpose: 'Ruby on Rails static analysis', bin: 'brakeman', check: ['--version'], install: { gem: 'gem install brakeman' } },
  { id: 'njsscan', domain: 'code', purpose: 'Node.js static analysis', bin: 'njsscan', check: ['--help'], install: { pipx: 'pipx install njsscan' } },
  { id: 'codeql', domain: 'code', purpose: 'Semantic dataflow analysis', bin: 'codeql', check: ['version'], install: { manual: 'https://github.com/github/codeql-cli-binaries/releases' }, note: 'Free for open source; commercial use outside GitHub Advanced Security is licence-restricted.' },
  { id: 'cppcheck', domain: 'code', purpose: 'C/C++ static analysis', bin: 'cppcheck', check: ['--version'], install: { apt: 'apt install cppcheck', brew: 'brew install cppcheck' } },

  /* ---------------- secrets ---------------- */
  { id: 'gitleaks', domain: 'secrets', purpose: 'Secret detection across git history and the filesystem', bin: 'gitleaks', check: ['version'], install: { brew: 'brew install gitleaks', docker: 'docker run -v "$PWD:/p" zricethezav/gitleaks:latest detect -s /p' } },
  { id: 'trufflehog', domain: 'secrets', purpose: 'Secret detection with live credential verification', bin: 'trufflehog', check: ['--version'], install: { brew: 'brew install trufflehog', sh: 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin' }, note: 'Verification proves a key is live - only run it against credentials you are authorized to test.' },
  { id: 'detect-secrets', domain: 'secrets', purpose: 'Baseline-driven pre-commit secret scanning', bin: 'detect-secrets', check: ['--version'], install: { pipx: 'pipx install detect-secrets' } },

  /* ---------------- dependencies / SBOM ---------------- */
  { id: 'osv-scanner', domain: 'dependencies', purpose: 'OSV.dev-backed vulnerability scanning of lockfiles and SBOMs', bin: 'osv-scanner', check: ['--version'], install: { brew: 'brew install osv-scanner', go: 'go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest' } },
  { id: 'trivy', domain: 'dependencies', purpose: 'Universal scanner: images, filesystems, IaC, SBOM, secrets', bin: 'trivy', check: ['--version'], install: { brew: 'brew install trivy', docker: 'docker run aquasec/trivy:latest' } },
  { id: 'grype', domain: 'dependencies', purpose: 'Vulnerability scanning of images, directories and SBOMs', bin: 'grype', check: ['version'], install: { brew: 'brew install grype', sh: 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin' } },
  { id: 'syft', domain: 'dependencies', purpose: 'SBOM generation in SPDX and CycloneDX', bin: 'syft', check: ['version'], install: { brew: 'brew install syft' } },
  { id: 'cdxgen', domain: 'dependencies', purpose: 'Polyglot CycloneDX SBOM generation', bin: 'cdxgen', check: ['--version'], install: { npm: 'npm install -g @cyclonedx/cdxgen' } },
  { id: 'pip-audit', domain: 'dependencies', purpose: 'Python dependency auditing, maintained by the PyPA', bin: 'pip-audit', check: ['--version'], install: { pipx: 'pipx install pip-audit' }, note: 'Preferred over `safety`, whose full database is now commercially gated.' },
  { id: 'govulncheck', domain: 'dependencies', purpose: 'Go vulnerability detection with call-graph reachability', bin: 'govulncheck', check: ['-version'], install: { go: 'go install golang.org/x/vuln/cmd/govulncheck@latest' } },
  { id: 'dependency-check', domain: 'dependencies', purpose: 'Multi-ecosystem CVE detection via NVD and CPE', bin: 'dependency-check', check: ['--version'], install: { brew: 'brew install dependency-check' }, note: 'Upstream moved to dependency-check/DependencyCheck; the jeremylong repository is archived.' },
  { id: 'retire', domain: 'dependencies', purpose: 'Known-vulnerable JavaScript library detection', bin: 'retire', check: ['--version'], install: { npm: 'npm install -g retire' } },

  /* ---------------- IaC / container ---------------- */
  { id: 'checkov', domain: 'iac', purpose: 'Terraform, CloudFormation, Kubernetes, ARM and Helm policy scanning', bin: 'checkov', check: ['--version'], install: { pipx: 'pipx install checkov' } },
  { id: 'kics', domain: 'iac', purpose: 'Broad infrastructure-as-code misconfiguration scanning', bin: 'kics', check: ['version'], install: { brew: 'brew install kics', docker: 'docker run checkmarx/kics:latest scan -p /path' } },
  { id: 'conftest', domain: 'iac', purpose: 'Open Policy Agent rules over any structured configuration', bin: 'conftest', check: ['--version'], install: { brew: 'brew install conftest' } },
  { id: 'hadolint', domain: 'container', purpose: 'Dockerfile linting', bin: 'hadolint', check: ['--version'], install: { brew: 'brew install hadolint', docker: 'docker run --rm -i hadolint/hadolint < Dockerfile' } },
  { id: 'dockle', domain: 'container', purpose: 'Container image linting against CIS practice', bin: 'dockle', check: ['--version'], install: { brew: 'brew install goodwithtech/dockle/dockle' } },
  { id: 'kubescape', domain: 'container', purpose: 'Kubernetes posture against NSA, CIS and MITRE frameworks', bin: 'kubescape', check: ['version'], install: { sh: 'curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash' } },
  { id: 'kube-bench', domain: 'container', purpose: 'CIS Kubernetes Benchmark checks', bin: 'kube-bench', check: ['version'], install: { docker: 'docker run --pid=host aquasec/kube-bench:latest' } },

  /* ---------------- cloud ---------------- */
  { id: 'prowler', domain: 'cloud', purpose: 'Multi-cloud posture and compliance (AWS, Azure, GCP, Kubernetes, M365)', bin: 'prowler', check: ['--version'], install: { pipx: 'pipx install prowler' } },
  { id: 'scoutsuite', domain: 'cloud', purpose: 'Multi-cloud configuration audit producing an HTML report', bin: 'scout', check: ['--version'], install: { pipx: 'pipx install scoutsuite' }, note: 'Upstream has slowed; prefer Prowler as the primary posture tool.' },
  { id: 'steampipe', domain: 'cloud', purpose: 'SQL over live cloud APIs, with CIS and NIST benchmark mods', bin: 'steampipe', check: ['--version'], install: { brew: 'brew install turbot/tap/steampipe' } },
  { id: 'cloudfox', domain: 'cloud', purpose: 'Offensive cloud reconnaissance and attack-path enumeration', bin: 'cloudfox', check: ['--version'], install: { brew: 'brew install cloudfox' }, intrusive: true },

  /* ---------------- web / API ---------------- */
  { id: 'nuclei', domain: 'web', purpose: 'Template-driven vulnerability scanning', bin: 'nuclei', check: ['-version'], install: { go: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' }, intrusive: true },
  { id: 'zap', domain: 'web', purpose: 'Full dynamic application security testing proxy and scanner', bin: 'zap.sh', check: ['-version'], install: { docker: 'docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t URL', brew: 'brew install --cask zap' }, intrusive: true },
  { id: 'httpx', domain: 'web', purpose: 'HTTP probing and fingerprinting', bin: 'httpx', check: ['-version'], install: { go: 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest' }, intrusive: true },
  { id: 'katana', domain: 'web', purpose: 'Crawler for endpoint and parameter discovery', bin: 'katana', check: ['-version'], install: { go: 'go install github.com/projectdiscovery/katana/cmd/katana@latest' }, intrusive: true },
  { id: 'ffuf', domain: 'web', purpose: 'Content and parameter fuzzing', bin: 'ffuf', check: ['-V'], install: { go: 'go install github.com/ffuf/ffuf/v2@latest' }, intrusive: true },
  { id: 'sqlmap', domain: 'web', purpose: 'SQL injection detection and exploitation', bin: 'sqlmap', check: ['--version'], install: { pipx: 'pipx install sqlmap' }, intrusive: true },
  { id: 'testssl', domain: 'web', purpose: 'TLS configuration and cipher auditing', bin: 'testssl.sh', check: ['--version'], install: { brew: 'brew install testssl' }, intrusive: true },
  { id: 'schemathesis', domain: 'api', purpose: 'Property-based API fuzzing driven by an OpenAPI or GraphQL schema', bin: 'schemathesis', check: ['--version'], install: { pipx: 'pipx install schemathesis' }, intrusive: true },
  { id: 'mitmproxy', domain: 'api', purpose: 'Intercepting TLS proxy with scriptable add-ons', bin: 'mitmproxy', check: ['--version'], install: { pipx: 'pipx install mitmproxy' }, intrusive: true },

  /* ---------------- mobile ---------------- */
  { id: 'mobsf', domain: 'mobile', purpose: 'Static and dynamic mobile application analysis', bin: 'mobsf', check: ['--help'], install: { docker: 'docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest' } },
  { id: 'jadx', domain: 'mobile', purpose: 'Android DEX to Java decompilation', bin: 'jadx', check: ['--version'], install: { brew: 'brew install jadx', apt: 'apt install jadx' } },
  { id: 'apktool', domain: 'mobile', purpose: 'APK decoding, resource and smali extraction', bin: 'apktool', check: ['--version'], install: { brew: 'brew install apktool' } },
  { id: 'frida', domain: 'mobile', purpose: 'Dynamic instrumentation for Android and iOS', bin: 'frida', check: ['--version'], install: { pipx: 'pipx install frida-tools' }, intrusive: true },
  { id: 'objection', domain: 'mobile', purpose: 'Frida-powered runtime mobile exploration', bin: 'objection', check: ['version'], install: { pipx: 'pipx install objection' }, intrusive: true },

  /* ---------------- network ---------------- */
  { id: 'nmap', domain: 'network', purpose: 'Port, service and version scanning with NSE', bin: 'nmap', check: ['--version'], install: { apt: 'apt install nmap', brew: 'brew install nmap' }, intrusive: true },
  { id: 'naabu', domain: 'network', purpose: 'Fast port discovery that pipes into httpx and nuclei', bin: 'naabu', check: ['-version'], install: { go: 'go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest' }, intrusive: true },
  { id: 'netexec', domain: 'network', purpose: 'Network and Active Directory enumeration', bin: 'nxc', check: ['--version'], install: { pipx: 'pipx install git+https://github.com/Pennyw0rth/NetExec' }, intrusive: true, note: 'Successor to CrackMapExec, which is no longer maintained.' },
  { id: 'impacket', domain: 'network', purpose: 'Windows and Active Directory protocol toolkit', bin: 'impacket-secretsdump', check: ['-h'], install: { pipx: 'pipx install impacket' }, intrusive: true },

  /* ---------------- wireless ---------------- */
  { id: 'aircrack-ng', domain: 'wireless', purpose: 'Wireless capture, injection and cracking suite', bin: 'aircrack-ng', check: ['--help'], install: { apt: 'apt install aircrack-ng' }, intrusive: true },
  { id: 'hcxdumptool', domain: 'wireless', purpose: 'PMKID and EAPOL capture', bin: 'hcxdumptool', check: ['--version'], install: { apt: 'apt install hcxdumptool' }, intrusive: true },
  { id: 'hcxtools', domain: 'wireless', purpose: 'Capture conversion into hashcat 22000 format', bin: 'hcxpcapngtool', check: ['--version'], install: { apt: 'apt install hcxtools' }, intrusive: true },
  { id: 'hashcat', domain: 'wireless', purpose: 'GPU-accelerated credential cracking', bin: 'hashcat', check: ['--version'], install: { apt: 'apt install hashcat', brew: 'brew install hashcat' }, intrusive: true },
  { id: 'bettercap', domain: 'wireless', purpose: 'Network and 802.11 reconnaissance and manipulation', bin: 'bettercap', check: ['-version'], install: { apt: 'apt install bettercap' }, intrusive: true },
  { id: 'wifite', domain: 'wireless', purpose: 'Automated wireless audit wrapper', bin: 'wifite', check: ['--help'], install: { apt: 'apt install wifite' }, intrusive: true, note: 'Use the kimocoder fork; the original derv82 repository is inactive.' },
];

/** Tools that upstream has retired. Naming the successor prevents silent decay. */
export const RETIRED = {
  tfsec: { reason: 'folded into Trivy', replacement: 'trivy config' },
  terrascan: { reason: 'archived 2025-11-20', replacement: 'checkov or trivy config' },
  'kube-hunter': { reason: 'deprecated by Aqua', replacement: 'kubescape or trivy k8s' },
  crackmapexec: { reason: 'unmaintained', replacement: 'netexec (nxc)' },
  'git-secrets': { reason: 'unmaintained', replacement: 'gitleaks' },
  needle: { reason: 'archived 2020', replacement: 'MobSF or objection' },
  safety: { reason: 'full database now commercially gated', replacement: 'pip-audit or osv-scanner' },
};

/* ------------------------------------------------------------------ */

function detect(tool) {
  try {
    // On Windows many tools are `.cmd`/`.bat` shims that execFile cannot launch
    // directly (and Node refuses to run under shell:false for CVE-2024-27980).
    // Run them through cmd.exe there; everything else stays shell-free.
    const { command, args } = IS_WINDOWS
      ? { command: process.env.COMSPEC || 'cmd.exe', args: ['/d', '/s', '/c', tool.bin, ...tool.check] }
      : { command: tool.bin, args: tool.check };
    const output = execFileSync(command, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 8000,
      windowsHide: true,
      shell: false,
    });
    return finalize(true, output);
  } catch (err) {
    const combined = `${err.stdout ?? ''}${err.stderr ?? ''}`;
    // A tool that exists but exits non-zero can still be present — but only
    // trust it if the output actually looks like a version banner, so a
    // same-named unrelated binary printing an error is not counted as installed.
    if (combined.trim()) {
      const version = firstVersion(combined);
      if (version) return { installed: true, version };
    }
    return { installed: false, version: null };
  }
}

function finalize(installed, output) {
  return { installed, version: firstVersion(output) };
}

/** Return a version-shaped token, or null — never an arbitrary line of output. */
function firstVersion(output) {
  const match = /(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)/.exec(String(output).split(/\r?\n/).slice(0, 6).join(' '));
  return match ? match[1] : null;
}

function installHint(tool) {
  const order = IS_WINDOWS
    ? ['docker', 'pipx', 'npm', 'go', 'gem', 'sh', 'brew', 'apt', 'manual']
    : ['brew', 'pipx', 'apt', 'go', 'npm', 'gem', 'sh', 'docker', 'manual'];
  for (const key of order) {
    if (tool.install?.[key]) return { via: key, command: tool.install[key] };
  }
  return null;
}

export function inventory({ domains = null } = {}) {
  const wanted = domains ? new Set([].concat(domains)) : null;
  const tools = CATALOGUE
    .filter((tool) => !wanted || wanted.has(tool.domain))
    .map((tool) => {
      const { installed, version } = detect(tool);
      return {
        id: tool.id,
        domain: tool.domain,
        purpose: tool.purpose,
        installed,
        version,
        intrusive: tool.intrusive === true,
        ...(tool.note ? { note: tool.note } : {}),
        ...(installed ? {} : { install: installHint(tool) }),
      };
    });

  const byDomain = {};
  for (const tool of tools) {
    byDomain[tool.domain] ??= { installed: [], missing: [] };
    byDomain[tool.domain][tool.installed ? 'installed' : 'missing'].push(tool.id);
  }

  return {
    checkedAt: new Date().toISOString(),
    platform: process.platform,
    total: tools.length,
    installedCount: tools.filter((t) => t.installed).length,
    byDomain,
    tools,
    retired: RETIRED,
  };
}

/* ------------------------------------------------------------------ */

if (process.argv[1]?.endsWith('tools.mjs')) {
  const args = parseArgs();
  const result = inventory({ domains: args.domain ? String(args.domain).split(',') : null });

  if (args.json) {
    emit(result);
  } else if (args.missing) {
    const missing = result.tools.filter((t) => !t.installed);
    if (missing.length === 0) {
      process.stdout.write('Every catalogued tool for this scope is installed.\n');
    } else {
      process.stdout.write(`${missing.length} tool(s) not installed:\n\n`);
      for (const tool of missing) {
        process.stdout.write(`  ${tool.id.padEnd(18)} ${tool.purpose}\n`);
        if (tool.install) process.stdout.write(`  ${' '.repeat(18)} ${tool.install.command}\n`);
      }
    }
  } else {
    const lines = [`${result.installedCount}/${result.total} catalogued tools available on ${result.platform}`, ''];
    for (const [domain, entry] of Object.entries(result.byDomain)) {
      lines.push(`${domain}:`);
      if (entry.installed.length) lines.push(`  available: ${entry.installed.join(', ')}`);
      if (entry.missing.length) lines.push(`  missing:   ${entry.missing.join(', ')}`);
    }
    process.stdout.write(lines.join('\n') + '\n');
  }
}
