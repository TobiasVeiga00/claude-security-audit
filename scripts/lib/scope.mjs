/**
 * Rules of engagement and the authorization gate.
 *
 * Everything in this plugin that touches a system it did not find on disk goes
 * through here first. The rule is simple and non-negotiable:
 *
 *   Static analysis of code you already have is always allowed.
 *   Anything that sends a packet at a target requires written scope.
 *
 * This is not ceremony. Running a scanner against a host you were not asked to
 * test is, depending on jurisdiction, a crime - and it is the single fastest
 * way for an audit to become the incident. The gate makes the authorized path
 * the easy path.
 */

import fs from 'node:fs';
import path from 'node:path';
import { auditHome, readJson, writeJson, nowIso } from './util.mjs';

export const SCOPE_VERSION = 1;

/* ------------------------------------------------------------------ *
 * Tool classification
 * ------------------------------------------------------------------ */

/**
 * `local` tools only read artefacts already on disk. They never need scope.
 * Everything else is ordered by how much damage a mistake can do.
 */
export const TOOL_CLASSES = {
  local: [
    // SAST
    'semgrep', 'opengrep', 'bandit', 'gosec', 'brakeman', 'eslint', 'njsscan',
    'flawfinder', 'cppcheck', 'codeql',
    // Secrets
    'gitleaks', 'trufflehog', 'detect-secrets', 'ggshield', 'noseyparker',
    // Dependencies / SBOM
    'trivy', 'grype', 'syft', 'cdxgen', 'osv-scanner', 'dependency-check', 'retire',
    'npm audit', 'pnpm audit', 'yarn audit', 'pip-audit', 'cargo audit',
    'bundler-audit', 'govulncheck', 'composer audit', 'cyclonedx', 'cyclonedx-cli',
    // Infrastructure as code and containers
    'checkov', 'kics', 'conftest', 'kube-linter', 'kubesec', 'hadolint', 'dockle',
    // Mobile static analysis
    'apktool', 'jadx', 'dex2jar', 'class-dump', 'otool', 'nm', 'strings',
    'mobsf', 'apkleaks', 'androguard',
    // Supply chain
    'cosign verify-blob', 'scorecard',
  ],
  passiveRecon: [
    'whois', 'dig', 'nslookup', 'host', 'subfinder', 'assetfinder',
    'theharvester', 'shodan', 'censys', 'crt.sh', 'waybackurls', 'gau',
    'dnsx', 'httpx', 'amass intel', 'amass enum -passive',
  ],
  activeScan: [
    'nmap', 'masscan', 'rustscan', 'zmap', 'naabu', 'unicornscan',
    'nuclei', 'nikto', 'wpscan', 'joomscan', 'droopescan', 'whatweb',
    'gobuster', 'ffuf', 'dirb', 'dirsearch', 'feroxbuster', 'wfuzz',
    'zap', 'zap-cli', 'zap-baseline', 'arachni', 'skipfish', 'w3af',
    'testssl.sh', 'testssl', 'sslyze', 'sslscan', 'tlsx',
    'amass enum', 'katana', 'hakrawler', 'arjun', 'paramspider',
    'enum4linux', 'smbclient', 'rpcclient', 'ldapsearch', 'snmpwalk',
    'prowler', 'scoutsuite', 'cloudsploit', 'pacu', 'cloudfox',
    'kube-bench', 'kubescape', 'kubeaudit', 'lynis', 'openvas', 'nessus',
  ],
  exploitation: [
    'sqlmap', 'commix', 'xsser', 'tplmap', 'nosqlmap',
    'msfconsole', 'msfvenom', 'metasploit', 'beef',
    'hydra', 'medusa', 'ncrack', 'patator', 'crowbar',
    'john', 'hashcat', 'ophcrack',
    'crackmapexec', 'nxc', 'netexec', 'impacket', 'secretsdump',
    'responder', 'evil-winrm', 'mimikatz', 'rubeus', 'certipy',
    'bloodhound', 'sharphound', 'kerbrute',
    'searchsploit -x', 'exploitdb',
    'objection', 'frida', 'drozer',
  ],
  wireless: [
    'aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'airbase-ng',
    'wifite', 'hcxdumptool', 'hcxpcapngtool', 'hcxtools',
    'reaver', 'bully', 'pixiewps', 'mdk3', 'mdk4',
    'bettercap', 'kismet', 'wifiphisher', 'fluxion', 'eaphammer',
    'hostapd-wpe', 'airgeddon',
  ],
  disruptive: [
    'hping3', 'slowloris', 't50', 'thc-ssl-dos', 'goldeneye', 'slowhttptest',
    'mdk4 d', 'mdk3 d', 'aireplay-ng --deauth', 'aireplay-ng -0',
  ],
};

/** Flags that turn an otherwise-scanning tool into an exploitation tool. */
const ESCALATING_FLAGS = [
  { re: /\bsqlmap\b[^\n]*--(os-shell|os-pwn|os-cmd|file-write|file-dest|sql-shell)/i, reason: 'sqlmap shell/file-write mode' },
  { re: /\bnmap\b[^\n]*(--script[= ]?[^\s]*\b(exploit|brute|dos|malware|vuln)\b)/i, reason: 'nmap intrusive NSE category' },
  { re: /\bnuclei\b[^\n]*-(?:severity|s)\s+[^\n]*critical[^\n]*-(?:itags|tags)[^\n]*\b(rce|intrusive)\b/i, reason: 'nuclei intrusive templates' },
  { re: /\baireplay-ng\b[^\n]*(-0|--deauth)/i, reason: 'wireless deauthentication (denial of service)' },
  { re: /\bmdk[34]\b\s+\w+\s+d\b/i, reason: 'wireless deauthentication flood' },
  { re: /\bhping3\b[^\n]*--flood/i, reason: 'packet flood' },
];

/* ------------------------------------------------------------------ *
 * Scope document
 * ------------------------------------------------------------------ */

export function scopePath(cwd = process.cwd()) {
  return path.join(auditHome(cwd), 'scope.json');
}

export function defaultScope() {
  return {
    version: SCOPE_VERSION,
    engagement: {
      name: '',
      client: '',
      auditor: '',
      type: 'self-owned', // self-owned | authorized-pentest | bug-bounty | internal
      startsAt: null,
      endsAt: null,
    },
    authorization: {
      granted: false,
      grantedBy: '',
      reference: '',
      attestedAt: null,
      attestation: '',
    },
    targets: {
      repos: [],
      hosts: [],
      domains: [],
      urls: [],
      ipRanges: [],
      cloudAccounts: [],
      mobileApps: [],
      wireless: { ssids: [], bssids: [] },
    },
    outOfScope: { hosts: [], domains: [], ipRanges: [], notes: [] },
    rules: {
      staticAnalysis: true,
      passiveRecon: false,
      activeTesting: false,
      exploitation: false,
      denialOfService: false,
      socialEngineering: false,
      dataExfiltration: false,
      maxRequestsPerSecond: 10,
      testWindow: '',
    },
    contacts: [],
    createdAt: nowIso(),
  };
}

export function loadScope(cwd = process.cwd()) {
  const file = scopePath(cwd);
  if (!fs.existsSync(file)) return null;
  const scope = readJson(file, null);
  if (!scope) return null;
  return { ...defaultScope(), ...scope, _path: file };
}

export function saveScope(scope, cwd = process.cwd()) {
  const { _path, ...body } = scope;
  return writeJson(scopePath(cwd), { ...body, updatedAt: nowIso() });
}

/* ------------------------------------------------------------------ *
 * Target matching
 * ------------------------------------------------------------------ */

/**
 * Output-file extensions that are genuinely files, not hosts. Deliberately
 * excludes real gTLDs (`.zip`, `.mov`, `.app`, `.dev`, `.sh`): a token that ends
 * in a gTLD is treated as a possible host so the scope check sees it, rather
 * than being silently dropped and letting the command through.
 */
const FILE_EXT_SKIP = /\.(js|ts|jsx|tsx|py|go|rb|php|java|json|ya?ml|md|txt|xml|html?|css|lock|toml|ini|cfg|conf|env|pem|crt|key|log|csv|tar|gz|tgz|apk|ipa|jar|war|so|dll|exe|out|nmap|gnmap|pcap|pcapng)$/i;

/**
 * Extract every plausible network target from a shell command line.
 *
 * This feeds the authorization gate, so its bias is toward OVER-extraction: a
 * token that might be a host is surfaced and left for the scope check to
 * approve or deny. Missing a target is a bypass; an extra one is only a
 * false deny the operator can fix by declaring scope.
 *
 * Handles dotted-quad IPv4, decimal / hex / octal integer IPv4 (nmap accepts
 * `nmap 134744072`), bracketed and bare IPv6, `http(s)` URLs (incl. userinfo
 * and IPv6 literals), and letter-TLD hostnames.
 */
export function extractTargets(command) {
  const targets = new Set();
  const add = (value) => { if (value) targets.add(String(value).toLowerCase()); };
  let match;

  // URLs first, including user@host and [IPv6] literals.
  const urlRe = /\bhttps?:\/\/(?:[^/@\s"']*@)?(\[[0-9a-f:]+\]|[A-Za-z0-9._-]+)(?::\d+)?/gi;
  while ((match = urlRe.exec(command)) !== null) {
    add(normalizeIpToken(match[1].replace(/^\[|\]$/g, '')));
  }

  // CIDR and dotted-quad IPv4 (with optional hex/octal octets).
  const cidrRe = /\b((?:0x[0-9a-f]+|0[0-7]*|\d{1,3})(?:\.(?:0x[0-9a-f]+|0[0-7]*|\d{1,3})){3}(?:\/\d{1,2})?)\b/gi;
  while ((match = cidrRe.exec(command)) !== null) add(normalizeIpToken(match[1]));

  // Hostnames with a letter TLD.
  const hostRe = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23})\b/gi;
  while ((match = hostRe.exec(command)) !== null) {
    const host = match[1].toLowerCase().replace(/\.$/, '');
    if (FILE_EXT_SKIP.test(host)) continue;
    add(host);
  }

  // Bare IPv6 literals (at least two colons so we do not catch `host:port`).
  const ipv6Re = /\b((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})\b/gi;
  while ((match = ipv6Re.exec(command)) !== null) {
    if ((match[1].match(/:/g) || []).length >= 2 && /[0-9a-f]/i.test(match[1])) add(match[1]);
  }

  // Bare decimal / hex integer that resolves to a valid IPv4 (nmap accepts these).
  const intRe = /(?:^|[\s=@])((?:0x[0-9a-f]{1,8})|\d{1,10})(?=$|[\s/])/gi;
  while ((match = intRe.exec(command)) !== null) {
    const normalized = normalizeIntegerIp(match[1]);
    if (normalized) add(normalized);
  }

  return [...targets];
}

/** Normalize a single token that may be a dotted/integer/hex IPv4 to dotted-quad. */
function normalizeIpToken(token) {
  if (!token) return token;
  const t = token.toLowerCase();
  if (/^(?:0x[0-9a-f]+|0[0-7]*|\d{1,3})(?:\.(?:0x[0-9a-f]+|0[0-7]*|\d{1,3})){3}$/.test(t)) {
    const parts = t.split('.').map(parseIntAuto);
    if (parts.every((n) => n !== null && n >= 0 && n <= 255)) return parts.join('.');
  }
  return t;
}

/** A bare integer (decimal or hex) that fits in 32 bits maps to a dotted-quad. */
function normalizeIntegerIp(token) {
  const n = parseIntAuto(token);
  if (n === null || n < 0 || n > 0xffffffff) return null;
  // A small integer is almost never an IP target (it is a port, count, flag).
  if (n <= 255) return null;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parseIntAuto(token) {
  const t = String(token).trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (/^0[0-7]+$/.test(t)) return parseInt(t, 8);
  if (/^\d+$/.test(t)) return parseInt(t, 10);
  return null;
}

/** MAC addresses on a wireless command line are access points, i.e. targets. */
export function extractBssids(command) {
  const out = new Set();
  const re = /\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b/gi;
  let match;
  while ((match = re.exec(command)) !== null) out.add(match[1].toUpperCase());
  return [...out];
}

/** SSIDs passed explicitly, e.g. `--essid ACME-CORP` or `-e "Guest WiFi"`. */
export function extractSsids(command) {
  const out = new Set();
  const re = /(?:--essid|--bssid-?ssid|-e)\s+(?:"([^"]+)"|'([^']+)'|(\S+))/gi;
  let match;
  while ((match = re.exec(command)) !== null) {
    const value = match[1] ?? match[2] ?? match[3];
    if (value && !value.startsWith('-')) out.add(value);
  }
  return [...out];
}

function ipToLong(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function inCidr(ip, cidr) {
  const [network, bitsRaw] = cidr.split('/');
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const ipLong = ipToLong(ip);
  const netLong = ipToLong(network);
  if (ipLong === null || netLong === null || Number.isNaN(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipLong & mask) === (netLong & mask);
}

/** Loopback and RFC1918 targets are the auditor's own lab; never gate them. */
export function isLocalTarget(target) {
  const t = String(target).toLowerCase().replace(/^\[|\]$/g, '');
  if (/^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0|::)$/i.test(t)) return true;
  if (/\.(local|localhost|test|internal|invalid|example)$/i.test(t)) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    return inCidr(t, '10.0.0.0/8')
      || inCidr(t, '172.16.0.0/12')
      || inCidr(t, '192.168.0.0/16')
      || inCidr(t, '127.0.0.0/8')
      || inCidr(t, '169.254.0.0/16'); // link-local
  }
  // IPv6 private/loopback/link-local ranges.
  if (t.includes(':')) {
    return /^::1$/.test(t)              // loopback
      || /^fe[89ab][0-9a-f]:/i.test(t)  // link-local fe80::/10
      || /^f[cd][0-9a-f]{2}:/i.test(t)  // unique local fc00::/7
      || /^::ffff:127\./i.test(t);      // IPv4-mapped loopback
  }
  return false;
}

export function matchesScope(target, scope) {
  if (!scope) return false;
  const t = target.toLowerCase();

  // Exclusions match a host and all of its subdomains, so excluding
  // `payments.acme.com` also excludes `www.payments.acme.com`. Using an exact
  // match here (while inclusions use a suffix match) let an excluded host's
  // subdomains back into scope.
  for (const blocked of [...(scope.outOfScope?.hosts ?? []), ...(scope.outOfScope?.domains ?? [])]) {
    const b = blocked.toLowerCase().replace(/^\*\./, '');
    if (t === b || t.endsWith(`.${b}`)) return false;
  }
  for (const range of scope.outOfScope?.ipRanges ?? []) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t) && inCidr(t, range)) return false;
  }

  const hosts = (scope.targets?.hosts ?? []).map((h) => h.toLowerCase());
  if (hosts.includes(t)) return true;

  for (const domain of scope.targets?.domains ?? []) {
    const d = domain.toLowerCase().replace(/^\*\./, '');
    if (t === d || t.endsWith(`.${d}`)) return true;
  }

  for (const url of scope.targets?.urls ?? []) {
    try {
      if (new URL(url).hostname.toLowerCase() === t) return true;
    } catch { /* not a URL, ignore */ }
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    for (const range of scope.targets?.ipRanges ?? []) {
      if (inCidr(t, range)) return true;
    }
  }

  return false;
}

/* ------------------------------------------------------------------ *
 * The gate
 * ------------------------------------------------------------------ */

/**
 * Normalize a command for tool detection.
 *
 * Tool names hide behind a path prefix (`/usr/bin/nmap`), quotes (`n"m"ap`),
 * backslashes, or a leading env assignment (`PROG=x nmap`). We strip quotes and
 * turn every path separator into a space, so a path-qualified or quoted binary
 * surfaces as a bare word the classifier can see. The bias is deliberate:
 * over-detecting a tool only gates more; under-detecting one is a bypass.
 *
 * Target extraction still runs on the ORIGINAL command, so URLs and hosts are
 * unaffected by this transform.
 */
export function normalizeForClassification(command) {
  return String(command)
    .replace(/['"]/g, '')       // n"m"ap -> nmap
    .replace(/[/\\]/g, ' ')     // /usr/bin/nmap -> ' usr bin nmap'
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

function classify(command) {
  const normalized = normalizeForClassification(command);
  const matched = [];

  for (const escalation of ESCALATING_FLAGS) {
    // Escalating flags are matched on both forms: the flag text on the original
    // (flags can contain slashes), and on the normalized to catch path-qualified
    // binaries.
    if (escalation.re.test(command) || escalation.re.test(normalized)) {
      matched.push({ class: escalation.reason.includes('denial') || escalation.reason.includes('flood') ? 'disruptive' : 'exploitation', tool: escalation.reason });
    }
  }

  for (const [className, tools] of Object.entries(TOOL_CLASSES)) {
    for (const tool of tools) {
      // After normalization every token is space-delimited, so a single word
      // boundary rule covers path-qualified, quoted and env-prefixed forms. An
      // optional Windows executable extension (nmap.exe, sqlmap.cmd) is allowed.
      const escaped = tool.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const pattern = new RegExp(`(?:^|\\s)${escaped}(?:\\.(?:exe|cmd|bat|com|ps1))?(?=$|[\\s;&|])`, 'i');
      if (pattern.test(normalized)) matched.push({ class: className, tool });
    }
  }

  if (matched.length === 0) return { class: null, tools: [] };

  const order = ['disruptive', 'exploitation', 'wireless', 'activeScan', 'passiveRecon', 'local'];
  const highest = order.find((c) => matched.some((m) => m.class === c));
  return { class: highest, tools: [...new Set(matched.filter((m) => m.class === highest).map((m) => m.tool))] };
}

const RULE_FOR_CLASS = {
  local: 'staticAnalysis',
  passiveRecon: 'passiveRecon',
  activeScan: 'activeTesting',
  wireless: 'activeTesting',
  exploitation: 'exploitation',
  disruptive: 'denialOfService',
};

/**
 * Decide whether a shell command may run.
 *
 * Returns { decision: 'allow' | 'deny' | 'ask', reason, class, tools, targets }.
 * `ask` is never silently upgraded to `allow` anywhere in this plugin.
 */
export function evaluateCommand(command, cwd = process.cwd()) {
  const { class: cls, tools } = classify(command);

  if (!cls || cls === 'local') {
    return { decision: 'allow', class: cls ?? 'none', tools, targets: [], reason: 'static analysis of local artefacts' };
  }

  const scope = loadScope(cwd);
  const targets = extractTargets(command);
  const remoteTargets = targets.filter((t) => !isLocalTarget(t));
  const bssids = extractBssids(command);

  /**
   * The "it is only my own lab" shortcut is available to scanning classes,
   * where a target must be named for anything to happen at all.
   *
   * It requires that AT LEAST ONE target was parsed and EVERY parsed target is
   * local. A scanning command with no parseable target is NOT assumed local:
   * that is exactly the obfuscated-target case (`nmap 134744072`, a target
   * file via `-iL`, an unusual encoding), and treating "nothing I could read"
   * as "my own lab" was a bypass. Unverifiable fails closed.
   *
   * The shortcut is never available to wireless, exploitation or disruptive
   * activity: those act on radio space, credentials or availability.
   */
  const MAY_ASSUME_LOCAL = new Set(['passiveRecon', 'activeScan']);

  if (MAY_ASSUME_LOCAL.has(cls)) {
    if (targets.length > 0 && remoteTargets.length === 0) {
      return {
        decision: 'allow',
        class: cls,
        tools,
        targets,
        reason: 'every parsed target resolves to localhost or a private range (auditor-owned lab)',
      };
    }
    if (targets.length === 0) {
      return {
        decision: scope ? 'ask' : 'deny',
        class: cls,
        tools,
        targets: [],
        reason: `No verifiable target could be read from this ${cls} command. Declare the target in scope, or use an explicit local address (127.0.0.1, a private range). An unreadable or obfuscated target is not assumed to be your own lab.`,
      };
    }
  }

  if (!scope) {
    return {
      decision: 'deny',
      class: cls,
      tools,
      targets: remoteTargets,
      reason: 'No rules of engagement found. Run /security-audit:scope to declare the authorized targets before any active testing.',
    };
  }

  if (!scope.authorization?.granted) {
    return {
      decision: 'deny',
      class: cls,
      tools,
      targets: remoteTargets,
      reason: `Scope exists but authorization.granted is false. ${cls} activity is blocked until the engagement is signed off.`,
    };
  }

  const expiry = scope.engagement?.endsAt ? Date.parse(scope.engagement.endsAt) : null;
  if (expiry && Date.now() > expiry) {
    return {
      decision: 'deny',
      class: cls,
      tools,
      targets: remoteTargets,
      reason: `The engagement window closed on ${scope.engagement.endsAt}. Re-authorize before testing again.`,
    };
  }

  const rule = RULE_FOR_CLASS[cls];
  if (rule && scope.rules?.[rule] !== true) {
    return {
      decision: 'deny',
      class: cls,
      tools,
      targets: remoteTargets,
      reason: `Rules of engagement set rules.${rule} = false, which forbids ${cls} activity (${tools.join(', ')}).`,
    };
  }

  if (cls === 'wireless' || cls === 'disruptive') {
    const wireless = scope.targets?.wireless ?? { ssids: [], bssids: [] };
    const declaredSsids = (wireless.ssids ?? []).map((s) => s.toLowerCase());
    const declaredBssids = (wireless.bssids ?? []).map((b) => b.toUpperCase());

    if (declaredSsids.length === 0 && declaredBssids.length === 0) {
      return {
        decision: 'deny',
        class: cls,
        tools,
        targets: remoteTargets,
        reason: 'Wireless testing requires targets.wireless.ssids or .bssids in scope. Radio attacks reach every device in range, not just the one you meant.',
      };
    }

    // A named radio target must be one that was declared.
    const strayBssids = bssids.filter((b) => !declaredBssids.includes(b));
    if (strayBssids.length > 0) {
      return {
        decision: 'deny',
        class: cls,
        tools,
        targets: [...remoteTargets, ...strayBssids],
        reason: `BSSID(s) not in scope: ${strayBssids.join(', ')}. Declare them under targets.wireless.bssids or correct the command.`,
      };
    }
    const straySsids = extractSsids(command).filter((s) => !declaredSsids.includes(s.toLowerCase()));
    if (straySsids.length > 0) {
      return {
        decision: 'deny',
        class: cls,
        tools,
        targets: [...remoteTargets, ...straySsids],
        reason: `SSID(s) not in scope: ${straySsids.join(', ')}. Declare them under targets.wireless.ssids or correct the command.`,
      };
    }
  }

  const outside = remoteTargets.filter((t) => !matchesScope(t, scope));
  if (outside.length > 0) {
    return {
      decision: 'deny',
      class: cls,
      tools,
      targets: remoteTargets,
      reason: `Target(s) not in scope: ${outside.join(', ')}. Add them to .security-audit/scope.json or correct the command.`,
    };
  }

  return {
    decision: 'allow',
    class: cls,
    tools,
    targets: remoteTargets,
    reason: `Authorized: ${cls} against in-scope target(s) under engagement "${scope.engagement?.name || 'unnamed'}".`,
  };
}
