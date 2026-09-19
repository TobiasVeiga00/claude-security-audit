import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  evaluateCommand, extractTargets, extractBssids, extractSsids,
  isLocalTarget, matchesScope, defaultScope,
} from '../scripts/lib/scope.mjs';

function withScope(scope) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sa-scope-'));
  if (scope) {
    fs.mkdirSync(path.join(dir, '.security-audit'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, '.security-audit', 'scope.json'),
      JSON.stringify(scope, null, 2),
    );
  }
  return dir;
}

const AUTHORIZED = {
  ...defaultScope(),
  engagement: { name: 'Acme Q3', client: 'Acme', type: 'authorized-pentest', endsAt: '2099-01-01T00:00:00Z' },
  authorization: { granted: true, grantedBy: 'CISO', reference: 'SOW-114' },
  targets: {
    repos: [], hosts: ['api.acme.com'], domains: ['acme.com'], urls: [],
    ipRanges: ['203.0.113.0/24'], cloudAccounts: [], mobileApps: [],
    wireless: { ssids: ['ACME-CORP'], bssids: ['AA:BB:CC:DD:EE:FF'] },
  },
  outOfScope: { hosts: [], domains: ['payments.acme.com'], ipRanges: ['203.0.113.200/29'], notes: [] },
  rules: {
    staticAnalysis: true, passiveRecon: true, activeTesting: true,
    exploitation: false, denialOfService: false, socialEngineering: false,
    dataExfiltration: false, maxRequestsPerSecond: 10, testWindow: '',
  },
};

/* ---------------------------------------------------------------- */

test('target extraction', () => {
  assert.deepEqual(extractTargets('nmap -sV scanme.nmap.org'), ['scanme.nmap.org']);
  assert.ok(extractTargets('curl https://api.acme.com/v1/users').includes('api.acme.com'));
  assert.ok(extractTargets('nmap 203.0.113.0/24').includes('203.0.113.0/24'));
  // A filename must not be mistaken for a hostname.
  assert.deepEqual(extractTargets('semgrep --config auto src/app.js'), []);
  assert.deepEqual(extractBssids('aireplay-ng -a aa:bb:cc:dd:ee:ff wlan0'), ['AA:BB:CC:DD:EE:FF']);
  assert.deepEqual(extractSsids('airodump-ng --essid "Guest WiFi" wlan0mon'), ['Guest WiFi']);
});

test('local and private targets are recognised', () => {
  for (const t of ['localhost', '127.0.0.1', '10.1.2.3', '192.168.1.5', '172.16.0.9', 'app.local']) {
    assert.equal(isLocalTarget(t), true, `${t} should be local`);
  }
  for (const t of ['acme.com', '8.8.8.8', '203.0.113.5']) {
    assert.equal(isLocalTarget(t), false, `${t} should not be local`);
  }
});

test('scope matching honours wildcards and exclusions', () => {
  assert.equal(matchesScope('acme.com', AUTHORIZED), true);
  assert.equal(matchesScope('www.acme.com', AUTHORIZED), true);
  assert.equal(matchesScope('api.acme.com', AUTHORIZED), true);
  assert.equal(matchesScope('203.0.113.42', AUTHORIZED), true);
  assert.equal(matchesScope('payments.acme.com', AUTHORIZED), false, 'explicit exclusion wins');
  assert.equal(matchesScope('203.0.113.201', AUTHORIZED), false, 'excluded range wins');
  assert.equal(matchesScope('evil.com', AUTHORIZED), false);
});

/* ---------------------------------------------------------------- */

test('static analysis never requires scope', () => {
  const dir = withScope(null);
  for (const cmd of ['semgrep --config auto .', 'gitleaks detect', 'trivy fs .', 'npm audit']) {
    const v = evaluateCommand(cmd, dir);
    assert.equal(v.decision, 'allow', cmd);
  }
});

test('active scanning without scope is denied', () => {
  const dir = withScope(null);
  const v = evaluateCommand('nmap -sV scanme.nmap.org', dir);
  assert.equal(v.decision, 'deny');
  assert.equal(v.class, 'activeScan');
  assert.match(v.reason, /No rules of engagement/);
});

test('loopback and RFC1918 targets are treated as the auditor lab', () => {
  const dir = withScope(null);
  assert.equal(evaluateCommand('nmap -sV 127.0.0.1', dir).decision, 'allow');
  assert.equal(evaluateCommand('nuclei -u http://localhost:3000', dir).decision, 'allow');
  assert.equal(evaluateCommand('nmap -sV 192.168.1.10', dir).decision, 'allow');
});

test('authorized in-scope scanning is allowed', () => {
  const dir = withScope(AUTHORIZED);
  for (const cmd of ['nmap -sV www.acme.com', 'nmap -sV 203.0.113.42', 'nuclei -u https://api.acme.com']) {
    const v = evaluateCommand(cmd, dir);
    assert.equal(v.decision, 'allow', `${cmd} -> ${v.reason}`);
  }
});

test('out-of-scope targets are denied even under a valid engagement', () => {
  const dir = withScope(AUTHORIZED);
  for (const cmd of ['nmap -sV payments.acme.com', 'nmap -sV google.com', 'nmap -sV 203.0.113.201']) {
    const v = evaluateCommand(cmd, dir);
    assert.equal(v.decision, 'deny', cmd);
    assert.match(v.reason, /not in scope/i);
  }
});

test('a disabled rule blocks its whole activity class', () => {
  const dir = withScope(AUTHORIZED); // exploitation: false
  const v = evaluateCommand('sqlmap -u https://www.acme.com/a?id=1', dir);
  assert.equal(v.decision, 'deny');
  assert.equal(v.class, 'exploitation');
  assert.match(v.reason, /rules\.exploitation = false/);
});

test('an expired engagement blocks everything active', () => {
  const dir = withScope({
    ...AUTHORIZED,
    engagement: { ...AUTHORIZED.engagement, endsAt: '2020-01-01T00:00:00Z' },
  });
  const v = evaluateCommand('nmap -sV www.acme.com', dir);
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /window closed/);
});

test('unrevoked authorization is still required', () => {
  const dir = withScope({ ...AUTHORIZED, authorization: { ...AUTHORIZED.authorization, granted: false } });
  const v = evaluateCommand('nmap -sV www.acme.com', dir);
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /authorization\.granted is false/);
});

/* ---------------------------------------------------------------- *
 * Regression: a destructive command with no parseable host must not
 * inherit the "it is only my own lab" shortcut. Radio attacks reach
 * every device in range whether or not a target was typed.
 * ---------------------------------------------------------------- */

test('deauthentication without scope is denied even with no host in the command', () => {
  const dir = withScope(null);
  const v = evaluateCommand('aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon', dir);
  assert.equal(v.decision, 'deny');
  assert.equal(v.class, 'disruptive');
});

test('wireless capture without declared radio scope is denied', () => {
  const dir = withScope(null);
  assert.equal(evaluateCommand('airodump-ng wlan0mon', dir).decision, 'deny');
  assert.equal(evaluateCommand('hcxdumptool -i wlan0 -o dump.pcapng', dir).decision, 'deny');
});

test('declared wireless targets are allowed, undeclared ones are not', () => {
  const dir = withScope(AUTHORIZED);
  assert.equal(
    evaluateCommand('airodump-ng --essid ACME-CORP wlan0mon', dir).decision,
    'allow',
  );
  const stray = evaluateCommand('airodump-ng --essid "Neighbour WiFi" wlan0mon', dir);
  assert.equal(stray.decision, 'deny');
  assert.match(stray.reason, /SSID\(s\) not in scope/);

  const strayBssid = evaluateCommand('airodump-ng --bssid 11:22:33:44:55:66 wlan0mon', dir);
  assert.equal(strayBssid.decision, 'deny');
  assert.match(strayBssid.reason, /BSSID\(s\) not in scope/);
});

test('deauth stays blocked while denialOfService is false, even in scope', () => {
  const dir = withScope(AUTHORIZED); // denialOfService: false
  const v = evaluateCommand('aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon', dir);
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /rules\.denialOfService = false/);
});

test('escalating flags reclassify an otherwise-permitted tool', () => {
  const dir = withScope(AUTHORIZED);
  const plain = evaluateCommand('nmap -sV www.acme.com', dir);
  assert.equal(plain.decision, 'allow');

  const intrusive = evaluateCommand('nmap --script exploit www.acme.com', dir);
  assert.equal(intrusive.decision, 'deny');
  assert.equal(intrusive.class, 'exploitation');
});
