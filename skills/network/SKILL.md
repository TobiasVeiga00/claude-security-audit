---
name: network
description: Network and wireless security assessment — host and service discovery, TLS posture, exposed services, and Wi-Fi testing (WPA2/WPA3, PMKID, 802.1X EAP, evil twin, PMF). All active work is gated behind written rules of engagement. Use for "network scan", "port scan", "check my TLS", "Wi-Fi audit", "wireless assessment".
argument-hint: "[host, range, or --wireless]"
allowed-tools: Read, Write, AskUserQuestion, Bash(node:*), Bash(nmap:*), Bash(testssl.sh:*), Bash(naabu:*), Bash(hcxdumptool:*), Bash(hashcat:*), Bash(hostapd-wpe:*)
---

# Network and wireless security

**Everything in this skill puts packets on a wire.** None of it runs until the
authorization gate clears it. That is not a formality — an unauthorized scan is,
in many jurisdictions, a criminal act.

Rules of engagement:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" show 2>&1`

Tooling:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/tools.mjs" --domain network,wireless --missing 2>&1`

---

## Before anything

If there is no scope, stop and run `/security-audit:scope`. If there is, confirm
the specific target is covered:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "nmap -sV target"
```

The gate will block an out-of-scope target regardless, but checking first lets
you fix the command instead of hitting a wall.

---

## Network

### Discovery

Start narrow. A full scan of a large range is slow, noisy, and rarely what the
engagement needs first.

```bash
nmap -sV -sC -oX .security-audit/nmap.xml <in-scope target>
```

Then import the results rather than reading the XML into the conversation:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool sarif --file <converted>
```

(Nmap XML has no importer; summarise the interesting services and record
findings by hand, or convert to SARIF first.)

### What to look for

- **Unexpected exposed services.** Databases, admin panels, message brokers,
  Kubernetes API, Docker daemon, Redis, Elasticsearch — anything data-bearing
  that answers from the internet.
- **Default or weak service configuration.** Anonymous FTP, open SMB shares,
  SNMP with `public`, unauthenticated Redis.
- **Version-based exposure.** Cross-reference banners against known CVEs:
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" cve <id>`.

### TLS

```bash
testssl.sh --jsonfile .security-audit/testssl.json <host:port>
```

Report protocol versions (SSLv3, TLS 1.0/1.1 should be gone), weak cipher
suites, certificate validity and chain, `Secure` renegotiation, and known issues
(Heartbleed, ROBOT) where the tool flags them.

---

## Wireless

Wireless is different in kind: **radio attacks reach every device in range**, not
only your target. The gate therefore requires SSIDs or BSSIDs to be declared
explicitly, and every one on a command line must match a declared target.

Weight the assessment toward what actually matters in 2026 (full rationale in
`${CLAUDE_PLUGIN_ROOT}/references/frameworks.md`):

### High priority

- **WPA3 transition-mode downgrade** — the number-one WPA3 finding. Transition
  mode keeps a WPA2 path; force it, capture, crack offline. The control is
  SAE-only with transition mode disabled.
- **802.1X / EAP misconfiguration** — the top enterprise finding. Absent server
  certificate validation, no CA pinning, no `ServerName` constraint, crackable
  MSCHAPv2. Test with a controlled `hostapd-wpe`, never against a live corporate
  network without explicit sign-off.
- **PMKID capture** — clientless. `hcxdumptool` to capture, hashcat `-m 22000`
  to crack. The fastest WPA2-PSK passphrase audit.
- **Evil twin / rogue AP** — unaffected by WPA3 for open and captive-portal
  cases. The primary credential-harvest vector.

### Medium priority

- **WPS Pixie Dust / PIN brute force** — still enabled on plenty of SOHO gear.
  The finding is "WPS enabled".
- **4-way handshake capture** — meaningful against PSK only, never SAE.
- **Karma / PNL abuse** — client-side; persists on legacy and provisioned
  profiles.

### As a control, not an attack

- **802.11w PMF state** — mandatory under WPA3, optional under WPA2. Audit the
  state; deauthentication is only the symptom.
- **KRACK and Dragonblood** — patched across mainstream stacks. Report as
  firmware-currency checks; the residual surface is unmanaged IoT and legacy
  embedded.

### Deauthentication is a denial of service

It needs `denialOfService: true` in scope, and it affects bystanders on shared
spectrum. Confirm the client genuinely wants it, in writing, before enabling it.

---

## Recording

`domain: "network"` or `"wireless"`, the host and port or the SSID/BSSID in
`location`, and evidence that is a real captured artefact, redacted. For
wireless, name the specific configuration control (SAE-only, PMF required, WPS
disabled) in the remediation.
