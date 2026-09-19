# Reference frameworks

Current editions as of **2026-09**. Only identifiers, titles and mappings are
recorded here — these are facts, not expression. OWASP prose is CC-BY-SA and is
linked, never copied.

Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" status` to see which
versions the vendored intelligence was built from.

---

## OWASP Top 10 — **2025** (8th edition)

Do not cite the 2021 codes. SSRF was absorbed into A01; two categories are new.

| Code | Category |
| --- | --- |
| A01:2025 | Broken Access Control *(now includes SSRF)* |
| A02:2025 | Security Misconfiguration |
| A03:2025 | **Software Supply Chain Failures** *(new; replaces "Vulnerable and Outdated Components")* |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | **Mishandling of Exceptional Conditions** *(new)* |

<https://top10.owasp.org/2025/>

## OWASP API Security Top 10 — **2023** (still current)

| Code | Category |
| --- | --- |
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

<https://api-security.owasp.org/>

## OWASP Top 10 for LLM Applications — **2025** (current edition)

| Code | Category |
| --- | --- |
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

## OWASP Top 10 for Agentic Applications — **2026**

| Code | Category |
| --- | --- |
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory and Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

<https://genai.owasp.org/>

---

## OWASP ASVS — **5.0.0** (2025-05-30)

Seventeen chapters, 345 requirements. **Every requirement was renumbered in 5.0**
— 4.x identifiers do not map across, so never cite a `V…` id without the version.

V1 Encoding and Sanitization · V2 Validation and Business Logic ·
V3 Web Frontend Security · V4 API and Web Service · V5 File Handling ·
V6 Authentication · V7 Session Management · V8 Authorization ·
V9 Self-contained Tokens · V10 OAuth and OIDC · V11 Cryptography ·
V12 Secure Communication · V13 Configuration · V14 Data Protection ·
V15 Secure Coding and Architecture · V16 Security Logging and Error Handling ·
V17 WebRTC

Levels: **L1** baseline · **L2** applications handling sensitive data (the usual
target) · **L3** highest assurance.

## OWASP WSTG — **v4.2**

| Prefix | Category |
| --- | --- |
| WSTG-INFO | Information Gathering |
| WSTG-CONF | Configuration and Deployment Management |
| WSTG-IDNT | Identity Management |
| WSTG-ATHN | Authentication |
| WSTG-ATHZ | Authorization |
| WSTG-SESS | Session Management |
| WSTG-INPV | Input Validation |
| WSTG-ERRH | Error Handling |
| WSTG-CRYP | Weak Cryptography |
| WSTG-BUSL | Business Logic |
| WSTG-CLNT | Client-side |
| WSTG-APIT | API Testing |

## OWASP MASVS **2.1.0** / MASTG **2.0.0**

Eight control groups. **From MASTG v2.0 the L1/L2/R levels no longer live in
MASVS** — they were reworked as MAS Testing Profiles. Cite a profile, not
"MASVS-L1".

MASVS-STORAGE · MASVS-CRYPTO · MASVS-AUTH · MASVS-NETWORK ·
MASVS-PLATFORM · MASVS-CODE · MASVS-RESILIENCE · MASVS-PRIVACY

## OWASP Top 10 CI/CD Security Risks — v1.0

CICD-SEC-1 Insufficient Flow Control · -2 Inadequate IAM · -3 Dependency Chain
Abuse · -4 Poisoned Pipeline Execution · -5 Insufficient PBAC · -6 Insufficient
Credential Hygiene · -7 Insecure System Configuration · -8 Ungoverned Third-Party
Services · -9 Improper Artifact Integrity Validation · -10 Insufficient Logging

---

## MITRE ATT&CK — **v19** (2026-04-28)

**Breaking change:** Defense Evasion was split. `TA0005` is now **Stealth**, and
`TA0112` **Defense Impairment** is new. Any mapping that still reads `TA0005 =
Defense Evasion` is wrong.

| Order | ID | Tactic |
| --- | --- | --- |
| 1 | TA0043 | Reconnaissance |
| 2 | TA0042 | Resource Development |
| 3 | TA0001 | Initial Access |
| 4 | TA0002 | Execution |
| 5 | TA0003 | Persistence |
| 6 | TA0004 | Privilege Escalation |
| 7 | TA0005 | **Stealth** |
| 8 | TA0112 | **Defense Impairment** |
| 9 | TA0006 | Credential Access |
| 10 | TA0007 | Discovery |
| 11 | TA0008 | Lateral Movement |
| 12 | TA0009 | Collection |
| 13 | TA0011 | Command and Control |
| 14 | TA0010 | Exfiltration |
| 15 | TA0040 | Impact |

Mobile and ICS matrices are separate. Look techniques up locally rather than
from memory:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" attack T1190
```

## CWE Top 25 — **2025 edition** (published 2025-12-11, MITRE view CWE-1435)

1 CWE-79 · 2 CWE-89 · 3 CWE-352 · 4 CWE-862 · 5 CWE-787 · 6 CWE-22 ·
7 CWE-416 · 8 CWE-125 · 9 CWE-78 · 10 CWE-94 · 11 CWE-120 · 12 CWE-434 ·
13 CWE-476 · 14 CWE-121 · 15 CWE-502 · 16 CWE-122 · 17 CWE-863 · 18 CWE-20 ·
19 CWE-284 · 20 CWE-200 · 21 CWE-306 · 22 CWE-918 · 23 CWE-77 · 24 CWE-639 ·
25 CWE-770

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/intel.mjs" cwe 89
```

---

## Process and compliance

- **NIST CSF 2.0** (2024-02-26) — six functions: **GOVERN**, IDENTIFY, PROTECT,
  DETECT, RESPOND, RECOVER.
- **NIST SP 800-115** (2008) — Planning → Discovery → Attack → Reporting.
- **PTES** — Pre-engagement → Intelligence Gathering → Threat Modeling →
  Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting.
- **CIS Controls v8.1** (2024-06-25) — 18 controls, 153 safeguards, IG1–IG3.
- **PCI DSS v4.0.1** (June 2024) — 12 requirements; future-dated v4.x items
  became mandatory 2025-03-31.
- **ISO/IEC 27001:2022** + Amd 1:2024 — Annex A: 93 controls in four themes
  (A.5 Organizational 37, A.6 People 8, A.7 Physical 14, A.8 Technological 34).
- **SOC 2** — 2017 Trust Services Criteria (revised points of focus, 2022):
  Security (CC1–CC9, mandatory), Availability, Processing Integrity,
  Confidentiality, Privacy.

---

## Wireless: what still matters in 2026

Weight the playbook toward the first five. Treat KRACK and Dragonblood as
patch-currency checks, not primary vectors.

| Priority | Class | Note |
| --- | --- | --- |
| High | **WPA3 transition-mode downgrade** | The number one WPA3 finding. Transition mode keeps a WPA2 path; force it, capture, crack offline. Control: SAE-only, transition mode disabled. |
| High | **802.1X / EAP misconfiguration** | Top enterprise finding. Absent server-certificate validation, no CA pinning, no `ServerName` constraint, MSCHAPv2 hash cracking. |
| High | **PMKID capture** | Clientless. `hcxdumptool` → hashcat `-m 22000`. Fastest WPA2-PSK passphrase audit. |
| High | **Evil twin / rogue AP** | Unaffected by WPA3 for open and captive-portal cases. Primary credential-harvest vector. |
| Medium | **WPS Pixie Dust / PIN brute force** | Still enabled on plenty of SOHO gear. The finding is "WPS enabled". |
| Medium | **4-way handshake capture** | Only meaningful against PSK, never against SAE. |
| Medium | **Karma / PNL abuse** | Client-side; persists on legacy and provisioned profiles. |
| Control | **802.11w PMF state** | Mandatory for WPA3 and Enhanced Open, optional under WPA2. Audit the *state*; deauth is the symptom. |
| Low | KRACK, Dragonblood | Patched across mainstream stacks. Residual surface is unmanaged IoT and legacy embedded. Report as firmware currency. |
