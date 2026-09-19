---
name: mobile
description: Mobile application security assessment against OWASP MASVS and MASTG — insecure storage, cryptography, authentication, network trust, platform interaction, code quality, resilience and privacy, for Android and iOS. Use for "audit my Android app", "iOS security review", "MASVS assessment", "check my APK".
argument-hint: "[path to project, APK or IPA]"
allowed-tools: Read, Glob, Grep, Write, Bash(node:*), Bash(git:*), Bash(jadx:*), Bash(apktool:*), Bash(unzip:*), Bash(strings:*), Bash(plutil:*), Bash(frida:*), Bash(objection:*)
---

# Mobile application security

Anchored to **OWASP MASVS 2.1.0** and **MASTG 2.0.0**. Note the level model
changed: from MASTG v2.0 the L1/L2/R levels no longer live in MASVS — they were
reworked as **MAS Testing Profiles**. Cite a profile, never "MASVS-L1".

## Surface

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/surface.mjs" $ARGUMENTS --budget 150000 --summary`

Tooling:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/tools.mjs" --domain mobile --missing 2>&1`

---

## Working from a binary

Source is better. If you only have an APK or IPA:

```bash
# Android
apktool d app.apk -o .security-audit/apk-decoded
jadx -d .security-audit/apk-source app.apk

# iOS
unzip -q app.ipa -d .security-audit/ipa
```

Then run the surface mapper over the decoded tree. Decompiled output is
generated code — read the manifest, the entitlements and the network config
first, because those are authoritative and small.

## MASVS-STORAGE — data at rest

The most productive category in practice. Mobile devices get lost, backed up and
shared.

- **Android:** `SharedPreferences` holding tokens or passwords;
  `MODE_WORLD_READABLE`/`WRITEABLE`; external storage for anything sensitive;
  SQLite without encryption; `android:allowBackup="true"` in the manifest.
- **iOS:** `UserDefaults` for credentials; Keychain accessibility class —
  `kSecAttrAccessibleAlways` and non-`ThisDeviceOnly` variants sync to iCloud;
  Core Data and plist files unprotected.
- **Both:** secrets written to logs (`Log.d`, `NSLog`, `print`), cached HTTP
  responses containing personal data, screenshots on backgrounding, pasteboard
  leakage.

## MASVS-CRYPTO

Hardcoded keys are the classic finding — a key in the binary is a key everyone
has. Also: ECB mode, static IVs, `Cipher.getInstance("AES")` without a mode,
custom crypto, and keys not held in the Keystore or Secure Enclave.

## MASVS-AUTH

Authentication decisions made on the device that should be made on the server.
Biometric prompts used as a UI gate rather than bound to a Keystore-protected
key. Session tokens without expiry. Compare what the client enforces against
what the server enforces — only the second one counts.

## MASVS-NETWORK

- **Certificate validation disabled.** A `TrustManager` whose
  `checkServerTrusted` is empty, a `HostnameVerifier` returning `true`, or an
  iOS trust callback that calls `.useCredential` unconditionally. This is a
  critical finding; it turns any network into a full interception.
- **Cleartext traffic:** `android:usesCleartextTraffic="true"`, missing
  `network_security_config.xml`, or iOS `NSAllowsArbitraryLoads`.
- **Certificate pinning:** absent, or implemented in a way that is trivially
  bypassed. Note that pinning is a control, and its absence is a hardening note
  unless the threat model demands it.

## MASVS-PLATFORM

- **Exported components** — activities, services, receivers and providers with
  `android:exported="true"` and no permission. Check every intent-filter.
- **WebView**: `setJavaScriptEnabled(true)` with remote content;
  `addJavascriptInterface` (a JavaScript bridge into native code);
  `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`; iOS `UIWebView`
  (deprecated and unsafe) or a `WKUserContentController` message handler.
- **Deep links and URL schemes** — unvalidated parameters reaching sensitive
  actions, and custom schemes any app can claim.
- **`PendingIntent`** created mutable, or implicit.
- **iOS:** `LSApplicationQueriesSchemes`, app group containers, and entitlements
  broader than the app needs.

## MASVS-CODE

Third-party SDK inventory and their known vulnerabilities — route this to
`/security-audit:deps`. Also: debuggable builds shipped
(`android:debuggable="true"`), test code in release, and verbose logging left on.

## MASVS-RESILIENCE

Root and jailbreak detection, anti-tamper, obfuscation. Be honest with the
client: these raise cost for an attacker, they do not prevent anything. A
finding here is only material when the app's threat model genuinely includes a
hostile device owner — payment, DRM, gaming. Otherwise it is a note.

## MASVS-PRIVACY

Permissions requested beyond what the app does. Analytics SDKs receiving
identifiers. Data collection without disclosure. Background location. This
category increasingly carries regulatory weight, so report it plainly.

## Dynamic testing

Frida and objection are instrumentation — they run code inside the application.
On your own build, fine. On anything else, that is active testing:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "frida -U -f com.example.app"
```

## Recording

`domain: "mobile"`, the `masvs` control group as a tag, the file and line from
decompiled or original source, and remediation naming the specific API or
manifest attribute to change.
