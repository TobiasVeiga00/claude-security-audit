# Java / Kotlin — sink reference

Depth beyond the signal database. Read when auditing JVM code (Scala and Groovy
share most sinks).

## Deserialization — the JVM's signature flaw

`ObjectInputStream.readObject`, `XMLDecoder`, Jackson with
`enableDefaultTyping` / `activateDefaultTyping` or `@JsonTypeInfo`, `fastjson`
autotype, `XStream` without a whitelist, SnakeYAML `new Yaml().load(...)`
without a safe constructor. Any of these on untrusted bytes is RCE (CWE-502) —
the highest-value JVM finding.

## Injection

- **Command**: `Runtime.getRuntime().exec`, `ProcessBuilder`. A single-string
  `exec` splits on spaces (not a shell) but still allows argument injection.
- **SQL**: `Statement.executeQuery("..." + v)`; `String.format` into SQL;
  `createStatement` used instead of `prepareStatement`. A bound identifier is
  not possible, so dynamic table names need an allowlist.
- **Expression language**: `SpelExpressionParser`, OGNL (`OgnlContext`), MVEL,
  `ScriptEngineManager().getEngineByName("js").eval(...)` — Struts/Spring EL
  injection.
- **LDAP**: `InitialDirContext.search` with concatenated filters (CWE-90).

## XXE

`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`,
`TransformerFactory`, `SAXReader` — all require explicit hardening (disable
DOCTYPE and external entities). A factory created without that hardening,
parsing untrusted XML, is a finding.

## TLS and crypto

- An `X509TrustManager` whose `checkServerTrusted` is empty; `ALLOW_ALL_HOSTNAME_VERIFIER`;
  a `HostnameVerifier` returning `true`. Critical — it disables all transport
  security.
- `Cipher.getInstance("DES" | "AES/ECB" | "Blowfish")`; `MessageDigest` MD5/SHA-1
  for security; `new Random()` for tokens (use `SecureRandom`); `SHA1PRNG`.

## Spring specifics

- **Spring Security**: read the `SecurityFilterChain` — `permitAll()` on too
  much, `csrf().disable()`, method security not enabled.
- **Actuator** endpoints exposed (`/actuator/env`, `/heapdump`, `/jolokia`) — a
  common information-disclosure and RCE path.
- `@CrossOrigin(origins = "*")` with credentials.
- Mass assignment via `@ModelAttribute` binding without `@InitBinder` field
  restrictions.

## Android (Kotlin/Java)

Route to `/security-audit:mobile`, but at code level watch: a `WebView` with
`addJavascriptInterface` and `setJavaScriptEnabled(true)` on remote content;
`rawQuery` / `execSQL` string-built SQL; secrets in `Log.d`; exported components;
`MODE_WORLD_READABLE`.
