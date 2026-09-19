---
name: web
description: Web application security assessment against OWASP Top 10 2025 and the WSTG methodology — access control, misconfiguration, injection, session handling, client-side sinks and security headers. Use for "audit this web app", "OWASP review", "test my website", "check for XSS or CSRF".
argument-hint: "[path or URL]"
allowed-tools: Read, Glob, Grep, Write, Agent, Bash(node:*), Bash(git:*), Bash(nuclei:*), Bash(httpx:*), Bash(testssl.sh:*), Bash(zap-baseline.py:*)
---

# Web application security

Anchored to **OWASP Top 10 2025** — note the codes changed: SSRF is now inside
A01, supply chain is A03, and A10 "Mishandling of Exceptional Conditions" is new.
Full list in `${CLAUDE_PLUGIN_ROOT}/references/frameworks.md`.

Read `${CLAUDE_PLUGIN_ROOT}/references/methodology.md` and
`${CLAUDE_PLUGIN_ROOT}/references/false-positives.md` first.

## Surface

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/surface.mjs" $ARGUMENTS --budget 150000 --domain entrypoint --summary`

---

## Live targets require scope

A URL or hostname argument means active testing. Check first:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "nuclei -u https://target"
```

If denied, stop and route the user to `/security-audit:scope`. Source review
continues regardless — it needs no authorization.

## A01:2025 — Broken access control *(start here)*

The largest category, the hardest to scan for, and therefore where your
attention is worth most.

For every route and handler:

- **Is authorization checked at all?** Missing entirely is the common case.
- **Is the *object* checked, or only the session?** `GET /orders/:id` that
  loads by id without verifying ownership is IDOR (CWE-639).
- **Where does the tenant come from?** Session: correct. Request body or header:
  that is the bug.
- **Function-level:** can a normal user reach an admin route by guessing it?
  Look for authorization in middleware versus per-handler, and find the gaps.
- **SSRF** lives here now. Outbound requests with a user-influenced destination,
  especially ones that could reach `169.254.169.254` or an internal range.
- **Force browsing:** static files, backups, `.git`, source maps, admin panels.

## A02:2025 — Security misconfiguration

- Security headers: `Content-Security-Policy` (and whether it is actually
  restrictive or just present), `Strict-Transport-Security`, `X-Content-Type-Options`,
  `Referrer-Policy`, `X-Frame-Options` or CSP `frame-ancestors`.
- CORS: `Access-Control-Allow-Origin` reflecting the request origin, or `*`
  together with credentials. Check whether the origin check is a substring match
  — `evil-acme.com` passing a check for `acme.com` is a real and common bug.
- Cookies: `Secure`, `HttpOnly`, `SameSite`, scope, and prefix.
- **Subresource integrity.** A third-party `<script>` or `<link>` pulled from a
  CDN without an `integrity` hash — a compromised CDN then executes in your
  origin (OWASP A03:2025 supply chain, client side).
- Debug endpoints, stack traces, directory listing, default credentials,
  verbose error pages, exposed actuator or metrics endpoints.

## Cross-site request forgery (CSRF)

State-changing requests authenticated by an ambient credential — a session
cookie the browser attaches automatically — that a third-party page can trigger
on the victim's behalf. For every non-idempotent endpoint (`POST`, `PUT`,
`PATCH`, `DELETE`, or a `GET` that mutates):

- **Is there an anti-CSRF control at all, and is it *verified*?** A synchroniser
  token, a double-submit cookie, or an origin/referer check — issuing one is not
  enough; it has to be checked server-side and the request rejected when it is
  absent or wrong.
- **`SameSite` on the session cookie.** `Lax` (and the modern browser default)
  blocks the cross-site top-level `POST`; `None` with no token is exposed;
  `Strict` is safest but breaks some navigation flows. A cookie-auth API leaning
  on `SameSite` alone is one browser quirk from exposure.
- **JSON is not automatically safe.** A form-encoded or `text/plain` body is
  sendable cross-origin without a preflight; only a content type that forces the
  preflight, plus a *verified* custom header or token, actually protects it.
- **State-changing `GET`.** A mutation reachable by `GET` can be fired from an
  `<img src>`; no token in a form helps once the browser sends the request on
  its own.

The finding is "state-changing endpoint X has no verified CSRF defence", tagged
`WSTG-SESS-05`.

## A05:2025 — Injection

Server-side injection is covered by `/security-audit:code`. Here, focus on the
web-specific surface:

- **Reflected, stored and DOM XSS.** Remember the exclusions: React, Vue,
  Angular and Svelte escape by default — report only `dangerouslySetInnerHTML`,
  `v-html`, `[innerHTML]`, `{@html}`, `javascript:` URL sinks, or a bypassed
  sanitizer.
- **Prototype pollution.** User-controlled keys merged into an object (a
  recursive merge, `Object.assign` over parsed input, `lodash.merge`, a
  query-string parser) that reaches `__proto__`, `constructor` or `prototype` —
  a gadget chain can escalate it to XSS or RCE.
- Template injection in server-rendered views.
- Header injection and response splitting.
- Open redirect (CWE-601) — and whether it can be chained into OAuth token theft.

## A07:2025 — Authentication failures

Login, registration, password reset, MFA, session lifecycle:

- Account enumeration via differing responses **or timing**.
- Rate limiting and lockout on authentication endpoints specifically — this is
  the carve-out where missing rate limiting *is* a finding.
- Password reset tokens: entropy, expiry, single use, and whether the token is
  bound to the account.
- Session fixation: is the identifier rotated on privilege change?
- "Remember me" tokens, and logout that actually invalidates server-side.
- OAuth/OIDC: `state` parameter, PKCE, redirect-URI validation, token storage.

## A09:2025 — Logging and alerting failures

Renamed in 2025 — alerting is now explicit. Are authentication failures,
access-control denials and input-validation failures logged with enough context
to investigate? Are secrets or tokens being logged (CWE-532)?

## A10:2025 — Mishandling of exceptional conditions

New. Error paths that fail open, swallowed exceptions around authorization,
discarded verification results, and inconsistent state after a partial failure.

## WSTG coverage

Tag findings with the WSTG category so the report maps cleanly:
`WSTG-ATHZ` authorization · `WSTG-ATHN` authentication · `WSTG-SESS` session ·
`WSTG-INPV` input validation · `WSTG-CONF` configuration · `WSTG-CRYP` crypto ·
`WSTG-BUSL` business logic · `WSTG-CLNT` client-side.

## Business logic

Scanners never find these; you might. Ask what the application is *for*, then
ask how to abuse that:

- Can a price, quantity or discount be negative, or manipulated client-side?
- Can a workflow step be skipped, replayed, or run out of order?
- Are there race conditions on balance, inventory or quota — two requests in
  flight against one check?
- Can a limit be evaded by parallelism rather than by a larger value?

## Recording

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" add --file candidates.json
```

Set `domain: "web"`, tag `owasp` with the **2025** codes, and add `wstg` ids.
For a live target, evidence must be a real request and response, redacted.
