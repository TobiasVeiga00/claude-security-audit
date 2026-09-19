---
name: api
description: API security assessment against the OWASP API Security Top 10 — object and function level authorization, resource consumption, business flow abuse, inventory and unsafe consumption of upstream APIs. Covers REST, GraphQL and RPC. Use for "audit my API", "check my endpoints", "GraphQL security", "BOLA/IDOR review".
argument-hint: "[path, OpenAPI spec, or base URL]"
allowed-tools: Read, Glob, Grep, Write, Agent, Bash(node:*), Bash(git:*), Bash(schemathesis:*), Bash(nuclei:*)
---

# API security

Anchored to **OWASP API Security Top 10 (2023)** — still the current edition.

Read `${CLAUDE_PLUGIN_ROOT}/references/methodology.md` and
`${CLAUDE_PLUGIN_ROOT}/references/false-positives.md` first.

## Surface

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/surface.mjs" $ARGUMENTS --budget 150000 --domain entrypoint --summary`

API descriptions present:
!`ls -1 openapi.yaml openapi.json swagger.json schema.graphql 2>/dev/null || echo "(none at root — search the tree for a schema)"`

---

## Build the endpoint inventory first

You cannot audit authorization on endpoints you have not enumerated. Derive the
inventory from, in order of reliability:

1. An OpenAPI or GraphQL schema, if one exists.
2. Route registrations in source — the surface map's `entrypoint` hotspots.
3. Client code that calls the API.

For each endpoint record: method, path, parameters, the authentication it
expects, the authorization it performs, and the object it touches. That table
*is* the audit.

## API1 — Broken object level authorization (BOLA)

The single most exploited API flaw. For every endpoint taking an identifier:

- Is ownership verified, or only authentication?
- Is the check before or after the object is loaded — and does the error
  response differ, leaking existence?
- Are identifiers sequential? Sequential ids do not create the vulnerability,
  but they make it trivially exploitable at scale. UUIDv4 does not fix a missing
  check; it only makes it harder to enumerate.

## API2 — Broken authentication

Token validation on **every** path, not just the happy one. Algorithm pinning,
expiry enforcement, signature verification, revocation. Look for endpoints that
accept an unauthenticated request by omission rather than by design.

## API3 — Broken object property level authorization

Two directions, both common:

- **Excessive data exposure:** the response serialises the whole model —
  `passwordHash`, `internalNotes`, `isAdmin`, another user's email. Check what
  the serialiser actually emits, not what the documentation claims.
- **Mass assignment:** the request body is bound wholesale to a model, letting a
  caller set `role`, `isAdmin`, `balance` or `tenantId`.

## API4 — Unrestricted resource consumption

Pagination limits, upload size caps, and the cost of a single request:

- **GraphQL:** query depth and complexity limits, alias-based amplification,
  batching abuse, and introspection in production.
- Endpoints that fan out to third parties, send email or SMS, or run expensive
  queries.

## API5 — Broken function level authorization

Administrative endpoints reachable by role manipulation, path guessing, or an
HTTP method the authorization middleware does not cover. Check that the
middleware matches *all* methods and path variants.

## API6 — Unrestricted access to sensitive business flows

Not a technical flaw — an abuse of a working feature. Ticket purchase,
referral credit, voting, reservation. Can it be automated at a scale the
business did not intend?

## API7 — Server side request forgery

Any endpoint accepting a URL: webhooks, imports, avatar fetching, link preview.
Check for an allowlist, whether redirects are followed, and whether cloud
metadata endpoints are reachable.

## API8 — Security misconfiguration

TLS, CORS, headers, verbose errors, HTTP methods enabled by accident (`TRACE`,
`OPTIONS` leaking), and inconsistent behaviour between API gateway and origin.

## API9 — Improper inventory management

Old versions still live (`/v1` beside `/v2`), staging hosts reachable from the
internet, undocumented debug endpoints, deprecated routes with weaker checks.
This is where the inventory you built pays off: compare it to what is deployed.

## API10 — Unsafe consumption of APIs

Your service trusting an upstream one. Is the third-party response validated,
size-limited and schema-checked before use? Is its TLS verified? A compromised
upstream should not become a compromised you.

## Schema-driven testing

With an OpenAPI schema and authorization in place:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "schemathesis run openapi.yaml"
schemathesis run --checks all --base-url https://target openapi.yaml
```

## Recording

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" add --file candidates.json
```

Set `domain: "api"`, tag `owasp` with the `APIn:2023` codes, and put the
endpoint in `location.url` with the offending parameter in `location.parameter`.
