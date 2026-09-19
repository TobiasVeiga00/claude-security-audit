# JavaScript / TypeScript — sink reference

Depth beyond the signal database. Read when auditing JS/TS code.

## Injection

- **SQL**: `.query`/`.raw`/`.execute` with a concatenated or template string.
  With an ORM, check whether the interpolated part is a *value* (parameterisable
  via `$1`/`?`) or an *identifier* (table/column — needs an allowlist; a bound
  parameter cannot quote an identifier). `knex.raw`, `sequelize.query` with
  `replacements` vs. without, `mongoose` `$where` and operator injection.
- **NoSQL**: `find({ $where: userInput })`, or a request object spread into a
  query so `{ "$gt": "" }` becomes an operator. `req.body` reaching a Mongo
  query without casting is the classic authentication bypass.
- **Command**: `child_process.exec`/`execSync` take a *shell string* — injectable.
  `execFile`/`spawn` with an argument array do **not** invoke a shell — that is
  the safe form. Confirm which is used before reporting.
- **Code**: `eval`, `new Function`, `vm.runInContext`, `vm.compileFunction`.

## XSS and DOM

- `.innerHTML`/`.outerHTML =`, `insertAdjacentHTML`, `document.write`,
  `$(...).html()`, `dangerouslySetInnerHTML`.
- **React/Vue/Angular/Svelte escape by default** — only report `dangerouslySetInnerHTML`,
  `v-html`, `[innerHTML]`, `{@html}`, a `javascript:`/`data:` URL in `href`/`src`,
  or a bypassed sanitizer. See false-positives §7.
- `href={userInput}` where `userInput` can be `javascript:...`.

## Auth and crypto

- **JWT**: `jwt.decode()` without a following `verify`; `algorithms: ['none']`;
  `ignoreExpiration: true`; a verify call with a short or hardcoded secret;
  algorithm confusion (RS256 verified with a public key passed as an HMAC secret).
- **Weak crypto**: `crypto.createCipher` (deprecated, derives a weak key —
  `createCipheriv` is correct); `md5`/`sha1` for passwords or signatures;
  `Math.random()` for tokens, session ids, nonces, OTPs (needs
  `crypto.randomBytes`/`randomUUID`).

## Server-side request forgery

`axios`/`fetch`/`got`/`http.get`/`undici` with a URL from `req`. Check for an
allowlist, whether redirects are followed (`maxRedirects`), and whether
`169.254.169.254` or internal ranges are reachable.

## Node-specific

- **Path traversal**: `fs.readFile`/`createReadStream`/`res.sendFile` with a
  user path. Safe only if `path.resolve` is followed by a check that the result
  is still inside the intended root.
- **Prototype pollution**: recursive merge, `Object.assign({}, req.body)`,
  `__proto__`/`constructor.prototype` reachable from parsed input. Needs a
  reachable gadget to be more than theoretical.
- **Deserialization**: `node-serialize`, `serialize-javascript` used to
  *deserialize*, `js-yaml` `load` without `JSON_SCHEMA`/`FAILSAFE_SCHEMA`.
- **ReDoS**: `new RegExp(userInput)`, or a static regex with catastrophic
  backtracking (nested quantifiers `(a+)+`) fed unbounded input.
- **Dynamic require/import**: `require(userVar)`, `import(userVar)` (CWE-470).
- **Open redirect**: `res.redirect(req.query.next)` without an allowlist.
- **CORS**: `origin: true` or reflecting `req.headers.origin` together with
  `credentials: true`; a substring origin check (`origin.includes('acme.com')`
  passes `acme.com.evil.com`).

## Framework notes

- **Express**: missing `helmet`, no body-size limit (`express.json({ limit })`),
  no rate limiting on auth routes, error handler leaking stack traces.
- **Next.js**: server actions without auth, middleware matcher gaps, API routes
  trusting client-set headers, `dangerouslySetInnerHTML` in components.
- **NestJS**: a global `ValidationPipe` with `whitelist: true` and
  `forbidNonWhitelisted: true` is the mass-assignment defence — check it exists.
- **GraphQL** (`apollo`, `graphql`): depth/complexity limits, introspection in
  production, batching abuse, field-level authorization.
