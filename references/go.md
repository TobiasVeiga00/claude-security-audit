# Go — sink reference

Depth beyond the signal database. Read when auditing Go.

## Injection

- **SQL**: `db.Query` / `Exec` / `QueryRow` with `fmt.Sprintf` or `"..." + v`.
  The safe form uses placeholders (`?` or `$1`) and variadic args. Check `gorm`
  raw fragments and `sqlx` string building.
- **Command**: `exec.Command(name, args...)` is safe when `name` is fixed and
  args are separate. It becomes injectable when the program is `sh -c` with a
  built string, or when `name` itself is user-controlled.
- **Template**: `text/template` does **no** escaping — using it for HTML is XSS.
  `html/template` escapes, but the `template.HTML` / `template.JS` /
  `template.URL` wrappers bypass that escaping.

## Web

- **Path traversal**: `os.Open` / `os.ReadFile` / `http.ServeFile` with a path
  from `r.URL` / `r.FormValue` / `mux.Vars` / `c.Param`. `filepath.Join(root,
  userPath)` without a containment check escapes the root.
- **SSRF**: `http.Get` / `http.Post` / `client.Do` with a user URL.
- **Open redirect**: `http.Redirect(w, r, r.URL.Query().Get("next"), ...)`.

## Crypto and TLS

- `tls.Config{InsecureSkipVerify: true}` — disables certificate validation.
- `MinVersion` unset or `tls.VersionTLS10` / `TLS11`.
- `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4` for security;
  `math/rand` for tokens or keys (use `crypto/rand`).

## Idioms that hide bugs

- **Ignored errors on security operations**: `valid, _ := verify(...)` then using
  `valid`, or discarding the error from an auth check (CWE-252). Grep for `_ =`
  and `_,` around `Verify` / `Validate` / `Authenticate` / `Authorize`.
- **`context` without a deadline** on outbound calls — resource exhaustion.
- **Integer overflow** in size arithmetic before `make([]byte, n)`.
- **Race conditions** on shared mutable state reached by concurrent handlers —
  TOCTOU on balance/quota checks. Confirm with `go test -race`.
- A nil-pointer dereference on an unchecked type assertion as a DoS.

## Reachability advantage

Go has `govulncheck`, which proves whether a vulnerable dependency *function* is
actually called. Prefer it over version-range matching — it removes most
dependency false positives outright.
