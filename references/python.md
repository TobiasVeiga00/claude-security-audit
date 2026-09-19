# Python — sink reference

Depth beyond the signal database. Read when auditing Python.

## Injection

- **Code**: `eval`, `exec`, `compile`, `__import__` with any influenced input.
- **Command**: `os.system`, `os.popen`, `subprocess.*(..., shell=True)`,
  `commands.getoutput`. `subprocess.run(['cmd', arg])` with a list and no
  `shell=True` is safe — confirm which form is used.
- **SQL**: `cursor.execute("... %s" % v)`, `execute(f"... {v}")`, or
  `execute("..." + v)`. The safe form is `execute("... %s", (v,))` — a
  parameter tuple, not string formatting. Django `.raw()` and `.extra()`, and
  `RawSQL` in `annotate`.
- **SSTI**: `render_template_string(user)`, `Template(user).render()`,
  `jinja2.Template(user)`, or Jinja2 with `autoescape=False`.

## Deserialization

`pickle.load`/`loads`, `cPickle`, `marshal.loads`, `dill.loads`, `shelve.open`,
`yaml.load` **without** `SafeLoader` (`yaml.safe_load` is safe), `jsonpickle`.
Any of these on attacker-influenced bytes is RCE (CWE-502).

## TLS and crypto

- `verify=False` on `requests`; `ssl._create_unverified_context`; `CERT_NONE`;
  `check_hostname=False`.
- `hashlib.md5`/`sha1` for passwords or signatures (fine for cache keys — see
  false-positives §14); `Crypto.Cipher.DES/ARC4`; `MODE_ECB`; `random.*` for
  security values (use `secrets`).

## Web-framework specifics

- **Django**: `DEBUG=True` in production; `ALLOWED_HOSTS=['*']`; a `SECRET_KEY`
  literal in settings; `mark_safe` / `|safe` on user data; `@csrf_exempt`;
  `.extra()` / `.raw()` SQL.
- **Flask**: `app.run(debug=True)` (the Werkzeug debugger is RCE if reachable);
  an unintentional `host='0.0.0.0'`; `render_template_string`; a hardcoded
  `SECRET_KEY`; `send_file` with a user path.
- **FastAPI**: dependency-based auth actually applied to every route; response
  models that leak fields; `Depends` ordering.

## Gotchas unique to Python

- **`assert` for security** — stripped under `python -O`. `assert user.is_admin`
  is not an access-control check in an optimised build (CWE-617).
- **XXE**: `xml.etree`, `xml.dom`, `xml.sax`, `lxml` with
  `resolve_entities=True`. Use `defusedxml`.
- **Archive traversal**: `tarfile`/`zipfile` `extractall` without a member-path
  check ("Zip Slip").
- **Billion laughs** via YAML/XML entity expansion for resource exhaustion.
- A `subprocess` call with `shell=True` hidden inside a helper — grep for the
  helper, not just direct call sites.
