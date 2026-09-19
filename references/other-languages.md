# PHP, Ruby, C#, C/C++ — sink reference

Concise per-language depth. Read the section you need.

## PHP

- **Code**: `eval`, `assert($userString)`, `create_function`,
  `preg_replace('/.../e', ...)` (the `e` modifier executes).
- **Command**: `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`,
  backtick execution with interpolation.
- **File inclusion (LFI/RFI)**: `include` / `require($userVar)`,
  `file_get_contents($_GET[...])`, `phar://` deserialization.
- **Object injection**: `unserialize($userInput)` (CWE-502) — a magic-method
  gadget chain turns it into RCE.
- **SQL**: `mysql_query` / `mysqli_query` / `->query("..." . $v)`. PDO prepared
  statements are the fix.
- **XSS**: `echo $_GET[...]` without `htmlspecialchars`.
- **Other**: `extract($_REQUEST)` and variable variables enabling arbitrary
  variable overwrite; `move_uploaded_file` without type and extension
  validation; `md5` / `sha1` for passwords (use `password_hash`).
- **Frameworks**: Laravel `APP_DEBUG=true`, mass assignment via unguarded
  models, Blade raw output; WordPress nonce and capability checks.

## Ruby

- **Code**: `eval`, `instance_eval`, `class_eval`, `send` / `public_send` with a
  user-supplied method name, `constantize` on user input.
- **Command**: `system`, `exec`, backtick execution, `IO.popen`, `Open3` with
  interpolation.
- **Deserialization**: `Marshal.load`, `YAML.load` / `unsafe_load`
  (`safe_load` is safe), `Oj.load` in compat mode.
- **SQL (Rails)**: string conditions in `where` / `order` / `group` / `joins`
  with interpolation; `find_by_sql`. Hash conditions and `?` placeholders are
  safe.
- **Mass assignment**: `params.permit!`, `attr_accessible` without strong
  parameters.
- **XSS**: `.html_safe`, `raw()` on user data.

## C#

- **Deserialization**: `BinaryFormatter` (deprecated and dangerous),
  `LosFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, JSON.NET
  with `TypeNameHandling.All/Objects/Auto` (CWE-502).
- **SQL**: `new SqlCommand("..." + v)`, `CommandText` concatenation,
  `FromSqlRaw` interpolation. Parameterise with `SqlParameter`.
- **XSS/validation**: `Html.Raw`, `Response.Write`, `[AllowHtml]`,
  `ValidateInput(false)`.
- **TLS**: `ServerCertificateValidationCallback` returning `true`;
  `DangerousAcceptAnyServerCertificateValidator`.
- **Crypto**: `MD5` / `SHA1` / `DES` / `TripleDES` for security; `CipherMode.ECB`;
  `new Random()` for tokens (use `RandomNumberGenerator`).
- **XXE**: `XmlDocument` / `XmlTextReader` with `DtdProcessing.Parse` and a
  resolver.

## C / C++

Memory safety is the domain here — report these only in memory-unsafe code (see
false-positives §11):

- **Buffer overflow**: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`,
  unbounded `scanf` (CWE-120/787). The `n` variants help but `strncpy` still
  mis-terminates.
- **Format string**: `printf(userString)` — a non-literal format argument
  (CWE-134).
- **Command**: `system`, `popen`, the `exec*` family with built strings.
- **Integer overflow** feeding `malloc` / `alloca` size arithmetic (CWE-190),
  leading to an undersized allocation and a heap overflow.
- **Use-after-free / double-free**: `free` then dereference; unclear ownership
  across functions (CWE-416).
- **PRNG**: `rand` / `random` for security-relevant values (CWE-338).
- Prefer AddressSanitizer and a fuzzer for confirmation. Static reasoning about C
  aliasing is error-prone, so lean toward `needs-validation` when you cannot
  trace a lifetime precisely.
