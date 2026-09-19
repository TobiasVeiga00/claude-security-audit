/**
 * The signal database.
 *
 * This file is the reason the audit is cheap. Instead of asking a model to read
 * a repository, a single deterministic pass ranks the attack surface with these
 * signals and hands the model a short list of places that actually matter.
 *
 * Every signal is deliberately *high-recall, low-precision*: its job is to say
 * "look here", never "this is a vulnerability". Confirmation is the model's job,
 * and a finding is only ever raised after the surrounding code is read.
 *
 * Weights are on an open scale; only their relative size matters.
 */

/* ------------------------------------------------------------------ *
 * Language detection
 * ------------------------------------------------------------------ */

export const LANG_BY_EXT = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.vue': 'javascript', '.svelte': 'javascript', '.astro': 'javascript',
  '.py': 'python', '.pyi': 'python',
  '.rb': 'ruby', '.erb': 'ruby', '.rake': 'ruby',
  '.php': 'php', '.phtml': 'php',
  '.java': 'java', '.jsp': 'java', '.jspx': 'java',
  '.kt': 'kotlin', '.kts': 'kotlin',
  '.scala': 'scala', '.groovy': 'groovy',
  '.go': 'go',
  '.rs': 'rust',
  '.cs': 'csharp', '.cshtml': 'csharp', '.razor': 'csharp', '.vb': 'csharp',
  '.c': 'c', '.h': 'c',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hh': 'cpp',
  '.m': 'objc', '.mm': 'objc',
  '.swift': 'swift',
  '.dart': 'dart',
  '.ex': 'elixir', '.exs': 'elixir',
  '.pl': 'perl', '.pm': 'perl',
  '.lua': 'lua',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.ps1': 'powershell',
  '.sql': 'sql',
  '.tf': 'terraform', '.tfvars': 'terraform', '.hcl': 'terraform',
  '.yml': 'yaml', '.yaml': 'yaml',
  '.json': 'json', '.jsonc': 'json',
  '.toml': 'toml', '.ini': 'ini', '.cfg': 'ini', '.conf': 'conf', '.properties': 'ini',
  '.xml': 'xml', '.plist': 'xml', '.gradle': 'groovy',
  '.html': 'html', '.htm': 'html', '.hbs': 'html', '.ejs': 'html', '.njk': 'html',
  '.tpl': 'html', '.twig': 'html', '.jinja': 'html', '.jinja2': 'html',
  '.env': 'dotenv',
  '.md': 'markdown', '.mdx': 'markdown',
  '.sol': 'solidity',
};

/* ------------------------------------------------------------------ *
 * Path signals - what a file is, judged by where it lives
 * ------------------------------------------------------------------ */

export const PATH_SIGNALS = [
  // Trust boundaries: every audit starts here.
  { id: 'auth', re: /(^|[\/_.-])(auth|authn|authz|login|signin|sign-in|logout|session|oauth|oidc|saml|sso|jwt|token|passport|identity|principal)([\/_.-]|$)/i, weight: 30, tags: ['authn', 'trust-boundary'] },
  { id: 'access-control', re: /(^|[\/_.-])(permission|role|rbac|abac|acl|policy|policies|guard|authorize|privilege|tenant)([\/_.-]|$)/i, weight: 28, tags: ['authz', 'trust-boundary'] },
  { id: 'crypto', re: /(^|[\/_.-])(crypto|cipher|encrypt|decrypt|hash|signature|sign|keystore|keychain|secret|vault|kms|hsm|password|passwd|credential)([\/_.-]|$)/i, weight: 26, tags: ['crypto'] },
  { id: 'entrypoint', re: /(^|[\/_.-])(route|routes|router|controller|controllers|handler|handlers|endpoint|api|rest|graphql|resolver|resolvers|rpc|grpc|webhook|lambda|function)([\/_.-]|$)/i, weight: 24, tags: ['entrypoint', 'attack-surface'] },
  { id: 'middleware', re: /(^|[\/_.-])(middleware|interceptor|filter|filters|pipeline|hooks?)([\/_.-]|$)/i, weight: 20, tags: ['entrypoint'] },
  { id: 'input', re: /(^|[\/_.-])(upload|uploads|import|parser|parse|deserialize|unmarshal|decode|multipart|form|forms|validator|validation|sanitiz\w*)([\/_.-]|$)/i, weight: 22, tags: ['input'] },
  { id: 'data-access', re: /(^|[\/_.-])(db|database|repository|repositories|dao|model|models|entity|entities|query|queries|orm|migration|migrations|schema)([\/_.-]|$)/i, weight: 16, tags: ['data'] },
  { id: 'money', re: /(^|[\/_.-])(payment|payments|billing|invoice|checkout|charge|stripe|paypal|subscription|wallet|transfer|transaction)([\/_.-]|$)/i, weight: 26, tags: ['financial', 'high-value'] },
  { id: 'admin', re: /(^|[\/_.-])(admin|superuser|root|internal|debug|dev-?tools?|backdoor|impersonat\w*)([\/_.-]|$)/i, weight: 24, tags: ['privileged'] },
  { id: 'pii', re: /(^|[\/_.-])(user|users|account|accounts|profile|customer|patient|employee|member|contact|address|ssn|dob)([\/_.-]|$)/i, weight: 12, tags: ['pii'] },
  { id: 'network', re: /(^|[\/_.-])(http|client|fetch|request|axios|proxy|cors|socket|websocket|ws|tls|ssl|cert)([\/_.-]|$)/i, weight: 14, tags: ['network'] },
  { id: 'config', re: /(^|[\/_.-])(config|configuration|settings?|environment|env|secrets?|credentials?)([\/_.-]|$)/i, weight: 18, tags: ['config'] },
  { id: 'infra', re: /(^|[\/])(terraform|tf|infra|infrastructure|deploy|deployment|k8s|kubernetes|helm|charts?|ansible|pulumi|cdk|cloudformation)([\/_.-]|$)/i, weight: 18, tags: ['iac'] },
  { id: 'ci', re: /(^|[\/])\.(github|gitlab|circleci|azure-pipelines|drone|woodpecker)([\/_.-]|$)/i, weight: 20, tags: ['ci', 'supply-chain'] },

  // Negative signals: places where a finding is usually noise.
  { id: 'test', re: /(^|[\/_.-])(test|tests|spec|specs|__tests__|__mocks__|fixture|fixtures|e2e|cypress|playwright|testdata|mock|mocks|stub|stubs)([\/_.-]|$)/i, weight: -26, tags: ['test'] },
  { id: 'example', re: /(^|[\/_.-])(example|examples|sample|samples|demo|demos|playground|scratch|sandbox|tutorial)([\/_.-]|$)/i, weight: -20, tags: ['example'] },
  { id: 'docs', re: /(^|[\/_.-])(doc|docs|documentation|changelog|readme|license|contributing)([\/_.-]|$)/i, weight: -22, tags: ['docs'] },
  { id: 'generated', re: /(^|[\/_.-])(generated|autogen|third[_-]?party)([\/_.-]|$)|(\.pb\.|_pb2|\.g\.|\.min\.)|(^|\/)(vendor|node_modules)\/|[_.-]bundle\.|migrations?\/\d/i, weight: -24, tags: ['generated'] },
  { id: 'i18n', re: /(^|[\/_.-])(locale|locales|i18n|l10n|translation|translations|lang)([\/_.-]|$)/i, weight: -16, tags: ['i18n'] },
];

/* ------------------------------------------------------------------ *
 * Sink signals - dangerous constructs, by language
 * ------------------------------------------------------------------ *
 * `cwe` records the weakness class the construct *can* produce. It is a
 * hypothesis attached to a location, never a verdict.
 */

export const SINK_SIGNALS = {
  javascript: [
    { id: 'js.eval', re: /\beval\s*\(|new\s+Function\s*\(|\bvm\.(runIn\w+|compileFunction)\s*\(/, weight: 34, cwe: 'CWE-95', hint: 'dynamic code execution' },
    { id: 'js.exec', re: /child_process\.(exec|execSync|spawn|spawnSync|execFile)\s*\(|\brequire\(['"]child_process['"]\)/, weight: 32, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'js.dom-xss', re: /\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|\.insertAdjacentHTML\s*\(|\$\s*\(\s*[^)]*\)\.html\s*\(/, weight: 28, cwe: 'CWE-79', hint: 'DOM sink for XSS' },
    { id: 'js.sqli', re: /\.(query|raw|execute)\s*\(\s*[`'"][^`'"\n]{0,300}(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^`'"\n]{0,300}[`'"]\s*\+|\.(query|raw)\s*\(\s*`[^`\n]{0,300}\$\{/i, weight: 34, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'js.nosqli', re: /\$where\s*:|\.find\s*\(\s*\{[^}]*req\.(body|query|params)/, weight: 26, cwe: 'CWE-943', hint: 'NoSQL operator injection' },
    { id: 'js.path-traversal', re: /fs\.(readFile|readFileSync|createReadStream|writeFile|unlink)\s*\(\s*(?!['"`])[^,)]*(req|request|params|query|body|input|user)/i, weight: 28, cwe: 'CWE-22', hint: 'user-controlled filesystem path' },
    { id: 'js.deserialize', re: /node-serialize|serialize-javascript|\bunserialize\s*\(|js-yaml.*load\s*\((?!.*JSON_SCHEMA)/, weight: 30, cwe: 'CWE-502', hint: 'unsafe deserialization' },
    { id: 'js.weak-crypto', re: /createCipher\s*\(|['"](md5|sha1|des|rc4|des-ede3)['"]|Math\.random\s*\(\)[^;]*\b(token|secret|key|nonce|otp|password|session|id)\b/i, weight: 24, cwe: 'CWE-327', hint: 'weak or misused cryptography' },
    { id: 'js.jwt', re: /jwt\.decode\s*\((?![^)]*verify)|algorithms\s*:\s*\[\s*['"]none['"]|ignoreExpiration\s*:\s*true|jwt\.verify\s*\([^,]+,\s*['"][^'"]{0,15}['"]/, weight: 32, cwe: 'CWE-347', hint: 'JWT verification weakness' },
    { id: 'js.tls', re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|strictSSL\s*:\s*false|checkServerIdentity\s*:\s*\(\s*\)\s*=>/, weight: 30, cwe: 'CWE-295', hint: 'TLS verification disabled' },
    { id: 'js.cors', re: /origin\s*:\s*(true|['"]\*['"]|function)[\s\S]{0,120}credentials\s*:\s*true|credentials\s*:\s*true[\s\S]{0,120}origin\s*:\s*(true|['"]\*['"])/, weight: 26, cwe: 'CWE-942', hint: 'permissive CORS with credentials' },
    { id: 'js.proto-pollution', re: /__proto__|\bconstructor\s*\[\s*['"]prototype|Object\.assign\s*\(\s*\{\}\s*,\s*(req\.|JSON\.parse)/, weight: 24, cwe: 'CWE-1321', hint: 'prototype pollution' },
    { id: 'js.ssrf', re: /(axios|fetch|got|request|http\.get|https\.get|undici)\s*(\.\w+)?\s*\(\s*(?!['"`])[^,)]*(req\.|request\.|params|query|body|userUrl|targetUrl)/i, weight: 28, cwe: 'CWE-918', hint: 'user-controlled outbound request' },
    { id: 'js.redos', re: /new\s+RegExp\s*\(\s*(?!['"`])[^,)]*(req\.|input|user)/i, weight: 20, cwe: 'CWE-1333', hint: 'user-controlled regular expression' },
    { id: 'js.open-redirect', re: /\.redirect\s*\(\s*(?!['"`])[^,)]*(req\.|query|params|body|returnUrl|next)/i, weight: 22, cwe: 'CWE-601', hint: 'user-controlled redirect target' },
    { id: 'js.dyn-require', re: /\brequire\s*\(\s*(?!['"`])[A-Za-z_$][\w$.]*\s*\)|\bimport\s*\(\s*(?!['"`])[A-Za-z_$]/, weight: 22, cwe: 'CWE-470', hint: 'dynamic module load' },
  ],

  python: [
    { id: 'py.eval', re: /(?<![\w.])(eval|exec|compile)\s*\(|(?<![\w.])__import__\s*\(/, weight: 34, cwe: 'CWE-95', hint: 'dynamic code execution' },
    { id: 'py.shell', re: /os\.(system|popen|spawn\w*)\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|commands\.(getoutput|getstatusoutput)/, weight: 34, cwe: 'CWE-78', hint: 'shell command execution' },
    { id: 'py.pickle', re: /\bpickle\.loads?\s*\(|\bcPickle\.|\bmarshal\.loads?\s*\(|\bdill\.loads?\s*\(|\bshelve\.open\s*\(/, weight: 34, cwe: 'CWE-502', hint: 'unsafe deserialization' },
    { id: 'py.yaml', re: /yaml\.load\s*\((?![^)]*(SafeLoader|CSafeLoader|Loader\s*=\s*yaml\.Safe))/, weight: 30, cwe: 'CWE-502', hint: 'yaml.load without SafeLoader' },
    { id: 'py.sqli', re: /(execute|executemany|raw|extra)\s*\(\s*[f]?['"][^'"\n]{0,300}(SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'"\n]{0,300}['"]\s*%|(execute|raw)\s*\(\s*f['"][^'"\n]{0,300}\{|(execute|raw)\s*\([^)\n]{0,200}\+\s*\w+/i, weight: 34, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'py.ssti', re: /render_template_string\s*\(|Template\s*\([^)]*(request|user|input)|jinja2\.Template\s*\(/, weight: 30, cwe: 'CWE-1336', hint: 'server-side template injection' },
    { id: 'py.tls', re: /verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE|check_hostname\s*=\s*False/, weight: 30, cwe: 'CWE-295', hint: 'TLS verification disabled' },
    { id: 'py.weak-crypto', re: /hashlib\.(md5|sha1)\s*\(|Crypto\.Cipher\.(DES|ARC4|XOR)|mode\s*=\s*\w+\.MODE_ECB|\brandom\.(random|randint|choice)\s*\([^)]*\)[^\n]*\b(token|secret|key|password|otp)/i, weight: 24, cwe: 'CWE-327', hint: 'weak or misused cryptography' },
    { id: 'py.path-traversal', re: /open\s*\(\s*(?!['"])[^,)]*(request\.|args\.|form\.|params|user_input|filename)/i, weight: 28, cwe: 'CWE-22', hint: 'user-controlled filesystem path' },
    { id: 'py.ssrf', re: /requests\.(get|post|put|head)\s*\(\s*(?!['"])[^,)]*(request\.|args\.|url_param|user)/i, weight: 28, cwe: 'CWE-918', hint: 'user-controlled outbound request' },
    { id: 'py.xxe', re: /etree\.(parse|fromstring)\s*\(|xml\.(dom|sax)\.|xmlrpc\.|resolve_entities\s*=\s*True/, weight: 24, cwe: 'CWE-611', hint: 'XML parsing without entity hardening' },
    { id: 'py.django-debug', re: /DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]|SECRET_KEY\s*=\s*['"][^'"]+['"]/, weight: 26, cwe: 'CWE-489', hint: 'insecure Django settings' },
    { id: 'py.assert-auth', re: /^\s*assert\s+.*(is_auth|permission|role|is_admin|has_perm)/im, weight: 26, cwe: 'CWE-617', hint: 'assert used for access control (stripped under -O)' },
    { id: 'py.flask-debug', re: /app\.run\s*\([^)]*debug\s*=\s*True|host\s*=\s*['"]0\.0\.0\.0['"]/, weight: 22, cwe: 'CWE-489', hint: 'debug server exposed' },
  ],

  java: [
    { id: 'java.exec', re: /Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(/, weight: 32, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'java.deserialize', re: /new\s+ObjectInputStream\s*\(|readObject\s*\(\s*\)|XMLDecoder\s*\(|enableDefaultTyping|activateDefaultTyping|TypeNameHandling/, weight: 36, cwe: 'CWE-502', hint: 'unsafe deserialization' },
    { id: 'java.sqli', re: /(createStatement\s*\(\s*\)[\s\S]{0,200}execute\w*\s*\(\s*['"][\s\S]*?\+)|(executeQuery|executeUpdate)\s*\(\s*['"][^'"]*['"]\s*\+|String\.format\s*\(\s*['"][^'"]*(SELECT|INSERT|UPDATE|DELETE)/i, weight: 34, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'java.xxe', re: /DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.newInstance|TransformerFactory\.newInstance|SAXReader\s*\(/, weight: 26, cwe: 'CWE-611', hint: 'XML factory requires XXE hardening' },
    { id: 'java.weak-crypto', re: /Cipher\.getInstance\s*\(\s*['"](DES|DESede|RC2|RC4|AES\/ECB|Blowfish)|MessageDigest\.getInstance\s*\(\s*['"](MD5|MD2|SHA-?1)|new\s+Random\s*\(|SecureRandom\.getInstance\s*\(\s*['"]SHA1PRNG/, weight: 26, cwe: 'CWE-327', hint: 'weak or misused cryptography' },
    { id: 'java.tls', re: /TrustAllCerts|X509TrustManager\s*\(\s*\)\s*\{[\s\S]{0,300}\}\s*;|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\s*\(\s*\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true/, weight: 32, cwe: 'CWE-295', hint: 'TLS trust manager accepts everything' },
    { id: 'java.ldap', re: /new\s+InitialDirContext|search\s*\(\s*['"][^'"]*['"]\s*\+|new\s+SearchControls/, weight: 24, cwe: 'CWE-90', hint: 'LDAP query construction' },
    { id: 'java.el', re: /ExpressionParser|SpelExpressionParser|OgnlContext|MVEL\.eval|ScriptEngineManager/, weight: 30, cwe: 'CWE-917', hint: 'expression language evaluation' },
    { id: 'java.path-traversal', re: /new\s+File\s*\(\s*(?!['"])[^,)]*(request\.|getParameter|param|userInput|filename)/i, weight: 28, cwe: 'CWE-22', hint: 'user-controlled filesystem path' },
    { id: 'java.cors', re: /@CrossOrigin\s*\(\s*origins\s*=\s*['"]\*['"]|setAllowedOrigins\s*\(\s*(Arrays\.asList\s*\(\s*)?['"]\*['"]|addAllowedOrigin\s*\(\s*['"]\*['"]/, weight: 24, cwe: 'CWE-942', hint: 'wildcard CORS' },
    { id: 'java.ssrf', re: /new\s+URL\s*\(\s*(?!['"])[^,)]*(request\.|getParameter|param)|HttpClient[\s\S]{0,80}(request\.|getParameter)/i, weight: 26, cwe: 'CWE-918', hint: 'user-controlled outbound request' },
  ],

  php: [
    { id: 'php.eval', re: /\beval\s*\(|\bassert\s*\(\s*\$|create_function\s*\(|preg_replace\s*\(\s*['"][^'"]*\/[a-z]*e[a-z]*['"]/i, weight: 36, cwe: 'CWE-95', hint: 'dynamic code execution' },
    { id: 'php.exec', re: /\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$/, weight: 36, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'php.deserialize', re: /\bunserialize\s*\(|\bphar:\/\//, weight: 34, cwe: 'CWE-502', hint: 'PHP object injection' },
    { id: 'php.lfi', re: /\b(include|include_once|require|require_once)\s*\(?\s*\$|file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/, weight: 34, cwe: 'CWE-98', hint: 'file inclusion from variable' },
    { id: 'php.sqli', re: /(mysql_query|mysqli_query|->query|->exec)\s*\(\s*['"][^'"]*['"]\s*\.|\$_(GET|POST|REQUEST)\[[^\]]*\][^;]*(SELECT|INSERT|UPDATE|DELETE)/i, weight: 34, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'php.xss', re: /echo\s+\$_(GET|POST|REQUEST|COOKIE)|print\s+\$_(GET|POST|REQUEST)|<\?=\s*\$_(GET|POST)/, weight: 30, cwe: 'CWE-79', hint: 'unescaped output of request data' },
    { id: 'php.upload', re: /move_uploaded_file\s*\(|\$_FILES\[/, weight: 26, cwe: 'CWE-434', hint: 'file upload handling' },
    { id: 'php.varvar', re: /\bextract\s*\(|\$\$[A-Za-z_]/, weight: 26, cwe: 'CWE-621', hint: 'variable variables / extract()' },
    { id: 'php.weak-crypto', re: /\b(md5|sha1|crypt)\s*\(\s*\$(pass|pwd|password)|mcrypt_|MCRYPT_MODE_ECB|\brand\s*\(|\bmt_rand\s*\(/i, weight: 24, cwe: 'CWE-327', hint: 'weak password hashing or PRNG' },
  ],

  go: [
    { id: 'go.exec', re: /exec\.Command\s*\(|exec\.CommandContext\s*\(|syscall\.Exec\s*\(/, weight: 30, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'go.sqli', re: /(Query|Exec|QueryRow)\s*\(\s*(fmt\.Sprintf|['"][^'"]*['"]\s*\+)/, weight: 34, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'go.tls', re: /InsecureSkipVerify\s*:\s*true|tls\.Config\{[^}]*MinVersion\s*:\s*tls\.VersionTLS10/, weight: 32, cwe: 'CWE-295', hint: 'TLS verification disabled or weak floor' },
    { id: 'go.template', re: /template\.HTML\s*\(|template\.JS\s*\(|template\.URL\s*\(/, weight: 26, cwe: 'CWE-79', hint: 'escaping bypass in html/template' },
    { id: 'go.weak-crypto', re: /crypto\/(md5|sha1|des|rc4)|math\/rand|des\.NewCipher|ECB/, weight: 24, cwe: 'CWE-327', hint: 'weak cryptography or non-CSPRNG' },
    { id: 'go.path-traversal', re: /(os\.Open|os\.ReadFile|ioutil\.ReadFile|http\.ServeFile)\s*\([^)]*(r\.URL|r\.FormValue|vars\[|c\.Param)/, weight: 28, cwe: 'CWE-22', hint: 'user-controlled filesystem path' },
    { id: 'go.ssrf', re: /http\.(Get|Post|Head)\s*\(\s*(?!['"])[^,)]*(r\.|req\.|param|userURL)/i, weight: 26, cwe: 'CWE-918', hint: 'user-controlled outbound request' },
    { id: 'go.error-ignored', re: /(?:^|[,(\s])_\s*(?:,\s*\w+\s*)?:?=\s*[\w.]+\.(Verify|Validate|Check|Authenticate|Authorize)\s*\(/m, weight: 24, cwe: 'CWE-252', hint: 'security check result discarded' },
  ],

  ruby: [
    { id: 'rb.eval', re: /\b(eval|instance_eval|class_eval|module_eval)\s*[\s(]|\bsend\s*\(\s*params|\bconstantize\b|\bpublic_send\s*\(\s*params/, weight: 34, cwe: 'CWE-95', hint: 'dynamic code execution' },
    { id: 'rb.exec', re: /\b(system|exec|spawn)\s*\(|`[^`]*#\{|%x\{|IO\.popen\s*\(|Open3\./, weight: 32, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'rb.deserialize', re: /Marshal\.load|YAML\.(load|unsafe_load)\s*\((?![^)]*safe)|Oj\.load/, weight: 32, cwe: 'CWE-502', hint: 'unsafe deserialization' },
    { id: 'rb.sqli', re: /(where|find_by_sql|execute|order|group|having|joins|select)\s*\(\s*["'][^"'\n]{0,300}#\{|["'][^"'\n]{0,200}#\{[^}\n]{0,100}\}[^"'\n]{0,100}["']\s*\)\s*(?=[\s.;])/i, weight: 32, cwe: 'CWE-89', hint: 'interpolated SQL fragment' },
    { id: 'rb.mass-assign', re: /params\.permit!|attr_accessible|without_protection\s*:\s*true/, weight: 26, cwe: 'CWE-915', hint: 'unrestricted mass assignment' },
    { id: 'rb.xss', re: /\.html_safe\b|raw\s*\(|<%==/, weight: 26, cwe: 'CWE-79', hint: 'escaping bypass' },
  ],

  csharp: [
    { id: 'cs.exec', re: /Process\.Start\s*\(|ProcessStartInfo\s*\{/, weight: 30, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'cs.deserialize', re: /BinaryFormatter|LosFormatter|NetDataContractSerializer|ObjectStateFormatter|JavaScriptSerializer[\s\S]{0,80}SimpleTypeResolver|TypeNameHandling\s*[=.]\s*(TypeNameHandling\.)?(All|Objects|Auto)/, weight: 36, cwe: 'CWE-502', hint: 'unsafe deserialization' },
    { id: 'cs.sqli', re: /new\s+SqlCommand\s*\(\s*(['"][^'"]*['"]\s*\+|\$['"])|CommandText\s*=\s*(['"][^'"]*['"]\s*\+|\$['"])|FromSqlRaw\s*\(\s*\$?['"][^'"]*\{/, weight: 34, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'cs.xss', re: /Html\.Raw\s*\(|Response\.Write\s*\(|\[AllowHtml\]|ValidateInput\s*\(\s*false\s*\)/, weight: 26, cwe: 'CWE-79', hint: 'escaping bypass or validation disabled' },
    { id: 'cs.tls', re: /ServerCertificateValidationCallback\s*[+]?=\s*[^;]*true|DangerousAcceptAnyServerCertificateValidator|CheckCertificateRevocationList\s*=\s*false/, weight: 32, cwe: 'CWE-295', hint: 'TLS validation disabled' },
    { id: 'cs.weak-crypto', re: /new\s+(MD5|SHA1|DES|TripleDES|RC2)CryptoServiceProvider|MD5\.Create|SHA1\.Create|CipherMode\.ECB|new\s+Random\s*\(/, weight: 26, cwe: 'CWE-327', hint: 'weak cryptography or non-CSPRNG' },
    { id: 'cs.xxe', re: /XmlDocument\s*\(\s*\)|XmlTextReader|DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new/, weight: 26, cwe: 'CWE-611', hint: 'XML parsing without entity hardening' },
    { id: 'cs.path-traversal', re: /(File\.(ReadAll\w+|Open\w*|WriteAll\w+)|Path\.Combine)\s*\([^)]*(Request\.|Query\[|Form\[)/, weight: 28, cwe: 'CWE-22', hint: 'user-controlled filesystem path' },
  ],

  c: [
    { id: 'c.overflow', re: /\b(strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|realpath|getwd)\s*\(/, weight: 34, cwe: 'CWE-120', hint: 'unbounded buffer operation' },
    { id: 'c.format-string', re: /\b(printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?!["'])[A-Za-z_]\w*\s*\)/, weight: 32, cwe: 'CWE-134', hint: 'non-literal format string' },
    { id: 'c.exec', re: /\b(system|popen|execl|execlp|execv|execvp)\s*\(/, weight: 32, cwe: 'CWE-78', hint: 'OS command execution' },
    { id: 'c.memory', re: /\b(?:alloca|memcpy|memmove|strncpy|strncat)\s*\(|\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)[\s\S]{0,80}\b\1\b/, weight: 24, cwe: 'CWE-787', hint: 'manual memory operation to review' },
    { id: 'c.int-overflow', re: /\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)|\balloca\s*\(\s*\w+/, weight: 24, cwe: 'CWE-190', hint: 'allocation size arithmetic' },
    { id: 'c.random', re: /\b(rand|srand|random)\s*\(/, weight: 18, cwe: 'CWE-338', hint: 'non-cryptographic PRNG' },
  ],

  kotlin: [
    { id: 'kt.webview', re: /setJavaScriptEnabled\s*\(\s*true\s*\)|addJavascriptInterface\s*\(|setAllowFileAccess\s*\(\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true|loadDataWithBaseURL/, weight: 32, cwe: 'CWE-749', hint: 'WebView exposed to untrusted content' },
    { id: 'kt.storage', re: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorage|SharedPreferences[\s\S]{0,120}(token|password|secret|key)/i, weight: 30, cwe: 'CWE-922', hint: 'sensitive data in insecure storage' },
    { id: 'kt.tls', re: /TrustManager\s*\([\s\S]{0,300}checkServerTrusted[\s\S]{0,120}\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier\s*\{\s*_?,?\s*_?\s*->\s*true/, weight: 34, cwe: 'CWE-295', hint: 'certificate validation disabled' },
    { id: 'kt.sqli', re: /rawQuery\s*\(\s*['"][^'"]*['"]\s*\+|execSQL\s*\(\s*['"][^'"]*['"]\s*\+|rawQuery\s*\(\s*"[^"]*\$\{/, weight: 32, cwe: 'CWE-89', hint: 'string-built SQL' },
    { id: 'kt.log', re: /Log\.[dveiw]\s*\([^)]*(token|password|secret|key|session|pin|otp|jwt)/i, weight: 24, cwe: 'CWE-532', hint: 'secret written to system log' },
    { id: 'kt.crypto', re: /Cipher\.getInstance\s*\(\s*['"](AES\/ECB|DES|RC4|AES(?!\/))|IvParameterSpec\s*\(\s*['"]|SecureRandom\s*\(\s*['"]/, weight: 28, cwe: 'CWE-327', hint: 'weak or misconfigured cipher' },
    { id: 'kt.intent', re: /getIntent\s*\(\s*\)\.get\w*Extra|PendingIntent\.getActivity\s*\([^)]*FLAG_MUTABLE|Intent\s*\(\s*\)\.setPackage\s*\(\s*null/, weight: 22, cwe: 'CWE-926', hint: 'untrusted or mutable intent data' },
  ],

  swift: [
    { id: 'sw.storage', re: /UserDefaults[\s\S]{0,120}(token|password|secret|apiKey|credential)|NSUserDefaults[\s\S]{0,80}set\w*\(/i, weight: 30, cwe: 'CWE-922', hint: 'sensitive data in UserDefaults' },
    { id: 'sw.keychain', re: /kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock(?!ThisDeviceOnly)/, weight: 28, cwe: 'CWE-922', hint: 'weak keychain accessibility class' },
    { id: 'sw.tls', re: /NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|serverTrust[\s\S]{0,200}\.useCredential|URLSession[\s\S]{0,200}didReceive\s+challenge[\s\S]{0,200}\.useCredential/, weight: 34, cwe: 'CWE-295', hint: 'ATS disabled or trust callback bypass' },
    { id: 'sw.webview', re: /UIWebView|evaluateJavaScript\s*\(|WKUserContentController[\s\S]{0,80}add\s*\(/, weight: 26, cwe: 'CWE-749', hint: 'WebView bridge or deprecated UIWebView' },
    { id: 'sw.crypto', re: /CCCrypt\s*\(|kCCAlgorithmDES|kCCOptionECBMode|arc4random(?!_uniform)|String\(\s*Int\.random/, weight: 26, cwe: 'CWE-327', hint: 'weak cryptography' },
    { id: 'sw.log', re: /print\s*\([^)]*(token|password|secret|key)|NSLog\s*\([^)]*(token|password|secret)/i, weight: 22, cwe: 'CWE-532', hint: 'secret written to log' },
  ],

  terraform: [
    { id: 'tf.open-ingress', re: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[\s*"::\/0"|source_ranges\s*=\s*\[\s*"0\.0\.0\.0\/0"/, weight: 34, cwe: 'CWE-284', hint: 'network open to the internet' },
    { id: 'tf.public-bucket', re: /acl\s*=\s*"public-read|block_public_acls\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false/, weight: 34, cwe: 'CWE-732', hint: 'publicly readable object storage' },
    { id: 'tf.iam-wildcard', re: /"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]|"Resource"\s*:\s*"\*"|"Principal"\s*:\s*"\*"/, weight: 32, cwe: 'CWE-269', hint: 'wildcard IAM permission' },
    { id: 'tf.unencrypted', re: /encrypted\s*=\s*false|storage_encrypted\s*=\s*false|enable_key_rotation\s*=\s*false|kms_key_id\s*=\s*""/, weight: 28, cwe: 'CWE-311', hint: 'encryption disabled' },
    { id: 'tf.no-logging', re: /logging\s*\{\s*\}|enable_logging\s*=\s*false|cloudwatch_logs_enabled\s*=\s*false/, weight: 20, cwe: 'CWE-778', hint: 'audit logging disabled' },
    { id: 'tf.hardcoded', re: /(access_key|secret_key|password|token)\s*=\s*"[^"$\n]{8,}"/, weight: 36, cwe: 'CWE-798', hint: 'credential literal in IaC' },
    { id: 'tf.public-db', re: /publicly_accessible\s*=\s*true|public_network_access_enabled\s*=\s*true/, weight: 34, cwe: 'CWE-284', hint: 'database reachable from the internet' },
    { id: 'tf.imdsv1', re: /http_tokens\s*=\s*"optional"/, weight: 26, cwe: 'CWE-918', hint: 'IMDSv1 left reachable (SSRF-to-credentials); require IMDSv2 http_tokens = "required"' },
  ],

  yaml: [
    { id: 'k8s.privileged', re: /privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true/, weight: 34, cwe: 'CWE-250', hint: 'container escapes the sandbox' },
    { id: 'k8s.root', re: /runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false|readOnlyRootFilesystem\s*:\s*false/, weight: 26, cwe: 'CWE-250', hint: 'container runs as root' },
    { id: 'k8s.caps', re: /add\s*:\s*\[?[^\]\n]*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)/, weight: 30, cwe: 'CWE-250', hint: 'dangerous Linux capability' },
    { id: 'k8s.secret', re: /kind\s*:\s*Secret[\s\S]{0,400}(data|stringData)\s*:/, weight: 22, cwe: 'CWE-798', hint: 'secret manifest - verify it is not committed in clear' },
    { id: 'k8s.rbac', re: /(verbs|resources|apiGroups)\s*:\s*\[?\s*["']?\*/, weight: 28, cwe: 'CWE-269', hint: 'wildcard RBAC rule' },
    { id: 'k8s.automount', re: /automountServiceAccountToken\s*:\s*true/, weight: 18, cwe: 'CWE-250', hint: 'service account token mounted by default' },
    { id: 'gha.injection', re: /\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.(title|body|head\.(ref|label))/, weight: 36, cwe: 'CWE-94', hint: 'untrusted GitHub context interpolated into a script' },
    { id: 'gha.pr-target', re: /pull_request_target[\s\S]{0,600}actions\/checkout[\s\S]{0,200}ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head/, weight: 38, cwe: 'CWE-94', hint: 'pull_request_target checking out untrusted code' },
    { id: 'gha.unpinned', re: /uses\s*:\s*[\w-]+\/[\w.-]+@(?![0-9a-f]{40}\b)[^\s]+\s*$/m, weight: 16, cwe: 'CWE-1357', hint: 'action not pinned to a commit SHA' },
    { id: 'gha.perms', re: /permissions\s*:\s*write-all|contents\s*:\s*write[\s\S]{0,200}pull_request_target/, weight: 24, cwe: 'CWE-269', hint: 'broad workflow token permissions' },
    { id: 'compose.privileged', re: /privileged\s*:\s*true|network_mode\s*:\s*['"]?host|pid\s*:\s*['"]?host|\/var\/run\/docker\.sock/, weight: 32, cwe: 'CWE-250', hint: 'container granted host-level access' },
  ],

  dockerfile: [
    { id: 'docker.root', re: /^(?!.*\bUSER\b)/s, weight: 0, cwe: 'CWE-250', hint: 'no USER directive - container runs as root' },
    { id: 'docker.latest', re: /^FROM\s+\S+:latest|^FROM\s+[^:@\s]+(?:\s+AS\s+\S+)?\s*$/im, weight: 18, cwe: 'CWE-1104', hint: 'base image not pinned' },
    { id: 'docker.add-remote', re: /^ADD\s+https?:\/\//im, weight: 24, cwe: 'CWE-494', hint: 'remote fetch without integrity check' },
    { id: 'docker.secret', re: /^(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\w*\s*=?\s*\S+/im, weight: 34, cwe: 'CWE-798', hint: 'credential baked into an image layer' },
    { id: 'docker.insecure-fetch', re: /curl\s+[^\n|]*(-k|--insecure)|wget\s+[^\n|]*--no-check-certificate|apt-get[^\n]*--allow-unauthenticated/, weight: 28, cwe: 'CWE-295', hint: 'TLS verification disabled during build' },
    { id: 'docker.sudo', re: /^RUN\s+.*\b(sudo|chmod\s+777|chmod\s+-R\s+777)\b/im, weight: 22, cwe: 'CWE-732', hint: 'over-permissive file mode or privilege use' },
    { id: 'docker.pipe-shell', re: /curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh|wget[^\n|]*\|\s*(ba)?sh/, weight: 26, cwe: 'CWE-494', hint: 'remote script piped into a shell' },
  ],
};

/* ------------------------------------------------------------------ *
 * Secret patterns
 * ------------------------------------------------------------------ *
 * High-confidence, provider-specific prefixes only. Generic "password ="
 * matching belongs in a dedicated pass with entropy scoring, not here, because
 * it drowns a report in noise.
 */

export const SECRET_PATTERNS = [
  { id: 'aws-access-key-id', re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, severity: 'critical', provider: 'AWS', cwe: 'CWE-798' },
  { id: 'aws-secret-access-key', re: /\baws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'critical', provider: 'AWS', cwe: 'CWE-798' },
  { id: 'github-pat', re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/g, severity: 'critical', provider: 'GitHub', cwe: 'CWE-798' },
  { id: 'github-fine-grained', re: /\b(github_pat_[A-Za-z0-9_]{60,})\b/g, severity: 'critical', provider: 'GitHub', cwe: 'CWE-798' },
  { id: 'gitlab-pat', re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g, severity: 'critical', provider: 'GitLab', cwe: 'CWE-798' },
  { id: 'slack-token', re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, severity: 'high', provider: 'Slack', cwe: 'CWE-798' },
  { id: 'slack-webhook', re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_+/]{8,}\/B[A-Za-z0-9_+/]{8,}\/[A-Za-z0-9_+/]{20,})/g, severity: 'high', provider: 'Slack', cwe: 'CWE-798' },
  { id: 'stripe-secret', re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g, severity: 'critical', provider: 'Stripe', cwe: 'CWE-798' },
  { id: 'google-api-key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, severity: 'high', provider: 'Google', cwe: 'CWE-798' },
  { id: 'gcp-service-account', re: /"type"\s*:\s*"service_account"[\s\S]{0,400}"private_key"\s*:\s*"-----BEGIN/g, severity: 'critical', provider: 'GCP', cwe: 'CWE-798' },
  { id: 'openai-key', re: /\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,})\b/g, severity: 'critical', provider: 'OpenAI', cwe: 'CWE-798' },
  { id: 'anthropic-key', re: /\b(sk-ant-[A-Za-z0-9_-]{24,})\b/g, severity: 'critical', provider: 'Anthropic', cwe: 'CWE-798' },
  { id: 'private-key', re: /(-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?-----)/g, severity: 'critical', provider: 'PKI', cwe: 'CWE-321' },
  { id: 'npm-token', re: /\b(npm_[A-Za-z0-9]{36})\b/g, severity: 'high', provider: 'npm', cwe: 'CWE-798' },
  { id: 'pypi-token', re: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/g, severity: 'high', provider: 'PyPI', cwe: 'CWE-798' },
  { id: 'sendgrid-key', re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g, severity: 'high', provider: 'SendGrid', cwe: 'CWE-798' },
  { id: 'twilio-key', re: /\b(SK[0-9a-fA-F]{32})\b/g, severity: 'high', provider: 'Twilio', cwe: 'CWE-798' },
  { id: 'mailgun-key', re: /\b(key-[0-9a-zA-Z]{32})\b/g, severity: 'high', provider: 'Mailgun', cwe: 'CWE-798' },
  { id: 'jwt', re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, severity: 'medium', provider: 'JWT', cwe: 'CWE-522' },
  { id: 'db-uri-credentials', re: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:\s'"]+:[^@\s'"]{3,}@[^\s'"]+)/g, severity: 'critical', provider: 'Database', cwe: 'CWE-798' },
  { id: 'azure-storage-key', re: /(AccountKey\s*=\s*[A-Za-z0-9+/]{86}==)/g, severity: 'critical', provider: 'Azure', cwe: 'CWE-798' },
  { id: 'firebase-token', re: /\b(1\/\/[A-Za-z0-9_-]{50,})\b/g, severity: 'high', provider: 'Google OAuth', cwe: 'CWE-798' },
  { id: 'hashicorp-vault', re: /\b((?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,})\b/g, severity: 'critical', provider: 'Vault', cwe: 'CWE-798' },
  { id: 'square-token', re: /\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,})\b/g, severity: 'critical', provider: 'Square', cwe: 'CWE-798' },
  { id: 'shopify-token', re: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g, severity: 'critical', provider: 'Shopify', cwe: 'CWE-798' },
  { id: 'telegram-bot', re: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b/g, severity: 'high', provider: 'Telegram', cwe: 'CWE-798' },
  { id: 'datadog-key', re: /\bdd_api_key\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/gi, severity: 'high', provider: 'Datadog', cwe: 'CWE-798' },
];

/**
 * Strings that look like secrets but are published examples. Matching one of
 * these downgrades a hit instead of dropping it, so a real key that happens to
 * resemble a sample is still surfaced for review.
 */
export const SECRET_ALLOWLIST = [
  /AKIAIOSFODNN7EXAMPLE/i,
  /wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,
  /EXAMPLE|SAMPLE|PLACEHOLDER|DUMMY|FAKE|TEST[_-]?KEY|YOUR[_-]?(API[_-]?)?KEY|XXXX+|<[^>]+>|\{\{[^}]+\}\}|\$\{[^}]+\}/i,
  /000000000000|1234567890|abcdef0123456789/i,
];

/* ------------------------------------------------------------------ *
 * Stack markers - what kind of target am I looking at?
 * ------------------------------------------------------------------ */

export const STACK_MARKERS = [
  { file: 'package.json', stack: 'node', domains: ['code', 'dependencies', 'web', 'api'] },
  { file: 'requirements.txt', stack: 'python', domains: ['code', 'dependencies'] },
  { file: 'pyproject.toml', stack: 'python', domains: ['code', 'dependencies'] },
  { file: 'Pipfile', stack: 'python', domains: ['code', 'dependencies'] },
  { file: 'go.mod', stack: 'go', domains: ['code', 'dependencies'] },
  { file: 'Cargo.toml', stack: 'rust', domains: ['code', 'dependencies'] },
  { file: 'pom.xml', stack: 'java-maven', domains: ['code', 'dependencies'] },
  { file: 'build.gradle', stack: 'java-gradle', domains: ['code', 'dependencies'] },
  { file: 'build.gradle.kts', stack: 'java-gradle', domains: ['code', 'dependencies'] },
  { file: 'composer.json', stack: 'php', domains: ['code', 'dependencies'] },
  { file: 'Gemfile', stack: 'ruby', domains: ['code', 'dependencies'] },
  { file: 'mix.exs', stack: 'elixir', domains: ['code', 'dependencies'] },
  { file: 'pubspec.yaml', stack: 'flutter', domains: ['mobile', 'dependencies'] },
  { file: 'Package.swift', stack: 'swift', domains: ['mobile', 'dependencies'] },
  { file: 'Podfile', stack: 'ios', domains: ['mobile', 'dependencies'] },
  { file: 'AndroidManifest.xml', stack: 'android', domains: ['mobile'] },
  { file: 'Info.plist', stack: 'ios', domains: ['mobile'] },
  { file: 'Dockerfile', stack: 'docker', domains: ['container'] },
  { file: 'docker-compose.yml', stack: 'docker-compose', domains: ['container', 'iac'] },
  { file: 'docker-compose.yaml', stack: 'docker-compose', domains: ['container', 'iac'] },
  { file: 'Chart.yaml', stack: 'helm', domains: ['iac', 'container'] },
  { file: 'serverless.yml', stack: 'serverless', domains: ['cloud', 'iac'] },
  { file: 'template.yaml', stack: 'sam-or-cfn', domains: ['cloud', 'iac'] },
  { file: 'main.tf', stack: 'terraform', domains: ['iac', 'cloud'] },
  { file: 'Makefile', stack: 'make', domains: ['code'] },
  { file: 'next.config.js', stack: 'nextjs', domains: ['web', 'api'] },
  { file: 'nuxt.config.ts', stack: 'nuxt', domains: ['web', 'api'] },
  { file: 'angular.json', stack: 'angular', domains: ['web'] },
  { file: 'vite.config.ts', stack: 'vite', domains: ['web'] },
  { file: 'manage.py', stack: 'django', domains: ['web', 'api'] },
  { file: 'artisan', stack: 'laravel', domains: ['web', 'api'] },
  { file: 'config.ru', stack: 'rails', domains: ['web', 'api'] },
  { file: 'nginx.conf', stack: 'nginx', domains: ['network', 'web'] },
  { file: '.env', stack: 'dotenv', domains: ['secrets'] },
  { file: 'openapi.yaml', stack: 'openapi', domains: ['api'] },
  { file: 'openapi.json', stack: 'openapi', domains: ['api'] },
  { file: 'swagger.json', stack: 'openapi', domains: ['api'] },
  { file: 'schema.graphql', stack: 'graphql', domains: ['api'] },
];

/** Framework fingerprints read out of a manifest's dependency list. */
export const FRAMEWORK_MARKERS = {
  express: { domains: ['web', 'api'], notes: 'Check helmet, rate limiting, body size limits, CORS.' },
  fastify: { domains: ['web', 'api'], notes: 'Check @fastify/helmet, schema validation, rate limit.' },
  koa: { domains: ['web', 'api'], notes: 'Check koa-helmet and body parser limits.' },
  '@nestjs/core': { domains: ['web', 'api'], notes: 'Check global ValidationPipe with whitelist and forbidNonWhitelisted.' },
  next: { domains: ['web', 'api'], notes: 'Check server actions, middleware auth, and headers config.' },
  react: { domains: ['web'], notes: 'Check dangerouslySetInnerHTML and href sinks.' },
  vue: { domains: ['web'], notes: 'Check v-html sinks.' },
  'socket.io': { domains: ['web', 'api'], notes: 'Check origin verification and auth on connection.' },
  graphql: { domains: ['api'], notes: 'Check depth/complexity limits, introspection, batching abuse.' },
  mongoose: { domains: ['code'], notes: 'Check operator injection and strict query mode.' },
  sequelize: { domains: ['code'], notes: 'Check sequelize.query and replacements usage.' },
  knex: { domains: ['code'], notes: 'Check knex.raw call sites.' },
  jsonwebtoken: { domains: ['code'], notes: 'Check algorithm pinning and secret strength.' },
  passport: { domains: ['code'], notes: 'Check session fixation and strategy callbacks.' },
  django: { domains: ['web', 'api'], notes: 'Check DEBUG, ALLOWED_HOSTS, SECRET_KEY, CSRF, and ORM .extra/.raw.' },
  flask: { domains: ['web', 'api'], notes: 'Check debug mode, secret key, and render_template_string.' },
  fastapi: { domains: ['api'], notes: 'Check dependency-based auth and response_model leakage.' },
  spring: { domains: ['web', 'api'], notes: 'Check Spring Security config, actuator exposure, CSRF.' },
  'spring-boot-starter-actuator': { domains: ['api'], notes: 'Actuator endpoints must not be publicly exposed.' },
  laravel: { domains: ['web', 'api'], notes: 'Check APP_DEBUG, mass assignment, and Blade raw output.' },
  rails: { domains: ['web', 'api'], notes: 'Check strong parameters, html_safe, and CSRF protection.' },
  'aws-sdk': { domains: ['cloud'], notes: 'Check credential sourcing and IAM least privilege.' },
  boto3: { domains: ['cloud'], notes: 'Check credential sourcing and IAM least privilege.' },
  langchain: { domains: ['llm'], notes: 'Check prompt injection, tool sandboxing, and output handling.' },
  openai: { domains: ['llm'], notes: 'Check prompt injection and key handling.' },
  '@anthropic-ai/sdk': { domains: ['llm'], notes: 'Check prompt injection and key handling.' },
};

/* ------------------------------------------------------------------ *
 * Lockfiles worth parsing for a software bill of materials
 * ------------------------------------------------------------------ */

export const LOCKFILES = [
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json',
  'poetry.lock', 'Pipfile.lock', 'requirements.txt', 'uv.lock',
  'go.sum', 'Cargo.lock', 'composer.lock', 'Gemfile.lock',
  'gradle.lockfile', 'packages.lock.json', 'pubspec.lock', 'mix.lock',
  'Package.resolved', 'Podfile.lock',
];
