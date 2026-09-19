/**
 * A tolerant reader for JavaScript object literals.
 *
 * FIRST publishes the official CVSS v4.0 tables as bare global assignments in
 * .js files - not JSON, not ES modules. They contain line comments inside the
 * object, unquoted numeric keys and trailing commas, so JSON.parse rejects
 * them outright.
 *
 * Rather than evaluating untrusted JavaScript (which would hand a remote file
 * arbitrary code execution inside our pipeline), this normalises the literal
 * into strict JSON with a character scanner that respects string boundaries.
 * A `//` inside a quoted vector string must survive; a `//` outside one is a
 * comment. A regex cannot tell those apart, so we do not use one.
 */

/**
 * Extract `identifier = { ... }` from a source file and parse it.
 * @param {string} source  file contents
 * @param {string} identifier  the global being assigned
 */
export function parseJsObjectLiteral(source, identifier) {
  const start = source.indexOf(identifier);
  if (start === -1) throw new Error(`identifier "${identifier}" not found`);

  const eq = source.indexOf('=', start + identifier.length);
  if (eq === -1) throw new Error(`no assignment found for "${identifier}"`);

  const body = extractBalanced(source, eq + 1);
  return JSON.parse(toStrictJson(body));
}

/** Read one balanced {...} or [...] literal starting at or after `from`. */
function extractBalanced(source, from) {
  let i = from;
  while (i < source.length && /\s/.test(source[i])) i++;

  const open = source[i];
  if (open !== '{' && open !== '[') {
    throw new Error(`expected an object or array literal, found "${open ?? 'EOF'}"`);
  }
  const close = open === '{' ? '}' : ']';

  let depth = 0;
  let inString = false;
  let quote = '';
  let inLineComment = false;
  let inBlockComment = false;

  for (; i < source.length; i++) {
    const ch = source[i];
    const next = source[i + 1];

    if (inLineComment) { if (ch === '\n') inLineComment = false; continue; }
    if (inBlockComment) { if (ch === '*' && next === '/') { inBlockComment = false; i++; } continue; }

    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) inString = false;
      continue;
    }

    if (ch === '"' || ch === "'") { inString = true; quote = ch; continue; }
    if (ch === '/' && next === '/') { inLineComment = true; i++; continue; }
    if (ch === '/' && next === '*') { inBlockComment = true; i++; continue; }

    if (ch === open) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) return source.slice(from, i + 1);
    }
  }

  throw new Error('unterminated literal');
}

/** Normalise a JS object literal into strict JSON. */
function toStrictJson(input) {
  let out = '';
  let inString = false;
  let quote = '';

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const next = input[i + 1];

    if (inString) {
      out += ch;
      if (ch === '\\') { out += next ?? ''; i++; continue; }
      if (ch === quote) {
        inString = false;
        // Single-quoted strings must be re-emitted with double quotes.
        if (quote === "'") out = `${out.slice(0, -1)}"`;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      inString = true;
      quote = ch;
      out += ch === "'" ? '"' : ch;
      continue;
    }

    if (ch === '/' && next === '/') {
      while (i < input.length && input[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < input.length && !(input[i] === '*' && input[i + 1] === '/')) i++;
      i++;
      continue;
    }

    out += ch;
  }

  // Quote bare object keys: `0:` and `eq1:` become `"0":` and `"eq1":`.
  // Runs only over the comment-free text, and the lookbehind keeps it from
  // touching anything inside a string, which is already double-quoted.
  out = quoteBareKeys(out);

  // Drop trailing commas before a closing brace or bracket.
  out = out.replace(/,(\s*[}\]])/g, '$1');

  return out;
}

function quoteBareKeys(input) {
  let out = '';
  let inString = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (inString) {
      out += ch;
      if (ch === '\\') { out += input[i + 1] ?? ''; i++; continue; }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; out += ch; continue; }

    // A bare key can only follow `{` or `,` (ignoring whitespace).
    if (/[A-Za-z0-9_$]/.test(ch)) {
      const prev = lastMeaningful(out);
      if (prev === '{' || prev === ',') {
        let j = i;
        while (j < input.length && /[A-Za-z0-9_$.]/.test(input[j])) j++;
        let k = j;
        while (k < input.length && /\s/.test(input[k])) k++;
        if (input[k] === ':') {
          out += `"${input.slice(i, j)}"`;
          i = j - 1;
          continue;
        }
      }
    }

    out += ch;
  }

  return out;
}

function lastMeaningful(text) {
  for (let i = text.length - 1; i >= 0; i--) {
    if (!/\s/.test(text[i])) return text[i];
  }
  return '';
}
