/**
 * Minimal HTTP client for the intelligence layer.
 *
 * Every public feed we consume is rate limited, occasionally flaky, and
 * sometimes simply down. Retrying with backoff and honouring Retry-After is
 * not politeness, it is the difference between a pipeline that works and one
 * that pages someone every other week.
 */

import zlib from 'node:zlib';

const USER_AGENT = 'claude-security-audit/1.0 (+https://github.com/TobiasVeiga00/claude-security-audit)';

export class HttpError extends Error {
  constructor(status, url, body) {
    super(`HTTP ${status} for ${url}${body ? `: ${String(body).slice(0, 200)}` : ''}`);
    this.status = status;
    this.url = url;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Fetch with bounded retries.
 *
 * Retries 429, 5xx and network faults. Never retries 4xx other than 429,
 * because a 404 will still be a 404 in eight seconds.
 */
export async function request(url, {
  headers = {},
  retries = 4,
  timeoutMs = 60000,
  baseDelayMs = 1000,
  method = 'GET',
  body = null,
} = {}) {
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method,
        body,
        headers: { 'user-agent': USER_AGENT, 'accept-encoding': 'gzip, deflate', ...headers },
        signal: controller.signal,
      });

      if (response.ok) return response;

      if (response.status === 429 || response.status >= 500) {
        const retryAfter = Number(response.headers.get('retry-after'));
        const delay = Number.isFinite(retryAfter) && retryAfter > 0
          ? retryAfter * 1000
          : baseDelayMs * 2 ** attempt + Math.random() * 400;
        lastError = new HttpError(response.status, url, await safeText(response));
        if (attempt < retries) {
          process.stderr.write(`  retry ${attempt + 1}/${retries} after ${Math.round(delay)}ms (HTTP ${response.status})\n`);
          await sleep(delay);
          continue;
        }
      }

      throw new HttpError(response.status, url, await safeText(response));
    } catch (err) {
      if (err instanceof HttpError && err.status < 500 && err.status !== 429) throw err;
      lastError = err;
      if (attempt < retries) {
        await sleep(baseDelayMs * 2 ** attempt + Math.random() * 400);
        continue;
      }
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastError ?? new Error(`request to ${url} failed`);
}

export async function getJson(url, options = {}) {
  const response = await request(url, { headers: { accept: 'application/json', ...options.headers }, ...options });
  return response.json();
}

export async function getText(url, options = {}) {
  const response = await request(url, options);
  return response.text();
}

/** Fetch a gzipped payload and return the decompressed text. */
export async function getGzipText(url, options = {}) {
  const response = await request(url, options);
  const buffer = Buffer.from(await response.arrayBuffer());
  // Some CDNs already decompress transparently; detect the gzip magic number.
  if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
    return zlib.gunzipSync(buffer).toString('utf8');
  }
  return buffer.toString('utf8');
}

async function safeText(response) {
  try { return await response.text(); } catch { return ''; }
}

/** Run tasks with bounded concurrency so a batch cannot stampede a public API. */
export async function pooled(items, worker, concurrency = 4) {
  const results = new Array(items.length);
  let cursor = 0;

  async function run() {
    while (cursor < items.length) {
      const index = cursor++;
      try {
        results[index] = { ok: true, value: await worker(items[index], index) };
      } catch (err) {
        results[index] = { ok: false, error: err };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, run));
  return results;
}
