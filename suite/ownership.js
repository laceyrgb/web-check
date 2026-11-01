import { timingSafeEqual } from 'node:crypto';

export const TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;

export const VERIFY_PREFIX = 'cormorant-verify=';
export const VERIFY_NAME = (hostname) => `_cormorant-verify.${hostname}`;
export const VERIFY_PATH = '/.well-known/cormorant-verify.txt';

export const tokenHint = (token) => {
  if (!token) return null;
  const text = String(token);
  return `…${text.slice(-4)}`;
};

const safeEqual = (left, right) => {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
};

export const tokenMatches = (presented, expected) => {
  if (!TOKEN_RE.test(expected || '') || !TOKEN_RE.test(presented || '')) return false;
  return safeEqual(presented, expected);
};

const txtValues = (rows) =>
  (Array.isArray(rows) ? rows : [])
    .map((row) => (Array.isArray(row) ? row.join('') : String(row)))
    .map((value) => value.trim());

// DNS TXT at _cormorant-verify.<host> or an exact token file. Either proof is enough.
export const verifyOwnership = async ({ hostname, token, origin, transports = {} }) => {
  if (!TOKEN_RE.test(token || '')) {
    return { ok: false, method: null, reason: 'token-format' };
  }
  const expectedRecord = `${VERIFY_PREFIX}${token}`;
  if (typeof transports.resolveTxt === 'function') {
    try {
      const rows = await transports.resolveTxt(VERIFY_NAME(hostname));
      const values = txtValues(rows);
      if (values.some((value) => value === expectedRecord || tokenMatches(value, token))) {
        return { ok: true, method: 'dns-txt', reason: null };
      }
    } catch {
      // Fall through to the file. A DNS blip must not look like a pass.
    }
  }
  if (typeof transports.httpGet === 'function' && origin) {
    try {
      const response = await transports.httpGet(`${origin}${VERIFY_PATH}`);
      const body = String(response?.body || '')
        .replace(/^\uFEFF/, '')
        .trim();
      if (response?.status === 200 && body.length <= 256 && tokenMatches(body, token)) {
        return { ok: true, method: 'well-known-file', reason: null };
      }
    } catch {
      return { ok: false, method: null, reason: 'lookup-failed' };
    }
  }
  return { ok: false, method: null, reason: 'not-found' };
};
