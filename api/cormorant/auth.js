import { safeEqual } from './util.js';

export const DEFAULT_TENANT = 'default';

export const presentedKey = (req) => {
  const header = req.get?.('x-api-key') || req.headers?.['x-api-key'];
  if (header) return header;
  const authorization = req.get?.('authorization') || req.headers?.authorization || '';
  return authorization.replace(/^Bearer\s+/i, '');
};

// WEBCHECK_API_KEY stays the default tenant. WEBCHECK_TENANT_KEYS is "tenant:key,tenant:key".
export const tenantKeyMap = () => {
  const entries = [];
  for (const part of String(process.env.WEBCHECK_TENANT_KEYS || '').split(',')) {
    const trimmed = part.trim();
    const splitAt = trimmed.indexOf(':');
    if (splitAt <= 0) continue;
    const tenant = trimmed.slice(0, splitAt).trim();
    const key = trimmed.slice(splitAt + 1).trim();
    if (!/^[a-z0-9][a-z0-9-]{0,40}$/i.test(tenant) || !key) continue;
    entries.push({ tenant, key });
  }
  if (process.env.WEBCHECK_API_KEY)
    entries.push({ tenant: DEFAULT_TENANT, key: process.env.WEBCHECK_API_KEY });
  return entries;
};

export const resolveTenant = (presented) => {
  const entries = tenantKeyMap();
  if (!entries.length) return { tenant: DEFAULT_TENANT, open: true };
  const match = entries.find((entry) => safeEqual(presented, entry.key));
  return match ? { tenant: match.tenant, open: false } : null;
};

export const requireApiKey = (req, res, next) => {
  const resolved = resolveTenant(presentedKey(req));
  if (!resolved) return res.status(401).json({ error: 'API key required' });
  req.tenant = resolved.tenant;
  return next();
};
