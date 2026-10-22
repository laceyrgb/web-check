import { safeEqual } from './util.js';

export const presentedKey = (req) => {
  const header = req.get?.('x-api-key') || req.headers?.['x-api-key'];
  if (header) return header;
  const authorization = req.get?.('authorization') || req.headers?.authorization || '';
  return authorization.replace(/^Bearer\s+/i, '');
};

export const requireApiKey = (req, res, next) => {
  const expected = process.env.WEBCHECK_API_KEY;
  if (!expected) return next();
  if (safeEqual(presentedKey(req), expected)) return next();
  return res.status(401).json({ error: 'API key required' });
};
