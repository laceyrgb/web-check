import net from 'net';
import { parseTarget, baseDomain } from '../_common/parse-target.js';
import { isPrivateTarget } from '../_common/check-skipper.js';

export const flagOn = (name) => {
  const value = String(process.env[name] || '').toLowerCase();
  return value === 'true' || value === '1';
};

export const SENSITIVE_KEY = /password|passwd|secret|credential|api[-_]?key|token|hash/i;

// Drop fields that could carry secrets. Used on scan output, never as a substitute for an allowlist.
export const redactObject = (value) => {
  if (Array.isArray(value)) return value.map(redactObject);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) continue;
    out[key] = redactObject(item);
  }
  return out;
};

export const previewSecret = (value) => {
  const text = String(value || '');
  if (text.includes('PRIVATE KEY')) return '[private key redacted]';
  if (text.length <= 8) return '[redacted]';
  return `${text.slice(0, 4)}…${text.slice(-2)}`;
};

export const canonicalHost = (input) => {
  const { hostname } = parseTarget(String(input || '').trim());
  return hostname.replace(/\.$/, '').toLowerCase();
};

export const targetHref = (input) => {
  const host = canonicalHost(input);
  return `https://${host}`;
};

export const domainOf = (input) => {
  const host = canonicalHost(input);
  if (net.isIP(host)) return host;
  return (baseDomain(host) || host).toLowerCase();
};

export const blockedInfrastructure = (host) => {
  const name = String(host || '').toLowerCase();
  if (
    ['localhost', '0.0.0.0', '::', '::1', '169.254.169.254', 'metadata.google.internal'].includes(
      name,
    )
  )
    return true;
  if (name.endsWith('.localhost')) return true;
  return /^127\./.test(name);
};

export const assertPublicTarget = (input) => {
  const host = canonicalHost(input);
  if (blockedInfrastructure(host) || isPrivateTarget(host)) {
    const error = new Error('Refusing a private, local, or metadata address');
    error.status = 400;
    throw error;
  }
  return host;
};

export const hostInScope = (hostname, scope) => {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/\.$/, '');
  return (scope || []).some((entry) => {
    const item = String(entry || '')
      .toLowerCase()
      .replace(/^\*\./, '')
      .replace(/\.$/, '');
    if (!item) return false;
    if (net.isIP(item)) return item === host;
    return host === item || host.endsWith(`.${item}`);
  });
};

export const robotsAllows = (robotsTxt, requestPath) => {
  if (!robotsTxt) return true;
  const pathName = requestPath?.startsWith('/') ? requestPath : `/${requestPath || ''}`;
  let inStar = false;
  const disallows = [];
  for (const line of String(robotsTxt).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const agent = /^user-agent:\s*(.+)$/i.exec(trimmed);
    if (agent) {
      inStar = agent[1].trim() === '*';
      continue;
    }
    if (!inStar) continue;
    const rule = /^disallow:\s*(.*)$/i.exec(trimmed);
    if (rule) disallows.push(rule[1].trim());
  }
  return !disallows.some((rule) => rule && (rule === '/' || pathName.startsWith(rule)));
};

export const cardFields = (summary, items, note) => ({
  summary: summary.filter(Boolean),
  items: items.filter((item) => item && item.value !== undefined && item.value !== '').slice(0, 40),
  note,
});

export const safeEqual = (presented, expected) => {
  if (!expected) return true;
  if (typeof presented !== 'string' || presented.length !== expected.length) return false;
  const left = Buffer.from(presented);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let i = 0; i < left.length; i += 1) mismatch |= left[i] ^ right[i];
  return mismatch === 0;
};

export const httpError = (status, message, extra = {}) => {
  const error = new Error(message);
  error.status = status;
  Object.assign(error, extra);
  return error;
};
