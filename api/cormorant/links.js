import { assertPublicTarget, canonicalHost, domainOf } from './util.js';
import { collectSubdomains, fetchPage, targetUrl } from './hosts.js';

export const LINK_QUEUE_CAP = 80;

const trimToken = (value) =>
  String(value || '')
    .trim()
    .replace(/^[<('"]+|[>)'",.]+$/g, '');

export const hostFromLink = (value) => {
  const text = trimToken(value).slice(0, 500);
  if (!text) return null;
  if (/^(javascript|mailto|data|tel):/i.test(text))
    return { error: 'not a web link', value: text.slice(0, 120) };
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`;
    const host = canonicalHost(withScheme);
    assertPublicTarget(host);
    return { host };
  } catch (error) {
    return { error: error.message || 'invalid link', value: text.slice(0, 120) };
  }
};

export const tokensFromDump = (text) => {
  const raw = String(text || '');
  const found = [];
  for (const match of raw.matchAll(/https?:\/\/[^\s<>"'`]+/gi)) found.push(match[0]);
  if (found.length) {
    const withoutUrls = raw.replace(/https?:\/\/[^\s<>"'`]+/gi, ' ');
    for (const token of withoutUrls.split(/[\s,;]+/)) {
      const cleaned = trimToken(token);
      if (cleaned) found.push(cleaned);
    }
    return found;
  }
  return raw
    .split(/[\s,;]+/)
    .map(trimToken)
    .filter(Boolean);
};

export const linksOnPage = (html, pageUrl) => {
  const urls = [];
  for (const match of String(html || '').matchAll(/(?:href|src)=["']([^"']+)["']/gi)) {
    try {
      const absolute = new URL(match[1], pageUrl);
      if (absolute.protocol !== 'http:' && absolute.protocol !== 'https:') continue;
      absolute.hash = '';
      urls.push(absolute.href);
    } catch {
      continue;
    }
    if (urls.length >= 400) break;
  }
  return urls;
};

export const classifyHosts = (parsed, seen = new Map(), cap = LINK_QUEUE_CAP) => {
  const queued = [];
  const duplicates = [];
  const alreadyScanned = [];
  const retried = [];
  const rejected = [];
  const known = new Set();
  for (const item of parsed) {
    if (!item) continue;
    if (item.error) {
      rejected.push({ value: item.value || '', error: item.error });
      continue;
    }
    if (known.has(item.host)) {
      duplicates.push(item.host);
      continue;
    }
    known.add(item.host);
    const prior = seen.get(item.host);
    if (prior && prior.status !== 'failed') {
      alreadyScanned.push({ host: item.host, status: prior.status, scanId: prior.id });
      continue;
    }
    if (prior?.status === 'failed') retried.push(item.host);
    queued.push(item.host);
  }
  return {
    queued: queued.slice(0, cap),
    held: queued.slice(cap),
    duplicates: [...new Set(duplicates)],
    alreadyScanned,
    retried,
    rejected: rejected.slice(0, 40),
  };
};

export const collectLinkDump = async (
  { text = '', target = null, includeSubdomains = true } = {},
  deps = {},
) => {
  const tokens = tokensFromDump(text);
  let pageStatus = null;
  if (target) {
    const href = targetUrl(target);
    const host = canonicalHost(href);
    assertPublicTarget(host);
    const page = deps.page || (await fetchPage(href, deps));
    pageStatus = page.status ?? null;
    tokens.push(host, ...linksOnPage(page.html || '', page.url || href));
    if (includeSubdomains) {
      const found = await collectSubdomains(domainOf(host), deps);
      tokens.push(...(found.hosts || []).map((item) => item.host));
    }
  }
  return {
    pageStatus,
    parsed: tokens.map(hostFromLink).filter(Boolean),
    note: 'Links are grouped by host. One scan covers the host, so repeated paths collapse. Hosts already queued or completed for this tenant are skipped. Failed hosts are queued again.',
  };
};
