// Same-site link rules as the crawl in api/sitemap.js (the page-links work): drop
// non-page schemes, stay on the origin host, and cap the number of pages.
// extractAnchors from that module is used when cheerio is installed. The fallback
// below is what the suite tests run so they do not need that dependency.

const NON_PAGE = /^(javascript|mailto|tel|sms|data|blob|about|chrome):/i;

export const canonicalPage = (href, base) => {
  if (href == null) return null;
  const raw = String(href).trim();
  if (!raw || raw.startsWith('#') || NON_PAGE.test(raw)) return null;
  let url;
  try {
    url = new URL(raw, base);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  url.hash = '';
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, '');
  return url.href;
};

export const simpleExtract = (html, base) => {
  const out = [];
  const pattern = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
  let match = pattern.exec(String(html || ''));
  while (match) {
    const href = canonicalPage(match[1], base);
    if (href) out.push(href);
    match = pattern.exec(String(html || ''));
  }
  return out;
};

const lowerHeaders = (headers = {}) =>
  Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));

export const crawlSameSite = async ({ origin, httpGet, extract = simpleExtract, limit = 5 }) => {
  const startUrl = new URL(origin);
  const start = startUrl.href;
  const host = startUrl.hostname;
  const seen = new Set();
  const queue = [start];
  const pages = [];
  while (queue.length && pages.length < limit) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    let pageUrl;
    try {
      pageUrl = new URL(url);
    } catch {
      continue;
    }
    if (pageUrl.hostname !== host) continue;
    seen.add(url);
    let response;
    try {
      response = await httpGet(url);
    } catch {
      continue;
    }
    const body = String(response?.body || '');
    pages.push({
      url,
      status: response?.status,
      headers: lowerHeaders(response?.headers),
      bodySnippet: body.slice(0, 50000),
      scheme: pageUrl.protocol.replace(':', ''),
    });
    for (const href of extract(body, url)) {
      let next;
      try {
        next = new URL(href);
      } catch {
        continue;
      }
      if (next.hostname !== host || seen.has(href)) continue;
      queue.push(href);
    }
  }
  return pages;
};
