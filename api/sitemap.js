import xml2js from 'xml2js';
import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';
import { createLogger } from './_common/logger.js';
import { isPrivateTarget } from './_common/check-skipper.js';
import { canonicalUrl, extractAnchors, hostOf, portOf } from './_common/page-links.js';

const log = createLogger('sitemap');
const TIMEOUT = 6000;
const MAX_DEPTH = 3;
const MAX_CHILD_SITEMAPS = 25;
const MAX_URLS = 5000;

// How far a crawl of the page itself may go when the site publishes no sitemap
const CRAWL_DEPTH = 3;
const CRAWL_FETCHES = 20;
const CRAWL_LISTED = 300;
const CRAWL_CONCURRENCY = 5;
const CRAWL_BUDGET = 24000;
const CRAWL_TIMEOUT = 6000;
const REDIRECT_HOPS = 5;

const HEADERS = { accept: 'application/xml, text/xml, application/rss+xml, */*;q=0.1' };

// Reduce a target URL to its origin so child paths resolve cleanly
const toOrigin = (url) => {
  try {
    return new URL(url).origin;
  } catch {
    return url.replace(/\/+$/, '');
  }
};

// Fetch and parse XML in lenient mode so minor well-formedness errors do not abort
const fetchSitemap = async (sitemapUrl) => {
  const res = await httpGet(sitemapUrl, { timeout: TIMEOUT, headers: HEADERS });
  return new xml2js.Parser({ strict: false, normalizeTags: true }).parseStringPromise(res.data);
};

// Pull the first Sitemap: directive out of robots.txt, if any
const findSitemapInRobots = async (origin) => {
  try {
    const robots = await httpGet(`${origin}/robots.txt`, { timeout: TIMEOUT, headers: HEADERS });
    for (const line of String(robots.data).split('\n')) {
      if (line.toLowerCase().startsWith('sitemap:')) {
        return line.split(/\s+/)[1]?.trim() || null;
      }
    }
  } catch (error) {
    log.debug(`robots.txt fetch failed for ${origin}`, error.message);
  }
  return null;
};

// Recursively flatten a sitemap-index into its child url sets
const expandSitemap = async (parsed, depth) => {
  if (!parsed?.sitemapindex?.sitemap || depth >= MAX_DEPTH) return parsed;
  const children = parsed.sitemapindex.sitemap
    .map((s) => s?.loc?.[0])
    .filter(Boolean)
    .slice(0, MAX_CHILD_SITEMAPS);
  const fetched = await Promise.all(
    children.map((loc) =>
      fetchSitemap(loc).catch((error) => {
        log.debug(`child sitemap failed for ${loc}`, error.message);
        return null;
      }),
    ),
  );
  const expanded = await Promise.all(
    fetched.map((child) => (child ? expandSitemap(child, depth + 1) : null)),
  );
  const urls = expanded.flatMap((child) => child?.urlset?.url || []);
  return {
    sitemapindex: parsed.sitemapindex,
    urlset: urls.length ? { url: urls } : undefined,
    sources: children,
  };
};

// Whether the parsed XML matched one of the canonical sitemap shapes
const isValidSitemap = (p) => !!(p?.urlset?.url?.length || p?.sitemapindex?.sitemap?.length);

// Keep only the four fields the frontend renders, dropping locale alternates and image/video extras
const slimUrl = (u) => {
  const out = { loc: u.loc };
  if (u.lastmod) out.lastmod = u.lastmod;
  if (u.changefreq) out.changefreq = u.changefreq;
  if (u.priority) out.priority = u.priority;
  return out;
};

// Drop bulky XML extensions and cap total entries so the JSON payload stays sane
const slimResult = (r) => {
  if (!r) return r;
  const out = {};
  if (r.urlset?.url) out.urlset = { url: r.urlset.url.slice(0, MAX_URLS).map(slimUrl) };
  if (r.sitemapindex?.sitemap) {
    out.sitemapindex = {
      sitemap: r.sitemapindex.sitemap.map((s) => ({ loc: s.loc })),
    };
  }
  if (r.sources) out.sources = r.sources;
  return out;
};

// Try a candidate URL, return parsed result only when it looks like a real sitemap
const tryFetch = async (target, label) => {
  try {
    const parsed = await fetchSitemap(target);
    if (isValidSitemap(parsed)) return parsed;
    log.debug(`${label} parsed but lacked urlset/sitemapindex (${target})`);
  } catch (error) {
    log.debug(`${label} fetch failed (${target})`, error.message);
  }
  return null;
};

// The published sitemap, or null when the site does not have one we can read
const loadPublishedSitemap = async (url) => {
  const origin = toOrigin(url);
  let parsed = await tryFetch(`${origin}/sitemap.xml`, 'sitemap.xml');
  if (!parsed) {
    const fromRobots = await findSitemapInRobots(origin);
    if (fromRobots) parsed = await tryFetch(fromRobots, 'robots-listed sitemap');
  }
  if (!parsed) return null;
  return { source: 'sitemap', ...slimResult(await expandSitemap(parsed, 0)) };
};

// Same host as the page we were asked to scan, on a normal web port or the page's own port
const sameSite = (href, originHost, originPort, originPrivate) => {
  let url;
  try {
    url = new URL(href);
  } catch {
    return false;
  }
  if (hostOf(href) !== originHost) return false;
  const port = portOf(href);
  if (port !== originPort && port !== '80' && port !== '443') return false;
  if (!originPrivate && isPrivateTarget(href)) return false;
  return url.protocol === 'http:' || url.protocol === 'https:';
};

// Follow same-site redirects ourselves so a link cannot send the crawl somewhere else
const fetchDocument = async (target, allowed) => {
  let current = target;
  for (let hop = 0; hop <= REDIRECT_HOPS; hop++) {
    const res = await httpGet(current, {
      timeout: CRAWL_TIMEOUT,
      redirect: 'manual',
      validateStatus: () => true,
      headers: { accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1' },
    });
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location && hop < REDIRECT_HOPS) {
      const next = canonicalUrl(location, current);
      // Stop on a redirect that leaves the site, and keep the redirect status for this link
      if (!next || !allowed(next))
        return { status: res.status, html: '', finalUrl: current, bot: false };
      current = next;
      continue;
    }
    const html = typeof res.data === 'string' ? res.data : '';
    const type = String(res.headers['content-type'] || '');
    const isHtml = /html|xml/.test(type) || /^\s*</.test(html.slice(0, 200));
    return {
      status: res.status,
      html: isHtml ? html : '',
      finalUrl: current,
      bot: isBotCheck({ status: res.status, headers: res.headers, data: html }),
    };
  }
  return { status: 0, html: '', finalUrl: current, bot: false };
};

// A listed link, in the same loc/status shape the sitemap card already reads
const linkEntry = (href, record) => {
  const entry = { loc: [href] };
  if (record.status) entry.status = [String(record.status)];
  if (record.blocked) entry.blocked = ['yes'];
  return entry;
};

const isWorking = (record) => !record.blocked && record.status >= 200 && record.status < 400;

// Crawl the page and list the same-site links it leads to, with the status of each one
export const collectSiteLinks = async (url) => {
  const start = canonicalUrl(url, url);
  if (!start) return { error: 'URL provided is invalid' };
  const originHost = hostOf(start);
  const originPort = portOf(start);
  const originPrivate = isPrivateTarget(start);
  const allowed = (href) => sameSite(href, originHost, originPort, originPrivate);

  const listed = new Map();
  let truncated = false;
  const queue = [{ href: start, depth: 0 }];
  const enqueued = new Set([start]);
  listed.set(start, {});
  let fetched = 0;
  const deadline = Date.now() + CRAWL_BUDGET;

  const remember = (href) => {
    if (listed.has(href)) return;
    if (listed.size >= CRAWL_LISTED) {
      truncated = true;
      return;
    }
    listed.set(href, {});
  };

  let firstError = null;
  while (queue.length && fetched < CRAWL_FETCHES && Date.now() < deadline) {
    const batch = queue.splice(0, CRAWL_CONCURRENCY);
    await Promise.all(
      batch.map(async (item) => {
        fetched += 1;
        let doc;
        try {
          doc = await fetchDocument(item.href, allowed);
        } catch (error) {
          if (item.href === start) firstError = error;
          listed.get(item.href).status = 0;
          log.debug(`crawl fetch failed for ${item.href}`, error.message);
          return;
        }
        const record = listed.get(item.href);
        record.status = doc.status;
        record.blocked = doc.bot;
        if (!doc.html || doc.bot || item.depth >= CRAWL_DEPTH) return;
        // Relative links resolve against the page we actually landed on
        const base = allowed(canonicalUrl(doc.finalUrl, doc.finalUrl) || '')
          ? doc.finalUrl
          : item.href;
        for (const href of extractAnchors(doc.html, base)) {
          if (!allowed(href)) continue;
          const known = listed.has(href);
          remember(href);
          if (known || enqueued.has(href) || item.depth + 1 > CRAWL_DEPTH) continue;
          if (fetched + queue.length >= CRAWL_FETCHES) {
            truncated = true;
            continue;
          }
          enqueued.add(href);
          queue.push({ href, depth: item.depth + 1 });
        }
      }),
    );
  }
  if (queue.length) truncated = true;
  if (firstError && listed.size === 1 && !listed.get(start).status) {
    return upstreamError(firstError, 'Page crawl');
  }

  const startRecord = listed.get(start);
  if (startRecord?.blocked) return BOT_CHECK_ERROR;

  const others = [...listed.keys()].filter((href) => href !== start);
  if (!others.length) {
    if (!isWorking(startRecord)) {
      return { skipped: 'No sitemap was published, and the page could not be crawled' };
    }
    return { skipped: 'No sitemap was published, and the page has no same-site links to list' };
  }

  const rows = [...listed.entries()]
    .map(([href, record]) => ({ href, record }))
    .sort((a, b) => {
      const rank = (record) => (isWorking(record) ? 0 : record.status ? 1 : 2);
      return rank(a.record) - rank(b.record) || a.href.localeCompare(b.href);
    });
  const valid = rows.filter((item) => isWorking(item.record)).length;
  log.debug(`crawled ${fetched} pages, listed ${rows.length} for ${start}`);
  return {
    source: 'crawl',
    pagesCrawled: fetched,
    truncated,
    valid,
    urlset: { url: rows.map((item) => linkEntry(item.href, item.record)) },
  };
};

const sitemapHandler = async (url) => {
  try {
    const published = await loadPublishedSitemap(url);
    if (published) return published;
  } catch (error) {
    return upstreamError(error, 'Sitemap fetch');
  }
  return collectSiteLinks(url);
};

export const handler = middleware(sitemapHandler);
export default handler;
