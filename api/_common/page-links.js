import * as cheerio from 'cheerio';

// Schemes that are not pages, so they never belong in a link list
const NON_PAGE = /^(javascript|mailto|tel|sms|data|blob|about|chrome):/i;

// A comparable host, without a trailing dot or capital letters
export const hostOf = (href) => {
  try {
    return new URL(href).hostname.replace(/\.$/, '').toLowerCase();
  } catch {
    return '';
  }
};

// The port a URL actually connects to, filling in the scheme default
export const portOf = (href) => {
  const url = new URL(href);
  if (url.port) return url.port;
  return url.protocol === 'https:' ? '443' : '80';
};

// An absolute http(s) URL with the fragment and trailing slash removed, or null when it isn't a page link
export const canonicalUrl = (href, base) => {
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
  url.hostname = hostOf(url.href);
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, '');
  return url.href;
};

// Every anchor on the page, in document order, already resolved and cleaned
export const extractAnchors = (html, baseUrl) => {
  const $ = cheerio.load(String(html ?? ''));
  const links = [];
  $('a[href]').each((_, element) => {
    const href = canonicalUrl($(element).attr('href'), baseUrl);
    if (href) links.push(href);
  });
  return links;
};
