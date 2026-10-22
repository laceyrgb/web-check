import { httpGet, APP_UA } from '../_common/http.js';
import { canonicalHost, domainOf, cardFields } from './util.js';

export const parseRss = (xml) => {
  const items = [];
  const pattern = /<item>([\s\S]*?)<\/item>/gi;
  let match = pattern.exec(String(xml || ''));
  while (match && items.length < 6) {
    const block = match[1];
    const title = /<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i.exec(block)?.[1]?.trim();
    const link = /<link>([\s\S]*?)<\/link>/i.exec(block)?.[1]?.trim();
    if (title && link) items.push({ title: title.replace(/<[^>]*>/g, ''), url: link, source: 'Google News RSS' });
    match = pattern.exec(xml);
  }
  return items;
};

const POSITIVE = ['award', 'partnership', 'growth', 'launch', 'wins', 'profit'];
const NEGATIVE = ['breach', 'lawsuit', 'hack', 'hacked', 'outage', 'fine', 'scandal', 'leak'];

export const scoreSentiment = (titles) => {
  let positive = 0;
  let negative = 0;
  for (const title of titles) {
    const text = title.toLowerCase();
    if (NEGATIVE.some((word) => text.includes(word))) negative += 1;
    else if (POSITIVE.some((word) => text.includes(word))) positive += 1;
  }
  const neutral = titles.length - positive - negative;
  return {
    positive,
    negative,
    neutral,
    summary: `${titles.length} public news titles. Keyword count: ${negative} negative, ${positive} positive, ${neutral} neutral. This is not a sentiment model.`,
  };
};

const leakLink = (row) => row?.url || row?.link || row?.html || null;

export const publicMentions = async (url, deps = {}) => {
  const domain = domainOf(canonicalHost(url));
  const http = deps.httpGet || httpGet;
  const newsQuery = `https://news.google.com/rss/search?q=${encodeURIComponent(domain)}&hl=en-US&gl=US&ceid=US:en`;
  const tasks = {
    news: http(newsQuery, { timeout: 8000, headers: { 'user-agent': APP_UA } }).then((res) => parseRss(typeof res.data === 'string' ? res.data : '')),
    leaks: searchLeaks(domain, deps),
  };
  const [newsResult, leakResult] = await Promise.allSettled([tasks.news, tasks.leaks]);
  const news = newsResult.status === 'fulfilled' ? newsResult.value : [];
  const leaks = leakResult.status === 'fulfilled' ? leakResult.value : [];
  const sentiment = scoreSentiment(news.map((item) => item.title));
  const result = {
    domain,
    news,
    leaks,
    sentiment,
    degraded: newsResult.status === 'rejected' || leakResult.status === 'rejected',
    note: 'Mentions come from public news RSS and public paste or code indexes. Onion services are not queried. Paste bodies are not stored.',
    citations: [
      { name: 'Google News RSS', url: 'https://news.google.com/' },
      { name: 'searchcode', url: 'https://searchcode.com/' },
    ],
  };
  return {
    ...result,
    ...cardFields(
      [sentiment.summary, leaks.length ? `${leaks.length} public code or paste hits` : 'No public code or paste hits returned'],
      [...news, ...leaks].slice(0, 12).map((item) => ({ label: item.source, value: item.title || item.url, href: item.url })),
      result.note,
    ),
  };
};

export const searchLeaks = async (domain, deps = {}) => {
  const http = deps.httpGet || httpGet;
  const hits = [];
  const searchcode = await http(`https://searchcode.com/api/v1.0/code/?q=${encodeURIComponent(domain)}`, {
    timeout: 8000,
    validateStatus: () => true,
  }).catch(() => null);
  const results = searchcode?.data?.results || searchcode?.data?.results || [];
  if (Array.isArray(results)) {
    for (const row of results.slice(0, 5)) {
      const link = leakLink(row) || row.repo;
      if (!link) continue;
      hits.push({
        title: row.name || row.filename || domain,
        url: String(link),
        source: 'searchcode',
      });
    }
  }
  if (process.env.GITHUB_TOKEN) {
    const github = await http('https://api.github.com/search/code', {
      params: { q: `${domain} in:file`, per_page: '5' },
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        'user-agent': 'cormorant-web-check',
      },
      timeout: 8000,
      validateStatus: () => true,
    }).catch(() => null);
    for (const row of github?.data?.items || []) {
      if (!row.html_url) continue;
      hits.push({ title: row.name || row.path || domain, url: row.html_url, source: 'GitHub code search' });
    }
  }
  const paste = await http(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(domain)}`, {
    timeout: 8000,
    validateStatus: () => true,
  }).catch(() => null);
  const pasteRows = Array.isArray(paste?.data) ? paste.data : paste?.data?.data || [];
  if (Array.isArray(pasteRows)) {
    for (const row of pasteRows.slice(0, 5)) {
      const id = row.id || row.pasteid;
      if (!id) continue;
      hits.push({
        title: `Public paste index hit ${id}`,
        url: `https://psbdmp.ws/dump/${id}`,
        source: 'psbdmp public index',
      });
    }
  }
  return hits.filter((hit) => /^https?:\/\//.test(hit.url)).slice(0, 10);
};
