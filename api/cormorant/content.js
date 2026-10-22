import { httpGet } from '../_common/http.js';
import { cardFields } from './util.js';
import { lookupCves } from './cve.js';
import { cpeFor } from './hosts.js';

const BUCKET = /https?:\/\/(?:[a-z0-9.-]+\.)?(?:s3[.-][a-z0-9-]+\.amazonaws\.com|[a-z0-9.-]+\.s3\.amazonaws\.com|storage\.googleapis\.com|[a-z0-9.-]+\.storage\.googleapis\.com|[a-z0-9.-]+\.blob\.core\.windows\.net|[a-z0-9.-]+\.digitaloceanspaces\.com)\/[^\s"'<>]*/gi;

export const findBucketUrls = (html) => [...new Set(String(html || '').match(BUCKET) || [])].slice(0, 8);

export const classifyListing = (status, body) => {
  const text = String(body || '');
  if (status === 200 && /<ListBucketResult|<EnumerationResults/i.test(text)) return 'public-listing';
  if (status === 200) return 'public-object';
  if (status === 403 || status === 401) return 'not-public';
  return 'unknown';
};

export const inspectBuckets = async (html, deps = {}) => {
  const urls = deps.urls || findBucketUrls(html);
  const http = deps.httpGet || httpGet;
  const rows = [];
  for (const bucketUrl of urls) {
    try {
      const response = await http(bucketUrl, { timeout: 8000, validateStatus: () => true });
      rows.push({
        url: bucketUrl,
        status: response.status,
        access: classifyListing(response.status, typeof response.data === 'string' ? response.data.slice(0, 2000) : ''),
      });
    } catch (error) {
      rows.push({ url: bucketUrl, access: 'unknown', error: error.message });
    }
  }
  return {
    buckets: rows,
    note: 'Only URLs already published on the page were requested. Access was not forced after a denial.',
    ...cardFields(
      rows.length ? rows.map((row) => `${row.access}: ${row.url}`) : ['No public bucket URLs were published on the page'],
      rows.map((row) => ({ label: row.access, value: row.url, href: row.url })),
      'Only storage URLs already present on the public page were requested.',
    ),
  };
};

export const fingerprintCms = async (html, deps = {}) => {
  const text = String(html || '');
  const generator = /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i.exec(text)?.[1] || '';
  let cms = null;
  let version = null;
  if (/wordpress/i.test(generator) || /\/wp-content\//i.test(text)) {
    cms = 'WordPress';
    version = /wordpress\s+(\d+(?:\.\d+){0,2})/i.exec(generator)?.[1] || null;
  } else if (/drupal/i.test(generator)) {
    cms = 'Drupal';
    version = /(\d+(?:\.\d+){0,2})/.exec(generator)?.[1] || null;
  } else if (/joomla/i.test(generator)) {
    cms = 'Joomla';
    version = /(\d+(?:\.\d+){0,2})/.exec(generator)?.[1] || null;
  }
  const plugins = [];
  const pluginRe = /\/wp-content\/plugins\/([a-z0-9_-]+)\/[^"'?\s]*\?ver=(\d+(?:\.\d+){0,3})/gi;
  let match = pluginRe.exec(text);
  while (match && plugins.length < 8) {
    plugins.push({ name: match[1], version: match[2], source: 'plugin asset query string' });
    match = pluginRe.exec(text);
  }
  const products = [];
  if (cms && version) products.push({ name: cms, version, cpe: cpeFor(cms) });
  const cves = products.length ? await lookupCves(products, deps) : { findings: [], skipped: [] };
  const result = {
    cms,
    version,
    plugins,
    cves: cves.findings || [],
    skipped: cves.skipped || [],
    note: cms
      ? 'Fingerprint uses the public generator tag and asset URLs. No exploit payload was sent.'
      : 'No WordPress, Drupal, or Joomla generator was observed on the public HTML.',
  };
  return {
    ...result,
    ...cardFields(
      [cms ? `${cms}${version ? ` ${version}` : ' (version not disclosed)'}` : 'No supported CMS fingerprint'],
      result.cves.map((row) => ({ label: row.id, value: row.severity, href: row.url })),
      result.note,
    ),
  };
};

const TRACKER_HOSTS = ['google-analytics.com', 'googletagmanager.com', 'facebook.net', 'doubleclick.net', 'hotjar.com', 'segment.com', 'mixpanel.com'];
const BANNER_HINTS = ['onetrust', 'cookiebot', 'cookieconsent', 'quantcast', 'osano'];

export const auditPrivacy = (html, pageUrl, headers = {}) => {
  const text = String(html || '');
  let host = '';
  try {
    host = new URL(pageUrl).hostname;
  } catch {
    host = '';
  }
  const images = [...text.matchAll(/<img\b[^>]*>/gi)];
  const missingAlt = images.filter((tag) => !/\balt=/i.test(tag[0])).length;
  const inputs = [...text.matchAll(/<input\b[^>]*>/gi)].filter((tag) => !/type=["']hidden["']/i.test(tag[0]));
  const unlabeled = inputs.filter((tag) => {
    const id = /\bid=["']([^"']+)["']/i.exec(tag[0])?.[1];
    if (/\baria-label=/i.test(tag[0]) || /\baria-labelledby=/i.test(tag[0])) return false;
    if (!id) return true;
    return !new RegExp(`<label[^>]+for=["']${id}["']`, 'i').test(text);
  }).length;
  const scripts = [...text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((match) => match[1]);
  const thirdParty = [];
  for (const src of scripts) {
    try {
      const scriptHost = new URL(src, pageUrl).hostname;
      if (host && scriptHost && scriptHost !== host && !scriptHost.endsWith(`.${host}`)) thirdParty.push(scriptHost);
    } catch {
      // ignore unparsable script URLs
    }
  }
  const trackers = [...new Set(thirdParty.filter((name) => TRACKER_HOSTS.some((hint) => name.includes(hint))))];
  const banner = BANNER_HINTS.filter((hint) => text.toLowerCase().includes(hint));
  const a11y = {
    htmlLang: /<html[^>]+lang=/i.test(text),
    title: /<title>[^<]+<\/title>/i.test(text),
    viewport: /name=["']viewport["']/i.test(text),
    images: images.length,
    imagesMissingAlt: missingAlt,
    unlabeledInputs: unlabeled,
  };
  const setCookie = headers['set-cookie'];
  const cookieCount = Array.isArray(setCookie) ? setCookie.length : setCookie ? 1 : 0;
  const notes = [];
  if (!a11y.htmlLang) notes.push('html element has no lang attribute');
  if (missingAlt) notes.push(`${missingAlt} images have no alt attribute`);
  if (unlabeled) notes.push(`${unlabeled} inputs have no associated label`);
  if (!banner.length) notes.push('No common cookie-banner script name was observed');
  if (trackers.length) notes.push(`Tracker hosts observed: ${trackers.join(', ')}`);
  return {
    a11y,
    trackers,
    thirdPartyHosts: [...new Set(thirdParty)].slice(0, 20),
    cookieBannerHints: banner,
    setCookieCount: cookieCount,
    notes,
    note: 'Checks are heuristics on the public HTML and Set-Cookie header. They are not a WCAG audit.',
    ...cardFields(
      [
        a11y.htmlLang ? 'html lang is set' : 'html lang is missing',
        `${missingAlt} images missing alt`,
        trackers.length ? `Trackers: ${trackers.join(', ')}` : 'No listed tracker host observed',
      ],
      notes.map((item) => ({ label: 'Note', value: item })),
      'Heuristics on the public HTML only.',
    ),
  };
};

const ROLE = /\b(chief|ceo|cto|ciso|founder|director|head|manager|engineer|officer|lead)\b/i;

export const parsePublicBio = (html, url) => {
  const title = /<meta[^>]+property=["']og:title["'][^>]*content=["']([^"']+)["']/i.exec(html)?.[1]
    || /<title>([^<]+)<\/title>/i.exec(html)?.[1]
    || '';
  const description = /<meta[^>]+name=["']description["'][^>]*content=["']([^"']+)["']/i.exec(html)?.[1] || '';
  const loginWall = /authwall|sign in to linkedin|join linkedin/i.test(html);
  if (loginWall) {
    return { url, status: 'unavailable', reason: 'Page was not public or asked for a login. It was not bypassed.' };
  }
  const cleaned = title.replace(/\s+\|.*$/, '').trim();
  const role = ROLE.exec(`${title} ${description}`)?.[0] || null;
  return {
    url,
    status: 'public',
    name: cleaned || null,
    title: role ? description.slice(0, 140) || role : description.slice(0, 140) || null,
    confidence: role && cleaned ? 'medium' : cleaned ? 'low' : 'none',
    source: url,
  };
};

export const listPeopleFromPage = (html, pageUrl) => {
  const links = [...String(html || '').matchAll(/href=["']([^"']+)["']/gi)].map((match) => match[1]);
  const people = [];
  for (const href of links) {
    let absolute;
    try {
      absolute = new URL(href, pageUrl).href;
    } catch {
      continue;
    }
    if (/linkedin\.com\/in\//i.test(absolute)) {
      people.push({
        url: absolute.split('?')[0],
        status: 'listed',
        name: null,
        title: null,
        confidence: 'none',
        reason: 'LinkedIn URL was published on the target. It was not fetched.',
        source: pageUrl,
      });
    }
  }
  return people.slice(0, 15);
};

export const fetchPeople = async (urls, deps = {}) => {
  const http = deps.httpGet || httpGet;
  const people = [];
  for (const url of (urls || []).slice(0, 8)) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      people.push({ url, status: 'skipped', reason: 'URL was not valid' });
      continue;
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      people.push({ url, status: 'skipped', reason: 'Only http(s) public URLs are fetched' });
      continue;
    }
    try {
      const response = await http(url, { timeout: 10000, validateStatus: () => true });
      if (response.status === 401 || response.status === 403 || response.status === 999) {
        people.push({ url, status: 'unavailable', reason: 'The site refused an anonymous request. It was not bypassed.' });
        continue;
      }
      const html = typeof response.data === 'string' ? response.data : '';
      people.push(parsePublicBio(html, url));
    } catch (error) {
      people.push({ url, status: 'unavailable', reason: error.message });
    }
  }
  const graph = {
    nodes: [{ id: 'org', kind: 'org', label: 'Target' }],
    edges: [],
  };
  people.forEach((person, index) => {
    if (!person.name) return;
    const id = `p${index}`;
    graph.nodes.push({ id, kind: 'person', label: person.name });
    graph.edges.push({ from: 'org', to: id, role: person.title, confidence: person.confidence, source: person.source });
  });
  return {
    people,
    graph,
    note: 'Names and roles come only from pages that responded without a login. Confidence is low or medium because titles are taken from public metadata.',
    ...cardFields(
      people.map((person) => person.name ? `${person.name} (${person.confidence})` : person.reason || person.status),
      people.filter((person) => person.url).map((person) => ({ label: person.name || person.status, value: person.url, href: person.url })),
      'Public pages only. Login walls are reported and not bypassed.',
    ),
  };
};
