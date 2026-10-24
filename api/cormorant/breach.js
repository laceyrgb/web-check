import { APP_UA, httpGet } from '../_common/http.js';
import { canonicalHost, domainOf, cardFields } from './util.js';
import { extractEmails, fetchPage, targetUrl } from './hosts.js';

const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;

export const toPublicBreach = (raw, source) => {
  const name = raw?.Name || raw?.Title || raw?.name;
  if (!name || typeof name !== 'string') return null;
  const date = raw?.BreachDate || raw?.date || null;
  const url =
    source === 'Have I Been Pwned'
      ? `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(raw.Name || name)}`
      : 'https://xposedornot.com/';
  return {
    name,
    title: raw?.Title || name,
    date,
    url,
    source,
    fact: `Appeared in public breach ${name}`,
  };
};

const hibp = async (email, deps) => {
  const key = process.env.HIBP_API_KEY;
  if (!key) return null;
  const http = deps.httpGet || httpGet;
  const response = await http(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
    params: { truncateResponse: 'false' },
    headers: { 'hibp-api-key': key, 'user-agent': `${APP_UA} cormorant` },
    timeout: 15000,
    validateStatus: (status) => status === 200 || status === 404,
  });
  if (response.status === 404) return [];
  return (Array.isArray(response.data) ? response.data : []).map((row) => toPublicBreach(row, 'Have I Been Pwned')).filter(Boolean);
};

const xposed = async (email, deps) => {
  const http = deps.httpGet || httpGet;
  const response = await http(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, {
    timeout: 12000,
    validateStatus: (status) => status === 200 || status === 404,
  });
  const data = response.data;
  if (!data || data.Error) return [];
  const names = [];
  const walk = (value) => {
    if (typeof value === 'string') names.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
  };
  walk(data.breaches);
  return [...new Set(names)]
    .filter((name) => /^[A-Za-z0-9 ._-]{2,80}$/.test(name))
    .map((name) => toPublicBreach({ Name: name }, 'XposedOrNot'));
};

export const checkEmailBreaches = async (url, deps = {}) => {
  const domain = domainOf(canonicalHost(url));
  const extra = typeof deps.email === 'string' && EMAIL_RE.test(deps.email) ? deps.email.toLowerCase() : null;
  let pageEmails = deps.pageEmails;
  if (!pageEmails && !deps.skipPageFetch) {
    try {
      const page = deps.page || (await fetchPage(targetUrl(url), deps));
      pageEmails = extractEmails(page.html, domain);
    } catch (error) {
      pageEmails = [];
      deps.pageError = error.message;
    }
  }
  const emails = [...new Set([...(pageEmails || []), ...(extra ? [extra] : [])])].slice(0, 5);
  const rows = [];
  let degraded = false;
  const pace = deps.paceMs ?? (process.env.HIBP_API_KEY ? 1600 : 0);
  for (const [index, email] of emails.entries()) {
    if (index && pace) await new Promise((resolve) => setTimeout(resolve, pace));
    const source = email === extra ? 'user' : 'page';
    try {
      let breaches = await hibp(email, deps);
      let provider = 'Have I Been Pwned';
      if (!breaches) {
        provider = 'XposedOrNot';
        breaches = await xposed(email, deps);
      }
      rows.push({
        email,
        source,
        provider,
        status: breaches.length ? 'found' : 'clear',
        breaches,
      });
    } catch (error) {
      degraded = true;
      rows.push({
        email,
        source,
        status: 'unavailable',
        breaches: [],
        message: 'Breach index was unavailable. No password data was requested or stored.',
      });
    }
  }
  if (!process.env.HIBP_API_KEY && !rows.length) degraded = true;
  const result = {
    domain,
    emails: rows,
    degraded,
    note: process.env.HIBP_API_KEY
      ? 'Email breach status comes from Have I Been Pwned. Passwords are never requested or stored.'
      : 'HIBP_API_KEY is unset. A public breach index was used when it responded. Passwords are never stored.',
  };
  return {
    ...result,
    ...cardFields(
      rows.map((row) =>
        row.status === 'found'
          ? `${row.email} appeared in ${row.breaches.map((item) => item.name).join(', ')}`
          : row.status === 'clear'
            ? `${row.email} had no public breach record`
            : `${row.email} could not be checked`,
      ),
      rows.flatMap((row) => row.breaches.map((item) => ({ label: item.name, value: row.email, href: item.url }))),
      result.note,
    ),
  };
};
