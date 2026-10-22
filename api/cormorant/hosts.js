import dns from 'dns/promises';
import net from 'net';
import { httpGet } from '../_common/http.js';
import { canonicalHost, domainOf, cardFields } from './util.js';

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const MAX_HOSTS = 200;
const SKIP_PRODUCTS = new Set([
  'cloudflare',
  'akamai',
  'awselb',
  'amazons3',
  'amazon',
  'gws',
  'gse',
  'microsoft-httpapi',
]);

const CPE = {
  nginx: 'cpe:2.3:a:f5:nginx',
  apache: 'cpe:2.3:a:apache:http_server',
  php: 'cpe:2.3:a:php:php',
  wordpress: 'cpe:2.3:a:wordpress:wordpress',
  jquery: 'cpe:2.3:a:jquery:jquery',
  drupal: 'cpe:2.3:a:drupal:drupal',
  joomla: 'cpe:2.3:a:joomla:joomla\\!',
  'microsoft-iis': 'cpe:2.3:a:microsoft:internet_information_services',
  tomcat: 'cpe:2.3:a:apache:tomcat',
  lighttpd: 'cpe:2.3:a:lighttpd:lighttpd',
  openssl: 'cpe:2.3:a:openssl:openssl',
  express: 'cpe:2.3:a:openjsf:express',
};

const ALIAS = {
  httpd: 'apache',
  'apache-httpd': 'apache',
  iis: 'microsoft-iis',
  'microsoft-iis': 'microsoft-iis',
};

export const cpeFor = (name) => {
  const key = ALIAS[String(name || '').toLowerCase()] || String(name || '').toLowerCase();
  return CPE[key] || null;
};

export const sieveHosts = (names, domain) => {
  const suffix = `.${domain}`;
  return [
    ...new Set(
      (names || [])
        .filter((name) => typeof name === 'string')
        .map((name) => name.trim().toLowerCase().replace(/^\*\./, ''))
        .filter((name) => name && name !== domain && name.endsWith(suffix) && HOSTNAME_RE.test(name)),
    ),
  ].sort();
};

const certSpotter = async (domain, timeout, http) => {
  const token = process.env.CERTSPOTTER_TOKEN;
  const res = await http('https://api.certspotter.com/v1/issuances', {
    params: { domain, include_subdomains: 'true', expand: 'dns_names' },
    headers: { Accept: 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
    timeout,
  });
  if (!Array.isArray(res.data)) throw new Error('CertSpotter returned an unexpected response');
  return res.data.flatMap((row) => (Array.isArray(row?.dns_names) ? row.dns_names : []));
};

const crtSh = async (domain, timeout, http) => {
  const res = await http('https://crt.sh/', {
    params: { q: `%.${domain}`, output: 'json' },
    headers: { Accept: 'application/json' },
    timeout,
  });
  if (!Array.isArray(res.data)) throw new Error('crt.sh returned an unexpected response');
  return res.data.flatMap((row) => String(row?.name_value ?? '').split('\n'));
};

const hackerTarget = async (domain, timeout, http) => {
  const res = await http('https://api.hackertarget.com/hostsearch/', {
    params: { q: domain },
    timeout,
  });
  const body = typeof res.data === 'string' ? res.data : '';
  if (!body || /error|api count|quota/i.test(body)) throw new Error('HackerTarget unavailable');
  return body.split('\n').map((line) => line.split(',')[0]);
};

const SOURCES = [
  { name: 'CertSpotter', cite: 'https://sslmate.com/certspotter/', lookup: certSpotter },
  { name: 'crt.sh', cite: 'https://crt.sh/', lookup: crtSh },
  { name: 'HackerTarget', cite: 'https://hackertarget.com/hostsearch/', lookup: hackerTarget },
];

export const collectSubdomains = async (domain, deps = {}) => {
  const http = deps.httpGet || httpGet;
  const timeout = deps.timeout || 7000;
  const settled = await Promise.allSettled(
    SOURCES.map(async (source) => ({
      source: source.name,
      cite: source.cite,
      names: sieveHosts(await source.lookup(domain, timeout, http), domain),
    })),
  );
  const hosts = new Map();
  const sources = [];
  const errors = [];
  for (const item of settled) {
    if (item.status === 'rejected') {
      errors.push(item.reason?.message || 'source failed');
      continue;
    }
    sources.push(item.value.source);
    for (const name of item.value.names) {
      if (!hosts.has(name)) hosts.set(name, item.value.source);
    }
  }
  const list = [...hosts.entries()]
    .map(([host, source]) => ({ host, source }))
    .sort((a, b) => a.host.localeCompare(b.host));
  return {
    sources,
    citations: SOURCES.filter((source) => sources.includes(source.name)).map((source) => ({
      name: source.name,
      url: source.cite,
    })),
    hosts: list.slice(0, MAX_HOSTS),
    truncated: list.length > MAX_HOSTS,
    error: list.length || sources.length ? null : errors[0] || 'No passive subdomain source responded',
  };
};

const versionOf = (value) => {
  const match = /^(\d+(?:\.\d+){0,3})/.exec(String(value || ''));
  return match ? match[1] : null;
};

const fromProductToken = (value) => {
  const match = /^([A-Za-z][\w.+-]*)(?:\/(\d[\w.+-]*))?/.exec(String(value || '').trim());
  if (!match) return null;
  return { name: match[1], version: versionOf(match[2]) };
};

export const detectTechnologies = ({ headers = {}, html = '' } = {}) => {
  const found = [];
  const push = (name, version, source) => {
    const key = String(name || '').toLowerCase();
    if (!key || SKIP_PRODUCTS.has(key)) return;
    const alias = ALIAS[key] || key;
    if (found.some((item) => item.key === alias)) return;
    found.push({
      key: alias,
      name: alias === 'apache' ? 'Apache HTTP Server' : name,
      version: version || null,
      source,
      cpe: cpeFor(alias),
    });
  };
  for (const header of ['server', 'x-powered-by', 'x-aspnet-version']) {
    const token = fromProductToken(headers[header]);
    if (token) push(token.name, token.version, `${header} header`);
  }
  const generator = /<meta[^>]+name=["']generator["'][^>]*>/i.exec(html)?.[0] || '';
  const content = /content=["']([^"']+)["']/i.exec(generator)?.[1] || '';
  const named = /^([A-Za-z][\w.+!\- ]*?)[\s/]+(\d+(?:\.\d+){0,3})/.exec(content);
  if (named) push(named[1].replace(/!$/, ''), named[2], 'generator meta');
  const jquery = /jquery[.-](\d+\.\d+\.\d+)/i.exec(html);
  if (jquery) push('jQuery', jquery[1], 'script url on the page');
  return found;
};

const INTERESTING = [
  ['server', 'Server software disclosed', null],
  ['x-powered-by', 'Technology disclosed', null],
  ['strict-transport-security', 'HSTS observed', 'HSTS header not observed'],
  ['content-security-policy', 'Content-Security-Policy observed', 'Content-Security-Policy not observed'],
  ['x-frame-options', 'X-Frame-Options observed', 'X-Frame-Options not observed'],
  ['x-content-type-options', 'X-Content-Type-Options observed', 'X-Content-Type-Options not observed'],
  ['referrer-policy', 'Referrer-Policy observed', 'Referrer-Policy not observed'],
  ['permissions-policy', 'Permissions-Policy observed', 'Permissions-Policy not observed'],
];

export const headerNotes = (headers = {}) => {
  const interesting = [];
  const missing = [];
  for (const [name, presentNote, missingNote] of INTERESTING) {
    const value = headers[name];
    if (value) interesting.push({ name, value: String(value).slice(0, 180), note: presentNote });
    else if (missingNote) missing.push({ name, note: missingNote });
  }
  return { interesting, missing };
};

export const fetchPage = async (url, deps = {}) => {
  const http = deps.httpGet || httpGet;
  const response = await http(url, {
    timeout: deps.timeout || 12000,
    validateStatus: () => true,
    headers: deps.headers,
  });
  return {
    status: response.status,
    headers: response.headers || {},
    html: typeof response.data === 'string' ? response.data.slice(0, 500_000) : '',
    url: response.url || url,
  };
};

const SERVICE_NAMES = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  143: 'imap',
  443: 'https',
  587: 'submission',
  993: 'imaps',
  995: 'pop3s',
  3306: 'mysql',
  3389: 'rdp',
  8080: 'http-alt',
  8443: 'https-alt',
};

const resolveHost = async (host) => {
  const withTimeout = (promise) =>
    Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000)),
    ]).catch(() => []);
  const [v4, v6] = await Promise.all([
    withTimeout(dns.resolve4(host)),
    withTimeout(dns.resolve6(host)),
  ]);
  return [...v4, ...v6];
};

export const buildAttackSurface = async (url, deps = {}) => {
  const host = canonicalHost(url);
  const domain = domainOf(host);
  const page = deps.page || (await fetchPage(targetUrl(url), deps).catch((error) => ({ error: error.message, headers: {}, html: '' })));
  let subdomains = { hosts: [], sources: [], citations: [], truncated: false, error: null };
  if (!net.isIP(host)) {
    subdomains = await collectSubdomains(domain, deps);
  }
  const resolved = [];
  const slice = subdomains.hosts.slice(0, 15);
  for (let i = 0; i < slice.length; i += 5) {
    const group = slice.slice(i, i + 5);
    const found = await Promise.all(
      group.map(async (item) => ({
        ...item,
        addresses: deps.resolveHost ? await deps.resolveHost(item.host) : await resolveHost(item.host),
        dns: 'resolved',
      })),
    );
    resolved.push(...found);
  }
  const unresolved = subdomains.hosts.slice(15).map((item) => ({ ...item, addresses: [], dns: 'not-queried' }));
  const technologies = detectTechnologies(page);
  const headers = headerNotes(page.headers || {});
  let ports = { open: [], interesting: [], error: null };
  if (!deps.skipPorts) {
    try {
      const scan = deps.scanPorts || (await import('../ports.js')).default;
      const body = deps.scanPorts ? await scan(host) : await invoke(scan, targetUrl(url));
      const open = Array.isArray(body?.openPorts) ? body.openPorts : Array.isArray(body?.open) ? body.open : [];
      ports = {
        open,
        interesting: open
          .filter((port) => ![80, 443].includes(Number(port)))
          .map((port) => ({ port: Number(port), service: SERVICE_NAMES[port] || 'unknown' })),
        error: body?.error || null,
        note: 'Port list is the existing web-check common set, checked against the primary host only.',
      };
    } catch (error) {
      ports = { open: [], interesting: [], error: error.message };
    }
  }
  const result = {
    target: targetUrl(url),
    domain,
    scannedAt: new Date().toISOString(),
    hosts: [...resolved, ...unresolved],
    hostCount: subdomains.hosts.length,
    truncated: subdomains.truncated,
    subdomainSources: subdomains.sources,
    citations: subdomains.citations,
    subdomainError: subdomains.error,
    ports,
    headers,
    technologies,
    publishedEmails: extractEmails(page.html || '', domain),
    notes: [
      'Subdomains come from public Certificate Transparency and passive DNS datasets. No name brute force is performed.',
      'Port checks reuse the existing web-check common port list against the primary host only.',
    ],
  };
  return {
    ...result,
    ...cardFields(
      [
        `${result.hostCount} hostnames from passive sources`,
        result.ports.open?.length ? `Open ports: ${result.ports.open.join(', ')}` : 'No open common ports observed',
        result.technologies.length ? `Disclosed tech: ${result.technologies.map((item) => item.name).join(', ')}` : 'No product version disclosed in headers',
      ],
      result.hosts.slice(0, 20).map((item) => ({ label: item.host, value: item.source })),
      result.notes[0],
    ),
  };
};

export const extractEmails = (html, domain) => {
  const found = new Set();
  const matches = String(html || '').match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  for (const email of matches) {
    const normal = email.toLowerCase();
    const emailDomain = normal.split('@')[1];
    if (emailDomain === domain || emailDomain.endsWith(`.${domain}`)) found.add(normal);
    if (found.size >= 8) break;
  }
  return [...found];
};

export const targetUrl = (input) => {
  const host = canonicalHost(input);
  return net.isIP(host) ? `https://${host}` : `https://${host}`;
};

export const invoke = (handler, url, query = {}) =>
  new Promise((resolve, reject) => {
    const response = {
      statusCode: 200,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        resolve(body);
      },
    };
    Promise.resolve(handler({ query: { url, ...query }, url: '/api/internal' }, response)).catch(reject);
  });

export const SERVICE_NAMES_MAP = SERVICE_NAMES;
