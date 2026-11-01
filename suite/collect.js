import { registrableDomain } from './domain.js';
import { CORS_PROBE_ORIGIN } from './checks/cors.js';
import { EXPOSED_PATHS, classifyExposure } from './checks/exposed-files.js';
import { ACTIVE_PORT_LIST } from './checks/ports.js';

const DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'k2',
  's1',
  's2',
  'dkim',
  'mail',
];

const emptyDns = (error) => ['ENOTFOUND', 'ENODATA', 'ENOTIMP', 'EBADNAME'].includes(error?.code);

const joinTxt = (rows) =>
  (Array.isArray(rows) ? rows : []).map((row) => (Array.isArray(row) ? row.join('') : String(row)));

const txt = async (transports, name) => {
  try {
    return joinTxt(await transports.resolveTxt(name));
  } catch (error) {
    if (emptyDns(error)) return [];
    throw error;
  }
};

const optionalList = async (fn) => {
  try {
    const rows = await fn();
    return rows || [];
  } catch (error) {
    if (emptyDns(error)) return [];
    throw error;
  }
};

const resolves = async (transports, name) => {
  if (typeof transports.resolve4 !== 'function' || !name || name === '.') return undefined;
  try {
    const rows = await transports.resolve4(name);
    return Array.isArray(rows) && rows.length > 0;
  } catch (error) {
    if (emptyDns(error)) return false;
    return undefined;
  }
};

const parsePolicy = (body) => {
  const policy = { mx: [], valid: false };
  let version;
  for (const line of String(body || '').split('\n')) {
    const [key, ...rest] = line.split(':');
    const value = rest.join(':').trim();
    const name = key.trim().toLowerCase();
    if (name === 'version') version = value;
    if (name === 'mode') policy.mode = value;
    if (name === 'mx') policy.mx.push(value.replace(/\.$/, ''));
    if (name === 'max_age') policy.maxAge = Number(value);
  }
  policy.valid = version === 'STSv1' && ['enforce', 'testing', 'none'].includes(policy.mode);
  return policy;
};

export const collectDns = async (hostname, transports) => {
  const domain = hostname.toLowerCase();
  const org = registrableDomain(domain);
  const names = [
    domain,
    `_dmarc.${domain}`,
    `_dmarc.${org}`,
    `default._bimi.${domain}`,
    `_smtp._tls.${domain}`,
    `_mta-sts.${domain}`,
    ...DKIM_SELECTORS.map((selector) => `${selector}._domainkey.${domain}`),
  ];
  const unique = [...new Set(names)];
  const txtRows = {};
  for (const name of unique) txtRows[name] = await txt(transports, name);
  const mx =
    typeof transports.resolveMx === 'function'
      ? await optionalList(() => transports.resolveMx(domain))
      : [];
  const ns =
    typeof transports.resolveNs === 'function'
      ? await optionalList(() => transports.resolveNs(domain))
      : undefined;
  let caa;
  if (typeof transports.resolveCaa === 'function') {
    const rows = await optionalList(() => transports.resolveCaa(domain));
    caa = rows.map((row) => row.issue || row.issuewild || row.iodef || JSON.stringify(row));
  }
  let dnssec;
  if (typeof transports.resolveType === 'function') {
    const ds = await optionalList(() => transports.resolveType(domain, 'DS'));
    const dnskey = await optionalList(() => transports.resolveType(domain, 'DNSKEY'));
    dnssec = { ds: ds.length > 0, dnskey: dnskey.length > 0 };
  }
  const mxResolves = {};
  for (const row of mx) {
    const exchange = String(row.exchange || '')
      .replace(/\.$/, '')
      .toLowerCase();
    if (!exchange || exchange === '.') continue;
    const answer = await resolves(transports, exchange);
    if (answer !== undefined) mxResolves[exchange] = answer;
  }
  const nsResolves = {};
  if (Array.isArray(ns)) {
    for (const name of ns) {
      const host = String(name).replace(/\.$/, '').toLowerCase();
      const answer = await resolves(transports, host);
      if (answer !== undefined) nsResolves[host] = answer;
    }
  }
  let mtaSts;
  const mtaRecord = (txtRows[`_mta-sts.${domain}`] || []).find((row) =>
    row.toLowerCase().startsWith('v=stsv1'),
  );
  if (mtaRecord && typeof transports.httpGet === 'function') {
    try {
      const response = await transports.httpGet(
        `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
      );
      mtaSts = response?.status === 200 ? parsePolicy(response.body) : { valid: false, mx: [] };
    } catch {
      mtaSts = { valid: false, mx: [] };
    }
  }
  const dkim = [];
  for (const selector of DKIM_SELECTORS) {
    const rows = txtRows[`${selector}._domainkey.${domain}`] || [];
    for (const record of rows) {
      if (/p=/i.test(record)) dkim.push({ selector, record });
    }
  }
  return {
    txt: txtRows,
    mx,
    ns,
    caa,
    dnssec,
    mxResolves,
    nsResolves,
    mtaSts,
    dkim,
  };
};

const lowerHeaders = (headers = {}) =>
  Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));

export const collectHttp = async (origin, transports) => {
  const response = await transports.httpGet(origin);
  const headers = lowerHeaders(response?.headers);
  let scheme;
  try {
    scheme = new URL(response?.finalUrl || origin).protocol.replace(':', '');
  } catch {
    scheme = undefined;
  }
  return {
    status: response?.status,
    scheme,
    headers,
    bodySnippet: String(response?.body || '').slice(0, 100000),
  };
};

export const collectActive = async ({ origin, hostname, transports }) => {
  const exposed = [];
  if (typeof transports.httpGet === 'function') {
    for (const rule of EXPOSED_PATHS) {
      try {
        const response = await transports.httpGet(`${origin}${rule.path}`);
        const match = classifyExposure(rule.path, response?.status, response?.body || '');
        if (match) {
          const { test, ...rest } = match;
          exposed.push(rest);
        }
      } catch {
        // A single path timing out does not fail the scan.
      }
    }
  }
  let corsProbe;
  if (typeof transports.httpGet === 'function') {
    try {
      const response = await transports.httpGet(origin, { headers: { Origin: CORS_PROBE_ORIGIN } });
      const headers = lowerHeaders(response?.headers);
      const allow = headers['access-control-allow-origin'];
      corsProbe = {
        originSent: CORS_PROBE_ORIGIN,
        allowOrigin: Array.isArray(allow) ? allow[0] : allow || '',
        allowCredentials: /^true$/i.test(String(headers['access-control-allow-credentials'] || '')),
      };
    } catch {
      corsProbe = undefined;
    }
  }
  const openPorts = [];
  if (typeof transports.connect === 'function') {
    for (const port of ACTIVE_PORT_LIST) {
      try {
        if (await transports.connect(port, hostname)) openPorts.push(port);
      } catch {
        // Closed, filtered, or refused. Absence is not a finding.
      }
    }
  }
  return { exposed, corsProbe, openPorts };
};

export const collectPassive = async ({ hostname, origin, transports }) => {
  const observations = {};
  if (typeof transports.resolveTxt === 'function') {
    try {
      observations.dns = await collectDns(hostname, transports);
    } catch (error) {
      observations.dns = { error: error.message || 'DNS lookup failed' };
    }
  }
  if (typeof transports.httpGet === 'function') {
    try {
      observations.http = await collectHttp(origin, transports);
    } catch (error) {
      observations.httpError = error.message || 'HTTP fetch failed';
    }
  }
  if (typeof transports.inspectTls === 'function') {
    try {
      observations.tls = await transports.inspectTls(hostname);
    } catch (error) {
      observations.tlsError = error.message || 'TLS handshake failed';
    }
  }
  if (typeof transports.ctLookup === 'function') {
    try {
      observations.ctNames = await transports.ctLookup(registrableDomain(hostname));
      if (!Array.isArray(observations.ctNames)) observations.ctNames = [];
    } catch (error) {
      observations.ctError = error.message || 'Certificate transparency lookup failed';
    }
  }
  return observations;
};
