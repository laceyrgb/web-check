import dns from 'dns/promises';
import net from 'net';
import { httpGet, APP_UA } from '../_common/http.js';
import { canonicalHost, cardFields } from './util.js';
import { targetUrl } from './hosts.js';

const CLOUDS = [
  [/amazon|aws|ec2/i, 'Amazon Web Services'],
  [/google(?![\w]* analytics)|gcp|google cloud/i, 'Google Cloud'],
  [/microsoft|azure/i, 'Microsoft Azure'],
  [/cloudflare/i, 'Cloudflare'],
  [/digitalocean/i, 'DigitalOcean'],
  [/akamai|linode/i, 'Akamai'],
  [/oracle/i, 'Oracle Cloud'],
  [/hetzner/i, 'Hetzner'],
  [/ovh/i, 'OVH'],
];

export const mapCloud = (org) => {
  const text = String(org || '');
  for (const [pattern, name] of CLOUDS) if (pattern.test(text)) return name;
  return null;
};

export const parseRoutingHistory = (payload) => {
  const events = [];
  for (const row of payload?.data?.by_origin || []) {
    for (const prefix of row.prefixes || []) {
      for (const timeline of prefix.timelines || []) {
        events.push({
          origin: row.origin || null,
          prefix: prefix.prefix || null,
          start: timeline.starttime || null,
          end: timeline.endtime || null,
        });
      }
    }
  }
  return events.slice(0, 20);
};

const resolveIp = async (host) => {
  if (net.isIP(host)) return host;
  const records = await dns.resolve4(host).catch(() => []);
  return records[0] || null;
};

export const networkExposure = async (url, deps = {}) => {
  const host = canonicalHost(url);
  const http = deps.httpGet || httpGet;
  const ip = deps.ip || (await resolveIp(host));
  if (!ip) {
    return {
      host,
      ip: null,
      note: 'The hostname did not resolve to an IP, so GeoIP, RDAP, and exposure lookups were skipped.',
      ...cardFields(['No IP resolved'], [], 'Exposure lookups need a public IP.'),
    };
  }
  const grab = async (name, fn) => {
    try {
      return { name, value: await fn() };
    } catch (error) {
      return { name, error: error.message };
    }
  };
  const jobs = await Promise.all([
    grab('geo', async () => {
      const response = await http(`https://ipwho.is/${ip}`, { timeout: 8000 });
      const data = response.data || {};
      if (data.success === false) throw new Error('geo provider returned no data');
      return {
        ip,
        city: data.city || null,
        country: data.country || null,
        org: data.connection?.org || data.connection?.isp || null,
        asn: data.connection?.asn || null,
        source: 'https://ipwho.is/',
      };
    }),
    grab('rdap', async () => {
      const response = await http(`https://rdap.org/ip/${ip}`, { timeout: 8000, headers: { accept: 'application/rdap+json' } });
      const data = response.data || {};
      const name = data.name || data.handle || null;
      return { name, handle: data.handle || null, start: data.startAddress || null, end: data.endAddress || null, source: 'https://rdap.org/' };
    }),
    grab('history', async () => {
      const response = await http(`https://stat.ripe.net/data/routing-history/data.json?resource=${ip}`, { timeout: 8000 });
      return {
        source: 'https://stat.ripe.net/data/routing-history',
        events: parseRoutingHistory(response.data),
        note: 'Public BGP visibility from RIPEstat. This is not a complete hosting ledger.',
      };
    }),
    grab('internetdb', async () => {
      const response = await http(`https://internetdb.shodan.io/${ip}`, { timeout: 8000, validateStatus: () => true });
      if (response.status === 404) return { status: 'none', ports: [], hostnames: [], vulns: [] };
      if (response.status >= 400) throw new Error(`InternetDB HTTP ${response.status}`);
      const data = response.data || {};
      return {
        status: 'ok',
        ports: data.ports || [],
        hostnames: data.hostnames || [],
        vulns: (data.vulns || []).slice(0, 15).map((id) => ({ id, url: `https://nvd.nist.gov/vuln/detail/${id}` })),
        source: 'https://internetdb.shodan.io/',
      };
    }),
    grab('ptr', () => dns.reverse(ip).catch(() => [])),
    grab('neighbors', async () => {
      const response = await http('https://api.hackertarget.com/reverseiplookup/', {
        params: { q: ip },
        timeout: 8000,
        validateStatus: () => true,
      });
      const body = typeof response.data === 'string' ? response.data : '';
      if (!body || /error|api count|quota|no records/i.test(body)) return [];
      return body.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 40);
    }),
  ]);
  const byName = Object.fromEntries(jobs.map((job) => [job.name, job]));
  const org = byName.geo.value?.org || byName.rdap.value?.name || '';
  const cloud = mapCloud(org);
  let shodan = { status: 'unset', note: 'SHODAN_API_KEY is not set. InternetDB public data is shown when it responds.' };
  if (process.env.SHODAN_API_KEY && !deps.skipShodan) {
    try {
      const response = await http(`https://api.shodan.io/shodan/host/${ip}`, {
        params: { key: process.env.SHODAN_API_KEY },
        timeout: 10000,
        headers: { 'user-agent': APP_UA },
      });
      const data = response.data || {};
      shodan = {
        status: 'ok',
        ports: data.ports || [],
        hostnames: data.hostnames || [],
        org: data.org || null,
        services: (data.data || []).slice(0, 12).map((row) => ({
          port: row.port,
          transport: row.transport,
          product: row.product || null,
          version: row.version || null,
        })),
        source: 'https://www.shodan.io/',
      };
    } catch {
      shodan = { status: 'unavailable', note: 'Shodan host lookup failed. The API key is not included in this message.' };
    }
  }
  let censys = { status: 'unset', note: 'Set CENSYS_API_TOKEN or CENSYS_API_ID and CENSYS_API_SECRET for a read-only host lookup.' };
  const token = process.env.CENSYS_API_TOKEN;
  const id = process.env.CENSYS_API_ID;
  const secret = process.env.CENSYS_API_SECRET;
  if ((token || (id && secret)) && !deps.skipCensys) {
    try {
      const response = token
        ? await http(`https://api.platform.censys.io/v3/global/asset/host/${ip}`, {
            timeout: 10000,
            headers: { Authorization: `Bearer ${token}`, accept: 'application/json' },
            validateStatus: () => true,
          })
        : await http(`https://search.censys.io/api/v2/hosts/${ip}`, {
            timeout: 10000,
            auth: { username: id, password: secret },
            validateStatus: () => true,
          });
      if (response.status >= 400) throw new Error(`HTTP ${response.status}`);
      const services = response.data?.result?.services || response.data?.services || response.data?.resource?.services || [];
      censys = {
        status: 'ok',
        services: (Array.isArray(services) ? services : []).slice(0, 12).map((row) => ({
          port: row.port || row.transport_port || null,
          protocol: row.protocol || row.transport_protocol || null,
          product: row.product || row.software?.[0]?.product || null,
        })),
        source: 'https://search.censys.io/',
      };
    } catch {
      censys = { status: 'unavailable', note: 'Censys host lookup failed. Credentials are not included in this message.' };
    }
  }
  const neighborSet = new Map();
  for (const name of byName.ptr.value || []) neighborSet.set(name, 'reverse DNS');
  for (const name of byName.internetdb.value?.hostnames || []) neighborSet.set(name, 'InternetDB');
  for (const name of byName.neighbors.value || []) neighborSet.set(name, 'HackerTarget reverse IP');
  const neighbors = [...neighborSet.entries()].slice(0, 40).map(([name, source]) => ({ host: name, source }));
  const result = {
    host,
    ip,
    geo: byName.geo.value || { error: byName.geo.error },
    rdap: byName.rdap.value || { error: byName.rdap.error },
    cloud,
    hostingHistory: byName.history.value || { error: byName.history.error },
    internetdb: byName.internetdb.value || { error: byName.internetdb.error },
    ptr: byName.ptr.value || [],
    neighbors,
    shodan,
    censys,
    target: targetUrl(url),
    note: 'Read-only queries against public GeoIP, RDAP, RIPEstat, InternetDB, and optional Shodan or Censys host APIs. No scan was submitted to those services.',
  };
  return {
    ...result,
    ...cardFields(
      [
        result.geo?.country ? `${ip} geolocates to ${[result.geo.city, result.geo.country].filter(Boolean).join(', ')}` : '',
        result.geo?.org ? `Network org: ${result.geo.org}` : '',
        cloud ? `Cloud heuristic: ${cloud}` : 'No cloud provider matched the public org string',
        `${neighbors.length} same-IP or reverse-DNS names`,
      ],
      neighbors.slice(0, 15).map((item) => ({ label: item.host, value: item.source })),
      result.note,
    ),
  };
};
