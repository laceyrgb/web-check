import { readFileSync } from 'node:fs';
import https from 'node:https';

import { finding } from '../findings.js';
import { REFS } from '../refs.js';

export const INTEL_URLS = {
  nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  epss: 'https://api.first.org/data/v1/epss',
};

const INTEL_HOSTS = new Set(['services.nvd.nist.gov', 'www.cisa.gov', 'api.first.org']);

const SEVERITY = new Set(['critical', 'high', 'medium', 'low']);

export const assertIntelUrl = (urlString) => {
  const url = new URL(urlString);
  if (url.protocol !== 'https:' || !INTEL_HOSTS.has(url.hostname)) {
    throw new Error(`Refusing intel host ${url.hostname}`);
  }
  return url;
};

const versionParts = (version) => {
  const match = /^(\d+(?:\.\d+)*)([a-z])?$/i.exec(String(version).trim());
  if (!match) return null;
  return {
    numbers: match[1].split('.').map(Number),
    letter: (match[2] || '').toLowerCase(),
  };
};

const compareVersions = (left, right) => {
  const a = versionParts(left);
  const b = versionParts(right);
  if (!a || !b) return null;
  const length = Math.max(a.numbers.length, b.numbers.length);
  for (let i = 0; i < length; i += 1) {
    const delta = (a.numbers[i] || 0) - (b.numbers[i] || 0);
    if (delta !== 0) return delta;
  }
  if (a.letter === b.letter) return 0;
  if (!a.letter) return -1;
  if (!b.letter) return 1;
  return a.letter < b.letter ? -1 : 1;
};

const matchesItem = (item, version) => {
  if (Array.isArray(item.versions) && item.versions.includes(version)) return true;
  if (!item.below && !item.atLeast) return false;
  if (item.atLeast && compareVersions(version, item.atLeast) < 0) return false;
  if (item.below && compareVersions(version, item.below) >= 0) return false;
  return Boolean(item.below || item.atLeast);
};

const boosted = (item) => {
  let severity = SEVERITY.has(item.severity) ? item.severity : 'medium';
  let priority = 'standard';
  if (!item.kev && Number(item.epss) >= 0.1) {
    if (severity === 'low') severity = 'medium';
    else if (severity === 'medium') severity = 'high';
    else if (severity === 'high') severity = 'critical';
    priority = 'elevated';
  }
  if (item.kev) {
    severity = 'critical';
    priority = 'immediate';
  }
  return { severity, priority };
};

const cpeVersion = (criteria) => {
  const parts = String(criteria || '').split(':');
  if (parts.length < 6 || parts[5] === '*' || parts[5] === '-') return null;
  const product = parts[4] === 'http_server' ? 'apache' : parts[4];
  return { product, version: parts[5] };
};

const baseSeverity = (cve) => {
  const groups = cve?.metrics || {};
  const metric =
    groups.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
    groups.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
    '';
  const severity = String(metric).toLowerCase();
  return SEVERITY.has(severity) ? severity : 'medium';
};

// Turn public NVD, KEV, and EPSS payloads into the cache shape. No network here.
export const normaliseIntel = ({ nvd, kev, epss }) => {
  const kevIds = new Set((kev?.vulnerabilities || []).map((row) => row.cveID));
  const epssById = new Map((epss?.data || []).map((row) => [row.cve, Number(row.epss)]));
  const items = [];
  for (const row of nvd?.vulnerabilities || []) {
    const cve = row.cve || row;
    const id = cve.id;
    if (!id) continue;
    const versions = [];
    let product = '';
    for (const config of cve.configurations || []) {
      for (const node of config.nodes || []) {
        for (const match of node.cpeMatch || []) {
          if (!match.vulnerable) continue;
          const parsed = cpeVersion(match.criteria);
          if (!parsed) continue;
          product = product || parsed.product;
          versions.push(parsed.version);
        }
      }
    }
    if (!product || !versions.length) continue;
    items.push({
      cve: id,
      findingId: `tech.cve.${id.toLowerCase()}`,
      product,
      versions: [...new Set(versions)],
      severity: baseSeverity(cve),
      kev: kevIds.has(id),
      epss: epssById.get(id) ?? 0,
      title: `${id} matches a banner version`,
      titleAr: `${id} يطابق إصدارًا في اللافتة`,
      remediation:
        'Patch the affected product and confirm the running build. This is a version match. No exploit was sent.',
      remediationAr:
        'رقِّ المنتج المتأثر وتأكد من البناء الذي يعمل. هذا تطابق إصدار. لم يُرسل استغلال.',
    });
  }
  return { schema: 'cormorant-intel-v1', items };
};

export const loadDefaultCache = () =>
  JSON.parse(readFileSync(new URL('./cache.json', import.meta.url), 'utf8'));

export const matchProduct = (product, version, source, items = loadDefaultCache().items) => {
  const name = String(product || '').toLowerCase();
  const ver = String(version || '').trim();
  if (!name || !ver) return [];
  const out = [];
  for (const item of items) {
    if (!name.includes(item.product)) continue;
    if (!matchesItem(item, ver)) continue;
    const { severity, priority } = boosted(item);
    out.push(
      finding({
        id: item.findingId,
        title: item.title,
        titleAr: item.titleAr,
        severity,
        evidence: `${source}: ${item.product} ${ver}. ${item.cve}. CISA KEV: ${item.kev ? 'yes' : 'no'}. EPSS: ${item.epss}. Banner match only; no exploit payload was sent.`,
        remediation: item.remediation,
        remediationAr: item.remediationAr,
        references: [
          { title: item.cve, url: `https://nvd.nist.gov/vuln/detail/${item.cve}` },
          REFS.kev,
          REFS.epss,
        ],
        service: 'vulnerability',
        needsHumanReview: true,
        impact: 'high',
        effort: priority === 'immediate' ? 'medium' : 'low',
        priority,
      }),
    );
  }
  return out;
};

export const httpsGetJson = (url) =>
  new Promise((resolve, reject) => {
    assertIntelUrl(url);
    const req = https.get(url, { timeout: 15000 }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('intel request timed out'));
    });
  });

export const fetchIntel = async (httpGet) => {
  const read = async (url) => {
    assertIntelUrl(url);
    const response = await httpGet(url);
    return JSON.parse(response.body);
  };
  return normaliseIntel({
    nvd: await read(INTEL_URLS.nvd),
    kev: await read(INTEL_URLS.kev),
    epss: await read(INTEL_URLS.epss),
  });
};
