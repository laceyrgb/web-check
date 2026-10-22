import { APP_UA } from '../_common/http.js';
import { cpeFor } from './hosts.js';
import { cardFields } from './util.js';

const memory = new Map();
let chain = Promise.resolve();
let lastAt = 0;

const pace = async (ms) => {
  if (!ms) return;
  let release;
  const next = new Promise((resolve) => {
    release = resolve;
  });
  const run = chain.then(async () => {
    const wait = lastAt + ms - Date.now();
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    lastAt = Date.now();
  });
  chain = run.then(release, release);
  await run;
};

const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

export const normalizeCve = (item) => {
  const cve = item?.cve || item || {};
  const id = cve.id;
  if (!id) return null;
  const description = (cve.descriptions || []).find((row) => row.lang === 'en')?.value || '';
  const metrics = cve.metrics || {};
  const cvss = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
  return {
    id,
    severity: cvss?.cvssData?.baseSeverity || cvss?.baseSeverity || 'UNKNOWN',
    score: cvss?.cvssData?.baseScore ?? cvss?.baseScore ?? null,
    description: String(description).replace(/<[^>]*>/g, '').slice(0, 400),
    url: `https://nvd.nist.gov/vuln/detail/${id}`,
  };
};

export const lookupCves = async (products = [], deps = {}) => {
  const fetchImpl = deps.fetchImpl || fetch;
  const cache = deps.cache || memory;
  const paceMs = deps.paceMs ?? (process.env.NVD_API_KEY ? 700 : 6500);
  const findings = [];
  const skipped = [];
  let queries = 0;
  for (const product of products.slice(0, 8)) {
    const name = product?.name || product?.key;
    if (!name) continue;
    if (!product.version) {
      skipped.push({
        product: name,
        status: 'version-unknown',
        message: `Version was not disclosed for ${name}; CVE matching was skipped.`,
      });
      continue;
    }
    const cpe = product.cpe || cpeFor(name);
    if (!cpe) {
      skipped.push({
        product: name,
        version: product.version,
        status: 'unmapped',
        message: `No CPE mapping for ${name}; CVE matching was skipped to avoid unrelated results.`,
      });
      continue;
    }
    if (queries >= 3) {
      skipped.push({
        product: name,
        version: product.version,
        status: 'deferred',
        message: 'Deferred to stay inside the NVD rate limit. Set NVD_API_KEY for a higher quota.',
      });
      continue;
    }
    const virtual = `${cpe}:${product.version}:*:*:*:*:*:*:*`;
    const cached = cache.get(virtual);
    if (cached && cached.expires > Date.now()) {
      findings.push(...cached.value.map((row) => ({ ...row, product: name, version: product.version })));
      continue;
    }
    queries += 1;
    await pace(queries === 1 ? 0 : paceMs);
    try {
      const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
      url.searchParams.set('virtualMatchString', virtual);
      url.searchParams.set('resultsPerPage', '8');
      const response = await fetchImpl(url, {
        headers: {
          'user-agent': APP_UA,
          ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}),
        },
        signal: AbortSignal.timeout(deps.timeout || 15000),
      });
      if (!response.ok) throw new Error(`NVD HTTP ${response.status}`);
      const payload = await response.json();
      const rows = (payload.vulnerabilities || []).map(normalizeCve).filter(Boolean);
      rows.sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9));
      cache.set(virtual, { expires: Date.now() + 24 * 60 * 60 * 1000, value: rows });
      findings.push(...rows.map((row) => ({ ...row, product: name, version: product.version })));
      if ((payload.totalResults || 0) > rows.length) {
        skipped.push({
          product: name,
          version: product.version,
          status: 'truncated',
          message: `NVD reports ${payload.totalResults} CVEs; the first ${rows.length} are shown.`,
        });
      }
    } catch (error) {
      skipped.push({
        product: name,
        version: product.version,
        status: 'unavailable',
        message: `NVD lookup failed (${error.message}).`,
      });
    }
  }
  const result = {
    source: 'https://nvd.nist.gov/',
    degraded: skipped.some((row) => row.status === 'unavailable'),
    findings,
    skipped,
  };
  return {
    ...result,
    ...cardFields(
      [
        findings.length ? `${findings.length} CVEs matched a disclosed version` : 'No CVEs matched',
        skipped.some((row) => row.status === 'version-unknown') ? 'Some products had no version, so they were not matched' : '',
      ],
      findings.slice(0, 12).map((row) => ({
        label: row.id,
        value: `${row.severity} · ${row.product} ${row.version}`,
        href: row.url,
      })),
      'Matches use a public CPE and the version the site disclosed. An empty list is not proof the host is patched.',
    ),
  };
};
