import dns from 'dns/promises';
import { canonicalHost, domainOf } from './util.js';
import { buildAttackSurface, extractEmails, fetchPage, targetUrl } from './hosts.js';
import { lookupCves } from './cve.js';
import { checkEmailBreaches } from './breach.js';
import { networkExposure } from './exposure.js';
import { checkLookalikes } from './lookalike.js';
import { publicMentions } from './mentions.js';
import { observePosture } from './posture.js';
import {
  auditPrivacy,
  fetchPeople,
  fingerprintCms,
  inspectBuckets,
  listPeopleFromPage,
} from './content.js';
import { buildExecutiveSummary, scoreRisk } from './risk.js';
import { buildDossier } from './dossier.js';
import { collectPublicRecords } from './records.js';

const sorted = (values) => [...(values || [])].map(String).sort();

export const readDns = async (host) => {
  const domain = domainOf(host);
  const safe = (promise) => promise.catch(() => []);
  const [A, NS, MX] = await Promise.all([
    safe(dns.resolve4(host)),
    safe(dns.resolveNs(domain)),
    safe(dns.resolveMx(domain)),
  ]);
  return { A: sorted(A), NS: sorted(NS), MX: sorted(MX.map((row) => row.exchange)) };
};

export const executeScan = async (target, opts = {}) => {
  const deps = opts.deps || {};
  const href = targetUrl(target);
  const errors = [];
  const guard = async (name, fn) => {
    try {
      return await fn();
    } catch (error) {
      errors.push({ section: name, message: error.message });
      return { error: error.message };
    }
  };
  const page = await guard('page', () => (deps.page ? deps.page : fetchPage(href, deps)));
  const pageOk = page && !page.error ? page : { headers: {}, html: '', status: null };
  const domainHint = domainOf(canonicalHost(href));
  const [attackSurface, exposure, lookalikes, mentions, posture, dnsSnapshot, records] =
    await Promise.all([
      guard('attackSurface', () =>
        buildAttackSurface(href, { ...deps, page: pageOk, skipPorts: opts.skipPorts }),
      ),
      guard('exposure', () => networkExposure(href, deps)),
      guard('lookalikes', () => checkLookalikes(href, deps)),
      guard('mentions', () => publicMentions(href, deps)),
      guard('posture', () => observePosture(href, { ...deps, page: pageOk })),
      guard('dns', () => (deps.dns ? deps.dns : readDns(canonicalHost(href)))),
      guard('records', () =>
        collectPublicRecords({ html: pageOk.html || '', href, domain: domainHint }, deps),
      ),
    ]);
  const technologies = attackSurface?.technologies || [];
  const [cves, breaches, cms, buckets, people] = await Promise.all([
    guard('cves', () => lookupCves(technologies, deps)),
    guard('breaches', () =>
      checkEmailBreaches(href, {
        ...deps,
        email: opts.email,
        page: pageOk,
        pageEmails: extractEmails(pageOk.html || '', attackSurface?.domain),
        skipPageFetch: true,
      }),
    ),
    guard('cms', () => fingerprintCms(pageOk.html || '', deps)),
    guard('buckets', () => inspectBuckets(pageOk.html || '', deps)),
    guard('people', async () => {
      const listed = listPeopleFromPage(pageOk.html || '', href);
      const fetched = opts.publicUrls?.length
        ? await fetchPeople(opts.publicUrls, deps)
        : { people: [], graph: { nodes: [], edges: [] } };
      return { ...fetched, people: [...listed, ...(fetched.people || [])], note: fetched.note };
    }),
  ]);
  const privacy = auditPrivacy(pageOk.html || '', href, pageOk.headers || {});
  const domain = attackSurface?.domain || domainHint;
  const dossier = await guard('dossier', () =>
    buildDossier(
      {
        html: pageOk.html || '',
        domain,
        host: canonicalHost(href),
        href,
        report: {
          attackSurface,
          exposure,
          breaches: breaches?.error ? null : breaches,
          people: people?.error ? null : people,
          dns: dnsSnapshot?.error ? null : dnsSnapshot,
          posture: posture?.error ? null : posture,
        },
      },
      deps,
    ),
  );
  if (dossier && !dossier.error && breaches && !breaches.error) {
    const seen = new Set((breaches.emails || []).map((row) => row.email));
    for (const row of dossier.breachRows || []) {
      if (row?.email && !seen.has(row.email)) breaches.emails.push(row);
    }
  }
  const scannedAt = new Date().toISOString();
  const report = {
    target: href,
    hostname: canonicalHost(href),
    scannedAt,
    attackSurface,
    cves,
    breaches,
    exposure,
    lookalikes,
    mentions,
    posture,
    cms,
    privacy,
    buckets,
    people,
    records: records?.error ? { error: records.error } : records,
    dossier: dossier?.error ? { error: dossier.error } : dossier,
    dns: dnsSnapshot?.error ? null : dnsSnapshot,
    sectionErrors: errors,
    partial: errors.length > 0,
  };
  report.risk = scoreRisk(report);
  report.executiveSummary = buildExecutiveSummary(report);
  return report;
};
