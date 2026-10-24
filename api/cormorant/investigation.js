// An investigation starts from one host, pivots across the organisation's own footprint,
// and merges every host's results into one dossier with confidence, sources, and gaps.
// Pivots stay on the same registrable domain. Hosts on other domains are listed, not scanned.
import { sieveHosts } from './hosts.js';
import { updateInventory } from './inventory.js';

export const INVESTIGATION_HOST_CAP = 12;
export const REUSE_WINDOW_MS = 24 * 60 * 60 * 1000;

// Names an analyst opens first: remote access, mail, identity, admin, and pre-production.
const PRIORITY = [
  ['vpn', 'remote access'],
  ['remote', 'remote access'],
  ['citrix', 'remote access'],
  ['rdp', 'remote access'],
  ['mail', 'mail'],
  ['webmail', 'mail'],
  ['owa', 'mail'],
  ['autodiscover', 'mail'],
  ['smtp', 'mail'],
  ['exchange', 'mail'],
  ['sso', 'identity'],
  ['login', 'identity'],
  ['auth', 'identity'],
  ['id', 'identity'],
  ['adfs', 'identity'],
  ['admin', 'administration'],
  ['portal', 'administration'],
  ['cpanel', 'administration'],
  ['intranet', 'administration'],
  ['api', 'application interface'],
  ['dev', 'pre-production'],
  ['staging', 'pre-production'],
  ['stage', 'pre-production'],
  ['test', 'pre-production'],
  ['uat', 'pre-production'],
  ['beta', 'pre-production'],
  ['demo', 'pre-production'],
  ['git', 'source control'],
  ['gitlab', 'source control'],
  ['jenkins', 'build system'],
  ['ci', 'build system'],
  ['ftp', 'file transfer'],
  ['sftp', 'file transfer'],
  ['files', 'file transfer'],
  ['backup', 'backups'],
  ['db', 'database'],
  ['sql', 'database'],
  ['www', 'main site'],
  ['app', 'application'],
  ['shop', 'commerce'],
  ['pay', 'commerce'],
  ['billing', 'commerce'],
  ['support', 'support'],
  ['help', 'support'],
  ['status', 'status page'],
];

const priorityOf = (host) => {
  const label = String(host).split('.')[0].replace(/\d+$/, '');
  const index = PRIORITY.findIndex(([name]) => name === label);
  return index === -1
    ? { rank: PRIORITY.length, reason: 'passive source' }
    : { rank: index, reason: PRIORITY[index][1] };
};

const underDomain = (host, domain) => host === domain || host.endsWith(`.${domain}`);

export const pivotHosts = (root = {}, { domain, host, cap = INVESTIGATION_HOST_CAP } = {}) => {
  const limit = Math.max(
    1,
    Math.min(INVESTIGATION_HOST_CAP, Number(cap) || INVESTIGATION_HOST_CAP),
  );
  const sources = new Map();
  const note = (name, source) => {
    if (typeof name !== 'string') return;
    const key = name.trim().toLowerCase().replace(/^\*\./, '');
    if (!key) return;
    const set = sources.get(key) || new Set();
    set.add(source);
    sources.set(key, set);
  };
  for (const item of root.attackSurface?.hosts || []) note(item.host, item.source || 'passive-dns');
  for (const name of root.records?.certificates?.names || []) note(name, 'certificate-log');
  for (const name of root.dns?.MX || []) note(String(name).replace(/^\d+\s+/, ''), 'mx');
  for (const neighbor of root.exposure?.neighbors || [])
    note(neighbor.host, neighbor.source || 'same-ip');
  const inScope = sieveHosts([...sources.keys()], domain).filter((name) => name !== host);
  const related = [...sources.keys()]
    .filter((name) => !underDomain(name, domain) && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(name))
    .map((name) => ({ host: name, source: [...sources.get(name)].join(', ') }))
    .slice(0, 20);
  const ranked = inScope
    .map((name) => ({ host: name, ...priorityOf(name), sources: [...sources.get(name)] }))
    .sort((a, b) => a.rank - b.rank || a.host.localeCompare(b.host));
  return {
    selected: ranked.slice(0, limit).map(({ host: name, reason, sources: from }) => ({
      host: name,
      reason,
      sources: from,
    })),
    held: ranked.slice(limit).map((row) => row.host),
    related,
    cap: limit,
  };
};

const letterOf = (score) => {
  if (score == null) return 'n/a';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
};

// Facts that belong to one host: the same value seen from two hosts is two observations.
// Everything else (hostnames, lookalikes, mail policy, people, registrant data) is looked up
// for the registrable domain, so repeating it from another host adds nothing.
const HOST_SCOPED_FACTS = new Set([
  'ip',
  'service',
  'tech',
  'cve',
  'local-path',
  'hosting',
  'cloud',
]);
// Risk factors scored against the domain rather than the host that reported them.
const DOMAIN_SCOPED_FINDINGS = new Set([
  'lookalike',
  'breach',
  'leak-index',
  'mail',
  'certificate',
]);

const confidenceOf = (kind, evidence) => {
  const distinct = new Set(
    evidence.map((row) => (HOST_SCOPED_FACTS.has(kind) ? `${row.host}|${row.source}` : row.source)),
  ).size;
  if (distinct >= 3) return 'high';
  if (distinct === 2) return 'medium';
  return 'low';
};

const findingKey = (owner, factor) =>
  `${owner}|${factor.source}|${factor.id || factor.detail || factor.action || ''}`.slice(0, 200);

export const consolidate = ({
  target,
  domain,
  hostname,
  scans = [],
  plan = {},
  reused = [],
  startedAt,
  notes = null,
} = {}) => {
  const complete = scans.filter((scan) => scan.status === 'complete' && scan.results);
  const failed = scans.filter((scan) => scan.status === 'failed');
  const facts = new Map();
  const add = (kind, value, host, source, extra = {}) => {
    if (value == null || value === '') return;
    const text = String(value).trim();
    if (!text) return;
    const key = `${kind}:${text.toLowerCase()}`;
    const row = facts.get(key) || { kind, value: text, evidence: [], ...extra };
    row.evidence.push({ host, source: source || 'scan' });
    Object.assign(row, extra);
    facts.set(key, row);
  };
  const findingRows = new Map();
  for (const scan of complete) {
    const r = scan.results;
    const host = scan.hostname;
    const inventory = updateInventory(null, r, r.scannedAt);
    for (const item of Object.values(inventory.items || {}))
      add(item.kind, item.value, host, item.source);
    for (const person of r.dossier?.people || [])
      add('person', person.name, host, person.source, { onPage: Boolean(person.onPage) });
    for (const key of r.dossier?.publicKeys || []) add('pgp', key.email, host, key.source);
    if (r.dossier?.mailProvider) add('mail-provider', r.dossier.mailProvider, host, 'dns');
    if (r.dossier?.hostingOrg) add('hosting', r.dossier.hostingOrg, host, 'rdap');
    if (r.dossier?.cloud) add('cloud', r.dossier.cloud, host, 'rdap');
    for (const ns of r.dossier?.nameservers || []) add('nameserver', ns, host, 'dns');
    for (const item of r.dossier?.news || []) add('news', item.title || item.url, host, 'news');
    for (const finding of r.cves?.findings || [])
      add('cve', finding.id, host, 'nvd', { severity: finding.severity });
    for (const cve of r.cms?.cves || []) add('cve', cve.id, host, 'cms-fingerprint');
    for (const row of r.breaches?.emails || []) {
      if (row.breaches?.length)
        add('breach', row.email, host, r.breaches.source || 'breach-index', {
          detail: row.breaches.map((item) => item.name).join(', '),
        });
    }
    for (const leak of r.mentions?.leaks || []) add('leak', leak.url, host, 'leak-index');
    for (const name of r.lookalikes?.live || []) add('lookalike', name, host, 'dns');
    for (const cert of r.records?.certificates?.expiring || [])
      add(
        'cert-expiring',
        `${(cert.names || []).join(' ')} ${cert.notAfter || ''}`.trim(),
        host,
        'certificate-log',
      );
    for (const doc of r.records?.documents || []) {
      for (const localPath of doc.localPaths || [])
        add('local-path', localPath, host, 'published-file');
    }
    if (r.records?.mail) {
      const mail = r.records.mail;
      add(
        'mail-policy',
        `SPF ${mail.spf?.qualifier || 'absent'}, DMARC ${mail.dmarc?.policy || 'absent'}`,
        host,
        'dns',
      );
    }
    for (const factor of r.risk?.factors || []) {
      const domainLevel = DOMAIN_SCOPED_FINDINGS.has(factor.source);
      const owner = domainLevel ? domain : host;
      const key = findingKey(owner, factor);
      const row = findingRows.get(key) || {
        key,
        host: owner,
        hosts: [],
        source: factor.source,
        detail: factor.detail || factor.id || '',
        points: factor.points || 0,
        action: factor.action || null,
        scope: domainLevel ? 'domain' : 'host',
      };
      if (!row.hosts.includes(host)) row.hosts.push(host);
      findingRows.set(key, row);
    }
  }
  const findings = [...findingRows.values()];
  const factList = [...facts.values()]
    .map((row) => ({
      ...row,
      confidence:
        row.kind === 'person' && !row.onPage ? 'low' : confidenceOf(row.kind, row.evidence),
      hosts: [...new Set(row.evidence.map((item) => item.host))],
      sources: [...new Set(row.evidence.map((item) => item.source))],
    }))
    .sort(
      (a, b) =>
        ['high', 'medium', 'low'].indexOf(a.confidence) -
          ['high', 'medium', 'low'].indexOf(b.confidence) ||
        a.kind.localeCompare(b.kind) ||
        a.value.localeCompare(b.value),
    );
  const dispositions = notes?.dispositions || {};
  for (const finding of findings) finding.disposition = dispositions[finding.key] || 'open';
  findings.sort((a, b) => b.points - a.points || a.host.localeCompare(b.host));

  const perHost = complete.map((scan) => ({
    host: scan.hostname,
    scanId: scan.id,
    score: scan.results.risk?.score ?? null,
    letter: scan.results.risk?.letter || 'n/a',
    reused: reused.includes(scan.hostname),
  }));
  const scored = perHost.filter((row) => typeof row.score === 'number');
  const min = scored.length ? Math.min(...scored.map((row) => row.score)) : null;
  const mean = scored.length
    ? Math.round(scored.reduce((sum, row) => sum + row.score, 0) / scored.length)
    : null;
  const orgScore = scored.length ? Math.round(0.6 * min + 0.4 * mean) : null;
  const weakest = scored.slice().sort((a, b) => a.score - b.score)[0] || null;

  const gaps = [];
  const gap = (title, why, next) => gaps.push({ gap: title, why, next });
  const emails = factList.filter((row) => row.kind === 'email');
  const org = factList.find((row) => row.kind === 'org');
  const people = factList.filter((row) => row.kind === 'person');
  const rootResults = complete.find((scan) => scan.hostname === hostname)?.results;
  if (!emails.length)
    gap(
      'No contact email',
      `No published or registered email was found across ${complete.length} host(s).`,
      'Read the organisation\u2019s contact page and the registrar record by hand. Do not query a people-search site.',
    );
  if (!org)
    gap(
      'No organisation name',
      'RDAP and certificate records did not carry a usable organisation name, or the registrant is redacted.',
      'Confirm the legal entity with the client. Company registry lookups are outside this tool.',
    );
  if (!people.some((row) => row.onPage))
    gap(
      'No corroborated people',
      'No person named in public records also appears on the organisation\u2019s own pages.',
      'Treat any name in this report as unconfirmed.',
    );
  if (rootResults && !(rootResults.attackSurface?.hosts || []).length)
    gap(
      'No subdomains from passive sources',
      'Certificate logs and passive DNS listed no hosts under the domain. Wildcard certificates or a short history can cause this.',
      'Harvest the main page under Link list, or ask the client for an asset list.',
    );
  if (plan.held?.length)
    gap(
      `${plan.held.length} in-scope host(s) held`,
      `The host cap of ${plan.cap || INVESTIGATION_HOST_CAP} was reached.`,
      `Start a second investigation for ${plan.held.slice(0, 3).join(', ')}${plan.held.length > 3 ? ', and the rest' : ''}.`,
    );
  if (plan.related?.length)
    gap(
      `${plan.related.length} related host(s) on other domains`,
      'They share infrastructure with the target but are not under the same registrable domain, so they were not scanned.',
      'Add them only with the client\u2019s written confirmation that they are in scope.',
    );
  for (const scan of failed)
    gap(
      `Scan of ${scan.hostname} failed`,
      scan.error || 'Unknown error',
      'Queue the host again from Link list.',
    );
  const moduleErrors = new Map();
  for (const scan of complete) {
    for (const error of scan.results.sectionErrors || []) {
      const key = error.section;
      const row = moduleErrors.get(key) || { hosts: [], message: error.message };
      row.hosts.push(scan.hostname);
      moduleErrors.set(key, row);
    }
  }
  for (const [section, row] of moduleErrors)
    gap(
      `Module ${section} returned no data`,
      `${row.message} (${row.hosts.length} host(s))`,
      'Re-run after the source recovers. Missing data is not scored.',
    );

  const counts = {
    cves: factList.filter((row) => row.kind === 'cve').length,
    breachedEmails: factList.filter((row) => row.kind === 'breach').length,
    leaks: factList.filter((row) => row.kind === 'leak').length,
    lookalikesLive: factList.filter((row) => row.kind === 'lookalike').length,
    expiringCertificates: factList.filter((row) => row.kind === 'cert-expiring').length,
    hosts: factList.filter((row) => row.kind === 'host').length,
    emails: emails.length,
    people: people.length,
  };
  const narrative = [];
  narrative.push(
    `Investigation of ${domain} covered ${complete.length} of ${scans.length} host(s). ${reused.length} result(s) were reused from scans completed in the last 24 hours. ${plan.held?.length || 0} in-scope host(s) were held by the cap.`,
  );
  narrative.push(
    org
      ? `The organisation behind the domain reads as ${org.value} (${org.sources.join(', ')}; confidence ${org.confidence}).`
      : 'No organisation name could be read from public registration or certificate records.',
  );
  const provider = factList.find((row) => row.kind === 'mail-provider');
  const hosting = factList.find((row) => row.kind === 'hosting');
  const cloud = factList.find((row) => row.kind === 'cloud');
  if (provider || hosting)
    narrative.push(
      `Mail is handled by ${provider?.value || 'an unidentified provider'}; hosting is ${hosting?.value || 'unidentified'}${cloud ? ` on ${cloud.value}` : ''}.`,
    );
  narrative.push(
    `${counts.hosts} hostname(s), ${counts.emails} email address(es), and ${counts.people} person name(s) were collected; ${people.filter((row) => row.onPage).length} name(s) also appear on the organisation\u2019s own pages.`,
  );
  if (weakest)
    narrative.push(
      `The weakest host is ${weakest.host} at ${weakest.score} (${weakest.letter}). The organisation score is ${orgScore} (${letterOf(orgScore)}), weighted toward the weakest host.`,
    );
  if (findings.length)
    narrative.push(
      `The highest-weighted findings are ${findings
        .slice(0, 3)
        .map((row) => `${row.source} ${row.detail} on ${row.host} (${row.points})`)
        .join('; ')}.`,
    );
  narrative.push(
    `Across hosts: ${counts.cves} CVE(s), ${counts.breachedEmails} breached address(es), ${counts.leaks} leak-index link(s), ${counts.lookalikesLive} live lookalike(s), ${counts.expiringCertificates} certificate(s) expiring within 30 days.`,
  );
  narrative.push(
    plan.held?.length
      ? 'Collection stopped at the host cap.'
      : 'Collection stopped when every in-scope host from passive sources had been covered.',
  );
  return {
    target,
    domain,
    generatedAt: new Date().toISOString(),
    startedAt: startedAt || null,
    coverage: {
      requested: scans.length,
      scanned: complete.length,
      reused: reused.length,
      failed: failed.length,
      held: plan.held || [],
      related: plan.related || [],
      selected: plan.selected || [],
    },
    risk: { score: orgScore, letter: letterOf(orgScore), min, mean, perHost },
    facts: factList.map(({ evidence, ...row }) => ({ ...row, evidence: evidence.slice(0, 12) })),
    findings,
    gaps,
    counts,
    narrative,
    analystSummary: notes?.summary || null,
    notesUpdatedAt: notes?.updatedAt || null,
    note: 'Every host scanned is under the same registrable domain as the target. Confidence counts the distinct sources behind a fact; for host-specific facts (IP, service, technology, CVE, hosting, local path) each host and source pair counts. Findings scored against the domain (lookalikes, breaches, leak links, mail policy, certificates) are listed once with the hosts that reported them. A gap is something the public record did not answer, not a finding.',
  };
};

export const applyNotes = (current = {}, body = {}) => {
  const summary =
    typeof body.summary === 'string' ? body.summary.trim().slice(0, 4000) : current.summary || null;
  const allowed = new Set(['open', 'accepted', 'false-positive', 'fixed']);
  const dispositions = { ...(current.dispositions || {}) };
  for (const [key, value] of Object.entries(body.dispositions || {})) {
    if (typeof key !== 'string' || key.length > 200) continue;
    if (!allowed.has(value)) continue;
    if (value === 'open') delete dispositions[key];
    else dispositions[key] = value;
  }
  return { summary: summary || null, dispositions, updatedAt: new Date().toISOString() };
};
