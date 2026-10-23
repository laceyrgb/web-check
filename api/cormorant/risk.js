const letterOf = (score) => {
  if (score == null) return 'n/a';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
};

const severityPoints = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 };

export const scoreRisk = (report = {}) => {
  const observed = [
    'attackSurface',
    'cves',
    'breaches',
    'exposure',
    'lookalikes',
    'mentions',
    'posture',
  ].some((key) => report[key] && !report[key].error);
  if (!observed) {
    return {
      score: null,
      letter: 'n/a',
      factors: [],
      note: 'No module returned data, so no risk score was assigned.',
    };
  }
  let score = 100;
  const factors = [];
  const deduct = (points, factor) => {
    if (!points) return;
    factors.push({ ...factor, points });
    score -= points;
  };
  for (const finding of report.cves?.findings || []) {
    deduct(severityPoints[finding.severity] || 0, {
      source: 'cve',
      id: finding.id,
      detail: finding.severity,
    });
  }
  for (const row of report.breaches?.emails || []) {
    if (row.breaches?.length)
      deduct(12, { source: 'breach', detail: row.breaches.map((item) => item.name).join(', ') });
  }
  for (const bucket of report.buckets?.buckets || []) {
    if (bucket.access === 'public-listing') deduct(20, { source: 'cloud', detail: bucket.url });
  }
  for (const port of report.attackSurface?.ports?.interesting || []) {
    deduct(7, { source: 'port', detail: `${port.port}/${port.service}` });
  }
  for (const host of report.lookalikes?.live || [])
    deduct(8, { source: 'lookalike', detail: host });
  for (const leak of report.mentions?.leaks || [])
    deduct(10, { source: 'leak-index', detail: leak.url });
  for (const cve of report.cms?.cves || []) deduct(12, { source: 'cms', detail: cve.id });
  if ((report.posture?.score ?? 100) < 70) {
    deduct(Math.min(20, 100 - report.posture.score), {
      source: 'posture',
      detail: report.posture.letter,
    });
  }
  for (const finding of report.nuclei?.findings || []) {
    if (['HIGH', 'CRITICAL', 'MEDIUM'].includes(String(finding.severity || '').toUpperCase())) {
      deduct(finding.severity?.toUpperCase() === 'MEDIUM' ? 8 : 15, {
        source: 'nuclei',
        detail: finding.id,
      });
    }
  }
  score = Math.max(0, Math.min(100, score));
  return {
    score,
    letter: letterOf(score),
    factors,
    note: 'Weighted only from findings the scan actually recorded. A high score is not proof of safety.',
  };
};

export const buildExecutiveSummary = (report) => {
  const lines = [`Target ${report.target} was scanned at ${report.scannedAt}.`];
  const hosts = report.attackSurface?.hostCount;
  if (typeof hosts === 'number') lines.push(`Passive sources listed ${hosts} hostnames.`);
  if (report.attackSurface?.subdomainError)
    lines.push(`Subdomain sources: ${report.attackSurface.subdomainError}.`);
  const open = report.attackSurface?.ports?.open;
  if (Array.isArray(open)) {
    lines.push(
      open.length
        ? `Common-port check observed: ${open.join(', ')}.`
        : 'Common-port check observed no open ports.',
    );
  }
  const cves = report.cves?.findings || [];
  if (cves.length) lines.push(`NVD returned ${cves.length} CVEs for disclosed versions.`);
  else if ((report.cves?.skipped || []).some((row) => row.status === 'version-unknown')) {
    lines.push(
      'At least one product had no disclosed version, so CVE matching was skipped for it.',
    );
  }
  const breached = (report.breaches?.emails || []).filter((row) => row.breaches?.length);
  if (breached.length)
    lines.push(`${breached.length} checked address(es) appeared in a public breach index.`);
  else if (report.breaches)
    lines.push('No checked address had a public breach record in the indexes that responded.');
  if (report.risk?.score != null)
    lines.push(
      `Rolled-up risk score is ${report.risk.score} (${report.risk.letter}) from ${report.risk.factors.length} weighted factors.`,
    );
  lines.push(
    'Empty sections mean the data was not observed. They are not a statement that the target is safe.',
  );
  return lines;
};

const remediationFor = (factor) => {
  switch (factor.source) {
    case 'cve':
      return `Review ${factor.id || factor.detail || 'the disclosed CVE'} and upgrade that version.`;
    case 'breach':
      return 'Treat the published address as exposed and rotate any credential that mailbox still uses.';
    case 'cloud':
      return 'Remove public listing from the storage URL that was already linked on the page.';
    case 'port':
      return `Confirm whether ${factor.detail || 'the observed service'} should be reachable from the internet.`;
    case 'lookalike':
      return `Review the resolving lookalike ${factor.detail || ''}.`.trim();
    case 'leak-index':
      return 'Open the public index link and take down material that belongs to the client.';
    case 'cms':
      return `Upgrade the CMS component matched to ${factor.detail || 'the disclosed version'}.`;
    case 'posture':
      return 'Close the header, TLS, cookie, or CORS gaps that lowered the posture grade.';
    case 'nuclei':
      return `Triage template ${factor.detail || ''} inside the engagement scope.`.trim();
    default:
      return factor.detail || factor.source;
  }
};

export const prioritizeRemediations = (report = {}) => {
  const items = [];
  const seen = new Set();
  const add = (priority, source, action) => {
    const text = String(action || '').trim();
    if (!text || seen.has(text)) return;
    seen.add(text);
    items.push({ priority, source, action: text });
  };
  for (const factor of report.risk?.factors || [])
    add(factor.points || 0, factor.source, remediationFor(factor));
  for (const fix of report.posture?.remediations || []) add(4, 'posture', fix);
  for (const bucket of report.buckets?.buckets || []) {
    if (bucket.access === 'public-listing')
      add(20, 'cloud', `Remove public listing at ${bucket.url}.`);
  }
  items.sort((left, right) => right.priority - left.priority);
  return items;
};

export const summarizeScan = (results) => ({
  scannedAt: results.scannedAt,
  riskScore: results.risk?.score ?? null,
  posture: results.posture?.score ?? null,
  hosts: (results.attackSurface?.hosts || []).map((item) => item.host),
  certHosts: results.posture?.tls?.names || [],
  certs: results.posture?.tls?.fingerprint ? [results.posture.tls.fingerprint] : [],
  cveIds: [
    ...(results.cves?.findings || []).map((item) => item.id),
    ...(results.cms?.cves || []).map((item) => item.id),
  ],
  openPorts: results.attackSurface?.ports?.open || [],
  leakUrls: (results.mentions?.leaks || []).map((item) => item.url),
  lookalikesLive: results.lookalikes?.live || [],
  dns: results.dns || null,
});

export const diffScans = (prev, next) => {
  if (!prev || !next) return [];
  const changes = [];
  const added = (type, before = [], after = []) => {
    const seen = new Set(before);
    for (const value of after) if (!seen.has(value)) changes.push({ type, value: String(value) });
  };
  added('new-subdomain', prev.hosts, next.hosts);
  added('new-cert-name', prev.certHosts, next.certHosts);
  added('cert-change', prev.certs, next.certs);
  added('new-cve', prev.cveIds, next.cveIds);
  added('new-open-service', (prev.openPorts || []).map(String), (next.openPorts || []).map(String));
  added('new-leak-mention', prev.leakUrls, next.leakUrls);
  added('new-lookalike', prev.lookalikesLive, next.lookalikesLive);
  if (prev.dns && next.dns && JSON.stringify(prev.dns) !== JSON.stringify(next.dns)) {
    changes.push({ type: 'dns-change', value: 'DNS snapshot changed' });
  }
  if (
    typeof prev.riskScore === 'number' &&
    typeof next.riskScore === 'number' &&
    next.riskScore < prev.riskScore
  ) {
    changes.push({ type: 'risk-worse', value: `${prev.riskScore} -> ${next.riskScore}` });
  }
  if (
    typeof prev.posture === 'number' &&
    typeof next.posture === 'number' &&
    next.posture < prev.posture - 5
  ) {
    changes.push({ type: 'posture-worse', value: `${prev.posture} -> ${next.posture}` });
  }
  return changes;
};
