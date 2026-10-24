// Weights match api/cormorant/risk.js. The desk API score is the one that goes in the PDF.

const letterOf = (score: number | null) => {
  if (score == null) return 'n/a';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
};

const severityPoints: Record<string, number> = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 };

export interface RiskFactor {
  source: string;
  detail?: string;
  points: number;
}

export interface RiskScore {
  score: number | null;
  letter: string;
  factors: RiskFactor[];
  note: string;
}

export const scoreRisk = (report: any = {}): RiskScore => {
  const observed = [
    'attackSurface',
    'cves',
    'breaches',
    'exposure',
    'lookalikes',
    'mentions',
    'posture',
    'records',
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
  const factors: RiskFactor[] = [];
  const deduct = (points: number, factor: Omit<RiskFactor, 'points'>) => {
    if (!points) return;
    factors.push({ ...factor, points });
    score -= points;
  };
  for (const finding of report.cves?.findings || []) {
    deduct(severityPoints[finding.severity] || 0, { source: 'cve', detail: finding.id });
  }
  for (const row of report.breaches?.emails || []) {
    if (row.breaches?.length) deduct(12, { source: 'breach', detail: row.email });
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
  for (const finding of report.records?.findings || [])
    deduct(finding.points || 0, { source: finding.source || 'record', detail: finding.detail });
  for (const cve of report.cms?.cves || []) deduct(12, { source: 'cms', detail: cve.id });
  if ((report.posture?.score ?? 100) < 70) {
    deduct(Math.min(20, 100 - report.posture.score), {
      source: 'posture',
      detail: report.posture.letter,
    });
  }
  score = Math.max(0, Math.min(100, score));
  return {
    score,
    letter: letterOf(score),
    factors,
    note: 'Weighted only from findings this page actually recorded. A high score is not proof of safety.',
  };
};

export const riskFromJobs = (jobs: Record<string, { state?: string; raw?: any }>): RiskScore => {
  const raw = (id: string) => (jobs[id]?.state === 'success' ? jobs[id].raw : null);
  return scoreRisk({
    attackSurface: raw('attack-surface'),
    cves: raw('tech-cves'),
    breaches: raw('email-breaches'),
    exposure: raw('network-exposure'),
    lookalikes: raw('lookalikes'),
    mentions: raw('public-mentions'),
    posture: raw('posture'),
    cms: raw('cms-fingerprint'),
  });
};
