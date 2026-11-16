import { finding } from '../findings.js';
import { REFS } from '../refs.js';

const looksPersonal = (value) => {
  const text = String(value || '');
  return text.includes('@') || /[+]?\d[\d\s-]{7,}/.test(text);
};

// Domain-level counts only. Personal rows never reach the default report.
export const minimiseBreach = (rows) => {
  const byDomain = new Map();
  for (const row of rows || []) {
    const domain = String(row.domain || '')
      .trim()
      .toLowerCase();
    if (!domain || looksPersonal(domain)) continue;
    const entry = byDomain.get(domain) || { domain, breachCount: 0, dataClasses: new Set() };
    entry.breachCount += 1;
    for (const item of row.dataClasses || []) {
      if (!looksPersonal(item)) entry.dataClasses.add(String(item).slice(0, 80));
    }
    byDomain.set(domain, entry);
  }
  return [...byDomain.values()].map((entry) => ({
    domain: entry.domain,
    breachCount: entry.breachCount,
    dataClasses: [...entry.dataClasses].sort(),
  }));
};

export const createBreachProvider = ({ fixtures = [] } = {}) => ({
  id: 'fixture-stub',
  licensed: false,
  async lookup(domain) {
    const name = String(domain || '').toLowerCase();
    return minimiseBreach(
      fixtures.filter((row) => String(row.domain || '').toLowerCase() === name),
    );
  },
});

export const breachFindings = (rows) =>
  (rows || []).map((row) =>
    finding({
      id: 'breach.domain.count',
      title: `${row.breachCount} known breach record(s) for this domain`,
      titleAr: `${row.breachCount} سجل اختراق معروف لهذا النطاق`,
      severity: row.breachCount ? 'medium' : 'info',
      evidence: `Domain ${row.domain}. Data classes: ${row.dataClasses.join(', ') || 'none listed'}. Personal rows are not included.`,
      remediation:
        'Ask the breach provider for a minimised export and tell affected people through your own notice process. Do not paste personal data into this report.',
      remediationAr:
        'اطلب من مزود بيانات الاختراق تصديرًا مختصرًا، وأبلغ المتأثرين عبر إجراءكم. لا تلصق بيانات شخصية في هذا التقرير.',
      references: [REFS.pdpl],
      service: 'legal',
      needsHumanReview: true,
      effort: 'medium',
      impact: 'high',
    }),
  );
