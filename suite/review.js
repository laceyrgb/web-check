import { prioritise, scoreFindings, summarise } from './score.js';
import { sortFindings } from './findings.js';

const SERIOUS = new Set(['critical', 'high']);

export const reviewQueue = (report) =>
  (report?.findings || []).filter((item) => item.status === 'open' && SERIOUS.has(item.severity));

// A report stays a draft until every open critical and high finding is approved, edited, or
// suppressed. Suppress and edit require a reason. The audit log is append-only.
export const applyReview = (report, { reviewer, decisions = [], at } = {}) => {
  if (!reviewer || typeof reviewer !== 'string' || !reviewer.trim()) {
    throw new Error('Reviewer name is required');
  }
  const when = at || new Date().toISOString();
  const queue = reviewQueue(report);
  const byId = new Map(decisions.map((decision) => [decision.id, decision]));
  for (const decision of decisions) {
    const item = (report.findings || []).find((finding) => finding.id === decision.id);
    if (!item || item.status !== 'open' || !SERIOUS.has(item.severity)) {
      throw new Error(`Finding ${decision.id} is not in the sign-off queue`);
    }
    if (!['approve', 'edit', 'suppress'].includes(decision.action)) {
      throw new Error(`Bad review action for ${decision.id}`);
    }
    if (
      (decision.action === 'suppress' || decision.action === 'edit') &&
      !String(decision.reason || '').trim()
    ) {
      throw new Error(`A reason is required to ${decision.action} ${decision.id}`);
    }
  }
  const missing = queue.filter((item) => !byId.has(item.id)).map((item) => item.id);
  if (missing.length) {
    return {
      ok: false,
      missing,
      report: {
        ...report,
        release: {
          status: 'draft',
          ready: false,
          missing,
        },
      },
    };
  }
  const audit = [...(report.audit || [])];
  const findings = [];
  for (const item of report.findings || []) {
    const decision = byId.get(item.id);
    if (!decision) {
      findings.push(item);
      continue;
    }
    audit.push({
      at: when,
      reviewer: reviewer.trim(),
      findingId: item.id,
      action: decision.action,
      reason: String(decision.reason || '').trim(),
    });
    if (decision.action === 'suppress') continue;
    if (decision.action === 'edit') {
      findings.push({
        ...item,
        title: decision.title || item.title,
        titleAr: decision.titleAr || item.titleAr,
        remediation: decision.remediation || item.remediation,
        remediationAr: decision.remediationAr || item.remediationAr,
        plainFix: decision.plainFix || decision.remediation || item.plainFix,
        review: { action: 'edit', reviewer: reviewer.trim(), at: when },
      });
      continue;
    }
    findings.push({
      ...item,
      review: { action: 'approve', reviewer: reviewer.trim(), at: when },
    });
  }
  const ordered = sortFindings(findings);
  const score = scoreFindings(ordered);
  const released = {
    ...report,
    findings: ordered,
    score,
    prioritisedFixes: prioritise(ordered),
    summary: summarise({
      hostname: report.target.hostname,
      findings: ordered,
      score,
      blocked: null,
      source: report.source,
    }),
    audit,
    release: { status: 'released', ready: true, reviewer: reviewer.trim(), at: when },
  };
  return { ok: true, report: released };
};
