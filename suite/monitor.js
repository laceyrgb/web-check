import { buildDenylist } from './denylist.js';
import { diffReports } from './diff.js';
import { registrableDomain } from './domain.js';
import { parseTarget } from './target.js';

const HOUR = 60 * 60 * 1000;

export const isDue = (subscription, now = new Date()) => {
  const interval = Number(subscription?.intervalHours);
  if (!Number.isFinite(interval) || interval < 1) {
    throw new Error('intervalHours must be at least 1');
  }
  if (!subscription.lastRunAt) return true;
  return new Date(now).getTime() - new Date(subscription.lastRunAt).getTime() >= interval * HOUR;
};

export const nextRunAt = (subscription) => {
  const interval = Number(subscription.intervalHours);
  const start = subscription.lastRunAt ? new Date(subscription.lastRunAt) : new Date();
  return new Date(start.getTime() + interval * HOUR).toISOString();
};

// Re-check ownership before every run. Active mode still needs the subscription to say so.
// Alerts are JSON events. This function does not send email or touch the network itself.
export const runMonitor = async ({
  subscription,
  previousReport = null,
  scan,
  verify,
  now = new Date(),
}) => {
  if (typeof scan !== 'function' || typeof verify !== 'function') {
    throw new Error('Monitor needs a scan function and a verify function');
  }
  const at = new Date(now).toISOString();
  const events = [];
  const target = parseTarget(subscription.target);
  const denied =
    buildDenylist().check(target.hostname) ||
    buildDenylist().check(registrableDomain(target.hostname));
  if (denied) {
    events.push({
      type: 'scan.refused',
      at,
      subscriptionId: subscription.id,
      rule: denied.id,
    });
    return { ran: false, events, report: null, changes: null };
  }
  const proof = await verify({
    hostname: subscription.target,
    token: subscription.verificationToken,
  });
  events.push({
    type: proof?.ok ? 'ownership.verified' : 'ownership.failed',
    at,
    subscriptionId: subscription.id,
    method: proof?.method || null,
  });
  if (!proof?.ok) return { ran: false, events, report: null, changes: null };
  const active = subscription.mode === 'active' && subscription.authorized === true;
  const report = await scan({
    target: subscription.target,
    mode: active ? 'active' : 'passive',
    authorized: active,
    verificationToken: subscription.verificationToken,
    ownership: { ok: true, method: proof.method || 'rechecked' },
    previousReport: previousReport || undefined,
  });
  if (!previousReport) {
    events.push({
      type: 'monitor.baseline',
      at,
      subscriptionId: subscription.id,
      score: report.score?.value ?? null,
      open: (report.findings || []).filter((item) => item.status === 'open').length,
    });
    return { ran: true, events, report, changes: null };
  }
  const changes = diffReports(previousReport, report);
  for (const item of changes.added) {
    events.push({
      type: 'finding.opened',
      at,
      subscriptionId: subscription.id,
      findingId: item.id,
      severity: item.severity,
      title: item.title,
    });
  }
  for (const item of changes.removed) {
    events.push({
      type: 'finding.resolved',
      at,
      subscriptionId: subscription.id,
      findingId: item.id,
      severity: item.severity,
      title: item.title,
    });
  }
  if (changes.scoreDelta) {
    events.push({
      type: 'score.changed',
      at,
      subscriptionId: subscription.id,
      delta: changes.scoreDelta,
      score: report.score?.value ?? null,
    });
  }
  return { ran: true, events, report, changes };
};
