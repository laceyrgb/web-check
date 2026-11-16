import { isLoopbackHost } from './addresses.js';
import { analyseCors } from './checks/cors.js';
import { analyseCookies } from './checks/cookies.js';
import { analyseDns } from './checks/dns-hygiene.js';
import { analyseEmail } from './checks/email.js';
import { classifyExposure, findingsFromExposure } from './checks/exposed-files.js';
import { analysePorts } from './checks/ports.js';
import {
  analyseInnerPages,
  analyseMixedContent,
  analyseRobots,
  analyseSecurityTxt,
  analyseWaf,
} from './checks/publish.js';
import { sectorFindings } from './checks/sectors.js';
import { breachFindings } from './providers/breach.js';
import { runRecord } from './store.js';
import { analyseSubdomains } from './checks/subdomains.js';
import { analyseTech } from './checks/tech-cve.js';
import { analyseHeaders, analyseTls } from './checks/tls-headers.js';
import { collectActive, collectPassive } from './collect.js';
import { buildDenylist } from './denylist.js';
import { diffReports } from './diff.js';
import { findingsFromNuclei, runNuclei } from './engines/nuclei.js';
import { SUITE_VERSION, dedupe, finding, sortFindings } from './findings.js';
import { DESC_SOURCE, PDPL_SOURCE, UAE_IA_SOURCE } from './uae-map.js';
import { registrableDomain } from './domain.js';
import { tokenHint, verifyOwnership } from './ownership.js';
import { prioritise, scoreFindings, summarise } from './score.js';
import { parseTarget } from './target.js';
import { REFS } from './refs.js';

export const OUT_OF_SCOPE = [
  {
    en: 'No exploit payloads, no brute force, and no credential testing.',
    ar: 'لا حمولات استغلال، ولا تخمين لكلمات المرور، ولا اختبار لبيانات الدخول.',
  },
  {
    en: 'Not an authenticated application test and not a penetration test.',
    ar: 'ليس اختبار تطبيق بعد تسجيل الدخول، وليس اختبار اختراق.',
  },
  {
    en: 'Version matches use a short starter catalog, not the full National Vulnerability Database.',
    ar: 'مطابقة الإصدارات تستخدم فهرسًا قصيرًا، وليس قاعدة الثغرات الوطنية كاملة.',
  },
  {
    en: 'UAE IA and PDPL labels are reference themes for a reviewer. They are not a certification and not a gap assessment.',
    ar: 'إشارات معيار ضمان المعلومات ونظام حماية البيانات موضوعات استرشادية للمراجع. ليست شهادة وليست تقييم فجوات.',
  },
];

const classifyRows = (rows) => {
  if (!Array.isArray(rows)) return [];
  const matches = [];
  for (const row of rows) {
    if (!row) continue;
    if (row.title && row.id && row.remediation && row.severity) {
      matches.push(row);
      continue;
    }
    const match = classifyExposure(row.path, row.status, row.body || '');
    if (match) {
      const { test, ...rest } = match;
      matches.push(rest);
    }
  }
  return findingsFromExposure(matches);
};

const coverageFor = (observations, extras) => {
  const ran = [];
  const skipped = [];
  const mark = (id, present, reason, reasonAr) => {
    if (present) ran.push(id);
    else skipped.push({ id, reason, reasonAr });
  };
  mark(
    'email-domain',
    Boolean(observations.dns),
    'No DNS snapshot was supplied.',
    'لم تُزوَّد لقطة DNS.',
  );
  mark(
    'dns-hygiene',
    Boolean(observations.dns) && !observations.dns?.error,
    observations.dns?.error || 'No DNS snapshot was supplied.',
    'تعذر فحص سلامة DNS.',
  );
  mark(
    'tls-headers',
    Boolean(observations.http || observations.tls),
    'No HTTP or TLS snapshot was supplied.',
    'لم تُزوَّد لقطة HTTP أو TLS.',
  );
  mark(
    'cookies',
    Boolean(observations.http),
    'No HTTP response was supplied, so cookies were not reviewed.',
    'لم تُزوَّد استجابة HTTP، لذا لم تُراجع ملفات الارتباط.',
  );
  mark(
    'certificate-transparency',
    Array.isArray(observations.ctNames),
    observations.ctError || 'No certificate-transparency names were supplied.',
    'لم تُزوَّد أسماء من شفافية الشهادات.',
  );
  mark(
    'passive-ports',
    Array.isArray(observations.passivePorts),
    'No passive port data was supplied. This run does not scan all ports.',
    'لم تُزوَّد بيانات منافذ سلبية. هذا التشغيل لا يفحص كل المنافذ.',
  );
  for (const extra of extras) skipped.push(extra);
  return { ran, skipped, outOfScope: OUT_OF_SCOPE };
};

const blockedReport = (target, rule) => {
  const blockedFinding = finding({
    id: 'legal.denylist.blocked',
    title: 'Scan refused by the do-not-scan list',
    titleAr: 'رُفض الفحص بسبب قائمة المنع',
    severity: 'critical',
    evidence: `${target.hostname} matched ${rule.id}. No DNS query and no HTTP request was made.`,
    remediation:
      'Do not scan government or other denied names. This product is for a customer domain the operator is allowed to test.',
    remediationAr: 'لا تفحص أسماء حكومية أو أسماء ممنوعة. هذا المنتج لنطاق عميل مسموح باختباره.',
    references: [REFS.cybercrime],
    service: 'legal',
    needsHumanReview: true,
  });
  return {
    product: 'UAE Readiness Scan',
    vendor: 'Cormorant Cyber',
    version: SUITE_VERSION,
    generatedAt: new Date().toISOString(),
    target,
    mode: 'blocked',
    source: 'none',
    score: null,
    summary: summarise({
      hostname: target.hostname,
      findings: [],
      score: null,
      blocked: rule.id,
      source: 'none',
    }),
    prioritisedFixes: [],
    findings: [blockedFinding],
    coverage: {
      ran: [],
      skipped: [
        {
          id: 'all',
          reason: 'Stopped before any check because the name is denied.',
          reasonAr: 'توقف قبل أي فحص لأن الاسم ممنوع.',
        },
      ],
      outOfScope: OUT_OF_SCOPE,
    },
    legal: {
      denied: true,
      denyRule: rule.id,
      authorized: false,
      ownership: { required: false, ok: false, method: null, reason: 'denied', tokenHint: null },
      activeRan: false,
    },
    safety: {
      passiveByDefault: true,
      exploitation: false,
      bruteForce: false,
      credentialTesting: false,
      nmap: false,
    },
  };
};

export const runScan = async (options = {}) => {
  const target = parseTarget(options.target);
  const denylist = buildDenylist({ extra: options.deny || [], env: options.env ?? process.env });
  const names = [target.hostname, registrableDomain(target.hostname)];
  const denied = names.map((name) => denylist.check(name)).find(Boolean);
  if (denied) return blockedReport(target, denied);

  const mode = options.mode === 'active' ? 'active' : 'passive';
  const authorized = options.authorized === true;
  const token = typeof options.verificationToken === 'string' ? options.verificationToken : '';
  const transports = options.transports || null;
  const supplied = Boolean(options.observations);
  let observations = supplied ? { ...options.observations } : null;
  const now = options.now ? new Date(options.now) : new Date();

  let ownership = {
    required: mode === 'active',
    ok: false,
    method: null,
    reason: mode === 'active' ? 'not-checked' : 'not-required',
    tokenHint: tokenHint(token),
  };
  let activeRan = false;
  const extraSkipped = [];

  if (mode === 'active') {
    if (!authorized) {
      ownership = { ...ownership, reason: 'not-authorised' };
      extraSkipped.push({
        id: 'active',
        reason:
          'Active checks were not run. Pass an explicit authorisation flag as well as a verification token.',
        reasonAr: 'لم تُنفَّذ الفحوص النشطة. مرّر إذنًا صريحًا ورمز تحقق.',
      });
    } else if (!token) {
      ownership = { ...ownership, reason: 'token-missing' };
      extraSkipped.push({
        id: 'active',
        reason: 'Active checks need a verification token published in DNS or a well-known file.',
        reasonAr: 'الفحوص النشطة تحتاج رمز تحقق منشورًا في DNS أو في ملف معروف.',
      });
    } else if (
      // Library callers may pass a proof they already checked. The CLI never does.
      options.ownership?.ok === true &&
      options.ownership.method
    ) {
      ownership = { ...ownership, ok: true, method: options.ownership.method, reason: null };
    } else if (transports) {
      const result = await verifyOwnership({
        hostname: target.hostname,
        token,
        origin: target.origin,
        transports,
      });
      ownership = { ...ownership, ...result, tokenHint: tokenHint(token) };
      if (!result.ok) {
        extraSkipped.push({
          id: 'active',
          reason: 'Ownership was not verified, so active checks were not run.',
          reasonAr: 'لم يُتحقق من الملكية، لذا لم تُنفَّذ الفحوص النشطة.',
        });
      }
    } else {
      ownership = { ...ownership, reason: 'no-transport' };
      extraSkipped.push({
        id: 'active',
        reason:
          'Active checks need a live transport to verify ownership. A snapshot file alone is not authorisation.',
        reasonAr: 'الفحوص النشطة تحتاج اتصالًا للتحقق من الملكية. ملف اللقطة وحده ليس إذنًا.',
      });
    }
  }

  const gatesOpen = mode === 'active' && authorized && Boolean(token) && ownership.ok === true;
  if (!observations) {
    if (!transports)
      throw new Error('Provide observations or live transports. Refusing to guess a target.');
    observations = await collectPassive({
      hostname: target.hostname,
      origin: target.origin,
      transports,
    });
  }
  if (gatesOpen && transports && !supplied) {
    const active = await collectActive({
      origin: target.origin,
      hostname: target.hostname,
      transports,
    });
    observations = { ...observations, ...active };
    activeRan = true;
    if (options.engines?.nuclei) {
      const engine = await runNuclei({
        binary: options.engines.nuclei,
        targetUrl: target.origin,
        spawn: transports.spawn,
        activeAllowed: true,
      });
      observations.nuclei = engine.events;
      if (engine.skipped) {
        extraSkipped.push({ id: 'nuclei', reason: engine.skipped, reasonAr: 'لم يُشغَّل Nuclei.' });
      }
    }
  } else if (options.engines?.nuclei && !gatesOpen) {
    extraSkipped.push({
      id: 'nuclei',
      reason: 'Nuclei stays off unless the run is active, authorised, and ownership-verified.',
      reasonAr: 'يبقى Nuclei متوقفًا ما لم يكن التشغيل نشطًا ومأذونًا ومتحققًا من الملكية.',
    });
  }

  let intelItems;
  if (options.nvdProvider) {
    const ingested = await options.nvdProvider.ingest();
    intelItems = ingested.items;
  }
  const breachRows = options.breachProvider
    ? await options.breachProvider.lookup(registrableDomain(target.hostname))
    : [];

  const findings = dedupe(
    sortFindings([
      ...analyseEmail(target.hostname, observations.dns),
      ...analyseDns(observations.dns),
      ...analyseTls(observations.tls, now),
      ...analyseHeaders(observations.http),
      ...analyseCookies(observations.http),
      ...analyseCors({ headers: observations.http?.headers, probe: observations.corsProbe }),
      ...analyseSubdomains(target.hostname, observations.ctNames),
      ...analyseTech(observations, intelItems),
      ...breachFindings(breachRows),
      ...analysePorts(observations.passivePorts, 'passive'),
      ...analysePorts(observations.openPorts, 'active'),
      ...classifyRows(observations.exposed),
      ...findingsFromNuclei(observations.nuclei),
      ...analyseRobots(observations.robotsTxt),
      ...analyseSecurityTxt(observations.securityTxt),
      ...analyseWaf(observations.http?.headers),
      ...analyseMixedContent(observations.pages),
      ...analyseInnerPages(observations.pages),
      ...sectorFindings(observations),
    ]),
  );

  const score = scoreFindings(findings);
  const source = supplied ? 'supplied' : 'live';
  const report = {
    product: 'UAE Readiness Scan',
    vendor: 'Cormorant Cyber',
    version: SUITE_VERSION,
    generatedAt: now.toISOString(),
    target: {
      input: target.input,
      hostname: target.hostname,
      origin: target.origin,
      registrable: registrableDomain(target.hostname),
      loopback: isLoopbackHost(target.hostname),
    },
    mode,
    source,
    score,
    summary: summarise({ hostname: target.hostname, findings, score, blocked: null, source }),
    prioritisedFixes: prioritise(findings),
    findings,
    coverage: coverageFor(observations, extraSkipped),
    legal: {
      denied: false,
      denyRule: null,
      authorized,
      ownership,
      activeRan,
    },
    safety: {
      passiveByDefault: true,
      activeRequested: mode === 'active',
      activeRan,
      exploitation: false,
      bruteForce: false,
      credentialTesting: false,
      nmap: false,
    },
    mappingDisclaimer: {
      en: 'UAE IA control ids are from Regulation v1.1 (TDRA). They are reference-only: v2.1 may renumber families, and this is not a certification, not a DESC assessment, and not legal advice. PDPL notes are the same kind of reference.',
      ar: 'أرقام ضوابط معيار ضمان المعلومات من الإصدار 1.1. هي للاسترشاد فقط: الإصدار 2.1 قد يعيد ترقيم العائلات، وهذا ليس شهادة ولا تقييم DESC ولا استشارة قانونية. ملاحظات نظام حماية البيانات من النوع نفسه.',
    },
    commercial: {
      currency: 'AED',
      market: 'AE',
      vat: 'exclusive',
    },
    language: {
      en: 'ready',
      ar: 'needs-native-review',
    },
    sources: {
      uaeIa: UAE_IA_SOURCE,
      desc: DESC_SOURCE,
      pdpl: PDPL_SOURCE,
    },
    release: {
      status: 'draft',
      ready: false,
      reason: 'Critical and high findings need a reviewer decision before this report is released.',
    },
  };
  if (options.previousReport) report.changes = diffReports(options.previousReport, report);
  if (options.store) {
    options.store.saveRun(runRecord(report));
    report.trend = options.store.trend(target.hostname);
  }
  return report;
};
