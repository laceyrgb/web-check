import assert from 'node:assert/strict';
import test from 'node:test';

import { crawlSameSite, simpleExtract } from '../crawl.js';
import { assertTemplateSafe, verifyTemplatePin } from '../engines/templates.js';
import { buildNucleiArgs } from '../engines/nuclei.js';
import { assertIntelUrl, fetchIntel, matchProduct, normaliseIntel } from '../intel/intel.js';
import { isDue, runMonitor } from '../monitor.js';
import { renderExecutivePdf } from '../pdf.js';
import { renderExecutiveHtml } from '../report-html.js';
import { applyReview } from '../review.js';
import { prioritise } from '../score.js';
import { runScan } from '../runner.js';

const quiet = { env: {}, now: '2026-11-01T00:00:00.000Z' };

const draft = async () =>
  runScan({
    ...quiet,
    target: 'https://scan.example',
    observations: {
      dns: {
        txt: { 'scan.example': ['v=spf1 +all'] },
        mx: [{ exchange: 'mail.scan.example' }],
        dkim: [],
      },
      http: { scheme: 'https', headers: { server: 'Apache/2.4.49' } },
    },
  });

test('a report cannot be released until every critical and high finding has a decision', async () => {
  const report = await draft();
  const queue = report.findings.filter(
    (item) => item.status === 'open' && (item.severity === 'critical' || item.severity === 'high'),
  );
  assert.ok(queue.length >= 1);
  const blocked = applyReview(report, {
    reviewer: 'Amina Al',
    decisions: [],
    at: '2026-11-16T00:00:00Z',
  });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.report.release.status, 'draft');
  assert.throws(
    () =>
      applyReview(report, {
        reviewer: 'Amina Al',
        decisions: queue.map((item) => ({ id: item.id, action: 'suppress' })),
      }),
    /reason/,
  );
  const result = applyReview(report, {
    reviewer: 'Amina Al',
    at: '2026-11-16T00:00:00Z',
    decisions: queue.map((item, index) =>
      index === 0
        ? { id: item.id, action: 'suppress', reason: 'Banner is a mirror, confirmed with the host' }
        : { id: item.id, action: 'approve', reason: 'Checked' },
    ),
  });
  assert.equal(result.ok, true);
  assert.equal(result.report.release.status, 'released');
  assert.equal(
    result.report.findings.some((item) => item.id === queue[0].id),
    false,
  );
  assert.equal(result.report.audit[0].reviewer, 'Amina Al');
  assert.equal(result.report.audit[0].action, 'suppress');
  assert.match(result.report.audit[0].reason, /mirror/);
});

test('monitoring re-checks ownership and emits opened and resolved events', async () => {
  let scanned = false;
  const failed = await runMonitor({
    subscription: {
      id: 'sub-1',
      target: 'scan.example',
      intervalHours: 24,
      mode: 'active',
      authorized: true,
      verificationToken: 'cormorant-test-token',
    },
    verify: async () => ({ ok: false, method: null }),
    scan: async () => {
      scanned = true;
      return {};
    },
    now: '2026-11-16T00:00:00Z',
  });
  assert.equal(failed.ran, false);
  assert.equal(scanned, false);
  assert.equal(failed.events[0].type, 'ownership.failed');
  let governmentChecked = false;
  const refused = await runMonitor({
    subscription: {
      id: 'sub-gov',
      target: 'https://unit.test.gov.ae',
      intervalHours: 24,
      verificationToken: 'cormorant-test-token',
    },
    verify: async () => {
      governmentChecked = true;
      return { ok: true, method: 'dns-txt' };
    },
    scan: async () => {
      governmentChecked = true;
      return {};
    },
  });
  assert.equal(governmentChecked, false);
  assert.equal(refused.events[0].type, 'scan.refused');

  const previous = {
    score: { value: 80 },
    findings: [
      { id: 'email.spf.plus-all', status: 'open', severity: 'high', title: 'SPF' },
      { id: 'ports.23', status: 'open', severity: 'critical', title: 'Telnet' },
    ],
  };
  const current = {
    target: { hostname: 'scan.example' },
    source: 'live',
    score: { value: 90 },
    findings: [{ id: 'ports.23', status: 'open', severity: 'critical', title: 'Telnet' }],
  };
  const ok = await runMonitor({
    subscription: {
      id: 'sub-1',
      target: 'scan.example',
      intervalHours: 24,
      mode: 'passive',
      authorized: false,
      verificationToken: 'cormorant-test-token',
    },
    previousReport: previous,
    verify: async () => ({ ok: true, method: 'dns-txt' }),
    scan: async (options) => {
      assert.equal(options.mode, 'passive');
      assert.equal(options.ownership.ok, true);
      return current;
    },
    now: '2026-11-16T00:00:00Z',
  });
  assert.equal(ok.ran, true);
  assert.ok(
    ok.events.some(
      (event) => event.type === 'finding.resolved' && event.findingId === 'email.spf.plus-all',
    ),
  );
  assert.equal(
    isDue({ intervalHours: 24, lastRunAt: '2026-11-16T00:00:00Z' }, '2026-11-16T12:00:00Z'),
    false,
  );
  assert.equal(
    isDue({ intervalHours: 24, lastRunAt: '2026-11-15T00:00:00Z' }, '2026-11-16T01:00:00Z'),
    true,
  );
});

test('NVD, KEV, and EPSS fixtures normalise, and the feed hosts are allow-listed', async () => {
  assert.throws(() => assertIntelUrl('https://evil.example/cve'), /Refusing/);
  const cache = normaliseIntel({
    nvd: {
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2021-41773',
            metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH' } }] },
            configurations: [
              {
                nodes: [
                  {
                    cpeMatch: [
                      {
                        vulnerable: true,
                        criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
                      },
                    ],
                  },
                ],
              },
            ],
          },
        },
      ],
    },
    kev: { vulnerabilities: [{ cveID: 'CVE-2021-41773' }] },
    epss: { data: [{ cve: 'CVE-2021-41773', epss: '0.94' }] },
  });
  const hit = matchProduct('Apache', '2.4.49', 'banner', cache.items)[0];
  assert.equal(hit.severity, 'critical');
  assert.equal(hit.priority, 'immediate');
  assert.match(hit.evidence, /CISA KEV: yes/);
  assert.match(hit.evidence, /no exploit payload/);
  let called = 0;
  const fetched = await fetchIntel(async (url) => {
    called += 1;
    assertIntelUrl(url);
    if (url.includes('nvd')) {
      return {
        body: JSON.stringify({
          vulnerabilities: [
            {
              cve: {
                id: 'CVE-2020-11022',
                metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'MEDIUM' } }] },
                configurations: [
                  {
                    nodes: [
                      {
                        cpeMatch: [
                          {
                            vulnerable: true,
                            criteria: 'cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*',
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            },
          ],
        }),
      };
    }
    if (url.includes('cisa')) return { body: '{"vulnerabilities":[]}' };
    return { body: '{"data":[{"cve":"CVE-2020-11022","epss":"0.04"}]}' };
  });
  assert.equal(called, 3);
  assert.equal(fetched.items[0].product, 'jquery');
  assert.equal(fetched.items[0].kev, false);
});

test('the pinned nuclei set is GET-only and is what the adapter launches', () => {
  const pin = verifyTemplatePin();
  assert.equal(pin.count, 3);
  assert.throws(
    () => assertTemplateSafe('http:\n  - method: GET\n    payload: exploit'),
    /forbidden/,
  );
  const args = buildNucleiArgs('https://scan.example');
  assert.ok(args.includes('-t'));
  assert.ok(args.includes('-no-interactsh'));
  assert.equal(args.includes('-interactsh-url'), false);
});

test('the same-site crawl stays on the origin and mixed content is reported', async () => {
  const urls = [];
  const pages = await crawlSameSite({
    origin: 'https://scan.example/',
    extract: simpleExtract,
    httpGet: async (url) => {
      urls.push(url);
      if (url.endsWith('/')) {
        return {
          status: 200,
          headers: {},
          body: '<a href="/shop">Shop</a><a href="https://evil.example/out">Out</a><a href="mailto:a@scan.example">M</a>',
        };
      }
      return {
        status: 200,
        headers: {},
        body: '<script src="http://cdn.example/app.js"></script>',
      };
    },
  });
  assert.equal(
    urls.some((url) => url.includes('evil.example')),
    false,
  );
  assert.equal(
    urls.some((url) => url.includes('mailto:')),
    false,
  );
  assert.ok(pages.some((page) => page.url.includes('/shop')));
  const report = await runScan({
    ...quiet,
    target: 'https://scan.example',
    mode: 'active',
    authorized: true,
    verificationToken: 'cormorant-test-token',
    ownership: { ok: true, method: 'dns-txt' },
    observations: {
      pages,
      http: { scheme: 'https', headers: { 'cf-ray': 'abc', server: 'cloudflare' } },
      robotsTxt: 'User-agent: *\nDisallow: /admin\n',
      securityTxt: null,
      dns: {
        mx: [{ exchange: 'scan-example.mail.protection.outlook.com' }],
        txt: { 'scan.example': ['v=spf1 -all'] },
        dkim: [{ selector: 'selector1', bits: 2048 }],
      },
    },
  });
  const ids = new Set(report.findings.map((item) => item.id));
  assert.ok([...ids].some((id) => id.startsWith('page.mixed.')));
  assert.ok(ids.has('surface.robots.sensitive'));
  assert.ok(ids.has('surface.waf.present'));
  assert.ok(ids.has('sector.microsoft-365'));
  assert.equal(report.commercial.currency, 'AED');
  assert.equal(report.language.ar, 'needs-native-review');
  assert.equal(report.release.status, 'draft');
  assert.equal(
    report.findings.find((item) => item.id === 'sector.microsoft-365').mapping.uaeIaControl,
    'T4.2.4',
  );
  const html = renderExecutiveHtml(report);
  assert.match(html, /dir="rtl"/);
  assert.match(html, /native reviewer/);
  const pdf = renderExecutivePdf(report);
  const pdfText = Buffer.isBuffer(pdf) ? pdf.toString('latin1') : pdf;
  assert.match(pdfText, /^%PDF-1.4/);
  assert.match(pdfText, /impact/);
  const ranked = prioritise([
    {
      id: 'a',
      status: 'open',
      severity: 'low',
      impact: 'high',
      effort: 'low',
      remediation: 'easy',
      title: 'Easy',
      titleAr: 'سهل',
      remediationAr: 'سهل',
    },
    {
      id: 'b',
      status: 'open',
      severity: 'high',
      impact: 'high',
      effort: 'high',
      remediation: 'hard',
      title: 'Hard',
      titleAr: 'صعب',
      remediationAr: 'صعب',
    },
  ]);
  assert.equal(ranked[0].id, 'a');
});
