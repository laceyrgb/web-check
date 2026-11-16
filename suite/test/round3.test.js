import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { shapeArabic, visualSegments } from '../arabic.js';
import { createOutbox, deliverMonitoring, renderMessage } from '../delivery.js';
import { createOrder, releaseOrder } from '../order.js';
import { renderExecutivePdf } from '../pdf.js';
import { breachFindings, createBreachProvider } from '../providers/breach.js';
import { createNvdProvider } from '../providers/nvd.js';
import { openStore } from '../store.js';
import { readTrueType } from '../ttf.js';
import { runScan } from '../runner.js';

const quiet = { env: {}, now: '2026-11-16T00:00:00.000Z' };

test('Arabic shaping joins letters and the PDF embeds Noto Naskh', () => {
  assert.equal(shapeArabic('ب')[0], 0xfe8f);
  assert.equal(shapeArabic('ببب')[1], 0xfe92);
  assert.equal(shapeArabic('لا')[0], 0xfefb);
  const mixed = visualSegments('ب 12');
  assert.equal(mixed[0].font, 'helvetica');
  assert.deepEqual(mixed[0].cps, [49, 50]);
  assert.equal(mixed.at(-1).font, 'arabic');
  const font = readTrueType(new URL('../fonts/NotoNaskhArabic-Regular.ttf', import.meta.url));
  assert.ok(font.glyphs.get(0xfe8f) > 0);
  assert.ok(font.glyphs.get(0xfefb) > 0);
  const license = readFileSync(new URL('../fonts/OFL.txt', import.meta.url), 'utf8');
  assert.match(license, /SIL OPEN FONT LICENSE Version 1.1/);
  assert.match(license, /Copyright 2019-2021 Google LLC/);
  const pdf = renderExecutivePdf({
    target: { hostname: 'scan.example' },
    score: { value: 70, bandEn: 'needs attention' },
    release: { status: 'draft' },
    summary: {
      en: 'Score 70. Arabic needs native review.',
      ar: 'النتيجة ٧٠. النص العربي يحتاج مراجعة لغوية.',
    },
    prioritisedFixes: [
      {
        severity: 'high',
        impact: 'high',
        effort: 'low',
        title: 'Publish DMARC',
        titleAr: 'انشر DMARC',
        remediation: 'Add one DMARC record.',
      },
    ],
  });
  const text = pdf.toString('latin1');
  assert.match(text, /^%PDF-1.4/);
  assert.match(text, /NotoNaskhArabic/);
  assert.match(text, /FontFile2/);
  assert.match(text, /needs native review/);
  assert.match(text, /Tm <[0-9a-f]+> Tj/);
  assert.ok(pdf.length > 100000);
});

test('stored runs show a score trend and new or resolved ids', async () => {
  const store = openStore(mkdtempSync(path.join(tmpdir(), 'readiness-store-')));
  const base = {
    ...quiet,
    target: 'https://scan.example',
    store,
  };
  const first = await runScan({
    ...base,
    observations: { dns: { txt: { 'scan.example': ['v=spf1 +all'] }, mx: [], dkim: [] } },
  });
  const second = await runScan({
    ...base,
    now: '2026-11-17T00:00:00.000Z',
    observations: { dns: { txt: { 'scan.example': ['v=spf1 -all'] }, mx: [], dkim: [] } },
  });
  assert.equal(second.trend.points.length, 2);
  assert.ok(second.trend.points[0].score <= second.trend.points[1].score);
  assert.ok(second.trend.resolved.includes('email.spf.plus-all'));
  assert.equal(first.trend.points.length, 1);
  assert.equal(JSON.stringify(store.history('scan.example')).includes('secret'), false);
});

test('email and WhatsApp delivery write an outbox and refuse a live send', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'readiness-outbox-'));
  const outbox = createOutbox(dir);
  const delivered = await deliverMonitoring({
    outbox,
    hostname: 'scan.example',
    score: 80,
    events: [
      { type: 'finding.opened', findingId: 'email.dmarc.missing' },
      { type: 'finding.resolved', findingId: 'ports.23' },
    ],
  });
  assert.equal(delivered.length, 2);
  assert.equal(
    delivered.every((item) => item.sent === false),
    true,
  );
  const files = readdirSync(dir);
  assert.equal(files.length, 2);
  const body = JSON.parse(readFileSync(path.join(dir, files[0]), 'utf8'));
  assert.equal(body.mode, 'dry-run');
  assert.match(body.text, /New findings: 1/);
  assert.match(body.textAr, /نتائج جديدة/);
  assert.equal(body.needsNativeReview, true);
  await assert.rejects(
    () =>
      outbox.deliver('email', {
        ...renderMessage({ hostname: 'a', events: [] }),
        apiKey: 'secret',
      }),
    /credentials/,
  );
  const refused = spawnSync(
    process.execPath,
    ['suite/cli.js', 'scan', '--send', '--target', 'scan.example'],
    {
      encoding: 'utf8',
    },
  );
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /Sending is disabled/);
});

test('an order stays unreleased until proof, authorisation, and sign-off are all present', () => {
  const order = createOrder({
    id: 'ord-1',
    customer: { name: 'Scan Example LLC' },
    target: 'scan.example',
    ownership: { ok: true, method: 'dns-txt', tokenHint: '…oken' },
    authorisation: { granted: true, reference: 'click-wrap' },
    signOff: { reviewer: 'Amina Al', at: '2026-11-16T00:00:00Z', status: 'released' },
    payment: { status: 'paid', provider: 'card' },
  });
  assert.equal(order.payment.status, 'not-integrated');
  assert.equal(order.payment.provider, null);
  const blocked = releaseOrder(
    createOrder({
      id: 'ord-2',
      customer: { name: 'Scan Example LLC' },
      target: 'scan.example',
      ownership: { ok: false },
      authorisation: { granted: false },
    }),
    { release: { status: 'draft' } },
  );
  assert.equal(blocked.ok, false);
  assert.deepEqual(
    blocked.missing.sort(),
    ['authorisation', 'ownership', 'report-sign-off', 'sign-off'].sort(),
  );
  const released = releaseOrder(order, {
    release: { status: 'released', reviewer: 'Amina Al', at: '2026-11-16T00:00:00Z' },
    generatedAt: '2026-11-16T00:00:00Z',
  });
  assert.equal(released.ok, true);
  assert.equal(released.order.reportRelease.status, 'released');
});

test('breach and NVD stubs stay offline and keep personal rows out of the report', async () => {
  const secret = 'ada@scan.example';
  const provider = createBreachProvider({
    fixtures: [
      {
        domain: 'scan.example',
        email: secret,
        password: 'hunter2',
        dataClasses: ['Email addresses', secret],
      },
      {
        domain: 'scan.example',
        phone: '+971500000000',
        dataClasses: ['Passwords'],
      },
    ],
  });
  assert.equal(provider.licensed, false);
  const rows = await provider.lookup('scan.example');
  assert.equal(rows[0].breachCount, 2);
  assert.deepEqual(rows[0].dataClasses, ['Email addresses', 'Passwords']);
  assert.equal(JSON.stringify(rows).includes(secret), false);
  assert.equal(JSON.stringify(rows).includes('hunter2'), false);
  const report = await runScan({
    ...quiet,
    target: 'https://scan.example',
    observations: { http: { scheme: 'https', headers: {} } },
    breachProvider: provider,
  });
  assert.ok(report.findings.some((item) => item.id === 'breach.domain.count'));
  assert.equal(JSON.stringify(report).includes(secret), false);
  let called = false;
  const nvd = createNvdProvider({
    fixture: {
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
    },
  });
  const ingested = await nvd.ingest();
  assert.equal(nvd.apiKey, null);
  assert.equal(called, false);
  assert.equal(ingested.items[0].kev, true);
  const findings = breachFindings(rows);
  assert.equal(JSON.stringify(findings).includes(secret), false);
});

test('the UAE IA v2.1 crosswalk is a blank template', () => {
  const doc = JSON.parse(
    readFileSync(new URL('../uae/v21-crosswalk.json', import.meta.url), 'utf8'),
  );
  assert.equal(doc.label, 'reference-only');
  assert.equal(doc.needsHumanReview, true);
  assert.equal(doc.sourceV21, '');
  assert.ok(doc.rows.length >= 6);
  for (const row of doc.rows) {
    assert.equal(row.v21, '');
    assert.equal(row.v21Name, '');
    assert.equal(row.verified, false);
    assert.match(row.v11, /^[TM]\d+\.\d+\.\d+$/);
  }
});
