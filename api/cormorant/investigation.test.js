import assert from 'node:assert/strict';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import test from 'node:test';
import express from 'express';
import { createRouter } from './router.js';
import { createFileStore } from './store.js';
import { applyNotes, consolidate, pivotHosts } from './investigation.js';
import { renderInvestigation } from './pdf.js';

const listen = (app) =>
  new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

const scanRow = (hostname, results, status = 'complete') => ({
  id: `scan-${hostname}`,
  hostname,
  status,
  results,
  error: status === 'failed' ? 'timed out' : undefined,
});

test('pivots open remote access, mail, and identity first and stay on the domain', () => {
  const plan = pivotHosts(
    {
      attackSurface: {
        hosts: [
          { host: 'www.example.com', source: 'crt.sh' },
          { host: 'vpn.example.com', source: 'crt.sh' },
          { host: 'example.com', source: 'crt.sh' },
          { host: '*.example.com', source: 'crt.sh' },
          { host: 'shop.example.com', source: 'hackertarget' },
        ],
      },
      records: { certificates: { names: ['sso.example.com', 'cdn.example.net'] } },
      dns: { MX: ['10 mail.example.com'] },
      exposure: { neighbors: [{ host: 'partner.example.org', source: 'same-ip' }] },
    },
    { domain: 'example.com', host: 'www.example.com', cap: 3 },
  );
  assert.deepEqual(
    plan.selected.map((row) => row.host),
    ['vpn.example.com', 'mail.example.com', 'sso.example.com'],
  );
  assert.equal(plan.selected[0].reason, 'remote access');
  assert.equal(plan.selected[1].reason, 'mail');
  assert.deepEqual(plan.selected[1].sources, ['mx']);
  assert.deepEqual(plan.held, ['shop.example.com']);
  assert.deepEqual(plan.related.map((row) => row.host).sort(), [
    'cdn.example.net',
    'partner.example.org',
  ]);
  assert.equal(plan.cap, 3);
  assert.equal(pivotHosts({}, { domain: 'example.com', host: 'example.com', cap: 99 }).cap, 12);
});

test('consolidation weights the weakest host and grades confidence by independent evidence', () => {
  const root = scanRow('example.com', {
    scannedAt: '2026-10-24T00:00:00.000Z',
    hostname: 'example.com',
    attackSurface: { hosts: [{ host: 'vpn.example.com', source: 'crt.sh' }] },
    exposure: { geo: { org: 'Example Hosting' }, rdap: { name: 'Example Hosting' } },
    dossier: {
      organization: { name: 'Example Ltd', source: 'rdap' },
      mailProvider: 'Google Workspace',
      hostingOrg: 'Example Hosting',
      people: [{ name: 'Jane Doe', source: 'gravatar', onPage: false }],
      contacts: [],
    },
    records: { mail: { spf: { qualifier: 'softfail' }, dmarc: null } },
    lookalikes: { live: ['examp1e.com'] },
    risk: {
      score: 80,
      letter: 'B',
      factors: [
        { source: 'mail', detail: 'DMARC absent', points: 10, action: 'Publish DMARC' },
        { source: 'lookalike', detail: 'examp1e.com', points: 8 },
      ],
    },
  });
  const vpn = scanRow('vpn.example.com', {
    scannedAt: '2026-10-24T00:00:00.000Z',
    hostname: 'vpn.example.com',
    exposure: { geo: { org: 'Example Hosting' } },
    dossier: { hostingOrg: 'Example Hosting', people: [] },
    cves: { findings: [{ id: 'CVE-2024-0001', severity: 'HIGH' }] },
    lookalikes: { live: ['examp1e.com'] },
    risk: {
      score: 40,
      letter: 'D',
      factors: [
        { source: 'cves', id: 'CVE-2024-0001', detail: 'HIGH', points: 25 },
        { source: 'lookalike', detail: 'examp1e.com', points: 8 },
      ],
    },
    sectionErrors: [{ section: 'breaches', message: 'index unavailable' }],
  });
  const mail = scanRow('mail.example.com', null, 'failed');
  const report = consolidate({
    target: 'https://example.com',
    domain: 'example.com',
    hostname: 'example.com',
    scans: [root, vpn, mail],
    plan: { held: ['shop.example.com'], related: [{ host: 'cdn.example.net' }], cap: 3 },
    reused: ['vpn.example.com'],
    notes: {
      summary: 'Client briefed.',
      dispositions: { 'vpn.example.com|cves|CVE-2024-0001': 'accepted' },
    },
  });
  assert.equal(report.risk.min, 40);
  assert.equal(report.risk.mean, 60);
  assert.equal(report.risk.score, 48);
  assert.equal(report.risk.letter, 'D');
  const hosting = report.facts.find((row) => row.kind === 'hosting');
  assert.equal(hosting.confidence, 'medium');
  assert.deepEqual(hosting.hosts, ['example.com', 'vpn.example.com']);
  const person = report.facts.find((row) => row.kind === 'person');
  assert.equal(person.confidence, 'low');
  assert.equal(report.findings[0].key, 'vpn.example.com|cves|CVE-2024-0001');
  assert.equal(report.findings[0].disposition, 'accepted');
  assert.equal(report.findings[0].scope, 'host');
  assert.equal(report.findings[1].disposition, 'open');
  const lookalike = report.findings.find((row) => row.source === 'lookalike');
  assert.equal(report.findings.filter((row) => row.source === 'lookalike').length, 1);
  assert.equal(lookalike.host, 'example.com');
  assert.equal(lookalike.scope, 'domain');
  assert.deepEqual(lookalike.hosts, ['example.com', 'vpn.example.com']);
  const lookalikeFact = report.facts.find((row) => row.kind === 'lookalike');
  assert.equal(lookalikeFact.confidence, 'low');
  assert.deepEqual(lookalikeFact.hosts, ['example.com', 'vpn.example.com']);
  assert.equal(report.analystSummary, 'Client briefed.');
  assert.equal(report.coverage.scanned, 2);
  assert.equal(report.coverage.failed, 1);
  assert.equal(report.coverage.reused, 1);
  const gaps = report.gaps.map((row) => row.gap);
  assert.ok(gaps.includes('No contact email'));
  assert.ok(gaps.includes('No corroborated people'));
  assert.ok(gaps.includes('1 in-scope host(s) held'));
  assert.ok(gaps.includes('1 related host(s) on other domains'));
  assert.ok(gaps.includes('Scan of mail.example.com failed'));
  assert.ok(gaps.includes('Module breaches returned no data'));
  assert.ok(!gaps.includes('No organisation name'));
  assert.ok(report.narrative.some((line) => line.includes('weakest host is vpn.example.com')));
});

test('analyst notes keep only known dispositions and a bounded summary', () => {
  const notes = applyNotes(
    { summary: 'old', dispositions: { a: 'accepted', b: 'fixed' } },
    {
      summary: ` ${'x'.repeat(5000)} `,
      dispositions: { a: 'open', b: 'bogus', c: 'false-positive' },
    },
  );
  assert.equal(notes.summary.length, 4000);
  assert.deepEqual(notes.dispositions, { b: 'fixed', c: 'false-positive' });
  assert.equal(applyNotes({ summary: 'kept' }, {}).summary, 'kept');
});

test('the investigation PDF renders', async () => {
  const pdf = await renderInvestigation({
    id: 'inv-1',
    target: 'https://example.com',
    domain: 'example.com',
    narrative: ['Line one.'],
    coverage: {
      requested: 1,
      scanned: 1,
      reused: 0,
      failed: 0,
      held: [],
      related: [],
      selected: [],
    },
    risk: { score: 70, letter: 'C', min: 70, mean: 70, perHost: [] },
    facts: [],
    findings: [],
    gaps: [],
    note: 'note',
  });
  assert.equal(pdf.subarray(0, 4).toString(), '%PDF');
});

test('an investigation runs the root scan, pivots in scope, and consolidates', async () => {
  const previousKey = process.env.WEBCHECK_API_KEY;
  const previousTenants = process.env.WEBCHECK_TENANT_KEYS;
  delete process.env.WEBCHECK_API_KEY;
  delete process.env.WEBCHECK_TENANT_KEYS;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-inv-'));
  const store = createFileStore(dir);
  const reusable = store.createScan({
    target: 'https://mail.example.com',
    hostname: 'mail.example.com',
    tenant: 'default',
  });
  store.updateScan(reusable.id, {
    status: 'complete',
    finishedAt: new Date().toISOString(),
    results: {
      scannedAt: new Date().toISOString(),
      hostname: 'mail.example.com',
      risk: { score: 90, letter: 'A', factors: [] },
    },
  });
  const targets = [];
  let releaseRoot;
  const rootGate = new Promise((resolve) => {
    releaseRoot = resolve;
  });
  const router = createRouter({
    store,
    schedule: false,
    executeScan: async (target) => {
      targets.push(target);
      if (target === 'https://example.com') {
        await rootGate;
        return {
          scannedAt: new Date().toISOString(),
          hostname: 'example.com',
          attackSurface: {
            hosts: [
              { host: 'vpn.example.com', source: 'crt.sh' },
              { host: 'mail.example.com', source: 'crt.sh' },
              { host: 'shop.example.com', source: 'crt.sh' },
            ],
          },
          exposure: { neighbors: [{ host: 'other.example.net', source: 'same-ip' }] },
          dossier: { organization: { name: 'Example Ltd', source: 'rdap' } },
          risk: { score: 85, letter: 'B', factors: [] },
        };
      }
      return {
        scannedAt: new Date().toISOString(),
        hostname: new URL(target).hostname,
        risk: {
          score: 50,
          letter: 'D',
          factors: [{ source: 'ports', detail: 'RDP open', points: 20, action: 'Close 3389' }],
        },
      };
    },
  });
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  const server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  const json = async (url, init) => {
    const response = await fetch(url, init);
    return { status: response.status, body: await response.json() };
  };
  try {
    const started = await json(`${base}/investigations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'https://Example.com/path', maxHosts: 2 }),
    });
    assert.equal(started.status, 202);
    assert.equal(started.body.status, 'running');
    assert.equal(started.body.domain, 'example.com');
    assert.equal(started.body.maxHosts, 2);
    const id = started.body.id;
    const early = await json(`${base}/investigations/${id}/report`);
    assert.equal(early.status, 409);
    assert.equal(early.body.stage, 'root');
    releaseRoot();
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const current = store.getInvestigation(id);
      if (current.status !== 'running') break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const status = await json(`${base}/investigations/${id}`);
    assert.equal(status.body.status, 'complete');
    assert.deepEqual(status.body.held, ['shop.example.com']);
    assert.deepEqual(
      status.body.related.map((row) => row.host),
      ['other.example.net'],
    );
    assert.deepEqual(status.body.reused, ['mail.example.com']);
    assert.deepEqual(targets.sort(), ['https://example.com', 'https://vpn.example.com']);
    assert.ok(status.body.hosts.find((row) => row.host === 'mail.example.com').reused);
    assert.ok(status.body.log.some((entry) => entry.line.includes('Pivot to vpn.example.com')));

    const report = await json(`${base}/investigations/${id}/report`);
    assert.equal(report.status, 200);
    assert.equal(report.body.coverage.scanned, 3);
    assert.equal(report.body.coverage.reused, 1);
    assert.equal(report.body.risk.min, 50);
    assert.equal(report.body.risk.score, 60);
    assert.equal(report.body.findings[0].disposition, 'open');
    const key = report.body.findings[0].key;

    const noted = await json(`${base}/investigations/${id}/notes`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        summary: 'RDP accepted by the client.',
        dispositions: { [key]: 'accepted' },
      }),
    });
    assert.equal(noted.status, 200);
    const after = await json(`${base}/investigations/${id}/report`);
    assert.equal(after.body.findings[0].disposition, 'accepted');
    assert.equal(after.body.analystSummary, 'RDP accepted by the client.');

    const pdf = await fetch(`${base}/investigations/${id}/report.pdf`);
    assert.equal(pdf.status, 200);
    assert.equal(pdf.headers.get('content-type'), 'application/pdf');

    const list = await json(`${base}/investigations`);
    assert.equal(list.body.investigations.length, 1);
    const scans = await json(`${base}/scans/${started.body.rootScanId}`);
    assert.equal(scans.body.investigationId, id);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    if (previousKey == null) delete process.env.WEBCHECK_API_KEY;
    else process.env.WEBCHECK_API_KEY = previousKey;
    if (previousTenants == null) delete process.env.WEBCHECK_TENANT_KEYS;
    else process.env.WEBCHECK_TENANT_KEYS = previousTenants;
  }
});

test('investigations are scoped to the tenant that started them', async () => {
  const previousKey = process.env.WEBCHECK_API_KEY;
  const previousTenants = process.env.WEBCHECK_TENANT_KEYS;
  delete process.env.WEBCHECK_API_KEY;
  process.env.WEBCHECK_TENANT_KEYS = 'alpha:alpha-key,beta:beta-key';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-inv-tenant-'));
  const store = createFileStore(dir);
  const router = createRouter({
    store,
    schedule: false,
    executeScan: async () => ({
      scannedAt: new Date().toISOString(),
      risk: { score: 70, letter: 'C', factors: [] },
    }),
  });
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  const server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  try {
    const started = await fetch(`${base}/investigations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'alpha-key' },
      body: JSON.stringify({ target: 'example.com' }),
    });
    assert.equal(started.status, 202);
    const { id } = await started.json();
    const other = await fetch(`${base}/investigations/${id}`, {
      headers: { 'x-api-key': 'beta-key' },
    });
    assert.equal(other.status, 404);
    const anonymous = await fetch(`${base}/investigations/${id}`);
    assert.equal(anonymous.status, 401);
    const own = await fetch(`${base}/investigations/${id}`, {
      headers: { 'x-api-key': 'alpha-key' },
    });
    assert.equal(own.status, 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    if (previousKey == null) delete process.env.WEBCHECK_API_KEY;
    else process.env.WEBCHECK_API_KEY = previousKey;
    if (previousTenants == null) delete process.env.WEBCHECK_TENANT_KEYS;
    else process.env.WEBCHECK_TENANT_KEYS = previousTenants;
  }
});
