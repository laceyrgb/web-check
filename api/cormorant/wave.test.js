import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import express from 'express';
import { checkEmailBreaches } from './breach.js';
import { lookupCves } from './cve.js';
import { networkExposure } from './exposure.js';
import { prioritizeRemediations } from './risk.js';
import { deliverAlerts, sendSmtpMail } from './alerts.js';
import { buildSbom, parseManifest } from './sbom.js';
import { renderReport } from './pdf.js';
import { createFileStore } from './store.js';
import { createRouter } from './router.js';

const saved = {};
const keys = [
  'HIBP_API_KEY',
  'NVD_API_KEY',
  'SHODAN_API_KEY',
  'CENSYS_API_TOKEN',
  'CENSYS_API_ID',
  'CENSYS_API_SECRET',
  'WEBCHECK_API_KEY',
  'WEBCHECK_TENANT_KEYS',
  'WEBCHECK_SLACK_WEBHOOK_URL',
  'SLACK_WEBHOOK_URL',
  'WEBCHECK_ALERT_EMAIL_TO',
  'WEBCHECK_SMTP_HOST',
  'WEBCHECK_SMTP_PORT',
  'WEBCHECK_PENTEST_ENABLED',
];

test.beforeEach(() => {
  for (const key of keys) saved[key] = process.env[key];
});

test.afterEach(() => {
  for (const key of keys) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

test('HIBP is used when the key is set and the public index is the fallback', async () => {
  process.env.HIBP_API_KEY = 'hibp-test-key';
  const keyed = [];
  const found = await checkEmailBreaches('https://example.com', {
    skipPageFetch: true,
    pageEmails: ['person@example.com'],
    paceMs: 0,
    httpGet: async (url, opts) => {
      keyed.push({ url, key: opts.headers?.['hibp-api-key'] });
      return { status: 404, data: null };
    },
  });
  assert.equal(keyed[0].key, 'hibp-test-key');
  assert.match(keyed[0].url, /haveibeenpwned/);
  assert.equal(found.emails[0].provider, 'Have I Been Pwned');
  assert.equal(JSON.stringify(found).includes('hibp-test-key'), false);

  delete process.env.HIBP_API_KEY;
  const publicCalls = [];
  await checkEmailBreaches('https://example.com', {
    skipPageFetch: true,
    pageEmails: ['person@example.com'],
    paceMs: 0,
    httpGet: async (url) => {
      publicCalls.push(url);
      return { status: 200, data: { breaches: ['Adobe'] } };
    },
  });
  assert.match(publicCalls[0], /xposedornot/);
});

test('NVD receives the API key header and omits it from errors', async () => {
  process.env.NVD_API_KEY = 'nvd-test-key';
  const result = await lookupCves([{ name: 'nginx', version: '1.24.0' }], {
    paceMs: 0,
    cache: new Map(),
    fetchImpl: async (_url, opts) => {
      assert.equal(opts.headers.apiKey, 'nvd-test-key');
      throw new Error('down');
    },
  });
  assert.equal(result.skipped[0].status, 'unavailable');
  assert.equal(JSON.stringify(result).includes('nvd-test-key'), false);
});

const exposureHttp =
  (seen) =>
  async (url, opts = {}) => {
    seen.push({ url: String(url), headers: opts.headers, params: opts.params, auth: opts.auth });
    const href = String(url);
    if (href.includes('ipwho.is'))
      return {
        status: 200,
        data: { success: true, country: 'Testland', connection: { org: 'Example Hosting' } },
      };
    if (href.includes('rdap.org')) return { status: 200, data: { name: 'Example' } };
    if (href.includes('ripe.net')) return { status: 200, data: {} };
    if (href.includes('internetdb')) return { status: 404, data: {} };
    if (href.includes('hackertarget')) return { status: 200, data: '' };
    if (href.includes('shodan'))
      return { status: 200, data: { ports: [443], hostnames: [], data: [] } };
    if (href.includes('censys'))
      return { status: 200, data: { result: { services: [{ port: 443, protocol: 'https' }] } } };
    return { status: 200, data: {} };
  };

test('Shodan and Censys run read-only when configured and skip when unset', async () => {
  delete process.env.SHODAN_API_KEY;
  delete process.env.CENSYS_API_TOKEN;
  const quiet = [];
  const unset = await networkExposure('https://example.com', {
    ip: '203.0.113.10',
    httpGet: exposureHttp(quiet),
  });
  assert.equal(unset.shodan.status, 'unset');
  assert.equal(unset.censys.status, 'unset');
  assert.equal(
    quiet.some((call) => call.url.includes('api.shodan.io')),
    false,
  );

  process.env.SHODAN_API_KEY = 'shodan-test-key';
  process.env.CENSYS_API_TOKEN = 'censys-test-token';
  const seen = [];
  const keyed = await networkExposure('https://example.com', {
    ip: '203.0.113.10',
    httpGet: exposureHttp(seen),
  });
  const shodan = seen.find((call) => call.url.includes('api.shodan.io'));
  const censys = seen.find((call) => call.url.includes('censys.io'));
  assert.equal(shodan.params.key, 'shodan-test-key');
  assert.equal(censys.headers.Authorization, 'Bearer censys-test-token');
  assert.equal(keyed.shodan.status, 'ok');
  assert.equal(keyed.censys.status, 'ok');
  assert.equal(JSON.stringify(keyed).includes('shodan-test-key'), false);
  assert.equal(JSON.stringify(keyed).includes('censys-test-token'), false);
});

test('remediations are ordered by impact', () => {
  const items = prioritizeRemediations({
    risk: {
      factors: [
        { source: 'port', points: 7, detail: '22/ssh' },
        { source: 'cve', points: 25, id: 'CVE-2024-0001', detail: 'CRITICAL' },
      ],
    },
    posture: {
      remediations: ['Send Strict-Transport-Security with max-age of at least one year.'],
    },
  });
  assert.equal(items[0].source, 'cve');
  assert.ok(items.at(-1).priority <= items[0].priority);
});

test('pdf includes the summary, remediation list, and trend labels', async () => {
  const pdf = await renderReport({
    target: 'example.com',
    scannedAt: '2026-10-22T00:00:00.000Z',
    executiveSummary: ['Observed only.'],
    risk: {
      score: 70,
      letter: 'C',
      factors: [{ source: 'cve', points: 25, id: 'CVE-1', detail: 'CRITICAL' }],
      note: 'weighted',
    },
    trend: [
      { scannedAt: '2026-10-01', riskScore: 90 },
      { scannedAt: '2026-10-22', riskScore: 70 },
    ],
  });
  const text = [...pdf.toString('latin1').matchAll(/<([0-9A-Fa-f]+)>/g)]
    .map((match) => Buffer.from(match[1], 'hex').toString('latin1'))
    .join('');
  assert.match(text, /Executive summary/);
  assert.match(text, /Prioritized remediation/);
  assert.match(text, /Risk score trend/);
  assert.match(text, /CVE-1/);
});

test('alerts are a no-op until a sink is configured', async () => {
  delete process.env.WEBCHECK_SLACK_WEBHOOK_URL;
  delete process.env.SLACK_WEBHOOK_URL;
  delete process.env.WEBCHECK_ALERT_EMAIL_TO;
  delete process.env.WEBCHECK_SMTP_HOST;
  const skipped = await deliverAlerts(
    { target: 'example.com', changes: [{ type: 'risk-worse', value: '90 -> 70' }] },
    {
      fetchImpl: async () => {
        throw new Error('should not send');
      },
    },
  );
  assert.equal(skipped.skipped, 'unconfigured');

  process.env.WEBCHECK_SLACK_WEBHOOK_URL = 'https://hooks.slack.test/services/secret';
  let posted = '';
  const sent = await deliverAlerts(
    {
      target: 'example.com',
      changes: [
        { type: 'new-subdomain', value: 'www.example.com' },
        { type: 'dns-change', value: 'ignore' },
      ],
    },
    {
      fetchImpl: async (url, opts) => {
        assert.equal(url, process.env.WEBCHECK_SLACK_WEBHOOK_URL);
        posted = opts.body;
        return { ok: true };
      },
    },
  );
  assert.deepEqual(sent.delivered, ['slack']);
  assert.match(posted, /new-subdomain/);
  assert.equal(posted.includes('dns-change'), false);
  assert.equal(posted.includes('hooks.slack.test'), false);
});

test('email alerts use SMTP and include the finding, not the configuration', async () => {
  const received = [];
  const server = net.createServer((socket) => {
    socket.write('220 ready\r\n');
    let data = false;
    socket.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      received.push(text);
      if (data) {
        if (text.includes('\r\n.\r\n')) {
          data = false;
          socket.write('250 queued\r\n');
        }
        return;
      }
      if (text.startsWith('DATA')) {
        data = true;
        socket.write('354 go\r\n');
      } else if (text.startsWith('QUIT')) {
        socket.write('221 bye\r\n');
        socket.end();
      } else socket.write('250 ok\r\n');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  process.env.WEBCHECK_ALERT_EMAIL_TO = 'alerts@example.com';
  process.env.WEBCHECK_SMTP_HOST = '127.0.0.1';
  process.env.WEBCHECK_SMTP_PORT = String(port);
  delete process.env.WEBCHECK_SLACK_WEBHOOK_URL;
  try {
    const result = await deliverAlerts(
      {
        target: 'example.com',
        changes: [{ type: 'cert-change', value: 'fingerprint' }],
      },
      { sendMail: (message) => sendSmtpMail(message) },
    );
    assert.deepEqual(result.delivered, ['email']);
    const blob = received.join('');
    assert.match(blob, /cert-change/);
    assert.equal(blob.includes('WEBCHECK_SMTP'), false);
  } finally {
    server.close();
  }
});

test('manifests become an SBOM and only exact versions are queried', () => {
  const node = parseManifest(
    'package.json',
    JSON.stringify({ dependencies: { leftpad: '1.2.3', loose: '^2.0.0' } }),
  );
  assert.deepEqual(node.packages, [{ name: 'leftpad', version: '1.2.3', ecosystem: 'npm' }]);
  assert.equal(node.skipped[0].name, 'loose');
  const python = parseManifest('requirements.txt', 'requests==2.31.0\nflask>=2\n');
  assert.equal(python.packages[0].ecosystem, 'PyPI');
  const go = parseManifest(
    'go.mod',
    'module example.com/app\n\nrequire github.com/foo/bar v1.2.3\n',
  );
  assert.equal(go.packages[0].name, 'github.com/foo/bar');
  assert.equal(go.packages[0].ecosystem, 'Go');
  const sbom = buildSbom(python.packages, 'requirements.txt');
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.components[0].purl, 'pkg:pypi/requests@2.31.0');
});

test('legacy records are visible only to the default tenant', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-tenant-'));
  fs.writeFileSync(
    path.join(dir, 'osint-store.json'),
    JSON.stringify({
      scans: {
        old: {
          id: 'old',
          hostname: 'example.com',
          status: 'complete',
          createdAt: '2026-10-01T00:00:00.000Z',
          target: 'https://example.com',
        },
      },
      assets: {
        'example.com': {
          items: { 'host:www.example.com': { kind: 'host', value: 'www.example.com' } },
        },
      },
      timeline: { 'example.com': [{ scannedAt: '2026-10-01T00:00:00.000Z', riskScore: 88 }] },
    }),
  );
  const store = createFileStore(dir);
  assert.equal(store.listScans('default')[0].id, 'old');
  assert.equal(store.listScans('acme').length, 0);
  assert.equal(
    store.getAssets('example.com', 'default').items['host:www.example.com'].value,
    'www.example.com',
  );
  assert.equal(store.getAssets('example.com', 'acme'), null);
  assert.equal(store.timeline('example.com', 'default')[0].riskScore, 88);
  fs.rmSync(dir, { recursive: true, force: true });
});

const listen = (app) =>
  new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

test('tenants cannot read each other, and history is read-only', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-api-'));
  const alerts = [];
  let pass = 0;
  const router = createRouter({
    store: createFileStore(dir),
    schedule: false,
    deliverAlerts: async (event) => {
      alerts.push(event);
      return { delivered: ['slack'] };
    },
    executeScan: async (target) => {
      pass += 1;
      return {
        target,
        scannedAt: `2026-10-2${pass}T00:00:00.000Z`,
        attackSurface: {
          hosts: pass === 1 ? [] : [{ host: 'new.example.com' }],
          hostCount: pass === 1 ? 0 : 1,
          ports: { open: [], interesting: [] },
          technologies: [],
          publishedEmails: [],
          citations: [],
        },
        cves: { findings: [] },
        breaches: { emails: [] },
        exposure: { ip: null },
        lookalikes: { live: [] },
        mentions: { leaks: [] },
        posture: {
          score: 90,
          letter: 'A',
          tls: {
            fingerprint: pass === 1 ? 'aaa' : 'bbb',
            names: pass === 1 ? ['example.com'] : ['example.com', 'mail.example.com'],
          },
        },
        risk: { score: pass === 1 ? 90 : 40, letter: pass === 1 ? 'A' : 'F', factors: [] },
        executiveSummary: ['Observed only.'],
      };
    },
  });
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  const server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  process.env.WEBCHECK_TENANT_KEYS = 'acme:acme-secret,other:other-secret';
  delete process.env.WEBCHECK_API_KEY;
  const acme = { 'content-type': 'application/json', 'x-api-key': 'acme-secret' };
  const other = { 'content-type': 'application/json', 'x-api-key': 'other-secret' };
  try {
    const created = await fetch(`${base}/monitors`, {
      method: 'POST',
      headers: acme,
      body: JSON.stringify({ target: 'example.com', everyMinutes: 1440 }),
    });
    assert.equal(created.status, 201);
    await router.queue.whenIdle();
    const monitor = await created.json();
    const again = await fetch(`${base}/monitors/${monitor.id}/run`, {
      method: 'POST',
      headers: acme,
    });
    assert.equal(again.status, 202);
    await router.queue.whenIdle();
    assert.equal(alerts.length, 1);
    const types = alerts[0].changes.map((row) => row.type);
    assert.ok(types.includes('risk-worse'));
    assert.ok(types.includes('new-subdomain'));
    assert.ok(types.includes('cert-change'));

    const hidden = await fetch(`${base}/history?target=example.com`, { headers: other });
    assert.deepEqual((await hidden.json()).scans, []);
    const visible = await fetch(`${base}/history?target=example.com`, { headers: acme });
    const history = await visible.json();
    assert.equal(history.scans.length, 2);
    assert.equal(history.trend.length, 2);
    assert.equal(history.latestFindings.risk.score, 40);

    const scanId = history.scans[0].id;
    const denied = await fetch(`${base}/scans/${scanId}`, { headers: other });
    assert.equal(denied.status, 404);

    process.env.WEBCHECK_PENTEST_ENABLED = 'true';
    const engagement = await fetch(`${base}/engagements`, {
      method: 'POST',
      headers: acme,
      body: JSON.stringify({
        clientName: 'Acme',
        operator: 'Casey',
        acknowledged: true,
        confirm: 'I am authorized to test Acme',
        scope: ['example.com'],
        start: '2026-10-01',
        end: '2026-12-31',
      }),
    });
    const record = await engagement.json();
    await fetch(`${base}/engagements/${record.id}/secrets`, {
      method: 'POST',
      headers: acme,
      body: JSON.stringify({ testUsername: 'trainee', testPassword: 'not-a-spray-list' }),
    });
    const spray = await fetch(`${base}/engagements/${record.id}/spray`, {
      method: 'POST',
      headers: acme,
      body: '{}',
    });
    assert.equal(spray.status, 403);
    assert.equal((await spray.json()).code, 'spray-refused');
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
