import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import zlib from 'node:zlib';
import express from 'express';
import { sieveHosts } from './hosts.js';
import { lookupCves } from './cve.js';
import { toPublicBreach } from './breach.js';
import { generateLookalikes } from './lookalike.js';
import { hostInScope, robotsAllows } from './util.js';
import { scorePosture } from './posture.js';
import { diffScans, scoreRisk } from './risk.js';
import { updateInventory } from './inventory.js';
import { analyzeApkFiles, readZip } from './apk.js';
import { assertNmapAuthorized, buildNmapArgs, parseNmapXml } from './nmap.js';
import { buildNucleiArgs, parseNucleiJsonl, simulationTemplate } from './pentest.js';
import { renderReport } from './pdf.js';
import { createFileStore } from './store.js';
import { createRouter } from './router.js';

const savedEnv = { ...process.env };

test.afterEach(() => {
  for (const key of [
    'WEBCHECK_API_KEY',
    'WEBCHECK_NMAP_ENABLED',
    'WEBCHECK_PENTEST_ENABLED',
    'WEBCHECK_DISABLE_SCHEDULER',
  ]) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

test('sieveHosts drops the apex and wildcard labels', () => {
  assert.deepEqual(
    sieveHosts(
      ['example.com', '*.www.example.com', 'api.example.com', 'other.test'],
      'example.com',
    ),
    ['api.example.com', 'www.example.com'],
  );
});

test('lookupCves skips unknown versions and does not call NVD', async () => {
  let called = false;
  const result = await lookupCves([{ name: 'nginx' }], {
    paceMs: 0,
    cache: new Map(),
    fetchImpl: async () => {
      called = true;
      throw new Error('should not fetch');
    },
  });
  assert.equal(called, false);
  assert.equal(result.skipped[0].status, 'version-unknown');
  assert.equal(result.findings.length, 0);
});

test('lookupCves uses a CPE match for a disclosed version', async () => {
  const result = await lookupCves([{ name: 'nginx', version: '1.24.0' }], {
    paceMs: 0,
    cache: new Map(),
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        totalResults: 1,
        vulnerabilities: [
          {
            cve: {
              id: 'CVE-2024-0001',
              descriptions: [{ lang: 'en', value: 'Example issue' }],
              metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH', baseScore: 7.5 } }] },
            },
          },
        ],
      }),
    }),
  });
  assert.equal(result.findings[0].id, 'CVE-2024-0001');
  assert.equal(result.findings[0].severity, 'HIGH');
  assert.equal(result.findings[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2024-0001');
});

test('breach records stay on the public allowlist', () => {
  const row = toPublicBreach(
    {
      Name: 'Adobe',
      Title: 'Adobe',
      BreachDate: '2013-10-04',
      Password: 'nope',
      DataClasses: ['passwords'],
    },
    'Have I Been Pwned',
  );
  assert.equal(row.fact, 'Appeared in public breach Adobe');
  assert.equal('Password' in row, false);
  assert.equal(JSON.stringify(row).includes('nope'), false);
});

test('lookalikes never include the real domain', () => {
  const names = generateLookalikes('example.com');
  assert.equal(names.includes('example.com'), false);
  assert.ok(names.includes('example.ae'));
  assert.ok(names.includes('example.com.ae'));
  assert.ok(names.some((name) => name.startsWith('xn--')));
});

test('robots.txt star rules are the only ones enforced', () => {
  assert.equal(robotsAllows('User-agent: *\nDisallow: /\n', '/'), false);
  assert.equal(robotsAllows('User-agent: Other\nDisallow: /\n', '/'), true);
});

test('posture drops points when HSTS is missing', () => {
  const scored = scorePosture({
    headers: {
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
  assert.equal(scored.score, 85);
  assert.ok(scored.findings.some((row) => /HSTS/.test(row.title)));
});

test('risk score deducts for a critical CVE and stays unset without data', () => {
  const scored = scoreRisk({ cves: { findings: [{ id: 'CVE-1', severity: 'CRITICAL' }] } });
  assert.equal(scored.score, 75);
  assert.equal(scored.letter, 'B');
  const empty = scoreRisk({});
  assert.equal(empty.score, null);
  assert.equal(empty.letter, 'n/a');
});

test('scan diffs report new hosts and a worse score', () => {
  const changes = diffScans(
    {
      hosts: ['a.example.com'],
      riskScore: 90,
      openPorts: [],
      cveIds: [],
      leakUrls: [],
      lookalikesLive: [],
      certHosts: [],
    },
    {
      hosts: ['a.example.com', 'b.example.com'],
      riskScore: 70,
      openPorts: [],
      cveIds: [],
      leakUrls: [],
      lookalikesLive: [],
      certHosts: [],
    },
  );
  assert.ok(changes.some((row) => row.type === 'new-subdomain' && row.value === 'b.example.com'));
  assert.ok(changes.some((row) => row.type === 'risk-worse'));
});

test('inventory keeps the first time an asset was seen', () => {
  const first = updateInventory(
    null,
    {
      target: 'example.com',
      attackSurface: {
        hosts: [{ host: 'www.example.com', source: 'ct' }],
        ports: { open: [] },
        technologies: [],
      },
    },
    '2026-10-01T00:00:00.000Z',
  );
  const second = updateInventory(
    first,
    {
      target: 'example.com',
      attackSurface: {
        hosts: [{ host: 'www.example.com', source: 'ct' }],
        ports: { open: ['443'] },
        technologies: [],
      },
    },
    '2026-10-02T00:00:00.000Z',
  );
  assert.equal(second.items['host:www.example.com'].firstSeen, '2026-10-01T00:00:00.000Z');
  assert.equal(second.items['host:www.example.com'].lastSeen, '2026-10-02T00:00:00.000Z');
  assert.equal(second.items['service:443'].firstSeen, '2026-10-02T00:00:00.000Z');
});

test('nmap profiles stay connect-scan and script free', () => {
  for (const profile of ['default', 'version', 'deeper', 'syn']) {
    const args = buildNmapArgs(profile, '203.0.113.10');
    assert.equal(args.includes('-A'), false);
    assert.equal(args.includes('-O'), false);
    assert.equal(
      args.some((arg) => String(arg).startsWith('--script')),
      false,
    );
    assert.equal(args.at(-1), '203.0.113.10');
  }
  assert.ok(buildNmapArgs('default', '203.0.113.10').includes('-sT'));
  assert.ok(buildNmapArgs('syn', '203.0.113.10').includes('-sS'));
  assert.throws(() => buildNmapArgs('default', 'example.com'), /single IP/);
});

test('nmap authorization is required and SYN needs root', () => {
  assert.throws(
    () =>
      assertNmapAuthorized({
        enabled: false,
        authorization: { acknowledged: true, operator: 'Casey', ip: '203.0.113.10' },
      }),
    (error) => error.status === 403,
  );
  assert.throws(
    () =>
      assertNmapAuthorized({
        enabled: true,
        authorization: { operator: 'Casey', ip: '203.0.113.10' },
        profile: 'default',
      }),
    (error) => error.status === 403,
  );
  assert.throws(
    () =>
      assertNmapAuthorized({
        enabled: true,
        profile: 'syn',
        uid: 1000,
        authorization: { acknowledged: true, operator: 'Casey', ip: '203.0.113.10' },
      }),
    (error) => error.status === 400,
  );
});

test('scope matching is suffix based', () => {
  assert.equal(hostInScope('www.example.com', ['example.com']), true);
  assert.equal(hostInScope('ample.com', ['example.com']), false);
  assert.equal(hostInScope('notexample.com', ['example.com']), false);
});

test('simulation templates are labeled and do not collect credentials', () => {
  const template = simulationTemplate({ clientName: 'Acme', operator: 'Casey' });
  const blob = `${template.subject}\n${template.text}\n${template.html}`.toLowerCase();
  assert.match(template.label, /SIMULATION/);
  assert.equal(blob.includes('<form'), false);
  assert.equal(blob.includes('password'), false);
  assert.match(template.text, /\{\{SIMULATION_URL\}\}/);
});

test('nuclei output drops exploit payloads and honors the severity cap', () => {
  const args = buildNucleiArgs('https://example.com', 'medium');
  assert.ok(args.includes('-exclude-tags'));
  assert.equal(args[args.indexOf('-exclude-tags') + 1], 'dos,fuzz,intrusive,exploit,rce,sqli');
  assert.ok(args.includes('-ni'));
  const findings = parseNucleiJsonl(
    [
      JSON.stringify({
        'template-id': 'info-check',
        info: { severity: 'low', name: 'Banner' },
        host: 'https://example.com',
        request: 'GET /secret-payload',
      }),
      JSON.stringify({
        'template-id': 'too-hot',
        info: { severity: 'critical', name: 'Nope' },
        host: 'https://example.com',
      }),
    ].join('\n'),
    'medium',
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'info-check');
  assert.equal(JSON.stringify(findings).includes('secret-payload'), false);
});

const zipStored = (files) => {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name);
    const data = Buffer.from(file.data);
    const crc = zlib.crc32(data);
    const local = Buffer.alloc(30 + name.length + data.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(crc >>> 0, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    data.copy(local, 30 + name.length);
    locals.push(local);
    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc >>> 0, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    centrals.push(central);
    offset += local.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
};

test('apk review is static and redacts secret values', () => {
  const archive = zipStored([
    {
      name: 'AndroidManifest.xml',
      data: '<manifest><uses-permission android:name="android.permission.INTERNET"/><activity android:exported="true" android:name=".MainActivity"></activity></manifest>',
    },
    {
      name: 'res/values/secrets.txt',
      data: 'api_key="supersecretvalue"\nAKIAIOSFODNN7EXAMPLE\n',
    },
  ]);
  const analysis = analyzeApkFiles(readZip(archive));
  assert.ok(analysis.permissions.includes('android.permission.INTERNET'));
  assert.equal(analysis.exportedComponents[0].name, '.MainActivity');
  const encoded = JSON.stringify(analysis);
  assert.equal(encoded.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.equal(encoded.includes('supersecretvalue'), false);
  assert.ok(
    analysis.secrets.some((row) => row.type === 'aws-access-key' && row.preview.startsWith('AKIA')),
  );
});

test('nmap xml becomes host, port, and service records', () => {
  const parsed = parseNmapXml(
    `<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"></service></port></ports></host></nmaprun>`,
  );
  assert.equal(parsed.hosts[0].address, '203.0.113.10');
  assert.equal(parsed.hosts[0].ports[0].port, 443);
  assert.equal(parsed.hosts[0].ports[0].service, 'https');
  assert.equal(parsed.hosts[0].ports[0].version, '1.24.0');
});

test('a passive scan never calls nmap, nuclei, or a sprayer', () => {
  const source = fs.readFileSync(new URL('./scan.js', import.meta.url), 'utf8');
  assert.equal(/nmap|nuclei|spray/i.test(source), false);
});

test('pdf report names Cormorant and the target', async () => {
  const pdf = await renderReport({
    target: 'example.com',
    scannedAt: '2026-10-22T00:00:00.000Z',
    executiveSummary: ['Observed only.'],
  });
  assert.equal(pdf.subarray(0, 4).toString(), '%PDF');
  const text = [...pdf.toString('latin1').matchAll(/<([0-9A-Fa-f]+)>/g)]
    .map((match) => Buffer.from(match[1], 'hex').toString('latin1'))
    .join('');
  assert.match(text, /Cormorant Cyber/);
  assert.match(text, /example\.com/);
});

const listen = (app) =>
  new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

const close = (server) => new Promise((resolve) => server.close(resolve));

test('desk API gates scans, nmap, engagements, and spraying', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-'));
  const store = createFileStore(dir);
  let nmapCalls = [];
  const router = createRouter({
    store,
    schedule: false,
    executeScan: async (target) => ({
      target,
      scannedAt: '2026-10-22T00:00:00.000Z',
      attackSurface: {
        hosts: [],
        hostCount: 0,
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
      posture: { score: 90, letter: 'A' },
      risk: { score: 90, letter: 'A', factors: [] },
      executiveSummary: ['Observed only.'],
    }),
    nmapRunner: async (_cmd, args) => {
      nmapCalls.push(args);
      if (args[0] === '-V') return { stdout: 'Nmap version 7.95\n' };
      return {
        stdout:
          '<nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"></service></port></ports></host></nmaprun>',
      };
    },
  });
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  const server = await listen(app);
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  const headers = { 'content-type': 'application/json', 'x-api-key': 'desk-test-key' };
  try {
    process.env.WEBCHECK_API_KEY = 'desk-test-key';
    const locked = await fetch(`${base}/scans`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"target":"example.com"}',
    });
    assert.equal(locked.status, 401);
    const started = await fetch(`${base}/scans`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ target: 'example.com' }),
    });
    assert.equal(started.status, 202);
    const scan = await started.json();
    await router.queue.whenIdle();
    const status = await fetch(`${base}/scans/${scan.id}`, { headers });
    assert.equal((await status.json()).status, 'complete');
    assert.equal(
      nmapCalls.some((args) => args[0] !== '-V'),
      false,
    );

    const mismatch = await fetch(`${base}/authorizations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        target: '1.1.1.1',
        confirm: 'wrong',
        operator: 'Casey',
        acknowledged: true,
      }),
    });
    const mismatchBody = await mismatch.json();
    assert.equal(mismatch.status, 400);
    assert.equal(mismatchBody.canonical, '1.1.1.1');

    const local = await fetch(`${base}/authorizations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        target: '127.0.0.1',
        confirm: '127.0.0.1',
        operator: 'Casey',
        acknowledged: true,
      }),
    });
    assert.equal(local.status, 400);
    const metadata = await fetch(`${base}/authorizations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        target: 'metadata.google.internal',
        confirm: 'metadata.google.internal',
        operator: 'Casey',
        acknowledged: true,
      }),
    });
    assert.equal(metadata.status, 400);

    const authRes = await fetch(`${base}/authorizations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        target: '1.1.1.1',
        confirm: '1.1.1.1',
        operator: 'Casey',
        acknowledged: true,
      }),
    });
    assert.equal(authRes.status, 201);
    const authorization = await authRes.json();
    delete process.env.WEBCHECK_NMAP_ENABLED;
    const disabled = await fetch(`${base}/nmap`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ authorizationId: authorization.id, profile: 'default' }),
    });
    assert.equal(disabled.status, 403);
    process.env.WEBCHECK_NMAP_ENABLED = 'true';
    const queued = await fetch(`${base}/nmap`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ authorizationId: authorization.id, profile: 'default' }),
    });
    assert.equal(queued.status, 202);
    const job = await queued.json();
    let finished;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      finished = await (await fetch(`${base}/nmap/${job.id}`, { headers })).json();
      if (finished.status === 'complete' || finished.status === 'failed') break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(finished.status, 'complete');
    assert.equal(
      (finished.flags || []).some(
        (flag) => flag === '-A' || flag === '-O' || String(flag).startsWith('--script'),
      ),
      false,
    );

    delete process.env.WEBCHECK_PENTEST_ENABLED;
    const closed = await fetch(`${base}/engagements`, {
      method: 'POST',
      headers,
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
    assert.equal(closed.status, 403);
    process.env.WEBCHECK_PENTEST_ENABLED = 'true';
    const badPhrase = await fetch(`${base}/engagements`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        clientName: 'Acme',
        operator: 'Casey',
        acknowledged: true,
        confirm: 'please',
        scope: ['example.com'],
        start: '2026-10-01',
        end: '2026-12-31',
      }),
    });
    assert.equal(badPhrase.status, 403);
    const opened = await fetch(`${base}/engagements`, {
      method: 'POST',
      headers,
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
    assert.equal(opened.status, 201);
    const engagement = await opened.json();
    await fetch(`${base}/engagements/${engagement.id}/secrets`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ testPassword: 'not-returned' }),
    });
    const visible = await (await fetch(`${base}/engagements/${engagement.id}`, { headers })).json();
    assert.equal(JSON.stringify(visible).includes('not-returned'), false);
    assert.equal(visible.testPassword, undefined);
    const spray = await fetch(`${base}/engagements/${engagement.id}/spray`, {
      method: 'POST',
      headers,
      body: '{}',
    });
    assert.equal(spray.status, 403);
    assert.equal((await spray.json()).code, 'spray-refused');
  } finally {
    await close(server);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
