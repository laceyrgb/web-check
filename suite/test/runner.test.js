import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import test from 'node:test';

import { buildNucleiArgs, findingsFromNuclei } from '../engines/nuclei.js';
import { diffReports } from '../diff.js';
import { renderHtml } from '../report-html.js';
import { runScan } from '../runner.js';

const TOKEN = 'cormorant-test-token';
const quiet = { env: {}, now: '2026-11-01T00:00:00.000Z' };

const listen = (server) =>
  new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });

test('a government name is refused before any transport is used', async () => {
  let called = false;
  const report = await runScan({
    ...quiet,
    target: 'https://unit.test.gov.ae',
    transports: {
      resolveTxt: async () => {
        called = true;
        return [];
      },
      httpGet: async () => {
        called = true;
        return { status: 200, headers: {}, body: '' };
      },
    },
  });
  assert.equal(called, false);
  assert.equal(report.score, null);
  assert.equal(report.legal.denyRule, 'uae-gov');
  assert.equal(report.findings[0].id, 'legal.denylist.blocked');
  assert.match(report.summary.ar, /لم يُنفَّذ فحص/);
});

test('passive mode does not request sensitive paths or open sockets', async () => {
  const urls = [];
  await runScan({
    ...quiet,
    target: 'http://127.0.0.1',
    mode: 'passive',
    transports: {
      httpGet: async (url) => {
        urls.push(url);
        return { status: 200, headers: {}, body: '<html>ok</html>' };
      },
      connect: async () => {
        throw new Error('passive mode must not connect to ports');
      },
    },
  });
  assert.ok(urls.length >= 1);
  assert.equal(
    urls.some((url) => url.includes('/.git') || url.includes('/.env')),
    false,
  );
});

test('active checks stay off without authorisation, and off when ownership fails', async () => {
  const urls = [];
  const transports = {
    resolveTxt: async () => [],
    httpGet: async (url) => {
      urls.push(url);
      return { status: 404, headers: {}, body: '' };
    },
    connect: async () => {
      throw new Error('ports must stay closed');
    },
  };
  await runScan({ ...quiet, target: 'http://127.0.0.1', mode: 'active', transports });
  assert.equal(
    urls.some((url) => url.includes('/.git')),
    false,
  );
  urls.length = 0;
  await runScan({
    ...quiet,
    target: 'http://127.0.0.1',
    mode: 'active',
    authorized: true,
    verificationToken: TOKEN,
    transports,
  });
  assert.equal(
    urls.some((url) => url.includes('/.git')),
    false,
  );
  assert.ok(urls.some((url) => url.includes('/.well-known/cormorant-verify.txt')));
});

test('an authorised localhost target can be checked for a readable git directory', async () => {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url);
    if (req.url === '/.well-known/cormorant-verify.txt') {
      res.end(TOKEN);
      return;
    }
    if (req.url === '/.git/HEAD') {
      res.end('ref: refs/heads/main\n');
      return;
    }
    res.writeHead(404);
    res.end('no');
  });
  const port = await listen(server);
  const origin = `http://127.0.0.1:${port}`;
  try {
    const report = await runScan({
      ...quiet,
      target: origin,
      mode: 'active',
      authorized: true,
      verificationToken: TOKEN,
      transports: {
        resolveTxt: async (name) =>
          name.startsWith('_cormorant-verify.') ? [[`cormorant-verify=${TOKEN}`]] : [],
        httpGet: (url) =>
          fetch(url).then(async (response) => ({
            status: response.status,
            headers: Object.fromEntries(response.headers),
            body: await response.text(),
            finalUrl: url,
          })),
        connect: async () => false,
        inspectTls: async () => ({
          protocol: 'TLSv1.3',
          authorized: true,
          bits: 2048,
          validTo: '2030-01-01T00:00:00.000Z',
        }),
      },
    });
    assert.equal(report.legal.activeRan, true);
    assert.equal(report.legal.ownership.method, 'dns-txt');
    assert.ok(report.findings.some((item) => item.id === 'exposure.git'));
    assert.equal(JSON.stringify(report).includes(TOKEN), false);
    assert.ok(hits.some((url) => url === '/.git/HEAD'));
  } finally {
    server.close();
  }
});

test('the sample snapshot produces a bilingual report without copying the cookie value', async () => {
  const observations = JSON.parse(
    readFileSync(new URL('../fixtures/example-observations.json', import.meta.url)),
  );
  const report = await runScan({
    ...quiet,
    target: 'https://scan.example',
    observations,
  });
  const wanted = [
    'email.spf.pass',
    'email.dmarc.monitor',
    'email.dkim.not-seen',
    'dns.ns.single',
    'dns.dnssec.missing',
    'dns.caa.missing',
    'dns.cname.dangling-service',
    'tls.protocol.legacy',
    'headers.hsts.missing',
    'tech.apache.path-traversal',
    'tech.jquery.html',
    'ports.3306',
    'cors.wildcard',
  ];
  const have = new Set(report.findings.map((item) => item.id));
  for (const id of wanted) assert.ok(have.has(id), id);
  assert.equal(report.source, 'supplied');
  assert.equal(report.legal.activeRan, false);
  assert.ok(report.score.value < 50);
  assert.ok(report.prioritisedFixes.length > 0);
  assert.match(report.summary.en, /not a penetration test/);
  assert.match(report.summary.ar, /ليس اختبار اختراق/);
  const packed = JSON.stringify(report) + renderHtml(report);
  assert.equal(packed.includes('secretvalue'), false);
  assert.equal(packed.includes('jquery-3.4.1.min.js'), false);
  const html = renderHtml(report);
  assert.match(html, /فحص الجاهزية للإمارات/);
  assert.match(html, /Reference only/);
  assert.match(html, /للاسترشاد فقط/);
});

test('cookie names are escaped in the HTML report', async () => {
  const report = await runScan({
    ...quiet,
    target: 'https://scan.example',
    observations: { http: { scheme: 'https', headers: { 'set-cookie': '<script>=1; Path=/' } } },
  });
  const html = renderHtml(report);
  assert.equal(html.includes('<script>'), false);
  assert.match(html, /&lt;script&gt;/);
});

test('nuclei is not started from a snapshot, and its parser drops exploit tags and response bodies', async () => {
  let spawned = false;
  await runScan({
    ...quiet,
    target: 'https://scan.example',
    mode: 'active',
    authorized: true,
    verificationToken: TOKEN,
    ownership: { ok: true, method: 'dns-txt' },
    observations: { http: { scheme: 'https', headers: {} } },
    engines: { nuclei: '/usr/bin/nuclei' },
    transports: {
      spawn: async () => {
        spawned = true;
        return { stdout: '', code: 0 };
      },
    },
  });
  assert.equal(spawned, false);
  const args = buildNucleiArgs('https://scan.example');
  assert.ok(args.includes('-no-interactsh'));
  assert.ok(args.includes('-omit-raw'));
  assert.match(args.join(' '), /exclude-tags/);
  assert.match(args.join(' '), /exploit/);
  assert.equal(args.includes('-interactsh-url'), false);
  const findings = findingsFromNuclei([
    {
      'template-id': 'exposed-env',
      info: { name: 'Env file', severity: 'high', tags: 'exposure' },
      'matched-at': 'https://scan.example/.env',
      response: 'SECRET_BODY',
    },
    {
      'template-id': 'rce',
      info: { name: 'Do not run', severity: 'critical', tags: ['exploit', 'rce'] },
    },
  ]);
  assert.equal(findings.length, 1);
  assert.equal(JSON.stringify(findings).includes('SECRET_BODY'), false);
  assert.equal(findings[0].needsHumanReview, true);
});

test('report diff lists added and removed open findings', () => {
  const changes = diffReports(
    {
      score: { value: 80 },
      findings: [
        { id: 'a', status: 'open' },
        { id: 'b', status: 'open' },
      ],
    },
    {
      score: { value: 70 },
      findings: [
        { id: 'b', status: 'open' },
        { id: 'c', status: 'open' },
      ],
    },
  );
  assert.deepEqual(
    changes.added.map((item) => item.id),
    ['c'],
  );
  assert.deepEqual(
    changes.removed.map((item) => item.id),
    ['a'],
  );
  assert.deepEqual(changes.unchanged, ['b']);
  assert.equal(changes.scoreDelta, -10);
});
