import assert from 'node:assert/strict';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import test from 'node:test';
import express from 'express';
import { createRouter } from './router.js';
import { createFileStore } from './store.js';
import { classifyHosts, collectLinkDump, linksOnPage } from './links.js';

const listen = (app) =>
  new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

test('page links keep web addresses and drop scripts', () => {
  const links = linksOnPage(
    '<a href="/docs">docs</a><a href="https://other.example.net/a">out</a><a href="javascript:alert(1)">x</a><a href="mailto:a@example.com">m</a>',
    'https://www.example.com/index.html',
  );
  assert.deepEqual(links, ['https://www.example.com/docs', 'https://other.example.net/a']);
});

test('a dump collapses to new hosts and skips ones already scanned', () => {
  const seen = new Map([['example.com', { id: 'scan-1', status: 'complete' }]]);
  const plan = classifyHosts(
    [
      { host: 'example.com' },
      { host: 'example.com' },
      { host: 'www.example.com' },
      { host: 'example.org' },
      { host: 'failed.example' },
      { error: 'not a web link', value: 'mailto:a@example.com' },
      { error: 'Refusing a private, local, or metadata address', value: '127.0.0.1' },
    ],
    seen,
    2,
  );
  seen.set('failed.example', { id: 'scan-2', status: 'failed' });
  const retried = classifyHosts([{ host: 'failed.example' }, { host: 'example.com' }], seen, 2);
  assert.deepEqual(plan.queued, ['www.example.com', 'example.org']);
  assert.deepEqual(plan.held, ['failed.example']);
  assert.deepEqual(plan.duplicates, ['example.com']);
  assert.equal(plan.alreadyScanned[0].scanId, 'scan-1');
  assert.equal(plan.rejected.length, 2);
  assert.deepEqual(retried.retried, ['failed.example']);
  assert.deepEqual(retried.queued, ['failed.example']);
});

test('harvest reads the page and subdomain names without fetching the other links', async () => {
  const calls = [];
  const dump = await collectLinkDump(
    { target: 'https://example.com', text: 'https://example.com/docs\nhttps://example.com/docs' },
    {
      httpGet: async (url) => {
        const href = String(url);
        calls.push(href);
        if (href.includes('crt.sh'))
          return { status: 200, data: [{ name_value: 'www.example.com\nexample.com' }] };
        if (href.includes('certspotter') || href.includes('hackertarget')) throw new Error('skip');
        return {
          status: 200,
          data: '<a href="https://other.example.net/item">item</a><a href="/about">about</a>',
          url: 'https://example.com/',
        };
      },
    },
  );
  const hosts = dump.parsed.filter((item) => item.host).map((item) => item.host);
  assert.ok(hosts.includes('example.com'));
  assert.ok(hosts.includes('www.example.com'));
  assert.ok(hosts.includes('other.example.net'));
  assert.equal(
    calls.some((url) => url.includes('other.example.net')),
    false,
  );
});

test('the desk link route queues only the hosts that are new', async () => {
  const previousKey = process.env.WEBCHECK_API_KEY;
  const previousTenants = process.env.WEBCHECK_TENANT_KEYS;
  delete process.env.WEBCHECK_API_KEY;
  delete process.env.WEBCHECK_TENANT_KEYS;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-links-'));
  const store = createFileStore(dir);
  const done = store.createScan({
    target: 'https://example.com',
    hostname: 'example.com',
    tenant: 'default',
    status: 'queued',
  });
  store.updateScan(done.id, { status: 'complete' });
  const router = createRouter({
    store,
    schedule: false,
    executeScan: async () => ({ scannedAt: '2026-10-24T00:00:00.000Z' }),
  });
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  const server = await listen(app);
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/v1/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        text: 'https://example.com/docs\nexample.com\nhttps://example.org/a\nmailto:a@example.com\nhttp://127.0.0.1/',
      }),
    });
    const body = await response.json();
    assert.equal(response.status, 202);
    assert.deepEqual(body.queued, ['example.org']);
    assert.equal(body.alreadyScanned[0].host, 'example.com');
    assert.equal(body.duplicates.includes('example.com'), true);
    assert.equal(body.rejected.length, 2);
    assert.equal(
      store.listScans('default').filter((scan) => scan.hostname === 'example.com').length,
      1,
    );
    assert.equal(
      store.listScans('default').some((scan) => scan.hostname === 'example.org'),
      true,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    if (previousKey == null) delete process.env.WEBCHECK_API_KEY;
    else process.env.WEBCHECK_API_KEY = previousKey;
    if (previousTenants == null) delete process.env.WEBCHECK_TENANT_KEYS;
    else process.env.WEBCHECK_TENANT_KEYS = previousTenants;
  }
});
