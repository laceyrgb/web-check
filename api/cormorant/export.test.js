import assert from 'node:assert/strict';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import test from 'node:test';
import express from 'express';
import { crc32, exportToDrive, exportZip, zipStore } from './export.js';
import { createRouter } from './router.js';
import { createFileStore } from './store.js';

const listen = (app) =>
  new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });

const seed = (store, tenant) => {
  const scan = store.createScan({
    target: 'https://example.com',
    hostname: 'example.com',
    tenant,
    status: 'queued',
  });
  store.updateScan(scan.id, {
    status: 'complete',
    results: {
      target: 'https://example.com',
      scannedAt: '2026-10-24T00:00:00.000Z',
      executiveSummary: ['Observed only.'],
      dossier: { organization: { name: 'Cormorant Cyber', source: 'page' } },
      sessionCookie: 'should-not-export',
      nested: { password: 'hunter2', note: 'keep' },
    },
  });
  return store.getScan(scan.id);
};

test('crc32 matches the known check value', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});

test('drive export writes an offline folder and can drop only that tenant', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-data-'));
  const drive = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-drive-'));
  const store = createFileStore(dataDir);
  const kept = seed(store, 'default');
  seed(store, 'acme');
  store.createMonitor({
    target: 'https://example.com',
    hostname: 'example.com',
    tenant: 'acme',
    everyMinutes: 1440,
  });

  const written = await exportToDrive({
    store,
    tenant: 'acme',
    removeLocal: true,
    root: drive,
    renderReport: async () => Buffer.from('%PDF-offline'),
  });
  assert.equal(fs.existsSync(path.join(written.directory, 'COMPLETE')), true);
  assert.match(
    fs.readFileSync(path.join(written.directory, 'index.html'), 'utf8'),
    /does not contact a server/,
  );
  const saved = fs.readdirSync(path.join(written.directory, 'scans'));
  const body = fs.readFileSync(path.join(written.directory, 'scans', saved[0]), 'utf8');
  assert.match(body, /Cormorant Cyber/);
  assert.equal(body.includes('hunter2'), false);
  assert.equal(body.includes('should-not-export'), false);
  assert.match(body, /keep/);
  const report = fs.readdirSync(path.join(written.directory, 'reports'))[0];
  assert.match(
    fs.readFileSync(path.join(written.directory, 'reports', report), 'utf8'),
    /%PDF-offline/,
  );
  assert.equal(store.getScan(kept.id, 'default').status, 'complete');
  assert.equal(store.listScans('acme').length, 0);
  assert.equal(store.listMonitors('acme').length, 0);
});

test('a symlink inside the mount is not used as the export destination', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-data-'));
  const drive = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-drive-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-outside-'));
  fs.symlinkSync(outside, path.join(drive, 'acme'));
  const store = createFileStore(dataDir);
  seed(store, 'acme');
  await assert.rejects(
    () =>
      exportToDrive({
        store,
        tenant: 'acme',
        removeLocal: true,
        root: drive,
        renderReport: async () => Buffer.from('%PDF'),
      }),
    (error) => error.code === 'export-dir-unsafe',
  );
  assert.equal(store.listScans('acme').length, 1);
  assert.equal(
    fs.readdirSync(outside).some((name) => name.startsWith('.partial') || name === 'COMPLETE'),
    false,
  );
});

test('export refuses the server data directory and an unset drive', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-data-'));
  const store = createFileStore(dataDir);
  seed(store, 'default');
  await assert.rejects(
    () =>
      exportToDrive({
        store,
        tenant: 'default',
        root: dataDir,
        renderReport: async () => Buffer.from('%PDF'),
      }),
    (error) => error.code === 'export-dir-unsafe',
  );
  await assert.rejects(
    () =>
      exportToDrive({
        store,
        tenant: 'default',
        root: '',
        renderReport: async () => Buffer.from('%PDF'),
      }),
    (error) => error.code === 'export-dir-unset',
  );
});

test('zip download contains the dossier and does not remove server records', async () => {
  const previousExport = process.env.WEBCHECK_EXPORT_DIR;
  const previousKey = process.env.WEBCHECK_API_KEY;
  delete process.env.WEBCHECK_EXPORT_DIR;
  process.env.WEBCHECK_API_KEY = 'desk-secret';
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cormorant-data-'));
  const store = createFileStore(dataDir);
  const scan = seed(store, 'default');
  const packed = zipStore([{ name: 'hello.txt', data: 'hello' }]);
  assert.equal(packed.readUInt32LE(0), 0x04034b50);
  const { zip } = await exportZip({
    store,
    tenant: 'default',
    renderReport: async () => Buffer.from('%PDF-offline'),
  });
  assert.match(zip.toString('latin1'), /index\.html/);
  assert.match(zip.toString('latin1'), /Cormorant Cyber/);
  assert.equal(zip.toString('latin1').includes('hunter2'), false);
  const router = createRouter({
    store,
    schedule: false,
    renderReport: async () => Buffer.from('%PDF-offline'),
  });
  const app = express();
  app.use(express.json());
  app.use('/api/v1', router);
  const server = await listen(app);
  try {
    const port = server.address().port;
    const denied = await fetch(`http://127.0.0.1:${port}/api/v1/export.zip`);
    assert.equal(denied.status, 401);
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/export.zip`, {
      headers: { 'x-api-key': 'desk-secret' },
    });
    assert.equal(response.status, 200);
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(bytes.readUInt32LE(0), 0x04034b50);
    assert.match(bytes.toString('latin1'), /offline copy/);
    const missing = await fetch(`http://127.0.0.1:${port}/api/v1/export`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': 'desk-secret' },
      body: JSON.stringify({ removeLocal: true }),
    });
    assert.equal(missing.status, 409);
    assert.equal(store.getScan(scan.id, 'default').status, 'complete');
  } finally {
    if (previousExport === undefined) delete process.env.WEBCHECK_EXPORT_DIR;
    else process.env.WEBCHECK_EXPORT_DIR = previousExport;
    if (previousKey === undefined) delete process.env.WEBCHECK_API_KEY;
    else process.env.WEBCHECK_API_KEY = previousKey;
    await new Promise((resolve) => server.close(resolve));
  }
});
