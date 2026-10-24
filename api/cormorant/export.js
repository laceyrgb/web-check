import fs from 'fs';
import path from 'path';
import { renderReport as defaultRender } from './pdf.js';
import { canonicalHost, httpError } from './util.js';

const sameHost = (value, target) => {
  if (!target) return true;
  try {
    return canonicalHost(value) === target;
  } catch {
    return false;
  }
};

const PRIVATE_KEY =
  /password|passwd|secret|credential|api[-_]?key|token|sessioncookie|authorization/i;

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export const crc32 = (buffer) => {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
};

const stripPrivate = (value) => {
  if (Array.isArray(value)) return value.map(stripPrivate);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (PRIVATE_KEY.test(key)) continue;
    out[key] = stripPrivate(item);
  }
  return out;
};

const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char],
  );

export const zipStore = (files) => {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(String(file.name).replace(/\\/g, '/').replace(/^\/+/, ''), 'utf8');
    if (name.includes('..')) throw httpError(400, 'Bundle path is not allowed');
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(String(file.data));
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(Buffer.concat([local, name, data]));
    centrals.push(Buffer.concat([central, name]));
    offset += 30 + name.length + data.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, eocd]);
};

const safeName = (value) =>
  String(value || 'item')
    .replace(/[^a-z0-9.-]/gi, '_')
    .slice(0, 80);

export const collectBundle = async ({ store, tenant, target, renderReport = defaultRender }) => {
  const scans = store
    .listScans(tenant)
    .filter((scan) => sameHost(scan.hostname, target))
    .slice(0, 200);
  const monitors = store
    .listMonitors(tenant)
    .filter((row) => sameHost(row.target || row.hostname, target));
  const nmapJobs = (store.listNmap?.(tenant) || []).filter((row) =>
    sameHost(row.target || row.hostname, target),
  );
  const shots = (store.listScreenshots?.(undefined, tenant) || []).filter((row) =>
    sameHost(row.target || row.hostname, target),
  );
  const authorizations = (store.listAuthorizations?.(tenant) || []).filter((row) =>
    sameHost(row.target || row.hostname, target),
  );
  const hosts = [...new Set(scans.map((scan) => scan.hostname).filter(Boolean))];
  if (!scans.length && !monitors.length && !nmapJobs.length) {
    throw httpError(409, 'Nothing stored for this tenant yet', { code: 'export-empty' });
  }
  const files = [];
  const scanRows = [];
  for (const scan of scans) {
    const record = stripPrivate({
      id: scan.id,
      target: scan.target,
      hostname: scan.hostname,
      status: scan.status,
      createdAt: scan.createdAt,
      finishedAt: scan.finishedAt || null,
      results: scan.results || null,
      changes: scan.changes || [],
    });
    files.push({ name: `scans/${scan.id}.json`, data: JSON.stringify(record, null, 2) });
    if (scan.status === 'complete' && scan.results) {
      const pdf = await renderReport({
        ...scan.results,
        id: scan.id,
        target: scan.target,
        scannedAt: scan.results.scannedAt,
      });
      files.push({ name: `reports/${safeName(scan.hostname)}-${scan.id}.pdf`, data: pdf });
    }
    scanRows.push({
      id: scan.id,
      hostname: scan.hostname,
      status: scan.status,
      createdAt: scan.createdAt,
      pdf: scan.status === 'complete',
    });
  }
  const assets = {};
  const timeline = {};
  for (const host of hosts) {
    assets[host] = stripPrivate(store.getAssets(host, tenant));
    timeline[host] = stripPrivate(store.timeline(host, tenant));
  }
  files.push({ name: 'assets.json', data: JSON.stringify(assets, null, 2) });
  files.push({ name: 'timeline.json', data: JSON.stringify(timeline, null, 2) });
  files.push({ name: 'monitors.json', data: JSON.stringify(stripPrivate(monitors), null, 2) });
  files.push({ name: 'nmap.json', data: JSON.stringify(stripPrivate(nmapJobs), null, 2) });
  files.push({
    name: 'authorizations.json',
    data: JSON.stringify(stripPrivate(authorizations), null, 2),
  });
  const shotFiles = [];
  for (const shot of shots) {
    if (!shot.file) continue;
    const source = path.join(store.dir, 'screenshots', path.basename(shot.file));
    if (!fs.existsSync(source)) continue;
    files.push({ name: `screenshots/${path.basename(shot.file)}`, data: fs.readFileSync(source) });
    shotFiles.push(source);
  }
  const exportedAt = new Date().toISOString();
  const manifest = {
    product: 'Cormorant OSINT Desk',
    offline: true,
    tenant,
    target: target || null,
    exportedAt,
    scans: scanRows,
    note: 'This folder is the offline copy. It does not contact the server. API keys, passwords, session cookies, and engagement secrets are not included.',
  };
  files.unshift({ name: 'manifest.json', data: JSON.stringify(manifest, null, 2) });
  files.unshift({ name: 'README.txt', data: readme(manifest) });
  files.unshift({ name: 'index.html', data: indexHtml(manifest) });
  return {
    files,
    manifest,
    shotFiles,
    removal: {
      scanIds: scans.map((scan) => scan.id),
      bulkIds: [...new Set(scans.map((scan) => scan.bulkId).filter(Boolean))],
      monitorIds: monitors.map((row) => row.id),
      nmapIds: nmapJobs.map((row) => row.id),
      screenshotIds: shots.map((row) => row.id),
      authorizationIds: authorizations.map((row) => row.id),
      hosts,
    },
  };
};

const readme = (manifest) =>
  [
    'Cormorant offline copy',
    `Tenant: ${manifest.tenant}`,
    `Exported: ${manifest.exportedAt}`,
    '',
    'Open index.html from this drive. The page uses only the files next to it.',
    'Do not put this folder on a web server or a shared cloud drive.',
    manifest.note,
    '',
  ].join('\n');

const indexHtml = (manifest) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Cormorant offline copy</title>
  <style>
    body { font: 16px/1.45 Georgia, serif; margin: 2rem auto; max-width: 42rem; color: #102033; background: #f4f7f6; }
    h1 { color: #0B1F33; } a { color: #1F6F6A; }
  </style>
</head>
<body>
  <h1>Cormorant offline copy</h1>
  <p>Tenant ${esc(manifest.tenant)}. Exported ${esc(manifest.exportedAt)}. This page does not contact a server.</p>
  <ul>
    ${manifest.scans.map((scan) => `<li>${esc(scan.createdAt)} ${esc(scan.hostname)} (${esc(scan.status)}) <a href="scans/${esc(scan.id)}.json">JSON</a>${scan.pdf ? ` <a href="reports/${esc(safeName(scan.hostname))}-${esc(scan.id)}.pdf">PDF</a>` : ''}</li>`).join('')}
  </ul>
  <p>${esc(manifest.note)}</p>
</body>
</html>
`;

export const assertExportRoot = (root, dataDir) => {
  if (!root)
    throw httpError(
      409,
      'WEBCHECK_EXPORT_DIR is not set. Mount the USB or external drive and point WEBCHECK_EXPORT_DIR at that mount, or download /api/v1/export.zip and save the file onto the drive.',
      { code: 'export-dir-unset' },
    );
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    throw httpError(
      409,
      'WEBCHECK_EXPORT_DIR is not a mounted directory. Plug in the drive and use its mount path.',
      { code: 'export-dir-missing' },
    );
  }
  const rootReal = fs.realpathSync(root);
  if (rootReal === path.parse(rootReal).root) {
    throw httpError(400, 'WEBCHECK_EXPORT_DIR must be the drive mount, not the filesystem root.', {
      code: 'export-dir-unsafe',
    });
  }
  let dataReal = null;
  try {
    dataReal = fs.realpathSync(dataDir);
  } catch {
    dataReal = path.resolve(dataDir);
  }
  if (rootReal === dataReal || rootReal.startsWith(`${dataReal}${path.sep}`)) {
    throw httpError(400, 'WEBCHECK_EXPORT_DIR must be outside the server data directory.', {
      code: 'export-dir-unsafe',
    });
  }
  return rootReal;
};

const writeFiles = (dir, files) => {
  for (const file of files) {
    const name = String(file.name).replace(/\\/g, '/');
    if (name.includes('..') || path.isAbsolute(name))
      throw httpError(400, 'Bundle path is not allowed');
    const dest = path.resolve(dir, name);
    if (!dest.startsWith(`${dir}${path.sep}`))
      throw httpError(400, 'Bundle path escaped the drive');
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const handle = fs.openSync(dest, 'w', 0o600);
    try {
      fs.writeFileSync(handle, file.data);
      fs.fsyncSync(handle);
    } finally {
      fs.closeSync(handle);
    }
  }
  const marker = path.join(dir, 'COMPLETE');
  const handle = fs.openSync(marker, 'w', 0o600);
  try {
    fs.writeFileSync(handle, 'ok\n');
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
};

export const exportToDrive = async ({
  store,
  tenant,
  target,
  removeLocal = false,
  root = process.env.WEBCHECK_EXPORT_DIR,
  renderReport,
} = {}) => {
  const rootReal = assertExportRoot(root, store.dir);
  const bundle = await collectBundle({ store, tenant, target, renderReport });
  const stamp = bundle.manifest.exportedAt.replace(/[:.]/g, '-');
  const tenantName = String(tenant || 'default').replace(/[^a-z0-9-]/gi, '') || 'default';
  const partial = path.resolve(rootReal, tenantName, `.partial-${stamp}`);
  if (!partial.startsWith(`${rootReal}${path.sep}`))
    throw httpError(400, 'Export path escaped the drive');
  fs.mkdirSync(partial, { recursive: true, mode: 0o700 });
  const partialReal = fs.realpathSync(partial);
  if (!partialReal.startsWith(`${rootReal}${path.sep}`)) {
    fs.rmSync(partialReal, { recursive: true, force: true });
    throw httpError(400, 'Export path escaped the drive', { code: 'export-dir-unsafe' });
  }
  try {
    writeFiles(partialReal, bundle.files);
  } catch (error) {
    fs.rmSync(partialReal, { recursive: true, force: true });
    throw error;
  }
  const finalDir = path.resolve(rootReal, tenantName, stamp);
  fs.renameSync(partialReal, finalDir);
  if (
    !fs.existsSync(path.join(finalDir, 'COMPLETE')) ||
    !fs.existsSync(path.join(finalDir, 'index.html'))
  ) {
    throw httpError(500, 'Drive write did not finish. Server records were left in place.');
  }
  let removed = null;
  if (removeLocal) {
    removed = store.removeExported(tenant, bundle.removal);
    for (const file of bundle.shotFiles) {
      try {
        fs.unlinkSync(file);
      } catch (error) {
        if (error.code !== 'ENOENT') removed.filesLeft = [...(removed.filesLeft || []), file];
      }
    }
  }
  return {
    directory: finalDir,
    tenant,
    scans: bundle.manifest.scans.length,
    removeLocal: Boolean(removeLocal),
    removed,
    note: bundle.manifest.note,
  };
};

export const exportZip = async ({ store, tenant, target, renderReport } = {}) => {
  const bundle = await collectBundle({ store, tenant, target, renderReport });
  const stamp = bundle.manifest.exportedAt.slice(0, 10);
  return {
    zip: zipStore(bundle.files),
    filename: `cormorant-${safeName(tenant)}-${stamp}.zip`,
    note: 'Save this zip onto the USB or external drive. The server copy is unchanged. Use the drive export with removeLocal to delete it after the drive write succeeds.',
  };
};
