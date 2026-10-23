import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const DEFAULT_TENANT = 'default';

const empty = () => ({
  scans: {},
  bulks: {},
  monitors: {},
  authorizations: {},
  engagements: {},
  assets: { [DEFAULT_TENANT]: {} },
  timeline: { [DEFAULT_TENANT]: {} },
  nmapJobs: {},
  screenshots: {},
  __tenants: 1,
});

const isInventory = (value) =>
  value && typeof value === 'object' && !Array.isArray(value) && value.items;
const nestLeaves = (value, isLeaf) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { [DEFAULT_TENANT]: {} };
  const entries = Object.entries(value);
  if (!entries.length) return { [DEFAULT_TENANT]: {} };
  if (entries.every(([, item]) => isLeaf(item))) return { [DEFAULT_TENANT]: value };
  return value;
};

const migrateTenants = (state) => {
  if (state.__tenants) return state;
  for (const name of [
    'scans',
    'bulks',
    'monitors',
    'authorizations',
    'engagements',
    'nmapJobs',
    'screenshots',
  ]) {
    state[name] ||= {};
    for (const row of Object.values(state[name])) {
      if (row && typeof row === 'object' && !row.tenant) row.tenant = DEFAULT_TENANT;
    }
  }
  state.assets = nestLeaves(state.assets, isInventory);
  state.timeline = nestLeaves(state.timeline, Array.isArray);
  state.__tenants = 1;
  return state;
};

export const createFileStore = (
  dir = process.env.WEBCHECK_DATA_DIR || path.join(process.cwd(), '.data'),
) => {
  const file = path.join(dir, 'osint-store.json');
  const secretsFile = path.join(dir, 'secrets.json');
  let state = null;
  const load = () => {
    if (state) return state;
    try {
      state = migrateTenants(JSON.parse(fs.readFileSync(file, 'utf8')));
      state.nmapJobs ||= {};
      state.screenshots ||= {};
      state.scans ||= {};
      state.timeline ||= { [DEFAULT_TENANT]: {} };
      state.assets ||= { [DEFAULT_TENANT]: {} };
    } catch {
      state = empty();
    }
    return state;
  };
  const owned = (row, tenant) => !tenant || (row?.tenant || DEFAULT_TENANT) === tenant;
  const bucket = (collection, tenant = DEFAULT_TENANT) => {
    const root = load()[collection];
    root[tenant] ||= {};
    return root[tenant];
  };
  const save = () => {
    fs.mkdirSync(dir, { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(load()));
    fs.renameSync(tmp, file);
    fs.chmodSync(file, 0o600);
  };
  const id = () => crypto.randomUUID();
  return {
    dir,
    file,
    createScan(input) {
      const scan = {
        id: id(),
        status: 'queued',
        createdAt: new Date().toISOString(),
        ...input,
        tenant: input.tenant || DEFAULT_TENANT,
      };
      load().scans[scan.id] = scan;
      save();
      return scan;
    },
    getScan: (scanId, tenant) => {
      const scan = load().scans[scanId] || null;
      return owned(scan, tenant) ? scan : null;
    },
    updateScan(scanId, patch) {
      const scan = load().scans[scanId];
      if (!scan) return null;
      Object.assign(scan, patch);
      save();
      return scan;
    },
    listScans: (tenant) =>
      Object.values(load().scans)
        .filter((scan) => owned(scan, tenant))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
    createBulk(domains, tenant = DEFAULT_TENANT) {
      const bulk = {
        id: id(),
        domains,
        scanIds: [],
        status: 'queued',
        tenant,
        createdAt: new Date().toISOString(),
      };
      load().bulks[bulk.id] = bulk;
      save();
      return bulk;
    },
    updateBulk(bulkId, patch) {
      Object.assign(load().bulks[bulkId], patch);
      save();
      return load().bulks[bulkId];
    },
    getBulk: (bulkId, tenant) => {
      const bulk = load().bulks[bulkId] || null;
      return owned(bulk, tenant) ? bulk : null;
    },
    refreshBulk(bulkId) {
      const bulk = load().bulks[bulkId];
      if (!bulk) return null;
      const scans = bulk.scanIds.map((scanId) => load().scans[scanId]).filter(Boolean);
      bulk.status = scans.every((scan) => scan.status === 'complete' || scan.status === 'failed')
        ? 'complete'
        : 'running';
      save();
      return bulk;
    },
    createMonitor(input) {
      const monitor = {
        id: id(),
        enabled: true,
        running: false,
        changes: [],
        createdAt: new Date().toISOString(),
        ...input,
      };
      load().monitors[monitor.id] = monitor;
      save();
      return monitor;
    },
    listMonitors: (tenant) => Object.values(load().monitors).filter((row) => owned(row, tenant)),
    getMonitor: (monitorId, tenant) => {
      const monitor = load().monitors[monitorId] || null;
      return owned(monitor, tenant) ? monitor : null;
    },
    updateMonitor(monitorId, patch) {
      const monitor = load().monitors[monitorId];
      if (!monitor) return null;
      Object.assign(monitor, patch);
      save();
      return monitor;
    },
    deleteMonitor(monitorId, tenant) {
      const monitor = load().monitors[monitorId];
      if (!owned(monitor, tenant)) return false;
      delete load().monitors[monitorId];
      save();
      return true;
    },
    saveAuthorization(record) {
      const row = { id: id(), tenant: record.tenant || DEFAULT_TENANT, ...record };
      load().authorizations[row.id] = row;
      save();
      return row;
    },
    getAuthorization: (authId, tenant) => {
      const row = load().authorizations[authId] || null;
      return owned(row, tenant) ? row : null;
    },
    saveEngagement(record) {
      const row = { id: id(), tenant: record.tenant || DEFAULT_TENANT, ...record };
      load().engagements[row.id] = row;
      save();
      return row;
    },
    getEngagement: (engagementId, tenant) => {
      const row = load().engagements[engagementId] || null;
      return owned(row, tenant) ? row : null;
    },
    listEngagements: (tenant) =>
      Object.values(load().engagements).filter((row) => owned(row, tenant)),
    saveSecrets(engagementId, secrets) {
      fs.mkdirSync(dir, { recursive: true });
      let current = {};
      try {
        current = JSON.parse(fs.readFileSync(secretsFile, 'utf8'));
      } catch {
        current = {};
      }
      current[engagementId] = { ...(current[engagementId] || {}), ...secrets };
      fs.writeFileSync(secretsFile, JSON.stringify(current), { mode: 0o600 });
      fs.chmodSync(secretsFile, 0o600);
    },
    getSecrets(engagementId) {
      try {
        return JSON.parse(fs.readFileSync(secretsFile, 'utf8'))[engagementId] || {};
      } catch {
        return {};
      }
    },
    latestSummary(host, tenant = DEFAULT_TENANT) {
      const rows = bucket('timeline', tenant)[host] || [];
      return rows[rows.length - 1] || null;
    },
    rememberSummary(host, summary, tenant = DEFAULT_TENANT) {
      const rows = bucket('timeline', tenant)[host] || [];
      rows.push(summary);
      bucket('timeline', tenant)[host] = rows.slice(-30);
      save();
    },
    timeline: (host, tenant = DEFAULT_TENANT) => bucket('timeline', tenant)[host] || [],
    getAssets: (host, tenant = DEFAULT_TENANT) => bucket('assets', tenant)[host] || null,
    saveAssets(host, assets, tenant = DEFAULT_TENANT) {
      bucket('assets', tenant)[host] = assets;
      save();
    },
    saveNmap(job) {
      const row = {
        id: id(),
        status: 'queued',
        createdAt: new Date().toISOString(),
        tenant: job.tenant || DEFAULT_TENANT,
        ...job,
      };
      load().nmapJobs[row.id] = row;
      save();
      return row;
    },
    getNmap: (jobId, tenant) => {
      const job = load().nmapJobs[jobId] || null;
      return owned(job, tenant) ? job : null;
    },
    updateNmap(jobId, patch) {
      const job = load().nmapJobs[jobId];
      if (!job) return null;
      Object.assign(job, patch);
      save();
      return job;
    },
    saveScreenshot(record) {
      const row = { id: id(), tenant: record.tenant || DEFAULT_TENANT, ...record };
      load().screenshots[row.id] = row;
      save();
      return row;
    },
    updateScreenshot(shotId, patch) {
      const shot = load().screenshots[shotId];
      if (!shot) return null;
      Object.assign(shot, patch);
      save();
      return shot;
    },
    listScreenshots(target, tenant) {
      return Object.values(load().screenshots).filter(
        (row) => owned(row, tenant) && (!target || row.target === target),
      );
    },
    getScreenshot: (shotId, tenant) => {
      const shot = load().screenshots[shotId] || null;
      return owned(shot, tenant) ? shot : null;
    },
  };
};
