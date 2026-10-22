import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const empty = () => ({
  scans: {},
  bulks: {},
  monitors: {},
  authorizations: {},
  engagements: {},
  assets: {},
  timeline: {},
  nmapJobs: {},
  screenshots: {},
});

export const createFileStore = (dir = process.env.WEBCHECK_DATA_DIR || path.join(process.cwd(), '.data')) => {
  const file = path.join(dir, 'osint-store.json');
  const secretsFile = path.join(dir, 'secrets.json');
  let state = null;
  const load = () => {
    if (state) return state;
    try {
      state = JSON.parse(fs.readFileSync(file, 'utf8'));
      state.nmapJobs ||= {};
      state.screenshots ||= {};
      state.scans ||= {};
      state.timeline ||= {};
    } catch {
      state = empty();
    }
    return state;
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
      };
      load().scans[scan.id] = scan;
      save();
      return scan;
    },
    getScan: (scanId) => load().scans[scanId] || null,
    updateScan(scanId, patch) {
      const scan = load().scans[scanId];
      if (!scan) return null;
      Object.assign(scan, patch);
      save();
      return scan;
    },
    listScans: () => Object.values(load().scans).sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
    createBulk(domains) {
      const bulk = { id: id(), domains, scanIds: [], status: 'queued', createdAt: new Date().toISOString() };
      load().bulks[bulk.id] = bulk;
      save();
      return bulk;
    },
    updateBulk(bulkId, patch) {
      Object.assign(load().bulks[bulkId], patch);
      save();
      return load().bulks[bulkId];
    },
    getBulk: (bulkId) => load().bulks[bulkId] || null,
    refreshBulk(bulkId) {
      const bulk = load().bulks[bulkId];
      if (!bulk) return null;
      const scans = bulk.scanIds.map((scanId) => load().scans[scanId]).filter(Boolean);
      bulk.status = scans.every((scan) => scan.status === 'complete' || scan.status === 'failed') ? 'complete' : 'running';
      save();
      return bulk;
    },
    createMonitor(input) {
      const monitor = { id: id(), enabled: true, running: false, changes: [], createdAt: new Date().toISOString(), ...input };
      load().monitors[monitor.id] = monitor;
      save();
      return monitor;
    },
    listMonitors: () => Object.values(load().monitors),
    getMonitor: (monitorId) => load().monitors[monitorId] || null,
    updateMonitor(monitorId, patch) {
      const monitor = load().monitors[monitorId];
      if (!monitor) return null;
      Object.assign(monitor, patch);
      save();
      return monitor;
    },
    deleteMonitor(monitorId) {
      delete load().monitors[monitorId];
      save();
    },
    saveAuthorization(record) {
      const row = { id: id(), ...record };
      load().authorizations[row.id] = row;
      save();
      return row;
    },
    getAuthorization: (authId) => load().authorizations[authId] || null,
    saveEngagement(record) {
      const row = { id: id(), ...record };
      load().engagements[row.id] = row;
      save();
      return row;
    },
    getEngagement: (engagementId) => load().engagements[engagementId] || null,
    listEngagements: () => Object.values(load().engagements),
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
    latestSummary(host) {
      const rows = load().timeline[host] || [];
      return rows[rows.length - 1] || null;
    },
    rememberSummary(host, summary) {
      const rows = load().timeline[host] || [];
      rows.push(summary);
      load().timeline[host] = rows.slice(-30);
      save();
    },
    timeline: (host) => load().timeline[host] || [],
    getAssets: (host) => load().assets[host] || null,
    saveAssets(host, assets) {
      load().assets[host] = assets;
      save();
    },
    saveNmap(job) {
      const row = { id: id(), status: 'queued', createdAt: new Date().toISOString(), ...job };
      load().nmapJobs[row.id] = row;
      save();
      return row;
    },
    getNmap: (jobId) => load().nmapJobs[jobId] || null,
    updateNmap(jobId, patch) {
      const job = load().nmapJobs[jobId];
      if (!job) return null;
      Object.assign(job, patch);
      save();
      return job;
    },
    saveScreenshot(record) {
      const row = { id: id(), ...record };
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
    listScreenshots(target) {
      return Object.values(load().screenshots).filter((row) => !target || row.target === target);
    },
    getScreenshot: (shotId) => load().screenshots[shotId] || null,
  };
};
