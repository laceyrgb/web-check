import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import express from 'express';
import { requireApiKey, tenantKeyMap } from './auth.js';
import { deliverAlerts as defaultDeliverAlerts, selectAlerts } from './alerts.js';
import { createFileStore } from './store.js';
import { createQueue, startScheduler } from './queue.js';
import { executeScan as defaultExecute } from './scan.js';
import { summarizeScan, diffScans, prioritizeRemediations } from './risk.js';
import { updateInventory } from './inventory.js';
import {
  assertPublicTarget,
  blockedInfrastructure,
  canonicalHost,
  flagOn,
  httpError,
  robotsAllows,
} from './util.js';
import { invoke, targetUrl } from './hosts.js';
import { collectPublicRecords } from './records.js';
import { classifyHosts, collectLinkDump } from './links.js';
import { assertNmapAuthorized, nmapAvailable, parseNmapXml, resolveSingleIp } from './nmap.js';
import {
  assertEngagement,
  buildNucleiArgs,
  crawlInScope,
  engagementPhrase,
  nucleiAvailable,
  parseNucleiJsonl,
  simulationTemplate,
} from './pentest.js';
import { inspectApkBuffer, inspectStoreUrl } from './apk.js';
import { buildSbom, parseManifest, publicGithubLockfile, queryOsv } from './sbom.js';
import { fetchPeople } from './content.js';
import { exportToDrive, exportZip } from './export.js';
import { renderReport as defaultRenderReport } from './pdf.js';
import { httpGet } from '../_common/http.js';
import { openapi } from './openapi.js';

const exec = promisify(execFile);

const publicScan = (scan) => ({
  id: scan.id,
  target: scan.target,
  hostname: scan.hostname,
  status: scan.status,
  createdAt: scan.createdAt,
  startedAt: scan.startedAt || null,
  finishedAt: scan.finishedAt || null,
  error: scan.error || null,
  partial: scan.results?.partial || false,
  risk: scan.results?.risk || null,
  monitorId: scan.monitorId || null,
  bulkId: scan.bulkId || null,
});

export const parseEveryMinutes = (body = {}) => {
  const direct = Number(body.everyMinutes);
  if (Number.isFinite(direct) && direct >= 15 && direct <= 10080) return direct;
  const match = /^every:(\d+)(m|h|d)$/.exec(String(body.schedule || ''));
  if (!match) return null;
  const factor = match[2] === 'm' ? 1 : match[2] === 'h' ? 60 : 1440;
  const minutes = Number(match[1]) * factor;
  return minutes >= 15 && minutes <= 10080 ? minutes : null;
};

const hostFrom = (value) => {
  try {
    return canonicalHost(value);
  } catch (error) {
    throw httpError(400, error.message);
  }
};

export const createRouter = ({
  store = createFileStore(),
  executeScan = defaultExecute,
  schedule = true,
  nmapRunner = exec,
  nucleiRunner = exec,
  deliverAlerts = defaultDeliverAlerts,
  renderReport = defaultRenderReport,
} = {}) => {
  const tenantOf = (req) => req.tenant || 'default';
  const router = express.Router();
  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

  const finishScan = async (scanId) => {
    const scan = store.getScan(scanId);
    if (!scan || scan.status === 'complete') return;
    store.updateScan(scanId, { status: 'running', startedAt: new Date().toISOString() });
    try {
      const tenant = scan.tenant || 'default';
      const previous = store.latestSummary(scan.hostname, tenant);
      const results = await executeScan(scan.target, {
        email: scan.email,
        publicUrls: scan.publicUrls,
      });
      const summary = summarizeScan(results);
      const changes = diffScans(previous, summary);
      results.history = { baseline: !previous, changes };
      const assets = updateInventory(
        store.getAssets(scan.hostname, tenant),
        results,
        results.scannedAt,
      );
      results.assets = assets;
      store.saveAssets(scan.hostname, assets, tenant);
      store.rememberSummary(scan.hostname, summary, tenant);
      store.updateScan(scanId, {
        status: 'complete',
        finishedAt: new Date().toISOString(),
        results,
        summary,
        changes,
      });
      if (scan.monitorId) {
        const monitor = store.getMonitor(scan.monitorId);
        let alertDelivery = { delivered: [], skipped: 'no-alert' };
        if (selectAlerts(changes).length) {
          try {
            alertDelivery = await deliverAlerts({
              target: scan.target,
              tenant,
              changes,
              risk: results.risk?.score ?? null,
            });
          } catch {
            alertDelivery = { delivered: [], error: 'Alert delivery failed' };
          }
        }
        store.updateMonitor(scan.monitorId, {
          running: false,
          lastRunAt: new Date().toISOString(),
          nextRunAt: new Date(Date.now() + (monitor?.everyMinutes || 1440) * 60000).toISOString(),
          lastSummary: summary,
          changes,
          alert: selectAlerts(changes).length > 0,
          alertDelivery,
          lastScanId: scanId,
        });
      }
      if (scan.bulkId) store.refreshBulk(scan.bulkId);
    } catch (error) {
      store.updateScan(scanId, {
        status: 'failed',
        error: error.message,
        finishedAt: new Date().toISOString(),
      });
      if (scan.monitorId) store.updateMonitor(scan.monitorId, { running: false });
      if (scan.bulkId) store.refreshBulk(scan.bulkId);
    }
  };

  const scans = createQueue(finishScan, {
    concurrency: Number(process.env.WEBCHECK_SCAN_CONCURRENCY || 1),
  });
  const nmapJobs = createQueue(async (jobId) => runNmap(jobId), {
    concurrency: Number(process.env.WEBCHECK_NMAP_CONCURRENCY || 1),
  });
  const screenshots = createQueue(async (shotId) => runScreenshot(shotId), { concurrency: 1 });

  const runNmap = async (jobId) => {
    const job = store.getNmap(jobId);
    if (!job) return;
    store.updateNmap(jobId, { status: 'running' });
    try {
      const auth = store.getAuthorization(job.authorizationId, job.tenant);
      const resolved = await resolveSingleIp(auth.target);
      if (auth.target !== auth.ip && !resolved.addresses.includes(auth.ip)) {
        throw httpError(
          409,
          'The hostname no longer resolves to the authorized IP. Authorize the address again.',
        );
      }
      const args = assertNmapAuthorized({
        enabled: flagOn('WEBCHECK_NMAP_ENABLED'),
        authorization: auth,
        profile: job.profile,
      });
      const { stdout } = await nmapRunner('nmap', args, {
        timeout: Number(process.env.WEBCHECK_NMAP_TIMEOUT_MS || 180000),
        maxBuffer: 8_000_000,
      });
      const parsed = parseNmapXml(stdout);
      store.updateNmap(jobId, {
        status: 'complete',
        finishedAt: new Date().toISOString(),
        flags: args.slice(0, -1),
        hosts: parsed.hosts,
        operator: auth.operator,
        authorizedAt: auth.authorizedAt,
      });
    } catch (error) {
      store.updateNmap(jobId, {
        status: 'failed',
        error: error.message,
        finishedAt: new Date().toISOString(),
      });
    }
  };

  const runScreenshot = async (shotId) => {
    const shot = store.getScreenshot(shotId);
    if (!shot) return;
    try {
      const pageUrl = new URL(shot.url);
      const robots = await httpGet(new URL('/robots.txt', pageUrl.origin).href, {
        timeout: 8000,
        validateStatus: () => true,
      }).catch(() => null);
      if (!robotsAllows(typeof robots?.data === 'string' ? robots.data : '', pageUrl.pathname)) {
        throw httpError(403, 'robots.txt disallows this path');
      }
      const handler = (await import('../screenshot.js')).default;
      const body = await invoke(handler, shot.url);
      if (!body?.image)
        throw new Error(body?.skipped || body?.error || 'Screenshot was not captured');
      const file = path.join(store.dir, 'screenshots', `${shot.id}.png`);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, Buffer.from(body.image, 'base64'));
      store.updateScreenshot(shotId, {
        status: 'complete',
        file: `${shot.id}.png`,
        capturedAt: new Date().toISOString(),
      });
    } catch (error) {
      store.updateScreenshot(shotId, { status: 'failed', error: error.message });
    }
  };

  router.use((req, res, next) => {
    if (req.method === 'GET' && (req.path === '/' || req.path === '/openapi.json')) return next();
    return requireApiKey(req, res, next);
  });

  router.get('/', (req, res) => {
    res.json({
      name: 'Cormorant OSINT Desk API',
      authRequired: tenantKeyMap().length > 0,
      openapi: '/api/v1/openapi.json',
      nmapEnabled: flagOn('WEBCHECK_NMAP_ENABLED'),
      pentestEnabled: flagOn('WEBCHECK_PENTEST_ENABLED'),
      exportConfigured: Boolean(process.env.WEBCHECK_EXPORT_DIR),
    });
  });
  router.get('/openapi.json', (req, res) => res.json(openapi));

  router.post(
    '/scans',
    wrap(async (req, res) => {
      const hostname = hostFrom(req.body?.target);
      const scan = store.createScan({
        target: `https://${hostname}`,
        hostname,
        tenant: tenantOf(req),
        email: req.body?.email || null,
        publicUrls: Array.isArray(req.body?.publicUrls) ? req.body.publicUrls.slice(0, 8) : [],
      });
      scans.push(scan.id);
      res.status(202).json(publicScan(scan));
    }),
  );

  router.get('/scans', (req, res) =>
    res.json({ scans: store.listScans(tenantOf(req)).slice(0, 50).map(publicScan) }),
  );
  router.get('/scans/:id', (req, res) => {
    const scan = store.getScan(req.params.id, tenantOf(req));
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    return res.json(publicScan(scan));
  });
  router.get('/scans/:id/results', (req, res) => {
    const scan = store.getScan(req.params.id, tenantOf(req));
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status !== 'complete')
      return res.status(409).json({ error: 'Scan is not complete', status: scan.status });
    return res.json(scan.results);
  });
  router.get(
    '/scans/:id/report.pdf',
    wrap(async (req, res) =>
      sendPdf(res, store.getScan(req.params.id, tenantOf(req)), req.query.nmap),
    ),
  );
  router.get(
    '/report.pdf',
    wrap(async (req, res) => {
      const hostname = hostFrom(req.query.url);
      const scan = store.createScan({
        target: `https://${hostname}`,
        hostname,
        tenant: tenantOf(req),
        email: req.query.email || null,
        publicUrls: [],
      });
      await scans.push(scan.id);
      return sendPdf(res, store.getScan(scan.id), req.query.nmap);
    }),
  );

  const sendPdf = async (res, scan, nmapId) => {
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status !== 'complete')
      return res.status(409).json({ error: 'Scan is not complete', status: scan.status });
    const report = { ...scan.results, id: scan.id };
    report.trend = store.timeline(scan.hostname, scan.tenant || 'default').map((point) => ({
      scannedAt: point.scannedAt,
      riskScore: point.riskScore,
    }));
    report.remediations = prioritizeRemediations(report);
    if (nmapId) {
      const job = store.getNmap(String(nmapId), scan.tenant || 'default');
      const same =
        job &&
        job.operator &&
        (job.target === scan.hostname || job.ip === scan.results?.exposure?.ip);
      if (!same || job.status !== 'complete')
        return res
          .status(403)
          .json({ error: 'Authorized port scan is not available for this target' });
      report.nmap = job;
    }
    const { renderReport } = await import('./pdf.js');
    const pdf = await renderReport(report);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="cormorant-${scan.hostname.replace(/[^a-z0-9.-]/gi, '')}.pdf"`,
    );
    return res.send(pdf);
  };

  const priorScans = (tenant) => {
    const rank = { complete: 3, running: 2, queued: 2, failed: 0 };
    const map = new Map();
    for (const scan of store.listScans(tenant)) {
      const prev = map.get(scan.hostname);
      if (!prev || (rank[scan.status] || 0) > (rank[prev.status] || 0))
        map.set(scan.hostname, { id: scan.id, status: scan.status });
    }
    return map;
  };
  const startBulk = (hosts, tenant) => {
    if (!hosts.length) return null;
    const bulk = store.createBulk(hosts, tenant);
    const scanIds = hosts.map((hostname) => {
      const scan = store.createScan({
        target: `https://${hostname}`,
        hostname,
        tenant,
        bulkId: bulk.id,
        publicUrls: [],
      });
      scans.push(scan.id);
      return scan.id;
    });
    store.updateBulk(bulk.id, { scanIds, status: 'running' });
    return store.getBulk(bulk.id);
  };
  const planLinks = async (body, tenant) => {
    const text = Array.isArray(body?.domains)
      ? body.domains.join('\n')
      : String(body?.text || body?.domains || '');
    const target = body?.target ? hostFrom(body.target) : null;
    if (!text.trim() && !target)
      throw httpError(400, 'Paste a link list or name a page to harvest');
    if (target) assertPublicTarget(target);
    const dump = await collectLinkDump(
      { text, target, includeSubdomains: body?.includeSubdomains !== false },
      {},
    );
    const plan = classifyHosts(dump.parsed, priorScans(tenant));
    const bulk = body?.queue === false ? null : startBulk(plan.queued, tenant);
    return {
      pageStatus: dump.pageStatus,
      note: dump.note,
      ...plan,
      bulkId: bulk?.id || null,
      bulk,
    };
  };
  const respondLinks = async (req, res) => {
    try {
      const plan = await planLinks(req.body || {}, tenantOf(req));
      const status = plan.bulk ? 202 : 200;
      return res.status(status).json({ ...plan, bulk: undefined });
    } catch (error) {
      return res.status(error.status || 500).json({ error: error.message });
    }
  };
  router.post('/bulk', wrap(respondLinks));
  router.post('/links', wrap(respondLinks));
  router.get('/bulk/:id', (req, res) => {
    const bulk = store.getBulk(req.params.id, tenantOf(req));
    if (!bulk) return res.status(404).json({ error: 'Bulk job not found' });
    const scans = bulk.scanIds.map((id) => store.getScan(id, tenantOf(req))).filter(Boolean);
    return res.json({
      ...bulk,
      progress: {
        total: scans.length,
        complete: scans.filter((scan) => scan.status === 'complete' || scan.status === 'failed')
          .length,
      },
      scans: scans.map(publicScan),
    });
  });

  router.get('/monitors', (req, res) => res.json({ monitors: store.listMonitors(tenantOf(req)) }));
  router.post(
    '/monitors',
    wrap(async (req, res) => {
      const everyMinutes = parseEveryMinutes(req.body || {});
      if (!everyMinutes)
        return res
          .status(400)
          .json({ error: 'Provide everyMinutes (15-10080) or schedule every:12h' });
      const hostname = hostFrom(req.body?.target);
      const monitor = store.createMonitor({
        target: `https://${hostname}`,
        hostname,
        tenant: tenantOf(req),
        everyMinutes,
        email: req.body?.email || null,
        publicUrls: Array.isArray(req.body?.publicUrls) ? req.body.publicUrls.slice(0, 8) : [],
        operator: req.body?.operator || null,
      });
      const scan = store.createScan({
        target: monitor.target,
        hostname,
        tenant: tenantOf(req),
        email: monitor.email,
        publicUrls: monitor.publicUrls,
        monitorId: monitor.id,
      });
      store.updateMonitor(monitor.id, {
        running: true,
        lastScanId: scan.id,
        nextRunAt: new Date(Date.now() + everyMinutes * 60000).toISOString(),
      });
      scans.push(scan.id);
      return res.status(201).json(store.getMonitor(monitor.id));
    }),
  );
  router.delete('/monitors/:id', (req, res) => {
    if (!store.getMonitor(req.params.id, tenantOf(req)))
      return res.status(404).json({ error: 'Monitor not found' });
    store.deleteMonitor(req.params.id, tenantOf(req));
    return res.status(204).end();
  });
  router.post('/monitors/:id/run', (req, res) => {
    const monitor = store.getMonitor(req.params.id, tenantOf(req));
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' });
    const scan = store.createScan({
      target: monitor.target,
      hostname: monitor.hostname,
      tenant: tenantOf(req),
      email: monitor.email,
      publicUrls: monitor.publicUrls,
      monitorId: monitor.id,
    });
    store.updateMonitor(monitor.id, { running: true, lastScanId: scan.id });
    scans.push(scan.id);
    return res.status(202).json(publicScan(scan));
  });

  router.get(
    '/records',
    wrap(async (req, res) => {
      try {
        const hostname = hostFrom(req.query.target);
        assertPublicTarget(hostname);
        const record = await collectPublicRecords({ href: targetUrl(hostname) });
        return res.json(record);
      } catch (error) {
        return res.status(error.status || 500).json({ error: error.message });
      }
    }),
  );
  router.get(
    '/timeline',
    wrap(async (req, res) => {
      const hostname = hostFrom(req.query.target);
      const rows = store.timeline(hostname, tenantOf(req));
      const changes = rows
        .slice(1)
        .map((row, index) => ({ at: row.scannedAt, changes: diffScans(rows[index], row) }));
      return res.json({ target: hostname, snapshots: rows, changes });
    }),
  );
  router.post(
    '/export',
    wrap(async (req, res) => {
      try {
        const target = req.body?.target ? hostFrom(req.body.target) : null;
        const result = await exportToDrive({
          store,
          tenant: tenantOf(req),
          target,
          removeLocal: req.body?.removeLocal === true,
          renderReport,
        });
        return res.json(result);
      } catch (error) {
        return res
          .status(error.status || 500)
          .json({ error: error.message, code: error.code || 'export-failed' });
      }
    }),
  );
  router.get(
    '/export.zip',
    wrap(async (req, res) => {
      try {
        const target = req.query.target ? hostFrom(req.query.target) : null;
        const result = await exportZip({ store, tenant: tenantOf(req), target, renderReport });
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
        res.setHeader('Cache-Control', 'no-store');
        return res.send(result.zip);
      } catch (error) {
        return res
          .status(error.status || 500)
          .json({ error: error.message, code: error.code || 'export-failed' });
      }
    }),
  );
  router.get(
    '/history',
    wrap(async (req, res) => {
      const hostname = hostFrom(req.query.target);
      const tenant = tenantOf(req);
      const scans = store
        .listScans(tenant)
        .filter((scan) => scan.hostname === hostname)
        .slice(0, 30);
      const latest = scans.find((scan) => scan.status === 'complete');
      return res.json({
        target: hostname,
        tenant,
        scans: scans.map(publicScan),
        trend: store.timeline(hostname, tenant).map((point) => ({
          scannedAt: point.scannedAt,
          riskScore: point.riskScore,
        })),
        latestFindings: latest?.results
          ? {
              risk: latest.results.risk || null,
              summary: latest.results.executiveSummary || [],
              changes: latest.changes || [],
            }
          : null,
      });
    }),
  );
  router.get(
    '/assets',
    wrap(async (req, res) =>
      res.json(store.getAssets(hostFrom(req.query.target), tenantOf(req)) || { items: {} }),
    ),
  );

  router.post(
    '/authorizations',
    wrap(async (req, res) => {
      if (!req.body?.acknowledged)
        return res
          .status(403)
          .json({ error: 'Authorization required', code: 'authorization-required' });
      if (!req.body?.operator) return res.status(400).json({ error: 'Operator name is required' });
      const canonical = hostFrom(req.body.target);
      if (blockedInfrastructure(canonical)) {
        return res.status(400).json({
          error: 'Refusing a metadata or local address',
          canonical,
          code: 'authorization-required',
        });
      }
      if (req.body.confirm !== canonical) {
        return res.status(400).json({
          error: `Type the exact host ${canonical} to authorize it`,
          canonical,
          code: 'authorization-required',
        });
      }
      const resolved = await resolveSingleIp(canonical);
      if (!resolved.addresses.length)
        return res.status(400).json({ error: 'Host did not resolve' });
      if (!resolved.ip) {
        return res.status(409).json({
          error: 'Host resolved to multiple addresses. Confirm a single IP.',
          addresses: resolved.addresses,
          canonical,
          code: 'authorization-required',
        });
      }
      const record = store.saveAuthorization({
        target: canonical,
        ip: resolved.ip,
        tenant: tenantOf(req),
        operator: String(req.body.operator).slice(0, 80),
        acknowledged: true,
        confirm: canonical,
        authorizedAt: new Date().toISOString(),
      });
      return res.status(201).json(record);
    }),
  );

  router.post(
    '/nmap',
    wrap(async (req, res) => {
      const available = await nmapAvailable(nmapRunner);
      if (!available.installed)
        return res.status(503).json({ error: available.message, code: 'nmap-missing' });
      const auth = store.getAuthorization(req.body?.authorizationId, tenantOf(req));
      if (!auth)
        return res
          .status(403)
          .json({ error: 'Authorization required', code: 'authorization-required' });
      const profile = req.body?.profile || 'default';
      assertNmapAuthorized({
        enabled: flagOn('WEBCHECK_NMAP_ENABLED'),
        authorization: auth,
        profile,
      });
      const job = store.saveNmap({
        authorizationId: auth.id,
        profile,
        target: auth.target,
        ip: auth.ip,
        tenant: tenantOf(req),
        operator: auth.operator,
        authorizedAt: auth.authorizedAt,
      });
      nmapJobs.push(job.id);
      return res
        .status(202)
        .json({ id: job.id, status: 'queued', target: auth.target, ip: auth.ip, profile });
    }),
  );
  router.get('/nmap/:id', (req, res) => {
    const job = store.getNmap(req.params.id, tenantOf(req));
    if (!job) return res.status(404).json({ error: 'Nmap job not found' });
    return res.json(job);
  });

  router.post(
    '/engagements',
    wrap(async (req, res) => {
      if (!flagOn('WEBCHECK_PENTEST_ENABLED'))
        return res
          .status(403)
          .json({ error: 'Pentest mode is disabled. Set WEBCHECK_PENTEST_ENABLED=true.' });
      const clientName = String(req.body?.clientName || '').trim();
      if (!clientName || !req.body?.operator)
        return res.status(400).json({ error: 'Client name and operator are required' });
      const phrase = engagementPhrase(clientName);
      if (!req.body?.acknowledged || req.body?.confirm !== phrase) {
        return res.status(403).json({
          error: `Checkbox and the exact phrase "${phrase}" are required`,
          code: 'authorization-required',
        });
      }
      const scope = [...new Set((req.body?.scope || []).map((item) => hostFrom(item)))];
      if (!scope.length)
        return res.status(400).json({ error: 'Scope needs at least one domain or IP' });
      const start = Date.parse(req.body?.start);
      const end = Date.parse(req.body?.end);
      if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
        return res.status(400).json({ error: 'Engagement dates are invalid' });
      }
      const record = store.saveEngagement({
        tenant: tenantOf(req),
        clientName,
        scope,
        start: req.body.start,
        end: req.body.end,
        operator: String(req.body.operator || '').slice(0, 80),
        acknowledged: true,
        confirm: phrase,
        acknowledgedAt: new Date().toISOString(),
      });
      return res.status(201).json(publicEngagement(record));
    }),
  );
  router.get('/engagements/:id', (req, res) => {
    const engagement = store.getEngagement(req.params.id, tenantOf(req));
    if (!engagement) return res.status(404).json({ error: 'Engagement not found' });
    return res.json(publicEngagement(engagement));
  });
  router.post('/engagements/:id/secrets', (req, res) => {
    if (!flagOn('WEBCHECK_PENTEST_ENABLED'))
      return res
        .status(403)
        .json({ error: 'Pentest mode is disabled. Set WEBCHECK_PENTEST_ENABLED=true.' });
    if (!store.getEngagement(req.params.id, tenantOf(req)))
      return res.status(404).json({ error: 'Engagement not found' });
    const allow = [
      'sessionCookie',
      'loginUrl',
      'usernameField',
      'passwordField',
      'testUsername',
      'testPassword',
      'githubToken',
    ];
    const secrets = {};
    for (const key of allow) if (req.body?.[key]) secrets[key] = String(req.body[key]);
    store.saveSecrets(req.params.id, secrets);
    return res.status(204).end();
  });
  router.post(
    '/engagements/:id/crawl',
    wrap(async (req, res) => {
      const engagement = store.getEngagement(req.params.id, tenantOf(req));
      const result = await crawlInScope(
        engagement,
        req.body?.startUrl,
        store.getSecrets(req.params.id),
      );
      return res.json(result);
    }),
  );
  router.post(
    '/engagements/:id/nuclei',
    wrap(async (req, res) => {
      const engagement = store.getEngagement(req.params.id, tenantOf(req));
      const target = new URL(req.body?.target || '');
      assertEngagement(engagement, target.hostname);
      const available = await nucleiAvailable(nucleiRunner);
      if (!available.installed) return res.status(503).json({ error: available.message });
      const maxSeverity =
        req.body?.maxSeverity || process.env.WEBCHECK_NUCLEI_MAX_SEVERITY || 'medium';
      const args = buildNucleiArgs(target.href, maxSeverity);
      let stdout = '';
      try {
        const result = await nucleiRunner('nuclei', args, {
          timeout: 180000,
          maxBuffer: 4_000_000,
        });
        stdout = result.stdout || '';
      } catch (error) {
        stdout = error.stdout || '';
        if (!stdout)
          return res.status(502).json({ error: 'Nuclei failed before producing results' });
      }
      return res.json({
        flags: args,
        findings: parseNucleiJsonl(stdout, maxSeverity),
        note: 'Exploit, intrusive, dos, fuzz, rce, and sqli tags are excluded. Request payloads are not stored.',
      });
    }),
  );
  router.post('/engagements/:id/simulation', (req, res) => {
    const engagement = store.getEngagement(req.params.id, tenantOf(req));
    if (!engagement) return res.status(404).json({ error: 'Engagement not found' });
    try {
      assertEngagement(engagement, engagement.scope[0]);
    } catch (error) {
      return res.status(error.status || 403).json({ error: error.message });
    }
    return res.json(
      simulationTemplate({ clientName: engagement.clientName, operator: engagement.operator }),
    );
  });
  router.post('/engagements/:id/spray', (req, res) => {
    res.status(403).json({
      error:
        'Password spraying is not available. This instance will not try passwords against any account.',
      code: 'spray-refused',
    });
  });

  router.post(
    '/people',
    wrap(async (req, res) => res.json(await fetchPeople(req.body?.publicUrls || [], {}))),
  );
  router.post(
    '/audit/sbom',
    wrap(async (req, res) => {
      let filename = req.body?.filename;
      let content = req.body?.content;
      if (req.body?.repo) {
        const engagement = req.body?.engagementId
          ? store.getEngagement(req.body.engagementId, tenantOf(req))
          : null;
        const token =
          req.body?.token ||
          (engagement ? store.getSecrets(engagement.id)?.githubToken : undefined);
        const fetched = await publicGithubLockfile(req.body.repo, { token });
        filename = fetched.filename;
        content = fetched.content;
      }
      const parsed = parseManifest(filename, content);
      const report = await queryOsv(parsed.packages);
      return res.json({
        ...report,
        sbom: buildSbom(parsed.packages, filename || 'upload'),
        skipped: parsed.skipped,
      });
    }),
  );
  router.post(
    '/audit/apk',
    wrap(async (req, res) => {
      if (req.body?.storeUrl) return res.json(await inspectStoreUrl(req.body.storeUrl));
      const buffer = Buffer.from(String(req.body?.base64 || ''), 'base64');
      if (!buffer.length || buffer.length > 8_000_000)
        return res.status(400).json({ error: 'APK must be a base64 upload under 8MB' });
      return res.json(inspectApkBuffer(buffer));
    }),
  );

  router.post(
    '/screenshots',
    wrap(async (req, res) => {
      const url = new URL(
        req.body?.url || `https://${hostFrom(req.body?.target)}${req.body?.path || '/'}`,
      );
      if (!['http:', 'https:'].includes(url.protocol))
        return res.status(400).json({ error: 'Only public http(s) pages can be archived' });
      const shot = store.saveScreenshot({
        target: url.hostname,
        url: url.href,
        path: url.pathname,
        tenant: tenantOf(req),
        status: 'queued',
      });
      screenshots.push(shot.id);
      return res.status(202).json({ id: shot.id, status: 'queued' });
    }),
  );
  router.get('/screenshots', (req, res) =>
    res.json({
      screenshots: store.listScreenshots(
        req.query.target ? hostFrom(req.query.target) : '',
        tenantOf(req),
      ),
    }),
  );
  router.get('/screenshots/:id.png', (req, res) => {
    const shot = store.getScreenshot(req.params.id, tenantOf(req));
    if (!shot?.file) return res.status(404).json({ error: 'Screenshot not found' });
    const file = path.join(store.dir, 'screenshots', path.basename(shot.file));
    return res.sendFile(file);
  });

  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    return res.status(error.status || 500).json({
      error: error.message || 'Request failed',
      ...(error.code ? { code: error.code } : {}),
    });
  });

  for (const scan of store.listScans()) {
    if (scan.status === 'running')
      store.updateScan(scan.id, { status: 'failed', error: 'Interrupted by process restart' });
    if (scan.status === 'queued') scans.push(scan.id);
  }
  for (const monitor of store.listMonitors())
    if (monitor.running) store.updateMonitor(monitor.id, { running: false });
  if (schedule && !flagOn('WEBCHECK_DISABLE_SCHEDULER'))
    startScheduler({ store, enqueue: (id) => scans.push(id) });

  router.queue = scans;
  return router;
};

const publicEngagement = (engagement) => ({
  id: engagement.id,
  clientName: engagement.clientName,
  scope: engagement.scope,
  start: engagement.start,
  end: engagement.end,
  operator: engagement.operator,
  acknowledged: engagement.acknowledged,
  acknowledgedAt: engagement.acknowledgedAt,
});
