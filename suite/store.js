import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const fileOf = (dir) => path.join(dir, 'runs.json');

const readRows = (dir) => {
  const file = fileOf(dir);
  if (!existsSync(file)) return [];
  const parsed = JSON.parse(readFileSync(file, 'utf8'));
  return Array.isArray(parsed) ? parsed : [];
};

// Local JSON history. Stores scores and finding ids, not raw responses or secrets.
export const openStore = (dir) => {
  mkdirSync(dir, { recursive: true });
  return {
    dir,
    saveRun(entry) {
      const record = {
        id: entry.id,
        at: entry.at,
        kind: entry.kind || 'scan',
        hostname: entry.hostname,
        score: entry.score ?? null,
        open: entry.open ?? 0,
        findingIds: (entry.findingIds || []).map((item) => ({
          id: item.id,
          severity: item.severity,
          status: item.status || 'open',
        })),
      };
      const rows = readRows(dir);
      rows.push(record);
      writeFileSync(fileOf(dir), `${JSON.stringify(rows, null, 2)}\n`);
      return record;
    },
    history(hostname) {
      return readRows(dir).filter((row) => row.hostname === hostname);
    },
    trend(hostname) {
      const rows = this.history(hostname);
      const previous =
        rows.length > 1 ? new Set(rows[rows.length - 2].findingIds.map((item) => item.id)) : null;
      const latestIds = new Set((rows.at(-1)?.findingIds || []).map((item) => item.id));
      return {
        hostname,
        points: rows.map((row) => ({ at: row.at, score: row.score, open: row.open })),
        opened: previous ? [...latestIds].filter((id) => !previous.has(id)) : [],
        resolved: previous ? [...previous].filter((id) => !latestIds.has(id)) : [],
      };
    },
  };
};

export const runRecord = (report, kind = 'scan') => ({
  id: `${report.target?.hostname || 'scan'}-${report.generatedAt}`,
  at: report.generatedAt,
  kind,
  hostname: report.target?.hostname,
  score: report.score?.value ?? null,
  open: (report.findings || []).filter((item) => item.status === 'open').length,
  findingIds: (report.findings || [])
    .filter((item) => item.status === 'open')
    .map((item) => ({ id: item.id, severity: item.severity, status: item.status })),
});
