export const openapi = {
  openapi: '3.0.3',
  info: {
    title: 'Cormorant OSINT Desk API',
    version: '1.0.0',
    description:
      'Stable JSON API for OSINT Desk. Plain scans never run Nmap or pentest modules. When WEBCHECK_API_KEY is set, send it as x-api-key or Authorization: Bearer on every route except GET /api/v1 and GET /api/v1/openapi.json.',
  },
  paths: {
    '/api/v1/scans': { post: { summary: 'Start a passive scan' }, get: { summary: 'List scans' } },
    '/api/v1/scans/{id}': { get: { summary: 'Poll scan status' } },
    '/api/v1/scans/{id}/results': { get: { summary: 'Fetch completed results' } },
    '/api/v1/scans/{id}/report.pdf': { get: { summary: 'Download the Cormorant PDF' } },
    '/api/v1/bulk': {
      post: { summary: 'Queue unique hosts from a list, skipping ones already scanned' },
    },
    '/api/v1/links': {
      post: {
        summary: 'Harvest links from a page or a pasted dump, then queue the new hosts',
      },
    },
    '/api/v1/monitors': {
      get: { summary: 'List monitors' },
      post: { summary: 'Create an interval monitor' },
    },
    '/api/v1/timeline': { get: { summary: 'Scan snapshots and diffs for a target' } },
    '/api/v1/records': {
      get: {
        summary: 'Passive mail policy, linked-file metadata, and certificate log for one domain',
      },
    },
    '/api/v1/history': {
      get: { summary: 'Read-only per-target scan history, risk trend, and latest findings' },
    },
    '/api/v1/export': {
      post: { summary: 'Write this tenant offline bundle onto WEBCHECK_EXPORT_DIR' },
    },
    '/api/v1/export.zip': {
      get: { summary: 'Download the offline bundle. Does not remove the server copy.' },
    },
    '/api/v1/assets': { get: { summary: 'Deduped asset inventory' } },
    '/api/v1/authorizations': { post: { summary: 'Record an authorized-target acknowledgement' } },
    '/api/v1/nmap': {
      post: { summary: 'Queue an authorized Nmap profile. Never called by a plain scan.' },
    },
    '/api/v1/engagements': {
      post: { summary: 'Open a pentest engagement. Requires WEBCHECK_PENTEST_ENABLED.' },
    },
    '/api/v1/engagements/{id}/crawl': { post: { summary: 'In-scope authenticated crawl' } },
    '/api/v1/engagements/{id}/nuclei': { post: { summary: 'Safe Nuclei templates only' } },
    '/api/v1/engagements/{id}/simulation': {
      post: { summary: 'Export a labeled training template. Does not send mail.' },
    },
    '/api/v1/engagements/{id}/spray': {
      post: { summary: 'Always refused. Password spraying is not implemented.' },
    },
    '/api/v1/audit/sbom': {
      post: { summary: 'Parse a lockfile or public GitHub repo and query OSV' },
    },
    '/api/v1/audit/apk': { post: { summary: 'Static APK or public store URL review' } },
    '/api/v1/people': { post: { summary: 'Read public URLs the caller supplies' } },
    '/api/v1/screenshots': { post: { summary: 'Archive a public page if robots.txt allows it' } },
  },
};
