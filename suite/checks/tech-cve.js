import { clip, finding } from '../findings.js';
import { matchProduct as matchIntel } from '../intel/intel.js';
import { REFS } from '../refs.js';

// PHP support window, separate from the CVE cache.
// 8.1 security support ended 2025-12-31. Review again when 8.2 ends (2026-12-31).
const PHP_MIN = [8, 2];

const versionParts = (version) =>
  String(version)
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map(Number);

const open = (spec) => finding({ needsHumanReview: true, ...spec });

const phpUnsupported = (product, version, source) => {
  const name = String(product || '').toLowerCase();
  if (!name.includes('php')) return [];
  const parts = versionParts(version);
  if (parts.length < 2) return [];
  if (parts[0] > PHP_MIN[0] || (parts[0] === PHP_MIN[0] && parts[1] >= PHP_MIN[1])) return [];
  return [
    open({
      id: 'tech.php.unsupported',
      title: `PHP ${parts[0]}.${parts[1]} is outside security support`,
      titleAr: `PHP ${parts[0]}.${parts[1]} خارج الدعم الأمني`,
      severity: 'medium',
      evidence: `${source}: PHP/${version}. The cutoff is 8.2, checked against the PHP supported-versions page as of November 2026. This is a support-window rule, not an NVD row.`,
      remediation:
        'Move to a PHP branch that still receives security fixes, then hide the X-Powered-By header.',
      remediationAr: 'انتقل إلى فرع PHP ما زال يتلقى إصلاحات أمنية، ثم أخفِ ترويسة X-Powered-By.',
      references: [REFS.php],
      service: 'vulnerability',
    }),
  ];
};

export const matchProduct = (product, version, source, items) => {
  if (!String(version || '').trim()) return [];
  return [
    ...matchIntel(product, version, source, items),
    ...phpUnsupported(product, version, source),
  ];
};

const fromHeader = (headers, body) => {
  const server = headers?.server || headers?.Server || '';
  const powered = headers?.['x-powered-by'] || '';
  const found = [];
  const apache = /apache\/(\d+\.\d+\.\d+)/i.exec(server);
  if (apache) found.push(['apache', apache[1], 'Server header']);
  const openssl = /openssl\/(\d+\.\d+\.\d+[a-z]?)/i.exec(`${server} ${powered}`);
  if (openssl) found.push(['openssl', openssl[1], 'TLS or Server banner']);
  const php = /php\/(\d+\.\d+\.\d+)/i.exec(`${powered} ${server}`);
  if (php) found.push(['php', php[1], 'X-Powered-By or Server header']);
  const jquery = /jquery[.-](\d+\.\d+\.\d+)/i.exec(body || '');
  if (jquery) found.push(['jquery', jquery[1], 'script reference']);
  return found;
};

export const analyseTech = (observations) => {
  const headers = observations.http?.headers || {};
  const body = observations.http?.bodySnippet || '';
  const out = [];
  for (const [product, version, source] of fromHeader(headers, body)) {
    out.push(...matchProduct(product, version, source));
  }
  for (const row of observations.passivePorts || []) {
    if (!row?.product || !row?.version) continue;
    out.push(...matchProduct(row.product, row.version, `passive port ${row.port}`));
  }
  return out.map((item) => ({ ...item, evidence: clip(item.evidence, 400) }));
};
