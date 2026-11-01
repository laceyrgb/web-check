import { clip, finding } from '../findings.js';
import { REFS } from '../refs.js';

// Starter catalog only. A match is a lead for a reviewer, not proof the bug is reachable.
// PHP cutoff: 8.1 security support ended 2025-12-31. Review again when 8.2 ends (2026-12-31).
const PHP_MIN = [8, 2];

const versionParts = (version) =>
  String(version)
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map(Number);

const olderThan = (version, floor) => {
  const parts = versionParts(version);
  if (!parts.length) return false;
  for (let i = 0; i < floor.length; i += 1) {
    const left = parts[i] || 0;
    if (left < floor[i]) return true;
    if (left > floor[i]) return false;
  }
  return false;
};

const heartbleed = (version) => /^1\.0\.1([a-f]?)$/.test(String(version).trim());

const open = (spec) => finding({ needsHumanReview: true, ...spec });

export const matchProduct = (product, version, source) => {
  const name = String(product || '').toLowerCase();
  const ver = String(version || '').trim();
  if (!ver) return [];
  if (name.includes('apache') && (ver === '2.4.49' || ver === '2.4.50')) {
    return [
      open({
        id: 'tech.apache.path-traversal',
        title: `Apache HTTP Server ${ver} has a known path-traversal bug`,
        titleAr: `خادم أباتشي ${ver} فيه ثغرة اجتياز مسار معروفة`,
        severity: 'critical',
        evidence: `${source}: Apache/${ver}. This scan did not try the attack.`,
        remediation:
          'Upgrade Apache HTTP Server past 2.4.50 and confirm the running build, not only the banner.',
        remediationAr:
          'رقِّ خادم أباتشي إلى ما بعد 2.4.50 وتأكد من البناء الذي يعمل فعلًا، لا من اللافتة فقط.',
        references: [REFS.cve41773, REFS.cve42013],
        service: 'vulnerability',
      }),
    ];
  }
  if (name.includes('openssl') && heartbleed(ver)) {
    return [
      open({
        id: 'tech.openssl.heartbleed',
        title: `OpenSSL ${ver} is in the Heartbleed range`,
        titleAr: `إصدار OpenSSL ${ver} ضمن مدى ثغرة Heartbleed`,
        severity: 'critical',
        evidence: `${source}: OpenSSL/${ver}. This scan did not send a heartbeat payload.`,
        remediation:
          'Upgrade OpenSSL to a supported release and replace the private key and certificate.',
        remediationAr: 'رقِّ OpenSSL إلى إصدار مدعوم واستبدل المفتاح الخاص والشهادة.',
        references: [REFS.cve0160],
        service: 'vulnerability',
      }),
    ];
  }
  if (name.includes('jquery') && olderThan(ver, [3, 5, 0]) && !olderThan(ver, [1, 2, 0])) {
    return [
      open({
        id: 'tech.jquery.html',
        title: `jQuery ${ver} is older than 3.5.0`,
        titleAr: `jQuery ${ver} أقدم من 3.5.0`,
        severity: 'medium',
        evidence: `${source}: jQuery ${ver}. CVE-2020-11022 needs a human to confirm the site passes HTML through jQuery.`,
        remediation:
          'Upgrade jQuery to 3.5.0 or later. A reviewer should confirm whether untrusted HTML reaches jQuery.',
        remediationAr:
          'رقِّ jQuery إلى 3.5.0 أو أحدث. على المراجع أن يتأكد إن كان HTML غير موثوق يصل إلى jQuery.',
        references: [REFS.cve11022],
        service: 'vulnerability',
      }),
    ];
  }
  if (name === 'php' || name.includes('php')) {
    const parts = versionParts(ver);
    if (
      parts.length >= 2 &&
      (parts[0] < PHP_MIN[0] || (parts[0] === PHP_MIN[0] && parts[1] < PHP_MIN[1]))
    ) {
      return [
        open({
          id: 'tech.php.unsupported',
          title: `PHP ${parts[0]}.${parts[1]} is outside security support`,
          titleAr: `PHP ${parts[0]}.${parts[1]} خارج الدعم الأمني`,
          severity: 'medium',
          evidence: `${source}: PHP/${ver}. The cutoff in this catalog is 8.2, reviewed against the PHP supported-versions page as of November 2026.`,
          remediation:
            'Move to a PHP branch that still receives security fixes, then hide the X-Powered-By header.',
          remediationAr:
            'انتقل إلى فرع PHP ما زال يتلقى إصلاحات أمنية، ثم أخفِ ترويسة X-Powered-By.',
          references: [REFS.php],
          service: 'vulnerability',
        }),
      ];
    }
  }
  return [];
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
  return out.map((item) => ({ ...item, evidence: clip(item.evidence, 300) }));
};
