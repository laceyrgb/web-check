import { createHash } from 'node:crypto';

import { analyseCookies } from './cookies.js';
import { finding } from '../findings.js';
import { REFS } from '../refs.js';

const info = (spec) => finding({ severity: 'info', ...spec });

const SENSITIVE =
  /^disallow:\s*(\/(?:admin|backup|wp-admin|phpmyadmin|\.git|\.env)(?:\/\S*)?)\s*$/i;

export const analyseRobots = (text) => {
  if (text === undefined) return [];
  if (!text) {
    return [
      info({
        id: 'surface.robots.missing',
        title: 'No robots.txt was found',
        titleAr: 'لم يُعثر على robots.txt',
        evidence: 'The request for /robots.txt did not return a robots file.',
        remediation:
          'Publish a robots.txt if you want to steer well-behaved crawlers. Do not rely on it to hide secrets.',
        remediationAr:
          'انشر robots.txt إذا أردت توجيه الزواحف المهذبة. لا تعتمد عليه لإخفاء الأسرار.',
        references: [REFS.securityTxt],
        service: 'attack-surface',
        effort: 'low',
        impact: 'low',
      }),
    ];
  }
  const sensitive = String(text)
    .split('\n')
    .map((line) => SENSITIVE.exec(line.trim()))
    .filter(Boolean)
    .map((match) => match[1]);
  if (!sensitive.length) {
    return [
      finding({
        status: 'pass',
        severity: 'info',
        id: 'surface.robots.pass',
        title: 'robots.txt does not advertise a sensitive path',
        titleAr: 'ملف robots.txt لا يعلن عن مسار حساس',
        evidence: 'Disallow lines were checked for admin, backup, and dotfile paths.',
        remediation: 'No action needed.',
        remediationAr: 'لا يلزم إجراء.',
        references: [REFS.securityTxt],
        service: 'attack-surface',
      }),
    ];
  }
  return [
    finding({
      id: 'surface.robots.sensitive',
      title: 'robots.txt names a sensitive path',
      titleAr: 'ملف robots.txt يذكر مسارًا حساسًا',
      severity: 'low',
      evidence: sensitive.slice(0, 8).join(', '),
      remediation:
        'Remove Disallow entries that point at admin, backup, or dotfile paths, and confirm those paths are not public.',
      remediationAr:
        'احذف أسطر Disallow التي تشير إلى الإدارة أو النسخ أو الملفات النقطية، وتأكد أن تلك المسارات ليست عامة.',
      references: [REFS.securityTxt],
      service: 'attack-surface',
      effort: 'low',
      impact: 'low',
    }),
  ];
};

export const analyseSecurityTxt = (text) => {
  if (text === undefined) return [];
  if (text && /contact\s*:/i.test(text)) {
    return [
      finding({
        status: 'pass',
        severity: 'info',
        id: 'surface.security-txt.pass',
        title: 'security.txt publishes a contact',
        titleAr: 'ملف security.txt ينشر جهة اتصال',
        evidence: 'Contact: is present. The rest of the file was not stored.',
        remediation: 'No action needed.',
        remediationAr: 'لا يلزم إجراء.',
        references: [REFS.securityTxt],
        service: 'attack-surface',
      }),
    ];
  }
  return [
    info({
      id: 'surface.security-txt.missing',
      title: 'No security.txt contact was found',
      titleAr: 'لم يُعثر على جهة اتصال في security.txt',
      evidence: 'GET /.well-known/security.txt did not return a file with a Contact field.',
      remediation:
        'Publish a security.txt with a Contact field so researchers know where to report a problem.',
      remediationAr: 'انشر security.txt مع حقل Contact حتى يعرف الباحثون أين يبلغون عن مشكلة.',
      references: [REFS.securityTxt],
      service: 'attack-surface',
      effort: 'low',
      impact: 'low',
    }),
  ];
};

const WAF = [
  ['cf-ray', null, 'Cloudflare'],
  ['server', 'cloudflare', 'Cloudflare'],
  ['server', 'sucuri', 'Sucuri'],
  ['x-sucuri-id', null, 'Sucuri'],
  ['server', 'akamaighost', 'Akamai'],
  ['x-iinfo', null, 'Imperva'],
  ['server', 'big-ip', 'F5 BIG-IP'],
  ['server', 'mod_security', 'ModSecurity'],
];

export const analyseWaf = (headers) => {
  if (!headers) return [];
  const found = new Set();
  for (const [header, needle, name] of WAF) {
    const value = String(headers[header] || headers[header?.toLowerCase()] || '').toLowerCase();
    if (!value) continue;
    if (needle == null || value.includes(needle)) found.add(name);
  }
  if (!found.size) {
    return [
      info({
        id: 'surface.waf.none',
        title: 'No web-application firewall fingerprint on the homepage',
        titleAr: 'لا توجد بصمة جدار حماية للتطبيق على الصفحة الرئيسية',
        evidence:
          'Header fingerprints for Cloudflare, Sucuri, Akamai, Imperva, F5, and ModSecurity were absent. That is not proof a firewall is missing.',
        remediation:
          'If a firewall sits in front of the site, leave its header in place or confirm the control another way.',
        remediationAr:
          'إذا كان هناك جدار حماية أمام الموقع، أبقِ ترويسته أو تأكد من الضابط بطريقة أخرى.',
        references: [REFS.mozillaTls],
        service: 'attack-surface',
        effort: 'low',
        impact: 'low',
      }),
    ];
  }
  return [
    finding({
      status: 'pass',
      severity: 'info',
      id: 'surface.waf.present',
      title: `Web-application firewall fingerprint: ${[...found].join(', ')}`,
      titleAr: `بصمة جدار حماية للتطبيق: ${[...found].join(', ')}`,
      evidence: 'Matched a passive header fingerprint. The product was not probed.',
      remediation: 'No action needed.',
      remediationAr: 'لا يلزم إجراء.',
      references: [REFS.mozillaTls],
      service: 'attack-surface',
    }),
  ];
};

export const analyseMixedContent = (pages) => {
  const out = [];
  for (const page of pages || []) {
    const secure = page.scheme === 'https' || String(page.url || '').startsWith('https:');
    if (!secure) continue;
    const hits = [
      ...String(page.bodySnippet || '').matchAll(
        /(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)["']/gi,
      ),
    ]
      .map((match) => match[1])
      .slice(0, 5);
    if (!hits.length) continue;
    const hash = createHash('sha256').update(page.url).digest('hex').slice(0, 8);
    out.push(
      finding({
        id: `page.mixed.${hash}`,
        title: 'Page loads a resource over cleartext HTTP',
        titleAr: 'الصفحة تحمّل موردًا عبر HTTP غير مشفّر',
        severity: 'medium',
        evidence: `${page.url} references ${hits.join(', ')}`,
        remediation: 'Change those URLs to HTTPS, or drop the resource.',
        remediationAr: 'حوّل هذه العناوين إلى HTTPS، أو احذف المورد.',
        references: [REFS.hsts],
        service: 'tls-headers',
        effort: 'low',
        impact: 'medium',
      }),
    );
  }
  return out;
};

export const analyseInnerPages = (pages) => {
  if (!Array.isArray(pages) || pages.length < 2) return [];
  const inner = pages.slice(1, 5);
  return inner.flatMap((page) =>
    analyseCookies({ headers: page.headers, scheme: page.scheme }, { salt: page.url }),
  );
};
