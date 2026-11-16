import { createHash } from 'node:crypto';

import { endsWithName, registrableDomain } from '../domain.js';
import { finding } from '../findings.js';
import { REFS } from '../refs.js';

const WATCH = new Set([
  'admin',
  'vpn',
  'staging',
  'stage',
  'dev',
  'test',
  'jenkins',
  'gitlab',
  'git',
  'phpmyadmin',
  'cpanel',
  'webmail',
  'owa',
  'autodiscover',
  'remote',
  'portal',
  'db',
  'backup',
  'internal',
  'sso',
  'citrix',
  'jira',
  'confluence',
  'grafana',
  'kibana',
  'uat',
  'preprod',
]);

const normalise = (name) =>
  String(name || '')
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '')
    .replace(/\.$/, '');

export const classifyNames = (hostname, names) => {
  if (!Array.isArray(names)) return { names: null, interesting: [], wildcard: false };
  const apex = registrableDomain(hostname);
  const seen = new Set();
  const kept = [];
  let wildcard = false;
  for (const raw of names) {
    if (String(raw).includes('*')) wildcard = true;
    const name = normalise(raw);
    if (!name || name === apex || !endsWithName(name, apex)) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    kept.push(name);
  }
  kept.sort();
  const interesting = kept.filter((name) => {
    const label = name
      .slice(0, -(apex.length + 1))
      .split('.')
      .pop();
    return WATCH.has(label);
  });
  return { names: kept, interesting, wildcard, apex };
};

export const analyseSubdomains = (hostname, names) => {
  const classified = classifyNames(hostname, names);
  if (!classified.names) return [];
  const out = [
    finding({
      id: 'surface.ct.count',
      title: classified.names.length
        ? `${classified.names.length} name(s) in the supplied certificate-transparency extract`
        : 'No other names in the supplied certificate-transparency extract',
      titleAr: classified.names.length
        ? `${classified.names.length} اسم في مقتطف شفافية الشهادات المزوَّد`
        : 'لا توجد أسماء أخرى في مقتطف شفافية الشهادات المزوَّد',
      severity: 'info',
      status: 'open',
      evidence: classified.names.slice(0, 12).join(', ') || 'The extract was empty.',
      remediation:
        'Review names you do not recognise. This list comes from public certificate logs, not from guessing hostnames.',
      remediationAr:
        'راجع الأسماء التي لا تعرفها. هذه القائمة من سجلات الشهادات العامة، وليست من تخمين أسماء المضيفين.',
      references: [REFS.securityTxt],
      service: 'attack-surface',
    }),
  ];
  if (classified.wildcard) {
    out.push(
      finding({
        id: 'surface.ct.wildcard',
        title: 'A wildcard name appears in certificate transparency',
        titleAr: 'اسم شامل يظهر في شفافية الشهادات',
        severity: 'info',
        evidence: `A *.${classified.apex} style name was present.`,
        remediation:
          'Confirm the wildcard certificate is still yours and that unused labels are not delegated.',
        remediationAr: 'تأكد أن الشهادة الشاملة ما زالت لكم وأن التسميات غير المستخدمة غير مفوضة.',
        references: [REFS.caa],
        service: 'attack-surface',
      }),
    );
  }
  for (const name of classified.interesting.slice(0, 15)) {
    const hash = createHash('sha256').update(name).digest('hex').slice(0, 8);
    out.push(
      finding({
        id: `surface.name.${hash}`,
        title: `Name worth a look: ${name}`,
        titleAr: `اسم يستحق المراجعة: ${name}`,
        severity: 'low',
        evidence:
          'The leftmost label is commonly an administrative or pre-production service. Being in a certificate log does not mean the port is open.',
        remediation:
          'If the service is unused, remove the DNS name and the certificate. If it is used, confirm it is meant to be public.',
        remediationAr:
          'إذا كانت الخدمة غير مستخدمة، احذف اسم DNS والشهادة. إذا كانت مستخدمة، تأكد أنها مقصودة للعامة.',
        references: [REFS.securityTxt],
        service: 'attack-surface',
      }),
    );
  }
  return out;
};
