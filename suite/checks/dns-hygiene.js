import { endsWithName } from '../domain.js';
import { clip, finding } from '../findings.js';
import { REFS } from '../refs.js';

const pass = (spec) =>
  finding({
    status: 'pass',
    severity: 'info',
    remediation: 'No action needed.',
    remediationAr: 'لا يلزم إجراء.',
    ...spec,
  });

// A CNAME to one of these, which then fails to resolve, is a lead — not a confirmed takeover.
const TAKEOVER_SUFFIXES = [
  'github.io',
  'herokuapp.com',
  'azurewebsites.net',
  'cloudapp.net',
  'amazonaws.com',
  'cloudfront.net',
  'myshopify.com',
  'ghost.io',
  'pantheonsite.io',
  'bitbucket.io',
  'surge.sh',
  'netlify.app',
  'vercel.app',
  'freshdesk.com',
  'zendesk.com',
];

const hostOf = (value) =>
  String(value || '')
    .toLowerCase()
    .replace(/\.$/, '');

export const analyseDns = (dns) => {
  if (!dns || dns.error) return [];
  const out = [];
  if (Array.isArray(dns.ns)) {
    if (dns.ns.length === 0) {
      out.push(
        finding({
          id: 'dns.ns.missing',
          title: 'No name servers were returned',
          titleAr: 'لم تُرجع خوادم أسماء',
          severity: 'high',
          evidence: 'The NS lookup was empty.',
          remediation: 'Publish at least two name servers on separate infrastructure.',
          remediationAr: 'انشر خادمي أسماء على الأقل على بنيتين منفصلتين.',
          references: [REFS.dnssec],
          service: 'dns-hygiene',
        }),
      );
    } else if (dns.ns.length === 1) {
      out.push(
        finding({
          id: 'dns.ns.single',
          title: 'Only one name server is published',
          titleAr: 'خادم أسماء واحد فقط منشور',
          severity: 'medium',
          evidence: dns.ns.map(hostOf).join(', '),
          remediation: 'Add a second name server so a single outage does not remove the domain.',
          remediationAr: 'أضف خادم أسماء ثانيًا حتى لا يختفي النطاق بعطل واحد.',
          references: [REFS.dnssec],
          service: 'dns-hygiene',
        }),
      );
    } else {
      out.push(
        pass({
          id: 'dns.ns.pass',
          title: 'More than one name server is published',
          titleAr: 'أكثر من خادم أسماء منشور',
          evidence: `${dns.ns.length} name servers.`,
          references: [REFS.dnssec],
          service: 'dns-hygiene',
        }),
      );
    }
    if (dns.nsResolves) {
      for (const ns of dns.ns) {
        const name = hostOf(ns);
        if (dns.nsResolves[name] === false) {
          out.push(
            finding({
              id: 'dns.ns.dangling',
              title: 'A published name server did not resolve',
              titleAr: 'خادم أسماء منشور لم يُحل',
              severity: 'high',
              evidence: name,
              remediation:
                'Remove or repair the NS host. A dangling delegation is an availability failure and sometimes an abuse path.',
              remediationAr:
                'أزل مضيف NS أو أصلحه. التفويض المعلق فشل في التوفر، وقد يكون مسار إساءة.',
              references: [REFS.dnssec],
              service: 'dns-hygiene',
            }),
          );
          break;
        }
      }
    }
  }
  if (Array.isArray(dns.caa)) {
    if (!dns.caa.length) {
      out.push(
        finding({
          id: 'dns.caa.missing',
          title: 'No CAA record',
          titleAr: 'لا يوجد سجل CAA',
          severity: 'low',
          evidence: 'No CAA records were returned for this name.',
          remediation:
            'Publish CAA records naming the certificate authorities allowed to issue for this domain.',
          remediationAr: 'انشر سجلات CAA تحدد جهات الإصدار المسموح لها بإصدار شهادات لهذا النطاق.',
          references: [REFS.caa],
          service: 'dns-hygiene',
        }),
      );
    } else {
      out.push(
        pass({
          id: 'dns.caa.pass',
          title: 'CAA records are published',
          titleAr: 'سجلات CAA منشورة',
          evidence: dns.caa
            .map((row) => (typeof row === 'string' ? row : JSON.stringify(row)))
            .join(', '),
          references: [REFS.caa],
          service: 'dns-hygiene',
        }),
      );
    }
  }
  if (dns.dnssec) {
    if (dns.dnssec.ds && dns.dnssec.dnskey) {
      out.push(
        pass({
          id: 'dns.dnssec.pass',
          title: 'DNSSEC DS and DNSKEY records are present',
          titleAr: 'سجلا DNSSEC من نوع DS وDNSKEY موجودان',
          evidence:
            'DS and DNSKEY were both found. This scan does not validate the chain of trust.',
          references: [REFS.dnssec],
          service: 'dns-hygiene',
        }),
      );
    } else {
      out.push(
        finding({
          id: 'dns.dnssec.missing',
          title: 'DNSSEC is not in place',
          titleAr: 'DNSSEC غير مفعّل',
          severity: 'medium',
          evidence: `DS ${dns.dnssec.ds ? 'found' : 'absent'}, DNSKEY ${dns.dnssec.dnskey ? 'found' : 'absent'}.`,
          remediation:
            'Sign the zone and publish a DS record at the parent. Confirm the chain with a validating resolver before you rely on it.',
          remediationAr:
            'وقّع المنطقة وانشر سجل DS عند النطاق الأعلى. تأكد من سلسلة الثقة بمحلل يتحقق قبل الاعتماد عليها.',
          references: [REFS.dnssec],
          service: 'dns-hygiene',
        }),
      );
    }
  }
  if (dns.mxResolves && Array.isArray(dns.mx)) {
    const dangling = dns.mx
      .map((row) => hostOf(row.exchange))
      .filter((exchange) => exchange && exchange !== '.' && dns.mxResolves[exchange] === false);
    if (dangling.length) {
      out.push(
        finding({
          id: 'dns.mx.dangling',
          title: 'An MX host did not resolve',
          titleAr: 'مضيف MX لم يُحل',
          severity: 'high',
          evidence: dangling.join(', '),
          remediation:
            'Point MX at a host that has address records, or remove the stale exchanger.',
          remediationAr: 'وجّه MX إلى مضيف لديه سجلات عناوين، أو احذف المبادل القديم.',
          references: [REFS.spf],
          service: 'dns-hygiene',
        }),
      );
    }
  }
  const cnames = Array.isArray(dns.cnames) ? dns.cnames.slice(0, 30) : [];
  for (const row of cnames) {
    if (row.targetResolves !== false) continue;
    const target = hostOf(row.target);
    const takeover = TAKEOVER_SUFFIXES.some((suffix) => endsWithName(target, suffix.trim()));
    out.push(
      finding({
        id: takeover ? 'dns.cname.dangling-service' : 'dns.cname.dangling',
        title: takeover
          ? 'Possible dangling CNAME to a third-party service'
          : 'CNAME target did not resolve',
        titleAr: takeover ? 'احتمال اسم CNAME معلّق نحو خدمة طرف ثالث' : 'هدف CNAME لم يُحل',
        severity: takeover ? 'high' : 'medium',
        evidence: `${row.host} → ${target}. This is not a confirmed takeover; a reviewer must check before saying so.`,
        remediation: takeover
          ? 'Remove the CNAME or reclaim the name at the provider. Do not describe this as a completed takeover until a human confirms it.'
          : 'Remove the stale CNAME or restore the target.',
        remediationAr: takeover
          ? 'احذف CNAME أو استعد الاسم عند المزود. لا تصف هذا كاستيلاء مكتمل قبل أن يؤكده مراجع.'
          : 'احذف CNAME القديم أو أعد الهدف.',
        references: [REFS.dnssec],
        service: 'dns-hygiene',
        needsHumanReview: true,
      }),
    );
    break;
  }
  return out.map((item) => ({ ...item, evidence: clip(item.evidence) }));
};
