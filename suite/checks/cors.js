import { finding } from '../findings.js';
import { REFS } from '../refs.js';

// Reserved name so a reflection test can never be a customer's real origin.
export const CORS_PROBE_ORIGIN = 'https://readiness-scan.invalid';

const valueOf = (headers, name) => {
  if (!headers) return '';
  const value = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(', ') : value ? String(value) : '';
};

export const analyseCors = ({ headers, probe } = {}) => {
  const out = [];
  const allow = valueOf(headers, 'access-control-allow-origin');
  const creds = /^true$/i.test(valueOf(headers, 'access-control-allow-credentials'));
  if (allow === '*' && creds) {
    out.push(
      finding({
        id: 'cors.wildcard-credentials',
        title: 'CORS allows any origin and credentials on the same response',
        titleAr: 'CORS يسمح بأي مصدر مع بيانات الاعتماد في الاستجابة نفسها',
        severity: 'medium',
        evidence:
          'Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true. Browsers ignore this pair, but it shows the policy was not thought through.',
        remediation:
          'Reflect a specific allow-list of origins, and only then enable credentials. Never combine * with credentials.',
        remediationAr:
          'اعكس قائمة محددة من المصادر، ثم فعّل بيانات الاعتماد. لا تجمع * مع بيانات الاعتماد.',
        references: [REFS.cors],
        service: 'tls-headers',
      }),
    );
  } else if (allow === '*') {
    out.push(
      finding({
        id: 'cors.wildcard',
        title: 'CORS allows any origin',
        titleAr: 'CORS يسمح بأي مصدر',
        severity: 'low',
        evidence: 'Access-Control-Allow-Origin: * on this response.',
        remediation:
          'If the response is not meant to be a public API, remove the wildcard or replace it with the origins that should call it.',
        remediationAr:
          'إذا لم تكن الاستجابة واجهة عامة مقصودة، أزل الرمز * أو استبدله بالمصادر المسموح لها.',
        references: [REFS.cors],
        service: 'tls-headers',
      }),
    );
  }
  if (probe?.originSent && probe.allowOrigin) {
    const reflected = probe.allowOrigin === probe.originSent && probe.originSent !== 'null';
    const probeCreds = probe.allowCredentials === true;
    if (reflected && probeCreds) {
      out.push(
        finding({
          id: 'cors.reflected-credentials',
          title: 'Site reflects an arbitrary Origin and allows credentials',
          titleAr: 'الموقع يعكس أي ترويسة Origin ويسمح ببيانات الاعتماد',
          severity: 'critical',
          evidence: `Origin ${probe.originSent} was echoed in Access-Control-Allow-Origin with credentials enabled.`,
          remediation:
            'Allow credentials only for an explicit list of your own origins. Do not copy the request Origin into the response.',
          remediationAr:
            'اسمح ببيانات الاعتماد فقط لقائمة صريحة من نطاقاتك. لا تنسخ ترويسة Origin من الطلب إلى الاستجابة.',
          references: [REFS.cors],
          service: 'tls-headers',
          needsHumanReview: true,
        }),
      );
    } else if (reflected) {
      out.push(
        finding({
          id: 'cors.reflected',
          title: 'Site reflects an arbitrary Origin',
          titleAr: 'الموقع يعكس أي ترويسة Origin',
          severity: 'medium',
          evidence: `Origin ${probe.originSent} was echoed. Credentials were not enabled on that response.`,
          remediation: 'Return a fixed allow-list instead of echoing the Origin header.',
          remediationAr: 'أرجع قائمة مصادر ثابتة بدل نسخ ترويسة Origin.',
          references: [REFS.cors],
          service: 'tls-headers',
        }),
      );
    }
    if (probe.allowOrigin === 'null' && probeCreds) {
      out.push(
        finding({
          id: 'cors.null-credentials',
          title: 'CORS allows the null origin with credentials',
          titleAr: 'CORS يسمح بالمصدر null مع بيانات الاعتماد',
          severity: 'high',
          evidence: 'Access-Control-Allow-Origin: null together with credentials.',
          remediation:
            'Remove the null origin from the allow-list. Sandboxed frames and data URLs use that origin.',
          remediationAr:
            'أزل المصدر null من القائمة. الإطارات المعزولة وعناوين data تستخدم هذا المصدر.',
          references: [REFS.cors],
          service: 'tls-headers',
        }),
      );
    }
  }
  return out;
};
