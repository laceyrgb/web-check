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

const open = (spec) => finding({ status: 'open', ...spec });

const header = (headers, name) => {
  if (!headers) return '';
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(', ');
  return value ? String(value) : '';
};

const daysUntil = (iso, now) => {
  const end = Date.parse(iso);
  if (Number.isNaN(end)) return null;
  return Math.floor((end - now.getTime()) / 86400000);
};

export const analyseTls = (tls, now = new Date()) => {
  if (!tls) return [];
  const out = [];
  const protocol = String(tls.protocol || '');
  if (
    /^ssl|tlsv1$|tlsv1\.0|tlsv1\.1/i.test(protocol) ||
    protocol === 'TLSv1' ||
    protocol === 'TLSv1.0' ||
    protocol === 'TLSv1.1'
  ) {
    out.push(
      open({
        id: 'tls.protocol.legacy',
        title: `TLS protocol ${protocol || 'unknown'} is obsolete`,
        titleAr: `بروتوكول ${protocol || 'غير معروف'} لم يعد مقبولًا`,
        severity: /sslv3|sslv2/i.test(protocol) ? 'critical' : 'high',
        evidence: `Negotiated protocol: ${protocol || '(not supplied)'}.`,
        remediation: 'Serve TLS 1.2 or TLS 1.3 only. Disable TLS 1.0, TLS 1.1, and SSL.',
        remediationAr: 'قدّم TLS 1.2 أو TLS 1.3 فقط. عطّل TLS 1.0 وTLS 1.1 وSSL.',
        references: [REFS.mozillaTls],
        service: 'tls-headers',
      }),
    );
  } else if (/tlsv1\.[23]/i.test(protocol) || protocol === 'TLSv1.2' || protocol === 'TLSv1.3') {
    out.push(
      pass({
        id: 'tls.protocol.pass',
        title: `TLS protocol ${protocol} is current`,
        titleAr: `بروتوكول ${protocol} حديث`,
        evidence: protocol,
        references: [REFS.mozillaTls],
        service: 'tls-headers',
      }),
    );
  }
  if (tls.cipher && /rc4|export|\bnull\b/i.test(tls.cipher)) {
    out.push(
      open({
        id: 'tls.cipher.weak',
        title: 'TLS cipher is weak',
        titleAr: 'خوارزمية TLS ضعيفة',
        severity: 'high',
        evidence: clip(tls.cipher),
        remediation: 'Use the Mozilla intermediate or modern TLS profile.',
        remediationAr: 'استخدم ملف TLS المتوسط أو الحديث من موزيلا.',
        references: [REFS.mozillaTls],
        service: 'tls-headers',
      }),
    );
  }
  if (tls.authorized === false) {
    out.push(
      open({
        id: 'tls.cert.untrusted',
        title: 'Certificate is not trusted for this name',
        titleAr: 'الشهادة غير موثوقة لهذا الاسم',
        severity: 'critical',
        evidence: clip(tls.authError || 'The TLS handshake did not authorise the certificate.'),
        remediation: 'Install a publicly trusted certificate that lists this hostname.',
        remediationAr: 'ثبّت شهادة موثوقة علنًا تذكر اسم هذا المضيف.',
        references: [REFS.mozillaTls],
        service: 'tls-headers',
      }),
    );
  }
  if (tls.bits && Number(tls.bits) < 2048) {
    out.push(
      open({
        id: 'tls.cert.short-key',
        title: 'Certificate key is shorter than 2048 bits',
        titleAr: 'مفتاح الشهادة أقصر من 2048 بت',
        severity: 'high',
        evidence: `${tls.bits} bits.`,
        remediation: 'Reissue the certificate with a 2048-bit RSA key or an elliptic-curve key.',
        remediationAr: 'أعد إصدار الشهادة بمفتاح RSA بطول 2048 بت أو بمفتاح منحنى إهليلجي.',
        references: [REFS.mozillaTls],
        service: 'tls-headers',
      }),
    );
  }
  if (tls.validTo) {
    const days = daysUntil(tls.validTo, now instanceof Date ? now : new Date(now));
    if (days != null && days < 0) {
      out.push(
        open({
          id: 'tls.cert.expired',
          title: 'Certificate has expired',
          titleAr: 'انتهت صلاحية الشهادة',
          severity: 'critical',
          evidence: `Not after ${tls.validTo}.`,
          remediation: 'Renew the certificate and automate renewal.',
          remediationAr: 'جدّد الشهادة واجعل التجديد تلقائيًا.',
          references: [REFS.mozillaTls],
          service: 'tls-headers',
        }),
      );
    } else if (days != null && days < 14) {
      out.push(
        open({
          id: 'tls.cert.expiring',
          title: 'Certificate expires within 14 days',
          titleAr: 'الشهادة تنتهي خلال 14 يومًا',
          severity: 'high',
          evidence: `Not after ${tls.validTo} (${days} days).`,
          remediation: 'Renew now and confirm the renewal job is actually running.',
          remediationAr: 'جدّد الآن وتأكد أن مهمة التجديد تعمل فعلًا.',
          references: [REFS.mozillaTls],
          service: 'tls-headers',
        }),
      );
    } else if (days != null && days < 30) {
      out.push(
        open({
          id: 'tls.cert.expiring-soon',
          title: 'Certificate expires within 30 days',
          titleAr: 'الشهادة تنتهي خلال 30 يومًا',
          severity: 'medium',
          evidence: `Not after ${tls.validTo} (${days} days).`,
          remediation: 'Renew before the expiry date.',
          remediationAr: 'جدّد قبل تاريخ الانتهاء.',
          references: [REFS.mozillaTls],
          service: 'tls-headers',
        }),
      );
    }
  }
  return out;
};

const hstsMaxAge = (value) => {
  const match = /max-age=(\d+)/i.exec(value);
  return match ? Number(match[1]) : null;
};

export const analyseHeaders = (http) => {
  if (!http?.headers) return [];
  const headers = http.headers;
  const out = [];
  const hsts = header(headers, 'strict-transport-security');
  if (!hsts) {
    out.push(
      open({
        id: 'headers.hsts.missing',
        title: 'Strict-Transport-Security is missing',
        titleAr: 'ترويسة HSTS غير موجودة',
        severity: 'medium',
        evidence: 'The homepage response did not include Strict-Transport-Security.',
        remediation:
          'Send Strict-Transport-Security: max-age=15552000; includeSubDomains on HTTPS responses.',
        remediationAr:
          'أرسل Strict-Transport-Security: max-age=15552000; includeSubDomains مع استجابات HTTPS.',
        references: [REFS.hsts],
        service: 'tls-headers',
      }),
    );
  } else {
    const age = hstsMaxAge(hsts);
    if (age != null && age < 15552000) {
      out.push(
        open({
          id: 'headers.hsts.short',
          title: 'HSTS max-age is under 180 days',
          titleAr: 'عمر HSTS أقل من 180 يومًا',
          severity: 'low',
          evidence: clip(hsts),
          remediation: 'Raise max-age to at least 15552000 seconds.',
          remediationAr: 'ارفع max-age إلى 15552000 ثانية على الأقل.',
          references: [REFS.hsts],
          service: 'tls-headers',
        }),
      );
    } else {
      out.push(
        pass({
          id: 'headers.hsts.pass',
          title: 'HSTS is set',
          titleAr: 'ترويسة HSTS موجودة',
          evidence: clip(hsts),
          references: [REFS.hsts],
          service: 'tls-headers',
        }),
      );
    }
  }
  const csp = header(headers, 'content-security-policy');
  if (!csp) {
    out.push(
      open({
        id: 'headers.csp.missing',
        title: 'Content-Security-Policy is missing',
        titleAr: 'سياسة أمن المحتوى غير موجودة',
        severity: 'medium',
        evidence: 'No Content-Security-Policy header on the homepage.',
        remediation:
          'Start with a policy that sets default-src and script-src to hosts you actually use. Avoid unsafe-inline.',
        remediationAr:
          'ابدأ بسياسة تحدد default-src وscript-src للمضيفين الذين تستخدمهم فعلًا. تجنب unsafe-inline.',
        references: [REFS.csp],
        service: 'tls-headers',
      }),
    );
  } else if (/script-src[^;]*\*/i.test(csp) || /default-src[^;]*\*/i.test(csp)) {
    out.push(
      open({
        id: 'headers.csp.wildcard',
        title: 'Content-Security-Policy allows scripts from anywhere',
        titleAr: 'سياسة المحتوى تسمح بالسكربت من أي مصدر',
        severity: 'medium',
        evidence: clip(csp),
        remediation:
          'Replace * in script-src or default-src with the specific hosts the site loads.',
        remediationAr:
          'استبدل * في script-src أو default-src بالمضيفين الذين يحمّل منهم الموقع فعلًا.',
        references: [REFS.csp],
        service: 'tls-headers',
      }),
    );
  } else {
    out.push(
      pass({
        id: 'headers.csp.pass',
        title: 'Content-Security-Policy is present',
        titleAr: 'سياسة أمن المحتوى موجودة',
        evidence: clip(csp),
        references: [REFS.csp],
        service: 'tls-headers',
      }),
    );
  }
  const nosniff = header(headers, 'x-content-type-options');
  if (nosniff.toLowerCase() !== 'nosniff') {
    out.push(
      open({
        id: 'headers.nosniff.missing',
        title: 'X-Content-Type-Options is not nosniff',
        titleAr: 'ترويسة X-Content-Type-Options ليست nosniff',
        severity: 'low',
        evidence: nosniff ? clip(nosniff) : 'Header absent.',
        remediation: 'Send X-Content-Type-Options: nosniff.',
        remediationAr: 'أرسل X-Content-Type-Options: nosniff.',
        references: [REFS.nosniff],
        service: 'tls-headers',
      }),
    );
  }
  const frame = header(headers, 'x-frame-options');
  const framedByCsp = /frame-ancestors/i.test(csp);
  if (!framedByCsp && !/^(deny|sameorigin)$/i.test(frame.trim())) {
    out.push(
      open({
        id: 'headers.frame.missing',
        title: 'Page can be framed by other sites',
        titleAr: 'يمكن لمواقع أخرى تضمين الصفحة في إطار',
        severity: 'low',
        evidence: frame ? clip(frame) : 'No X-Frame-Options and no CSP frame-ancestors.',
        remediation: 'Set X-Frame-Options: DENY or CSP frame-ancestors to your own origins.',
        remediationAr: 'اضبط X-Frame-Options: DENY أو frame-ancestors في CSP على نطاقاتك فقط.',
        references: [REFS.frame],
        service: 'tls-headers',
      }),
    );
  }
  if (!header(headers, 'referrer-policy')) {
    out.push(
      open({
        id: 'headers.referrer.missing',
        title: 'Referrer-Policy is missing',
        titleAr: 'ترويسة Referrer-Policy غير موجودة',
        severity: 'info',
        evidence: 'Header absent.',
        remediation: 'Send Referrer-Policy: strict-origin-when-cross-origin or a stricter value.',
        remediationAr: 'أرسل Referrer-Policy: strict-origin-when-cross-origin أو قيمة أشد.',
        references: [REFS.referrer],
        service: 'tls-headers',
      }),
    );
  }
  const server = header(headers, 'server');
  if (server && !/apache\/2\.4\.49|apache\/2\.4\.50/i.test(server)) {
    out.push(
      open({
        id: 'headers.server.banner',
        title: 'Server banner is exposed',
        titleAr: 'لافتة الخادم ظاهرة',
        severity: 'info',
        evidence: clip(server),
        remediation:
          'Remove or genericise the Server header so the exact product version is not advertised.',
        remediationAr: 'أزل ترويسة Server أو اجعلها عامة حتى لا يُعلَن إصدار المنتج.',
        references: [REFS.mozillaTls],
        service: 'tls-headers',
      }),
    );
  }
  if (String(http.scheme || '') === 'http') {
    out.push(
      open({
        id: 'tls.scheme.http',
        title: 'Homepage was collected over cleartext HTTP',
        titleAr: 'جُمعت الصفحة الرئيسية عبر HTTP غير مشفّر',
        severity: 'high',
        evidence: 'scheme: http',
        remediation: 'Redirect every HTTP request to HTTPS and then add HSTS.',
        remediationAr: 'حوّل كل طلب HTTP إلى HTTPS ثم أضف HSTS.',
        references: [REFS.hsts],
        service: 'tls-headers',
      }),
    );
  }
  return out;
};
