import { createHash } from 'node:crypto';

import { finding } from '../findings.js';
import { REFS } from '../refs.js';

const cookieLines = (setCookie) => {
  if (!setCookie) return [];
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  return list
    .flatMap((line) => String(line).split(/\r?\n/))
    .map((line) => line.trim())
    .filter(Boolean);
};

const parseCookie = (line) => {
  const parts = line
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean);
  if (!parts.length) return null;
  const name = parts[0].split('=')[0].trim();
  if (!name) return null;
  const attrs = {};
  for (const part of parts.slice(1)) {
    const [key, ...rest] = part.split('=');
    attrs[key.trim().toLowerCase()] = rest.join('=').trim();
  }
  return { name, attrs };
};

const idFor = (kind, name) => {
  const hash = createHash('sha256').update(name).digest('hex').slice(0, 8);
  return `cookie.${kind}.${hash}`;
};

const sessionLike = (name) => /session|sid|auth|token|jwt|sess/i.test(name);

export const analyseCookies = (http) => {
  const lines = cookieLines(http?.headers?.['set-cookie'] ?? http?.setCookie);
  if (!lines.length) return [];
  const out = [];
  for (const line of lines) {
    const cookie = parseCookie(line);
    if (!cookie) continue;
    const { name, attrs } = cookie;
    const secure = Object.prototype.hasOwnProperty.call(attrs, 'secure');
    const httpOnly = Object.prototype.hasOwnProperty.call(attrs, 'httponly');
    const same = (attrs.samesite || '').toLowerCase();
    if (!secure) {
      out.push(
        finding({
          id: idFor('secure', name),
          title: `Cookie "${name}" is missing Secure`,
          titleAr: `ملف تعريف الارتباط "${name}" بلا سمة Secure`,
          severity: 'medium',
          evidence:
            'The Set-Cookie line has no Secure attribute. The cookie value was not copied into this report.',
          remediation: 'Add Secure so browsers only send the cookie over HTTPS.',
          remediationAr: 'أضف Secure حتى يرسل المتصفح ملف الارتباط عبر HTTPS فقط.',
          references: [REFS.cookies],
          service: 'tls-headers',
        }),
      );
    }
    if (!httpOnly) {
      out.push(
        finding({
          id: idFor('httponly', name),
          title: `Cookie "${name}" is missing HttpOnly`,
          titleAr: `ملف تعريف الارتباط "${name}" بلا سمة HttpOnly`,
          severity: sessionLike(name) ? 'medium' : 'low',
          evidence:
            'The Set-Cookie line has no HttpOnly attribute. The cookie value was not copied.',
          remediation: 'Add HttpOnly unless browser script genuinely needs to read this cookie.',
          remediationAr: 'أضف HttpOnly ما لم يكن سكربت الصفحة بحاجة فعلية لقراءة هذا الملف.',
          references: [REFS.cookies],
          service: 'tls-headers',
        }),
      );
    }
    if (!same) {
      out.push(
        finding({
          id: idFor('samesite', name),
          title: `Cookie "${name}" has no SameSite attribute`,
          titleAr: `ملف تعريف الارتباط "${name}" بلا سمة SameSite`,
          severity: 'low',
          evidence: 'SameSite was not set. The cookie value was not copied.',
          remediation: 'Set SameSite=Lax or SameSite=Strict. Use None only together with Secure.',
          remediationAr: 'اضبط SameSite=Lax أو SameSite=Strict. لا تستخدم None إلا مع Secure.',
          references: [REFS.cookies],
          service: 'tls-headers',
        }),
      );
    } else if (same === 'none' && !secure) {
      out.push(
        finding({
          id: idFor('samesite-none', name),
          title: `Cookie "${name}" uses SameSite=None without Secure`,
          titleAr: `ملف الارتباط "${name}" يستخدم SameSite=None بدون Secure`,
          severity: 'high',
          evidence:
            'Browsers reject SameSite=None unless Secure is set. The cookie value was not copied.',
          remediation:
            'Add Secure, or change SameSite to Lax if the cookie is not needed cross-site.',
          remediationAr:
            'أضف Secure، أو غيّر SameSite إلى Lax إذا لم يكن الملف مطلوبًا عبر المواقع.',
          references: [REFS.cookies],
          service: 'tls-headers',
        }),
      );
    }
    if (
      name.startsWith('__Host-') &&
      (!secure || attrs.path !== '/' || Object.prototype.hasOwnProperty.call(attrs, 'domain'))
    ) {
      out.push(
        finding({
          id: idFor('host-prefix', name),
          title: `Cookie "${name}" breaks the __Host- prefix rules`,
          titleAr: `ملف الارتباط "${name}" يخالف قواعد بادئة __Host-`,
          severity: 'medium',
          evidence: 'A __Host- cookie must be Secure, Path=/, and must not set Domain.',
          remediation: 'Set Secure and Path=/ and remove Domain, or rename the cookie.',
          remediationAr: 'اضبط Secure وPath=/ واحذف Domain، أو غيّر اسم الملف.',
          references: [REFS.cookies],
          service: 'tls-headers',
        }),
      );
    }
    if (name.startsWith('__Secure-') && !secure) {
      out.push(
        finding({
          id: idFor('secure-prefix', name),
          title: `Cookie "${name}" uses the __Secure- prefix without Secure`,
          titleAr: `ملف الارتباط "${name}" يستخدم بادئة __Secure- بدون Secure`,
          severity: 'medium',
          evidence: 'The __Secure- prefix requires the Secure attribute.',
          remediation: 'Add Secure or rename the cookie.',
          remediationAr: 'أضف Secure أو غيّر اسم الملف.',
          references: [REFS.cookies],
          service: 'tls-headers',
        }),
      );
    }
  }
  if (!out.length && lines.length) {
    out.push(
      finding({
        status: 'pass',
        severity: 'info',
        id: 'cookie.flags.pass',
        title: 'Cookies that were set include Secure, HttpOnly, and SameSite',
        titleAr: 'ملفات الارتباط المرسلة تتضمن Secure وHttpOnly وSameSite',
        evidence: `${lines.length} Set-Cookie line(s) reviewed. Values were not stored.`,
        remediation: 'No action needed.',
        remediationAr: 'لا يلزم إجراء.',
        references: [REFS.cookies],
        service: 'tls-headers',
      }),
    );
  }
  return out;
};
