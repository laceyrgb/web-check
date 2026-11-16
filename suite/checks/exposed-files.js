import { finding } from '../findings.js';
import { REFS } from '../refs.js';

const looksLikeHtml = (body) => /<html|<!doctype html/i.test(String(body).slice(0, 800));

const looksLikeEnv = (body) => {
  if (looksLikeHtml(body)) return false;
  const assigns = String(body)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#') && /^[A-Z][A-Z0-9_]{2,}=/.test(line));
  return assigns.length >= 2;
};

// Fixed list. Callers cannot add paths; that would turn the runner into an open fetcher.
export const EXPOSED_PATHS = [
  {
    path: '/.git/HEAD',
    id: 'exposure.git',
    severity: 'high',
    title: 'Git metadata is readable',
    titleAr: 'بيانات Git قابلة للقراءة',
    test: (body) =>
      /^ref:\s*refs\//i.test(String(body).trim()) || /^[0-9a-f]{40}\s*$/i.test(String(body).trim()),
    remediation: 'Remove the .git directory from the web root and block the path at the server.',
    remediationAr: 'احذف مجلد .git من جذر الموقع واحجب المسار في الخادم.',
  },
  {
    path: '/.env',
    id: 'exposure.env',
    severity: 'high',
    title: 'Environment file is readable',
    titleAr: 'ملف البيئة قابل للقراءة',
    test: looksLikeEnv,
    remediation:
      'Remove the file from the web root, rotate every secret that was in it, and block dotfiles.',
    remediationAr: 'احذف الملف من جذر الموقع، وبدّل كل سر كان فيه، واحجب الملفات النقطية.',
  },
  {
    path: '/wp-config.php',
    id: 'exposure.wp-config',
    severity: 'critical',
    title: 'WordPress configuration is readable',
    titleAr: 'إعداد ووردبريس قابل للقراءة',
    test: (body) => /DB_PASSWORD|DB_NAME/.test(body) && !looksLikeHtml(body),
    remediation:
      'Remove the file from public reach and rotate the database password. Values were not copied into this report.',
    remediationAr:
      'أبعد الملف عن الوصول العام وبدّل كلمة مرور قاعدة البيانات. لم تُنسخ القيم إلى هذا التقرير.',
  },
  {
    path: '/wp-config.php.bak',
    id: 'exposure.wp-config-bak',
    severity: 'critical',
    title: 'A WordPress configuration backup is readable',
    titleAr: 'نسخة احتياطية من إعداد ووردبريس قابلة للقراءة',
    test: (body) => /DB_PASSWORD|DB_NAME/.test(body),
    remediation: 'Delete the backup from the site and rotate the database password.',
    remediationAr: 'احذف النسخة من الموقع وبدّل كلمة مرور قاعدة البيانات.',
  },
  {
    path: '/phpinfo.php',
    id: 'exposure.phpinfo',
    severity: 'medium',
    title: 'phpinfo page is exposed',
    titleAr: 'صفحة phpinfo مكشوفة',
    test: (body) => /<title>phpinfo\(\)<\/title>|PHP Version/i.test(body),
    remediation: 'Delete phpinfo.php from the site.',
    remediationAr: 'احذف phpinfo.php من الموقع.',
  },
  {
    path: '/server-status',
    id: 'exposure.server-status',
    severity: 'medium',
    title: 'Server status page is exposed',
    titleAr: 'صفحة حالة الخادم مكشوفة',
    test: (body) => /Apache Server Status/i.test(body),
    remediation: 'Restrict mod_status to local administrators.',
    remediationAr: 'اقصر mod_status على مسؤولي الجهاز المحلي.',
  },
  {
    path: '/actuator/env',
    id: 'exposure.actuator',
    severity: 'high',
    title: 'Application environment endpoint is exposed',
    titleAr: 'نقطة بيئة التطبيق مكشوفة',
    test: (body) => /propertySources|activeProfiles/.test(body),
    remediation: 'Disable the public actuator env endpoint and rotate any secret it could show.',
    remediationAr: 'عطّل نقطة actuator/env العامة وبدّل أي سر كان يمكن أن تظهره.',
  },
  {
    path: '/elmah.axd',
    id: 'exposure.elmah',
    severity: 'medium',
    title: 'ELMAH error log is exposed',
    titleAr: 'سجل أخطاء ELMAH مكشوف',
    test: (body) => /Error Log/i.test(body),
    remediation: 'Require authentication for elmah.axd or remove it.',
    remediationAr: 'اشترط المصادقة على elmah.axd أو احذفه.',
  },
  {
    path: '/backup.sql',
    id: 'exposure.sql',
    severity: 'high',
    title: 'SQL backup is readable',
    titleAr: 'نسخة SQL الاحتياطية قابلة للقراءة',
    test: (body) => /CREATE TABLE|INSERT INTO/i.test(body) && !looksLikeHtml(body),
    remediation: 'Remove the dump from the site and treat its contents as exposed.',
    remediationAr: 'احذف النسخة من الموقع وعامل محتواها على أنه انكشف.',
  },
  {
    path: '/crossdomain.xml',
    id: 'exposure.crossdomain',
    severity: 'medium',
    title: 'crossdomain.xml trusts every origin',
    titleAr: 'ملف crossdomain.xml يثق بكل المصادر',
    test: (body) => /allow-access-from[^>]+domain\s*=\s*"\*"/i.test(body),
    remediation: 'Remove the wildcard allow-access-from policy.',
    remediationAr: 'أزل سياسة allow-access-from ذات الرمز *.',
  },
];

const FORBIDDEN_HINTS = new Set([
  '/.git/HEAD',
  '/.env',
  '/wp-config.php',
  '/wp-config.php.bak',
  '/backup.sql',
]);

export const classifyExposure = (path, status, body) => {
  const rule = EXPOSED_PATHS.find((item) => item.path === path);
  if (!rule) return null;
  if (status === 200 && rule.test(String(body || ''))) {
    return { ...rule, hint: false, status };
  }
  if ((status === 401 || status === 403) && FORBIDDEN_HINTS.has(path)) {
    return { ...rule, id: `${rule.id}.forbidden`, severity: 'low', hint: true, status };
  }
  return null;
};

export const findingsFromExposure = (matches) =>
  (matches || []).filter(Boolean).map((rule) =>
    finding({
      id: rule.id,
      title: rule.hint ? `${rule.title} (request was forbidden)` : rule.title,
      titleAr: rule.hint ? `${rule.titleAr} (الطلب مرفوض)` : rule.titleAr,
      severity: rule.severity,
      evidence: rule.hint
        ? `HTTP ${rule.status} for ${rule.path}. The body was not stored.`
        : `HTTP 200 for ${rule.path} matched a signature. The body was not copied into this report.`,
      remediation: rule.remediation,
      remediationAr: rule.remediationAr,
      references: [REFS.securityTxt],
      service: 'attack-surface',
      needsHumanReview: true,
    }),
  );
