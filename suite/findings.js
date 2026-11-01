import { createHash } from 'node:crypto';

import { REFS } from './refs.js';

export const SUITE_VERSION = '0.1.0';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const ID_RE = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;

// Themes a reviewer can hang a finding on. These are not control IDs and not a certification.
const THEMES = {
  'email-domain': {
    en: 'Reference only: UAE IA theme of protecting message authenticity. Not a control assessment.',
    ar: 'للاسترشاد فقط: موضوع معيار ضمان المعلومات الإماراتي المتعلق بصحة الرسائل. هذا ليس تقييم ضابط وليس شهادة.',
    pdplEn:
      'Reference only: PDPL requires appropriate protection of personal data. Mail authentication reduces spoofing; it does not decide whether PDPL is met.',
    pdplAr:
      'للاسترشاد فقط: يُلزم نظام حماية البيانات الشخصية بحماية البيانات الشخصية حماية مناسبة. توثيق البريد يقلل انتحال المرسل، ولا يقرر اكتمال الالتزام بالنظام.',
  },
  'tls-headers': {
    en: 'Reference only: UAE IA theme of cryptography in transit and secure service configuration.',
    ar: 'للاسترشاد فقط: موضوع التشفير أثناء النقل والإعداد الآمن للخدمة ضمن معيار ضمان المعلومات.',
    pdplEn:
      'Reference only: PDPL security of personal data processed by this site. Not a determination that the article is satisfied.',
    pdplAr:
      'للاسترشاد فقط: أمن البيانات الشخصية التي يعالجها هذا الموقع وفق نظام حماية البيانات. ليس قرارًا بأن المادة مستوفاة.',
  },
  'dns-hygiene': {
    en: 'Reference only: UAE IA theme of protecting the integrity of name resolution.',
    ar: 'للاسترشاد فقط: موضوع سلامة حل أسماء النطاقات ضمن معيار ضمان المعلومات.',
    pdplEn:
      'Reference only: name-resolution integrity supports PDPL security measures. Not a compliance determination.',
    pdplAr:
      'للاسترشاد فقط: سلامة حل الأسماء تدعم تدابير الأمن في نظام حماية البيانات. ليس قرار التزام.',
  },
  'attack-surface': {
    en: 'Reference only: UAE IA theme of knowing which services are exposed and reducing them.',
    ar: 'للاسترشاد فقط: موضوع معرفة الخدمات المكشوفة وتقليلها ضمن معيار ضمان المعلومات.',
    pdplEn:
      'Reference only: exposed services can put personal data within reach. Not a finding that data was accessed.',
    pdplAr:
      'للاسترشاد فقط: الخدمات المكشوفة قد تجعل البيانات الشخصية في المتناول. ليست نتيجة بأن البيانات وُصِلت.',
  },
  vulnerability: {
    en: 'Reference only: UAE IA theme of vulnerability management. A version match is a lead for a human reviewer.',
    ar: 'للاسترشاد فقط: موضوع إدارة الثغرات. تطابق الإصدار إشارة لمراجع بشري، وليس تأكيد استغلال.',
    pdplEn:
      'Reference only: an unpatched service can affect PDPL security duties. This row does not confirm exploitation.',
    pdplAr:
      'للاسترشاد فقط: خدمة غير مرقعة قد تؤثر في واجب الأمن بموجب النظام. هذا السطر لا يؤكد حدوث استغلال.',
  },
  legal: {
    en: 'Reference only: authorisation and scope. Scanning without authority can fall under the cybercrime law. Not legal advice.',
    ar: 'للاسترشاد فقط: الإذن ونطاق الفحص. الفحص بلا صلاحية قد يدخل في قانون مكافحة الشائعات والجرائم الإلكترونية. هذه ليست استشارة قانونية.',
    pdplEn:
      'Reference only: PDPL purpose limitation. Do not collect personal data the engagement did not ask for.',
    pdplAr:
      'للاسترشاد فقط: تقييد الغرض في نظام حماية البيانات. لا تجمع بيانات شخصية لا يطلبها نطاق العمل.',
  },
};

export const clip = (value, max = 240) => {
  const text = String(value ?? '');
  return text.length <= max ? text : `${text.slice(0, max)}…`;
};

export const digestId = (prefix, raw) => {
  const hash = createHash('sha256').update(String(raw)).digest('hex').slice(0, 8);
  const slug = String(raw)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
  return `${prefix}.${slug || 'item'}.${hash}`.replace(/\.+/g, '.');
};

const themeFor = (service) => THEMES[service] || THEMES.legal;

export const finding = (input) => {
  const required = [
    'id',
    'title',
    'titleAr',
    'severity',
    'evidence',
    'remediation',
    'remediationAr',
    'service',
  ];
  for (const key of required) {
    if (typeof input[key] !== 'string' || input[key].trim() === '') {
      throw new Error(`Finding ${input.id || '(no id)'} is missing ${key}`);
    }
  }
  if (!ID_RE.test(input.id)) throw new Error(`Finding id is not a safe token: ${input.id}`);
  if (!SEVERITIES.includes(input.severity)) throw new Error(`Bad severity ${input.severity}`);
  if (!Array.isArray(input.references) || input.references.length === 0) {
    throw new Error(`Finding ${input.id} needs references`);
  }
  for (const item of input.references) {
    if (!item?.title || !/^https:\/\//.test(item.url || '')) {
      throw new Error(`Finding ${input.id} has a reference without an https URL`);
    }
  }
  const status = input.status === 'pass' ? 'pass' : 'open';
  const theme = themeFor(input.service);
  const openAndSerious =
    status === 'open' && (input.severity === 'critical' || input.severity === 'high');
  return {
    id: input.id,
    title: input.title,
    titleAr: input.titleAr,
    severity: input.severity,
    status,
    evidence: input.evidence,
    remediation: input.remediation,
    remediationAr: input.remediationAr,
    references: input.references.map((item) => ({ title: item.title, url: item.url })),
    service: input.service,
    needsHumanReview: input.needsHumanReview ?? openAndSerious,
    mapping: {
      uaeIa: theme.en,
      uaeIaAr: theme.ar,
      pdpl: theme.pdplEn,
      pdplAr: theme.pdplAr,
    },
  };
};

export const dedupe = (findings) => {
  const map = new Map();
  for (const item of findings) {
    const prev = map.get(item.id);
    if (!prev) {
      map.set(item.id, item);
      continue;
    }
    const prevRank = prev.status === 'pass' ? -1 : SEVERITY_RANK[prev.severity];
    const nextRank = item.status === 'pass' ? -1 : SEVERITY_RANK[item.severity];
    if (nextRank > prevRank) map.set(item.id, item);
  }
  return [...map.values()];
};

export const sortFindings = (findings) =>
  [...findings].sort((a, b) => {
    if (a.status !== b.status) return a.status === 'open' ? -1 : 1;
    const bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

export const standardsRefs = [REFS.uaeIa, REFS.pdpl];
