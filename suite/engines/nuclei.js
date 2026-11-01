import { finding } from '../findings.js';
import { REFS } from '../refs.js';

// Allow-list of template tags. CVE and exploit tags are excluded on purpose:
// many of those templates send attack payloads, and this product does not.
export const NUCLEI_TAGS = ['misconfig', 'exposure', 'tech', 'ssl', 'dns'];

export const NUCLEI_EXCLUDE_TAGS = [
  'dos',
  'fuzz',
  'bruteforce',
  'intrusive',
  'exploit',
  'rce',
  'sqli',
  'xss',
  'lfi',
  'rfi',
];

const FORBIDDEN = new Set(NUCLEI_EXCLUDE_TAGS);

const SEVERITY = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
};

export const buildNucleiArgs = (targetUrl) => [
  '-u',
  targetUrl,
  '-silent',
  '-jsonl',
  '-omit-raw',
  '-no-interactsh',
  '-disable-update-check',
  '-rate-limit',
  '5',
  '-timeout',
  '8',
  '-retries',
  '0',
  '-severity',
  'info,low,medium,high,critical',
  '-tags',
  NUCLEI_TAGS.join(','),
  '-exclude-tags',
  NUCLEI_EXCLUDE_TAGS.join(','),
];

const tagList = (info) => {
  const tags = info?.tags;
  if (Array.isArray(tags)) return tags.map((tag) => String(tag).toLowerCase());
  return String(tags || '')
    .split(',')
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);
};

const safeTemplateId = (value) =>
  String(value || 'template')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48) || 'template';

export const findingsFromNuclei = (events) => {
  const out = [];
  for (const event of events || []) {
    if (out.length >= 40) break;
    const info = event?.info || {};
    if (tagList(info).some((tag) => FORBIDDEN.has(tag))) continue;
    const severity = SEVERITY[String(info.severity || '').toLowerCase()] || 'info';
    const template = safeTemplateId(event['template-id'] || event.templateID || info.name);
    const matched = String(event['matched-at'] || event.matched || '').slice(0, 180);
    out.push(
      finding({
        id: `nuclei.${template}`,
        title: info.name ? String(info.name).slice(0, 140) : `Nuclei template ${template}`,
        titleAr: info.name
          ? `نتيجة Nuclei: ${String(info.name).slice(0, 120)}`
          : `قالب Nuclei ${template}`,
        severity,
        evidence: `Template ${template} matched ${matched || 'the target'}. Request and response bodies were not stored.`,
        remediation:
          'A human reviewer must confirm this template hit before it is sent to the customer. Do not treat it as proof of exploitation.',
        remediationAr:
          'يجب أن يؤكد مراجع بشري هذه النتيجة قبل إرسالها للعميل. لا تعاملها كدليل على الاستغلال.',
        references: [REFS.securityTxt],
        service: 'vulnerability',
        needsHumanReview: true,
      }),
    );
  }
  return out;
};

export const runNuclei = async ({ binary, targetUrl, spawn, activeAllowed }) => {
  if (!activeAllowed) {
    return { events: [], skipped: 'Nuclei is an active engine and this run is not authorised.' };
  }
  if (typeof spawn !== 'function' || !binary) {
    return { events: [], skipped: 'Nuclei was requested but no binary was configured.' };
  }
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { events: [], skipped: 'Nuclei target URL is not valid.' };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { events: [], skipped: 'Nuclei only runs against http or https.' };
  }
  const args = buildNucleiArgs(parsed.origin);
  const result = await spawn(binary, args);
  const events = [];
  for (const line of String(result?.stdout || '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      events.push(JSON.parse(trimmed));
    } catch {
      // Ignore banners and broken lines.
    }
  }
  return { events, code: result?.code ?? 0, args };
};
