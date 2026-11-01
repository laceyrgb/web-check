const WEIGHT = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const CAP = { critical: 100, high: 45, medium: 32, low: 12, info: 0 };

export const SCORE_MODEL =
  'Starts at 100. Open findings subtract critical 25 (no cap), high 15 (cap 45), medium 8 (cap 32), low 3 (cap 12). Informational items and passed checks do not move the score. A refused scan has no score.';

const BANDS = [
  { min: 90, id: 'strong', en: 'strong', ar: 'وضع قوي' },
  { min: 75, id: 'fair', en: 'fair, with items to fix', ar: 'مقبول مع ملاحظات' },
  { min: 50, id: 'attention', en: 'needs attention', ar: 'يحتاج معالجة' },
  { min: 0, id: 'serious', en: 'serious', ar: 'مخاطر مرتفعة' },
];

export const scoreFindings = (findings) => {
  const open = findings.filter((item) => item.status === 'open');
  let penalty = 0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of open) {
    counts[item.severity] += 1;
  }
  for (const severity of Object.keys(WEIGHT)) {
    penalty += Math.min(CAP[severity], counts[severity] * WEIGHT[severity]);
  }
  const value = Math.max(0, 100 - penalty);
  const band = BANDS.find((item) => value >= item.min);
  return {
    value,
    band: band.id,
    bandEn: band.en,
    bandAr: band.ar,
    penalty,
    counts,
    model: SCORE_MODEL,
  };
};

export const prioritise = (findings, limit = 8) => {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const open = findings
    .filter((item) => item.status === 'open' && item.severity !== 'info')
    .sort((a, b) => rank[b.severity] - rank[a.severity] || (a.id < b.id ? -1 : 1));
  const seen = new Set();
  const out = [];
  for (const item of open) {
    if (seen.has(item.remediation)) continue;
    seen.add(item.remediation);
    out.push({
      id: item.id,
      severity: item.severity,
      title: item.title,
      titleAr: item.titleAr,
      remediation: item.remediation,
      remediationAr: item.remediationAr,
    });
    if (out.length >= limit) break;
  }
  return out;
};

export const summarise = ({ hostname, findings, score, blocked, source }) => {
  if (blocked) {
    return {
      en: `No scan was run for ${hostname}. The name is on the do-not-scan list (${blocked}). Nothing was fetched.`,
      ar: `لم يُنفَّذ فحص لـ ${hostname}. الاسم ضمن قائمة المنع (${blocked}). لم يُجلب أي شيء.`,
    };
  }
  const open = findings.filter((item) => item.status === 'open');
  const review = open.filter((item) => item.needsHumanReview).length;
  const counts = score.counts;
  const sourceEn =
    source === 'supplied'
      ? 'This report was built from a supplied snapshot, not a live collection.'
      : 'This report was collected live.';
  const sourceAr =
    source === 'supplied'
      ? 'بُني هذا التقرير من لقطة مزوَّدة، وليس من جمع مباشر.'
      : 'جُمع هذا التقرير مباشرة.';
  return {
    en: `${sourceEn} ${hostname} scored ${score.value} (${score.bandEn}). ${open.length} open item(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} informational. ${review} need a human reviewer before the report is sent to a customer. This is not a penetration test and not a compliance certificate.`,
    ar: `${sourceAr} نتيجة ${hostname} هي ${score.value} (${score.bandAr}). البنود المفتوحة ${open.length}: ${counts.critical} حرجة، ${counts.high} مرتفعة، ${counts.medium} متوسطة، ${counts.low} منخفضة، ${counts.info} معلوماتية. ${review} منها تحتاج مراجعًا بشريًا قبل إرسال التقرير إلى العميل. هذا ليس اختبار اختراق وليس شهادة التزام.`,
  };
};
