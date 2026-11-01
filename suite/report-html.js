const escapeHtml = (value) =>
  String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const SERVICES = [
  ['email-domain', 'Email domain', 'أمن نطاق البريد'],
  ['tls-headers', 'TLS, headers, and cookies', 'TLS والترويسات وملفات الارتباط'],
  ['dns-hygiene', 'DNS hygiene', 'سلامة DNS'],
  ['attack-surface', 'Attack surface', 'سطح الهجوم'],
  ['vulnerability', 'Vulnerabilities', 'الثغرات'],
  ['legal', 'Scope and authorisation', 'النطاق والإذن'],
];

const findingBlock = (item) => `
<article class="finding ${escapeHtml(item.status)} sev-${escapeHtml(item.severity)}">
  <header>
    <span class="sev">${escapeHtml(item.severity)}</span>
    <span class="status">${item.status === 'pass' ? 'pass' : 'open'}</span>
    ${item.needsHumanReview ? '<span class="review">human review</span>' : ''}
  </header>
  <div class="pair">
    <div>
      <h3>${escapeHtml(item.title)}</h3>
      <p>${escapeHtml(item.evidence)}</p>
      <p><strong>Fix.</strong> ${escapeHtml(item.remediation)}</p>
    </div>
    <div class="ar" lang="ar" dir="rtl">
      <h3>${escapeHtml(item.titleAr)}</h3>
      <p><strong>المعالجة.</strong> ${escapeHtml(item.remediationAr)}</p>
      <p class="theme">${escapeHtml(item.mapping?.uaeIaAr || '')}</p>
    </div>
  </div>
  <p class="theme">${escapeHtml(item.mapping?.uaeIa || '')} ${escapeHtml(item.mapping?.pdpl || '')}</p>
  <ul class="refs">
    ${(item.references || [])
      .map((ref) => `<li><a href="${escapeHtml(ref.url)}">${escapeHtml(ref.title)}</a></li>`)
      .join('')}
  </ul>
</article>`;

export const renderHtml = (report) => {
  const score = report.score?.value;
  const scoreText = typeof score === 'number' ? String(score) : '—';
  const groups = SERVICES.map(([id, en, ar]) => {
    const items = (report.findings || []).filter((item) => item.service === id);
    if (!items.length) return '';
    return `<section><h2>${escapeHtml(en)} <span class="ar" lang="ar" dir="rtl">${escapeHtml(ar)}</span></h2>${items
      .map(findingBlock)
      .join('')}</section>`;
  }).join('');
  const fixes = (report.prioritisedFixes || [])
    .map(
      (item) =>
        `<li><span class="sev">${escapeHtml(item.severity)}</span><div class="pair"><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.remediation)}</p></div><div class="ar" lang="ar" dir="rtl"><strong>${escapeHtml(item.titleAr)}</strong><p>${escapeHtml(item.remediationAr)}</p></div></div></li>`,
    )
    .join('');
  const skipped = (report.coverage?.skipped || [])
    .map(
      (item) =>
        `<li><strong>${escapeHtml(item.id)}.</strong> ${escapeHtml(item.reason)} <span class="ar" lang="ar" dir="rtl">${escapeHtml(item.reasonAr || '')}</span></li>`,
    )
    .join('');
  const scope = (report.coverage?.outOfScope || [])
    .map(
      (item) =>
        `<li><div class="pair"><div>${escapeHtml(item.en)}</div><div class="ar" lang="ar" dir="rtl">${escapeHtml(item.ar)}</div></div></li>`,
    )
    .join('');
  const changes = report.changes
    ? `<section><h2>Changes since the previous report <span class="ar" lang="ar" dir="rtl">التغير منذ التقرير السابق</span></h2>
       <p>${report.changes.added.length} added, ${report.changes.removed.length} gone, score delta ${report.changes.scoreDelta ?? 'n/a'}.</p></section>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>UAE Readiness Scan — ${escapeHtml(report.target?.hostname || '')}</title>
  <style>
    :root { color-scheme: light; --ink:#1c2430; --paper:#f6f3ec; --card:#fffdf8; --line:#d9d1c3; --teal:#0f3d3e; }
    body { margin:0; background:var(--paper); color:var(--ink); font:16px/1.5 "Segoe UI", Tahoma, sans-serif; }
    main { max-width:920px; margin:0 auto; padding:2rem 1.25rem 4rem; }
    header.top { border-bottom:3px solid var(--teal); margin-bottom:1.5rem; }
    .brand { letter-spacing:.12em; text-transform:uppercase; font-size:.78rem; color:var(--teal); margin:0; }
    h1 { font-family:Georgia, "Times New Roman", serif; font-weight:500; margin:.2rem 0; }
    h2 { font-family:Georgia, "Times New Roman", serif; font-weight:500; font-size:1.35rem; }
    .pair { display:grid; grid-template-columns:1fr 1fr; gap:1rem 1.5rem; }
    .ar { font-family:Tahoma, "Noto Naskh Arabic", "Geeza Pro", sans-serif; }
    .score { font-family:Georgia, serif; font-size:4rem; line-height:1; margin:0; color:var(--teal); }
    .box, .finding, li { background:var(--card); border:1px solid var(--line); border-radius:8px; }
    .box { padding:1rem 1.1rem; margin:1rem 0; }
    .finding { padding:.9rem 1rem; margin:.7rem 0; }
    .sev { display:inline-block; font-size:.75rem; letter-spacing:.04em; text-transform:uppercase; border-radius:99px; padding:.1rem .5rem; background:#ece7dc; }
    .sev-critical .sev, .finding.sev-critical { border-color:#8f1d1d; }
    .sev-high { }
    .review { font-size:.75rem; color:#8f1d1d; margin-left:.4rem; }
    .theme, .refs { color:#3d4a57; font-size:.9rem; }
    ol { padding-left:1.2rem; } ol li { padding:.6rem .8rem; margin:.4rem 0; list-style:decimal inside; }
    a { color:var(--teal); }
    @media (max-width:800px) { .pair { grid-template-columns:1fr; } }
    @media print { body { background:#fff; } .finding, .box, li { break-inside:avoid; } }
  </style>
</head>
<body>
<main>
  <header class="top">
    <p class="brand">Cormorant Cyber</p>
    <h1>UAE Readiness Scan</h1>
    <p class="ar" lang="ar" dir="rtl">فحص الجاهزية للإمارات</p>
    <p>${escapeHtml(report.target?.hostname || '')} · ${escapeHtml(report.mode)} · ${escapeHtml(report.source)} · ${escapeHtml(report.generatedAt || '')}</p>
  </header>
  <section class="box pair">
    <div>
      <p class="score">${escapeHtml(scoreText)}</p>
      <p>${escapeHtml(report.score?.bandEn || 'not scored')}</p>
      <p>${escapeHtml(report.summary?.en || '')}</p>
    </div>
    <div class="ar" lang="ar" dir="rtl">
      <p class="score">${escapeHtml(scoreText)}</p>
      <p>${escapeHtml(report.score?.bandAr || 'بلا درجة')}</p>
      <p>${escapeHtml(report.summary?.ar || '')}</p>
    </div>
  </section>
  <section class="box">
    <h2>Prioritised fixes <span class="ar" lang="ar" dir="rtl">إصلاحات مرتبة حسب الأولوية</span></h2>
    ${fixes ? `<ol>${fixes}</ol>` : '<p>No prioritised fixes.</p>'}
  </section>
  ${groups}
  <section>
    <h2>What this scan did not do <span class="ar" lang="ar" dir="rtl">ما لم يفعله هذا الفحص</span></h2>
    <ul>${scope}</ul>
    ${skipped ? `<ul>${skipped}</ul>` : ''}
  </section>
  ${changes}
  <section class="box">
    <h2>Reference only <span class="ar" lang="ar" dir="rtl">للاسترشاد فقط</span></h2>
    <div class="pair">
      <p>${escapeHtml(report.mappingDisclaimer?.en || '')}</p>
      <p class="ar" lang="ar" dir="rtl">${escapeHtml(report.mappingDisclaimer?.ar || '')}</p>
    </div>
    <p>${escapeHtml(report.score?.model || '')}</p>
    <p>Authorised: ${report.legal?.authorized ? 'yes' : 'no'}. Ownership: ${escapeHtml(report.legal?.ownership?.method || report.legal?.ownership?.reason || 'n/a')}. Active checks ran: ${report.legal?.activeRan ? 'yes' : 'no'}.</p>
  </section>
</main>
</body>
</html>`;
};

export const renderJson = (report) => `${JSON.stringify(report, null, 2)}\n`;

export { escapeHtml };
