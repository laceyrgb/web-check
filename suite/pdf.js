const escapePdf = (value) =>
  String(value ?? '')
    .replaceAll('\\', '\\\\')
    .replaceAll('(', '\\(')
    .replaceAll(')', '\\)')
    .replace(/[^\x20-\x7e]/g, ' ');

// One-page English brief. Arabic stays in the HTML executive because the standard PDF
// fonts do not carry Arabic glyphs. The HTML is marked as needing a native review.
export const renderExecutivePdf = (report) => {
  const lines = [
    'Cormorant Cyber  |  UAE Readiness Scan',
    `Host: ${report.target?.hostname || ''}`,
    `Score: ${report.score?.value ?? 'n/a'} (${report.score?.bandEn || 'not scored'})`,
    `Status: ${report.release?.status || 'draft'}    Currency: AED    Arabic: needs native review`,
    report.summary?.en || '',
    'Top fixes, ranked by impact against effort:',
  ];
  for (const [index, item] of (report.prioritisedFixes || []).slice(0, 5).entries()) {
    lines.push(
      `${index + 1}. [${item.severity}] impact ${item.impact || ''} / effort ${item.effort || ''}: ${item.title}`,
    );
    lines.push(`   ${item.remediation}`);
  }
  lines.push(
    'Reference only. Not a penetration test, not a UAE IA or DESC certification, and not legal advice.',
  );
  const wrapped = [];
  for (const line of lines) {
    const text = escapePdf(line);
    for (let i = 0; i < text.length; i += 90) wrapped.push(text.slice(i, i + 90));
  }
  const body = wrapped
    .slice(0, 42)
    .map((line, index) => `BT /F1 11 Tf 48 ${760 - index * 16} Td (${line}) Tj ET`)
    .join('\n');
  const objects = [
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
    '2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj',
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj',
    `4 0 obj << /Length ${Buffer.byteLength(body)} >> stream\n${body}\nendstream endobj`,
    '5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj',
  ];
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (const object of objects) {
    offsets.push(Buffer.byteLength(pdf));
    pdf += `${object}\n`;
  }
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (const offset of offsets.slice(1)) {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return pdf;
};
