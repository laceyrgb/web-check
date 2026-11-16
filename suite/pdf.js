import { readFileSync } from 'node:fs';

import { visualSegments } from './arabic.js';
import { readTrueType } from './ttf.js';

const FONT_PATH = new URL('./fonts/NotoNaskhArabic-Regular.ttf', import.meta.url);
const font = readTrueType(readFileSync(FONT_PATH));

const helveticaWidth = (code) => {
  if (code === 32) return 278;
  if ("iljt.,:;'|".includes(String.fromCodePoint(code))) return 278;
  if ('mwMW'.includes(String.fromCodePoint(code))) return 890;
  if (code >= 48 && code <= 57) return 556;
  return 520;
};

const arabicWidth = (code) => {
  const glyph = font.glyphs.get(code) || 0;
  if (!glyph) return 0;
  return Math.round((font.advance(glyph) * 1000) / font.unitsPerEm);
};

const wrapSegments = (segments, maxWidth, size) => {
  const lines = [];
  let line = [];
  let width = 0;
  const push = () => {
    if (line.length) lines.push(line);
    line = [];
    width = 0;
  };
  for (const segment of segments) {
    const measure = segment.font === 'arabic' ? arabicWidth : helveticaWidth;
    for (const code of segment.cps) {
      const advance = (measure(code) * size) / 1000;
      if (code === 32 && width > maxWidth * 0.7) {
        push();
        continue;
      }
      if (width + advance > maxWidth && line.length) push();
      const last = line.at(-1);
      if (!last || last.font !== segment.font) line.push({ font: segment.font, cps: [code] });
      else last.cps.push(code);
      width += advance || size * 0.5;
    }
  }
  push();
  return lines.slice(0, 8);
};

const lineWidth = (segments, size) =>
  segments.reduce((sum, segment) => {
    const measure = segment.font === 'arabic' ? arabicWidth : helveticaWidth;
    return sum + segment.cps.reduce((inner, code) => inner + (measure(code) * size) / 1000, 0);
  }, 0);

const hexOf = (codes) =>
  codes
    .filter((code) => code > 0 && code < 0xfffe)
    .map((code) => code.toString(16).padStart(4, '0'))
    .join('');

const commandsFor = (lines, { x, right, y, size, leading }) => {
  const commands = [];
  let cursor = y;
  for (const line of lines) {
    if (cursor < 48) break;
    let pen = right ? right - lineWidth(line, size) : x;
    commands.push('BT');
    for (const segment of line) {
      if (!segment.cps.length) continue;
      const measure = segment.font === 'arabic' ? arabicWidth : helveticaWidth;
      if (segment.font === 'arabic') {
        const hex = hexOf(segment.cps.filter((code) => font.glyphs.has(code)));
        if (hex) {
          commands.push(
            `/F2 ${size} Tf 1 0 0 1 ${pen.toFixed(1)} ${cursor.toFixed(1)} Tm <${hex}> Tj`,
          );
        }
      } else {
        const text = String.fromCodePoint(...segment.cps.filter((code) => code < 128))
          .replaceAll('\\', '\\\\')
          .replaceAll('(', '\\(')
          .replaceAll(')', '\\)');
        commands.push(
          `/F1 ${size} Tf 1 0 0 1 ${pen.toFixed(1)} ${cursor.toFixed(1)} Tm (${text}) Tj`,
        );
      }
      pen += segment.cps.reduce((sum, code) => sum + (measure(code) * size) / 1000, 0);
    }
    commands.push('ET');
    cursor -= leading;
  }
  return { commands, y: cursor };
};

const cidMap = () => {
  const max = 0xfeff;
  const map = Buffer.alloc((max + 1) * 2);
  for (const [code, glyph] of font.glyphs) {
    if (code <= max && glyph <= 0xffff) map.writeUInt16BE(glyph, code * 2);
  }
  return map;
};

const widthsArray = () => {
  const entries = [];
  for (let code = 0x0600; code <= 0xfeff; code += 1) {
    const glyph = font.glyphs.get(code);
    if (!glyph) continue;
    entries.push(`${code} [${arabicWidth(code)}]`);
  }
  return entries.join(' ');
};

const buildPdf = (parts) => {
  const chunks = [Buffer.from('%PDF-1.4\n')];
  const offsets = [0];
  let pos = chunks[0].length;
  parts.forEach((body, index) => {
    offsets.push(pos);
    const wrapped = Buffer.concat([
      Buffer.from(`${index + 1} 0 obj\n`),
      body,
      Buffer.from('\nendobj\n'),
    ]);
    chunks.push(wrapped);
    pos += wrapped.length;
  });
  let xref = `xref\n0 ${parts.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i += 1) {
    xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  chunks.push(
    Buffer.from(
      `${xref}trailer << /Size ${parts.length + 1} /Root 1 0 R >>\nstartxref\n${pos}\n%%EOF`,
    ),
  );
  return Buffer.concat(chunks);
};

const stream = (body) => {
  const data = Buffer.isBuffer(body) ? body : Buffer.from(body);
  return Buffer.concat([
    Buffer.from(`<< /Length ${data.length} >>\nstream\n`),
    data,
    Buffer.from('\nendstream'),
  ]);
};

export const renderExecutivePdf = (report) => {
  const size = 11;
  const english = [
    'Cormorant Cyber | UAE Readiness Scan',
    `${report.target?.hostname || ''}    score ${report.score?.value ?? 'n/a'} (${report.score?.bandEn || 'not scored'})`,
    `Status: ${report.release?.status || 'draft'}    Currency: AED`,
    'Arabic needs native review before this report is sent.',
    report.summary?.en || '',
    'Top fixes, highest impact for the effort:',
    ...(report.prioritisedFixes || [])
      .slice(0, 3)
      .map(
        (item, index) =>
          `${index + 1}. [${item.severity}] impact ${item.impact} / effort ${item.effort}: ${item.title}. ${item.remediation}`,
      ),
    'Reference only. Not a penetration test and not a certification.',
  ];
  const arabic = [
    'فحص الجاهزية للإمارات',
    'النص العربي يحتاج مراجعة لغوية قبل التسليم.',
    report.summary?.ar || '',
    ...(report.prioritisedFixes || []).slice(0, 3).map((item) => item.titleAr || ''),
  ];
  const left = english.flatMap((line) =>
    wrapSegments(
      [{ font: 'helvetica', cps: [...line].map((char) => char.codePointAt(0)) }],
      250,
      size,
    ),
  );
  const right = arabic.flatMap((line) => wrapSegments(visualSegments(line), 250, size));
  const drawn = [
    ...commandsFor(left, { x: 40, y: 740, size, leading: 15 }).commands,
    ...commandsFor(right, { right: 572, y: 740, size, leading: 16 }).commands,
  ].join('\n');
  const map = cidMap();
  const fontStream = Buffer.concat([
    Buffer.from(`<< /Length ${font.data.length} /Length1 ${font.data.length} >>\nstream\n`),
    font.data,
    Buffer.from('\nendstream'),
  ]);
  const objects = [
    Buffer.from('<< /Type /Catalog /Pages 2 0 R >>'),
    Buffer.from('<< /Type /Pages /Count 1 /Kids [3 0 R] >>'),
    Buffer.from(
      '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>',
    ),
    stream(drawn),
    Buffer.from('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'),
    Buffer.from(
      '<< /Type /Font /Subtype /Type0 /BaseFont /NotoNaskhArabic /Encoding /Identity-H /DescendantFonts [7 0 R] >>',
    ),
    Buffer.from(
      `<< /Type /Font /Subtype /CIDFontType2 /BaseFont /NotoNaskhArabic /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 8 0 R /CIDToGIDMap 9 0 R /W [${widthsArray()}] >>`,
    ),
    Buffer.from(
      '<< /Type /FontDescriptor /FontName /NotoNaskhArabic /Flags 4 /FontBBox [-200 -400 1400 1100] /ItalicAngle 0 /Ascent 1100 /Descent -400 /CapHeight 700 /StemV 80 /FontFile2 10 0 R >>',
    ),
    stream(map),
    fontStream,
  ];
  return buildPdf(objects);
};
