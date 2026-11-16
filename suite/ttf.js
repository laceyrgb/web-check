import { readFileSync } from 'node:fs';

const u16 = (data, offset) => data.readUInt16BE(offset);
const u32 = (data, offset) => data.readUInt32BE(offset);
const i16 = (data, offset) => data.readInt16BE(offset);

const tablesOf = (data) => {
  const count = u16(data, 4);
  const tables = new Map();
  for (let i = 0; i < count; i += 1) {
    const at = 12 + i * 16;
    tables.set(data.toString('latin1', at, at + 4), {
      offset: u32(data, at + 8),
      length: u32(data, at + 12),
    });
  }
  return tables;
};

const cmapFormat4 = (data, start) => {
  const segCount = u16(data, start + 6) / 2;
  const endAt = start + 14;
  const startAt = endAt + segCount * 2 + 2;
  const deltaAt = startAt + segCount * 2;
  const offsetAt = deltaAt + segCount * 2;
  const map = new Map();
  for (let i = 0; i < segCount; i += 1) {
    const end = u16(data, endAt + i * 2);
    const startCode = u16(data, startAt + i * 2);
    const delta = i16(data, deltaAt + i * 2);
    const rangeOffset = u16(data, offsetAt + i * 2);
    for (let code = startCode; code <= end && code < 0xfffe; code += 1) {
      let glyph = 0;
      if (rangeOffset === 0) glyph = (code + delta) & 0xffff;
      else {
        const pos = offsetAt + i * 2 + rangeOffset + (code - startCode) * 2;
        glyph = u16(data, pos);
        if (glyph !== 0) glyph = (glyph + delta) & 0xffff;
      }
      if (glyph) map.set(code, glyph);
    }
  }
  return map;
};

export const readTrueType = (file) => {
  const data = Buffer.isBuffer(file) ? file : readFileSync(file);
  const tables = tablesOf(data);
  const cmap = tables.get('cmap');
  const subCount = u16(data, cmap.offset + 2);
  let format4 = 0;
  for (let i = 0; i < subCount; i += 1) {
    const at = cmap.offset + 4 + i * 8;
    const platform = u16(data, at);
    const encoding = u16(data, at + 2);
    const sub = cmap.offset + u32(data, at + 4);
    if (platform === 3 && encoding === 1 && u16(data, sub) === 4) format4 = sub;
  }
  if (!format4) throw new Error('Arabic font has no Windows cmap');
  const glyphs = cmapFormat4(data, format4);
  const head = tables.get('head').offset;
  const hhea = tables.get('hhea').offset;
  const unitsPerEm = u16(data, head + 18);
  const metrics = u16(data, hhea + 34);
  const hmtx = tables.get('hmtx').offset;
  const advance = (glyph) => {
    if (glyph < metrics) return u16(data, hmtx + glyph * 4);
    return u16(data, hmtx + (metrics - 1) * 4);
  };
  return { data, glyphs, unitsPerEm, advance };
};
