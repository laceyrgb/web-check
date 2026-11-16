// Presentation forms for the Arabic letters we shape. Isolated, final, initial, medial.
// Letters with two forms join only to the previous letter. This is shaping, not a translation.
const FORMS = {
  0x0621: [0xfe80],
  0x0622: [0xfe81, 0xfe82],
  0x0623: [0xfe83, 0xfe84],
  0x0624: [0xfe85, 0xfe86],
  0x0625: [0xfe87, 0xfe88],
  0x0626: [0xfe89, 0xfe8a, 0xfe8b, 0xfe8c],
  0x0627: [0xfe8d, 0xfe8e],
  0x0628: [0xfe8f, 0xfe90, 0xfe91, 0xfe92],
  0x0629: [0xfe93, 0xfe94],
  0x062a: [0xfe95, 0xfe96, 0xfe97, 0xfe98],
  0x062b: [0xfe99, 0xfe9a, 0xfe9b, 0xfe9c],
  0x062c: [0xfe9d, 0xfe9e, 0xfe9f, 0xfea0],
  0x062d: [0xfea1, 0xfea2, 0xfea3, 0xfea4],
  0x062e: [0xfea5, 0xfea6, 0xfea7, 0xfea8],
  0x062f: [0xfea9, 0xfeaa],
  0x0630: [0xfeab, 0xfeac],
  0x0631: [0xfead, 0xfeae],
  0x0632: [0xfeaf, 0xfeb0],
  0x0633: [0xfeb1, 0xfeb2, 0xfeb3, 0xfeb4],
  0x0634: [0xfeb5, 0xfeb6, 0xfeb7, 0xfeb8],
  0x0635: [0xfeb9, 0xfeba, 0xfebb, 0xfebc],
  0x0636: [0xfebd, 0xfebe, 0xfebf, 0xfec0],
  0x0637: [0xfec1, 0xfec2, 0xfec3, 0xfec4],
  0x0638: [0xfec5, 0xfec6, 0xfec7, 0xfec8],
  0x0639: [0xfec9, 0xfeca, 0xfecb, 0xfecc],
  0x063a: [0xfecd, 0xfece, 0xfecf, 0xfed0],
  0x0641: [0xfed1, 0xfed2, 0xfed3, 0xfed4],
  0x0642: [0xfed5, 0xfed6, 0xfed7, 0xfed8],
  0x0643: [0xfed9, 0xfeda, 0xfedb, 0xfedc],
  0x0644: [0xfedd, 0xfede, 0xfedf, 0xfee0],
  0x0645: [0xfee1, 0xfee2, 0xfee3, 0xfee4],
  0x0646: [0xfee5, 0xfee6, 0xfee7, 0xfee8],
  0x0647: [0xfee9, 0xfeea, 0xfeeb, 0xfeec],
  0x0648: [0xfeed, 0xfeee],
  0x0649: [0xfeef, 0xfef0],
  0x064a: [0xfef1, 0xfef2, 0xfef3, 0xfef4],
};

const LAM_ALEF = {
  0x0622: [0xfef5, 0xfef6],
  0x0623: [0xfef7, 0xfef8],
  0x0625: [0xfef9, 0xfefa],
  0x0627: [0xfefb, 0xfefc],
};

const MARK = (cp) => cp >= 0x064b && cp <= 0x0652;

const joinsForward = (cp) => (FORMS[cp] || []).length === 4;
const joinsBackward = (cp) => (FORMS[cp] || []).length >= 2;

const neighbour = (cps, index, step) => {
  for (let i = index + step; i >= 0 && i < cps.length; i += step) {
    if (MARK(cps[i])) continue;
    return cps[i];
  }
  return 0;
};

export const shapeArabic = (text) => {
  const cps = [...String(text)].map((char) => char.codePointAt(0));
  const out = [];
  for (let i = 0; i < cps.length; i += 1) {
    const cp = cps[i];
    const ligature = LAM_ALEF[cps[i + 1]];
    if (cp === 0x0644 && ligature) {
      const prev = neighbour(cps, i, -1);
      out.push(joinsForward(prev) ? ligature[1] : ligature[0]);
      i += 1;
      continue;
    }
    const forms = FORMS[cp];
    if (!forms) {
      out.push(cp);
      continue;
    }
    const prev = neighbour(cps, i, -1);
    const next = neighbour(cps, i, 1);
    const fromPrev = joinsForward(prev);
    const toNext = joinsForward(cp) && joinsBackward(next);
    let index = 0;
    if (fromPrev && toNext) index = 3;
    else if (fromPrev) index = 1;
    else if (toNext) index = 2;
    out.push(forms[Math.min(index, forms.length - 1)]);
  }
  return out;
};

const isArabic = (cp) => FORMS[cp] || MARK(cp) || (cp >= 0x060c && cp <= 0x061f);

// Visual order for a PDF that draws left to right. Arabic words are shaped, then
// the line is reversed so the first Arabic word sits on the right.
export const visualSegments = (line) => {
  const tokens = [];
  let kind = '';
  let text = '';
  const push = () => {
    if (text) tokens.push({ kind, text });
    text = '';
  };
  for (const char of String(line)) {
    const cp = char.codePointAt(0);
    const next = char === ' ' ? 'space' : isArabic(cp) ? 'ar' : 'ltr';
    if (kind && next !== kind) push();
    kind = next;
    text += char;
  }
  push();
  const rtl = tokens.some((token) => token.kind === 'ar');
  const ordered = rtl ? [...tokens].reverse() : tokens;
  const segments = [];
  for (const token of ordered) {
    if (token.kind === 'ar') {
      segments.push({ font: 'arabic', cps: [...shapeArabic(token.text)].reverse() });
    } else {
      segments.push({
        font: 'helvetica',
        cps: [...token.text].map((char) => char.codePointAt(0)),
      });
    }
  }
  return segments;
};
