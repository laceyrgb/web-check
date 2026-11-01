// Enough of the public suffix list to find the organisational domain for DMARC and CT filtering.
const MULTI_LABEL = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'co.ae',
  'ac.ae',
  'gov.ae',
  'org.ae',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'com.br',
  'co.jp',
  'com.sa',
  'gov.sa',
]);

export const registrableDomain = (hostname) => {
  const labels = String(hostname || '')
    .toLowerCase()
    .replace(/\.$/, '')
    .split('.')
    .filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tail2 = labels.slice(-2).join('.');
  if (MULTI_LABEL.has(tail2)) return labels.slice(-3).join('.');
  return tail2;
};

export const endsWithName = (host, suffix) => {
  const name = String(host || '')
    .toLowerCase()
    .replace(/\.$/, '');
  const tail = String(suffix || '').toLowerCase();
  return name === tail || name.endsWith(`.${tail}`);
};
