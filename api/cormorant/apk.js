import zlib from 'zlib';
import { cardFields, previewSecret } from './util.js';

export const readZip = (buffer) => {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  let eocd = -1;
  const start = Math.max(0, buf.length - 66_000);
  for (let i = buf.length - 22; i >= start; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('File is not a zip or APK archive');
  const count = buf.readUInt16LE(eocd + 10);
  let ptr = buf.readUInt32LE(eocd + 16);
  const files = [];
  for (let n = 0; n < count && files.length < 250; n += 1) {
    if (ptr + 46 > buf.length || buf.readUInt32LE(ptr) !== 0x02014b50) break;
    const method = buf.readUInt16LE(ptr + 10);
    const compSize = buf.readUInt32LE(ptr + 20);
    const nameLen = buf.readUInt16LE(ptr + 28);
    const extraLen = buf.readUInt16LE(ptr + 30);
    const commentLen = buf.readUInt16LE(ptr + 32);
    const localOff = buf.readUInt32LE(ptr + 42);
    const name = buf.slice(ptr + 46, ptr + 46 + nameLen).toString('utf8');
    ptr += 46 + nameLen + extraLen + commentLen;
    if (!name || name.endsWith('/')) continue;
    if (localOff + 30 > buf.length) continue;
    const localName = buf.readUInt16LE(localOff + 26);
    const localExtra = buf.readUInt16LE(localOff + 28);
    const dataOff = localOff + 30 + localName + localExtra;
    const compressed = buf.slice(dataOff, dataOff + compSize);
    if (compressed.length !== compSize) continue;
    let data;
    try {
      if (method === 0) data = compressed;
      else if (method === 8) data = zlib.inflateRawSync(compressed);
      else continue;
    } catch {
      continue;
    }
    if (data.length > 1_500_000) continue;
    files.push({ name, data });
  }
  return files;
};

const SECRET_RULES = [
  { type: 'aws-access-key', re: /AKIA[0-9A-Z]{16}/g },
  { type: 'google-api-key', re: /AIza[0-9A-Za-z\-_]{35}/g },
  { type: 'stripe-live-key', re: /sk_live_[0-9a-zA-Z]{16,}/g },
  { type: 'slack-token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { type: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
];

const TEXT_FILE = /\.(xml|json|txt|properties|js|env|config|html|yml|yaml)$/i;

export const analyzeApkFiles = (files) => {
  const permissions = new Set();
  const components = [];
  const secrets = [];
  const seenSecrets = new Set();
  for (const file of files) {
    const text = file.data.toString('latin1');
    for (const match of text.match(/android\.permission\.[A-Za-z0-9_.]+/g) || []) permissions.add(match);
    if (file.name === 'AndroidManifest.xml' && text.includes('<manifest')) {
      const pattern = /<(activity|service|receiver|provider)\b([^>]*?)>/gi;
      let item = pattern.exec(text);
      while (item) {
        const attrs = item[2];
        if (/android:exported="true"/i.test(attrs)) {
          components.push({
            kind: item[1],
            name: /android:name="([^"]+)"/i.exec(attrs)?.[1] || null,
            exported: true,
          });
        }
        item = pattern.exec(text);
      }
    }
    const rules = TEXT_FILE.test(file.name) ? SECRET_RULES.concat([{
      type: 'assigned-secret',
      re: /(?:api[_-]?key|secret|password)\s*[:=]\s*['"]([^'"]{8,80})['"]/gi,
    }]) : SECRET_RULES;
    for (const rule of rules) {
      for (const match of text.matchAll(rule.re)) {
        const raw = match[1] && rule.type === 'assigned-secret' ? match[1] : match[0];
        const fingerprint = `${rule.type}:${raw}`;
        if (seenSecrets.has(fingerprint)) continue;
        seenSecrets.add(fingerprint);
        secrets.push({ type: rule.type, file: file.name, preview: previewSecret(raw) });
      }
    }
  }
  return {
    permissions: [...permissions].sort(),
    exportedComponents: components,
    secrets,
    note: 'Static strings only. The APK was not installed or executed. Secret values are redacted.',
  };
};

export const inspectApkBuffer = (buffer) => {
  const files = readZip(buffer);
  const analysis = analyzeApkFiles(files);
  return {
    files: files.map((file) => file.name).slice(0, 80),
    ...analysis,
    ...cardFields(
      [`${analysis.permissions.length} permissions`, `${analysis.secrets.length} possible hardcoded secrets`, `${analysis.exportedComponents.length} exported components decoded from text XML`],
      analysis.permissions.slice(0, 20).map((item) => ({ label: 'permission', value: item })),
      analysis.note,
    ),
  };
};

export const inspectStoreUrl = async (url, deps = {}) => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    const error = new Error('Store URL is invalid');
    error.status = 400;
    throw error;
  }
  if (!['play.google.com', 'apps.apple.com'].includes(parsed.hostname)) {
    const error = new Error('Only public Google Play or Apple App Store URLs are accepted');
    error.status = 400;
    throw error;
  }
  const http = deps.httpGet || (await import('../_common/http.js')).httpGet;
  const response = await http(url, { timeout: 12000, validateStatus: () => true });
  const html = typeof response.data === 'string' ? response.data : '';
  const title = /<title>([^<]+)<\/title>/i.exec(html)?.[1]?.trim() || null;
  return {
    url,
    title,
    status: response.status,
    permissions: [],
    note: 'The public store page was fetched anonymously. Permission lists are usually not in that HTML. Upload an APK for a static review.',
  };
};
