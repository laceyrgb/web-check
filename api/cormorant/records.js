import dns from 'dns/promises';
import net from 'net';
import zlib from 'zlib';
import { APP_UA, httpGet } from '../_common/http.js';
import { assertPublicTarget, canonicalHost, cardFields, domainOf } from './util.js';
import { extractEmails, fetchPage, targetUrl } from './hosts.js';

const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'zoho'];
const MAX_DOCUMENT_BYTES = 1_500_000;
const DAY = 24 * 60 * 60 * 1000;

const asText = (value) =>
  String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);

const normalizeTxt = (value) => {
  if (Array.isArray(value)) return { records: value.map(String), error: null };
  if (!value) return { records: [], error: null };
  return { records: (value.records || []).map(String), error: value.error || null };
};

const readTxt = async (name, deps) => {
  if (deps.resolveTxt) return normalizeTxt(await deps.resolveTxt(name));
  try {
    const rows = await dns.resolveTxt(name);
    return { records: rows.map((parts) => parts.join('')), error: null };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') return { records: [], error: null };
    return { records: [], error: error.code || error.message };
  }
};

const tag = (record, name) => {
  const match = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;]+)`, 'i').exec(record);
  return match ? match[1].trim() : null;
};

export const parseSpf = (records) => {
  const record = (records || []).find((row) => /^v=spf1\b/i.test(row));
  if (!record) return null;
  const trimmed = record.slice(0, 300);
  let qualifier = 'other';
  if (/\+all\b/i.test(trimmed)) qualifier = 'pass';
  else if (/-all\b/i.test(trimmed)) qualifier = 'fail';
  else if (/~all\b/i.test(trimmed)) qualifier = 'softfail';
  else if (/\?all\b/i.test(trimmed)) qualifier = 'neutral';
  return { record: trimmed, qualifier };
};

export const parseDmarc = (records) => {
  const record = (records || []).find((row) => /^v=DMARC1\b/i.test(row));
  if (!record) return null;
  const policy = (tag(record, 'p') || '').toLowerCase();
  const pct = tag(record, 'pct');
  return {
    record: record.slice(0, 300),
    policy: ['none', 'quarantine', 'reject'].includes(policy) ? policy : 'unknown',
    pct: pct == null || pct === '' ? 100 : Number(pct),
    rua: tag(record, 'rua'),
  };
};

const mailFindings = (mail) => {
  const findings = [];
  if (!mail.spfError && !mail.spf)
    findings.push({
      source: 'mail',
      points: 8,
      detail: 'No SPF TXT record was published',
      action: 'Publish an SPF TXT record that does not use +all.',
    });
  else if (!mail.spfError && mail.spf?.qualifier === 'pass')
    findings.push({
      source: 'mail',
      points: 12,
      detail: 'SPF uses +all, so any host is authorized',
      action: 'Replace +all with ~all or -all.',
    });
  if (mail.dmarcError) return findings;
  if (!mail.dmarc)
    findings.push({
      source: 'mail',
      points: 10,
      detail: 'No DMARC record was published',
      action: 'Publish a DMARC record at _dmarc with p=quarantine or p=reject.',
    });
  else if (mail.dmarc.policy === 'none')
    findings.push({
      source: 'mail',
      points: 8,
      detail: 'DMARC policy is none',
      action: 'Move DMARC from p=none to p=quarantine or p=reject.',
    });
  else if (
    ['quarantine', 'reject'].includes(mail.dmarc.policy) &&
    Number.isFinite(mail.dmarc.pct) &&
    mail.dmarc.pct < 100
  )
    findings.push({
      source: 'mail',
      points: 4,
      detail: `DMARC pct is ${mail.dmarc.pct}`,
      action: 'Raise the DMARC pct to 100 once the reports look clean.',
    });
  return findings;
};

const readMail = async (domain, deps) => {
  const [apex, dmarcTxt, tlsRptTxt, bimiTxt, mtaTxt, ...dkimTxt] = await Promise.all([
    readTxt(domain, deps),
    readTxt(`_dmarc.${domain}`, deps),
    readTxt(`_smtp._tls.${domain}`, deps),
    readTxt(`default._bimi.${domain}`, deps),
    readTxt(`_mta-sts.${domain}`, deps),
    ...DKIM_SELECTORS.map((selector) => readTxt(`${selector}._domainkey.${domain}`, deps)),
  ]);
  const spf = parseSpf(apex.records);
  const dmarc = parseDmarc(dmarcTxt.records);
  const dkim = DKIM_SELECTORS.map((selector, index) => {
    const record = dkimTxt[index].records.find(
      (row) => /v=DKIM1\b/i.test(row) || /\bp=/i.test(row),
    );
    if (!record) return null;
    const revoked = /(?:^|;)\s*p=\s*(?:;|$)/i.test(record);
    return { selector, published: !revoked, revoked };
  }).filter(Boolean);
  const tlsRpt = tlsRptTxt.records.find((row) => /^v=TLSRPTv1\b/i.test(row)) || null;
  const bimi = bimiTxt.records.find((row) => /^v=BIMI1\b/i.test(row)) || null;
  const mtaId = mtaTxt.records.find((row) => /^v=STSv1\b/i.test(row)) || null;
  let mtaSts = { published: false, mode: null };
  if (mtaId) {
    const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    try {
      const http = deps.httpGet || httpGet;
      const response = await http(policyUrl, { timeout: 6000, validateStatus: () => true });
      const body = typeof response.data === 'string' ? response.data.slice(0, 2000) : '';
      mtaSts = {
        published: true,
        mode: /^mode:\s*(enforce|testing|none)/im.exec(body)?.[1] || null,
        policyUrl,
      };
    } catch {
      mtaSts = { published: true, mode: null, policyUrl, error: 'policy fetch failed' };
    }
  }
  const mail = {
    spf,
    spfError: apex.error,
    dmarc,
    dmarcError: dmarcTxt.error,
    dkim,
    tlsRpt: tlsRpt ? { published: true } : { published: false },
    bimi: bimi ? { published: true } : { published: false },
    mtaSts,
    dkimNote:
      'DKIM was checked only for the published provider selectors google, selector1, selector2, k1, and zoho. A missing row is not proof that DKIM is absent.',
  };
  mail.findings = mailFindings(mail);
  const notes = [];
  if (!mtaSts.published) notes.push('MTA-STS was not published.');
  if (!tlsRpt) notes.push('TLS-RPT was not published.');
  if (!bimi) notes.push('BIMI was not published.');
  mail.notes = notes;
  return mail;
};

const decodeUtf16be = (bytes) => {
  const swapped = Buffer.alloc(bytes.length - (bytes.length % 2));
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    swapped[i] = bytes[i + 1];
    swapped[i + 1] = bytes[i];
  }
  return swapped
    .toString('utf16le')
    .replace(/\u0000/g, '')
    .trim();
};

const decodePdfLiteral = (raw) => {
  let out = '';
  for (let i = 0; i < raw.length; i += 1) {
    if (raw[i] !== '\\') {
      out += raw[i];
      continue;
    }
    const next = raw[i + 1];
    if (next === 'n') out += '\n';
    else if (next === 'r') out += '\r';
    else if (next === 't') out += '\t';
    else if (next === '(' || next === ')' || next === '\\') out += next;
    else {
      const octal = /^[0-7]{1,3}/.exec(raw.slice(i + 1));
      if (octal) {
        out += String.fromCharCode(Number.parseInt(octal[0], 8));
        i += octal[0].length;
        continue;
      }
      out += next || '';
    }
    i += 1;
  }
  if (out.charCodeAt(0) === 0xfe && out.charCodeAt(1) === 0xff)
    return decodeUtf16be(Buffer.from(out.slice(2), 'latin1'));
  return out.replace(/\u0000/g, '').trim();
};

const decodePdfHex = (raw) => {
  const bytes = Buffer.from(raw.replace(/\s/g, ''), 'hex');
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff)
    return decodeUtf16be(bytes.subarray(2));
  return bytes.toString('latin1').trim();
};

export const pdfInfo = (buffer) => {
  const text = Buffer.from(buffer || '').toString('latin1');
  if (!text.startsWith('%PDF')) return null;
  const info = {};
  const pattern =
    /\/(Author|Title|Creator|Producer|CreationDate|ModDate|Subject)\s*(\((?:\\.|[^\\)]){0,500}\)|<[0-9A-Fa-f\s]{2,800}>)/g;
  for (const match of text.matchAll(pattern)) {
    const key = match[1].toLowerCase();
    const token = match[2];
    const value = token.startsWith('(')
      ? decodePdfLiteral(token.slice(1, -1))
      : decodePdfHex(token.slice(1, -1));
    if (value) info[key] = asText(value);
  }
  return info;
};

export const zipEntries = (buffer) => {
  const entries = [];
  let offset = 0;
  const bytes = Buffer.from(buffer || '');
  while (offset + 30 <= bytes.length && entries.length < 40) {
    if (bytes.readUInt32LE(offset) !== 0x04034b50) break;
    const flags = bytes.readUInt16LE(offset + 6);
    if (flags & 0x08) break;
    const method = bytes.readUInt16LE(offset + 8);
    const compressed = bytes.readUInt32LE(offset + 18);
    const nameLength = bytes.readUInt16LE(offset + 26);
    const extraLength = bytes.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    if (dataStart + compressed > bytes.length) break;
    entries.push({
      name: bytes.subarray(nameStart, nameStart + nameLength).toString('utf8'),
      method,
      data: bytes.subarray(dataStart, dataStart + compressed),
    });
    offset = dataStart + compressed;
  }
  return entries;
};

const xmlValue = (xml, names) => {
  for (const name of names) {
    const match = new RegExp(`<(?:[A-Za-z0-9]+:)?${name}[^>]*>([^<]{1,300})</`, 'i').exec(xml);
    if (match)
      return asText(
        match[1]
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&quot;/g, '"'),
      );
  }
  return null;
};

const entryText = (entry) => {
  try {
    if (entry.method === 0) return entry.data.toString('utf8');
    if (entry.method === 8)
      return zlib.inflateRawSync(entry.data).subarray(0, 200_000).toString('utf8');
  } catch {
    return '';
  }
  return '';
};

export const docxInfo = (buffer) => {
  const bytes = Buffer.from(buffer || '');
  if (bytes.length < 4 || bytes.readUInt32LE(0) !== 0x04034b50) return null;
  const entries = zipEntries(bytes);
  const core = entries.find((entry) =>
    entry.name.replace(/\\/g, '/').endsWith('docProps/core.xml'),
  );
  const app = entries.find((entry) => entry.name.replace(/\\/g, '/').endsWith('docProps/app.xml'));
  if (!core && !app) return null;
  const coreXml = core ? entryText(core) : '';
  const appXml = app ? entryText(app) : '';
  return {
    title: xmlValue(coreXml, ['title']),
    author: xmlValue(coreXml, ['creator']),
    modifiedBy: xmlValue(coreXml, ['lastModifiedBy']),
    application: xmlValue(appXml, ['Application']),
    company: xmlValue(appXml, ['Company']),
  };
};

const PATH_RE = /(?:[A-Za-z]:\\Users\\[^\\/\s)]+|\/Users\/[A-Za-z0-9._-]+)/g;

const describeFile = (info, domain) => {
  if (!info) return null;
  const blob = Object.values(info).filter(Boolean).join('\n');
  const paths = [...new Set(blob.match(PATH_RE) || [])].slice(0, 5);
  const hostPattern = new RegExp(
    `\\b(?:[a-z0-9-]+\\.)+${String(domain).replace(/\./g, '\\.')}\\b`,
    'gi',
  );
  const hosts = [
    ...new Set((blob.match(hostPattern) || []).map((item) => item.toLowerCase())),
  ].slice(0, 8);
  return {
    title: info.title || null,
    author: info.author || null,
    creator: info.creator || info.application || null,
    producer: info.producer || null,
    company: info.company || null,
    created: info.creationdate || null,
    paths,
    hosts,
    emails: extractEmails(blob, domain),
  };
};

export const linkedDocuments = (html, pageUrl, domain) => {
  const found = [];
  for (const match of String(html || '').matchAll(/(?:href|src)=["']([^"']+)["']/gi)) {
    let absolute;
    try {
      absolute = new URL(match[1], pageUrl);
    } catch {
      continue;
    }
    if (absolute.protocol !== 'https:' && absolute.protocol !== 'http:') continue;
    const pathName = absolute.pathname.toLowerCase();
    if (!pathName.endsWith('.pdf') && !pathName.endsWith('.docx')) continue;
    try {
      if (domainOf(absolute.hostname) !== domain) continue;
    } catch {
      continue;
    }
    absolute.hash = '';
    found.push(absolute.href);
    if (found.length >= 3) break;
  }
  return [...new Set(found)];
};

const readStream = async (response) => {
  const chunks = [];
  let total = 0;
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  while (total < MAX_DOCUMENT_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    chunks.push(Buffer.from(value));
  }
  await reader.cancel().catch(() => {});
  return Buffer.concat(chunks).subarray(0, MAX_DOCUMENT_BYTES);
};

const fetchBytes = async (start, domain, deps) => {
  if (deps.fetchBytes) return deps.fetchBytes(start);
  let current = start;
  for (let hop = 0; hop < 3; hop += 1) {
    const host = canonicalHost(current);
    assertPublicTarget(host);
    if (domainOf(host) !== domain)
      return { status: 0, data: Buffer.alloc(0), skipped: 'off-domain' };
    const response = await fetch(current, {
      signal: AbortSignal.timeout(deps.timeout || 8000),
      redirect: 'manual',
      headers: { 'user-agent': APP_UA },
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const next = response.headers.get('location');
      if (!next) return { status: response.status, data: Buffer.alloc(0) };
      current = new URL(next, current).href;
      continue;
    }
    return { status: response.status, data: await readStream(response), finalUrl: current };
  }
  return { status: 0, data: Buffer.alloc(0), skipped: 'redirects' };
};

const readDocuments = async (html, pageUrl, domain, deps) => {
  const documents = [];
  for (const url of linkedDocuments(html, pageUrl, domain)) {
    try {
      const response = await fetchBytes(url, domain, deps);
      if (response.skipped || response.status !== 200) continue;
      const pathName = new URL(url).pathname.toLowerCase();
      const info = pathName.endsWith('.docx') ? docxInfo(response.data) : pdfInfo(response.data);
      const described = describeFile(
        pathName.endsWith('.docx')
          ? info
          : info && {
              title: info.title,
              author: info.author,
              creator: info.creator,
              producer: info.producer,
              creationdate: info.creationdate,
            },
        domain,
      );
      if (!described) continue;
      const useful =
        described.author ||
        described.title ||
        described.creator ||
        described.producer ||
        described.company ||
        described.paths.length ||
        described.hosts.length ||
        described.emails.length;
      if (!useful) continue;
      documents.push({ url, kind: pathName.endsWith('.docx') ? 'docx' : 'pdf', ...described });
    } catch {
      continue;
    }
  }
  return documents;
};

const parseWhen = (value) => {
  const text = String(value || '').trim();
  if (!text) return null;
  const iso = /[zZ]|[+-]\d{2}:?\d{2}$/.test(text) ? text : `${text}Z`;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
};

const issuerOf = (value) => {
  const text = String(value || '');
  const quoted = /(?:^|,\s*)O="([^"]+)"/.exec(text);
  if (quoted) return asText(quoted[1]);
  const org = /(?:^|,\s*)O=([^,]+)/.exec(text);
  if (org) return asText(org[1]);
  const cn = /(?:^|,\s*)CN=([^,]+)/.exec(text);
  return cn ? asText(cn[1]) : asText(text);
};

export const summarizeCertificates = (rows, domain, now = Date.now()) => {
  const names = new Set();
  const issuers = new Map();
  const expiring = [];
  const seenExpiry = new Set();
  let newest = null;
  for (const row of (rows || []).slice(0, 80)) {
    const issued = parseWhen(row.not_before);
    const expires = parseWhen(row.not_after);
    const issuer = issuerOf(row.issuer_name || row.issuer_ca_name);
    if (issuer) issuers.set(issuer, (issuers.get(issuer) || 0) + 1);
    const rawNames = String(row.name_value || row.common_name || '').split(/\n+/);
    const certNames = [];
    for (const name of rawNames) {
      const raw = name.trim().toLowerCase();
      const host = raw.replace(/^\*\./, '');
      if (!host || (host !== domain && !host.endsWith(`.${domain}`))) continue;
      certNames.push(raw);
      if (host !== domain) names.add(host);
    }
    if (issued != null && (!newest || issued > newest.issued))
      newest = {
        issued,
        notBefore: new Date(issued).toISOString(),
        issuer,
        names: certNames.slice(0, 8),
      };
    if (expires != null && expires > now && expires - now <= 30 * DAY) {
      const key = `${expires}|${[...certNames].sort().join(',')}`;
      if (seenExpiry.has(key)) continue;
      seenExpiry.add(key);
      expiring.push({
        names: certNames.slice(0, 8),
        notAfter: new Date(expires).toISOString(),
        days: Math.ceil((expires - now) / DAY),
        issuer,
      });
    }
  }
  return {
    count: Math.min((rows || []).length, 80),
    issuers: [...issuers.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 5),
    newest: newest
      ? { notBefore: newest.notBefore, issuer: newest.issuer, names: newest.names }
      : null,
    expiring: expiring.sort((left, right) => left.days - right.days).slice(0, 8),
    names: [...names].sort().slice(0, 40),
  };
};

const rowsFrom = (data) => {
  if (Array.isArray(data)) return data;
  if (typeof data !== 'string') return null;
  try {
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const readCertificates = async (domain, deps) => {
  if (deps.certificateRows) return summarizeCertificates(deps.certificateRows, domain, deps.now);
  const http = deps.httpGet || httpGet;
  let lastError = 'Certificate log returned no rows';
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await http('https://crt.sh/', {
        params: { q: `%.${domain}`, output: 'json' },
        headers: { Accept: 'application/json', 'User-Agent': APP_UA },
        timeout: deps.timeout || 8000,
        validateStatus: () => true,
      });
      const rows = rowsFrom(response.data);
      if (rows) return summarizeCertificates(rows, domain, deps.now);
      lastError = `Certificate log returned HTTP ${response.status} without a row list`;
    } catch (error) {
      lastError = error.message;
    }
  }
  return { error: lastError, names: [], expiring: [] };
};

export const collectPublicRecords = async ({ html, href, domain } = {}, deps = {}) => {
  const pageUrl = href || targetUrl(domain);
  const host = canonicalHost(pageUrl);
  assertPublicTarget(host);
  const apex = domain || domainOf(host);
  if (net.isIP(apex)) {
    return {
      domain: apex,
      mail: null,
      documents: [],
      certificates: null,
      findings: [],
      note: 'Public records are collected for domain names.',
    };
  }
  const page = html != null ? { html, url: pageUrl } : await fetchPage(pageUrl, deps);
  const [mail, certificates, documents] = await Promise.all([
    readMail(apex, deps),
    readCertificates(apex, deps),
    readDocuments(page.html || '', page.url || pageUrl, apex, deps),
  ]);
  const findings = [...(mail.findings || [])];
  if ((certificates.expiring || []).some((row) => row.days <= 14))
    findings.push({
      source: 'certificate',
      points: 6,
      detail: 'A logged certificate expires within 14 days',
      action: 'Renew the certificate that the public log shows expiring within 14 days.',
    });
  const path = documents.find((doc) => doc.paths?.length)?.paths[0];
  if (path)
    findings.push({
      source: 'document',
      points: 5,
      detail: path,
      action: 'Remove local user paths from files the site already links.',
    });
  const result = {
    domain: apex,
    mail,
    documents,
    certificates,
    findings,
    note: 'Mail policy, files already linked on the site, and the public certificate log. Document authors stay in this report and are not sent to a people-search site. DKIM uses only published provider selectors.',
  };
  return {
    ...result,
    ...cardFields(
      [
        mail.dmarc ? `DMARC p=${mail.dmarc.policy}` : 'DMARC not published',
        mail.spf ? `SPF ${mail.spf.qualifier}` : 'SPF not published',
        documents.length ? `${documents.length} published file(s)` : 'No linked PDF or DOCX',
        certificates.expiring?.length
          ? `${certificates.expiring.length} certificate(s) expire within 30 days`
          : '',
      ],
      [
        ...documents.map((doc) => ({ label: doc.kind, value: doc.author || doc.title || doc.url })),
        ...(certificates.names || [])
          .slice(0, 12)
          .map((name) => ({ label: 'certificate', value: name })),
      ],
      result.note,
    ),
  };
};
