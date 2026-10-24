import crypto from 'crypto';
import dns from 'dns/promises';
import { httpGet } from '../_common/http.js';
import { checkEmailBreaches } from './breach.js';
import { parseRss } from './mentions.js';
import { mapCloud } from './exposure.js';

const MAX_ROUNDS = 3;
const MAX_LOOKUPS = 12;
const PER_ROUND = 6;
const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
const REDACTED =
  /redact|privacy|whoisguard|withheld|not disclosed|identity protect|contact privacy|domains by proxy|data protected/i;
const HOSTER =
  /amazon|aws|cloudflare|google cloud|digitalocean|akamai|microsoft azure|ovh|hetzner|linode/i;

const MAIL_PROVIDERS = [
  [/spf\.protection\.outlook\.com/i, 'Microsoft 365'],
  [/_spf\.google\.com/i, 'Google Workspace'],
  [/spf\.mail\.yahoo\.com/i, 'Yahoo'],
  [/amazonses\.com/i, 'Amazon SES'],
  [/sendgrid\.net/i, 'SendGrid'],
  [/mailgun\.org/i, 'Mailgun'],
];

const keyOf = (kind, value) =>
  `${kind}:${String(value || '')
    .trim()
    .toLowerCase()}`;

export const isRedacted = (value) => !value || REDACTED.test(String(value));

export const normalizePhone = (value) => {
  const digits = String(value || '').replace(/\D/g, '');
  if (digits.length < 8 || digits.length > 15) return null;
  return `+${digits}`;
};

export const extractPhones = (html) => {
  const found = new Set();
  const text = String(html || '');
  for (const raw of text.match(/tel:\+?[0-9().\-\s]{8,22}/gi) || []) {
    const phone = normalizePhone(raw);
    if (phone) found.add(phone);
  }
  for (const raw of text.match(/\+\d{1,3}(?:[\s.-]?\d){7,14}/g) || []) {
    const phone = normalizePhone(raw);
    if (phone) found.add(phone);
  }
  return [...found].slice(0, 6);
};

export const extractJsonLd = (html) => {
  const rows = [];
  const blocks = String(html || '').matchAll(
    /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi,
  );
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    const type = [].concat(node['@type'] || []).join(' ');
    if (/Organization|Person|ContactPoint|LocalBusiness/i.test(type)) {
      rows.push({
        type,
        name: typeof node.name === 'string' ? node.name.trim().slice(0, 120) : null,
        email: typeof node.email === 'string' ? node.email.trim().toLowerCase() : null,
        telephone: typeof node.telephone === 'string' ? node.telephone : null,
      });
    }
    if (node.contactPoint) walk(node.contactPoint);
    if (node.founder) walk(node.founder);
    if (node['@graph']) walk(node['@graph']);
  };
  for (const block of blocks) {
    try {
      walk(JSON.parse(block[1]));
    } catch {
      // Malformed JSON-LD is skipped. The rest of the page still counts.
    }
  }
  return rows.slice(0, 8);
};

export const extractCopyrightOwner = (html) => {
  const text = String(html || '').replace(/<[^>]+>/g, ' ');
  const match =
    /(?:©|&copy;|\bcopyright\b)\s*(?:\d{4}\s*[–-]\s*\d{4}|\d{4})?\s*([A-Z][\p{L}\p{N}&.,'’ -]{2,80})/iu.exec(
      text,
    );
  if (!match) return null;
  const name = match[1]
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[.\s]+$/, '');
  if (!name || /all rights|reserved|^\d+$/i.test(name) || HOSTER.test(name)) return null;
  return name;
};

export const parseSecurityTxt = (text) => {
  const contacts = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = /^\s*Contact:\s*(\S+)/i.exec(line);
    if (!match) continue;
    const value = match[1].trim();
    if (/^mailto:/i.test(value)) {
      const email = value.slice(7).split('?')[0].toLowerCase();
      if (EMAIL_RE.test(email)) contacts.push({ kind: 'email', value: email });
    } else if (/^tel:/i.test(value)) {
      const phone = normalizePhone(value);
      if (phone) contacts.push({ kind: 'phone', value: phone });
    }
  }
  return contacts.slice(0, 8);
};

export const parseRdapEntities = (payload) => {
  const rows = [];
  const walk = (entity) => {
    if (!entity || typeof entity !== 'object') return;
    const record = { roles: entity.roles || [], name: null, org: null, email: null, phone: null };
    for (const item of entity.vcardArray?.[1] || []) {
      if (!Array.isArray(item)) continue;
      const field = item[0];
      const value = item[3];
      if (typeof value !== 'string') continue;
      if (field === 'fn') record.name = value.trim();
      if (field === 'org') record.org = value.trim();
      if (field === 'email' && EMAIL_RE.test(value)) record.email = value.trim().toLowerCase();
      if (field === 'tel') record.phone = normalizePhone(value);
    }
    rows.push(record);
    for (const child of entity.entities || []) walk(child);
  };
  for (const entity of payload?.entities || []) walk(entity);
  return rows;
};

const addFact = (facts, fact) => {
  if (!fact?.value) return false;
  const id = keyOf(fact.kind, fact.value);
  if (facts.some((row) => row.id === id)) return false;
  facts.push({ ...fact, id });
  return true;
};

export const seedFacts = ({ html = '', domain, report = {} } = {}) => {
  const facts = [];
  const checked = new Set(
    (report.breaches?.emails || []).map((row) => String(row.email || '').toLowerCase()),
  );
  for (const email of report.attackSurface?.publishedEmails || []) {
    addFact(facts, {
      kind: 'email',
      value: email,
      source: 'public page',
      official: true,
      breachChecked: checked.has(email),
      round: 0,
    });
  }
  for (const phone of extractPhones(html)) {
    addFact(facts, {
      kind: 'phone',
      value: phone,
      source: 'public page',
      official: true,
      round: 0,
    });
  }
  for (const row of extractJsonLd(html)) {
    const orgLike =
      /Organization|LocalBusiness/i.test(row.type) && row.name && !isRedacted(row.name);
    if (orgLike)
      addFact(facts, {
        kind: 'org',
        value: row.name,
        source: 'JSON-LD on the public page',
        official: true,
        round: 0,
      });
    if (/Person/i.test(row.type) && row.name && !isRedacted(row.name)) {
      addFact(facts, {
        kind: 'person',
        value: row.name,
        source: 'JSON-LD on the public page',
        official: true,
        round: 0,
      });
    }
    if (row.email && EMAIL_RE.test(row.email)) {
      const emailDomain = row.email.split('@')[1];
      const onTarget = emailDomain === domain || emailDomain.endsWith(`.${domain}`);
      addFact(facts, {
        kind: 'email',
        value: row.email,
        source: 'JSON-LD on the public page',
        official: onTarget,
        breachChecked: checked.has(row.email),
        round: 0,
      });
    }
    const phone = normalizePhone(row.telephone);
    if (phone)
      addFact(facts, {
        kind: 'phone',
        value: phone,
        source: 'JSON-LD on the public page',
        official: true,
        round: 0,
      });
  }
  const copyright = extractCopyrightOwner(html);
  if (copyright)
    addFact(facts, {
      kind: 'org',
      value: copyright,
      source: 'copyright notice on the public page',
      official: true,
      round: 0,
    });
  const certOrg = report.posture?.tls?.organization;
  if (certOrg && !isRedacted(certOrg) && !HOSTER.test(certOrg)) {
    addFact(facts, {
      kind: 'org',
      value: certOrg,
      source: 'TLS certificate subject',
      official: true,
      round: 0,
    });
  }
  for (const person of report.people?.people || []) {
    if (person.name && person.status !== 'unavailable') {
      addFact(facts, {
        kind: 'person',
        value: person.name,
        source: person.source || 'public page',
        official: true,
        round: 0,
      });
    }
  }
  return facts;
};

const mailProvider = (spf) => {
  for (const [pattern, name] of MAIL_PROVIDERS) if (pattern.test(spf)) return name;
  return null;
};

const dmarcEmails = (record) =>
  [...String(record || '').matchAll(/mailto:([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/gi)]
    .map((match) => match[1].toLowerCase())
    .filter((email) => EMAIL_RE.test(email))
    .slice(0, 3);

export const planActions = (facts, lookups, domain) => {
  const done = new Set(lookups.map((row) => row.key));
  const actions = [];
  const push = (action) => {
    const key = `${action.type}:${action.subject || ''}`;
    if (done.has(key) || actions.some((row) => `${row.type}:${row.subject || ''}` === key)) return;
    actions.push({ ...action, key });
  };
  push({ type: 'dns-mail', subject: domain });
  push({ type: 'security-txt', subject: domain });
  push({ type: 'rdap-domain', subject: domain });
  const emails = facts
    .filter((fact) => fact.kind === 'email' && fact.official && !isRedacted(fact.value))
    .slice(0, 4);
  let related = false;
  for (const email of emails) {
    if (!email.breachChecked) push({ type: 'breach', subject: email.value });
    push({ type: 'gravatar', subject: email.value });
    push({ type: 'pgp', subject: email.value });
    const host = email.value.split('@')[1];
    if (!related && host && host !== domain && !host.endsWith(`.${domain}`)) {
      push({ type: 'rdap-related', subject: host });
      related = true;
    }
  }
  const org = facts.find(
    (fact) => fact.kind === 'org' && fact.official && !HOSTER.test(fact.value),
  );
  if (org) push({ type: 'news-org', subject: org.value });
  return actions;
};

const readTxt = async (name, deps) => {
  const resolve = deps.resolveTxt || dns.resolveTxt;
  const rows = await resolve(name).catch(() => []);
  return rows.map((row) => (Array.isArray(row) ? row.join('') : String(row)));
};

const httpOk = async (http, url) => {
  const response = await http(url, {
    timeout: 8000,
    validateStatus: () => true,
    headers: { accept: 'application/json, text/plain' },
  });
  return response;
};

const runAction = async (action, { domain, host, href }, deps) => {
  const http = deps.httpGet || httpGet;
  try {
    if (action.type === 'dns-mail') {
      const txt = await readTxt(domain, deps);
      const dmarc = await readTxt(`_dmarc.${domain}`, deps);
      const spf = txt.find((row) => /^v=spf1\b/i.test(row)) || '';
      const provider = mailProvider(spf);
      const emails = dmarc.flatMap(dmarcEmails);
      const facts = [];
      if (provider)
        facts.push({ kind: 'provider', value: provider, source: 'SPF TXT', official: true });
      for (const email of emails) {
        facts.push({
          kind: 'email',
          value: email,
          source: 'DMARC rua',
          official: true,
          breachChecked: false,
        });
      }
      const trail = [
        provider ? `SPF for ${domain} points at ${provider}.` : '',
        emails.length ? `DMARC publishes ${emails.join(', ')}.` : '',
      ]
        .filter(Boolean)
        .join(' ');
      return { ...action, ok: true, facts, trail };
    }
    if (action.type === 'security-txt') {
      const urls = [`https://${host}/.well-known/security.txt`, `https://${host}/security.txt`];
      let contacts = [];
      let used = '';
      for (const url of urls) {
        const response = await httpOk(http, url);
        const body = typeof response.data === 'string' ? response.data : '';
        if (
          response.status === 200 &&
          /^\s*contact:/im.test(body) &&
          !body.trim().startsWith('<')
        ) {
          contacts = parseSecurityTxt(body);
          used = url;
          break;
        }
      }
      const facts = contacts.map((row) => ({
        kind: row.kind,
        value: row.value,
        source: used,
        official: true,
        breachChecked: false,
      }));
      const listed = contacts.map((row) => row.value).join(', ');
      return {
        ...action,
        ok: true,
        facts,
        trail: listed ? `security.txt at ${used} published ${listed}.` : '',
      };
    }
    if (action.type === 'rdap-domain' || action.type === 'rdap-related') {
      const response = await httpOk(
        http,
        `https://rdap.org/domain/${encodeURIComponent(action.subject)}`,
      );
      if (response.status >= 400) throw new Error(`RDAP HTTP ${response.status}`);
      const entities = parseRdapEntities(response.data);
      const facts = [];
      for (const entity of entities) {
        if (action.type === 'rdap-domain') {
          if (entity.org && !isRedacted(entity.org))
            facts.push({ kind: 'org', value: entity.org, source: 'domain RDAP', official: true });
          if (entity.name && !isRedacted(entity.name) && entity.name !== entity.org) {
            facts.push({
              kind: 'person',
              value: entity.name,
              source: 'domain RDAP',
              official: true,
            });
          }
          if (entity.email && !isRedacted(entity.email))
            facts.push({
              kind: 'email',
              value: entity.email,
              source: 'domain RDAP',
              official: true,
              breachChecked: false,
            });
          if (entity.phone)
            facts.push({
              kind: 'phone',
              value: entity.phone,
              source: 'domain RDAP',
              official: true,
            });
        } else if (entity.org && !isRedacted(entity.org) && !HOSTER.test(entity.org)) {
          facts.push({
            kind: 'org',
            value: entity.org,
            source: `RDAP for contact domain ${action.subject}`,
            official: true,
          });
        }
      }
      const org = facts.find((fact) => fact.kind === 'org');
      const email = facts.find((fact) => fact.kind === 'email');
      const trail =
        action.type === 'rdap-related'
          ? `Contact address is on ${action.subject}. ${org ? `RDAP there names ${org.value}.` : 'RDAP returned no organization name.'} No scan of that domain was started.`
          : [
              org ? `Domain RDAP lists ${org.value}.` : '',
              email ? `Domain RDAP publishes ${email.value}.` : '',
            ]
              .filter(Boolean)
              .join(' ');
      return { ...action, ok: true, facts, trail };
    }
    if (action.type === 'breach') {
      const result = await checkEmailBreaches(href, {
        ...deps,
        pageEmails: [action.subject],
        skipPageFetch: true,
        paceMs: deps.paceMs ?? 0,
      });
      const row = result.emails?.[0];
      const names = (row?.breaches || []).map((item) => item.name).filter(Boolean);
      return {
        ...action,
        ok: true,
        facts: [],
        breachRow: row || null,
        trail: names.length
          ? `${action.subject} appeared in public breach ${names.join(', ')}.`
          : `${action.subject} had no public breach record in the index that responded.`,
      };
    }
    if (action.type === 'gravatar') {
      const hash = crypto
        .createHash('md5')
        .update(action.subject.trim().toLowerCase())
        .digest('hex');
      const response = await httpOk(http, `https://www.gravatar.com/${hash}.json`);
      const entry = response.status === 200 ? response.data?.entry?.[0] : null;
      const name = typeof entry?.displayName === 'string' ? entry.displayName.trim() : '';
      const usable = name && name.length <= 80 && !EMAIL_RE.test(name) && !isRedacted(name);
      return {
        ...action,
        ok: true,
        facts: usable
          ? [
              {
                kind: 'person',
                value: name,
                source: `Gravatar for ${action.subject}`,
                official: false,
                profileUrl: entry.profileUrl || null,
              },
            ]
          : [],
        trail: usable ? `Public Gravatar profile for ${action.subject} names ${name}.` : '',
      };
    }
    if (action.type === 'pgp') {
      const response = await httpOk(
        http,
        `https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(action.subject)}`,
      );
      const published =
        response.status === 200 &&
        typeof response.data === 'string' &&
        response.data.includes('BEGIN PGP PUBLIC KEY');
      return {
        ...action,
        ok: true,
        facts: published
          ? [{ kind: 'pgp', value: action.subject, source: 'keys.openpgp.org', official: true }]
          : [],
        trail: published ? `A public OpenPGP key is published for ${action.subject}.` : '',
      };
    }
    if (action.type === 'news-org') {
      const query = `https://news.google.com/rss/search?q=${encodeURIComponent(`"${action.subject}"`)}&hl=en-US&gl=US&ceid=US:en`;
      const response = await httpOk(http, query);
      const news = parseRss(typeof response.data === 'string' ? response.data : '').slice(0, 4);
      return {
        ...action,
        ok: true,
        facts: [],
        news,
        trail: news.length
          ? `Public news for ${action.subject} returned ${news.length} titles.`
          : '',
      };
    }
  } catch (error) {
    return { ...action, ok: false, facts: [], trail: '', message: error.message };
  }
  return { ...action, ok: false, facts: [], trail: '' };
};

const corroborate = (facts, html) => {
  const text = String(html || '')
    .replace(/<[^>]+>/g, ' ')
    .toLowerCase();
  return facts.map((fact) => {
    if (fact.kind !== 'person') return fact;
    const present = text.includes(String(fact.value).toLowerCase());
    return { ...fact, onPage: present, confidence: present ? 'medium' : 'low' };
  });
};

export const buildDossier = async (
  { html = '', domain, host, href, report = {} } = {},
  deps = {},
) => {
  const facts = seedFacts({ html, domain, report });
  const lookups = [];
  const progression = [];
  const breachRows = [];
  const news = [];
  let stopped = 'no-new-identifiers';
  const phonesAtStart = facts.filter((fact) => fact.kind === 'phone').map((fact) => fact.value);
  const emailsAtStart = new Set(
    facts.filter((fact) => fact.kind === 'email').map((fact) => fact.value),
  );
  if (phonesAtStart.length && emailsAtStart.size === 0) {
    progression.push(
      `The public page published ${phonesAtStart.join(', ')} and no email. Owner records are checked next.`,
    );
  }
  for (let round = 1; round <= MAX_ROUNDS; round += 1) {
    const room = Math.min(PER_ROUND, MAX_LOOKUPS - lookups.length);
    const actions = planActions(facts, lookups, domain).slice(0, room);
    if (!actions.length) {
      stopped = lookups.length >= MAX_LOOKUPS ? 'lookup-cap' : 'no-new-identifiers';
      break;
    }
    const results = await Promise.all(
      actions.map((action) => runAction(action, { domain, host, href }, deps)),
    );
    const added = [];
    for (const result of results) {
      lookups.push({ key: result.key, type: result.type, subject: result.subject, ok: result.ok });
      for (const fact of result.facts || []) {
        if (addFact(facts, { ...fact, round })) added.push(fact);
      }
      if (result.breachRow) breachRows.push(result.breachRow);
      if (result.news?.length) news.push(...result.news);
      if (result.trail) progression.push(result.trail);
    }
    const pivots = added.filter((fact) => ['email', 'phone', 'org', 'person'].includes(fact.kind));
    if (!pivots.length) {
      stopped = 'no-new-identifiers';
      break;
    }
    if (round === MAX_ROUNDS) stopped = 'round-cap';
  }
  const people = corroborate(
    facts.filter((fact) => fact.kind === 'person'),
    html,
  );
  for (const person of people) {
    if (person.onPage && person.source?.startsWith('Gravatar')) {
      progression.push(`${person.value} from Gravatar also appears on the target page.`);
    }
  }
  const org = facts.find((fact) => fact.kind === 'org' && fact.official);
  const contacts = facts.filter((fact) => fact.kind === 'email' || fact.kind === 'phone');
  return {
    domain,
    rounds: lookups.length,
    stopped,
    progression,
    organization: org ? { name: org.value, source: org.source } : null,
    mailProvider: facts.find((fact) => fact.kind === 'provider')?.value || null,
    nameservers: report.dns?.NS || [],
    mailHosts: report.dns?.MX || [],
    hostingOrg: report.exposure?.geo?.org || report.exposure?.rdap?.name || null,
    cloud: report.exposure?.cloud || mapCloud(report.exposure?.geo?.org || ''),
    contacts: contacts.map((fact) => ({ kind: fact.kind, value: fact.value, source: fact.source })),
    people: people.map((fact) => ({
      name: fact.value,
      source: fact.source,
      confidence: fact.confidence || 'low',
      onPage: Boolean(fact.onPage),
      profileUrl: fact.profileUrl || null,
    })),
    publicKeys: facts
      .filter((fact) => fact.kind === 'pgp')
      .map((fact) => ({ email: fact.value, source: fact.source })),
    news: news.slice(0, 4),
    breachRows,
    emailsDiscovered: contacts
      .filter((fact) => fact.kind === 'email' && !emailsAtStart.has(fact.value))
      .map((fact) => fact.value),
    note: 'Each round only queries public sources for identifiers the previous round actually produced. A person name is checked against the target page and is not sent to a people-search site. An email on another domain is recorded and does not start a scan of that domain.',
  };
};
