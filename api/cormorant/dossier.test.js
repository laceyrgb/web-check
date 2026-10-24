import assert from 'node:assert/strict';
import crypto from 'crypto';
import test from 'node:test';
import {
  buildDossier,
  extractCopyrightOwner,
  extractPhones,
  isRedacted,
  parseSecurityTxt,
} from './dossier.js';
import { renderReport } from './pdf.js';
import { updateInventory } from './inventory.js';

const hash = (email) => crypto.createHash('md5').update(email).digest('hex');

test('page parsers keep phones, security.txt contacts, and a copyright owner', () => {
  assert.deepEqual(extractPhones('<a href="tel:+97141234567">call</a>'), ['+97141234567']);
  assert.deepEqual(
    parseSecurityTxt('Contact: mailto:security@example.com\nContact: https://example.com/out'),
    [{ kind: 'email', value: 'security@example.com' }],
  );
  assert.equal(extractCopyrightOwner('<p>Copyright 2024 Cormorant Cyber</p>'), 'Cormorant Cyber');
  assert.equal(isRedacted('redacted@whoisguard.example'), true);
});

test('a phone on the page leads to an email, then to a name and a breach', async () => {
  const previous = process.env.HIBP_API_KEY;
  delete process.env.HIBP_API_KEY;
  const urls = [];
  const html =
    '<p>Call us <a href="tel:+97141234567">+971 4 123 4567</a></p><p>Copyright 2024 Cormorant Cyber</p>';
  const securityHash = hash('security@example.com');
  const httpGet = async (url) => {
    urls.push(url);
    if (url.endsWith('/.well-known/security.txt')) {
      return { status: 200, data: 'Contact: mailto:security@example.com\n' };
    }
    if (url.endsWith('/security.txt')) return { status: 404, data: '' };
    if (url === 'https://rdap.org/domain/example.com') {
      return {
        status: 200,
        data: {
          entities: [
            {
              roles: ['registrant'],
              vcardArray: [
                'vcard',
                [
                  ['org', {}, 'text', 'Cormorant Cyber LLC'],
                  ['email', {}, 'text', 'redacted@whoisguard.example'],
                ],
              ],
            },
          ],
        },
      };
    }
    if (
      url.includes('xposedornot.com') &&
      decodeURIComponent(url).includes('security@example.com')
    ) {
      return { status: 200, data: { breaches: ['Adobe'] } };
    }
    if (url.includes('xposedornot.com')) return { status: 404, data: { Error: 'Not found' } };
    if (url === `https://www.gravatar.com/${securityHash}.json`) {
      return {
        status: 200,
        data: { entry: [{ displayName: 'Ada Lovelace', profileUrl: 'https://gravatar.com/ada' }] },
      };
    }
    if (url.includes('gravatar.com')) return { status: 404, data: {} };
    if (url.includes('keys.openpgp.org')) return { status: 404, data: '' };
    if (url.includes('news.google.com'))
      return {
        status: 200,
        data: '<rss><channel><item><title>Cormorant opens</title><link>https://news.example/c</link></item></channel></rss>',
      };
    return { status: 404, data: '' };
  };
  const dossier = await buildDossier(
    {
      html,
      domain: 'example.com',
      host: 'example.com',
      href: 'https://example.com',
      report: {
        attackSurface: { publishedEmails: [] },
        dns: { NS: ['ns1.example.com'], MX: ['mx.example.com'] },
      },
    },
    {
      httpGet,
      paceMs: 0,
      resolveTxt: async (name) => {
        if (name === 'example.com') return [['v=spf1 include:_spf.google.com ~all']];
        if (name === '_dmarc.example.com')
          return [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']];
        return [];
      },
    },
  );

  assert.equal(dossier.mailProvider, 'Google Workspace');
  assert.equal(dossier.organization.name, 'Cormorant Cyber');
  assert.ok(dossier.contacts.some((row) => row.value === '+97141234567'));
  assert.ok(dossier.emailsDiscovered.includes('security@example.com'));
  assert.ok(dossier.emailsDiscovered.includes('dmarc@example.com'));
  assert.equal(
    dossier.breachRows.find((row) => row.email === 'security@example.com').breaches[0].name,
    'Adobe',
  );
  assert.equal(dossier.people.find((row) => row.name === 'Ada Lovelace').onPage, false);
  assert.equal(
    dossier.contacts.some((row) => String(row.value).includes('whoisguard')),
    false,
  );
  const securityAt = dossier.progression.findIndex((line) => line.includes('security.txt'));
  const breachAt = dossier.progression.findIndex((line) =>
    line.includes('appeared in public breach Adobe'),
  );
  assert.ok(securityAt >= 0 && breachAt > securityAt);
  assert.equal(
    urls.some((url) => /ada|lovelace/i.test(url)),
    false,
  );
  assert.equal(
    urls.some((url) => url.startsWith('https://example.com/') && !url.includes('security.txt')),
    false,
  );
  assert.ok(dossier.news[0].url.includes('news.example'));
  assert.match(dossier.note, /does not start a scan/);

  const pdf = await renderReport({
    target: 'https://example.com',
    scannedAt: '2026-10-24T00:00:00.000Z',
    executiveSummary: ['Observed only.'],
    dossier,
  });
  const text = [...pdf.toString('latin1').matchAll(/<([0-9A-Fa-f]+)>/g)]
    .map((match) => Buffer.from(match[1], 'hex').toString('latin1'))
    .join('');
  assert.match(text, /Owner dossier/);
  assert.match(text, /security@example.com/);
  assert.match(text, /Cormorant Cyber/);

  const assets = updateInventory(
    null,
    {
      target: 'https://example.com',
      dossier,
      attackSurface: { hosts: [], technologies: [], ports: { open: [] } },
    },
    '2026-10-24T00:00:00.000Z',
  );
  assert.ok(assets.items['email:security@example.com']);
  assert.ok(assets.items['phone:+97141234567']);
  assert.equal(assets.items['org:cormorant cyber'].value, 'Cormorant Cyber');
  if (previous === undefined) delete process.env.HIBP_API_KEY;
  else process.env.HIBP_API_KEY = previous;
});

test('an email on another domain is looked up once and does not start a scan', async () => {
  const previous = process.env.HIBP_API_KEY;
  delete process.env.HIBP_API_KEY;
  const urls = [];
  const httpGet = async (url) => {
    urls.push(url);
    if (url.endsWith('/.well-known/security.txt'))
      return { status: 200, data: 'Contact: mailto:admin@parent.example\n' };
    if (url === 'https://rdap.org/domain/parent.example') {
      return {
        status: 200,
        data: { entities: [{ vcardArray: ['vcard', [['org', {}, 'text', 'Parent Holdings']]] }] },
      };
    }
    if (url === 'https://rdap.org/domain/example.com')
      return { status: 200, data: { entities: [] } };
    if (url.includes('xposedornot.com')) return { status: 404, data: { Error: 'Not found' } };
    return { status: 404, data: '' };
  };
  const dossier = await buildDossier(
    {
      html: '<p>No contacts here.</p>',
      domain: 'example.com',
      host: 'example.com',
      href: 'https://example.com',
      report: {},
    },
    { httpGet, paceMs: 0, resolveTxt: async () => [] },
  );
  assert.equal(dossier.organization.name, 'Parent Holdings');
  assert.equal(urls.filter((url) => new URL(url).hostname.endsWith('parent.example')).length, 0);
  assert.ok(urls.includes('https://rdap.org/domain/parent.example'));
  assert.match(dossier.progression.join(' '), /No scan of that domain was started/);
  if (previous === undefined) delete process.env.HIBP_API_KEY;
  else process.env.HIBP_API_KEY = previous;
});
