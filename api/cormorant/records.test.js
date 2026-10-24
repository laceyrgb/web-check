import assert from 'node:assert/strict';
import test from 'node:test';
import { zipStore } from './export.js';
import { renderReport } from './pdf.js';
import { diffScans, scoreRisk } from './risk.js';
import {
  collectPublicRecords,
  docxInfo,
  linkedDocuments,
  pdfInfo,
  summarizeCertificates,
} from './records.js';

const pdf = Buffer.from(
  '%PDF-1.4\n1 0 obj\n<< /Title (Quarterly) /Author (Amina Hassan) /Creator (C:\\\\Users\\\\amina) >>\nendobj\n%%EOF\n',
  'latin1',
);

test('pdf and docx metadata keep the author and a local path', () => {
  const info = pdfInfo(pdf);
  assert.equal(info.author, 'Amina Hassan');
  assert.match(info.creator, /Users\\amina/);
  const docx = zipStore([
    {
      name: 'docProps/core.xml',
      data: '<?xml version="1.0"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Amina Hassan</dc:creator><dc:title>Brief</dc:title></cp:coreProperties>',
    },
  ]);
  assert.equal(docxInfo(docx).author, 'Amina Hassan');
  assert.equal(docxInfo(docx).title, 'Brief');
});

test('linked documents stay on the registrable domain', () => {
  const links = linkedDocuments(
    '<a href="/files/report.pdf">a</a><a href="https://cdn.example.net/a.pdf">b</a><a href="https://example.com/notes.docx">c</a>',
    'https://www.example.com/index.html',
    'example.com',
  );
  assert.deepEqual(links, [
    'https://www.example.com/files/report.pdf',
    'https://example.com/notes.docx',
  ]);
});

test('certificate summary keeps upcoming expirations and drops other domains', () => {
  const now = Date.parse('2026-10-24T00:00:00Z');
  const summary = summarizeCertificates(
    [
      {
        issuer_name: "C=US, O=Let's Encrypt, CN=R3",
        not_before: '2026-09-01T00:00:00',
        not_after: '2026-11-02T00:00:00',
        name_value: 'www.example.com\n*.example.com',
      },
      {
        issuer_name: 'C=US, O="Cloudflare, Inc.", CN=R3',
        not_before: '2020-01-01T00:00:00',
        not_after: '2021-01-01T00:00:00',
        name_value: 'old.example.com\nevil.com',
      },
    ],
    'example.com',
    now,
  );
  assert.deepEqual(summary.names, ['old.example.com', 'www.example.com']);
  assert.equal(summary.expiring.length, 1);
  assert.equal(summary.expiring[0].days <= 14, true);
  assert.equal(summary.issuers[0].name, "Let's Encrypt");
  assert.ok(summary.issuers.some((row) => row.name === 'Cloudflare, Inc.'));
});

test('public record scores spoofable mail and does not look the author up', async () => {
  const calls = [];
  const record = await collectPublicRecords(
    {
      href: 'https://example.com',
      domain: 'example.com',
      html: '<a href="https://example.com/files/report.pdf">pdf</a><a href="https://cdn.example.net/other.pdf">skip</a>',
    },
    {
      now: Date.parse('2026-10-24T00:00:00Z'),
      resolveTxt: async (name) => {
        if (name === 'example.com') return ['v=spf1 +all'];
        if (name === '_dmarc.example.com')
          return ['v=DMARC1; p=none; rua=mailto:dmarc@example.com'];
        if (name === 'google._domainkey.example.com') return ['v=DKIM1; k=rsa; p=MIIBSECRETKEY'];
        if (name === '_mta-sts.example.com') return ['v=STSv1; id=2026'];
        return [];
      },
      httpGet: async (url) => {
        calls.push(String(url));
        return { status: 200, data: 'version: STSv1\nmode: testing\n' };
      },
      fetchBytes: async (url) => {
        calls.push(String(url));
        return { status: 200, data: pdf };
      },
      certificateRows: [
        {
          issuer_name: 'O=Example CA',
          not_before: '2026-09-01T00:00:00',
          not_after: '2026-11-01T00:00:00',
          name_value: 'www.example.com',
        },
      ],
    },
  );
  assert.equal(record.documents[0].author, 'Amina Hassan');
  assert.ok(record.documents[0].paths[0].includes('amina'));
  assert.equal(record.mail.dkim[0].selector, 'google');
  assert.equal(JSON.stringify(record).includes('MIIBSECRETKEY'), false);
  assert.ok(record.findings.some((row) => row.detail.includes('+all')));
  assert.ok(record.findings.some((row) => row.detail === 'DMARC policy is none'));
  assert.ok(record.findings.some((row) => row.source === 'certificate'));
  assert.ok(record.findings.some((row) => row.source === 'document'));
  assert.equal(
    calls.some((url) => url.includes('cdn.example.net')),
    false,
  );
  assert.equal(
    calls.some((url) => /amina|people|linkedin|pipl/i.test(url)),
    false,
  );
  const scored = scoreRisk({ records: record });
  assert.equal(scored.score < 100, true);
  assert.ok(scored.factors.some((row) => row.action));
});

test('a DNS failure is not scored as a missing SPF record', async () => {
  const record = await collectPublicRecords(
    { href: 'https://example.com', domain: 'example.com', html: '' },
    {
      resolveTxt: async (name) =>
        name === 'example.com' ? { records: [], error: 'SERVFAIL' } : [],
      certificateRows: [],
      fetchBytes: async () => ({ status: 404, data: Buffer.alloc(0) }),
    },
  );
  assert.equal(record.mail.spfError, 'SERVFAIL');
  assert.equal(
    record.findings.some((row) => row.detail.includes('SPF')),
    false,
  );
});

test('mail policy changes are recorded and the pdf names the public record', async () => {
  const changes = diffScans(
    { hosts: [], mailPolicy: 'fail:reject', riskScore: 90 },
    { hosts: [], mailPolicy: 'pass:none', riskScore: 90 },
  );
  assert.ok(changes.some((row) => row.type === 'mail-policy-change'));
  const pdfBytes = await renderReport({
    target: 'https://example.com',
    scannedAt: '2026-10-24T00:00:00.000Z',
    records: {
      mail: { spf: { qualifier: 'pass', record: 'v=spf1 +all' }, dmarc: null, dkim: [], notes: [] },
      documents: [
        { kind: 'pdf', url: 'https://example.com/a.pdf', author: 'Amina Hassan', paths: [] },
      ],
      certificates: { issuers: [], expiring: [], names: ['www.example.com'] },
      note: 'Mail policy, files already linked on the site, and the public certificate log.',
    },
  });
  const text = [...pdfBytes.toString('latin1').matchAll(/<([0-9A-Fa-f]+)>/g)]
    .map((match) => Buffer.from(match[1], 'hex').toString('latin1'))
    .join('');
  assert.match(text, /Public record/);
  assert.match(text, /Amina Hassan/);
});
