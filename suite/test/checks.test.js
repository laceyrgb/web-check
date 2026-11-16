import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import { analyseDns } from '../checks/dns-hygiene.js';
import { analyseEmail } from '../checks/email.js';
import { classifyExposure } from '../checks/exposed-files.js';
import { ACTIVE_PORT_LIST } from '../checks/ports.js';
import { classifyNames } from '../checks/subdomains.js';
import { matchProduct } from '../checks/tech-cve.js';

const ids = (findings) => findings.map((item) => item.id);

test('SPF +all and a duplicated record are high findings', () => {
  const plus = analyseEmail('scan.example', {
    txt: { 'scan.example': ['v=spf1 +all'] },
    mx: [{ exchange: 'mail.scan.example' }],
    dkim: [],
  });
  assert.ok(ids(plus).includes('email.spf.plus-all'));
  const many = analyseEmail('scan.example', {
    txt: { 'scan.example': ['v=spf1 -all', 'v=spf1 include:other.example -all'] },
    mx: [],
    dkim: [],
  });
  assert.ok(ids(many).includes('email.spf.multiple'));
});

test('a resolver failure does not become a missing DMARC finding', () => {
  const findings = analyseEmail('scan.example', { error: 'ESERVFAIL' });
  assert.deepEqual(ids(findings), ['email.lookup-failed']);
});

test('DKIM length is judged from the supplied key size and from a real SPKI key', () => {
  const weak = analyseEmail('scan.example', {
    txt: { 'scan.example': ['v=spf1 -all'] },
    mx: [{ exchange: 'mail.scan.example' }],
    dkim: [{ selector: 's1', bits: 512 }],
  });
  assert.ok(ids(weak).includes('email.dkim.weak'));
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const body = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const strong = analyseEmail('scan.example', {
    txt: {
      'scan.example': ['v=spf1 -all'],
      '_dmarc.scan.example': ['v=DMARC1; p=reject; pct=100'],
      'default._domainkey.scan.example': [`v=DKIM1; k=rsa; p=${body}`],
    },
    mx: [{ exchange: 'mail.scan.example' }],
  });
  assert.ok(ids(strong).includes('email.dkim.pass'));
  assert.ok(ids(strong).includes('email.dmarc.pass'));
});

test('dangling cloud CNAME is a lead, and a name that only contains the suffix is not', () => {
  const lead = analyseDns({
    cnames: [
      { host: 'old.scan.example', target: 'old.scan.example.github.io', targetResolves: false },
    ],
  });
  assert.equal(lead[0].id, 'dns.cname.dangling-service');
  assert.match(lead[0].evidence, /not a confirmed takeover/);
  const noise = analyseDns({
    cnames: [{ host: 'www.scan.example', target: 'github.io.scan.example', targetResolves: false }],
  });
  assert.equal(noise[0].id, 'dns.cname.dangling');
});

test('certificate-transparency names stay inside the organisational domain', () => {
  const classified = classifyNames('www.scan.example', [
    'admin.scan.example',
    'www.scan.example',
    'scan.example',
    'admin.other.example',
  ]);
  assert.deepEqual(classified.interesting, ['admin.scan.example']);
  assert.equal(classified.names.includes('admin.other.example'), false);
});

test('exposed-file signatures ignore an HTML soft 404 and withhold the body', () => {
  assert.equal(classifyExposure('/.env', 200, '<html><title>Home</title></html>'), null);
  const env = classifyExposure('/.env', 200, 'DB_USER=app\nDB_PASSWORD=nope\n');
  assert.equal(env.id, 'exposure.env');
  const git = classifyExposure('/.git/HEAD', 200, 'ref: refs/heads/main\n');
  assert.equal(git.id, 'exposure.git');
  const forbidden = classifyExposure('/.git/HEAD', 403, '');
  assert.equal(forbidden.severity, 'low');
  assert.equal(classifyExposure('/.git/HEAD', 404, ''), null);
});

test('the version catalog matches known bad builds and ignores the patched neighbours', () => {
  assert.equal(matchProduct('Apache', '2.4.49', 'banner')[0].id, 'tech.apache.path-traversal');
  assert.equal(matchProduct('Apache', '2.4.51', 'banner').length, 0);
  assert.equal(matchProduct('OpenSSL', '1.0.1f', 'banner')[0].severity, 'critical');
  assert.equal(matchProduct('OpenSSL', '1.0.1g', 'banner').length, 0);
  assert.equal(matchProduct('jQuery', '3.4.1', 'page').length, 1);
  assert.equal(matchProduct('jQuery', '3.5.0', 'page').length, 0);
  assert.equal(matchProduct('PHP', '7.4.33', 'header')[0].id, 'tech.php.unsupported');
  assert.equal(matchProduct('PHP', '8.3.1', 'header').length, 0);
});

test('the active port list is a short fixed set and does not claim to be nmap', () => {
  assert.ok(ACTIVE_PORT_LIST.length < 20);
  assert.equal(ACTIVE_PORT_LIST.includes(3306), true);
  assert.equal(ACTIVE_PORT_LIST.includes(1), false);
});
