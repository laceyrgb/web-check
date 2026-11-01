import assert from 'node:assert/strict';
import test from 'node:test';

import { isBlockedAddress, matchesCidr } from '../addresses.js';
import { buildDenylist } from '../denylist.js';
import { registrableDomain } from '../domain.js';
import { assertFetchAllowed, assertPublicAddresses } from '../live.js';
import { tokenMatches, verifyOwnership } from '../ownership.js';
import { parseTarget } from '../target.js';

test('parseTarget accepts a domain and refuses addresses and credentials', () => {
  assert.equal(parseTarget('scan.example').hostname, 'scan.example');
  assert.equal(parseTarget('http://127.0.0.1:9/health').loopback, true);
  assert.throws(() => parseTarget('https://203.0.113.10'), /IP targets/);
  assert.throws(() => parseTarget('https://169.254.169.254'), /IP targets/);
  assert.throws(() => parseTarget('https://user:secret@scan.example'), /Credentials/);
  assert.throws(() => parseTarget('ftp://scan.example'), /http/);
});

test('non-public addresses are blocked and loopback is opt-in', () => {
  assert.equal(isBlockedAddress('8.8.8.8'), false);
  assert.equal(isBlockedAddress('10.1.2.3'), true);
  assert.equal(isBlockedAddress('192.168.0.1'), true);
  assert.equal(isBlockedAddress('172.16.5.5'), true);
  assert.equal(isBlockedAddress('172.32.0.1'), false);
  assert.equal(isBlockedAddress('169.254.169.254'), true);
  assert.equal(isBlockedAddress('127.0.0.1'), true);
  assert.equal(isBlockedAddress('127.0.0.1', { allowLoopback: true }), false);
  assert.equal(isBlockedAddress('::ffff:10.0.0.1'), true);
  assert.equal(matchesCidr('192.168.1.5', '192.168.0.0/16'), true);
  assert.equal(matchesCidr('scan.example', '192.168.0.0/16'), false);
});

test('public-address guard refuses the resolved address before a request', async () => {
  await assert.rejects(() => assertPublicAddresses('scan.example', ['10.0.0.5']), /non-public/);
  await assertPublicAddresses('localhost', ['127.0.0.1']);
});

test('fetches stay on the target host', () => {
  assert.equal(
    assertFetchAllowed('scan.example', 'https://scan.example/').hostname,
    'scan.example',
  );
  assert.equal(
    assertFetchAllowed('scan.example', 'https://mta-sts.scan.example/.well-known/mta-sts.txt')
      .hostname,
    'mta-sts.scan.example',
  );
  assert.throws(() => assertFetchAllowed('scan.example', 'https://crt.sh/'), /not the scan target/);
  assert.throws(
    () => assertFetchAllowed('scan.example', 'https://evil.example/'),
    /not the scan target/,
  );
  assert.throws(
    () => assertFetchAllowed('scan.example', 'http://mta-sts.scan.example/policy'),
    /HTTPS/,
  );
});

test('denylist blocks government names and not lookalikes', () => {
  const list = buildDenylist({ env: {} });
  assert.equal(list.check('ministry.gov.ae').id, 'uae-gov');
  assert.equal(list.check('gov.ae').id, 'uae-gov');
  assert.equal(list.check('unit.test.gov.ae').id, 'uae-gov');
  assert.equal(list.check('notgov.ae'), null);
  assert.equal(list.check('scan.example'), null);
  assert.equal(list.check('agency.gov').id, 'gov-tld');
  assert.equal(list.check('printer.local').id, 'mdns-local');
  assert.equal(list.check('localhost'), null);
  const extra = buildDenylist({
    extra: ['example.com'],
    env: { API_BLOCKED_HOSTS: 'blocked.test' },
  });
  assert.equal(extra.check('www.example.com').id, 'extra:example.com');
  assert.equal(extra.check('a.blocked.test').id, 'env:blocked.test');
});

test('registrable domain keeps multi-part suffixes', () => {
  assert.equal(registrableDomain('www.shop.co.ae'), 'shop.co.ae');
  assert.equal(registrableDomain('www.scan.example'), 'scan.example');
});

test('ownership accepts an exact DNS record or well-known file and rejects a short token', async () => {
  const token = 'cormorant-test-token';
  assert.equal(tokenMatches(token, token), true);
  assert.equal(tokenMatches(`${token}extra`, token), false);
  const dns = await verifyOwnership({
    hostname: 'scan.example',
    token,
    origin: 'https://scan.example',
    transports: {
      resolveTxt: async () => [[`cormorant-verify=${token}`]],
      httpGet: async () => {
        throw new Error('file should not be fetched after DNS matches');
      },
    },
  });
  assert.deepEqual(dns, { ok: true, method: 'dns-txt', reason: null });
  const file = await verifyOwnership({
    hostname: 'scan.example',
    token,
    origin: 'https://scan.example',
    transports: {
      resolveTxt: async () => [],
      httpGet: async (url) => {
        assert.match(url, /\/\.well-known\/cormorant-verify\.txt$/);
        return { status: 200, body: `${token}\n` };
      },
    },
  });
  assert.equal(file.ok, true);
  assert.equal(file.method, 'well-known-file');
  const bad = await verifyOwnership({
    hostname: 'scan.example',
    token: 'too-short',
    transports: {},
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, 'token-format');
});
