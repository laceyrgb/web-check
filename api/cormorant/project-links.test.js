import assert from 'node:assert/strict';
import test from 'node:test';
import { hostFromInput, projectLinks } from '../../src/client/cormorant/projectLinks.js';

test('a pasted url becomes the host used by every project link', () => {
  assert.equal(hostFromInput('https://Example.COM/docs?q=1#x'), 'example.com');
  assert.equal(hostFromInput('example.com.'), 'example.com');
  assert.equal(hostFromInput('mailto:a@example.com'), '');
  assert.equal(hostFromInput(''), '');

  const map = projectLinks('https://example.com/docs');
  assert.equal(map.host, 'example.com');
  assert.equal(map.groups[0].links[0].href, '/check/example.com');
  assert.ok(map.groups[0].links.some((link) => link.href === '/security/example.com'));
  assert.ok(map.groups[0].links.some((link) => link.href === '/privacy/example.com'));
  assert.equal(
    map.groups[1].links.find((link) => link.label === 'Link list')?.href,
    '/desk?target=example.com#links',
  );
  assert.equal(
    map.groups[1].links.find((link) => link.label === 'Public record')?.href,
    '/desk?target=example.com#records',
  );
  assert.equal(
    map.groups[1].links.find((link) => link.label === 'Investigation')?.href,
    '/desk?target=example.com#investigation',
  );
  assert.equal(
    map.groups[2].links.find((link) => link.label === 'Project map')?.href,
    '/project?target=example.com',
  );
  assert.equal(map.groups[2].links.find((link) => link.label === 'All checks')?.href, '/checks');
});

test('on the desk the same sections are in-page anchors', () => {
  const map = projectLinks('example.org', { here: 'desk' });
  assert.equal(map.groups[1].links[0].href, '#scan');
  assert.equal(map.groups[1].links.find((link) => link.label === 'Offline copy')?.href, '#offline');
  assert.equal(
    map.groups[0].links.find((link) => link.label === 'Full report')?.href,
    '/check/example.org',
  );
});

test('an empty target still links the project indexes', () => {
  const map = projectLinks('   ');
  assert.equal(map.host, '');
  assert.equal(map.groups[0].links[0].href, '/check');
  assert.equal(map.groups[1].links[0].href, '/desk#scan');
  assert.equal(map.groups[2].links[0].href, '/project');
});
