import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { canonicalUrl, extractAnchors, hostOf } from './page-links.js';

const page = (body) => `<!doctype html><html><body>${body}</body></html>`;

test('canonicalUrl keeps real page links and drops the rest', () => {
  const base = 'https://Example.com/docs/guide/';
  assert.equal(canonicalUrl('/about/', base), 'https://example.com/about');
  assert.equal(canonicalUrl('item?x=1#section', base), 'https://example.com/docs/guide/item?x=1');
  assert.equal(canonicalUrl('//cdn.example.com/a', base), 'https://cdn.example.com/a');
  assert.equal(canonicalUrl('#top', base), null);
  assert.equal(canonicalUrl('mailto:ada@example.com', base), null);
  assert.equal(canonicalUrl('javascript:void(0)', base), null);
  assert.equal(canonicalUrl('tel:+15551212', base), null);
  assert.equal(hostOf('https://Example.com./about'), 'example.com');
});

test('extractAnchors lists every anchor in order', () => {
  const html = page(`
    <a href="/a">A</a>
    <a href="mailto:ada@example.com">mail</a>
    <a href="https://other.test/x">out</a>
    <a href="/a#here">A again</a>
  `);
  assert.deepEqual(extractAnchors(html, 'https://example.com/start'), [
    'https://example.com/a',
    'https://other.test/x',
    'https://example.com/a',
  ]);
});

// A tiny site with internal pages, a broken link, and an off-site link
const fixture = {
  '/': page(
    '<a href="/about">About</a><a href="/missing">Missing</a><a href="https://example.com/out">Out</a><a href="/docs">Docs</a>',
  ),
  '/about': page('<a href="/deep">Deep</a>'),
  '/deep': page('<p>end</p>'),
  '/docs': page('<a href="/docs/item">Item</a>'),
  '/docs/item': page('<p>item</p>'),
};

test('collectSiteLinks lists same-site links and the status each one returned', async () => {
  const requested = [];
  const server = http.createServer((req, res) => {
    const path = req.url.split('?')[0];
    requested.push(path);
    const body = fixture[path];
    if (!body) {
      res.writeHead(404, { 'content-type': 'text/html' });
      res.end(page('missing'));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    // WC_SERVER keeps the API middleware on the Node export, which this import loads
    process.env.WC_SERVER = 'true';
    const { collectSiteLinks } = await import('../sitemap.js');
    const result = await collectSiteLinks(`http://127.0.0.1:${port}/`);
    const urls = result.urlset.url.map((entry) => entry.loc[0]);
    assert.equal(result.source, 'crawl');
    assert.ok(urls.includes(`http://127.0.0.1:${port}/`));
    assert.ok(urls.includes(`http://127.0.0.1:${port}/about`));
    assert.ok(urls.includes(`http://127.0.0.1:${port}/deep`));
    assert.ok(urls.includes(`http://127.0.0.1:${port}/docs`));
    assert.ok(urls.includes(`http://127.0.0.1:${port}/docs/item`));
    assert.ok(urls.includes(`http://127.0.0.1:${port}/missing`));
    assert.equal(
      urls.some((url) => url.includes('example.com')),
      false,
    );
    const status = Object.fromEntries(
      result.urlset.url.map((entry) => [new URL(entry.loc[0]).pathname, entry.status[0]]),
    );
    assert.equal(status['/about'], '200');
    assert.equal(status['/missing'], '404');
    assert.equal(result.valid, urls.length - 1);
    assert.equal(
      requested.some((path) => path.includes('example.com')),
      false,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
