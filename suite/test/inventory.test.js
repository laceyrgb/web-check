import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { gapMarkdown, legacyChecks } from '../inventory.js';

test('every legacy API check is in the gap inventory', () => {
  const files = readdirSync('api').filter((name) => name.endsWith('.js'));
  const ids = new Set(legacyChecks.map((item) => item.id));
  for (const file of files) {
    const id = file.replace(/\.js$/, '');
    assert.ok(ids.has(id), id);
  }
  assert.equal(ids.size, files.length);
});

test('the owner report embeds the generated gap table', () => {
  const doc = readFileSync('docs/UAE_READINESS_SCAN.md', 'utf8');
  const start = doc.indexOf('<!-- inventory:start -->');
  const end = doc.indexOf('<!-- inventory:end -->');
  assert.ok(start !== -1 && end > start);
  const embedded = doc.slice(start + '<!-- inventory:start -->'.length, end).trim();
  assert.equal(embedded, gapMarkdown().trim());
});

test('the CLI prints the inventory and refuses to scan without a snapshot or --live', () => {
  const inventory = spawnSync(process.execPath, ['suite/cli.js', 'inventory'], {
    encoding: 'utf8',
  });
  assert.equal(inventory.status, 0);
  assert.match(inventory.stdout, /mail-config/);
  const refused = spawnSync(
    process.execPath,
    ['suite/cli.js', 'scan', '--target', 'scan.example'],
    {
      encoding: 'utf8',
    },
  );
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /Refusing to scan/);
  const active = spawnSync(
    process.execPath,
    [
      'suite/cli.js',
      'scan',
      '--target',
      'scan.example',
      '--mode',
      'active',
      '--observations',
      'suite/fixtures/example-observations.json',
    ],
    { encoding: 'utf8' },
  );
  assert.equal(active.status, 1);
  assert.match(active.stderr, /without --live/);
});

test('a snapshot scan exits 0 and writes both report files', () => {
  const out = path.join(tmpdir(), 'readiness-scan-test');
  const scan = spawnSync(
    process.execPath,
    [
      'suite/cli.js',
      'scan',
      '--target',
      'scan.example',
      '--observations',
      'suite/fixtures/example-observations.json',
      '--out',
      out,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(scan.status, 0, scan.stderr);
  const html = readFileSync(`${out}/report.html`, 'utf8');
  assert.match(html, /UAE Readiness Scan/);
  assert.equal(html.includes('secretvalue'), false);
});
