import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const TEMPLATE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'templates');

const FORBIDDEN = ['interactsh', 'exploit', 'sqlmap', '{{cmd}}', 'cmdi', 'rce', 'bruteforce'];

export const assertTemplateSafe = (text, name = 'template') => {
  const lower = String(text).toLowerCase();
  for (const word of FORBIDDEN) {
    if (lower.includes(word)) throw new Error(`${name} contains a forbidden marker: ${word}`);
  }
  if (!/method:\s*get/i.test(text)) throw new Error(`${name} must use GET only`);
};

export const hashTemplate = (text) => createHash('sha256').update(text).digest('hex');

export const verifyTemplatePin = (dir = TEMPLATE_DIR) => {
  const pin = JSON.parse(readFileSync(path.join(dir, 'pin.json'), 'utf8'));
  const files = readdirSync(dir).filter((name) => name.endsWith('.yaml'));
  const pinned = Object.keys(pin.files || {}).sort();
  if (files.sort().join() !== pinned.join()) {
    throw new Error('Nuclei template directory does not match the pin');
  }
  for (const name of pinned) {
    const text = readFileSync(path.join(dir, name), 'utf8');
    assertTemplateSafe(text, name);
    if (hashTemplate(text) !== pin.files[name]) {
      throw new Error(`Nuclei template pin mismatch: ${name}`);
    }
  }
  return { id: pin.id, count: pinned.length, dir };
};
