import dns from 'dns/promises';
import { httpGet } from '../_common/http.js';
import { canonicalHost, domainOf, cardFields } from './util.js';
import { targetUrl } from './hosts.js';

const HOMO = { o: ['0'], i: ['1'], l: ['1'], e: ['3'], a: ['4'], s: ['5'] };
const ALT_TLD = { com: ['net', 'co'], net: ['com'], org: ['com'], co: ['com'] };

export const generateLookalikes = (domain) => {
  const [label, ...rest] = String(domain || '').toLowerCase().split('.');
  const tld = rest.join('.');
  if (!label || label.length < 4 || !tld) return [];
  const candidates = new Set();
  const add = (next, tldName = tld) => {
    const host = `${next}.${tldName}`.replace(/[^a-z0-9.-]/g, '');
    if (host && host !== domain && next.length >= 3) candidates.add(host);
  };
  for (let i = 0; i < label.length; i += 1) add(label.slice(0, i) + label.slice(i + 1));
  for (let i = 0; i < label.length - 1; i += 1) {
    add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
  }
  for (let i = 0; i < label.length; i += 1) add(label.slice(0, i) + label[i] + label.slice(i));
  for (let i = 0; i < label.length; i += 1) {
    for (const swap of HOMO[label[i]] || []) add(label.slice(0, i) + swap + label.slice(i + 1));
  }
  for (const alt of ALT_TLD[tld] || []) add(label, alt);
  return [...candidates].slice(0, 24);
};

const resolves = async (host) => {
  try {
    return await Promise.race([
      dns.resolve4(host),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1500)),
    ]);
  } catch {
    return [];
  }
};

export const checkLookalikes = async (url, deps = {}) => {
  const domain = domainOf(canonicalHost(url));
  const names = deps.candidates || generateLookalikes(domain);
  const checked = [];
  for (let i = 0; i < names.length; i += 6) {
    const group = names.slice(i, i + 6);
    const rows = await Promise.all(
      group.map(async (host) => {
        const addresses = deps.resolveHost ? await deps.resolveHost(host) : await resolves(host);
        return { domain: host, addresses, resolves: addresses.length > 0, suspicious: addresses.length > 0 };
      }),
    );
    checked.push(...rows);
  }
  const live = checked.filter((row) => row.resolves).slice(0, 8);
  const http = deps.httpGet || httpGet;
  for (const row of live) {
    try {
      const response = await http(targetUrl(row.domain), { timeout: 4000, validateStatus: () => true });
      row.httpStatus = response.status;
    } catch {
      row.httpStatus = null;
    }
  }
  const result = {
    domain,
    candidates: checked,
    live: live.map((row) => row.domain),
    note: 'Lookalikes are generated from omissions, swaps, duplications, and a few ASCII homoglyphs, then checked with DNS. A resolving name is suspicious and needs a person to review it. This is not a claim that the name is malicious.',
  };
  return {
    ...result,
    ...cardFields(
      [`${checked.length} lookalikes checked`, `${live.length} resolve in DNS`],
      live.map((row) => ({ label: row.domain, value: row.addresses.join(', ') || 'resolves' })),
      result.note,
    ),
  };
};
