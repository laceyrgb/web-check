import { matchesCidr } from './addresses.js';
import { endsWithName } from './domain.js';

// A suffix matches the name itself and any subdomain, and nothing that merely contains the text.
export const suffixRule = (suffix, id) => {
  const tail = String(suffix)
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '')
    .replace(/^\./, '')
    .replace(/\.$/, '');
  return { id, suffix: tail, test: (host) => endsWithName(host, tail) };
};

const exactRule = (host, id) => {
  const name = host.toLowerCase();
  return { id, suffix: name, test: (candidate) => candidate === name };
};

export const BUILTIN_RULES = [
  suffixRule('gov.ae', 'uae-gov'),
  suffixRule('government.ae', 'uae-government'),
  suffixRule('mil.ae', 'uae-mil'),
  suffixRule('gov', 'gov-tld'),
  suffixRule('mil', 'mil-tld'),
  suffixRule('gov.uk', 'uk-gov'),
  suffixRule('gc.ca', 'canada-gc'),
  exactRule('metadata.google.internal', 'cloud-metadata'),
  { id: 'mdns-local', suffix: 'local', test: (host) => host.endsWith('.local') },
  {
    id: 'special-internal',
    suffix: 'internal',
    test: (host) => host === 'internal' || host.endsWith('.internal'),
  },
  { id: 'home-arpa', suffix: 'home.arpa', test: (host) => endsWithName(host, 'home.arpa') },
];

const cidrRule = (entry) => ({
  id: `cidr:${entry}`,
  suffix: entry,
  test: (host) => matchesCidr(host, entry),
});

// API_BLOCKED_HOSTS is the existing web-check denylist. The suite honours it too.
export const rulesFromBlockedEnv = (env = process.env) => {
  const raw = env.API_BLOCKED_HOSTS || '';
  return raw
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean)
    .map((entry) => (entry.includes('/') ? cidrRule(entry) : suffixRule(entry, `env:${entry}`)));
};

export const buildDenylist = ({ extra = [], env = process.env } = {}) => {
  const extras = extra.map((entry) =>
    typeof entry === 'string' ? suffixRule(entry, `extra:${entry}`) : entry,
  );
  const rules = [...BUILTIN_RULES, ...rulesFromBlockedEnv(env), ...extras];
  return {
    rules,
    check(hostname) {
      const host = String(hostname || '')
        .toLowerCase()
        .replace(/\.$/, '');
      return rules.find((rule) => rule.test(host)) || null;
    },
  };
};
