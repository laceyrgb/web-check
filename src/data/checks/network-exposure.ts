import type { Check } from '.';

export default {
  title: 'Network exposure',
  categories: ['server', 'domain'],
  summary: 'GeoIP, ASN, reverse DNS, and optional Shodan or Censys data',
  description:
    'Maps the resolved address with public RDAP, routing history, and reverse lookups. ' +
    'Shodan and Censys host queries run only when their API keys are set, and only as read-only lookups.',
  use: 'See who announces the address and which names share it, from public data.',
  resources: [
    { title: 'RDAP', link: 'https://www.icann.org/rdap' },
    { title: 'Shodan InternetDB', link: 'https://internetdb.shodan.io/' },
  ],
} satisfies Check;
