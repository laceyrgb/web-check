import type { Check } from '.';

export default {
  title: 'Attack surface',
  categories: ['security', 'domain'],
  summary: 'Passive hostnames, common ports, and disclosed technologies',
  description:
    'Collects hostnames from public certificate transparency and DNS indexes, then records ' +
    'common open ports and technologies the site already discloses. Sources are cited on the card.',
  use: 'See the public footprint of a domain before deciding whether a closer look is in scope.',
  resources: [
    { title: 'crt.sh', link: 'https://crt.sh/' },
    { title: 'Cert Spotter', link: 'https://sslmate.com/certspotter/' },
  ],
} satisfies Check;
