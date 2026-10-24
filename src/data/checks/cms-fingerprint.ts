import type { Check } from '.';

export default {
  title: 'CMS fingerprint',
  categories: ['server', 'security'],
  summary: 'WordPress, Drupal, or Joomla version clues and matching CVEs',
  description:
    'Reads generator tags and plugin version query strings already in the HTML. ' +
    'Known CVEs are matched by version. No exploit payloads are sent.',
  use: 'Identify a public CMS version and the NVD records that match it.',
  resources: [{ title: 'National Vulnerability Database', link: 'https://nvd.nist.gov/' }],
} satisfies Check;
