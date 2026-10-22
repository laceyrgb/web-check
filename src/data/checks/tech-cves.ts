import type { Check } from '.';

export default {
  title: 'Known CVEs',
  categories: ['security'],
  summary: 'NVD matches for technologies that disclosed a version',
  description:
    'Looks up public NVD records only when a product has a known CPE and a version the site disclosed. ' +
    'Unknown versions and unmapped products are skipped. An empty list is not a claim that the host is patched.',
  use: 'Prioritize disclosed software that already has a public vulnerability record.',
  resources: [{ title: 'National Vulnerability Database', link: 'https://nvd.nist.gov/' }],
} satisfies Check;
