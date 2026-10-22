import type { Check } from '.';

export default {
  title: 'Lookalike domains',
  categories: ['domain', 'security'],
  summary: 'Typos and homoglyphs that currently resolve',
  description:
    'Generates a short list of omission, swap, duplication, and homoglyph names, then checks DNS and HTTP. ' +
    'A resolving name is marked for review. It is not labeled malicious.',
  use: 'Spot public lookalikes that are live and worth a human look.',
  resources: [{ title: 'Public Suffix List', link: 'https://publicsuffix.org/' }],
} satisfies Check;
