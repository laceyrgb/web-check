import type { Check } from '.';

export default {
  title: 'Public people',
  categories: ['domain'],
  summary: 'Names and roles linked from the public site',
  description:
    'Lists public profile URLs that the site itself publishes. LinkedIn pages are not fetched from this card. ' +
    'The desk can read a URL you paste, and it stops when a login wall is in the way.',
  use: 'Keep a sourced list of people the organization already names in public.',
  resources: [{ title: 'Open Graph', link: 'https://ogp.me/' }],
} satisfies Check;
