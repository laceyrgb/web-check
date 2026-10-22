import type { Check } from '.';

export default {
  title: 'Public mentions',
  categories: ['privacy', 'domain'],
  summary: 'News, posts, and public paste or code-index hits',
  description:
    'Searches public news and code indexes for the domain. Hits are links only. Paste bodies are not stored. ' +
    'Sentiment is a keyword count, not a language model.',
  use: 'Notice public pages that mention the domain, including code and paste indexes.',
  resources: [{ title: 'searchcode', link: 'https://searchcode.com/' }],
} satisfies Check;
