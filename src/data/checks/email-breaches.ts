import type { Check } from '.';

export default {
  title: 'Email breach index',
  categories: ['privacy', 'email'],
  summary: 'Whether published addresses appear in a public breach index',
  description:
    'Checks addresses published on the page, plus an optional address you supply, against Have I Been Pwned ' +
    'when HIBP_API_KEY is set, otherwise the public XposedOrNot index. Passwords are never stored or shown.',
  use: 'Learn that an address appeared in a named public breach, with a link to that record.',
  resources: [{ title: 'Have I Been Pwned', link: 'https://haveibeenpwned.com/' }],
} satisfies Check;
