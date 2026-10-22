import type { Check } from '.';

export default {
  title: 'Privacy and accessibility',
  categories: ['privacy'],
  summary: 'Cookie banners, trackers, and basic accessibility notes',
  description:
    'Looks at the public page for cookie-banner clues, known tracker hosts, missing image text, and form labels. ' +
    'These are heuristics for a human review.',
  use: 'Flag public privacy and accessibility issues a visitor can already see.',
  resources: [{ title: 'WCAG', link: 'https://www.w3.org/WAI/standards-guidelines/wcag/' }],
} satisfies Check;
