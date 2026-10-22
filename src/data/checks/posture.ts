import type { Check } from '.';

export default {
  title: 'Security posture',
  categories: ['security'],
  summary: 'Header, TLS, cookie, and CORS hygiene score',
  description:
    'Starts at 100 and subtracts points for missing headers, weak TLS, cookie flag gaps, and open CORS. ' +
    'Remediations are hardening notes. The letter grade is not a penetration test.',
  use: 'Give a client a short list of public hygiene gaps and how to close them.',
  resources: [
    { title: 'OWASP Secure Headers', link: 'https://owasp.org/www-project-secure-headers/' },
  ],
} satisfies Check;
