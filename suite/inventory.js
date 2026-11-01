// Gap audit of the legacy web-check endpoints against the UAE Readiness Scan launch list.
// The runner re-implements the launch checks. It does not call the legacy HTTP handlers.

const row = (id, service, legacy, runner) => ({ id, service, legacy, runner });

export const legacyChecks = [
  row(
    'mail-config',
    'Email domain security',
    'Existing: SPF, DKIM selectors, DMARC, MTA-STS, BIMI fetch, DANE, TLS-RPT. The UI does not judge BIMI.',
    'Re-implemented, including BIMI-versus-DMARC and null MX',
  ),
  row(
    'txt-records',
    'Email domain security',
    'Partial: raw TXT only',
    'Not called; mail TXT is read by the email check',
  ),
  row(
    'http-security',
    'TLS and security headers',
    'Existing: CSP, HSTS, framing, referrer, permissions, and isolation headers',
    'Re-implemented for the homepage snapshot',
  ),
  row(
    'headers',
    'TLS and security headers',
    'Partial: dumps every response header',
    'Not called; banner and security headers are judged in the suite',
  ),
  row(
    'hsts',
    'TLS and security headers',
    'Existing: HSTS preload lookup',
    'Re-implemented from the response header, without the preload list',
  ),
  row(
    'ssl',
    'TLS and security headers',
    'Existing: direct TLS handshake and certificate chain',
    'Re-implemented from a TLS snapshot',
  ),
  row(
    'tls-connection',
    'TLS and security headers',
    'Existing: negotiated protocol and cipher',
    'Re-implemented from a TLS snapshot',
  ),
  row(
    'tls-labs',
    'TLS and security headers',
    'Partial: SSL Labs cache only, no new assessment',
    'Not called',
  ),
  row(
    'mixed-content',
    'TLS and security headers',
    'Partial: finds http resources in the page',
    'Still missing from the runner',
  ),
  row(
    'redirects',
    'TLS and security headers',
    'Partial: redirect chain',
    'Partial: cleartext scheme is flagged when the snapshot says so',
  ),
  row(
    'cookies',
    'TLS and security headers',
    'Existing: Secure, HttpOnly, SameSite on Set-Cookie',
    'Re-implemented, plus SameSite=None and __Host-/__Secure- rules',
  ),
  row(
    'dns',
    'DNS hygiene',
    'Partial: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR',
    'Used as input ideas; the suite judges NS count, CAA, DNSSEC, and dangling names',
  ),
  row(
    'dnssec',
    'DNS hygiene',
    'Existing: DNSKEY, DS, and AD flag via a public resolver',
    'Re-implemented as a presence check, not a full chain validation',
  ),
  row('caa-records', 'DNS hygiene', 'Existing: CAA lookup', 'Re-implemented'),
  row('dns-server', 'DNS hygiene', 'Partial: walks to the zone NS', 'Not called'),
  row('whois', 'DNS hygiene', 'Partial: registration data', 'Still missing from the runner'),
  row(
    'subdomains',
    'Attack-surface discovery',
    'Existing: passive names from certificate transparency',
    'Re-implemented as classification of supplied names; live mode queries crt.sh only',
  ),
  row(
    'ports',
    'Attack-surface discovery',
    'Existing but active: TCP connect to a wide common-port list. Not nmap.',
    'Not called. Passive records are judged. A gated connect uses a short risky-port list and node:net',
  ),
  row(
    'shodan',
    'Attack-surface discovery',
    'Partial: passive host data, needs an API key',
    'Not called',
  ),
  row(
    'get-ip',
    'Attack-surface discovery',
    'Partial: resolves the address',
    'Not called. Live mode refuses non-public addresses',
  ),
  row(
    'firewall',
    'Attack-surface discovery',
    'Partial: passive WAF header fingerprints',
    'Still missing from the runner',
  ),
  row(
    'robots-txt',
    'Attack-surface discovery',
    'Partial: fetches robots.txt',
    'Still missing from the runner',
  ),
  row(
    'security-txt',
    'Attack-surface discovery',
    'Existing: security.txt',
    'Not called. Exposed-file checks are a separate gated list',
  ),
  row(
    'sitemap',
    'Attack-surface discovery',
    'Partial: sitemap, or a same-site link crawl when there is none',
    'Not called. The crawl stays in the legacy API',
  ),
  row(
    'linked-pages',
    'Attack-surface discovery',
    'Partial: links on the crawled pages',
    'Not called',
  ),
  row(
    'archives',
    'Attack-surface discovery',
    'Partial: historical URLs',
    'Still missing from the runner',
  ),
  row(
    'tech-stack',
    'Vulnerability scan',
    'Partial: Wappalyzer fingerprint, no version matching',
    'Not called. A short local version catalog was added instead',
  ),
  row(
    'threats',
    'Vulnerability scan',
    'Partial: Safe Browsing and similar, needs an API key',
    'Not called',
  ),
  row('block-lists', 'Vulnerability scan', 'Partial: DNS blocklist reputation', 'Not called'),
  row(
    'breaches',
    'Breach and exposure',
    'Partial: Have I Been Pwned domain list',
    'Still missing from the runner. Personal breach data stays out of this report',
  ),
  row(
    'trackers',
    'Breach and exposure',
    'Partial: tracker script list, adjacent to PDPL',
    'Still missing from the runner',
  ),
  row('status', 'Out of scope', 'HTTP status only', 'Not part of the launch suite'),
  row('quality', 'Out of scope', 'Page quality scores', 'Not part of the launch suite'),
  row('rank', 'Out of scope', 'Popularity rank', 'Not part of the launch suite'),
  row('location', 'Out of scope', 'GeoIP', 'Not part of the launch suite'),
  row('carbon', 'Out of scope', 'Carbon estimate', 'Not part of the launch suite'),
  row('trace-route', 'Out of scope', 'Traceroute', 'Not part of the launch suite'),
  row('screenshot', 'Out of scope', 'Page screenshot', 'Not part of the launch suite'),
  row('social-tags', 'Out of scope', 'Open Graph tags', 'Not part of the launch suite'),
  row('social-presence', 'Out of scope', 'Social accounts', 'Not part of the launch suite'),
];

export const addedChecks = [
  [
    'Normalised findings',
    'id, title, severity, evidence, remediation, references, bilingual title and fix, human-review flag',
  ],
  ['Severity model', 'critical, high, medium, low, info, with a capped score'],
  ['Runner', 'One passive-by-default scan that emits JSON and bilingual HTML'],
  ['Report takeaway', 'Executive summary, score, prioritised fixes, what was not tested'],
  ['UAE IA and PDPL labels', 'Reference themes on every finding. Not a certification'],
  [
    'Ownership gate',
    'DNS TXT at _cormorant-verify or /.well-known/cormorant-verify.txt, plus an explicit authorisation flag, before any active check',
  ],
  [
    'Do-not-scan list',
    'Built-in government and special-use suffixes, API_BLOCKED_HOSTS, and an extra-suffix hook',
  ],
  ['Private-address refusal', 'Live requests stop if the name resolves to a non-public address'],
  [
    'DNS hygiene bundle',
    'NS count, CAA, DNSSEC presence, dangling MX and NS, possible dangling CNAME',
  ],
  ['CORS', 'Wildcard on the homepage, and a gated reflection probe'],
  ['Exposed files', 'Fixed signature list, gated, bodies not copied into the report'],
  ['Cookie depth', 'SameSite=None without Secure, and __Host- / __Secure- prefix rules'],
  [
    'Version catalog',
    'Apache 2.4.49/2.4.50, OpenSSL 1.0.1 Heartbleed range, jQuery before 3.5.0, PHP outside security support',
  ],
  ['Passive ports', 'Judges supplied port records. Does not call Shodan or nmap'],
  ['Gated TCP connect', 'Short risky-port list via node:net, no payload, only after the gates'],
  ['Email depth', 'BIMI only counts with enforced DMARC, null MX, weak and revoked DKIM'],
  [
    'Certificate-transparency names',
    'Flags administrative labels in a supplied extract; live mode uses crt.sh',
  ],
  ['Report diff', 'Added and removed open findings, for a future monitoring subscription'],
  [
    'Nuclei adapter',
    'Off by default. Tag allow-list, no interactsh, raw responses omitted. Not an exploit scan',
  ],
];

export const missingChecks = [
  [
    'Licensed breach data',
    'Domain-level exposure with PDPL minimisation. The legacy HIBP list is not in this report',
  ],
  [
    'Full vulnerability feeds',
    'NVD, CISA KEV, and EPSS. The starter catalog is intentionally small',
  ],
  [
    'Authenticated DAST',
    'OWASP ZAP (Apache-2.0) is the candidate. It is not invoked: an active scan is out of policy for this phase',
  ],
  [
    'Monitoring product',
    'Schedule, re-verify ownership each run, store reports, and alert. Only the diff function exists',
  ],
  [
    'Human sign-off',
    'A queue so critical and high items are confirmed before a customer receives them',
  ],
  ['Confirmed takeover', 'Dangling CNAMEs are leads. The suite does not claim a takeover'],
  ['Zone transfer', 'AXFR is intentionally not implemented'],
  ['Cloud bucket names', 'Guessing storage hostnames is not implemented'],
  ['Whole-site header crawl', 'The legacy sitemap crawler is not fed into this report'],
  ['Mixed content', 'Still only in the legacy UI'],
  ['WAF fingerprint and robots.txt', 'Still only in the legacy UI'],
  [
    'Official control IDs',
    'UAE IA / DESC / PDPL article mapping needs a human against the official text',
  ],
  [
    'Native Arabic edit',
    'The Arabic in this report is a first draft for a reviewer, not a delivered translation',
  ],
  ['PDF one-pager', 'HTML is printable; a designed PDF is not built'],
  ['Customer audit log', 'Who ordered the scan, the proof, the time, and the source address'],
  ['Sector packs', 'Microsoft 365, Google Workspace, WooCommerce, and similar fix text'],
  ['nmap', 'Not used. Its licence is the wrong fit for shipping inside this product'],
];

const table = (headers, rows) => {
  const head = `| ${headers.join(' | ')} |\n| ${headers.map(() => '---').join(' | ')} |`;
  return `${head}\n${rows.join('\n')}`;
};

export const gapMarkdown = () => {
  const legacyRows = legacyChecks.map(
    (item) => `| \`${item.id}\` | ${item.service} | ${item.legacy} | ${item.runner} |`,
  );
  const addedRows = addedChecks.map(([name, detail]) => `| ${name} | ${detail} |`);
  const missingRows = missingChecks.map(
    ([name, detail], index) => `| ${index + 1} | ${name} | ${detail} |`,
  );
  return [
    `${legacyChecks.length} legacy endpoints were inventoried. The new runner does not call them over HTTP; it re-implements the launch checks so a report can be produced from a snapshot or a gated live collection.`,
    '',
    '### Existing',
    '',
    table(['Check', 'Launch service', 'Legacy web-check', 'In this suite'], legacyRows),
    '',
    '### Added',
    '',
    table(['Addition', 'What it does'], addedRows),
    '',
    '### Still missing',
    '',
    table(['#', 'Gap', 'Why it is still open'], missingRows),
  ].join('\n');
};
