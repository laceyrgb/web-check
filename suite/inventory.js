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
    'Reported for HTTPS pages in the active same-site crawl',
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
    'Passive fingerprints in the runner (Cloudflare, Sucuri, Akamai, Imperva, F5, ModSecurity)',
  ),
  row(
    'robots-txt',
    'Attack-surface discovery',
    'Partial: fetches robots.txt',
    'Fetched with the homepage. Sensitive Disallow paths are flagged',
  ),
  row(
    'security-txt',
    'Attack-surface discovery',
    'Existing: security.txt',
    'Fetched with the homepage. A Contact field is a pass',
  ),
  row(
    'sitemap',
    'Attack-surface discovery',
    'Partial: sitemap, or a same-site link crawl when there is none',
    'Active gate crawls same-site links (the same link rules as that crawl) and checks cookies and mixed content. Capped at 5 pages',
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
    'Not called. Banner versions are matched to a cached NVD, CISA KEV, and EPSS extract',
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
    'CVE cache',
    'Normalised NVD + CISA KEV + EPSS. KEV and high EPSS raise priority. Banner match only. A small cache ships with the repo; refresh-intel is a separate operator command',
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
    'Off by default. Pinned GET-only templates, pin checked before launch, no interactsh, raw responses omitted',
  ],
  [
    'Human sign-off',
    'Critical and high findings must be approved, edited, or suppressed with a reason before release. Append-only audit log',
  ],
  [
    'Monitoring events',
    'Ownership is re-checked every run. JSON events for new and resolved findings and score changes. No mail sender yet',
  ],
  [
    'Same-site crawl in the report',
    'Behind the active gate. Headers on the homepage, cookies and mixed content on crawled pages',
  ],
  ['robots.txt, security.txt, WAF', 'Passive checks on the homepage fetch'],
  [
    'UAE IA v1.1 control ids',
    'Cited from the TDRA regulation and labelled reference-only. DESC ISR is named without invented clause numbers',
  ],
  [
    'AED report metadata and sector packs',
    'Currency AED. Packs for Microsoft 365, Google Workspace, WooCommerce, Shopify, and common UAE shared hosting',
  ],
  [
    'Executive brief',
    'One-page HTML (EN/AR, RTL) and a one-page PDF with Noto Naskh Arabic (OFL), shaped and right-to-left. Arabic is still marked as needing native review. Fixes ranked by impact versus effort',
  ],
  [
    'Run history',
    'JSON store of each scan: score over time, and which open finding ids appeared or cleared',
  ],
  [
    'Delivery outbox',
    'Email and WhatsApp adapters render a bilingual note into a folder. Dry-run only. No credentials and no send',
  ],
  [
    'Order record',
    'Ties order, customer, target, ownership proof, authorisation, reviewer sign-off, and release. Payment status is a placeholder. Release is blocked until proof, authorisation, and sign-off are present',
  ],
  [
    'Breach and NVD stubs',
    'Provider interfaces backed by fixtures. PDPL minimisation keeps the default report to domain counts and data classes',
  ],
  [
    'UAE IA v2.1 crosswalk template',
    'v1.1 id to a blank v2.1 id. Reference-only. A blank is not a mapping',
  ],
];

export const missingChecks = [
  [
    'Licensed breach data',
    'A fixture provider returns domain counts only. Licensed breach data is not connected',
  ],
  [
    'Full NVD download',
    'A fixture provider can ingest an NVD-shaped payload. The committed cache is still a small extract, and refresh-intel is the only live fetch',
  ],
  [
    'Authenticated DAST',
    'OWASP ZAP (Apache-2.0) is still not invoked. An active scan stays out of policy for this phase',
  ],
  [
    'Live email and WhatsApp',
    'The adapters write an outbox. They do not send, and they accept no credentials',
  ],
  [
    'Filled UAE IA v2.1 crosswalk',
    'The template lists v1.1 ids and leaves v2.1 blank. A human has to verify every row',
  ],
  ['DESC ISR clause numbers', 'The report names the regulation and does not invent clause numbers'],
  [
    'Native Arabic edit',
    'The PDF shapes Arabic with Noto Naskh. The wording is still marked needs-native-review',
  ],
  ['Confirmed takeover', 'Dangling CNAMEs are leads. The suite does not claim a takeover'],
  ['Zone transfer', 'AXFR is intentionally not implemented'],
  ['Cloud bucket names', 'Guessing storage hostnames is not implemented'],
  [
    'Payment integration',
    'The order record has a payment status field fixed at not-integrated. No provider is called',
  ],
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
