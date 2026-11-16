# UAE Readiness Scan

Cormorant Cyber's first automated external scan. A customer orders it on the site, we scan a domain they own, and a reviewer sends a bilingual English/Arabic report. This document is the phase-1 gap audit, the way to run the suite, and the top ten next steps. The ranked list with the reasoning sits in [SUITE_ROADMAP.md](./SUITE_ROADMAP.md).

The launch services, from the service note, are email-domain security (SPF, DKIM, DMARC, MTA-STS, BIMI), TLS and security headers, external attack-surface discovery, a vulnerability scan a human validates, and a monitoring subscription. Legal controls (authorisation, ownership, a do-not-scan list) come before any active check.

The legacy web-check UI also has cards that read those payloads rather than collecting their own: server info, vulnerabilities, and the TLS client and audit views. They are covered by the rows for `shodan`, `ssl`, and `tls-connection`.

## Gap table

Canonical source: `node suite/cli.js inventory`, which prints `suite/inventory.js`. The copy below is checked against that output in `suite/test/inventory.test.js`.

<!-- inventory:start -->
40 legacy endpoints were inventoried. The new runner does not call them over HTTP; it re-implements the launch checks so a report can be produced from a snapshot or a gated live collection.

### Existing

| Check | Launch service | Legacy web-check | In this suite |
| --- | --- | --- | --- |
| `mail-config` | Email domain security | Existing: SPF, DKIM selectors, DMARC, MTA-STS, BIMI fetch, DANE, TLS-RPT. The UI does not judge BIMI. | Re-implemented, including BIMI-versus-DMARC and null MX |
| `txt-records` | Email domain security | Partial: raw TXT only | Not called; mail TXT is read by the email check |
| `http-security` | TLS and security headers | Existing: CSP, HSTS, framing, referrer, permissions, and isolation headers | Re-implemented for the homepage snapshot |
| `headers` | TLS and security headers | Partial: dumps every response header | Not called; banner and security headers are judged in the suite |
| `hsts` | TLS and security headers | Existing: HSTS preload lookup | Re-implemented from the response header, without the preload list |
| `ssl` | TLS and security headers | Existing: direct TLS handshake and certificate chain | Re-implemented from a TLS snapshot |
| `tls-connection` | TLS and security headers | Existing: negotiated protocol and cipher | Re-implemented from a TLS snapshot |
| `tls-labs` | TLS and security headers | Partial: SSL Labs cache only, no new assessment | Not called |
| `mixed-content` | TLS and security headers | Partial: finds http resources in the page | Reported for HTTPS pages in the active same-site crawl |
| `redirects` | TLS and security headers | Partial: redirect chain | Partial: cleartext scheme is flagged when the snapshot says so |
| `cookies` | TLS and security headers | Existing: Secure, HttpOnly, SameSite on Set-Cookie | Re-implemented, plus SameSite=None and __Host-/__Secure- rules |
| `dns` | DNS hygiene | Partial: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR | Used as input ideas; the suite judges NS count, CAA, DNSSEC, and dangling names |
| `dnssec` | DNS hygiene | Existing: DNSKEY, DS, and AD flag via a public resolver | Re-implemented as a presence check, not a full chain validation |
| `caa-records` | DNS hygiene | Existing: CAA lookup | Re-implemented |
| `dns-server` | DNS hygiene | Partial: walks to the zone NS | Not called |
| `whois` | DNS hygiene | Partial: registration data | Still missing from the runner |
| `subdomains` | Attack-surface discovery | Existing: passive names from certificate transparency | Re-implemented as classification of supplied names; live mode queries crt.sh only |
| `ports` | Attack-surface discovery | Existing but active: TCP connect to a wide common-port list. Not nmap. | Not called. Passive records are judged. A gated connect uses a short risky-port list and node:net |
| `shodan` | Attack-surface discovery | Partial: passive host data, needs an API key | Not called |
| `get-ip` | Attack-surface discovery | Partial: resolves the address | Not called. Live mode refuses non-public addresses |
| `firewall` | Attack-surface discovery | Partial: passive WAF header fingerprints | Passive fingerprints in the runner (Cloudflare, Sucuri, Akamai, Imperva, F5, ModSecurity) |
| `robots-txt` | Attack-surface discovery | Partial: fetches robots.txt | Fetched with the homepage. Sensitive Disallow paths are flagged |
| `security-txt` | Attack-surface discovery | Existing: security.txt | Fetched with the homepage. A Contact field is a pass |
| `sitemap` | Attack-surface discovery | Partial: sitemap, or a same-site link crawl when there is none | Active gate crawls same-site links (the same link rules as that crawl) and checks cookies and mixed content. Capped at 5 pages |
| `linked-pages` | Attack-surface discovery | Partial: links on the crawled pages | Not called |
| `archives` | Attack-surface discovery | Partial: historical URLs | Still missing from the runner |
| `tech-stack` | Vulnerability scan | Partial: Wappalyzer fingerprint, no version matching | Not called. Banner versions are matched to a cached NVD, CISA KEV, and EPSS extract |
| `threats` | Vulnerability scan | Partial: Safe Browsing and similar, needs an API key | Not called |
| `block-lists` | Vulnerability scan | Partial: DNS blocklist reputation | Not called |
| `breaches` | Breach and exposure | Partial: Have I Been Pwned domain list | Still missing from the runner. Personal breach data stays out of this report |
| `trackers` | Breach and exposure | Partial: tracker script list, adjacent to PDPL | Still missing from the runner |
| `status` | Out of scope | HTTP status only | Not part of the launch suite |
| `quality` | Out of scope | Page quality scores | Not part of the launch suite |
| `rank` | Out of scope | Popularity rank | Not part of the launch suite |
| `location` | Out of scope | GeoIP | Not part of the launch suite |
| `carbon` | Out of scope | Carbon estimate | Not part of the launch suite |
| `trace-route` | Out of scope | Traceroute | Not part of the launch suite |
| `screenshot` | Out of scope | Page screenshot | Not part of the launch suite |
| `social-tags` | Out of scope | Open Graph tags | Not part of the launch suite |
| `social-presence` | Out of scope | Social accounts | Not part of the launch suite |

### Added

| Addition | What it does |
| --- | --- |
| Normalised findings | id, title, severity, evidence, remediation, references, bilingual title and fix, human-review flag |
| Severity model | critical, high, medium, low, info, with a capped score |
| Runner | One passive-by-default scan that emits JSON and bilingual HTML |
| Report takeaway | Executive summary, score, prioritised fixes, what was not tested |
| UAE IA and PDPL labels | Reference themes on every finding. Not a certification |
| Ownership gate | DNS TXT at _cormorant-verify or /.well-known/cormorant-verify.txt, plus an explicit authorisation flag, before any active check |
| Do-not-scan list | Built-in government and special-use suffixes, API_BLOCKED_HOSTS, and an extra-suffix hook |
| Private-address refusal | Live requests stop if the name resolves to a non-public address |
| DNS hygiene bundle | NS count, CAA, DNSSEC presence, dangling MX and NS, possible dangling CNAME |
| CORS | Wildcard on the homepage, and a gated reflection probe |
| Exposed files | Fixed signature list, gated, bodies not copied into the report |
| Cookie depth | SameSite=None without Secure, and __Host- / __Secure- prefix rules |
| CVE cache | Normalised NVD + CISA KEV + EPSS. KEV and high EPSS raise priority. Banner match only. A small cache ships with the repo; refresh-intel is a separate operator command |
| Passive ports | Judges supplied port records. Does not call Shodan or nmap |
| Gated TCP connect | Short risky-port list via node:net, no payload, only after the gates |
| Email depth | BIMI only counts with enforced DMARC, null MX, weak and revoked DKIM |
| Certificate-transparency names | Flags administrative labels in a supplied extract; live mode uses crt.sh |
| Report diff | Added and removed open findings, for a future monitoring subscription |
| Nuclei adapter | Off by default. Pinned GET-only templates, pin checked before launch, no interactsh, raw responses omitted |
| Human sign-off | Critical and high findings must be approved, edited, or suppressed with a reason before release. Append-only audit log |
| Monitoring events | Ownership is re-checked every run. JSON events for new and resolved findings and score changes. No mail sender yet |
| Same-site crawl in the report | Behind the active gate. Headers on the homepage, cookies and mixed content on crawled pages |
| robots.txt, security.txt, WAF | Passive checks on the homepage fetch |
| UAE IA v1.1 control ids | Cited from the TDRA regulation and labelled reference-only. DESC ISR is named without invented clause numbers |
| AED report metadata and sector packs | Currency AED. Packs for Microsoft 365, Google Workspace, WooCommerce, Shopify, and common UAE shared hosting |
| Executive brief | One-page HTML (EN/AR, RTL) and a one-page English PDF. Arabic is marked as needing native review. Fixes ranked by impact versus effort |

### Still missing

| # | Gap | Why it is still open |
| --- | --- | --- |
| 1 | Licensed breach data | Domain-level exposure with PDPL minimisation. The legacy HIBP list is not in this report |
| 2 | Full NVD in git | The matcher and the feed normaliser exist. The committed cache is a small extract, not the whole database |
| 3 | Authenticated DAST | OWASP ZAP (Apache-2.0) is still not invoked. An active scan stays out of policy for this phase |
| 4 | Alert delivery | Monitoring emits JSON events. Email, SMS, and WhatsApp delivery are not built |
| 5 | UAE IA v2.1 crosswalk | Ids are from TDRA v1.1. A reviewer must confirm them against v2.1 before they are cited as current |
| 6 | DESC ISR clause numbers | The report names the regulation and does not invent clause numbers |
| 7 | Native Arabic edit | Arabic is marked needs-native-review. It is not a delivered translation |
| 8 | Arabic inside the PDF | The one-page PDF is English because standard PDF fonts have no Arabic glyphs. Arabic is in the HTML brief |
| 9 | Confirmed takeover | Dangling CNAMEs are leads. The suite does not claim a takeover |
| 10 | Zone transfer | AXFR is intentionally not implemented |
| 11 | Cloud bucket names | Guessing storage hostnames is not implemented |
| 12 | Customer order log | The reviewer audit log exists. Who ordered the scan, payment, and source address are not stored |
| 13 | nmap | Not used. Its licence is the wrong fit for shipping inside this product |
<!-- inventory:end -->

## How to run it

From the repository root, with Node 22:

```bash
node suite/cli.js inventory
node suite/cli.js scan --target scan.example --observations suite/fixtures/example-observations.json --out /tmp/readiness
```

That second command does not contact the network. `scan.example` is a reserved example name. It writes `report.json`, `report.html`, `executive.html` (one page, English and Arabic, RTL), and `executive.pdf` (one English page). Arabic is marked as needing a native reviewer. Fixes are ranked by impact against effort. The currency metadata is AED. UAE IA control ids are from Regulation v1.1 and are labelled reference-only.

Tests, including the legacy same-site link crawl:

```bash
yarn test
```

`node --test suite/test/*.test.js` runs the new suite without installing the web-check dependencies. `yarn test` also runs `api/_common/page-links.test.js`.

### Passive live check

This is the free lead magnet: public DNS, one homepage fetch, one TLS handshake, and certificate-transparency names from crt.sh.

```bash
node suite/cli.js scan --target customer.example --live --out /tmp/readiness
```

`--live` is the switch that contacts the target. Without it the CLI refuses to scan. Government and special-use names (`*.gov.ae`, `*.government.ae`, `*.mil.ae`, `*.gov`, `*.mil`, `*.local`, `*.internal`, and the `API_BLOCKED_HOSTS` list already used by web-check) are refused before any query. Add another suffix with `--deny example.net`. If the name resolves to a private, link-local, or metadata address, the HTTP and TLS steps stop.

### Active checks

Active checks are the exposed-file signatures, one CORS reflection request, and a short TCP connect to a fixed list of risky ports. They run only when all of the following are true:

1. `--live --mode active`
2. `--authorized` (the customer's explicit authorisation; a bare flag, not inferred)
3. `--verify-token` of 16 to 128 letters, digits, `_` or `-`
4. A matching proof, either a TXT record at `_cormorant-verify.<host>` whose value is `cormorant-verify=<token>`, or the same token as the entire body of `https://<host>/.well-known/cormorant-verify.txt`

```bash
node suite/cli.js scan --target customer.example --live --mode active --authorized --verify-token '<token>' --out /tmp/readiness
```

There is no exploitation, no brute force, no credential testing, and no nmap. Request bodies from exposed files are not copied into the report. The active crawl stays on the same host, follows the same link rules as the page-link crawl, and stops after 5 pages. It checks cookies and mixed content on those pages. `robots.txt`, `security.txt`, and a passive WAF fingerprint run with the homepage fetch.

A report is a draft until every open critical and high finding is approved, edited, or suppressed. Suppress and edit require a reason. The audit log is append-only.

```bash
node suite/cli.js review --report /tmp/readiness/report.json --decisions decisions.json --reviewer "Amina Al" --out /tmp/released
```

`decisions.json` is `{ "decisions": [{ "id": "tech.apache.path-traversal", "action": "approve", "reason": "Banner matches the host" }] }`. `action` is `approve`, `edit`, or `suppress`.

Nuclei (MIT, not bundled) runs only on an authorised active scan, and only the pinned GET-only templates in `suite/engines/templates`. The pin is checked before launch. Interactsh stays off. OWASP ZAP is not invoked.

```bash
node suite/cli.js scan --target customer.example --live --mode active --authorized --verify-token '<token>' --nuclei /usr/bin/nuclei --out /tmp/readiness
```

Monitoring re-checks ownership every run, then diffs the report. Alerts are JSON events (`finding.opened`, `finding.resolved`, `score.changed`). A government name is refused before that check. Pass `--live` and a subscription file. This does not send email.

Version matching uses a cached NVD + CISA KEV + EPSS extract. KEV and high EPSS raise the priority. The match is the banner only. `node suite/cli.js refresh-intel --fetch` is a separate operator command that contacts NVD, CISA, and FIRST. It is not part of a customer scan. The file in git is a small extract, not the whole NVD.

UAE IA control ids on each finding are from the TDRA Regulation v1.1 text (for example T4.2.4 Electronic Messaging, T7.7.1 Control of Technical Vulnerabilities, T7.4.1 cryptographic policy, T1.2.1 Inventory of Assets, T4.5.2 Security of Network Services, M5.2.1 Identification of Applicable Legislation). Source: https://tdra.gov.ae/-/media/About/regulations-and-ruling/EN/UAE-Information-Assurance-Regulation-v1-1-pdf.ashx . v2.1 may renumber families, so a reviewer confirms the current id before it is cited. DESC ISR is named, without invented clause numbers, at https://www.desc.gov.ae/regulations/licenses/ . PDPL notes stay reference-only and point at https://www.uaelegislation.gov.ae/en/legislations/1972 .

Sector packs add plain-language fix text when the snapshot looks like Microsoft 365, Google Workspace, WooCommerce, Shopify, or common UAE shared hosting (cPanel, Plesk, LiteSpeed, and a few local host strings).

Library entry point: `import { runScan, applyReview, runMonitor } from './suite/index.js'`. Pass `observations` to stay offline.

## What shipped, and the next five

The gap table above is the inventory. [SUITE_ROADMAP.md](./SUITE_ROADMAP.md) has the reasoning. Highest-leverage items still open:

1. A native Arabic edit, then Arabic glyphs in the one-page PDF.
2. A human crosswalk from these v1.1 ids to UAE IA v2.1, still labelled reference-only.
3. Deliver the monitoring JSON events by email or WhatsApp, and store each run.
4. Licensed breach data at domain level, with personal rows kept out of the default report.
5. An AED checkout in front of this scanner, with the order, the proof, and the reviewer stored together.
