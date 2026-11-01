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
| `mixed-content` | TLS and security headers | Partial: finds http resources in the page | Still missing from the runner |
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
| `firewall` | Attack-surface discovery | Partial: passive WAF header fingerprints | Still missing from the runner |
| `robots-txt` | Attack-surface discovery | Partial: fetches robots.txt | Still missing from the runner |
| `security-txt` | Attack-surface discovery | Existing: security.txt | Not called. Exposed-file checks are a separate gated list |
| `sitemap` | Attack-surface discovery | Partial: sitemap, or a same-site link crawl when there is none | Not called. The crawl stays in the legacy API |
| `linked-pages` | Attack-surface discovery | Partial: links on the crawled pages | Not called |
| `archives` | Attack-surface discovery | Partial: historical URLs | Still missing from the runner |
| `tech-stack` | Vulnerability scan | Partial: Wappalyzer fingerprint, no version matching | Not called. A short local version catalog was added instead |
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
| Version catalog | Apache 2.4.49/2.4.50, OpenSSL 1.0.1 Heartbleed range, jQuery before 3.5.0, PHP outside security support |
| Passive ports | Judges supplied port records. Does not call Shodan or nmap |
| Gated TCP connect | Short risky-port list via node:net, no payload, only after the gates |
| Email depth | BIMI only counts with enforced DMARC, null MX, weak and revoked DKIM |
| Certificate-transparency names | Flags administrative labels in a supplied extract; live mode uses crt.sh |
| Report diff | Added and removed open findings, for a future monitoring subscription |
| Nuclei adapter | Off by default. Tag allow-list, no interactsh, raw responses omitted. Not an exploit scan |

### Still missing

| # | Gap | Why it is still open |
| --- | --- | --- |
| 1 | Licensed breach data | Domain-level exposure with PDPL minimisation. The legacy HIBP list is not in this report |
| 2 | Full vulnerability feeds | NVD, CISA KEV, and EPSS. The starter catalog is intentionally small |
| 3 | Authenticated DAST | OWASP ZAP (Apache-2.0) is the candidate. It is not invoked: an active scan is out of policy for this phase |
| 4 | Monitoring product | Schedule, re-verify ownership each run, store reports, and alert. Only the diff function exists |
| 5 | Human sign-off | A queue so critical and high items are confirmed before a customer receives them |
| 6 | Confirmed takeover | Dangling CNAMEs are leads. The suite does not claim a takeover |
| 7 | Zone transfer | AXFR is intentionally not implemented |
| 8 | Cloud bucket names | Guessing storage hostnames is not implemented |
| 9 | Whole-site header crawl | The legacy sitemap crawler is not fed into this report |
| 10 | Mixed content | Still only in the legacy UI |
| 11 | WAF fingerprint and robots.txt | Still only in the legacy UI |
| 12 | Official control IDs | UAE IA / DESC / PDPL article mapping needs a human against the official text |
| 13 | Native Arabic edit | The Arabic in this report is a first draft for a reviewer, not a delivered translation |
| 14 | PDF one-pager | HTML is printable; a designed PDF is not built |
| 15 | Customer audit log | Who ordered the scan, the proof, the time, and the source address |
| 16 | Sector packs | Microsoft 365, Google Workspace, WooCommerce, and similar fix text |
| 17 | nmap | Not used. Its licence is the wrong fit for shipping inside this product |
<!-- inventory:end -->

## How to run it

From the repository root, with Node 22:

```bash
node suite/cli.js inventory
node suite/cli.js scan --target scan.example --observations suite/fixtures/example-observations.json --out /tmp/readiness
```

That second command does not contact the network. `scan.example` is a reserved example name. It writes `/tmp/readiness/report.json` and `/tmp/readiness/report.html`. The HTML report has an executive summary, a score, prioritised fixes, and the same findings in Arabic. UAE IA and PDPL lines are marked reference-only.

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

There is no exploitation, no brute force, no credential testing, and no nmap. Request bodies from exposed files are not copied into the report. Critical and high findings are flagged for a human reviewer.

Nuclei (MIT, not bundled) can be attached to an already authorised active run. The adapter allow-lists the tags `misconfig,exposure,tech,ssl,dns`, excludes exploit and brute-force tags, disables interactsh, and omits raw responses. OWASP ZAP is not invoked.

```bash
node suite/cli.js scan --target customer.example --live --mode active --authorized --verify-token '<token>' --nuclei /usr/bin/nuclei --out /tmp/readiness
```

A previous report can be passed with `--previous /tmp/readiness/report.json` on a later run. The new report then includes which open findings appeared or cleared. That is the seed of the monitoring subscription, not the subscription itself.

Library entry point: `import { runScan, renderHtml } from './suite/index.js'`. Pass `observations` to stay offline. The runner does not mount a route on the public web-check server.

## Top 10 roadmap ideas

The full ranking, including how each idea changes the report a customer actually reads, is in [SUITE_ROADMAP.md](./SUITE_ROADMAP.md). The first ten:

1. Human sign-off queue so a critical or high finding is confirmed before the report is marked deliverable.
2. Monitoring subscription: schedule, re-check ownership every run, store reports, alert on the diff this suite already computes.
3. Ship a curated nuclei template set behind the gates that already exist. Keep exploit tags excluded.
4. OWASP ZAP baseline (Apache-2.0) only under a signed scope. Leave the active scanner out.
5. Licensed breach data at domain level, with PDPL minimisation. Keep personal breach rows out of the default report.
6. Replace the starter version catalog with NVD, CISA KEV, and EPSS, still matching banners only.
7. Native Arabic edit and a one-page PDF an owner can forward.
8. A human maps findings to official UAE IA control IDs. Keep the label reference-only.
9. Sector packs for Microsoft 365, Google Workspace, and WooCommerce, with fix text in both languages.
10. Feed the existing same-site crawl into header, cookie, and mixed-content checks, behind the active gate.
