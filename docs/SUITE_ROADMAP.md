# Suite roadmap

Version 0.2 of the UAE Readiness Scan. The safety gates from 0.1 are unchanged: passive by default, active work only with ownership verification and `--authorized`, the government and critical-infrastructure denylist, no exploitation, no brute force, no credential testing, and tests on fixtures or localhost.

## Shipped in this round

1. **Sign-off queue.** Open critical and high findings must be approved, edited, or suppressed, with a reason on edit and suppress, before `release.status` becomes `released`. The audit log records reviewer, time, action, and reason.
2. **Monitoring.** `runMonitor` re-checks ownership on every run, refuses a denylisted name before that check, and emits JSON events for a baseline, new findings, resolved findings, and score changes. It does not send mail.
3. **CVE cache.** Banner and version matching reads a normalised NVD + CISA KEV + EPSS cache. KEV forces priority `immediate` and severity critical. EPSS at or above 0.1 raises severity one step. `refresh-intel --fetch` is an operator command with an allow-list of the three feed hosts. The committed cache is a small extract.
4. **Pinned nuclei templates.** Three GET-only templates (security.txt, robots.txt, missing HSTS), hashed in `pin.json`. The adapter refuses to launch if the pin or a forbidden marker fails. Exploit tags and interactsh stay excluded.
5. **Same-site crawl on the active path.** Up to five pages, same host, same non-page scheme rules as the page-link crawl. Mixed content and inner-page cookies are findings. `robots.txt`, `security.txt`, and a short WAF fingerprint list run with the homepage.
6. **UAE references.** Each finding carries a UAE IA Regulation v1.1 control id taken from the TDRA PDF (T4.2.4, T7.4.1, T7.7.1, T1.2.1, T4.5.2, M5.2.1, and the family that matches the service). The label says reference-only and points at the PDF. DESC ISR is named and linked, without invented clause numbers. PDPL notes stay reference-only. Report metadata is AED, market AE, VAT exclusive.
7. **Sector packs.** Microsoft 365, Google Workspace, WooCommerce, Shopify, and a shared-hosting hint used by many UAE sites. The text is a fix hint, not a claim about the vendor contract.
8. **Brief.** `executive.html` is one page, English and Arabic, RTL, and says the Arabic needs a native reviewer. `executive.pdf` is one English page. Fixes are ordered by impact against effort.

## Still missing

- Licensed breach data, with personal rows kept out of the default report.
- The full NVD in the repository. The normaliser is here. The cache in git is small.
- OWASP ZAP, including a baseline scan. Still out of policy until there is a signed scope.
- Delivery of monitoring events (email, SMS, WhatsApp) and a stored history beyond the previous file the caller passes in.
- A reviewer-confirmed crosswalk from v1.1 control ids to UAE IA v2.1.
- DESC ISR clause numbers. They are not guessed.
- A native Arabic edit, and Arabic text inside the PDF.
- Confirmed subdomain takeover. Dangling CNAMEs stay leads.
- AXFR, cloud bucket names, and nmap.
- The customer order log: who paid, the proof, and the source address. The reviewer log is a different record.

## Next five, for the UAE offer

1. **Native Arabic, then the PDF.** The bilingual HTML is what a customer would forward. It is still a draft. A native editor should lock the glossary, and the PDF should use a font that can carry that Arabic.
2. **v2.1 crosswalk.** Keep the reference-only label. Replace v1.1 ids only where the current standard moved them, and cite the page.
3. **Send the monitoring events.** JSON events are enough for an operator. A UAE SMB buyer needs a short Arabic and English note when a high finding appears or disappears, on a schedule, with ownership re-checked as it is now.
4. **Breach data with a PDPL rule.** Domain and date and data classes. No personal email addresses in the default export.
5. **AED checkout in front of the scanner.** The report already says the currency is AED. The missing product is the order, the stored proof, and the reviewer on the same record, so a released report can be tied to a paid engagement.

## Explicitly out of the next slice

- Brute force, credential testing, and exploit payloads.
- nmap.
- Selling this scan to a `*.gov.ae` name or other denylisted infrastructure.
- Treating the control ids as a certificate.
