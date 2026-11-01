# Suite roadmap

Ranked next steps for the UAE Readiness Scan. Version 0.1 already produces the takeaway a non-technical owner needs: an executive summary in English and Arabic, a capped score, prioritised fixes, a "what this scan did not do" section, and UAE IA / PDPL lines marked reference-only. `diffReports` compares two JSON reports. The items below make that takeaway more trustworthy, then widen the tests.

Scores in the product stay an aid for a reviewer. They are not a certification and not a penetration-test result.

## Top 10

1. **Human sign-off queue.** Critical and high rows already carry `needsHumanReview`. The missing piece is a state: draft, reviewer confirmed, sent. A false positive that reaches a customer costs more than a missed informational header. The report should show the reviewer's name and the date, and hide rows they rejected.
2. **Monitoring subscription.** Re-check the DNS TXT or well-known file on every run, store the JSON, and email the diff when a high or critical id appears or the score drops. The comparison function is already in `suite/diff.js`. What is missing is the schedule, the retention window from the service note, and the alert.
3. **Curated nuclei templates, still gated.** The adapter in `suite/engines/nuclei.js` is off unless the run is live, authorised, and ownership-verified. It allow-lists `misconfig,exposure,tech,ssl,dns` and excludes exploit, brute-force, fuzz, and denial-of-service tags. Next: pin a template revision, vendor only that set, and quote the MIT licence in the report. Do not enable the default template directory.
4. **OWASP ZAP baseline under a signed scope.** ZAP is Apache-2.0, so it can ship in a commercial service with attribution. Use the baseline (passive-plus-spider) only after a signed scope that names hosts, dates, and exclusions. Do not enable the active scanner in this product phase. Authenticated scanning stays a separate, higher-risk service.
5. **Licensed breach data, minimised.** The legacy `breaches` handler reads the public Have I Been Pwned domain list. A paid report needs a licensed source and a PDPL decision: show the breach title, date, and data classes, and leave personal email addresses out of the default export. A reviewer handles anything that is personal data.
6. **NVD, KEV, and EPSS instead of the starter catalog.** The catalog matches Apache 2.4.49/2.4.50, the OpenSSL 1.0.1 Heartbleed range, jQuery before 3.5.0, and PHP branches outside security support. Replace it with a feed the operator updates, matched to banners and passive port records only. A version match stays a lead. The scan must not send an exploit payload to prove it.
7. **Native Arabic and a one-page PDF.** The Arabic in the HTML is a first draft for a reviewer, not a delivered translation. A native editor should fix the glossary (severity words, DMARC, HSTS) and the summary. Then render one page: score, three fixes, and the reference-only disclaimer, in both languages, for the owner to forward.
8. **Official UAE IA control IDs, still reference-only.** Today's labels are themes, on purpose, so the report cannot be mistaken for a NESA, DESC, or PDPL assessment. After a human reads the current UAE IA text, attach the real control id beside the theme and keep the sentence that this is not a certification.
9. **Sector packs.** Microsoft 365, Google Workspace, and WooCommerce cover a large share of UAE SMB mail and sites. Each pack is a short bilingual fix for the findings those stacks usually produce (SPF includes, DKIM selectors, a known admin path), so the prioritised list reads like advice for that business rather than a generic header audit.
10. **Use the same-site crawl we already have.** `api/sitemap.js` lists same-site links when a site has no sitemap. Under the active gate, run the header, cookie, and mixed-content checks on a capped set of those URLs. The homepage-only snapshot misses a login form that drops Secure, and it misses mixed content on an inner page.

## Further tests

11. **Historical certificate-transparency diff.** Store the names from crt.sh and alert when a new administrative name appears. That is a monitoring signal, not a new probe.
12. **Unexpected certificates.** A certificate for the customer's name issued by an authority they did not list in CAA is a lead for a reviewer. Fetch the log entry; do not visit the lookalike host.
13. **BIMI logo checks.** The suite already checks that BIMI is paired with enforced DMARC. Next, fetch the logo URL and check it is HTTPS SVG within the size the BIMI group publishes. A broken logo is informational.
14. **MTA-STS in the passive live path is already fetched** when the DNS record exists. Add a check that every MX host is covered and that `max_age` is long enough to be useful, and surface TLS-RPT in the executive summary when mail is the customer's main channel.
15. **Dangling-name playbook.** Possible dangling CNAMEs are high and marked for review. Add a reviewer checklist for the common providers (GitHub Pages, S3, Azure, Netlify, Vercel) so the sent report says "confirmed" or "not a takeover" instead of leaving the hedge in the customer copy.
16. **Whois and expiry.** The legacy whois handler is not in this report. Domain expiry inside 30 days belongs next to certificate expiry in the prioritised fixes.
17. **WAF and robots.txt.** Both exist in the legacy UI. Fold a passive WAF fingerprint and a note when `robots.txt` advertises an admin path into the attack-surface section. They are informational.
18. **IPv6.** Repeat the gated port connect and the TLS handshake over AAAA when the customer has one. Skip it when the address is non-public, using the same guard as IPv4.
19. **Dependency versions in page source**, beyond jQuery: a small allow-list of libraries with a fixed vulnerable range, still matched from script URLs, still reviewed by a human.
20. **Safe request budget.** Cap passive live time and the number of HTTP requests, and publish the scanner addresses so a customer can allow-list them and so an abuse report reaches Cormorant.

## Report takeaway, after the top 10

The v0.1 report already opens with the score and the summary, then the fixes, then the evidence. The improvements that change what the customer remembers are 1, 2, 7, 8, and 9: a person has signed it, they can see whether it got worse, the Arabic is something they would send, the compliance line points at a real control without pretending to certify, and the fixes name their stack.

Keep the score model in the footer. It starts at 100 and subtracts a capped weight per open finding (critical 25, high 15 capped at 45, medium 8 capped at 32, low 3 capped at 12). Informational rows and passed checks do not move it. A refused scan has no score. Trend tracking should plot that number across the stored reports from item 2, with the added and removed ids beside the line.

## Explicitly out of this roadmap's first slice

- Brute force, credential testing, and exploit payloads.
- nmap. The legacy port check and the gated connect both use Node sockets. nmap's licence is the wrong fit for shipping inside this product.
- Selling penetration tests to Dubai government or critical-infrastructure entities. The do-not-scan list is the technical half of that decision; the commercial half is a policy, not a test.
- AXFR. Copying a zone is more than a hygiene read, so it stays unimplemented.
