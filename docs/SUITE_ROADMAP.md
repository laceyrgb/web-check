# Suite roadmap

Version 0.3 of the UAE Readiness Scan. The safety gates are unchanged: passive by default, active work only with ownership verification and `--authorized`, the government and critical-infrastructure denylist, no exploitation, no brute force, no credential testing, and tests on fixtures or localhost.

## Shipped in this round

1. **Arabic in the one-page PDF.** Noto Naskh Arabic (SIL Open Font License 1.1, copyright Google) is bundled with `suite/fonts/OFL.txt`. Arabic is shaped into presentation forms, including lam-alef, and drawn right to left. The line that the wording needs a native reviewer stays on the page.
2. **Run storage.** A JSON store records each scan's score and open finding ids. The report lists the score over those runs and which ids appeared or cleared.
3. **Delivery adapters.** Email and WhatsApp are pluggable channels. The only implementation writes a bilingual message into an outbox folder. It stores no credentials and refuses a live send.
4. **Order record.** One record holds the order id, customer, target, ownership proof, authorisation, reviewer sign-off, and report release. Payment status is fixed at `not-integrated`. Release is blocked until proof, authorisation, and sign-off are all present.
5. **Breach and NVD stubs.** Both are provider interfaces fed by fixtures. Breach results in the default report are domain counts and data classes. Personal rows are dropped. Neither provider has an API key.
6. **UAE IA v2.1 crosswalk template.** `suite/uae/v21-crosswalk.json` lists the v1.1 ids this suite cites and leaves every v2.1 cell blank. A blank is not a mapping. The file is labelled reference-only and needs human review.

## Still missing

- A licensed breach feed. The stub and the PDPL minimisation rule are in place.
- A full NVD download. The fixture ingester and the small committed cache are in place. `refresh-intel --fetch` remains the only live fetch, and it is an operator command.
- A filled v2.1 crosswalk. A person has to read the current standard and complete the blank cells.
- A native edit of the Arabic wording. The glyphs now render.
- Live email or WhatsApp. The outbox is the only delivery.
- A payment provider. The order field does not call one.
- OWASP ZAP, confirmed takeover, AXFR, cloud bucket names, nmap, and DESC ISR clause numbers.

## Next five

1. A native editor reviews the Arabic strings now that the PDF can show them.
2. A human fills the v2.1 crosswalk from the official text and leaves the reference-only label in place.
3. A real email and WhatsApp sender behind the same outbox interface, still without putting secrets in the repository.
4. A licensed breach provider that returns only the minimised domain record this stub already defines.
5. A payment status that a real AED provider can set on the order record, without changing the rule that release needs proof, authorisation, and sign-off.

## Explicitly out of the next slice

- Brute force, credential testing, and exploit payloads.
- nmap.
- Scanning a denylisted name.
- Treating control ids as a certificate.
- Inventing v2.1 mappings to fill the blank cells.
