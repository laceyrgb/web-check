# Cormorant OSINT Desk

This fork keeps the existing single-URL Web Check cards and adds a desk for passive recon, monitoring, and a few gated authorized actions. It is built for a self-hosted Node server. Scheduled monitors do not run on a serverless host.

## Run locally

```bash
yarn install
cp .env.sample .env
yarn dev
```

The UI is on port 4321 and the API on port 3001 during `yarn dev`. `yarn start` serves both from `server.js`.

Desk page: `/desk`. Result pages show a risk rollup and a PDF button. The PDF is generated on the server from a fresh scan, so the browser cannot invent findings.

## Project map

`/project` opens one host in the full report (`/check/<host>`), each category checker, and every desk section. The same links sit on the desk and on a finished report. Entering `https://example.com/docs` uses `example.com`, because a scan covers the host. The map does not start a scan.

State is a JSON file under `WEBCHECK_DATA_DIR` (default `.data`). Engagement secrets live in a separate file with mode `0600` and are never returned by GET.

## Offline copy

Scan results are not uploaded anywhere. To keep them off the web server, mount a USB stick or external drive and set `WEBCHECK_EXPORT_DIR` to that mount path. `POST /api/v1/export` writes a folder there: `index.html`, `manifest.json`, one JSON file per scan, and a PDF for each completed scan. Open `index.html` from the drive. It does not contact the server.

The write is synced, then a `COMPLETE` file is added. With `{ "removeLocal": true }` the server deletes that tenant's scans, monitors, timelines, assets, and screenshot files only after `COMPLETE` is present. A failed write leaves the server copy in place. Engagement passwords are not copied and are not deleted.

`GET /api/v1/export.zip` downloads the same folder as a zip for a drive plugged into the workstation. That download does not remove the server copy. Set the export directory and use `removeLocal` when the drive is mounted on the server itself.

`WEBCHECK_EXPORT_DIR` must be a real directory outside `WEBCHECK_DATA_DIR`, and it cannot be the filesystem root. The request body cannot choose a different path.

## Tenants

Each API key belongs to one tenant. `WEBCHECK_API_KEY` is the `default` tenant. `WEBCHECK_TENANT_KEYS` is a comma-separated `tenant:key` list for additional clients. Scans, monitors, assets, timelines, authorizations, engagements, and screenshots are stored under that tenant and are not returned to another key. A store written before tenants existed is loaded under `default`.

When no key is set, the API stays open and every record uses `default`. That is the local development mode.

## External keys

These modules call the real API when the key is present and skip or fall back when it is unset. The key is not copied into errors or results.

| Variable           | When set                                  | When unset                                                           |
| ------------------ | ----------------------------------------- | -------------------------------------------------------------------- |
| `HIBP_API_KEY`     | Have I Been Pwned breached-account lookup | Public XposedOrNot index                                             |
| `NVD_API_KEY`      | NVD CPE match with the higher quota       | Same CPE match, slower, still capped at three products               |
| `SHODAN_API_KEY`   | Read-only Shodan host lookup              | Skipped. InternetDB still runs and does not need a key               |
| `CENSYS_API_TOKEN` | Read-only Censys Platform host lookup     | Falls back to `CENSYS_API_ID` plus `CENSYS_API_SECRET`, then skipped |

Unknown product versions are not sent to NVD. Shodan and Censys are lookups of an address the scan already resolved. They do not submit a scan.

## What a plain scan does

`POST /api/v1/scans` collects public data only: certificate transparency hostnames, common-port observations, disclosed technologies, NVD matches, public breach indexes, GeoIP and RDAP, reverse DNS and same-IP neighbors, optional Shodan or Censys host lookups, public paste and code-index links, lookalikes (including `.ae` and a few Cyrillic homoglyphs), news mentions, header and TLS posture, CMS version clues, public bucket URLs already in the HTML, public profile links, and the public record of mail policy, linked documents, and certificate expirations. It then writes a risk score, a diff against the previous snapshot, and an asset inventory.

It does not run Nmap, Nuclei, an authenticated crawl, or anything that tries passwords.

## Link list

`POST /api/v1/links` takes a pasted dump, a page, or both. Pasted lines and the links on that one page are grouped by host. Repeated paths on the same host collapse. Hosts this tenant already queued or completed are listed under `alreadyScanned` and skipped. Failed hosts are queued again. Public subdomain names for the harvested page are included. The harvest does not fetch the other links it found. At most 80 new hosts are queued; further unique hosts are returned as `held` so a second pass can take the next batch. `/desk` has Queue pasted links and Harvest this page.

## Investigation

`POST /api/v1/investigations` runs the whole passive workflow for one organisation without an operator in the loop. It scans the root host, reads the hosts that passive sources returned for it, and pivots to the ones under the same registrable domain in the order an analyst would open them: remote access (`vpn`, `citrix`, `rdp`), mail (`mail`, `owa`, `autodiscover`, MX hosts), identity (`sso`, `login`, `adfs`), administration (`admin`, `portal`, `cpanel`), pre-production (`dev`, `staging`, `uat`), then source control, build systems, file transfer, databases, and the rest. At most 12 hosts are scanned per investigation (`maxHosts`, 1 to 12). A host this tenant completed in the last 24 hours is reused, not rescanned. Hosts beyond the cap are returned as `held`. Hostnames on other domains, including same-IP neighbours and certificate SANs, are listed under `related` and are never scanned.

When the last host scan finishes the results are merged into one dossier:

- **Facts** with a confidence. `high` means three or more independent sources produced the same value, `medium` two, `low` one. For host-specific facts (IP, service, technology, CVE, hosting, local path) each host and source pair counts as a source; for domain-level facts (hostnames, lookalikes, mail policy, registrant data, people) the same lookup repeated from another host adds nothing. A person name that does not also appear on the organisation's own pages is always `low`.
- **Organisation risk** weighted toward the weakest host: `round(0.6 × min + 0.4 × mean)` of the per-host scores.
- **Findings** with a disposition each: `open`, `accepted`, `false-positive`, or `fixed`. Host-level findings (CVE, port, posture, CMS, document) are listed per host. Domain-level findings (lookalike, breach, leak link, mail policy, certificate) are listed once against the domain with the hosts that reported them.
- **Intelligence gaps**: what the public record did not answer and the next legal step. A gap is not a finding.
- **Narrative** and a collection log with the reason for every pivot.

`POST /api/v1/investigations/:id/notes` stores the analyst summary and the dispositions on the investigation. They are applied every time the report or the PDF is generated. `GET /api/v1/investigations/:id/report.pdf` writes the dossier with the Cormorant header. Investigations are tenant scoped and travel with the offline export. `/desk` renders the hosts table, log, facts, findings with disposition selectors, gaps, and the summary field under Investigation.

An investigation never leaves the registrable domain, never fetches every harvested link, and runs no Nmap, Nuclei, crawl, or credential test. Those keep their own gates.

## Owner dossier

After the first pass, the scan keeps going while new public identifiers appear, for up to three rounds and twelve lookups. A phone or copyright name on the page is enough to check domain RDAP, `security.txt`, SPF, and DMARC. An email those records add is then checked in the breach index, on Gravatar, and on the public OpenPGP keyserver. A registrant email on a different domain gets one RDAP lookup for the organization name. That domain is not scanned.

A person name that comes back is compared with the target page. It is not sent to a people-search site. Redacted WHOIS addresses are ignored. The PDF section is "Owner dossier", and the new emails and the organization are part of the executive summary and the asset inventory.

## Public record

A plain scan also reads what the organization has already published around the site. `records` on the result, the PDF section "Public record", and `GET /api/v1/records?target=` carry the same three parts.

Mail policy comes from DNS: SPF, DMARC (`p` and `pct`), TLS-RPT, BIMI, and MTA-STS when `_mta-sts` is published. DKIM is limited to the provider selectors `google`, `selector1`, `selector2`, `k1`, and `zoho`. The key material is not stored. A missing selector is not treated as proof that DKIM is absent. A DNS failure is not scored as a missing record.

Published files are PDF and Word documents already linked on the fetched page, on the same registrable domain, at most three, and at most 1.5 MB each. Author, creator, company, and a local user path are kept for the report. Those names are not sent to a people-search site. Links on other domains are not fetched.

Certificate rows come from the public crt.sh log: issuers, names under the domain, and certificates that expire within 30 days. Historical expired certificates are not findings.

Risk points apply to missing SPF, SPF `+all`, missing DMARC, DMARC `p=none`, a partial DMARC percentage, a logged certificate expiring within 14 days, and a local user path inside a published file. MTA-STS, BIMI, and TLS-RPT are reported and are not scored. Lookalikes now also include `name.ae`, `name.com.ae`, and one Cyrillic homoglyph per matching letter, still checked with DNS only.

## Authorized extras

Nmap runs only after a person checks the authorization box, types the exact host, and `WEBCHECK_NMAP_ENABLED=true`. The host must resolve to one IP. Local and metadata addresses are refused. Flags are fixed profiles. None of them pass `-A`, `-O`, or `--script`.

Pentest routes run only when `WEBCHECK_PENTEST_ENABLED=true` and an engagement record matches the phrase `I am authorized to test <client>`, the date window, and the scope. Password spraying is not implemented, including when an engagement stores a test username and password for the single in-scope crawl login. `POST /api/v1/engagements/:id/spray` returns 403 and `spray-refused`.

## Reports and history

The PDF keeps the Cormorant header (navy `#0B1F33`, teal `#1F6F6A`, title “Cormorant Cyber”, subtitle “OSINT assessment · Dubai”). After the target and scan time it includes an executive summary, a prioritized remediation list ordered by the risk weights, and a risk-score trend drawn from that tenant's earlier snapshots. With fewer than two scored scans the trend section says no chart was drawn.

`/desk` has a read-only Target history panel. It calls `GET /api/v1/history?target=` and shows the tenant's scans, a bar for each risk score, and the latest findings. The same `x-api-key` gate as the rest of the desk applies.

## Monitor alerts

A monitor still records every diff. Email and Slack are sent only when the risk score worsens, a new subdomain appears, or a certificate name or SHA-256 fingerprint changes. Other diffs stay on the monitor record.

Delivery is a no-op when neither sink is configured. Slack uses `WEBCHECK_SLACK_WEBHOOK_URL` (or `SLACK_WEBHOOK_URL`). Email needs both `WEBCHECK_ALERT_EMAIL_TO` and `WEBCHECK_SMTP_HOST`. Optional: `WEBCHECK_SMTP_PORT` (465 is implicit TLS, 587 uses STARTTLS), `WEBCHECK_SMTP_USER`, `WEBCHECK_SMTP_PASS`, and `WEBCHECK_ALERT_EMAIL_FROM`. A failed delivery is stored on the monitor and does not fail the scan. Webhook URLs and SMTP settings are not written into the message.

## Dependency review

`POST /api/v1/audit/sbom` accepts a public GitHub URL or an uploaded manifest: `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `go.mod`, `Gemfile.lock`, `Cargo.lock`, `composer.lock`, `pom.xml`, CycloneDX, or SPDX. Exact `x.y.z` versions are kept, up to 40 packages. Ranges are listed under `skipped` and are not queried. The response includes a CycloneDX SBOM and OSV matches. Nothing is installed or executed.

## Tests

GitHub Actions runs `yarn lint` and `yarn test` on every pull request (`.github/workflows/cormorant.yml`, and the existing lint job in `ci.yml`).

```bash
yarn test
yarn build
```
