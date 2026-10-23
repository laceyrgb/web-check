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

State is a JSON file under `WEBCHECK_DATA_DIR` (default `.data`). Engagement secrets live in a separate file with mode `0600` and are never returned by GET.

## Tenants

Each API key belongs to one tenant. `WEBCHECK_API_KEY` is the `default` tenant. `WEBCHECK_TENANT_KEYS` is a comma-separated `tenant:key` list for additional clients. Scans, monitors, assets, timelines, authorizations, engagements, and screenshots are stored under that tenant and are not returned to another key. A store written before tenants existed is loaded under `default`.

When no key is set, the API stays open and every record uses `default`. That is the local development mode.

## External keys

These modules call the real API when the key is present and skip or fall back when it is unset. The key is not copied into errors or results.

| Variable | When set | When unset |
| --- | --- | --- |
| `HIBP_API_KEY` | Have I Been Pwned breached-account lookup | Public XposedOrNot index |
| `NVD_API_KEY` | NVD CPE match with the higher quota | Same CPE match, slower, still capped at three products |
| `SHODAN_API_KEY` | Read-only Shodan host lookup | Skipped. InternetDB still runs and does not need a key |
| `CENSYS_API_TOKEN` | Read-only Censys Platform host lookup | Falls back to `CENSYS_API_ID` plus `CENSYS_API_SECRET`, then skipped |

Unknown product versions are not sent to NVD. Shodan and Censys are lookups of an address the scan already resolved. They do not submit a scan.

## What a plain scan does

`POST /api/v1/scans` collects public data only: certificate transparency hostnames, common-port observations, disclosed technologies, NVD matches, public breach indexes, GeoIP and RDAP, reverse DNS and same-IP neighbors, optional Shodan or Censys host lookups, public paste and code-index links, lookalikes, news mentions, header and TLS posture, CMS version clues, public bucket URLs already in the HTML, and public profile links. It then writes a risk score, a diff against the previous snapshot, and an asset inventory.

It does not run Nmap, Nuclei, an authenticated crawl, or anything that tries passwords.

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
