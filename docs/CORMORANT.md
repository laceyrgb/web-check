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

## What a plain scan does

`POST /api/v1/scans` collects public data only: certificate transparency hostnames, common-port observations, disclosed technologies, NVD matches, public breach indexes, GeoIP and RDAP, reverse DNS and same-IP neighbors, optional Shodan or Censys host lookups, public paste and code-index links, lookalikes, news mentions, header and TLS posture, CMS version clues, public bucket URLs already in the HTML, and public profile links. It then writes a risk score, a diff against the previous snapshot, and an asset inventory.

It does not run Nmap, Nuclei, an authenticated crawl, or anything that tries passwords.

## Authorized extras

Nmap runs only after a person checks the authorization box, types the exact host, and `WEBCHECK_NMAP_ENABLED=true`. The host must resolve to one IP. Local and metadata addresses are refused. Flags are fixed profiles. None of them pass `-A`, `-O`, or `--script`.

Pentest routes run only when `WEBCHECK_PENTEST_ENABLED=true` and an engagement record matches the phrase `I am authorized to test <client>`, the date window, and the scope. Password spraying is not implemented. `POST /api/v1/engagements/:id/spray` returns 403.

## Tests

```bash
yarn test
yarn build
```
