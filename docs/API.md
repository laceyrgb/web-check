# OSINT Desk API

Base path: `/api/v1`.

Machine-readable index: `GET /api/v1/openapi.json`.

## Authentication

When `WEBCHECK_API_KEY` is unset, routes are open for local use. When it is set, every route except `GET /api/v1` and `GET /api/v1/openapi.json` requires the same value in `x-api-key` or `Authorization: Bearer`.

## Environment

| Variable | Effect when unset |
| --- | --- |
| `WEBCHECK_API_KEY` | API is open |
| `WEBCHECK_DATA_DIR` | Store files in `./.data` |
| `WEBCHECK_SCAN_CONCURRENCY` | One scan at a time |
| `WEBCHECK_DISABLE_SCHEDULER` | Monitor timer runs |
| `HIBP_API_KEY` | Email checks use the public XposedOrNot index |
| `NVD_API_KEY` | NVD is queried slowly and capped at three products |
| `SHODAN_API_KEY` | Shodan host lookup is skipped. InternetDB still runs |
| `CENSYS_API_TOKEN` | Censys is skipped unless `CENSYS_API_ID` and `CENSYS_API_SECRET` are both set |
| `GITHUB_TOKEN` | GitHub code search is skipped. searchcode still runs |
| `CERTSPOTTER_TOKEN` | Cert Spotter is queried anonymously |
| `WEBCHECK_NMAP_ENABLED` | Nmap routes refuse |
| `WEBCHECK_NMAP_CONCURRENCY` | One Nmap job |
| `WEBCHECK_NMAP_TIMEOUT_MS` | 180000 |
| `WEBCHECK_PENTEST_ENABLED` | Engagement routes refuse |
| `WEBCHECK_NUCLEI_MAX_SEVERITY` | Nuclei severity cap is `medium` |

Shodan and Censys calls are read-only host lookups. Errors do not include the key. Missing keys are reported as skipped, not as findings.

## Scans

```bash
curl -s -X POST localhost:3000/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{"target":"example.com"}'
```

Response `202` with `{ "id", "status": "queued" }`. Poll `GET /api/v1/scans/:id` until `complete`, then `GET /api/v1/scans/:id/results`.

`GET /api/v1/scans/:id/report.pdf` returns the Cormorant PDF. `GET /api/v1/report.pdf?url=example.com` runs a scan and returns the PDF. Optional `nmap=<job id>` attaches an authorized port-scan section only when that completed job is for the same host.

Results include `risk` (`score`, `letter`, `factors`), `history.changes`, and `assets`. If no module returned data, `risk.score` is null and `risk.letter` is `n/a`.

Bulk, up to 20 hosts:

```bash
curl -s -X POST localhost:3000/api/v1/bulk \
  -H 'content-type: application/json' \
  -d '{"domains":["example.com","example.org"]}'
```

Poll `GET /api/v1/bulk/:id`.

## Monitoring, timeline, inventory

```bash
curl -s -X POST localhost:3000/api/v1/monitors \
  -H 'content-type: application/json' \
  -d '{"target":"example.com","everyMinutes":1440}'
```

`everyMinutes` is 15 to 10080. `schedule` accepts `every:30m`, `every:12h`, or `every:1d`. Creating a monitor queues the first scan. Later runs are compared with the previous snapshot. Alert types: `new-subdomain`, `new-cert-name`, `new-cve`, `new-open-service`, `new-leak-mention`, `new-lookalike`, `dns-change`, `risk-worse`, `posture-worse`.

`GET /api/v1/timeline?target=example.com` returns snapshots and those diffs.

`GET /api/v1/assets?target=example.com` returns deduped hosts, IPs, services, technologies, and published emails with `firstSeen` and `lastSeen`.

`GET /api/v1/monitors`, `DELETE /api/v1/monitors/:id`, `POST /api/v1/monitors/:id/run`.

Leak monitoring stores links from public paste and code indexes. Paste bodies are not saved.

## Authorized Nmap

Never started by a plain scan.

```bash
curl -s -X POST localhost:3000/api/v1/authorizations \
  -H 'content-type: application/json' \
  -d '{"target":"203.0.113.10","confirm":"203.0.113.10","operator":"Casey","acknowledged":true}'

curl -s -X POST localhost:3000/api/v1/nmap \
  -H 'content-type: application/json' \
  -d '{"authorizationId":"<id>","profile":"default"}'
```

`confirm` must equal the canonical host. The host must resolve to exactly one IP. `127.0.0.1`, localhost, and metadata addresses are refused. A private address is accepted only when that exact IP was authorized.

Profiles, with no user-supplied flags:

- `default`: `-sT -Pn --top-ports 100 -T2 --max-retries 1 --max-rate 50 --host-timeout 120s --open -oX - <ip>`
- `version`: the default profile plus `-sV --version-light` and a 180s host timeout
- `deeper`: `--top-ports 1000 -sV --version-light --max-rate 40 --host-timeout 300s`
- `syn`: `-sS` instead of `-sT`, only when the process is root

If `nmap` is missing the route returns 503 with install instructions. Poll `GET /api/v1/nmap/:id`.

## Pentest engagement

Requires `WEBCHECK_PENTEST_ENABLED=true`, a client name, operator, checkbox, scope, start and end, and `confirm` equal to `I am authorized to test <client>`.

```bash
curl -s -X POST localhost:3000/api/v1/engagements \
  -H 'content-type: application/json' \
  -d '{"clientName":"Acme","operator":"Casey","acknowledged":true,"confirm":"I am authorized to test Acme","scope":["example.com"],"start":"2026-10-01","end":"2026-12-31"}'
```

`GET /api/v1/engagements/:id` returns the scope record and not the secrets.

`POST /api/v1/engagements/:id/secrets` accepts only `sessionCookie`, `loginUrl`, `usernameField`, `passwordField`, `testUsername`, `testPassword`, and `githubToken`.

`POST /api/v1/engagements/:id/crawl` with `{ "startUrl" }` crawls in-scope URLs, honors robots.txt, and reports form field names and cookie flags. Cookie and password values are not returned.

`POST /api/v1/engagements/:id/nuclei` runs Nuclei only if it is installed. Arguments are `-severity` up to the cap, `-exclude-tags dos,fuzz,intrusive,exploit,rce,sqli`, `-ni`, `-silent`, `-jsonl`, `-timeout 10`, `-rate-limit 10`, `-bulk-size 5`. Request and response bodies are dropped.

`POST /api/v1/engagements/:id/simulation` returns a labeled training template with `{{SIMULATION_URL}}` and `{{RECIPIENT_ID}}`. It does not send mail and it has no form.

`POST /api/v1/engagements/:id/spray` always returns `403` and `{ "code": "spray-refused" }`. Password spraying is not available.

## Other routes

`POST /api/v1/people` with `{ "publicUrls": [] }` reads pages you supply. A login wall is reported as unavailable.

`POST /api/v1/audit/sbom` accepts `{ "filename", "content" }` or `{ "repo": "https://github.com/org/name" }` and queries the public OSV API.

`POST /api/v1/audit/apk` accepts `{ "storeUrl" }` for play.google.com or apps.apple.com, or `{ "base64" }` under 8MB. The APK is not installed. Permissions, text-manifest exported components, and redacted secret previews are returned.

`POST /api/v1/screenshots` archives a public page when robots.txt allows it. `GET /api/v1/screenshots/:id.png` serves the PNG.

## Honesty

Empty CVE, breach, leak, and port lists mean those sources did not return a match. They are not a statement that the target is safe. Routing history is BGP visibility, not a full hosting ledger. Lookalike domains that resolve are marked for review, not labeled malicious.
