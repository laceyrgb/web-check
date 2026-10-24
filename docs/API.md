# OSINT Desk API

Base path: `/api/v1`.

Machine-readable index: `GET /api/v1/openapi.json`.

## Authentication

When neither `WEBCHECK_API_KEY` nor `WEBCHECK_TENANT_KEYS` is set, routes are open for local use and every record is stored on the `default` tenant. When either is set, every route except `GET /api/v1` and `GET /api/v1/openapi.json` requires `x-api-key` or `Authorization: Bearer`.

`WEBCHECK_API_KEY` maps to tenant `default`. `WEBCHECK_TENANT_KEYS` is `tenant:key` pairs separated by commas. A tenant id is 1–41 characters, starting with a letter or digit, then letters, digits, or hyphens. The key may contain colons. A presented key is compared in constant time and selects that tenant for the request. List and get routes return only that tenant's scans, bulk jobs, monitors, timeline, assets, authorizations, Nmap jobs, engagements, and screenshots. Existing JSON written before this field existed is migrated to `default` on load.

## Environment

| Variable                                    | Effect when unset                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------ |
| `WEBCHECK_API_KEY`                          | API is open unless `WEBCHECK_TENANT_KEYS` is set. This key is tenant `default` |
| `WEBCHECK_TENANT_KEYS`                      | No extra tenants. Format `acme:secret,other:secret`                            |
| `WEBCHECK_DATA_DIR`                         | Store files in `./.data`                                                       |
| `WEBCHECK_EXPORT_DIR`                       | Drive export is refused. Download `/api/v1/export.zip` instead                 |
| `WEBCHECK_SCAN_CONCURRENCY`                 | One scan at a time                                                             |
| `WEBCHECK_DISABLE_SCHEDULER`                | Monitor timer runs                                                             |
| `HIBP_API_KEY`                              | Email checks use the public XposedOrNot index                                  |
| `NVD_API_KEY`                               | NVD is queried slowly and capped at three products                             |
| `SHODAN_API_KEY`                            | Shodan host lookup is skipped. InternetDB still runs                           |
| `CENSYS_API_TOKEN`                          | Censys is skipped unless `CENSYS_API_ID` and `CENSYS_API_SECRET` are both set  |
| `GITHUB_TOKEN`                              | GitHub code search is skipped. searchcode still runs                           |
| `CERTSPOTTER_TOKEN`                         | Cert Spotter is queried anonymously                                            |
| `WEBCHECK_NMAP_ENABLED`                     | Nmap routes refuse                                                             |
| `WEBCHECK_NMAP_CONCURRENCY`                 | One Nmap job                                                                   |
| `WEBCHECK_NMAP_TIMEOUT_MS`                  | 180000                                                                         |
| `WEBCHECK_PENTEST_ENABLED`                  | Engagement routes refuse                                                       |
| `WEBCHECK_NUCLEI_MAX_SEVERITY`              | Nuclei severity cap is `medium`                                                |
| `WEBCHECK_SLACK_WEBHOOK_URL`                | Slack alerts are skipped. `SLACK_WEBHOOK_URL` is an alias                      |
| `WEBCHECK_ALERT_EMAIL_TO`                   | Email alerts are skipped                                                       |
| `WEBCHECK_SMTP_HOST`                        | Email alerts are skipped even if a recipient is set                            |
| `WEBCHECK_SMTP_PORT`                        | 587, which uses STARTTLS. Port 465 is implicit TLS                             |
| `WEBCHECK_SMTP_USER` / `WEBCHECK_SMTP_PASS` | SMTP AUTH is skipped                                                           |
| `WEBCHECK_ALERT_EMAIL_FROM`                 | From address is `cormorant@localhost`                                          |

Shodan and Censys calls are read-only host lookups. Errors do not include the key. Missing keys are reported as skipped, not as findings.

## Scans

```bash
curl -s -X POST localhost:3000/api/v1/scans \
  -H 'content-type: application/json' \
  -d '{"target":"example.com"}'
```

Response `202` with `{ "id", "status": "queued" }`. Poll `GET /api/v1/scans/:id` until `complete`, then `GET /api/v1/scans/:id/results`.

`GET /api/v1/scans/:id/report.pdf` returns the Cormorant PDF. `GET /api/v1/report.pdf?url=example.com` runs a scan and returns the PDF. Optional `nmap=<job id>` attaches an authorized port-scan section only when that completed job is for the same host and the same tenant. The PDF includes the executive summary, a remediation list ordered by severity weight, and the risk-score trend for that tenant.

Results include `risk` (`score`, `letter`, `factors`), `history.changes`, `assets`, and `dossier`. If no module returned data, `risk.score` is null and `risk.letter` is `n/a`.

`dossier` is the owner pivot. `progression` is the order of public discoveries. `contacts`, `people`, `organization`, `mailProvider`, `publicKeys`, and `news` are only values a source actually returned. `emailsDiscovered` lists addresses that were not on the first page pass and were then breach-checked. `stopped` is `no-new-identifiers`, `round-cap`, or `lookup-cap`. The loop does not scan a newly seen domain and does not query a people-search site with a person name.

`records` is the public record: `mail`, `documents`, `certificates`, and `findings`. The same payload is available without starting a scan:

```bash
curl -s 'localhost:3000/api/v1/records?target=example.com'
```

It reads SPF, DMARC, TLS-RPT, BIMI, MTA-STS, and five published DKIM selectors. It fetches at most three PDF or DOCX links from the page when they stay on the registrable domain. It reads crt.sh for issuers and upcoming expirations. A DNS error is reported on that lookup and is not scored as a missing policy. Document authors are not used as search terms.

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

`everyMinutes` is 15 to 10080. `schedule` accepts `every:30m`, `every:12h`, or `every:1d`. Creating a monitor queues the first scan. Later runs are compared with the previous snapshot for that tenant. Recorded diff types: `new-subdomain`, `new-cert-name`, `cert-change`, `new-cve`, `new-open-service`, `new-leak-mention`, `new-lookalike`, `dns-change`, `mail-policy-change`, `risk-worse`, `posture-worse`. The first snapshot is a baseline and has no diffs.

Slack and email are sent only for `risk-worse`, `new-subdomain`, `new-cert-name`, and `cert-change`. The monitor stores `alert` and `alertDelivery`. When no sink is configured, `alertDelivery.skipped` is `unconfigured` and nothing is sent.

`GET /api/v1/timeline?target=example.com` returns snapshots and those diffs.

`GET /api/v1/history?target=example.com` is read-only. It returns `{ target, tenant, scans, trend, latestFindings }` for the caller's tenant. `scans` is the latest 30 jobs with status and risk. `trend` is `{ scannedAt, riskScore }`. `latestFindings` is the newest completed scan's risk, executive summary, and changes, or null.

## Offline export

```bash
curl -s -X POST localhost:3000/api/v1/export \
  -H 'content-type: application/json' \
  -H 'x-api-key: ...' \
  -d '{"removeLocal":true}'
```

Requires `WEBCHECK_EXPORT_DIR` to be the mount path of a USB stick or external drive. The response `directory` is the folder written on that drive. `removeLocal: true` deletes the exported scans and related records from the server only after `COMPLETE` is on the drive. Omit it to keep the server copy.

`GET /api/v1/export.zip` returns the same files as a zip and does not delete anything. Optional `?target=example.com` limits either call to one host. Passwords, API keys, and session cookies are omitted.

`GET /api/v1/assets?target=example.com` returns deduped hosts, IPs, services, technologies, published emails, document authors, and certificate-log names with `firstSeen` and `lastSeen`.

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

`POST /api/v1/engagements/:id/spray` always returns `403` and `{ "code": "spray-refused" }`. Storing `testUsername` and `testPassword` does not change that. Those two fields are used only for one in-scope login during crawl. Password spraying is not available.

## Other routes

`POST /api/v1/people` with `{ "publicUrls": [] }` reads pages you supply. A login wall is reported as unavailable.

`POST /api/v1/audit/sbom` accepts `{ "filename", "content" }` or `{ "repo": "https://github.com/org/name" }`. Supported files are `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `go.mod`, `Gemfile.lock`, `Cargo.lock`, `composer.lock`, `pom.xml`, CycloneDX JSON, and SPDX JSON. A public GitHub URL is fetched from `raw.githubusercontent.com` at `HEAD` and tries those filenames in that order. Only exact versions are queried, at most 40. The JSON body is `{ findings, sbom, skipped, note }`. `sbom` is CycloneDX 1.5. Nothing is installed. A `githubToken` is taken from the request or from an engagement secret in the same tenant and is not returned.

`POST /api/v1/audit/apk` accepts `{ "storeUrl" }` for play.google.com or apps.apple.com, or `{ "base64" }` under 8MB. The APK is not installed. Permissions, text-manifest exported components, and redacted secret previews are returned.

`POST /api/v1/screenshots` archives a public page when robots.txt allows it. `GET /api/v1/screenshots/:id.png` serves the PNG.

## Honesty

Empty CVE, breach, leak, and port lists mean those sources did not return a match. They are not a statement that the target is safe. Routing history is BGP visibility, not a full hosting ledger. Lookalike domains that resolve are marked for review, not labeled malicious.
