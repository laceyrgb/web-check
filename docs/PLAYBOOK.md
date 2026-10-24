# Cormorant playbook

Use this with a client who knows the work is happening. Passive modules read public sources. Authorized modules stay off until the gates in `docs/API.md` are satisfied.

## Passive recon

1. Start a scan from `/desk` or `POST /api/v1/scans`. Open `/project` for that host when you also want the full Web Check report and the category checkers. The map links those pages. It does not start a scan. To run a pile of links, paste them under Link list, or use Harvest this page. The desk keeps one host once and skips hosts this tenant already queued or finished. Read `alreadyScanned` before assuming a name was missed. Harvest reads the requested page and public subdomain names. It does not walk every link it finds.
2. Read the attack-surface card for hostnames, common ports, and disclosed technologies. Citations name the index that supplied each host.
3. Read known CVEs only where a version was disclosed. Skipped products say why.
4. Read network exposure for GeoIP, ASN, reverse DNS, and same-IP neighbors. Shodan and Censys appear only when their keys are configured.
5. Read public mentions for news and code or paste-index links. Open the link. The desk does not store the paste.
6. Read lookalikes that resolve and decide, as a person, whether they matter.
7. Read the posture letter and the remediation lines. They are configuration advice.
8. Read the owner dossier. It starts from whatever the first pass actually found. A published phone can lead to an email in `security.txt` or RDAP, and that email can lead to a breach record, a Gravatar name, or a public key. The progression lines state which source added each fact. A name is kept when it appears on the target page or in those public profiles. It is not used to search for a private individual.
9. Read the public record on the scan, or use Read public record on `/desk` (`GET /api/v1/records`). Check DMARC and SPF first. Then read authors and local paths in PDF or Word files the site already links. Then read certificate-log names and anything expiring within 30 days. `.ae` and `.com.ae` lookalikes are in the lookalike list with the ASCII ones.
10. Download the PDF from the results page or `GET /api/v1/scans/:id/report.pdf`. Read the executive summary, then the remediation list from the top, then the risk trend, then the owner dossier and the public record.
11. On `/desk`, choose the target and use Load history. That view only reads `GET /api/v1/history` for the signed-in tenant.
12. When the assessment should leave the web server, mount the USB or external drive, set `WEBCHECK_EXPORT_DIR`, and use Save to external drive with removal checked. Take the drive. The folder's `index.html` is the offline report. A zip download is for a drive attached to the workstation and does not remove the server copy by itself.

## Monitoring

Create a monitor with an interval of at least 15 minutes. The first run is the baseline and does not alert. Later runs record a new hostname, certificate name, certificate fingerprint, CVE, open service, leak link, or live lookalike, plus DNS changes, a lower risk score, or a posture drop of more than five points.

Email and Slack fire only for a worse risk score, a new subdomain, or a new or changed certificate. Set `WEBCHECK_SLACK_WEBHOOK_URL` or both `WEBCHECK_ALERT_EMAIL_TO` and `WEBCHECK_SMTP_HOST`. Leave them unset and the monitor still saves the diff without sending anything.

The asset inventory on `GET /api/v1/assets` updates from those scans. `firstSeen` stays on the earliest observation. Another tenant's key does not see this inventory.

Give each client its own entry in `WEBCHECK_TENANT_KEYS`. The original `WEBCHECK_API_KEY` remains the default tenant, which is also where older data files land.

## Authorized port scan

1. Confirm the engagement covers that exact host.
2. Check the box and type the host exactly.
3. Set `WEBCHECK_NMAP_ENABLED=true` only on the host where `nmap` is installed.
4. Queue the default TCP connect profile. Use `version` or `deeper` when you need service versions. Use `syn` only as root.
5. Put the completed job on the PDF with `?nmap=<job id>` when the job target matches the report.

## Pentest mode

Turn on `WEBCHECK_PENTEST_ENABLED` only for an engagement with a written authorization, a scope list, and dates. Crawl and Nuclei refuse hosts outside that scope. Nuclei stays at medium and below unless `WEBCHECK_NUCLEI_MAX_SEVERITY` is raised, and exploit tags stay excluded either way.

Export the simulation template into the client's own awareness platform. Do not send it from this server.

Do not look for a password spray. The route is a refusal even after test credentials are saved for the crawl.

## Mobile and dependencies

Upload an APK you are allowed to review, or paste a public Play or App Store URL. The review is static. Secret values are shortened to a preview.

For dependencies, paste a manifest or a public GitHub URL. Accepted manifests include `package.json`, `requirements.txt`, `go.mod`, and the lockfiles listed in `docs/API.md`. OSV results cover exact versions the file names, up to 40. Ranges are reported as skipped. The response includes the CycloneDX SBOM. Nothing is installed, and the review does not attempt the vulnerabilities it lists.

## What this does not do

It does not exploit findings, brute-force names, log into LinkedIn, buy breach data, or scan onion services. Absence of a finding is not evidence of safety.
