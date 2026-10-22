# Cormorant playbook

Use this with a client who knows the work is happening. Passive modules read public sources. Authorized modules stay off until the gates in `docs/API.md` are satisfied.

## Passive recon

1. Start a scan from `/desk` or `POST /api/v1/scans`.
2. Read the attack-surface card for hostnames, common ports, and disclosed technologies. Citations name the index that supplied each host.
3. Read known CVEs only where a version was disclosed. Skipped products say why.
4. Read network exposure for GeoIP, ASN, reverse DNS, and same-IP neighbors. Shodan and Censys appear only when their keys are configured.
5. Read public mentions for news and code or paste-index links. Open the link. The desk does not store the paste.
6. Read lookalikes that resolve and decide, as a person, whether they matter.
7. Read the posture letter and the remediation lines. They are configuration advice.
8. Download the PDF from the results page or `GET /api/v1/scans/:id/report.pdf`.

## Monitoring

Create a monitor with an interval of at least 15 minutes. The first run is the baseline and does not alert. Later runs alert when a hostname, certificate name, CVE, open service, leak link, or live lookalike is new, or when DNS changes, the risk score drops, or posture drops by more than five points.

The asset inventory on `GET /api/v1/assets` updates from those scans. `firstSeen` stays on the earliest observation.

## Authorized port scan

1. Confirm the engagement covers that exact host.
2. Check the box and type the host exactly.
3. Set `WEBCHECK_NMAP_ENABLED=true` only on the host where `nmap` is installed.
4. Queue the default TCP connect profile. Use `version` or `deeper` when you need service versions. Use `syn` only as root.
5. Put the completed job on the PDF with `?nmap=<job id>` when the job target matches the report.

## Pentest mode

Turn on `WEBCHECK_PENTEST_ENABLED` only for an engagement with a written authorization, a scope list, and dates. Crawl and Nuclei refuse hosts outside that scope. Nuclei stays at medium and below unless `WEBCHECK_NUCLEI_MAX_SEVERITY` is raised, and exploit tags stay excluded either way.

Export the simulation template into the client's own awareness platform. Do not send it from this server.

Do not look for a password spray. The route is a refusal.

## Mobile and dependencies

Upload an APK you are allowed to review, or paste a public Play or App Store URL. The review is static. Secret values are shortened to a preview.

For dependencies, paste a lockfile or a public GitHub URL. OSV results are limited to packages the file actually names.

## What this does not do

It does not exploit findings, brute-force names, log into LinkedIn, buy breach data, or scan onion services. Absence of a finding is not evidence of safety.
