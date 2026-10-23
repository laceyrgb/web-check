import { buildExecutiveSummary, prioritizeRemediations } from './risk.js';

const loadPdf = async () => {
  const pdfkit = await import('pdfkit');
  return pdfkit.default || pdfkit;
};

const section = (pdf, title, lines) => {
  pdf.moveDown(0.6);
  pdf.fillColor('#1F6F6A').fontSize(13).text(title);
  pdf.fillColor('#1c1c1c').fontSize(10);
  for (const line of lines.filter(Boolean)) pdf.text(line, { width: 500 });
};

const drawTrend = (pdf, points) => {
  const rows = (points || []).filter((point) => typeof point.riskScore === 'number');
  section(
    pdf,
    'Risk score trend',
    rows.length < 2
      ? ['Fewer than two scored scans are on file, so no chart is drawn.']
      : rows.map((point) => `${point.scannedAt}: ${point.riskScore}`),
  );
  if (rows.length < 2) return;
  const left = 48;
  const width = 500;
  const height = 90;
  const top = pdf.y + 8;
  pdf.save();
  pdf.lineWidth(1).strokeColor('#1F6F6A').rect(left, top, width, height).stroke();
  rows.forEach((point, index) => {
    const x = left + (width * index) / (rows.length - 1);
    const y = top + height - (point.riskScore / 100) * height;
    if (index === 0) pdf.moveTo(x, y);
    else pdf.lineTo(x, y);
  });
  pdf.strokeColor('#0B1F33').lineWidth(2).stroke();
  pdf.restore();
  pdf.x = left;
  pdf.y = top + height + 10;
};

export const renderReport = async (report) => {
  const PDFDocument = await loadPdf();
  return new Promise((resolve, reject) => {
    const pdf = new PDFDocument({ size: 'A4', margin: 48, compress: false });
    const chunks = [];
    pdf.on('data', (chunk) => chunks.push(chunk));
    pdf.on('end', () => resolve(Buffer.concat(chunks)));
    pdf.on('error', reject);
    pdf.rect(0, 0, pdf.page.width, 72).fill('#0B1F33');
    pdf.fillColor('#ffffff').fontSize(20).text('Cormorant Cyber', 48, 24);
    pdf.fontSize(10).text('OSINT assessment · Dubai', 48, 48);
    pdf.fillColor('#1c1c1c');
    pdf.y = 96;
    pdf.fontSize(11).text(`Target: ${report.target || 'unknown'}`);
    pdf.text(`Scan time: ${report.scannedAt || 'unknown'}`);
    if (report.id) pdf.text(`Scan id: ${report.id}`);
    section(pdf, 'Executive summary', report.executiveSummary || buildExecutiveSummary(report));
    const remediations = report.remediations || prioritizeRemediations(report);
    section(
      pdf,
      'Prioritized remediation',
      remediations.length
        ? remediations.map((item, index) => `${index + 1}. [${item.source}] ${item.action}`)
        : ['No weighted findings produced a remediation.'],
    );
    drawTrend(pdf, report.trend);
    const surface = report.attackSurface;
    if (surface) {
      section(pdf, 'Attack surface', [
        `Passive hostnames: ${surface.hostCount ?? 0}`,
        surface.subdomainError ? `Subdomain note: ${surface.subdomainError}` : '',
        `Open common ports: ${(surface.ports?.open || []).join(', ') || 'none observed'}`,
        `Technologies: ${(surface.technologies || []).map((item) => `${item.name}${item.version ? ` ${item.version}` : ''}`).join(', ') || 'none disclosed'}`,
        ...(surface.citations || []).map((item) => `Source: ${item.name} ${item.url}`),
      ]);
    }
    section(
      pdf,
      'CVEs',
      (report.cves?.findings || [])
        .slice(0, 20)
        .map(
          (item) =>
            `${item.id} ${item.severity} ${item.product || ''} ${item.version || ''} ${item.url}`,
        )
        .concat((report.cves?.skipped || []).map((item) => item.message)),
    );
    section(
      pdf,
      'Breaches',
      (report.breaches?.emails || []).flatMap((row) =>
        row.breaches?.length
          ? row.breaches.map(
              (item) => `${row.email} appeared in public breach ${item.name} (${item.url})`,
            )
          : [`${row.email}: ${row.status}`],
      ),
    );
    if (report.exposure) {
      section(pdf, 'Network exposure', [
        report.exposure.ip ? `IP: ${report.exposure.ip}` : '',
        report.exposure.geo?.country
          ? `GeoIP: ${[report.exposure.geo.city, report.exposure.geo.country].filter(Boolean).join(', ')} (${report.exposure.geo.source || ''})`
          : '',
        report.exposure.cloud
          ? `Cloud heuristic: ${report.exposure.cloud}`
          : 'No cloud provider matched the public org string.',
        `Same-IP names: ${
          (report.exposure.neighbors || [])
            .map((item) => item.host)
            .slice(0, 15)
            .join(', ') || 'none'
        }`,
        report.exposure.shodan?.note ||
          (report.exposure.shodan?.status === 'ok'
            ? `Shodan ports: ${(report.exposure.shodan.ports || []).join(', ')}`
            : ''),
        report.exposure.censys?.note || '',
      ]);
    }
    if (report.lookalikes)
      section(pdf, 'Lookalike domains', [
        `Resolving: ${(report.lookalikes.live || []).join(', ') || 'none'}`,
        report.lookalikes.note,
      ]);
    if (report.mentions) {
      section(pdf, 'Public mentions', [
        report.mentions.sentiment?.summary,
        ...(report.mentions.news || []).map((item) => `${item.title} ${item.url}`),
        ...(report.mentions.leaks || []).map((item) => `${item.source}: ${item.title} ${item.url}`),
      ]);
    }
    if (report.posture)
      section(pdf, 'Posture', [
        `${report.posture.letter} (${report.posture.score})`,
        ...(report.posture.remediations || []),
      ]);
    if (report.cms)
      section(pdf, 'CMS fingerprint', [
        `${report.cms.cms || 'none observed'}${report.cms.version ? ` ${report.cms.version}` : ''}`,
        report.cms.note,
      ]);
    if (report.privacy)
      section(pdf, 'Privacy and accessibility heuristics', report.privacy.notes || []);
    if (report.buckets)
      section(
        pdf,
        'Public storage references',
        (report.buckets.buckets || [])
          .map((item) => `${item.access} ${item.url}`)
          .concat([report.buckets.note]),
      );
    if (report.people)
      section(
        pdf,
        'Public role notes',
        (report.people.people || []).map(
          (item) => `${item.name || item.status} ${item.url || ''} ${item.reason || ''}`,
        ),
      );
    if (report.history?.changes?.length)
      section(
        pdf,
        'Changes since the previous snapshot',
        report.history.changes.map((item) => `${item.type}: ${item.value}`),
      );
    if (report.risk)
      section(pdf, 'Risk score', [
        `${report.risk.score} (${report.risk.letter})`,
        report.risk.note,
        ...(report.risk.factors || []).map(
          (item) => `${item.source}: ${item.detail} (-${item.points})`,
        ),
      ]);
    if (report.nmap) {
      section(pdf, 'Authorized port scan', [
        `Operator: ${report.nmap.operator || 'recorded on the authorization'}`,
        `Authorized at: ${report.nmap.authorizedAt || ''}`,
        `Flags: ${(report.nmap.flags || []).join(' ')}`,
        ...(report.nmap.hosts || []).flatMap((host) =>
          (host.ports || []).map(
            (port) =>
              `${host.address} ${port.port}/${port.protocol} ${port.state} ${port.service || ''} ${port.product || ''} ${port.version || ''}`,
          ),
        ),
      ]);
    }
    if (report.assets) {
      section(
        pdf,
        'Asset inventory',
        Object.values(report.assets.items || {})
          .slice(0, 40)
          .map(
            (item) => `${item.kind} ${item.value} first ${item.firstSeen} last ${item.lastSeen}`,
          ),
      );
    }
    pdf.moveDown();
    pdf
      .fontSize(8)
      .fillColor('#444')
      .text(
        'Findings are limited to data collected for this scan. Sources are named in each section. Cormorant Cyber does not treat a missing finding as proof of safety.',
      );
    pdf.end();
  });
};
