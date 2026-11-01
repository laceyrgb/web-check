import { finding } from '../findings.js';
import { REFS } from '../refs.js';

// Fixed risky set. This is a TCP connect or a passive record, never nmap, and never a full range.
export const PORT_FINDINGS = {
  21: ['medium', 'FTP is exposed', 'FTP مكشوف', 'Stop offering FTP, or restrict it. Prefer SFTP.'],
  23: [
    'critical',
    'Telnet is exposed',
    'Telnet مكشوف',
    'Disable Telnet. Use SSH from a restricted source if a shell is required.',
  ],
  110: [
    'medium',
    'Cleartext POP3 is exposed',
    'POP3 غير المشفّر مكشوف',
    'Disable cleartext POP3 and use the TLS port only.',
  ],
  143: [
    'medium',
    'Cleartext IMAP is exposed',
    'IMAP غير المشفّر مكشوف',
    'Disable cleartext IMAP and use the TLS port only.',
  ],
  445: ['high', 'SMB is exposed', 'SMB مكشوف', 'Block TCP 445 from the internet.'],
  1433: [
    'high',
    'MSSQL is exposed',
    'MSSQL مكشوف',
    'Remove SQL Server from the internet and require a private path.',
  ],
  3306: [
    'high',
    'MySQL is exposed',
    'MySQL مكشوف',
    'Remove MySQL from the internet and require a private path.',
  ],
  3389: [
    'high',
    'RDP is exposed',
    'RDP مكشوف',
    'Do not publish RDP directly. Put it behind a VPN or a locked gateway.',
  ],
  5432: [
    'high',
    'PostgreSQL is exposed',
    'PostgreSQL مكشوف',
    'Remove PostgreSQL from the internet.',
  ],
  5900: ['high', 'VNC is exposed', 'VNC مكشوف', 'Remove VNC from the internet.'],
  6379: [
    'high',
    'Redis is exposed',
    'Redis مكشوف',
    'Bind Redis to localhost or a private network and require authentication.',
  ],
  9200: [
    'high',
    'Elasticsearch is exposed',
    'Elasticsearch مكشوف',
    'Do not publish Elasticsearch to the internet.',
  ],
  27017: ['high', 'MongoDB is exposed', 'MongoDB مكشوف', 'Do not publish MongoDB to the internet.'],
};

export const ACTIVE_PORT_LIST = Object.keys(PORT_FINDINGS).map(Number);

const arRemediation = {
  21: 'أوقف FTP أو قيّده. فضّل SFTP.',
  23: 'عطّل Telnet. استخدم SSH من مصدر مقيّد إذا كانت الصدفة ضرورية.',
  110: 'عطّل POP3 غير المشفّر واستخدم منفذ TLS فقط.',
  143: 'عطّل IMAP غير المشفّر واستخدم منفذ TLS فقط.',
  445: 'احجب منفذ TCP 445 عن الإنترنت.',
  1433: 'أبعد SQL Server عن الإنترنت واشترط مسارًا خاصًا.',
  3306: 'أبعد MySQL عن الإنترنت واشترط مسارًا خاصًا.',
  3389: 'لا تنشر RDP مباشرة. ضعه خلف VPN أو بوابة مقفلة.',
  5432: 'أبعد PostgreSQL عن الإنترنت.',
  5900: 'أبعد VNC عن الإنترنت.',
  6379: 'اربط Redis بالجهاز المحلي أو بشبكة خاصة واشترط المصادقة.',
  9200: 'لا تنشر Elasticsearch على الإنترنت.',
  27017: 'لا تنشر MongoDB على الإنترنت.',
};

export const analysePorts = (ports, source) => {
  const list = Array.isArray(ports) ? ports : [];
  const out = [];
  const seen = new Set();
  for (const entry of list) {
    const port = Number(typeof entry === 'object' ? entry.port : entry);
    if (!PORT_FINDINGS[port] || seen.has(port)) continue;
    seen.add(port);
    const [severity, title, titleAr, remediation] = PORT_FINDINGS[port];
    out.push(
      finding({
        id: `ports.${port}`,
        title,
        titleAr,
        severity,
        evidence:
          source === 'passive'
            ? `Port ${port} was present in supplied passive data. This run did not connect to it.`
            : `A TCP connection to port ${port} succeeded. No protocol payload was sent.`,
        remediation,
        remediationAr: arRemediation[port],
        references: [REFS.mozillaTls],
        service: 'attack-surface',
        needsHumanReview: true,
      }),
    );
  }
  return out;
};
