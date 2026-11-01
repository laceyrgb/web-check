// Public references cited from findings. Titles are short on purpose; the URL is the source.
export const ref = (title, url) => ({ title, url });

export const REFS = {
  spf: ref('RFC 7208, SPF', 'https://www.rfc-editor.org/rfc/rfc7208'),
  dmarc: ref('RFC 7489, DMARC', 'https://www.rfc-editor.org/rfc/rfc7489'),
  dkim: ref('RFC 6376, DKIM', 'https://www.rfc-editor.org/rfc/rfc6376'),
  mtaSts: ref('RFC 8461, MTA-STS', 'https://www.rfc-editor.org/rfc/rfc8461'),
  tlsRpt: ref('RFC 8460, TLS reporting', 'https://www.rfc-editor.org/rfc/rfc8460'),
  bimi: ref('BIMI group', 'https://bimigroup.org/'),
  dane: ref('RFC 7672, SMTP DANE', 'https://www.rfc-editor.org/rfc/rfc7672'),
  nullMx: ref('RFC 7505, null MX', 'https://www.rfc-editor.org/rfc/rfc7505'),
  dnssec: ref('RFC 4033, DNSSEC', 'https://www.rfc-editor.org/rfc/rfc4033'),
  caa: ref('RFC 8659, CAA', 'https://www.rfc-editor.org/rfc/rfc8659'),
  hsts: ref('RFC 6797, HSTS', 'https://www.rfc-editor.org/rfc/rfc6797'),
  csp: ref('MDN: Content-Security-Policy', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'),
  cors: ref('MDN: CORS', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'),
  cookies: ref('MDN: Cookies', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'),
  frame: ref(
    'MDN: X-Frame-Options',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
  ),
  nosniff: ref(
    'MDN: X-Content-Type-Options',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
  ),
  referrer: ref(
    'MDN: Referrer-Policy',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
  ),
  mozillaTls: ref('Mozilla SSL configuration', 'https://ssl-config.mozilla.org/'),
  securityTxt: ref('RFC 9116, security.txt', 'https://www.rfc-editor.org/rfc/rfc9116'),
  cve41773: ref('CVE-2021-41773', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'),
  cve42013: ref('CVE-2021-42013', 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013'),
  cve11022: ref('CVE-2020-11022', 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022'),
  cve0160: ref('CVE-2014-0160', 'https://nvd.nist.gov/vuln/detail/CVE-2014-0160'),
  php: ref('PHP supported versions', 'https://www.php.net/supported-versions.php'),
  uaeIa: ref(
    'UAE Information Assurance Standard',
    'https://csc.gov.ae/en/w/uae-information-assurance-standard',
  ),
  pdpl: ref(
    'PDPL, Federal Decree-Law 45/2021',
    'https://www.uaelegislation.gov.ae/en/legislations/1972',
  ),
  cybercrime: ref(
    'Federal Decree-Law 34/2021 on cybercrime',
    'https://uaelegislation.gov.ae/en/legislations/1526',
  ),
};
