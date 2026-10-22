import tls from 'tls';
import net from 'net';
import { httpGet } from '../_common/http.js';
import { canonicalHost, cardFields } from './util.js';
import { fetchPage, targetUrl } from './hosts.js';

const letterOf = (score) => {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
};

const cookieFlags = (setCookie) => {
  const rows = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  return rows.map((line) => {
    const [pair] = String(line).split(';');
    const name = pair.split('=')[0].trim();
    const lower = String(line).toLowerCase();
    return {
      name,
      secure: lower.includes('secure'),
      httpOnly: lower.includes('httponly'),
      sameSite: /samesite=([^;]+)/i.exec(line)?.[1] || null,
    };
  });
};

export const scorePosture = ({ headers = {}, tlsInfo = {}, cookies = [], cors = {} } = {}) => {
  let score = 100;
  const findings = [];
  const remediations = [];
  const deduct = (points, title, fix) => {
    score -= points;
    findings.push({ title, points });
    remediations.push(fix);
  };
  if (!headers['strict-transport-security']) {
    deduct(15, 'HSTS header was not observed', 'Send Strict-Transport-Security with max-age of at least one year.');
  }
  if (!headers['content-security-policy']) {
    deduct(10, 'Content-Security-Policy was not observed', 'Publish a Content-Security-Policy that fits the pages you serve.');
  }
  if (!headers['x-content-type-options']) {
    deduct(5, 'X-Content-Type-Options was not observed', 'Send X-Content-Type-Options: nosniff.');
  }
  if (!headers['x-frame-options'] && !/frame-ancestors/i.test(headers['content-security-policy'] || '')) {
    deduct(5, 'Clickjacking control was not observed', 'Send X-Frame-Options or CSP frame-ancestors.');
  }
  if (!headers['referrer-policy']) {
    deduct(4, 'Referrer-Policy was not observed', 'Send a Referrer-Policy such as strict-origin-when-cross-origin.');
  }
  if (tlsInfo.authorized === false) {
    deduct(20, 'TLS certificate was not trusted', 'Serve a certificate that matches the hostname and chains to a public CA.');
  }
  if (tlsInfo.expired) deduct(15, 'TLS certificate is expired', 'Renew the certificate before it expires.');
  if (tlsInfo.protocol && /^tlsv1(\.0|\.1)?$/i.test(tlsInfo.protocol)) {
    deduct(15, `Negotiated ${tlsInfo.protocol}`, 'Disable TLS 1.0 and 1.1.');
  }
  for (const cookie of cookies) {
    if (!cookie.secure) deduct(4, `Cookie ${cookie.name} is missing Secure`, 'Mark session cookies Secure.');
    if (!cookie.httpOnly) deduct(4, `Cookie ${cookie.name} is missing HttpOnly`, 'Mark session cookies HttpOnly unless a script must read them.');
    if (!cookie.sameSite) deduct(3, `Cookie ${cookie.name} is missing SameSite`, 'Set SameSite=Lax or Strict.');
  }
  if (cors.allowOrigin === '*') {
    deduct(12, 'Access-Control-Allow-Origin is *', 'Restrict CORS to the origins that need it.');
  }
  if (cors.reflected && cors.allowCredentials) {
    deduct(18, 'Arbitrary Origin was reflected with credentials', 'Do not reflect arbitrary Origin when credentials are allowed.');
  }
  score = Math.max(0, score);
  return {
    score,
    letter: letterOf(score),
    findings,
    remediations,
    tls: tlsInfo,
    cookies,
    cors,
    note: 'Score starts at 100 and subtracts observed gaps only. It is a hygiene grade, not a penetration test.',
  };
};

const observeTls = (host) =>
  new Promise((resolve) => {
    const socket = tls.connect(
      { host, port: 443, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: 8000 },
      () => {
        const cert = socket.getPeerCertificate();
        const validTo = cert?.valid_to ? Date.parse(cert.valid_to) : NaN;
        resolve({
          protocol: socket.getProtocol?.() || null,
          authorized: socket.authorized,
          subject: cert?.subject?.CN || null,
          issuer: cert?.issuer?.O || cert?.issuer?.CN || null,
          validTo: cert?.valid_to || null,
          expired: Number.isFinite(validTo) ? validTo < Date.now() : false,
        });
        socket.end();
      },
    );
    socket.on('error', (error) => resolve({ error: error.message }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ error: 'TLS observation timed out' });
    });
  });

export const observePosture = async (url, deps = {}) => {
  const host = canonicalHost(url);
  const href = targetUrl(url);
  const page = deps.page || (await fetchPage(href, deps));
  const http = deps.httpGet || httpGet;
  let corsProbe = {};
  try {
    const response = await http(href, {
      timeout: 8000,
      validateStatus: () => true,
      headers: { Origin: 'https://cormorant.invalid' },
    });
    const allowOrigin = response.headers?.['access-control-allow-origin'] || null;
    corsProbe = {
      allowOrigin,
      allowCredentials: String(response.headers?.['access-control-allow-credentials'] || '').toLowerCase() === 'true',
      reflected: allowOrigin === 'https://cormorant.invalid',
    };
  } catch (error) {
    corsProbe = { error: error.message };
  }
  const tlsInfo = deps.tlsInfo || (await observeTls(host));
  const scored = scorePosture({
    headers: page.headers || {},
    tlsInfo,
    cookies: cookieFlags(page.headers?.['set-cookie']),
    cors: corsProbe,
  });
  return {
    ...scored,
    ...cardFields(
      [`Posture ${scored.letter} (${scored.score})`],
      scored.findings.map((item) => ({ label: item.title, value: `-${item.points}` })),
      scored.note,
    ),
  };
};
