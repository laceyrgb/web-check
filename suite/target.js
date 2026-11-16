import net from 'node:net';

// Turn a customer-supplied target into a hostname. IP literals are refused so this
// runner cannot be pointed at cloud metadata or an internal address by number.
export const parseTarget = (input) => {
  if (!input || typeof input !== 'string') throw new Error('Target is required');
  const trimmed = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error('Invalid target');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only http and https targets are supported');
  }
  if (url.username || url.password)
    throw new Error('Credentials in the target URL are not accepted');
  const hostname = url.hostname.replace(/\.$/, '').toLowerCase();
  if (!hostname || hostname.includes(' ')) throw new Error('Invalid target');
  const loopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  if (net.isIP(hostname) && !loopback) {
    throw new Error('IP targets are not accepted; scan a domain name you are authorised to test');
  }
  if (url.protocol === 'http:' && !loopback) {
    // The homepage may be cleartext, and that itself is a finding. Active add-ons still
    // refuse cleartext except on loopback (see assertFetchAllowed).
  }
  return {
    input: trimmed,
    hostname,
    origin: url.origin,
    protocol: url.protocol,
    loopback,
  };
};
