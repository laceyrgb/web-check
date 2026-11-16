import net from 'node:net';

const ipv4ToInt = (ip) => {
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255))
    return null;
  return parts.reduce((acc, n) => ((acc << 8) + n) >>> 0, 0);
};

const inV4 = (ip, base, bits) => {
  const addr = ipv4ToInt(ip);
  const network = ipv4ToInt(base);
  if (addr == null || network == null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (addr & mask) === (network & mask);
};

const unwrap = (ip) => {
  const lower = String(ip || '').toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const rest = lower.slice('::ffff:'.length);
    if (net.isIP(rest) === 4) return rest;
  }
  return lower;
};

// True for addresses an external scanner must not connect to.
// Loopback is allowed only when the operator deliberately targeted localhost.
export const isBlockedAddress = (ip, { allowLoopback = false } = {}) => {
  const value = unwrap(ip);
  const kind = net.isIP(value);
  if (kind === 4) {
    const loopback = inV4(value, '127.0.0.0', 8);
    if (loopback) return !allowLoopback;
    return (
      inV4(value, '0.0.0.0', 8) ||
      inV4(value, '10.0.0.0', 8) ||
      inV4(value, '100.64.0.0', 10) ||
      inV4(value, '169.254.0.0', 16) ||
      inV4(value, '172.16.0.0', 12) ||
      inV4(value, '192.0.2.0', 24) ||
      inV4(value, '192.168.0.0', 16) ||
      inV4(value, '198.18.0.0', 15) ||
      inV4(value, '198.51.100.0', 24) ||
      inV4(value, '203.0.113.0', 24) ||
      inV4(value, '224.0.0.0', 4)
    );
  }
  if (kind === 6) {
    if (value === '::1' || value === '::') return !(allowLoopback && value === '::1');
    if (value.startsWith('fc') || value.startsWith('fd')) return true;
    if (/^fe[89ab]/.test(value)) return true;
    if (value.startsWith('ff')) return true;
    return false;
  }
  return true;
};

export const isLoopbackHost = (hostname) =>
  hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';

// IPv4 CIDR match for the admin denylist. Non-IPv4 hosts never match a CIDR entry.
export const matchesCidr = (host, entry) => {
  const [range, bitsRaw] = String(entry).split('/');
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (net.isIP(unwrap(host)) !== 4 || net.isIP(range) !== 4) return false;
  return inV4(unwrap(host), range, bits);
};
