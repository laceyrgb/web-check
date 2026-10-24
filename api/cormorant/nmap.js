import { execFile } from 'child_process';
import { promisify } from 'util';
import dns from 'dns/promises';
import net from 'net';
import { blockedInfrastructure, httpError } from './util.js';

const exec = promisify(execFile);

export const NMAP_PROFILES = {
  default: ['-sT', '-Pn', '--top-ports', '100', '-T2', '--max-retries', '1', '--max-rate', '50', '--host-timeout', '120s', '--open', '-oX', '-'],
  version: ['-sT', '-Pn', '--top-ports', '100', '-sV', '--version-light', '-T2', '--max-retries', '1', '--max-rate', '50', '--host-timeout', '180s', '--open', '-oX', '-'],
  deeper: ['-sT', '-Pn', '--top-ports', '1000', '-sV', '--version-light', '-T2', '--max-retries', '1', '--max-rate', '40', '--host-timeout', '300s', '--open', '-oX', '-'],
  syn: ['-sS', '-Pn', '--top-ports', '100', '-T2', '--max-retries', '1', '--max-rate', '50', '--host-timeout', '120s', '--open', '-oX', '-'],
};

export const buildNmapArgs = (profile, ip) => {
  const args = NMAP_PROFILES[profile];
  if (!args) throw httpError(400, 'Unknown Nmap profile');
  if (!net.isIP(ip)) throw httpError(400, 'Nmap target must be a single IP');
  if (args.some((arg) => arg === '-A' || arg === '-O' || arg.startsWith('--script'))) {
    throw httpError(500, 'Refusing an Nmap profile that enables scripts or OS detection');
  }
  return [...args, ip];
};

export const parseNmapXml = (xml) => {
  const hosts = [];
  const hostBlocks = String(xml || '').match(/<host\b[\s\S]*?<\/host>/g) || [];
  for (const block of hostBlocks) {
    const address = /<address\b[^>]*addr="([^"]+)"[^>]*addrtype="ipv[46]"/.exec(block)?.[1]
      || /<address\b[^>]*addr="([^"]+)"/.exec(block)?.[1]
      || null;
    const ports = [];
    const portBlocks = block.match(/<port\b[\s\S]*?<\/port>/g) || [];
    for (const portBlock of portBlocks) {
      const port = /portid="(\d+)"/.exec(portBlock)?.[1];
      const protocol = /protocol="([^"]+)"/.exec(portBlock)?.[1] || 'tcp';
      const state = /<state\b[^>]*state="([^"]+)"/.exec(portBlock)?.[1] || 'unknown';
      const service = /<service\b([^>]*)\/?>/.exec(portBlock)?.[1] || '';
      ports.push({
        port: Number(port),
        protocol,
        state,
        service: /name="([^"]+)"/.exec(service)?.[1] || null,
        product: /product="([^"]+)"/.exec(service)?.[1] || null,
        version: /version="([^"]+)"/.exec(service)?.[1] || null,
      });
    }
    hosts.push({ address, ports });
  }
  return { hosts };
};

export const nmapAvailable = async (runner = exec) => {
  try {
    const { stdout } = await runner('nmap', ['-V'], { timeout: 5000 });
    return { installed: true, version: String(stdout).split('\n')[0] };
  } catch (error) {
    return {
      installed: false,
      message: 'Nmap is not installed. Debian/Ubuntu: sudo apt-get install nmap. macOS: brew install nmap. Then set WEBCHECK_NMAP_ENABLED=true.',
      error: error.code || error.message,
    };
  }
};

export const resolveSingleIp = async (host) => {
  if (net.isIP(host)) return { ip: host, addresses: [host] };
  const v4 = await dns.resolve4(host).catch(() => []);
  const v6 = await dns.resolve6(host).catch(() => []);
  const addresses = [...v4, ...v6];
  if (addresses.length === 1) return { ip: addresses[0], addresses };
  return { ip: null, addresses };
};

export const assertNmapAuthorized = ({ enabled, authorization, profile, uid = typeof process.getuid === 'function' ? process.getuid() : 0 }) => {
  if (!enabled) throw httpError(403, 'Nmap is disabled. Set WEBCHECK_NMAP_ENABLED=true after installing nmap.');
  if (!authorization?.acknowledged) throw httpError(403, 'Authorization required');
  if (!authorization.operator) throw httpError(400, 'Operator name is required');
  if (!authorization.ip || !net.isIP(authorization.ip)) throw httpError(403, 'Authorization required for a single resolved IP');
  if (blockedInfrastructure(authorization.ip)) throw httpError(400, 'Refusing a metadata or local address');
  if (profile === 'syn' && uid !== 0) throw httpError(400, 'SYN scan needs root. Use the default TCP connect profile.');
  return buildNmapArgs(profile || 'default', authorization.ip);
};
