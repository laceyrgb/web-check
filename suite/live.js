import { spawn } from 'node:child_process';
import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

import { isBlockedAddress, isLoopbackHost } from './addresses.js';

const UA =
  'CormorantReadinessScan/0.1 (+https://csc.gov.ae/en/w/uae-information-assurance-standard)';

// Requests may go to the target, or to its published MTA-STS host. Nowhere else.
export const assertFetchAllowed = (scanHost, urlString) => {
  const url = new URL(urlString);
  const host = url.hostname.toLowerCase();
  const mta = `mta-sts.${scanHost}`;
  if (host !== scanHost && host !== mta) {
    throw new Error(`Refusing to request ${host}; it is not the scan target`);
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Unsupported URL protocol');
  if (host === mta && url.protocol !== 'https:')
    throw new Error('MTA-STS policy must be fetched over HTTPS');
  if (url.protocol === 'http:' && !isLoopbackHost(scanHost)) {
    if (host !== scanHost) throw new Error('Cleartext HTTP is limited to the target host');
  }
  if (url.port && !isLoopbackHost(scanHost) && !['80', '443'].includes(url.port)) {
    throw new Error('Refusing a non-default port on a public target');
  }
  return url;
};

export const assertPublicAddresses = async (hostname, addresses) => {
  if (isLoopbackHost(hostname)) return;
  for (const address of addresses || []) {
    if (isBlockedAddress(address, { allowLoopback: false })) {
      throw new Error(`Refusing ${hostname}: it resolves to a non-public address`);
    }
  }
};

const requestOnce = (url, headers) =>
  new Promise((resolve, reject) => {
    const lib = url.protocol === 'http:' ? http : https;
    const req = lib.request(
      url,
      {
        method: 'GET',
        headers: { 'user-agent': UA, accept: '*/*', ...(headers || {}) },
        timeout: 8000,
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            location: res.headers.location || null,
          });
        };
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size <= 65536) chunks.push(chunk);
          else {
            res.destroy();
            finish();
          }
        });
        res.on('end', finish);
        res.on('error', (error) => {
          if (settled) return;
          settled = true;
          reject(error);
        });
      },
    );
    req.on('timeout', () => {
      req.destroy();
      const error = new Error('timeout');
      error.code = 'ETIMEOUT';
      reject(error);
    });
    req.on('error', reject);
    req.end();
  });

export const fetchTarget = async (scanHost, startUrl, { headers, lookup } = {}) => {
  let current = startUrl;
  for (let hop = 0; hop < 3; hop += 1) {
    const url = assertFetchAllowed(scanHost, current);
    if (lookup) await assertPublicAddresses(scanHost, await lookup(url.hostname));
    const response = await requestOnce(url, headers);
    if ([301, 302, 303, 307, 308].includes(response.status) && response.location) {
      current = new URL(response.location, url).href;
      continue;
    }
    return { ...response, finalUrl: current };
  }
  throw new Error('Too many redirects on the target host');
};

export const lookupHost = (hostname) =>
  dns.lookup(hostname, { all: true }).then((rows) => rows.map((row) => row.address));

export const inspectTls = (hostname) =>
  new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: net.isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: false,
        timeout: 8000,
      },
      () => {
        const cert = socket.getPeerCertificate() || {};
        const cipher = socket.getCipher();
        const result = {
          protocol: socket.getProtocol(),
          cipher: cipher?.name || '',
          authorized: socket.authorized,
          authError: socket.authorizationError || null,
          bits: cert.bits || null,
          validTo: cert.valid_to || null,
          validFrom: cert.valid_from || null,
        };
        socket.end();
        resolve(result);
      },
    );
    socket.on('error', reject);
  });

export const connectPort = (port, hostname) =>
  new Promise((resolve) => {
    const socket = net.connect({ port, host: hostname, timeout: 800 });
    const finish = (open) => {
      socket.destroy();
      resolve(open);
    };
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });

// crt.sh is the one passive third party this runner calls, and only for certificate names.
export const fetchCtNames = async (domain) => {
  const url = new URL(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`);
  if (url.hostname !== 'crt.sh') throw new Error('Refusing an unexpected certificate-log host');
  const response = await requestOnce(url, { accept: 'application/json' });
  const data = JSON.parse(response.body || '[]');
  if (!Array.isArray(data)) return [];
  return data.flatMap((row) => String(row?.name_value || '').split('\n'));
};

export const spawnProcess = (binary, args) =>
  new Promise((resolve, reject) => {
    if (!binary || binary.startsWith('-')) {
      reject(new Error('Nuclei binary path is not valid'));
      return;
    }
    const child = spawn(binary, args, { shell: false });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8').slice(0, 500),
      });
    });
  });

export const createLiveTransports = (hostname) => ({
  resolveTxt: (name) => dns.resolveTxt(name),
  resolveMx: (name) => dns.resolveMx(name),
  resolveNs: (name) => dns.resolveNs(name),
  resolveCaa: (name) => dns.resolveCaa(name),
  resolve4: (name) => dns.resolve4(name),
  resolveType: (name, type) => dns.resolve(name, type),
  httpGet: async (url, options = {}) => {
    const host = new URL(url).hostname;
    await assertPublicAddresses(hostname, await lookupHost(host));
    return fetchTarget(hostname, url, { headers: options.headers, lookup: lookupHost });
  },
  inspectTls: async (host) => {
    await assertPublicAddresses(hostname, await lookupHost(host));
    return inspectTls(host);
  },
  connect: async (port, host) => {
    await assertPublicAddresses(hostname, await lookupHost(host));
    return connectPort(port, host);
  },
  ctLookup: fetchCtNames,
  spawn: spawnProcess,
});
