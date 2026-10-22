import { cardFields } from './util.js';

export const parseLockfile = (filename, content) => {
  const name = String(filename || '').toLowerCase();
  const text = String(content || '');
  if (name.endsWith('package-lock.json') || text.includes('"lockfileVersion"')) {
    const json = JSON.parse(text);
    const packages = json.packages || {};
    const deps = Object.keys(json.dependencies || {});
    const rows = [];
    for (const dep of deps) {
      const version = packages[`node_modules/${dep}`]?.version || json.dependencies[dep]?.version;
      if (version && /^\d/.test(version)) rows.push({ name: dep, version, ecosystem: 'npm' });
      if (rows.length >= 12) break;
    }
    return rows;
  }
  if (name.endsWith('yarn.lock')) {
    const rows = [];
    const pattern = /^"?(@?[^@\s]+)@[^:\n]*:\n(?:[ \t].*\n)*?[ \t]+version "([^"]+)"/gm;
    let match = pattern.exec(text);
    while (match && rows.length < 12) {
      rows.push({ name: match[1], version: match[2], ecosystem: 'npm' });
      match = pattern.exec(text);
    }
    return rows;
  }
  const json = JSON.parse(text);
  if (Array.isArray(json.components)) {
    return json.components
      .filter((row) => row?.name && row?.version)
      .slice(0, 12)
      .map((row) => ({ name: row.name, version: row.version, ecosystem: row.ecosystem || ecosystemFromPurl(row.purl) || 'npm' }));
  }
  if (Array.isArray(json.packages)) {
    return json.packages
      .filter((row) => row?.name && row?.versionInfo)
      .slice(0, 12)
      .map((row) => ({ name: String(row.name).replace(/^.*:/, ''), version: row.versionInfo, ecosystem: 'npm' }));
  }
  throw new Error('Unsupported lockfile or SBOM. Use package-lock.json, yarn.lock, CycloneDX JSON, or SPDX JSON.');
};

const ecosystemFromPurl = (purl) => {
  const match = /^pkg:([^/]+)\//.exec(purl || '');
  return match ? match[1] : null;
};

export const queryOsv = async (packages, deps = {}) => {
  const fetchImpl = deps.fetchImpl || fetch;
  const findings = [];
  for (const pkg of packages.slice(0, 12)) {
    try {
      const response = await fetchImpl('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ package: { name: pkg.name, ecosystem: ecosystemName(pkg.ecosystem) }, version: pkg.version }),
        signal: AbortSignal.timeout(12000),
      });
      if (!response.ok) throw new Error(`OSV HTTP ${response.status}`);
      const payload = await response.json();
      for (const vuln of (payload.vulns || []).slice(0, 5)) {
        const id = vuln.id;
        findings.push({
          id,
          package: pkg.name,
          version: pkg.version,
          summary: vuln.summary || '',
          url: vuln.id?.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${vuln.id}` : `https://osv.dev/vulnerability/${id}`,
        });
      }
    } catch (error) {
      findings.push({ package: pkg.name, version: pkg.version, status: 'unavailable', message: error.message });
    }
  }
  return {
    packages,
    findings: findings.filter((row) => row.id),
    errors: findings.filter((row) => row.status === 'unavailable'),
    source: 'https://osv.dev/',
    note: 'Versions come from the supplied lockfile or SBOM. OSV is queried read-only.',
    ...cardFields(
      [`${packages.length} packages parsed`, `${findings.filter((row) => row.id).length} known vulnerabilities`],
      findings.filter((row) => row.id).map((row) => ({ label: row.id, value: `${row.package}@${row.version}`, href: row.url })),
      'Read-only OSV lookup.',
    ),
  };
};

const ecosystemName = (value) => {
  if (value === 'npm') return 'npm';
  if (value === 'pypi' || value === 'PyPI') return 'PyPI';
  if (value === 'maven') return 'Maven';
  return 'npm';
};

export const publicGithubLockfile = async (repoUrl, deps = {}) => {
  const parsed = new URL(repoUrl);
  if (parsed.hostname !== 'github.com') {
    const error = new Error('Only public github.com repositories are fetched without an engagement token');
    error.status = 400;
    throw error;
  }
  const [owner, repo] = parsed.pathname.split('/').filter(Boolean);
  if (!owner || !repo) {
    const error = new Error('Repository URL must look like https://github.com/owner/repo');
    error.status = 400;
    throw error;
  }
  const token = deps.token;
  const fetchImpl = deps.fetchImpl || fetch;
  const names = ['package-lock.json', 'yarn.lock'];
  for (const filename of names) {
    const response = await fetchImpl(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${filename}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal: AbortSignal.timeout(12000),
    });
    if (response.ok) return { filename, content: await response.text() };
  }
  const error = new Error('No package-lock.json or yarn.lock was found at HEAD on the public repository');
  error.status = 404;
  throw error;
};
