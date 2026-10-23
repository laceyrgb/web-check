import { cardFields } from './util.js';

const MAX_PACKAGES = 40;

const exactVersion = (value) => {
  const text = String(value || '').replace(/^v/, '');
  return /^\d+\.\d+\.\d+/.test(text) ? text.replace(/^(\d+\.\d+\.\d+).*/, '$1') : null;
};

const push = (rows, skipped, row) => {
  if (rows.length >= MAX_PACKAGES) return;
  const version = exactVersion(row.version);
  if (!version) {
    if (row.version)
      skipped.push({ name: row.name, version: String(row.version), reason: 'version is a range' });
    return;
  }
  rows.push({ name: row.name, version, ecosystem: row.ecosystem });
};

export const parseManifest = (filename, content) => {
  const name = String(filename || '')
    .split('/')
    .pop()
    .toLowerCase();
  const text = String(content || '');
  const rows = [];
  const skipped = [];
  if (name === 'package.json') {
    const json = JSON.parse(text);
    for (const ecosystem of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [dep, version] of Object.entries(json[ecosystem] || {}))
        push(rows, skipped, { name: dep, version, ecosystem: 'npm' });
    }
    return { packages: rows, skipped };
  }
  if (
    name.endsWith('package-lock.json') ||
    (name.endsWith('.json') && text.includes('"lockfileVersion"'))
  ) {
    const json = JSON.parse(text);
    const packages = json.packages || {};
    for (const dep of Object.keys(json.dependencies || {})) {
      const version = packages[`node_modules/${dep}`]?.version || json.dependencies[dep]?.version;
      push(rows, skipped, { name: dep, version, ecosystem: 'npm' });
    }
    return { packages: rows, skipped };
  }
  if (name.endsWith('yarn.lock')) {
    const pattern = /^"?(@?[^@\s]+)@[^:\n]*:\n(?:[ \t].*\n)*?[ \t]+version "([^"]+)"/gm;
    let match = pattern.exec(text);
    while (match) {
      push(rows, skipped, { name: match[1], version: match[2], ecosystem: 'npm' });
      match = pattern.exec(text);
    }
    return { packages: rows, skipped };
  }
  if (
    name === 'requirements.txt' ||
    (name.endsWith('.txt') && /==/.test(text) && !text.includes('{'))
  ) {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const match = /^([A-Za-z0-9_.-]+)==([0-9][^;\s]*)/.exec(trimmed);
      if (match) push(rows, skipped, { name: match[1], version: match[2], ecosystem: 'PyPI' });
      else
        skipped.push({
          name: trimmed.split(/[=<>]/)[0],
          version: trimmed,
          reason: 'pinned version required',
        });
    }
    return { packages: rows, skipped };
  }
  if (name === 'go.mod') {
    // Single-line `require module v1.2.3` and parenthesized blocks both appear.
    const pattern =
      /^\s*(?:require\s+|exclude\s+)?([A-Za-z0-9_.\-/]+)\s+v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/gm;
    let match = pattern.exec(text);
    while (match) {
      if (!['go', 'module', 'replace', 'retract'].includes(match[1])) {
        push(rows, skipped, { name: match[1], version: match[2], ecosystem: 'Go' });
      }
      match = pattern.exec(text);
    }
    return { packages: rows, skipped };
  }
  if (name === 'gemfile.lock') {
    const pattern = /^    ([A-Za-z0-9_.-]+) \((\d+\.\d+\.\d+[^)]*)\)/gm;
    let match = pattern.exec(text);
    while (match) {
      push(rows, skipped, { name: match[1], version: match[2], ecosystem: 'RubyGems' });
      match = pattern.exec(text);
    }
    return { packages: rows, skipped };
  }
  if (name === 'cargo.lock') {
    const blocks = text.split('[[package]]').slice(1);
    for (const block of blocks) {
      const pkg = /^name = "([^"]+)"/m.exec(block)?.[1];
      const version = /^version = "([^"]+)"/m.exec(block)?.[1];
      if (pkg) push(rows, skipped, { name: pkg, version, ecosystem: 'crates.io' });
    }
    return { packages: rows, skipped };
  }
  if (name === 'composer.lock') {
    const json = JSON.parse(text);
    for (const row of json.packages || [])
      push(rows, skipped, { name: row.name, version: row.version, ecosystem: 'Packagist' });
    return { packages: rows, skipped };
  }
  if (name.endsWith('pom.xml')) {
    const pattern = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match = pattern.exec(text);
    while (match) {
      const group = /<groupId>([^<]+)<\/groupId>/.exec(match[1])?.[1];
      const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(match[1])?.[1];
      const version = /<version>([^<$]+)<\/version>/.exec(match[1])?.[1];
      if (group && artifact)
        push(rows, skipped, { name: `${group}:${artifact}`, version, ecosystem: 'Maven' });
      match = pattern.exec(text);
    }
    return { packages: rows, skipped };
  }
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(
      'Unsupported manifest. Use package.json, package-lock.json, yarn.lock, requirements.txt, go.mod, Gemfile.lock, Cargo.lock, composer.lock, pom.xml, CycloneDX, or SPDX.',
    );
  }
  if (Array.isArray(json.components)) {
    for (const row of json.components) {
      if (row?.name && row?.version)
        push(rows, skipped, {
          name: row.name,
          version: row.version,
          ecosystem: row.ecosystem || ecosystemFromPurl(row.purl) || 'npm',
        });
    }
    return { packages: rows, skipped };
  }
  if (Array.isArray(json.packages)) {
    for (const row of json.packages) {
      if (row?.name && row?.versionInfo) {
        push(rows, skipped, {
          name: String(row.name).replace(/^.*:/, ''),
          version: row.versionInfo,
          ecosystem: 'npm',
        });
      }
    }
    return { packages: rows, skipped };
  }
  throw new Error(
    'Unsupported manifest. Use package.json, package-lock.json, yarn.lock, requirements.txt, go.mod, Gemfile.lock, Cargo.lock, composer.lock, pom.xml, CycloneDX, or SPDX.',
  );
};

export const parseLockfile = (filename, content) => parseManifest(filename, content).packages;

const purl = (pkg) => {
  const ecosystem =
    {
      npm: 'npm',
      PyPI: 'pypi',
      Go: 'golang',
      RubyGems: 'gem',
      'crates.io': 'cargo',
      Packagist: 'composer',
      Maven: 'maven',
    }[pkg.ecosystem] || 'generic';
  return `pkg:${ecosystem}/${pkg.name}@${pkg.version}`;
};

export const buildSbom = (packages, source = 'upload') => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { component: { type: 'application', name: source } },
  components: packages.map((pkg) => ({
    type: 'library',
    name: pkg.name,
    version: pkg.version,
    purl: purl(pkg),
  })),
});

const ecosystemFromPurl = (purl) => {
  const match = /^pkg:([^/]+)\//.exec(purl || '');
  return match ? match[1] : null;
};

export const queryOsv = async (packages, deps = {}) => {
  const fetchImpl = deps.fetchImpl || fetch;
  const findings = [];
  for (const pkg of packages.slice(0, 40)) {
    try {
      const response = await fetchImpl('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          package: { name: pkg.name, ecosystem: ecosystemName(pkg.ecosystem) },
          version: pkg.version,
        }),
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
          url: vuln.id?.startsWith('CVE-')
            ? `https://nvd.nist.gov/vuln/detail/${vuln.id}`
            : `https://osv.dev/vulnerability/${id}`,
        });
      }
    } catch (error) {
      findings.push({
        package: pkg.name,
        version: pkg.version,
        status: 'unavailable',
        message: error.message,
      });
    }
  }
  return {
    packages,
    findings: findings.filter((row) => row.id),
    errors: findings.filter((row) => row.status === 'unavailable'),
    source: 'https://osv.dev/',
    note: 'Versions come from the supplied manifest. OSV is queried read-only. No package is installed or executed.',
    sbom: buildSbom(packages),
    ...cardFields(
      [
        `${packages.length} packages in the SBOM`,
        `${findings.filter((row) => row.id).length} known vulnerabilities`,
      ],
      findings
        .filter((row) => row.id)
        .map((row) => ({ label: row.id, value: `${row.package}@${row.version}`, href: row.url })),
      'Read-only OSV lookup.',
    ),
  };
};

const ecosystemName = (value) => {
  const known = {
    npm: 'npm',
    pypi: 'PyPI',
    PyPI: 'PyPI',
    Go: 'Go',
    golang: 'Go',
    RubyGems: 'RubyGems',
    'crates.io': 'crates.io',
    Packagist: 'Packagist',
    Maven: 'Maven',
    maven: 'Maven',
  };
  return known[value] || 'npm';
};

export const publicGithubLockfile = async (repoUrl, deps = {}) => {
  const parsed = new URL(repoUrl);
  if (parsed.hostname !== 'github.com') {
    const error = new Error(
      'Only public github.com repositories are fetched without an engagement token',
    );
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
  const names = [
    'package-lock.json',
    'yarn.lock',
    'package.json',
    'requirements.txt',
    'go.mod',
    'Gemfile.lock',
    'composer.lock',
    'Cargo.lock',
    'pom.xml',
  ];
  for (const filename of names) {
    const response = await fetchImpl(
      `https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${filename}`,
      {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: AbortSignal.timeout(12000),
      },
    );
    if (response.ok) return { filename, content: await response.text() };
  }
  const error = new Error('No supported manifest was found at HEAD on the public repository');
  error.status = 404;
  throw error;
};
