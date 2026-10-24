// One host, every surface in this project. Paths stay on this server.

const CHECKERS = [
  ['check', 'Full report'],
  ['security', 'Security'],
  ['seo', 'SEO'],
  ['server', 'Server'],
  ['domain', 'Domain'],
  ['email', 'Email'],
  ['performance', 'Performance'],
  ['privacy', 'Privacy'],
];

const DESK_SECTIONS = [
  ['scan', 'Scan'],
  ['links', 'Link list'],
  ['history', 'History'],
  ['records', 'Public record'],
  ['offline', 'Offline copy'],
  ['nmap', 'Authorized port scan'],
  ['engagement', 'Engagement'],
  ['audit', 'Mobile and SBOM'],
];

const REFERENCE = [
  ['/project', 'Project map'],
  ['/desk', 'OSINT desk'],
  ['/checks', 'All checks'],
  ['/glossary', 'Glossary'],
  ['/self-hosted-setup', 'Self-hosting'],
  ['/web-check-api', 'API'],
  ['/about', 'About'],
];

export const hostFromInput = (input) => {
  if (!input) return '';
  let host = String(input)
    .trim()
    .replace(/^https?:\/\//i, '');
  const stop = host.search(/[/?#\s]/);
  if (stop !== -1) host = host.slice(0, stop);
  host = host.replace(/\.$/, '').toLowerCase();
  if (!/^[a-z0-9._:-]+$/.test(host)) return '';
  return host;
};

const withTarget = (path, host) => (host ? `${path}?target=${encodeURIComponent(host)}` : path);

export const projectLinks = (input, options = {}) => {
  const host = hostFromInput(input);
  const here = options.here === 'desk' ? 'desk' : 'page';
  const tool = (path) => (host ? `/${path}/${encodeURIComponent(host)}` : `/${path}`);
  const desk = (id) => (here === 'desk' ? `#${id}` : `${withTarget('/desk', host)}#${id}`);
  return {
    host,
    groups: [
      {
        id: 'report',
        title: host ? `${host} in Web Check` : 'Web Check',
        links: CHECKERS.map(([path, label]) => ({ label, href: tool(path) })),
      },
      {
        id: 'desk',
        title: host ? `${host} on the desk` : 'OSINT desk',
        links: DESK_SECTIONS.map(([id, label]) => ({ label, href: desk(id) })),
      },
      {
        id: 'reference',
        title: 'The rest of the project',
        links: REFERENCE.map(([path, label]) => ({
          label,
          href: path === '/project' || path === '/desk' ? withTarget(path, host) : path,
        })),
      },
    ],
  };
};
