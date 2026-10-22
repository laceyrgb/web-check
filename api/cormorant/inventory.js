export const updateInventory = (prev, scan, seenAt) => {
  const next = {
    target: scan.target,
    updatedAt: seenAt,
    items: { ...(prev?.items || {}) },
  };
  const touch = (kind, value, source) => {
    if (value == null || value === '') return;
    const text = String(value);
    const key = `${kind}:${text.toLowerCase()}`;
    const current = next.items[key];
    next.items[key] = {
      kind,
      value: text,
      source,
      firstSeen: current?.firstSeen || seenAt,
      lastSeen: seenAt,
    };
  };
  for (const host of scan.attackSurface?.hosts || []) touch('host', host.host, host.source || 'passive-dns');
  if (scan.exposure?.ip) touch('ip', scan.exposure.ip, 'dns');
  for (const neighbor of scan.exposure?.neighbors || []) touch('host', neighbor.host, neighbor.source);
  for (const port of scan.attackSurface?.ports?.open || []) touch('service', String(port), 'common-port-check');
  for (const tech of scan.attackSurface?.technologies || []) {
    touch('tech', tech.version ? `${tech.name} ${tech.version}` : tech.name, tech.source);
  }
  if (scan.cms?.cms) touch('tech', scan.cms.version ? `${scan.cms.cms} ${scan.cms.version}` : scan.cms.cms, 'cms-fingerprint');
  for (const email of scan.attackSurface?.publishedEmails || []) touch('email', email, 'public-page');
  return next;
};
