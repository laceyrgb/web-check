import type { Analyzer, Result } from '../types';
import { formatNumber } from 'client/utils/format';

const pagesOf = (data: any) => data?.urlset?.url || data?.url || [];

const statusOf = (page: any) => {
  const raw = Array.isArray(page?.status) ? page.status[0] : page?.status;
  const code = Number(raw);
  return Number.isFinite(code) ? code : null;
};

const blocked = (page: any) => {
  const value = Array.isArray(page?.blocked) ? page.blocked[0] : page?.blocked;
  return value === 'yes';
};

// A published sitemap is the site's own list. A crawl is the fallback when that file is missing.
const sitemap: Analyzer = (data): Result[] => {
  const pages = pagesOf(data);
  if (!pages.length) return [];
  if (data.source !== 'crawl') {
    return [
      {
        severity: 'pass',
        title: `Sitemap lists ${formatNumber(pages.length)} page(s)`,
      },
    ];
  }
  const working = pages.filter((page: any) => {
    const code = statusOf(page);
    return !blocked(page) && code !== null && code >= 200 && code < 400;
  }).length;
  const broken = pages.filter((page: any) => {
    const code = statusOf(page);
    return !blocked(page) && code !== null && code >= 400;
  }).length;
  const findings: Result[] = [
    {
      severity: 'info',
      title: `No sitemap file, so ${formatNumber(working)} working link(s) were crawled from the page`,
      detail: data.truncated
        ? 'The list is capped. The page links to more than this check follows.'
        : 'These are same-site links found by following the page.',
    },
  ];
  if (broken) {
    findings.push({
      severity: 'warning',
      title: `${formatNumber(broken)} crawled link(s) did not respond`,
      detail: 'They are linked from the site but returned an error status.',
    });
  }
  return findings;
};

export default sitemap;
