import { Card } from 'client/components/Form/Card';
import Row, { ExpandableRow, type RowProps } from 'client/components/Form/Row';
import type { Status } from 'client/components/misc/Icon';
import { formatNumber } from 'client/utils/format';

// The URL a sitemap or crawl entry points at
const pageUrl = (page: any): string => {
  const loc = page?.loc;
  if (Array.isArray(loc)) return loc[0] || '';
  return loc || '';
};

// Path plus query, which is what distinguishes one listed page from another
const pageLabel = (url: string) => {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}` || '/';
  } catch {
    return url;
  }
};

const field = (page: any, name: string) => {
  const value = page?.[name];
  return Array.isArray(value) ? value[0] : value;
};

// HTTP status text for a crawled link, or a bot-check label when the page was blocked
const statusText = (page: any) => {
  if (field(page, 'blocked') === 'yes') return 'Bot check';
  const status = field(page, 'status');
  if (status === 0 || status === '0') return 'Failed';
  return status ? String(status) : '';
};

const statusKind = (text: string): Status | undefined => {
  if (text === 'Bot check') return 'warning';
  if (text === 'Failed') return 'error';
  const code = Number(text);
  if (!Number.isFinite(code) || !code) return undefined;
  if (code >= 200 && code < 400) return 'pass';
  if (code >= 400) return 'error';
  return 'info';
};

// Rows shown when a page is expanded, skipping any the sitemap leaves out
const details = (page: any, url: string): RowProps[] =>
  [
    { lbl: 'URL', val: url, link: url },
    { lbl: 'Last Modified', val: field(page, 'lastmod') },
    { lbl: 'Change Frequency', val: field(page, 'changefreq') },
    { lbl: 'Priority', val: field(page, 'priority') },
  ].filter((row) => row.val);

const SitemapCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const pages = props.data.url || props.data.urlset?.url || [];
  const sitemaps = props.data.sitemapindex?.sitemap || [];
  const crawled = props.data.source === 'crawl';
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Source" val={crawled ? 'Crawled from the page' : 'Published sitemap'} />
      <Row lbl="Pages listed" val={formatNumber(pages.length)} />
      {crawled && (
        <>
          <Row lbl="Working links" val={formatNumber(props.data.valid ?? 0)} />
          <Row lbl="Pages fetched" val={formatNumber(props.data.pagesCrawled ?? 0)} />
        </>
      )}
      {props.data.truncated && (
        <Row plaintext="This list is capped. The site links to more pages than this check follows." />
      )}
      {pages.map((page: any) => {
        const url = pageUrl(page);
        const text = statusText(page);
        return (
          <ExpandableRow
            key={url || pageLabel(url)}
            lbl={pageLabel(url)}
            title={url}
            val={text || undefined}
            status={statusKind(text)}
            rowList={details(page, url)}
          />
        );
      })}
      {sitemaps.length > 0 && (
        <p>This site returns a sitemap index, which is a list of sitemaps.</p>
      )}
      {sitemaps.map((sitemap: any, index: number) => {
        const url = pageUrl(sitemap);
        return (
          <Row key={url || index}>
            <a href={url}>{pageLabel(url)}</a>
          </Row>
        );
      })}
    </Card>
  );
};

export default SitemapCard;
