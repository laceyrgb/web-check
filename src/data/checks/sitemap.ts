import type { Check } from '.';

export default {
  title: 'Sitemap',
  categories: ['seo'],
  summary: 'The pages from the sitemap, or the same-site links found by crawling the page',
  description:
    "Finds and parses the site's sitemap, the file where an author lists the pages " +
    'they want search engines to crawl, usually with a last-modified date and a ' +
    'priority against each one. When the site does not publish a sitemap, the check ' +
    'crawls the page, follows its same-site links, and lists each one with the status it returned.',
  use:
    "It is the site's own table of contents when a sitemap exists. When it does not, " +
    'the crawled list shows which pages are actually linked and which of those links respond, ' +
    'so you can see what the site makes available.',
  resources: [
    {
      title: 'Learn about Sitemaps',
      link: 'https://developers.google.com/search/docs/crawling-indexing/sitemaps/overview',
    },
    { title: 'Sitemap XML spec', link: 'https://www.sitemaps.org/protocol.html' },
    {
      title: 'Sitemap tutorial',
      link: 'https://www.conductor.com/academy/xml-sitemap/',
    },
  ],
  screenshot: 'https://pixelflare.cc/alicia/web-check/wc-pages',
} satisfies Check;
