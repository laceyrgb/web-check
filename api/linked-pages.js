import middleware from './_common/middleware.js';
import { httpGet, isBotCheck, BOT_CHECK_ERROR } from './_common/http.js';
import { upstreamError } from './_common/upstream.js';
import { extractAnchors, hostOf } from './_common/page-links.js';

const linkedPagesHandler = async (url) => {
  let response;
  try {
    response = await httpGet(url);
  } catch (error) {
    return upstreamError(error, 'Linked pages fetch');
  }
  if (isBotCheck(response)) return BOT_CHECK_ERROR;
  const pageUrl = response.url || url;
  const originHost = hostOf(pageUrl);
  const internalLinksMap = new Map();
  const externalLinksMap = new Map();

  // Count each resolved page link, keeping same-site ones apart from the rest
  for (const href of extractAnchors(response.data, pageUrl)) {
    const bucket = hostOf(href) === originHost ? internalLinksMap : externalLinksMap;
    const count = bucket.get(href) || 0;
    bucket.set(href, count + 1);
  }

  // Sort by most occurrences, remove supplicates, and convert to array
  const internalLinks = [...internalLinksMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .map((entry) => entry[0]);
  const externalLinks = [...externalLinksMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .map((entry) => entry[0]);

  if (!internalLinks.length && !externalLinks.length) {
    return {
      skipped:
        'No internal or external links found in the page HTML. ' +
        'This often happens with single-page apps that render content client-side.',
    };
  }
  return { internal: internalLinks, external: externalLinks };
};

export const handler = middleware(linkedPagesHandler);
export default handler;
