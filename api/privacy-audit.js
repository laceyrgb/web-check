import middleware from './_common/middleware.js';
import { fetchPage, targetUrl } from './cormorant/hosts.js';
import { auditPrivacy } from './cormorant/content.js';

const privacyAudit = async (url) => {
  const href = targetUrl(url);
  const page = await fetchPage(href);
  return auditPrivacy(page.html, href, page.headers);
};

export const handler = middleware(privacyAudit);
export default handler;
