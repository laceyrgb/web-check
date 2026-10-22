import middleware from './_common/middleware.js';
import { detectTechnologies, fetchPage, targetUrl } from './cormorant/hosts.js';
import { lookupCves } from './cormorant/cve.js';

const techCves = async (url) => {
  const page = await fetchPage(targetUrl(url)).catch((error) => ({ error: error.message, headers: {}, html: '' }));
  if (page.error) return { findings: [], skipped: [], error: page.error, summary: [], items: [], note: page.error };
  return lookupCves(detectTechnologies(page));
};

export const handler = middleware(techCves);
export default handler;
