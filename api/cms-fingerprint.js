import middleware from './_common/middleware.js';
import { fetchPage, targetUrl } from './cormorant/hosts.js';
import { fingerprintCms } from './cormorant/content.js';

const cmsFingerprint = async (url) => fingerprintCms((await fetchPage(targetUrl(url))).html || '');

export const handler = middleware(cmsFingerprint);
export default handler;
