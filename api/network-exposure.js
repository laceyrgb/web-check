import middleware from './_common/middleware.js';
import { networkExposure } from './cormorant/exposure.js';

export const handler = middleware((url) => networkExposure(url));
export default handler;
