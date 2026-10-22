import middleware from './_common/middleware.js';
import { buildAttackSurface } from './cormorant/hosts.js';

export const handler = middleware((url) => buildAttackSurface(url));
export default handler;
