import middleware from './_common/middleware.js';
import { checkLookalikes } from './cormorant/lookalike.js';

export const handler = middleware((url) => checkLookalikes(url));
export default handler;
