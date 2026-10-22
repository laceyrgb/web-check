import middleware from './_common/middleware.js';
import { observePosture } from './cormorant/posture.js';

export const handler = middleware((url) => observePosture(url));
export default handler;
