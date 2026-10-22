import middleware from './_common/middleware.js';
import { checkEmailBreaches } from './cormorant/breach.js';

export const handler = middleware((url, request) => checkEmailBreaches(url, { email: request?.query?.email }));
export default handler;
