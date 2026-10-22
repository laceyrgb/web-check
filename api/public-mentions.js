import middleware from './_common/middleware.js';
import { publicMentions } from './cormorant/mentions.js';

export const handler = middleware((url) => publicMentions(url));
export default handler;
