import middleware from './_common/middleware.js';
import { fetchPage, targetUrl } from './cormorant/hosts.js';
import { listPeopleFromPage } from './cormorant/content.js';
import { cardFields } from './cormorant/util.js';

const publicPeople = async (url) => {
  const href = targetUrl(url);
  const page = await fetchPage(href);
  const people = listPeopleFromPage(page.html, href);
  return {
    people,
    note: 'LinkedIn URLs published on the page are listed and not fetched.',
    ...cardFields(
      [people.length ? `${people.length} public profile links listed` : 'No public profile links listed'],
      people.map((person) => ({ label: 'listed', value: person.url, href: person.url })),
      'LinkedIn URLs published on the page are listed and not fetched.',
    ),
  };
};

export const handler = middleware(publicPeople);
export default handler;
