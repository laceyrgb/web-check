export function hostFromInput(input: string | null | undefined): string;

export function projectLinks(
  input: string | null | undefined,
  options?: { here?: 'desk' | 'page' },
): {
  host: string;
  groups: {
    id: string;
    title: string;
    links: { label: string; href: string }[];
  }[];
};
