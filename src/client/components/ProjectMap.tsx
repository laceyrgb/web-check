import { useEffect, useMemo, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { projectLinks } from 'client/cormorant/projectLinks.js';

const Nav = styled.nav`
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
  p {
    margin: 0;
    color: ${colors.textColorSecondary};
  }
  h2 {
    margin: 0;
    font-size: 1rem;
  }
  ul {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 0.9rem;
    margin: 0.35rem 0 0;
    padding: 0;
    list-style: none;
  }
  a {
    color: ${colors.primaryIncreasedContrast};
  }
`;

export const ProjectMap = (props: { target: string; here?: 'desk' | 'page' }): JSX.Element => {
  const map = useMemo(
    () => projectLinks(props.target, { here: props.here }),
    [props.target, props.here],
  );
  return (
    <Nav aria-label="Project">
      <p>
        {map.host
          ? `${map.host} opens in the full report, each checker, and every desk section.`
          : 'Enter a target to open the same host in the report, the checkers, and the desk.'}
      </p>
      {map.groups.map((group) => (
        <div key={group.id}>
          <h2>{group.title}</h2>
          <ul>
            {group.links.map((link) => (
              <li key={`${group.id}-${link.label}`}>
                <a href={link.href}>{link.label}</a>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </Nav>
  );
};

const Page = styled.div`
  width: min(94vw, 960px);
  margin: 1rem auto 3rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  color: ${colors.textColor};
  h1 {
    margin: 0;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  input {
    font: inherit;
    color: ${colors.textColor};
    background: ${colors.background};
    border: 1px solid ${colors.primaryTransparent};
    border-radius: 4px;
    padding: 0.4rem 0.55rem;
  }
`;

const ProjectPage = (): JSX.Element => {
  const [target, setTarget] = useState('');
  useEffect(() => {
    setTarget(new URLSearchParams(window.location.search).get('target') || '');
  }, []);
  const change = (value: string) => {
    setTarget(value);
    const url = new URL(window.location.href);
    const trimmed = value.trim();
    if (trimmed) url.searchParams.set('target', trimmed);
    else url.searchParams.delete('target');
    window.history.replaceState(null, '', `${url.pathname}${url.search}`);
  };
  return (
    <Page>
      <header>
        <h1>Project map</h1>
        <p>
          The report, the category checkers, and the OSINT desk for one host. Passive pages only.
          Authorized scans stay on the desk, behind their existing gates.
        </p>
      </header>
      <label>
        Target
        <input
          value={target}
          onChange={(event) => change(event.target.value)}
          placeholder="example.com"
        />
      </label>
      <ProjectMap target={target} here="page" />
    </Page>
  );
};

export default ProjectPage;
