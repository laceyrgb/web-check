import { useMemo, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { riskFromJobs } from 'client/cormorant/risk';
import { projectLinks } from 'client/cormorant/projectLinks.js';
import type { JobsState } from 'client/jobs/types';

const Panel = styled.section`
  width: var(--page-width);
  margin: 0 auto;
  background: ${colors.backgroundRaised};
  border: 1px solid ${colors.primaryTransparent};
  border-radius: 4px;
  padding: 1rem 1.25rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem 1.5rem;
  align-items: center;
  justify-content: space-between;
  h2 {
    margin: 0;
    font-size: 1.1rem;
    color: ${colors.primaryIncreasedContrast};
  }
  p {
    margin: 0.25rem 0 0;
    color: ${colors.textColorSecondary};
  }
  a,
  button {
    color: ${colors.background};
    background: ${colors.primary};
    border: 0;
    border-radius: 4px;
    padding: 0.45rem 0.75rem;
    text-decoration: none;
    cursor: pointer;
    font: inherit;
  }
  nav {
    flex-basis: 100%;
  }
  nav a {
    background: transparent;
    color: ${colors.primaryIncreasedContrast};
    padding: 0;
  }
  nav ul {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 0.9rem;
    margin: 0.35rem 0 0;
    padding: 0;
    list-style: none;
  }
  nav h3 {
    margin: 0.6rem 0 0;
    font-size: 0.95rem;
  }
`;

const deskApi = () => {
  const root = (import.meta.env.PUBLIC_API_ENDPOINT || '/api').replace(/\/$/, '');
  return root.endsWith('/api') ? `${root}/v1` : `${root}/api/v1`;
};

const CormorantSection = (props: { address: string; jobs: JobsState }): JSX.Element => {
  const risk = useMemo(() => riskFromJobs(props.jobs), [props.jobs]);
  const map = useMemo(() => projectLinks(props.address), [props.address]);
  const [message, setMessage] = useState('');
  const download = async () => {
    setMessage('Building the PDF from a fresh server-side scan.');
    const key = window.localStorage.getItem('cormorant.apiKey') || '';
    const response = await fetch(
      `${deskApi()}/report.pdf?url=${encodeURIComponent(props.address)}`,
      {
        headers: key ? { 'x-api-key': key } : {},
      },
    );
    if (!response.ok) {
      setMessage(`PDF request returned ${response.status}.`);
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'cormorant-report.pdf';
    link.click();
    URL.revokeObjectURL(url);
    setMessage('PDF downloaded. It contains only findings the server collected.');
  };
  const score = risk.score == null ? 'n/a' : `${risk.score} (${risk.letter})`;
  return (
    <Panel>
      <div>
        <h2>Cormorant risk {score}</h2>
        <p>
          {risk.factors.length} weighted factor{risk.factors.length === 1 ? '' : 's'}. {risk.note}
        </p>
        {message && <p>{message}</p>}
      </div>
      <div>
        <button type="button" onClick={download}>
          Download PDF
        </button>{' '}
        <a href={`/desk?target=${encodeURIComponent(map.host || props.address)}`}>Open desk</a>{' '}
        <a href={`/project?target=${encodeURIComponent(map.host || props.address)}`}>Project map</a>
      </div>
      <nav aria-label="This host in the project">
        {map.groups.map((group) => (
          <div key={group.id}>
            <h3>{group.title}</h3>
            <ul>
              {group.links.map((link) => (
                <li key={`${group.id}-${link.label}`}>
                  <a href={link.href}>{link.label}</a>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </Panel>
  );
};

export default CormorantSection;
