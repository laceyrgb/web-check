import { useEffect, useMemo, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { ProjectMap } from 'client/components/ProjectMap';

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
  section {
    background: ${colors.backgroundRaised};
    border: 1px solid ${colors.primaryTransparent};
    border-radius: 4px;
    padding: 1rem;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin: 0.4rem 0;
  }
  input,
  textarea,
  select,
  button {
    font: inherit;
    color: ${colors.textColor};
    background: ${colors.background};
    border: 1px solid ${colors.primaryTransparent};
    border-radius: 4px;
    padding: 0.4rem 0.55rem;
  }
  button,
  a.button {
    background: ${colors.primary};
    color: ${colors.background};
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    margin-right: 0.4rem;
  }
  pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.5rem 0;
    font-size: 0.9rem;
  }
  th,
  td {
    text-align: left;
    vertical-align: top;
    padding: 0.3rem 0.4rem;
    border-bottom: 1px solid ${colors.primaryTransparent};
    overflow-wrap: anywhere;
  }
  .muted {
    opacity: 0.75;
  }
`;

const deskApi = () => {
  const root = (import.meta.env.PUBLIC_API_ENDPOINT || '/api').replace(/\/$/, '');
  return root.endsWith('/api') ? `${root}/v1` : `${root}/api/v1`;
};

const downloadFile = async (apiKey: string, path: string, filename: string) => {
  const headers = new Headers();
  if (apiKey) headers.set('x-api-key', apiKey);
  const response = await fetch(`${deskApi()}${path}`, { headers });
  if (!response.ok) {
    const text = await response.text();
    let message = text;
    try {
      message = JSON.parse(text).error || message;
    } catch {
      message = text;
    }
    throw new Error(message || `HTTP ${response.status}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  return filename;
};

const Desk = (): JSX.Element => {
  const initialTarget = useMemo(
    () => new URLSearchParams(window.location.search).get('target') || '',
    [],
  );
  const [apiKey, setApiKey] = useState('');
  const [target, setTarget] = useState(initialTarget);
  const [output, setOutput] = useState('Ready.');
  const [scanId, setScanId] = useState('');

  useEffect(() => {
    setApiKey(window.localStorage.getItem('cormorant.apiKey') || '');
  }, []);

  const saveKey = (value: string) => {
    setApiKey(value);
    window.localStorage.setItem('cormorant.apiKey', value);
  };

  const call = async (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    if (apiKey) headers.set('x-api-key', apiKey);
    if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
    const response = await fetch(`${deskApi()}${path}`, { ...init, headers });
    const text = await response.text();
    let body: any = text;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = text;
    }
    if (!response.ok)
      throw new Error(typeof body === 'string' ? body : body.error || `HTTP ${response.status}`);
    return body;
  };

  const show = (value: unknown) =>
    setOutput(typeof value === 'string' ? value : JSON.stringify(value, null, 2));

  const run = async (work: () => Promise<unknown>) => {
    try {
      show(await work());
    } catch (error) {
      show(error instanceof Error ? error.message : 'Request failed');
    }
  };

  return (
    <Page>
      <header>
        <h1>OSINT Desk</h1>
        <p>
          Passive checks, monitoring, and gated authorized scans. A high score is not proof of
          safety. Plain scans never run Nmap or pentest modules.
        </p>
      </header>
      <section>
        <label>
          API key, stored in this browser
          <input
            value={apiKey}
            onChange={(event) => saveKey(event.target.value)}
            autoComplete="off"
          />
        </label>
        <label>
          Target
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="example.com"
          />
        </label>
      </section>
      <section id="project">
        <h2>Project map</h2>
        <ProjectMap target={target} here="desk" />
      </section>
      <section id="scan">
        <h2>Scan, timeline, inventory</h2>
        <button
          type="button"
          onClick={() =>
            run(async () => {
              const scan = await call('/scans', {
                method: 'POST',
                body: JSON.stringify({ target }),
              });
              setScanId(scan.id);
              return scan;
            })
          }
        >
          Start scan
        </button>
        <button
          type="button"
          onClick={() => run(() => call(`/scans/${scanId}`))}
          disabled={!scanId}
        >
          Poll status
        </button>
        <button
          type="button"
          onClick={() => run(() => call(`/scans/${scanId}/results`))}
          disabled={!scanId}
        >
          Results
        </button>
        <button
          type="button"
          onClick={() => run(() => call(`/timeline?target=${encodeURIComponent(target)}`))}
        >
          Timeline
        </button>
        <button
          type="button"
          onClick={() => run(() => call(`/assets?target=${encodeURIComponent(target)}`))}
        >
          Assets
        </button>
        <Monitor onRun={run} call={call} target={target} />
      </section>
      <Investigation target={target} apiKey={apiKey} onRun={run} call={call} />
      <Links target={target} onRun={run} call={call} />
      <History target={target} onRun={run} call={call} />
      <Records target={target} onRun={run} call={call} />
      <Offline apiKey={apiKey} onRun={run} call={call} />
      <Nmap onRun={run} call={call} target={target} />
      <Engagement onRun={run} call={call} />
      <Audit onRun={run} call={call} />
      <pre>{output}</pre>
    </Page>
  );
};

type Disposition = 'open' | 'accepted' | 'false-positive' | 'fixed';

interface InvestigationStatus {
  id: string;
  status: string;
  stage: string;
  domain: string;
  progress: { total: number; complete: number };
  hosts: { host: string; scanId: string; status: string; risk: number | null; reused: boolean }[];
  held: string[];
  related: { host: string; source: string }[];
  log: { at: string; line: string }[];
  error: string | null;
}

interface InvestigationReport {
  id: string;
  narrative: string[];
  analystSummary: string | null;
  risk: {
    score: number | null;
    letter: string;
    min: number | null;
    mean: number | null;
    perHost: { host: string; score: number | null; letter: string; reused: boolean }[];
  };
  coverage: { requested: number; scanned: number; reused: number; failed: number };
  facts: {
    kind: string;
    value: string;
    confidence: string;
    sources: string[];
    hosts: string[];
    severity?: string;
    detail?: string;
  }[];
  findings: {
    key: string;
    host: string;
    hosts: string[];
    scope: 'host' | 'domain';
    source: string;
    detail: string;
    points: number;
    action: string | null;
    disposition: Disposition;
  }[];
  gaps: { gap: string; why: string; next: string }[];
  note: string;
}

const Investigation = ({
  target,
  apiKey,
  onRun,
  call,
}: {
  target: string;
  apiKey: string;
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => {
  const [maxHosts, setMaxHosts] = useState('12');
  const [status, setStatus] = useState<InvestigationStatus | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [summary, setSummary] = useState('');
  const [dispositions, setDispositions] = useState<Record<string, Disposition>>({});
  const id = status?.id || '';

  const start = () =>
    onRun(async () => {
      const body = await call('/investigations', {
        method: 'POST',
        body: JSON.stringify({ target, maxHosts: Number(maxHosts) }),
      });
      setStatus(body);
      setReport(null);
      setDispositions({});
      return body;
    });
  const refresh = () =>
    onRun(async () => {
      const body = await call(`/investigations/${id}`);
      setStatus(body);
      return body;
    });
  const loadLatest = () =>
    onRun(async () => {
      const wanted = target
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .split(/[/?#]/)[0];
      const body = await call('/investigations');
      const match = (body.investigations || []).find(
        (row: InvestigationStatus & { hostname: string }) => !wanted || row.hostname === wanted,
      );
      if (!match) throw new Error(`No investigation on file for ${wanted || 'this tenant'}`);
      setStatus(match);
      setReport(null);
      setDispositions({});
      return match;
    });
  const loadReport = () =>
    onRun(async () => {
      const body: InvestigationReport = await call(`/investigations/${id}/report`);
      setReport(body);
      setSummary(body.analystSummary || '');
      setDispositions({});
      return `Report for ${body.id}: ${body.facts.length} facts, ${body.findings.length} findings, ${body.gaps.length} gaps. Rendered above.`;
    });
  const saveNotes = () =>
    onRun(async () => {
      const body = await call(`/investigations/${id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ summary, dispositions }),
      });
      const fresh: InvestigationReport = await call(`/investigations/${id}/report`);
      setReport(fresh);
      setDispositions({});
      return body;
    });
  const dispositionOf = (finding: InvestigationReport['findings'][number]) =>
    dispositions[finding.key] || finding.disposition;

  return (
    <section id="investigation">
      <h2>Investigation</h2>
      <p>
        One root scan, then pivots to the organisation&apos;s own hosts under the same registrable
        domain, prioritised the way an analyst would open them: remote access, mail, identity,
        administration, pre-production. Results under 24 hours old are reused. Hosts on other
        domains are listed as related and are not scanned. The dossier marks each fact with a
        confidence drawn from independent host and source pairs, and lists what the public record
        did not answer.
      </p>
      <label>
        Host cap for this investigation (1 to 12)
        <input value={maxHosts} onChange={(event) => setMaxHosts(event.target.value)} />
      </label>
      <button type="button" onClick={start}>
        Start investigation
      </button>
      <button type="button" onClick={loadLatest}>
        Load latest for target
      </button>
      <button type="button" onClick={refresh} disabled={!id}>
        Refresh status
      </button>
      <button type="button" onClick={loadReport} disabled={status?.status !== 'complete'}>
        Load dossier
      </button>
      <button
        type="button"
        disabled={status?.status !== 'complete'}
        onClick={() =>
          onRun(() =>
            downloadFile(
              apiKey,
              `/investigations/${id}/report.pdf`,
              `cormorant-investigation-${status?.domain || 'report'}.pdf`,
            ),
          )
        }
      >
        Download PDF
      </button>
      {status && (
        <>
          <p>
            <strong>{status.status}</strong> · stage {status.stage} · {status.progress.complete} of{' '}
            {status.progress.total} host scan(s) finished
            {status.error ? ` · ${status.error}` : ''}
          </p>
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Reused</th>
              </tr>
            </thead>
            <tbody>
              {status.hosts.map((row) => (
                <tr key={row.scanId}>
                  <td>{row.host}</td>
                  <td>{row.status}</td>
                  <td>{row.risk ?? '—'}</td>
                  <td>{row.reused ? 'yes' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {status.held.length > 0 && (
            <p className="muted">Held by the cap: {status.held.join(', ')}</p>
          )}
          {status.related.length > 0 && (
            <p className="muted">
              Related, not scanned: {status.related.map((row) => row.host).join(', ')}
            </p>
          )}
          <ul className="muted">
            {status.log.map((entry, index) => (
              <li key={`${entry.at}-${index}`}>
                {entry.at} · {entry.line}
              </li>
            ))}
          </ul>
        </>
      )}
      {report && (
        <>
          <h3>
            Organisation risk{' '}
            {report.risk.score == null ? 'n/a' : `${report.risk.score} (${report.risk.letter})`}
          </h3>
          <p className="muted">
            Weakest host {report.risk.min ?? 'n/a'}, mean {report.risk.mean ?? 'n/a'}.{' '}
            {report.coverage.scanned} of {report.coverage.requested} host(s) scanned,{' '}
            {report.coverage.reused} reused, {report.coverage.failed} failed.
          </p>
          <h3>Analyst summary</h3>
          <textarea
            value={summary}
            onChange={(event) => setSummary(event.target.value)}
            rows={4}
            placeholder="Write the client-facing summary here. Saved with the dispositions."
          />
          <h3>Collection narrative</h3>
          <ul>
            {report.narrative.map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ul>
          <h3>Findings ({report.findings.length})</h3>
          <table>
            <thead>
              <tr>
                <th>Points</th>
                <th>Host</th>
                <th>Finding</th>
                <th>Disposition</th>
              </tr>
            </thead>
            <tbody>
              {report.findings.map((finding) => (
                <tr key={finding.key}>
                  <td>-{finding.points}</td>
                  <td>
                    {finding.host}
                    {finding.scope === 'domain' && (
                      <div className="muted">domain · seen from {finding.hosts.join(', ')}</div>
                    )}
                  </td>
                  <td>
                    <strong>{finding.source}</strong> {finding.detail}
                    {finding.action && <div className="muted">{finding.action}</div>}
                  </td>
                  <td>
                    <select
                      value={dispositionOf(finding)}
                      onChange={(event) =>
                        setDispositions({
                          ...dispositions,
                          [finding.key]: event.target.value as Disposition,
                        })
                      }
                    >
                      <option value="open">open</option>
                      <option value="accepted">accepted</option>
                      <option value="false-positive">false positive</option>
                      <option value="fixed">fixed</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button type="button" onClick={saveNotes}>
            Save summary and dispositions
          </button>
          <h3>Facts ({report.facts.length})</h3>
          <table>
            <thead>
              <tr>
                <th>Confidence</th>
                <th>Kind</th>
                <th>Value</th>
                <th>Sources</th>
                <th>Hosts</th>
              </tr>
            </thead>
            <tbody>
              {report.facts.map((fact) => (
                <tr key={`${fact.kind}:${fact.value}`}>
                  <td>{fact.confidence}</td>
                  <td>{fact.kind}</td>
                  <td>
                    {fact.value}
                    {fact.severity ? ` (${fact.severity})` : ''}
                    {fact.detail && <div className="muted">{fact.detail}</div>}
                  </td>
                  <td>{fact.sources.join(', ')}</td>
                  <td>{fact.hosts.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Intelligence gaps ({report.gaps.length})</h3>
          <ul>
            {report.gaps.map((gap) => (
              <li key={gap.gap}>
                <strong>{gap.gap}</strong> — {gap.why}{' '}
                <span className="muted">Next: {gap.next}</span>
              </li>
            ))}
          </ul>
          <p className="muted">{report.note}</p>
        </>
      )}
    </section>
  );
};

const Links = ({
  target,
  onRun,
  call,
}: {
  target: string;
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => {
  const [text, setText] = useState('');
  const send = (harvest: boolean) =>
    onRun(() =>
      call('/links', {
        method: 'POST',
        body: JSON.stringify({
          text,
          target: harvest ? target : undefined,
          queue: true,
        }),
      }),
    );
  return (
    <section id="links">
      <h2>Link list</h2>
      <p>
        Paste a dump, one link or host per line. The same host is kept once. Hosts this tenant
        already queued or finished are named and skipped. Harvest reads the links on the target page
        and its public subdomains, then queues the new hosts.
      </p>
      <label>
        Pasted links
        <textarea
          value={text}
          onChange={(event) => setText(event.target.value)}
          rows={5}
          placeholder="https://example.com/docs"
        />
      </label>
      <button type="button" onClick={() => send(false)}>
        Queue pasted links
      </button>
      <button type="button" onClick={() => send(true)}>
        Harvest this page
      </button>
    </section>
  );
};

const Monitor = ({
  onRun,
  call,
  target,
}: {
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
  target: string;
}) => {
  const [everyMinutes, setEveryMinutes] = useState('1440');
  return (
    <label>
      Monitor interval in minutes
      <input value={everyMinutes} onChange={(event) => setEveryMinutes(event.target.value)} />
      <button
        type="button"
        onClick={() =>
          onRun(() =>
            call('/monitors', {
              method: 'POST',
              body: JSON.stringify({ target, everyMinutes: Number(everyMinutes) }),
            }),
          )
        }
      >
        Create monitor
      </button>
      <button type="button" onClick={() => onRun(() => call('/monitors'))}>
        List monitors
      </button>
    </label>
  );
};

const Offline = ({
  apiKey,
  onRun,
  call,
}: {
  apiKey: string;
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => {
  const [removeLocal, setRemoveLocal] = useState(true);
  const download = () =>
    onRun(async () => ({
      downloaded: await downloadFile(apiKey, '/export.zip', 'cormorant-offline.zip'),
      note: 'Save the zip onto the USB or external drive. This server still has the copy until a drive export with removal finishes.',
    }));
  return (
    <section id="offline">
      <h2>Offline copy</h2>
      <p>
        Write this tenant&apos;s scans, dossiers, and PDFs to a USB stick or external drive. Open
        index.html from the drive. The folder does not contact the server, and passwords are not
        copied.
      </p>
      <label>
        <input
          type="checkbox"
          checked={removeLocal}
          onChange={(event) => setRemoveLocal(event.target.checked)}
        />
        Remove the server copy after the drive write succeeds
      </label>
      <button
        type="button"
        onClick={() =>
          onRun(() =>
            call('/export', {
              method: 'POST',
              body: JSON.stringify({ removeLocal }),
            }),
          )
        }
      >
        Save to external drive
      </button>
      <button type="button" onClick={download}>
        Download zip
      </button>
    </section>
  );
};

const Records = ({
  target,
  onRun,
  call,
}: {
  target: string;
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => (
  <section id="records">
    <h2>Public record</h2>
    <p>
      Mail policy, PDF and Word files already linked on the site, and the public certificate log.
      Authors stay in the report. They are not looked up. DKIM uses only published provider
      selectors.
    </p>
    <button
      type="button"
      onClick={() => onRun(() => call(`/records?target=${encodeURIComponent(target)}`))}
    >
      Read public record
    </button>
  </section>
);

const History = ({
  target,
  onRun,
  call,
}: {
  target: string;
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => {
  const [history, setHistory] = useState<any>(null);
  const load = () =>
    onRun(async () => {
      const body = await call(`/history?target=${encodeURIComponent(target)}`);
      setHistory(body);
      return body;
    });
  const trend = Array.isArray(history?.trend) ? history.trend : [];
  const max = 100;
  return (
    <section id="history">
      <h2>Target history</h2>
      <p>
        Read-only. Lists this tenant's scans, the risk score over time, and the latest findings.
      </p>
      <button type="button" onClick={load}>
        Load history
      </button>
      {history && (
        <>
          <div
            style={{ display: 'flex', alignItems: 'flex-end', gap: 6, height: 90, marginTop: 12 }}
          >
            {trend.length === 0 && <span>No scored scans yet.</span>}
            {trend.map(
              (point: { scannedAt?: string; riskScore?: number | null }, index: number) => (
                <div
                  key={`${point.scannedAt}-${index}`}
                  title={`${point.scannedAt || ''} ${point.riskScore ?? 'n/a'}`}
                  style={{
                    width: 18,
                    height: `${Math.max(4, ((point.riskScore || 0) / max) * 80)}px`,
                    background: 'var(--primary)',
                  }}
                />
              ),
            )}
          </div>
          <ul>
            {(history.scans || []).map(
              (scan: {
                id: string;
                status: string;
                createdAt: string;
                risk?: { score?: number; letter?: string };
              }) => (
                <li key={scan.id}>
                  {scan.createdAt} · {scan.status}
                  {scan.risk?.score != null
                    ? ` · risk ${scan.risk.score} (${scan.risk.letter})`
                    : ''}
                </li>
              ),
            )}
          </ul>
          {history.latestFindings?.summary && (
            <p>{(history.latestFindings.summary || []).join(' ')}</p>
          )}
        </>
      )}
    </section>
  );
};

const Nmap = ({
  onRun,
  call,
  target,
}: {
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
  target: string;
}) => {
  const [operator, setOperator] = useState('');
  const [confirm, setConfirm] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [profile, setProfile] = useState('default');
  return (
    <section id="nmap">
      <h2>Authorized port scan</h2>
      <p>Requires a checkbox, the exact host, and WEBCHECK_NMAP_ENABLED. No exploit scripts.</p>
      <label>
        Operator
        <input value={operator} onChange={(event) => setOperator(event.target.value)} />
      </label>
      <label>
        Type the exact host to authorize
        <input value={confirm} onChange={(event) => setConfirm(event.target.value)} />
      </label>
      <label>
        <span>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />{' '}
          I am authorized to scan this target
        </span>
      </label>
      <label>
        Profile
        <select value={profile} onChange={(event) => setProfile(event.target.value)}>
          <option value="default">TCP connect, top 100</option>
          <option value="version">TCP connect plus light versions</option>
          <option value="deeper">Top 1000, still no scripts</option>
          <option value="syn">SYN, root only</option>
        </select>
      </label>
      <button
        type="button"
        onClick={() =>
          onRun(async () => {
            const authorization = await call('/authorizations', {
              method: 'POST',
              body: JSON.stringify({ target, confirm, operator, acknowledged }),
            });
            return call('/nmap', {
              method: 'POST',
              body: JSON.stringify({ authorizationId: authorization.id, profile }),
            });
          })
        }
      >
        Authorize and queue
      </button>
    </section>
  );
};

const Engagement = ({
  onRun,
  call,
}: {
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => {
  const [clientName, setClientName] = useState('');
  const [operator, setOperator] = useState('');
  const [scope, setScope] = useState('');
  const [confirm, setConfirm] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <section id="engagement">
      <h2>Pentest engagement</h2>
      <p>
        Nothing here runs unless WEBCHECK_PENTEST_ENABLED is set and the phrase matches. Password
        spraying is refused.
      </p>
      <label>
        Client
        <input value={clientName} onChange={(event) => setClientName(event.target.value)} />
      </label>
      <label>
        Operator
        <input value={operator} onChange={(event) => setOperator(event.target.value)} />
      </label>
      <label>
        Scope, one host per line
        <textarea value={scope} onChange={(event) => setScope(event.target.value)} rows={2} />
      </label>
      <label>
        Typed authorization
        <input
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          placeholder="I am authorized to test Client"
        />
      </label>
      <label>
        <span>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />{' '}
          Written authorization is on file
        </span>
      </label>
      <button
        type="button"
        onClick={() =>
          onRun(() =>
            call('/engagements', {
              method: 'POST',
              body: JSON.stringify({
                clientName,
                operator,
                scope: scope.split(/\s+/).filter(Boolean),
                confirm,
                acknowledged,
                start: new Date().toISOString().slice(0, 10),
                end: new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10),
              }),
            }),
          )
        }
      >
        Open engagement
      </button>
    </section>
  );
};

const Audit = ({
  onRun,
  call,
}: {
  onRun: (work: () => Promise<unknown>) => void;
  call: (path: string, init?: RequestInit) => Promise<any>;
}) => {
  const [storeUrl, setStoreUrl] = useState('');
  const [repo, setRepo] = useState('');
  const [people, setPeople] = useState('');
  const uploadApk = async (file: File | undefined) => {
    if (!file) return;
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    onRun(() =>
      call('/audit/apk', { method: 'POST', body: JSON.stringify({ base64: btoa(binary) }) }),
    );
  };
  return (
    <section id="audit">
      <h2>Mobile, SBOM, public people</h2>
      <label>
        Public store URL
        <input
          value={storeUrl}
          onChange={(event) => setStoreUrl(event.target.value)}
          placeholder="https://play.google.com/store/apps/details?id="
        />
      </label>
      <button
        type="button"
        onClick={() =>
          onRun(() => call('/audit/apk', { method: 'POST', body: JSON.stringify({ storeUrl }) }))
        }
      >
        Read store page
      </button>
      <label>
        APK upload, static review only
        <input
          type="file"
          accept=".apk,application/vnd.android.package-archive"
          onChange={(event) => uploadApk(event.target.files?.[0])}
        />
      </label>
      <label>
        Public GitHub repo
        <input
          value={repo}
          onChange={(event) => setRepo(event.target.value)}
          placeholder="https://github.com/org/repo"
        />
      </label>
      <button
        type="button"
        onClick={() =>
          onRun(() => call('/audit/sbom', { method: 'POST', body: JSON.stringify({ repo }) }))
        }
      >
        Query OSV
      </button>
      <label>
        Public profile URLs
        <textarea value={people} onChange={(event) => setPeople(event.target.value)} rows={2} />
      </label>
      <button
        type="button"
        onClick={() =>
          onRun(() =>
            call('/people', {
              method: 'POST',
              body: JSON.stringify({ publicUrls: people.split(/\s+/).filter(Boolean) }),
            }),
          )
        }
      >
        Read public bios
      </button>
    </section>
  );
};

export default Desk;
