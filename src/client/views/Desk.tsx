import { useEffect, useMemo, useState } from 'react';
import styled from '@emotion/styled';
import colors from 'client/styles/colors';

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
`;

const deskApi = () => {
  const root = (import.meta.env.PUBLIC_API_ENDPOINT || '/api').replace(/\/$/, '');
  return root.endsWith('/api') ? `${root}/v1` : `${root}/api/v1`;
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
      <section>
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
    <section>
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
    onRun(async () => {
      const headers = new Headers();
      if (apiKey) headers.set('x-api-key', apiKey);
      const response = await fetch(`${deskApi()}/export.zip`, { headers });
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
      anchor.download = 'cormorant-offline.zip';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      return {
        downloaded: anchor.download,
        note: 'Save the zip onto the USB or external drive. This server still has the copy until a drive export with removal finishes.',
      };
    });
  return (
    <section>
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
  <section>
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
    <section>
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
    <section>
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
    <section>
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
    <section>
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
