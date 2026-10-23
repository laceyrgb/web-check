import net from 'net';
import tls from 'tls';

export const ALERT_TYPES = new Set(['risk-worse', 'new-subdomain', 'new-cert-name', 'cert-change']);

export const selectAlerts = (changes = []) => changes.filter((row) => ALERT_TYPES.has(row.type));

// Replies are buffered from the moment the socket exists. A greeting can
// arrive before the caller asks for it, and the listener must come off
// before STARTTLS so it does not swallow the handshake.
const openMailbox = (socket) => {
  let buffer = '';
  let waiter = null;
  const pump = () => {
    if (!waiter || !buffer.endsWith('\r\n')) return;
    const lines = buffer.split('\r\n').filter(Boolean);
    const last = lines.at(-1) || '';
    if (last.length < 4 || last[3] === '-') return;
    const code = Number(last.slice(0, 3));
    const text = last;
    buffer = '';
    const current = waiter;
    waiter = null;
    if (!Number.isFinite(code)) current.reject(new Error('SMTP reply was not understood'));
    else current.resolve({ code, text });
  };
  const onData = (chunk) => {
    buffer += chunk.toString('utf8');
    pump();
  };
  socket.on('data', onData);
  return {
    expect(ok) {
      return new Promise((resolve, reject) => {
        waiter = {
          resolve: (value) =>
            ok(value.code) ? resolve(value) : reject(new Error(`SMTP ${value.text}`)),
          reject,
        };
        pump();
      });
    },
    detach() {
      socket.off('data', onData);
    },
  };
};

const command = async (mailbox, socket, line, ok) => {
  socket.write(`${line}\r\n`);
  return mailbox.expect(ok);
};

export const sendSmtpMail = async ({ host, port = 587, user, pass, from, to, subject, text }) => {
  const secure = Number(port) === 465;
  let socket = secure
    ? tls.connect({ host, port: Number(port), servername: host })
    : net.connect({ host, port: Number(port) });
  let mailbox = openMailbox(socket);
  await new Promise((resolve, reject) => {
    socket.once('secure', resolve);
    socket.once('connect', () => {
      if (!secure) resolve();
    });
    socket.once('error', reject);
  });
  await mailbox.expect((code) => code === 220);
  await command(mailbox, socket, 'EHLO cormorant', (code) => code === 250);
  if (!secure && Number(port) === 587) {
    await command(mailbox, socket, 'STARTTLS', (code) => code === 220);
    mailbox.detach();
    socket = await new Promise((resolve, reject) => {
      const upgraded = tls.connect({ socket, servername: host }, () => resolve(upgraded));
      upgraded.once('error', reject);
    });
    mailbox = openMailbox(socket);
    await command(mailbox, socket, 'EHLO cormorant', (code) => code === 250);
  }
  if (user) {
    await command(mailbox, socket, 'AUTH LOGIN', (code) => code === 334);
    await command(
      mailbox,
      socket,
      Buffer.from(String(user)).toString('base64'),
      (code) => code === 334,
    );
    await command(
      mailbox,
      socket,
      Buffer.from(String(pass || '')).toString('base64'),
      (code) => code === 235,
    );
  }
  await command(mailbox, socket, `MAIL FROM:<${from}>`, (code) => code === 250);
  await command(mailbox, socket, `RCPT TO:<${to}>`, (code) => code === 250 || code === 251);
  await command(mailbox, socket, 'DATA', (code) => code === 354);
  const body = [
    `Subject: ${subject}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    text.replace(/^\./gm, '..'),
    '.',
  ].join('\r\n');
  socket.write(`${body}\r\n`);
  await mailbox.expect((code) => code === 250);
  socket.write('QUIT\r\n');
  socket.end();
};

export const deliverAlerts = async (event, deps = {}) => {
  const changes = selectAlerts(event.changes);
  if (!changes.length) return { delivered: [], skipped: 'no-alert' };
  const text = [
    `Cormorant monitor alert for ${event.target}`,
    ...changes.map((row) => `${row.type}: ${row.value}`),
  ].join('\n');
  const delivered = [];
  const fetchImpl = deps.fetchImpl || fetch;
  const slack = process.env.WEBCHECK_SLACK_WEBHOOK_URL || process.env.SLACK_WEBHOOK_URL;
  const emailTo = process.env.WEBCHECK_ALERT_EMAIL_TO;
  const smtpHost = process.env.WEBCHECK_SMTP_HOST;
  if (!slack && !(emailTo && smtpHost)) return { delivered: [], skipped: 'unconfigured' };
  if (slack) {
    const response = await fetchImpl(slack, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) throw new Error(`Slack webhook HTTP ${response.status}`);
    delivered.push('slack');
  }
  if (emailTo && smtpHost) {
    const send = deps.sendMail || sendSmtpMail;
    await send({
      host: smtpHost,
      port: Number(process.env.WEBCHECK_SMTP_PORT || 587),
      user: process.env.WEBCHECK_SMTP_USER,
      pass: process.env.WEBCHECK_SMTP_PASS,
      from: process.env.WEBCHECK_ALERT_EMAIL_FROM || 'cormorant@localhost',
      to: emailTo,
      subject: `Cormorant alert: ${event.target}`,
      text,
    });
    delivered.push('email');
  }
  return { delivered };
};
