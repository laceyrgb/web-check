import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

// Pluggable delivery. The only implementation writes an outbox. It has no credentials
// and it does not open a socket.
export const renderMessage = ({ hostname, score, events = [] }) => {
  const opened = events.filter((event) => event.type === 'finding.opened').length;
  const resolved = events.filter((event) => event.type === 'finding.resolved').length;
  const scoreText = score ?? 'n/a';
  return {
    subject: `UAE Readiness Scan: ${hostname}`,
    text: `UAE Readiness Scan for ${hostname}. Score ${scoreText}. New findings: ${opened}. Resolved: ${resolved}. Arabic wording needs native review before this note is sent to a customer.`,
    textAr: `فحص الجاهزية لـ ${hostname}. النتيجة ${scoreText}. نتائج جديدة: ${opened}. نتائج أُغلقت: ${resolved}. النص العربي يحتاج مراجعة لغوية قبل إرساله إلى العميل.`,
    needsNativeReview: true,
  };
};

export const createOutbox = (dir) => {
  mkdirSync(dir, { recursive: true });
  return {
    mode: 'dry-run',
    async deliver(channel, message) {
      if (!['email', 'whatsapp'].includes(channel)) {
        throw new Error(`Unknown delivery channel ${channel}`);
      }
      if (message.credentials || message.smtp || message.token || message.apiKey) {
        throw new Error('Delivery refuses credentials. This build only writes an outbox.');
      }
      const id = `${channel}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const file = path.join(dir, `${id}.json`);
      const body = {
        channel,
        mode: 'dry-run',
        sent: false,
        subject: message.subject,
        text: message.text,
        textAr: message.textAr,
        needsNativeReview: true,
      };
      writeFileSync(file, `${JSON.stringify(body, null, 2)}\n`);
      return { file, sent: false, channel };
    },
  };
};

export const createChannel = (name, outbox) => ({
  name,
  async send(message) {
    return outbox.deliver(name, message);
  },
});

export const deliverMonitoring = async ({
  outbox,
  channels = ['email', 'whatsapp'],
  hostname,
  score,
  events,
}) => {
  const message = renderMessage({ hostname, score, events });
  const sent = [];
  for (const channel of channels) {
    const adapter = createChannel(channel, outbox);
    sent.push(await adapter.send(message));
  }
  return sent;
};

export const refuseLiveSend = () => {
  throw new Error('Sending is disabled. Delivery writes an outbox only.');
};
