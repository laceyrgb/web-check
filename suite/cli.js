#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { deliverMonitoring, createOutbox, refuseLiveSend } from './delivery.js';
import { gapMarkdown } from './inventory.js';
import { fetchIntel, httpsGetJson } from './intel/intel.js';
import { createLiveTransports } from './live.js';
import { runMonitor } from './monitor.js';
import { verifyOwnership } from './ownership.js';
import { renderExecutivePdf } from './pdf.js';
import { renderExecutiveHtml, renderHtml, renderJson } from './report-html.js';
import { applyReview } from './review.js';
import { runScan } from './runner.js';
import { openStore } from './store.js';
import { parseTarget } from './target.js';

export const parseArgs = (argv) => {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      out._.push(arg);
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    const value = !next || next.startsWith('--') ? true : next;
    if (value !== true) i += 1;
    if (key === 'deny') out.deny = [...(out.deny || []), value];
    else out[key] = value;
  }
  return out;
};

const asBool = (value) => value === true || value === 'true';

export const usage = `UAE Readiness Scan

  node suite/cli.js inventory
  node suite/cli.js scan --target scan.example --observations suite/fixtures/example-observations.json --out /tmp/readiness
  node suite/cli.js scan --target scan.example --live
  node suite/cli.js scan --target scan.example --live --mode active --authorized --verify-token <token>
  node suite/cli.js review --report /tmp/readiness/report.json --decisions decisions.json --reviewer "Name" --out /tmp/released
  node suite/cli.js refresh-intel --fetch --out /tmp/intel.json

Active checks also require a DNS TXT record at _cormorant-verify.<host> containing
cormorant-verify=<token>, or that same token as the body of
https://<host>/.well-known/cormorant-verify.txt.
Passive mode is the default. --live is what contacts the target.
A report stays a draft until critical and high findings are reviewed.`;

const writeReport = async (report, directory) => {
  await mkdir(directory, { recursive: true });
  const jsonPath = path.join(directory, 'report.json');
  const htmlPath = path.join(directory, 'report.html');
  await writeFile(jsonPath, renderJson(report));
  await writeFile(htmlPath, renderHtml(report));
  const executivePath = path.join(directory, 'executive.html');
  const pdfPath = path.join(directory, 'executive.pdf');
  await writeFile(executivePath, renderExecutiveHtml(report));
  await writeFile(pdfPath, renderExecutivePdf(report));
  return { jsonPath, htmlPath, executivePath, pdfPath };
};

export const scanFromArgs = async (args) => {
  const live = asBool(args.live);
  const observations =
    !live && args.observations ? JSON.parse(await readFile(args.observations, 'utf8')) : undefined;
  let previousReport;
  if (args.previous) previousReport = JSON.parse(await readFile(args.previous, 'utf8'));
  const transports = live ? createLiveTransports(parseTarget(args.target).hostname) : undefined;
  const store =
    args.store || args.out ? openStore(args.store || path.join(args.out, 'history')) : undefined;
  return runScan({
    target: args.target,
    observations: live ? undefined : observations,
    mode: live && args.mode === 'active' ? 'active' : 'passive',
    authorized: asBool(args.authorized),
    verificationToken: typeof args['verify-token'] === 'string' ? args['verify-token'] : '',
    transports,
    deny: (args.deny || []).filter((entry) => typeof entry === 'string'),
    engines: args.nuclei ? { nuclei: args.nuclei } : {},
    previousReport,
    store,
  });
};

export const runCli = async (argv) => {
  const args = parseArgs(argv);
  const command = args._[0];
  if (asBool(args.send)) {
    try {
      refuseLiveSend();
    } catch (error) {
      console.error(error.message);
      return 1;
    }
  }
  if (args.help || !command) {
    console.log(usage);
    return command ? 0 : 1;
  }
  if (command === 'inventory') {
    console.log(gapMarkdown());
    return 0;
  }
  if (command === 'review') {
    if (!args.report || !args.decisions || !args.reviewer) {
      console.error('review needs --report, --decisions, and --reviewer.');
      return 1;
    }
    const current = JSON.parse(await readFile(args.report, 'utf8'));
    const decisions = JSON.parse(await readFile(args.decisions, 'utf8'));
    const result = applyReview(current, {
      reviewer: args.reviewer,
      decisions: decisions.decisions || decisions,
    });
    if (!result.ok) {
      console.error(`Release blocked. Missing decisions: ${result.missing.join(', ')}`);
      return 1;
    }
    if (args.out) {
      const written = await writeReport(result.report, args.out);
      console.log(`${written.jsonPath}\n${written.pdfPath}`);
    } else {
      console.log(renderJson(result.report));
    }
    return 0;
  }
  if (command === 'monitor') {
    if (!asBool(args.live) || !args.subscription) {
      console.error('monitor needs --live and --subscription. It re-checks ownership, then scans.');
      return 1;
    }
    const subscription = JSON.parse(await readFile(args.subscription, 'utf8'));
    const previousReport = args.previous ? JSON.parse(await readFile(args.previous, 'utf8')) : null;
    const target = parseTarget(subscription.target);
    const transports = createLiveTransports(target.hostname);
    const store = args.store ? openStore(args.store) : undefined;
    const result = await runMonitor({
      subscription,
      previousReport,
      verify: () =>
        verifyOwnership({
          hostname: target.hostname,
          token: subscription.verificationToken,
          origin: target.origin,
          transports,
        }),
      scan: (options) => runScan({ ...options, transports, store }),
    });
    if (args.outbox && result.events) {
      await deliverMonitoring({
        outbox: createOutbox(args.outbox),
        hostname: target.hostname,
        score: result.report?.score?.value ?? null,
        events: result.events,
      });
    }
    if (args.out) {
      await mkdir(args.out, { recursive: true });
      await writeFile(path.join(args.out, 'events.json'), renderJson(result.events));
      if (result.report) await writeReport(result.report, args.out);
    }
    console.log(renderJson(result.events));
    return result.ran ? 0 : 2;
  }
  if (command === 'refresh-intel') {
    if (!asBool(args.fetch)) {
      console.error('refresh-intel contacts NVD, CISA, and FIRST. Pass --fetch to confirm.');
      return 1;
    }
    const cache = await fetchIntel(httpsGetJson);
    const body = renderJson(cache);
    if (args.out) await writeFile(args.out, body);
    else console.log(body);
    return 0;
  }
  if (command !== 'scan') {
    console.error(usage);
    return 1;
  }
  if (!args.target) {
    console.error('A --target is required.');
    return 1;
  }
  if (!asBool(args.live) && !args.observations) {
    console.error('Refusing to scan. Pass --observations or --live.');
    return 1;
  }
  if (args.mode === 'active' && !asBool(args.live)) {
    console.error('Refusing active mode without --live. A snapshot is not an authorisation.');
    return 1;
  }
  if (
    args.nuclei &&
    !(
      asBool(args.live) &&
      args.mode === 'active' &&
      asBool(args.authorized) &&
      args['verify-token']
    )
  ) {
    console.error(
      'Nuclei stays off unless you pass --live --mode active --authorized --verify-token.',
    );
    return 1;
  }
  const report = await scanFromArgs(args);
  if (args.out) {
    const written = await writeReport(report, args.out);
    console.log(`${written.jsonPath}\n${written.htmlPath}`);
  } else {
    console.log(renderJson(report));
  }
  return report.legal?.denied ? 2 : 0;
};

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error.message || error);
      process.exitCode = 1;
    });
}
