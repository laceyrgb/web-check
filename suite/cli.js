#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { gapMarkdown } from './inventory.js';
import { createLiveTransports } from './live.js';
import { renderHtml, renderJson } from './report-html.js';
import { runScan } from './runner.js';
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

Active checks also require a DNS TXT record at _cormorant-verify.<host> containing
cormorant-verify=<token>, or that same token as the body of
https://<host>/.well-known/cormorant-verify.txt.
Passive mode is the default. --live is what contacts the target.`;

const writeReport = async (report, directory) => {
  await mkdir(directory, { recursive: true });
  const jsonPath = path.join(directory, 'report.json');
  const htmlPath = path.join(directory, 'report.html');
  await writeFile(jsonPath, renderJson(report));
  await writeFile(htmlPath, renderHtml(report));
  return { jsonPath, htmlPath };
};

export const scanFromArgs = async (args) => {
  const live = asBool(args.live);
  const observations =
    !live && args.observations ? JSON.parse(await readFile(args.observations, 'utf8')) : undefined;
  let previousReport;
  if (args.previous) previousReport = JSON.parse(await readFile(args.previous, 'utf8'));
  const transports = live ? createLiveTransports(parseTarget(args.target).hostname) : undefined;
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
  });
};

export const runCli = async (argv) => {
  const args = parseArgs(argv);
  const command = args._[0];
  if (args.help || !command) {
    console.log(usage);
    return command ? 0 : 1;
  }
  if (command === 'inventory') {
    console.log(gapMarkdown());
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
