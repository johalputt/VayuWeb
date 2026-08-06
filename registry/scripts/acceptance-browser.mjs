#!/usr/bin/env node
/**
 * Phase 3 acceptance: an UNMODIFIED browser renders a VayuWeb name.
 *
 * docs/ROADMAP.md states Phase 3's acceptance criterion as a browser nobody patched displaying a
 * `.vayu` name, with no extension, no certificate installed and no flag beyond `--proxy-server`.
 * Everything the page needs comes from the resolver. This script is that criterion, executable.
 *
 * ## Why it is a script and not a test
 *
 * It needs a real browser. Adding Playwright to `registry/package.json` would put a browser
 * driver and its transitive tree into the dependency set that `security.yml` caps at forty
 * packages — a cap that exists so a change of KIND gets a human look. A test harness is exactly
 * such a change, and the acceptance criterion does not need to run on every push to be true.
 *
 * So it runs on demand, and it **refuses rather than skips** when it cannot run. A harness that
 * quietly reports success on a machine with no browser is worse than no harness: it converts an
 * unrun check into a green one, which is the failure this project has been bitten by more than
 * any other.
 *
 * ## Running it
 *
 *   npm --prefix /tmp/vw-acceptance install playwright
 *   NODE_PATH=/tmp/vw-acceptance/node_modules node registry/scripts/acceptance-browser.mjs
 *
 * Chromium is found via PLAYWRIGHT_BROWSERS_PATH or CHROMIUM_PATH. Nothing is written outside a
 * temporary directory, and every process it starts is stopped before it exits.
 */

import { spawn } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REGISTRY = dirname(HERE);
const CLI = join(REGISTRY, 'bin', 'vayuweb-registry.ts');
const NAME = 'atlasobservatory.vayu';
const PORT = Number(process.env['VAYUWEB_ACCEPTANCE_PORT'] ?? 7654);

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  — ${detail}` : ''}\n`);
};

/* -------------------------------------------------------------------------- */
/* Article 14, measured rather than asserted                                   */
/* -------------------------------------------------------------------------- */

/**
 * Every non-loopback TCP peer THIS PROCESS is connected to.
 *
 * A resolver serving a verified local blockstore must have none. Its listeners are inbound, and
 * an outbound connection to anywhere is the phone-home Constitution Article 14 forbids.
 *
 * **The inode join is the whole measurement.** `/proc/<pid>/net/tcp` is per network NAMESPACE,
 * not per process — reading it directly reports every socket in the container, and the first
 * version of this check answered "14 outbound connections" for a resolver that had opened none.
 * The process's own sockets are the ones whose inode appears in `/proc/<pid>/fd/*` as
 * `socket:[N]`, so the fd set is what makes this a statement about the resolver rather than
 * about the machine it happens to be running on.
 *
 * Counting sockets rather than trapping `dns.lookup`, too: a trap catches only the library that
 * honours it, and catches nothing in a child process or behind a connect to a literal address —
 * which is the shape a leak would actually take.
 */
function outboundPeers(pid) {
  const owned = new Set();
  for (const fd of readdirSync(`/proc/${pid}/fd`)) {
    let target;
    try {
      target = readlinkSync(`/proc/${pid}/fd/${fd}`);
    } catch {
      continue; // Closed between listing and reading; it is not a connection now.
    }
    const match = /^socket:\[(\d+)\]$/.exec(target);
    if (match !== null) owned.add(match[1]);
  }

  const peers = [];
  for (const table of ['tcp', 'tcp6']) {
    let text;
    try {
      text = readFileSync(`/proc/${pid}/net/${table}`, 'utf8');
    } catch {
      continue;
    }
    for (const line of text.split('\n').slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 10) continue;
      const [remote, state, inode] = [fields[2], fields[3], fields[9]];
      if (!owned.has(inode)) continue; // Another process sharing this namespace.
      if (state === '0A') continue; // LISTEN: inbound, not a connection this process made.
      const hex = (remote.split(':')[0] ?? '').toUpperCase();
      const loopback = hex === '0100007F' || /^0{31}1$/.test(hex) || /^0+$/.test(hex);
      if (!loopback) peers.push(remote);
    }
  }
  return peers;
}

/* -------------------------------------------------------------------------- */
/* Fixture                                                                     */
/* -------------------------------------------------------------------------- */

const INDEX = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Atlas Observatory</title>
    <link rel="stylesheet" href="/assets/style.css" />
  </head>
  <body>
    <h1 id="headline">Atlas Observatory</h1>
    <p id="proof">Served over VayuWeb from a verified content root.</p>
  </body>
</html>
`;
const STYLE = `body { background: #0b0f14; color: #e6edf3; font-family: system-ui, sans-serif; }
h1 { color: #7ee787; }
`;

function cli(args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', CLI, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...options,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

function chromiumPath() {
  if (process.env['CHROMIUM_PATH']) return process.env['CHROMIUM_PATH'];
  const root = process.env['PLAYWRIGHT_BROWSERS_PATH'];
  if (root && existsSync(root)) {
    for (const entry of readdirSync(root)) {
      const candidate = join(root, entry, 'chrome-linux', 'chrome');
      if (entry.startsWith('chromium-') && existsSync(candidate)) return candidate;
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* The run                                                                     */
/* -------------------------------------------------------------------------- */

const dir = mkdtempSync(join(tmpdir(), 'vayuweb-acceptance-'));
let resolver = null;
let browser = null;

try {
  // ESM ignores NODE_PATH, so the fallback resolves by hand. Written out rather than left to
  // "just install it here" because installing it here is the thing the dependency ceiling exists
  // to notice.
  let chromium = null;
  const attempts = ['playwright'];
  for (const root of (process.env['NODE_PATH'] ?? '').split(':').filter(Boolean)) {
    attempts.push(pathToFileURL(join(root, 'playwright', 'index.js')).href);
  }
  for (const specifier of attempts) {
    try {
      // Playwright's entry point is CommonJS, so the interop namespace may carry the exports on
      // `default` rather than as named ones. Taking whichever is present, and checking that the
      // result is usable, is the difference between "the import resolved" and "the driver is
      // here" — the first version stopped at the former and failed later with `undefined.launch`.
      const module = await import(specifier);
      chromium = module.chromium ?? module.default?.chromium ?? null;
      if (chromium !== null && chromium !== undefined) break;
    } catch {
      // Try the next candidate; the throw below reports them all at once.
    }
  }
  if (chromium === null || chromium === undefined) {
    throw new Error(
      `playwright is not importable (tried: ${attempts.join(', ')}). Install it outside this ` +
        'package — it is deliberately not a dependency, see the header — and put its ' +
        'node_modules on NODE_PATH.',
    );
  }
  const executablePath = chromiumPath();
  if (executablePath === null) {
    throw new Error('no Chromium found; set CHROMIUM_PATH or PLAYWRIGHT_BROWSERS_PATH');
  }

  const site = join(dir, 'site');
  mkdirSync(join(site, 'assets'), { recursive: true });
  writeFileSync(join(site, 'index.html'), INDEX);
  writeFileSync(join(site, 'assets', 'style.css'), STYLE);

  // The root CID comes out of the same importer the resolver uses, so the name is registered
  // against the address the content actually has rather than one asserted alongside it.
  const { importSite } = await import(join(REGISTRY, 'src', 'unixfs.ts'));
  const root = importSite([
    { path: 'index.html', content: Buffer.from(INDEX) },
    { path: 'assets/style.css', content: Buffer.from(STYLE) },
  ]).root;

  const key = join(dir, 'key');
  const log = join(dir, 'log');
  const generated = await cli(['keygen', '--key', key]);
  if (generated.code !== 0) throw new Error(`keygen failed: ${generated.err}`);

  process.stdout.write(`registering ${NAME} -> ${root} (solving proof of work)\n`);
  const registered = await cli([
    'register',
    '--log',
    log,
    '--key',
    key,
    '--name',
    NAME,
    '--cid',
    root,
  ]);
  if (registered.code !== 0) throw new Error(`register failed: ${registered.err}`);

  resolver = spawn(
    process.execPath,
    [
      '--experimental-strip-types',
      CLI,
      'serve',
      '--log',
      log,
      '--port',
      String(PORT),
      '--socket',
      join(dir, 'control.sock'),
      '--site',
      site,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let banner = '';
  resolver.stdout.on('data', (d) => (banner += d));
  resolver.stderr.on('data', (d) => (banner += d));
  await new Promise((resolve, reject) => {
    const deadline = setTimeout(
      () => reject(new Error(`resolver did not start:\n${banner}`)),
      20_000,
    );
    const poll = setInterval(() => {
      if (banner.includes('browsing proxy')) {
        clearInterval(poll);
        clearTimeout(deadline);
        resolve();
      }
      if (resolver.exitCode !== null) {
        clearInterval(poll);
        clearTimeout(deadline);
        reject(new Error(`resolver exited ${resolver.exitCode}:\n${banner}`));
      }
    }, 100);
  });

  browser = await chromium.launch({
    executablePath,
    args: [`--proxy-server=http://127.0.0.1:${PORT}`, '--proxy-bypass-list=<-loopback>'],
  });
  const context = await browser.newContext();

  const requested = [];
  const failed = [];
  context.on('request', (r) => requested.push(r.url()));
  context.on('requestfailed', (r) => failed.push([r.url(), r.failure()?.errorText]));

  const page = await context.newPage();
  const response = await page.goto(`http://${NAME}/`, { waitUntil: 'load', timeout: 20_000 });

  check(
    'navigation returned 200',
    response !== null && response.status() === 200,
    String(response?.status()),
  );

  const headline = await page.textContent('#headline');
  check(
    'the page rendered from verified content',
    headline === 'Atlas Observatory',
    JSON.stringify(headline),
  );

  // Proves the SECOND fetch worked, not just the first: a resolver that serves index.html and
  // nothing else renders an unstyled page that still passes a text assertion.
  const colour = await page.evaluate(() => getComputedStyle(document.querySelector('h1')).color);
  check('the stylesheet was fetched and applied', colour === 'rgb(126, 231, 135)', colour);

  const csp = response?.headers()['content-security-policy'] ?? '';
  check("the CSP reached the browser with default-src 'none'", csp.includes("default-src 'none'"));
  check('no request failed', failed.length === 0, JSON.stringify(failed));
  check(
    'every request stayed inside the VayuWeb name',
    requested.length > 0 && requested.every((u) => u.startsWith(`http://${NAME}/`)),
    JSON.stringify(requested),
  );

  // A name outside the ratified namespace must be refused here, not handed to the OS resolver:
  // that is what makes "no DNS fallback" a property rather than an intention.
  const other = await context.newPage();
  let refused = false;
  try {
    const fallback = await other.goto('http://example.com/', { timeout: 15_000 });
    refused = fallback === null || fallback.status() >= 400;
  } catch {
    refused = true;
  }
  check('a non-VayuWeb name is refused, not resolved', refused);

  check(
    'the resolver opened no outbound connection (Constitution Art. 14)',
    outboundPeers(resolver.pid).length === 0,
    JSON.stringify(outboundPeers(resolver.pid)),
  );
} catch (error) {
  check('the harness ran at all', false, String(error).split('\n').slice(0, 3).join(' / '));
} finally {
  if (browser !== null) await browser.close().catch(() => {});
  if (resolver !== null) resolver.kill('SIGTERM');
  rmSync(dir, { recursive: true, force: true });
}

const passed = results.filter((r) => r.ok).length;
process.stdout.write(`\n${passed}/${results.length} checks passed\n`);
process.exit(passed === results.length && results.length > 1 ? 0 : 1);
