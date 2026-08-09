#!/usr/bin/env node
/**
 * Phase 3 acceptance: an UNMODIFIED browser renders a VayuWeb name.
 *
 * docs/ROADMAP.md states Phase 3's acceptance criterion as a browser nobody patched displaying a
 * `.vayu` name, with no extension and no certificate installed. Everything the page needs comes
 * from the resolver. This script is that criterion, executable.
 *
 * **Two flags, not one, and the difference is not cosmetic.** The header used to say "no flag
 * beyond `--proxy-server`" while the launch also passed `--proxy-bypass-list=<-loopback>`. That
 * second flag is not a no-op: it SUBTRACTS Chromium's built-in loopback bypass, which would
 * otherwise send `http://atlasobservatory.vayu/` — a name Chromium does not know is not local —
 * around the proxy for any address it resolves to loopback. So the configuration under test was
 * not the configuration documented, and the documented one is the weaker claim of the two.
 *
 * Neither flag installs anything, grants a permission, or teaches Chromium what a `.vayu` name
 * is: they point it at a proxy and stop it bypassing that proxy. A browser configured this way is
 * still a browser nobody modified, which is what Phase 3 asks for.
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

/**
 * A second name carrying ONLY an `ipns` pointer, so step 10 is the only way it can render.
 *
 * `SOURCE_ORDER` puts `ipns` first and HOSTING.md tells publishers to write one, and until step 10
 * was implemented nothing could act on it: a record carrying only a pointer answered 1421
 * `NO_USABLE_RECORD` — "this name points at nothing fetchable" — about a record that is exactly
 * what the specification recommends. With no `cid` beside it there is nothing to fall back to, so
 * this page loading is the pointer path working and cannot be anything else.
 */
const POINTER_NAME = 'borealisstations.vayu';
const POINTER = 'k51qzi5uqu5dabcdefghijklmnopqrstuvwxyz0123456789';
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
 * The socket inodes a process actually holds open.
 *
 * **This join is what makes every check below a statement about a process.**
 * `/proc/<pid>/net/tcp` is per network NAMESPACE, not per process — reading it directly reports
 * every socket in the container, and the first version of this harness answered "14 outbound
 * connections" for a resolver that had opened none.
 */
function socketInodes(pid) {
  const owned = new Set();
  let entries;
  try {
    entries = readdirSync(`/proc/${pid}/fd`);
  } catch {
    // **Not "it holds nothing".** An unreadable fd table is a failure to OBSERVE, and this used
    // to be returned as an empty set — which both callers then filtered every socket through,
    // yielding zero peers and zero DNS sockets, which the harness reported as a PASS. A dead or
    // unreadable process was evidence of good behaviour. The flag is what lets the caller tell
    // "nothing happened" from "nothing was looked at".
    return { inodes: owned, observed: false };
  }
  for (const fd of entries) {
    let target;
    try {
      target = readlinkSync(`/proc/${pid}/fd/${fd}`);
    } catch {
      continue; // Closed between listing and reading; it is not a connection now.
    }
    const match = /^socket:\[(\d+)\]$/.exec(target);
    if (match !== null) owned.add(match[1]);
  }
  return { inodes: owned, observed: true };
}

const isLoopback = (hex) => hex === '0100007F' || /^0{31}1$/.test(hex) || /^0+$/.test(hex);

/**
 * Every non-loopback TCP peer a process is connected to.
 *
 * A resolver serving a verified local blockstore must have none: its listeners are inbound, and
 * an outbound connection to anywhere is the phone-home Constitution Article 14 forbids.
 *
 * Counting sockets rather than trapping `dns.lookup`: a trap catches only the library that
 * honours it, and catches nothing in a child process or behind a connect to a literal address —
 * which is the shape a leak would actually take.
 */
function outboundPeers(pid) {
  const { inodes: owned, observed } = socketInodes(pid);
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
      if (!isLoopback((remote.split(':')[0] ?? '').toUpperCase())) peers.push(remote);
    }
  }
  return { peers, observed };
}

/**
 * The launched browser's pid, found by its own argv.
 *
 * Not `browser.process()`: that is a driver API whose availability varies by Playwright version
 * and by how the browser was launched, and this harness must not fail on a detail of the tool it
 * uses to observe. The `--proxy-server` this run passed is unique to this run, which makes argv a
 * more reliable identifier here than the driver's own bookkeeping.
 */
function browserProcessPid(port) {
  const marker = `--proxy-server=http://127.0.0.1:${port}`;
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const argv = readFileSync(`/proc/${entry}/cmdline`, 'utf8');
      if (argv.includes(marker)) return entry;
    } catch {
      continue;
    }
  }
  return null;
}

/** Every process in `root`'s tree, including `root` itself. */
function processTree(root) {
  const children = new Map();
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    let status;
    try {
      status = readFileSync(`/proc/${entry}/status`, 'utf8');
    } catch {
      continue;
    }
    const parent = /^PPid:\s*(\d+)$/m.exec(status);
    if (parent === null) continue;
    const list = children.get(parent[1]) ?? [];
    list.push(entry);
    children.set(parent[1], list);
  }
  const tree = [];
  const queue = [String(root)];
  while (queue.length > 0) {
    const pid = queue.shift();
    tree.push(pid);
    queue.push(...(children.get(pid) ?? []));
  }
  return tree;
}

/**
 * Name-resolution traffic from a process tree: any UDP or TCP socket to port 53.
 *
 * Article 14's clause is "no clearnet DNS query", and a browser handed a proxy is supposed to
 * pass the hostname to it rather than resolve the name itself. That is a claim about Chromium's
 * behaviour, and this is the measurement of it.
 *
 * **What it does not prove, stated because a check that only flatters itself gets discounted.**
 * A UDP socket is short-lived, so sampling can miss one that opened and closed between polls;
 * the caller samples throughout the navigation rather than once after it, which narrows the
 * window without closing it. A resolver reached over a Unix socket (systemd-resolved's
 * `/run/systemd/resolve/io.systemd.Resolve`) carries no port and would not appear here at all.
 * The load-bearing evidence for "no DNS fallback" is not this function — it is that a name
 * outside the ratified namespace is REFUSED while a VayuWeb name renders, which no configuration
 * that quietly resolved names could produce.
 */
function resolutionSockets(pids) {
  const seen = [];
  let observed = 0;
  for (const pid of pids) {
    const { inodes: owned, observed: readable } = socketInodes(pid);
    if (!readable) continue;
    observed += 1;
    if (owned.size === 0) continue;
    for (const table of ['udp', 'udp6', 'tcp', 'tcp6']) {
      let text;
      try {
        text = readFileSync(`/proc/${pid}/net/${table}`, 'utf8');
      } catch {
        continue;
      }
      for (const line of text.split('\n').slice(1)) {
        const fields = line.trim().split(/\s+/);
        if (fields.length < 10) continue;
        const [remote, inode] = [fields[2], fields[9]];
        if (!owned.has(inode)) continue;
        const [host, port] = remote.split(':');
        if (parseInt(port ?? '0', 16) !== 53) continue;
        if (isLoopback((host ?? '').toUpperCase())) continue; // A local stub is not clearnet.
        seen.push(`${pid}:${remote}`);
      }
    }
  }
  return { seen, observed };
}

/* -------------------------------------------------------------------------- */
/* Fixture                                                                     */
/* -------------------------------------------------------------------------- */

// **The fixture is deliberately not ASCII.**
//
// It used to be, and that is why this harness reported success for a resolver that corrupted every
// image and every accented character it served: the body was decoded as latin-1 on the way out of
// the handler and re-encoded as UTF-8 on the way to the socket, and on pure ASCII that round trip
// is the identity. A check whose fixture cannot express the failure is not evidence about it.
//
// So the headline carries characters above U+007F, and the site carries a real binary file whose
// bytes the page compares against the ones that were published.
const HEADLINE = 'Atlas Observatory — café ünïcode ✓';

const INDEX = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Atlas Observatory</title>
    <link rel="stylesheet" href="/assets/style.css" />
  </head>
  <body>
    <h1 id="headline">${HEADLINE}</h1>
    <p id="proof">Served over VayuWeb from a verified content root.</p>
  </body>
</html>
`;
const STYLE = `body { background: #0b0f14; color: #e6edf3; font-family: system-ui, sans-serif; }
h1 { color: #7ee787; }
`;

/**
 * A real PNG: an 8-byte signature, an IHDR for a 1x1 image, and an IEND. Every byte of it above
 * 0x7f is one the broken path would have doubled, and a browser refuses to decode it if any of them
 * is wrong — so `naturalWidth` is an assertion about the bytes, made by the same decoder a reader's
 * browser would use, rather than about a length this script computed itself.
 */
const PIXEL = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64',
);

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
  writeFileSync(join(site, 'assets', 'pixel.png'), PIXEL);

  // The root CID comes out of the same importer the resolver uses, so the name is registered
  // against the address the content actually has rather than one asserted alongside it.
  const { importSite } = await import(join(REGISTRY, 'src', 'unixfs.ts'));
  const root = importSite([
    { path: 'index.html', content: Buffer.from(INDEX) },
    { path: 'assets/style.css', content: Buffer.from(STYLE) },
    { path: 'assets/pixel.png', content: PIXEL },
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

  process.stdout.write(`registering ${POINTER_NAME} -> ${POINTER} (solving proof of work)\n`);
  const pointed = await cli([
    'register',
    '--log',
    log,
    '--key',
    key,
    '--name',
    POINTER_NAME,
    '--ipns',
    POINTER,
  ]);
  if (pointed.code !== 0) throw new Error(`pointer registration failed: ${pointed.err}`);

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
      // A locally declared answer for one pointer, which is what a publisher checking the
      // `ipns`-first path before they publish actually has. Not a network resolution, and the
      // banner the resolver prints says so.
      '--pointer',
      POINTER,
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

  // Sampled THROUGHOUT the navigation rather than once after it. A DNS socket lives for
  // milliseconds, so a single reading taken when the page has already loaded would be looking for
  // something that has been gone for a second — and would report "none" with total confidence.
  const browserPid = browserProcessPid(PORT);
  if (browserPid === null) throw new Error('could not find the launched browser process');
  const dnsSeen = new Set();
  // `sampledPids` counts what was actually looked at, not what was found. Zero findings across
  // zero observations is the shape of a check that cannot fail, which is what this one was.
  let sampledPids = 0;
  const sampler = setInterval(() => {
    const { seen, observed } = resolutionSockets(processTree(browserPid));
    sampledPids += observed;
    for (const socket of seen) dnsSeen.add(socket);
  }, 20);

  const page = await context.newPage();
  const response = await page.goto(`http://${NAME}/`, { waitUntil: 'load', timeout: 20_000 });

  check(
    'navigation returned 200',
    response !== null && response.status() === 200,
    String(response?.status()),
  );

  const headline = await page.textContent('#headline');
  check(
    'the page rendered from verified content, non-ASCII intact',
    headline === HEADLINE,
    JSON.stringify(headline),
  );

  // Step 10, through the whole stack: a name whose only content entry is a pointer, resolved by
  // the shipping CLI's wiring rather than by a test double, rendered by stock Chromium. Nothing to
  // fall back to, so a 200 here is the pointer path and cannot be anything else.
  const pointerPage = await context.newPage();
  const pointerResponse = await pointerPage.goto(`http://${POINTER_NAME}/`, {
    waitUntil: 'load',
    timeout: 20_000,
  });
  check(
    'a name carrying only an ipns pointer renders, which needs step 10',
    pointerResponse !== null && pointerResponse.status() === 200,
    String(pointerResponse?.status()),
  );
  check(
    'and it rendered the same verified content the pointer resolves to',
    (await pointerPage.textContent('#headline')) === HEADLINE,
  );
  await pointerPage.close();

  // Proves the SECOND fetch worked, not just the first: a resolver that serves index.html and
  // nothing else renders an unstyled page that still passes a text assertion.
  const colour = await page.evaluate(() => getComputedStyle(document.querySelector('h1')).color);
  check('the stylesheet was fetched and applied', colour === 'rgb(126, 231, 135)', colour);

  // The binary half, checked twice over: the bytes the browser received compared against the bytes
  // that were published, and the browser's own PNG decoder asked whether it can read them. Either
  // one alone would have caught the corruption; the pair distinguishes "wrong bytes" from "right
  // bytes the decoder rejects", which are different bugs with the same symptom.
  const fetched = await page.evaluate(async () => {
    const r = await fetch('/assets/pixel.png');
    return Array.from(new Uint8Array(await r.arrayBuffer()));
  });
  check(
    'a binary asset arrived byte for byte',
    fetched.length === PIXEL.length && PIXEL.every((b, i) => b === fetched[i]),
    `${fetched.length} bytes received, ${PIXEL.length} published`,
  );
  const decoded = await page.evaluate(
    () =>
      new Promise((done) => {
        const image = new Image();
        image.onload = () => done(image.naturalWidth);
        image.onerror = () => done(-1);
        image.src = '/assets/pixel.png';
      }),
  );
  check("the browser's own decoder accepted it", decoded === 1, `naturalWidth ${decoded}`);

  const csp = response?.headers()['content-security-policy'] ?? '';
  check("the CSP reached the browser with default-src 'none'", csp.includes("default-src 'none'"));
  check('no request failed', failed.length === 0, JSON.stringify(failed));
  // Both names this run registered, and nothing else. Written as a set rather than one prefix
  // because a second name was added and the single-prefix version would have failed for the right
  // reason in the wrong way — a check that has to be relaxed whenever the fixture grows tempts the
  // relaxation "any VayuWeb host", which is what it is actually asserting against.
  const OWN_HOSTS = [NAME, POINTER_NAME];
  check(
    'every request stayed inside the names this run registered',
    requested.length > 0 &&
      requested.every((u) => OWN_HOSTS.some((host) => u.startsWith(`http://${host}/`))),
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

  clearInterval(sampler);

  // The resolver must still be RUNNING when this is measured. A process that exited holds no
  // sockets, so "no outbound connection" would be true of a resolver that crashed during the
  // navigation — an absence of evidence published as evidence of absence.
  const outbound = outboundPeers(resolver.pid);
  check(
    'the resolver was still running when its sockets were counted',
    resolver.exitCode === null && outbound.observed,
    `exitCode ${resolver.exitCode}, fd table ${outbound.observed ? 'readable' : 'UNREADABLE'}`,
  );
  check(
    'the resolver opened no outbound connection (Constitution Art. 14)',
    outbound.observed && outbound.peers.length === 0,
    JSON.stringify(outbound.peers),
  );

  // The weaker of the two, and labelled so. See `resolutionSockets` for what sampling cannot see;
  // the refusal check above is the load-bearing evidence that no name fell through to DNS.
  check(
    'the browser tree was actually sampled for DNS sockets',
    sampledPids > 0,
    `${sampledPids} process observation(s) across the navigation`,
  );
  check(
    'no clearnet DNS query was sampled from the browser (Art. 14, sampled)',
    sampledPids > 0 && dnsSeen.size === 0,
    JSON.stringify([...dnsSeen]),
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
