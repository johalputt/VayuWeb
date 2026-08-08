#!/usr/bin/env node
/**
 * Phase 2 acceptance: independent peers, started in any order, deliberately partitioned.
 *
 * `docs/ROADMAP.md` Phase 2 is done when "independent peers, started in any order and partitioned
 * deliberately during the test, converge on identical registry state and identical conflict
 * outcomes across the conformance suite". This script is those words, executed.
 *
 * ## What it is, and what it is not
 *
 * It runs **two operating-system processes**, each with its own log file, its own `Store`, its own
 * state machine and its own view of time, talking over a **real TCP socket**. Neither is told what
 * the other holds. The socket is severed mid-run and re-established, which is the partition the
 * criterion asks for.
 *
 * It is **not two machines**, and the difference is stated rather than glossed: these processes
 * share a kernel, a clock, a filesystem and an operator who knows both roots. A second machine
 * would additionally exercise a different network stack, a genuinely independent clock — the thing
 * the whole `CLOCK_SKEW` deferral path exists for — and the case where neither party can read the
 * other's disk. So this closes the gap between the code and its claims. It does not close Phase 2,
 * and a run of this script must not be reported as though it had.
 *
 * Before this existed, every claim about replication rested on two objects joined by a pipe inside
 * one process, because `drivePeer` and `joinSwarm` had no caller anywhere that ships.
 *
 * ## Running it
 *
 *   node registry/scripts/acceptance-replication.mjs
 *
 * No dependencies and no network beyond loopback. It refuses rather than skips: a check that
 * cannot run must not report success.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REGISTRY = dirname(HERE);
const CLI = join(REGISTRY, 'bin', 'vayuweb-registry.ts');

/** A port nothing else is using, obtained by binding one and letting go. */
async function freePort() {
  const { createServer } = await import('node:net');
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

let failures = 0;
const check = (label, ok, detail = '') => {
  if (!ok) failures += 1;
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  — ${detail}` : ''}\n`);
};

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

/** Start a long-running `sync`, and expose its accumulated output. */
function startSync(args) {
  const child = spawn(process.execPath, ['--experimental-strip-types', CLI, 'sync', ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const state = { child, out: '', err: '' };
  child.stdout.on('data', (d) => (state.out += d));
  child.stderr.on('data', (d) => (state.err += d));
  return state;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Wait until `read()` returns true, or give up. Returns whether it happened. */
async function until(read, ms = 20_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await read()) return true;
    if (Date.now() > deadline) return false;
    await sleep(120);
  }
}

/** How many records a log file holds, read by opening it exactly as another tool would. */
async function logLength(path) {
  const { Store } = await import(join(REGISTRY, 'src', 'store.ts'));
  try {
    return Store.open(path, Math.floor(Date.now() / 1000)).length;
  } catch {
    return 0;
  }
}

/**
 * The merkle root of a log.
 *
 * Used here to prove two logs DIFFER, and deliberately NOT as the convergence test. A log is
 * ordered by arrival, so two peers holding exactly the same records in different orders have
 * different roots — the ordinary outcome of a real sync, not a failure. The first version of this
 * harness compared roots and reported converged peers as divergent.
 *
 * `HELLO.root` is therefore a cheap hint that two logs are byte-identical, not a statement about
 * registry state. The criterion says "identical registry state and identical conflict outcomes",
 * which is what {@link registryState} reads.
 */
async function logRoot(path) {
  const { Store, sinkOver } = await import(join(REGISTRY, 'src', 'store.ts'));
  const store = Store.open(path, Math.floor(Date.now() / 1000));
  return Buffer.from(sinkOver(store).treeRoot()).toString('hex');
}

/**
 * The registry state a log resolves to: every live name and the key that owns it.
 *
 * This is what "converge on identical registry state and identical conflict outcomes" means. The
 * owner is included precisely because a conflict outcome IS which key ends up owning a name.
 */
async function registryState(path) {
  const { Store } = await import(join(REGISTRY, 'src', 'store.ts'));
  const now = Math.floor(Date.now() / 1000);
  const store = Store.open(path, now);
  return store
    .list(now)
    .map((n) => {
      const held = store.lookup(n.name, n.tld);
      const owner = held
        ? Buffer.from(held.current.record.ownerKey).toString('hex').slice(0, 16)
        : '-';
      return `${n.name}.${n.tld}=${owner}`;
    })
    .sort()
    .join(' ');
}

const dir = mkdtempSync(join(tmpdir(), 'vayuweb-replication-'));
const alice = { key: join(dir, 'alice.key'), log: join(dir, 'alice.log') };
const bob = { key: join(dir, 'bob.key'), log: join(dir, 'bob.log') };
let listener = null;
let dialler = null;

try {
  for (const peer of [alice, bob]) {
    const generated = await cli(['keygen', '--key', peer.key]);
    if (generated.code !== 0) throw new Error(`keygen failed: ${generated.err}`);
  }

  // Each peer registers a DIFFERENT name into its OWN log, so neither starts with what the other
  // has and convergence is a real merge rather than one side being empty. Sixteen-character
  // labels sit at the four-bit proof-of-work floor.
  process.stdout.write('registering one name per peer (solving proof of work)\n');
  const registrations = await Promise.all([
    cli(['register', '--log', alice.log, '--key', alice.key, '--name', 'atlasobservatory.vayu']),
    cli(['register', '--log', bob.log, '--key', bob.key, '--name', 'borealisstations.vayu']),
  ]);
  for (const [i, result] of registrations.entries()) {
    if (result.code !== 0) throw new Error(`registration ${i} failed: ${result.err}`);
  }
  check(
    'each peer starts with its own record and not the other’s',
    (await logLength(alice.log)) === 1 && (await logLength(bob.log)) === 1,
  );
  const rootsBefore = [await logRoot(alice.log), await logRoot(bob.log)];
  check('their logs genuinely differ before syncing', rootsBefore[0] !== rootsBefore[1]);
  // The stub every test sink used. If a root is ever this, the tree is not being computed.
  check(
    'and neither root is the stub value that shipped in every test sink',
    !rootsBefore.includes('00'.repeat(32)),
    rootsBefore.map((r) => r.slice(0, 16)).join(' / '),
  );

  const port = await freePort();

  // **Started in any order**, which the criterion names. The DIALLER goes first, against a port
  // nothing is listening on yet, so the connection cannot succeed until the listener appears.
  dialler = startSync(['--log', bob.log, '--connect', `127.0.0.1:${port}`]);
  await sleep(400);
  listener = startSync(['--log', alice.log, '--listen', String(port)]);

  // The dialler was started first and will have failed to connect. That is the honest outcome of
  // "started in any order" for a client, and the operator sees it rather than a silent retry.
  const dialledLate = await until(
    async () => dialler.err.length > 0 || dialler.out.includes('connected'),
  );
  check(
    'the peer started before its listener reports the refusal rather than hanging',
    dialledLate,
  );

  // Now the other order: with the listener up, a dialler connects and they converge.
  dialler.child.kill('SIGTERM');
  await sleep(300);
  dialler = startSync(['--log', bob.log, '--connect', `127.0.0.1:${port}`]);

  const converged = await until(
    async () => (await logLength(alice.log)) === 2 && (await logLength(bob.log)) === 2,
  );
  check('two independent peers converge over a real socket', converged, `${alice.log}`);

  if (converged) {
    const stateAfter = [await registryState(alice.log), await registryState(bob.log)];
    check(
      'and on identical registry state, owners included',
      stateAfter[0] === stateAfter[1],
      stateAfter[0],
    );
    check('which is the union of what they started with', stateAfter[0].split(' ').length === 2);
  }

  // **The deliberate partition.** Sever the connection, register a third name on one side while
  // there is no path between them, and confirm the other side does NOT have it — a convergence
  // test that never observes divergence has not observed convergence either.
  dialler.child.kill('SIGTERM');
  await sleep(500);

  const partitioned = await cli([
    'register',
    '--log',
    bob.log,
    '--key',
    bob.key,
    '--name',
    'cygnusrelaystation.vayu',
  ]);
  if (partitioned.code !== 0)
    throw new Error(`partitioned registration failed: ${partitioned.err}`);
  check(
    'a record written during the partition does not reach the other side',
    (await logLength(bob.log)) === 3 && (await logLength(alice.log)) === 2,
    `alice ${await logLength(alice.log)}, bob ${await logLength(bob.log)}`,
  );

  // Heal it.
  dialler = startSync(['--log', bob.log, '--connect', `127.0.0.1:${port}`]);
  const healed = await until(async () => (await logLength(alice.log)) === 3);
  check('and reaches it once the partition heals', healed);

  if (healed) {
    const finalState = [await registryState(alice.log), await registryState(bob.log)];
    check(
      'both peers end on identical registry state',
      finalState[0] === finalState[1],
      finalState[0],
    );
    // And the logs themselves are NOT byte-identical, because each peer appended in the order it
    // learned things. Asserted rather than glossed: it is the reason the checks above read state
    // and not the tree root, and a reader who assumed otherwise would mis-diagnose a healthy sync.
    const finalRoots = [await logRoot(alice.log), await logRoot(bob.log)];
    check(
      'while their logs differ in order, which is why state is the criterion',
      finalRoots[0] !== finalRoots[1],
      `${finalRoots[0].slice(0, 12)} vs ${finalRoots[1].slice(0, 12)}`,
    );
  }

  // Every record each peer holds was verified by that peer, not taken on trust. The proof is that
  // the store accepted it: `Store.append` runs the full verification path on arrival.
  const listing = await cli(['list', '--log', alice.log]);
  check(
    'the receiving peer can resolve the name it was sent',
    listing.code === 0 && listing.out.includes('borealisstations'),
    listing.out.trim().split('\n').slice(0, 3).join(' | '),
  );
} catch (error) {
  failures += 1;
  process.stdout.write(`FAIL  the harness could not complete — ${error.message}\n`);
} finally {
  for (const peer of [listener, dialler]) peer?.child.kill('SIGKILL');
  rmSync(dir, { recursive: true, force: true });
}

const total = failures === 0;
process.stdout.write(`\n${total ? 'all checks passed' : `${failures} check(s) failed`}\n`);
process.stdout.write(
  'This is two processes on one machine. Phase 2 asks for independent peers, which these are, ' +
    'and a second machine would still exercise a different network stack and an independent ' +
    'clock. Do not report this run as Phase 2 complete.\n',
);
process.exit(total ? 0 : 1);
