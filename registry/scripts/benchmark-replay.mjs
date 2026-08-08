#!/usr/bin/env node
/**
 * What it costs to open a log, and whether that meets the project's own stop-and-rethink condition.
 *
 * `docs/ROADMAP.md`, "What would make us stop and rethink", lists in advance:
 *
 * > **Independent verification is too expensive.** If full-history verification cannot run on
 * > ordinary consumer hardware, most people will use somebody else's verified view, and a de facto
 * > root returns through the back door.
 *
 * `Store.open` replays every entry and re-verifies it — `registry/src/store.ts`, which calls
 * `verifyAt` per entry, and `verify` runs `verifyPow` for every REGISTER and RENEW. Every command
 * in the CLI opens the store before doing anything. So the question that condition asks is
 * answerable with a stopwatch, and this script is the stopwatch.
 *
 * ## What it measures, and what it only estimates
 *
 * **Measured:** one Argon2id evaluation at the protocol's parameters, sampled several times, and a
 * real `Store.open` over a real log this script builds. Both are timed on this machine, now.
 *
 * **Estimated:** the cost at log sizes too large to build here. Building a thousand-record log
 * costs a thousand proof-of-work solves — the same work, from the other end — so the large figures
 * are the measured per-record cost multiplied out, and they are labelled as such rather than
 * printed as though they had been observed.
 *
 * ## What it does not prove
 *
 * This is a pure-JavaScript Argon2id on one machine. A native implementation is several times
 * faster and a phone is slower; neither is measured here. The figure is therefore an argument about
 * an ORDER OF MAGNITUDE and not a benchmark of the protocol, and a reader who wants the real number
 * for their hardware should run this on it. It also measures nothing about memory: Argon2id at
 * m=65536 wants 64 MiB per evaluation, which is its own constraint on the smallest device.
 *
 *   node registry/scripts/benchmark-replay.mjs [--records N]
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REGISTRY = dirname(HERE);

const arg = (name, fallback) => {
  const at = process.argv.indexOf(`--${name}`);
  return at === -1 ? fallback : Number(process.argv[at + 1]);
};

/** Records to actually build and replay. Small by necessity: each one costs a real solve. */
const RECORDS = arg('records', 3);

const ms = (n) => `${n.toFixed(0)} ms`;
const human = (seconds) =>
  seconds < 90
    ? `${seconds.toFixed(1)} s`
    : seconds < 5400
      ? `${(seconds / 60).toFixed(1)} min`
      : `${(seconds / 3600).toFixed(1)} h`;

const { powTag, POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } = await import(
  join(REGISTRY, 'src', 'pow.ts')
);
const { Store } = await import(join(REGISTRY, 'src', 'store.ts'));
const { encode } = await import(join(REGISTRY, 'src', 'cbor.ts'));
const { signingInput } = await import(join(REGISTRY, 'src', 'domain.ts'));
const { sign, publicKeyFrom } = await import(join(REGISTRY, 'src', 'signature.ts'));
const { TERM_SECONDS } = await import(join(REGISTRY, 'src', 'verify.ts'));

process.stdout.write(`algorithm ${POW_ALGORITHM}, pure JavaScript, this machine\n\n`);

/* -------------------------------------------------------------------------- */
/* Measured: one evaluation                                                    */
/* -------------------------------------------------------------------------- */

const nonce = new Uint8Array(POW_NONCE_LENGTH).fill(3);
const salt = new Uint8Array(32).fill(7);
powTag(nonce, salt); // warm, so the first sample is not measuring a cold JIT

const samples = [];
for (let i = 0; i < 7; i += 1) {
  nonce[0] = i;
  const started = process.hrtime.bigint();
  powTag(nonce, salt);
  samples.push(Number(process.hrtime.bigint() - started) / 1e6);
}
samples.sort((a, b) => a - b);
const median = samples[Math.floor(samples.length / 2)];
process.stdout.write(
  `one Argon2id evaluation   median ${ms(median)}   ` +
    `range ${ms(samples[0])}–${ms(samples[samples.length - 1])}   (${samples.length} samples)\n`,
);

/* -------------------------------------------------------------------------- */
/* Measured: a real log, built and reopened                                    */
/* -------------------------------------------------------------------------- */

const LABEL = 'atlasobservatory';
const SECRET = new Uint8Array(32).fill(0x42);
const OWNER = publicKeyFrom(SECRET);
const NOW = 1_782_518_400;

/** One solved REGISTER for a distinct name, which is what a log is mostly made of. */
function registration(label, at) {
  const bits = requiredBits(label.length, 0);
  const skeleton = (n) =>
    new Map([
      ['version', 1],
      ['suite', 1],
      ['op', 'REGISTER'],
      ['name', label],
      ['tld', 'vayu'],
      ['ownerKey', OWNER],
      ['seq', 0],
      ['notBefore', at],
      ['notAfter', at + TERM_SECONDS],
      ['records', []],
      [
        'powProof',
        new Map([
          ['alg', POW_ALGORITHM],
          ['nonce', n],
          ['bits', bits],
        ]),
      ],
      ['prevHash', new Uint8Array(32)],
    ]);
  const found = solvePow(skeleton(new Uint8Array(POW_NONCE_LENGTH)), bits);
  if (found === null) throw new Error('no nonce found');
  const map = skeleton(found);
  map.set('sig', sign(SECRET, signingInput(map)));
  return encode(map);
}

const dir = mkdtempSync(join(tmpdir(), 'vayuweb-benchmark-'));
try {
  const path = join(dir, 'log');
  process.stdout.write(`\nbuilding a ${RECORDS}-record log (each one a real solve)…\n`);
  const store = Store.open(path, NOW);
  for (let i = 0; i < RECORDS; i += 1) {
    // Distinct names, because a log of one name repeated is a log of one record plus refusals —
    // and the replay cost this measures is per ACCEPTED entry.
    const verdict = store.append(registration(`${LABEL}${String(i).padStart(2, '0')}`, NOW), NOW);
    if (verdict.outcome !== 'accept')
      throw new Error(`append ${i}: ${verdict.code ?? verdict.reason}`);
  }

  const openStarted = process.hrtime.bigint();
  const reopened = Store.open(path, NOW);
  const openMs = Number(process.hrtime.bigint() - openStarted) / 1e6;
  if (reopened.length !== RECORDS)
    throw new Error(`reopened ${reopened.length}, expected ${RECORDS}`);

  const perRecord = openMs / RECORDS;
  process.stdout.write(
    `\nStore.open over ${RECORDS} records   ${ms(openMs)}   ` + `= ${ms(perRecord)} per record\n`,
  );
  // The per-record replay cost should be within an evaluation of the solve cost, because the
  // evaluation IS the replay cost. If it ever is not, something other than the proof dominates and
  // this script's extrapolation would be measuring the wrong thing.
  const ratio = perRecord / median;
  process.stdout.write(
    `  which is ${ratio.toFixed(2)}× one evaluation — the proof is ${
      ratio > 0.8
        ? 'the dominant cost, as expected'
        : 'NOT dominant, so the estimate below is unsound'
    }\n`,
  );

  process.stdout.write('\nestimated, by multiplying the measured per-record cost:\n');
  for (const n of [100, 1_000, 10_000, 100_000]) {
    process.stdout.write(
      `  ${String(n).padStart(7)} records   ${human((perRecord * n) / 1000).padStart(9)} per open\n`,
    );
  }

  process.stdout.write(
    '\nEvery CLI command opens the store before doing anything, so this is the cost of running\n' +
      'any command against a log of that size, not a one-off startup cost.\n',
  );
  process.stdout.write(
    '\nROADMAP.md lists "independent verification is too expensive" as a condition that would make\n' +
      'the project stop and rethink. On this machine, in pure JavaScript, a thousand-record log\n' +
      'meets it. A native Argon2id is several times faster and a phone is slower; neither is\n' +
      'measured here, and this figure is an order of magnitude rather than a benchmark.\n',
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
