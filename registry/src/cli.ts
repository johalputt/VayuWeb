/**
 * `vayuweb-registry` — the Phase 1 command-line tool.
 *
 * docs/ROADMAP.md Phase 1 is done when "a command-line tool can register a name into a local
 * log, resolve it back, reject every malformed and replayed record in the test-vector set".
 * This is that tool.
 *
 * Two things it deliberately does not do:
 *
 * - **No network.** Nothing here dials, discovers or replicates. That is Phase 2, and a Phase 1
 *   tool that quietly reached the network would make "verified locally" untestable.
 * - **No key management beyond a file.** A secret key lives in a file the user names, and the
 *   tool says so rather than implying a keystore it does not have. Pretending to more key
 *   hygiene than exists is worse than having none, because it stops the user providing their own.
 */

import { readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs';

import { encode, type CborMap, type CborValue } from './cbor.ts';
import { signingInput } from './domain.ts';
import { sign, publicKeyFrom, SECRET_KEY_LENGTH } from './signature.ts';
import { parseRecordBytes } from './record.ts';
import { RATIFIED_TLDS, assertValidName } from './names.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { Store } from './store.ts';
import { TERM_SECONDS } from './verify.ts';
import { stateAt } from './lifecycle.ts';
import { buildVectors, fromHex } from './vectors.ts';
import { verify, predecessorFrom, type RegistryView } from './verify.ts';

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const out = (line = ''): void => {
  process.stdout.write(`${line}\n`);
};
const err = (line: string): void => {
  process.stderr.write(`${line}\n`);
};

class UsageError extends Error {}

/* -------------------------------------------------------------------------- */
/* Argument handling                                                           */
/* -------------------------------------------------------------------------- */

interface Args {
  readonly positional: string[];
  readonly flags: Map<string, string>;
}

function parseArgs(argv: readonly string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    if (eq !== -1) {
      flags.set(token.slice(2, eq), token.slice(eq + 1));
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new UsageError(`flag ${token} needs a value`);
      }
      flags.set(token.slice(2), next);
      i += 1;
    }
  }
  return { positional, flags };
}

const required = (args: Args, flag: string): string => {
  const value = args.flags.get(flag);
  if (value === undefined) throw new UsageError(`--${flag} is required`);
  return value;
};

const number = (args: Args, flag: string, fallback: number): number => {
  const raw = args.flags.get(flag);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value)) throw new UsageError(`--${flag} must be an integer`);
  return value;
};

/** The clock, injectable so a test or a reproduction can pin it. */
const clockOf = (args: Args): number => number(args, 'at', Math.floor(Date.now() / 1000));

function readSecret(path: string): Uint8Array {
  if (!existsSync(path)) throw new UsageError(`no key at ${path} — run: keygen --key ${path}`);
  const hex = readFileSync(path, 'utf8').trim();
  const bytes = fromHex(hex);
  if (bytes.length !== SECRET_KEY_LENGTH) {
    throw new UsageError(`key at ${path} is ${bytes.length} bytes, expected ${SECRET_KEY_LENGTH}`);
  }
  return bytes;
}

const splitName = (value: string): { label: string; tld: string } => {
  const dot = value.lastIndexOf('.');
  if (dot <= 0 || dot === value.length - 1) {
    throw new UsageError(`expected label.tld, got '${value}'`);
  }
  const label = value.slice(0, dot);
  const tld = value.slice(dot + 1);
  assertValidName(label, tld);
  return { label, tld };
};

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

/** `--txt a --txt b` style repetition is not supported; one `--txt` keeps the tool honest. */
function entriesFrom(args: Args): CborValue[] {
  const entries: CborValue[] = [];
  const txt = args.flags.get('txt');
  if (txt !== undefined) entries.push(entry('txt', txt));
  const alias = args.flags.get('alias');
  if (alias !== undefined) entries.push(entry('alias', alias));
  const peer = args.flags.get('peer');
  if (peer !== undefined) entries.push(entry('peer', fromHex(peer)));
  return entries;
}

/* -------------------------------------------------------------------------- */
/* Commands                                                                    */
/* -------------------------------------------------------------------------- */

function cmdKeygen(args: Args): number {
  const path = required(args, 'key');
  if (existsSync(path) && args.flags.get('force') === undefined) {
    // Overwriting a secret key destroys every name it holds, irrecoverably. There is no
    // recovery key and no appeal, so this refuses by default.
    err(`refusing to overwrite ${path} — pass --force if you mean it`);
    err('overwriting a key destroys every name it holds; there is no recovery');
    return 1;
  }
  const seedHex = args.flags.get('seed');
  const secret = seedHex === undefined ? randomSecret() : fromHex(seedHex);
  if (secret.length !== SECRET_KEY_LENGTH) throw new UsageError('seed must be 32 bytes');

  writeFileSync(path, `${toHex(secret)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  out(`wrote secret key to ${path} (mode 0600)`);
  out(`public key: ${toHex(publicKeyFrom(secret))}`);
  out('');
  out('This is a file, not a keystore. Back it up yourself; losing it loses every name.');
  return 0;
}

function randomSecret(): Uint8Array {
  const bytes = new Uint8Array(SECRET_KEY_LENGTH);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function cmdRegister(args: Args): number {
  const store = Store.open(required(args, 'log'), clockOf(args));
  const { label, tld } = splitName(required(args, 'name'));
  const secret = readSecret(required(args, 'key'));
  const now = clockOf(args);

  const windowCount = store.registrationsInWindow(tld, now);
  const needed = requiredBits(label.length, windowCount);
  const bits = number(args, 'bits', needed);
  if (bits < needed) {
    // Refuse before the work rather than after it. Over-payment is valid and harmless;
    // under-payment is refused by the verifier, so solving first would burn the user's CPU to
    // reach a rejection that was predictable from the outset.
    err(
      `--bits ${bits} is below the ${needed} bits this log requires for a ${label.length}-character`,
    );
    err(`label in .${tld}. The proof would be solved and then rejected. Raise it or omit --bits.`);
    return 1;
  }

  const skeleton = (nonce: Uint8Array): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['op', 'REGISTER'],
      ['name', label],
      ['tld', tld],
      ['ownerKey', publicKeyFrom(secret)],
      ['seq', 0],
      ['notBefore', now],
      ['notAfter', now + TERM_SECONDS],
      ['records', entriesFrom(args)],
      [
        'powProof',
        new Map<string | Uint8Array, CborValue>([
          ['alg', POW_ALGORITHM],
          ['nonce', nonce],
          ['bits', bits],
        ]),
      ],
      ['prevHash', new Uint8Array(32)],
    ]);

  err(`solving proof of work at ${bits} bits (about ${2 ** bits} evaluations expected)`);
  const draft = skeleton(new Uint8Array(POW_NONCE_LENGTH));
  const nonce = solvePow(draft, bits, {
    onAttempt: (n) => {
      // Progress, not a countdown: the search is memoryless, so a percentage would be a lie.
      if (n % 64 === 0) err(`  ${n} evaluations`);
    },
  });
  if (nonce === null) {
    err('no nonce found');
    return 1;
  }

  return finish(store, skeleton(nonce), secret, undefined, now);
}

function cmdSuccessor(op: string, args: Args): number {
  const store = Store.open(required(args, 'log'), clockOf(args));
  const { label, tld } = splitName(required(args, 'name'));
  const secret = readSecret(required(args, 'key'));
  const now = clockOf(args);

  const held = store.lookup(label, tld);
  if (held === null) {
    err(`${label}.${tld} has no history in this log`);
    return 1;
  }
  const prev = held.current.record;

  let notAfter = prev.notAfter;
  let powProof: CborValue = null;
  let nonce: Uint8Array | null = null;
  let bits = 0;

  if (op === 'RELEASE') notAfter = now;

  const ownerKey = op === 'TRANSFER' ? fromHex(required(args, 'to')) : prev.ownerKey;

  const build = (proof: CborValue): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['op', op],
      ['name', label],
      ['tld', tld],
      ['ownerKey', ownerKey],
      ['seq', prev.seq + 1],
      ['notBefore', now],
      ['notAfter', notAfter],
      ['records', op === 'UPDATE' ? entriesFrom(args) : []],
      ['powProof', proof],
      ['prevHash', held.current.hash],
    ]);

  if (op === 'RENEW') {
    notAfter = Math.max(prev.notAfter, now) + TERM_SECONDS;
    bits = number(args, 'bits', requiredBits(label.length, store.registrationsInWindow(tld, now)));
    err(`solving proof of work at ${bits} bits`);
    const draft = build(
      new Map<string | Uint8Array, CborValue>([
        ['alg', POW_ALGORITHM],
        ['nonce', new Uint8Array(POW_NONCE_LENGTH)],
        ['bits', bits],
      ]),
    );
    nonce = solvePow(draft, bits);
    if (nonce === null) {
      err('no nonce found');
      return 1;
    }
    powProof = new Map<string | Uint8Array, CborValue>([
      ['alg', POW_ALGORITHM],
      ['nonce', nonce],
      ['bits', bits],
    ]);
  }

  const coSecretPath = args.flags.get('cosign');
  const coSecret = coSecretPath === undefined ? undefined : readSecret(coSecretPath);
  if (op === 'TRANSFER' && coSecret === undefined) {
    err('TRANSFER needs --cosign <incoming key file>: a transfer the incoming owner has not');
    err('signed can send a name to a key nobody holds, which is indistinguishable from a burn');
    return 1;
  }

  return finish(store, build(powProof), secret, coSecret, now);
}

/** Sign, append, and report the verdict in the same words the verifier uses. */
function finish(
  store: Store,
  map: CborMap,
  secret: Uint8Array,
  coSecret: Uint8Array | undefined,
  now: number,
): number {
  const input = signingInput(map);
  map.set('sig', sign(secret, input));
  if (coSecret !== undefined) map.set('coSig', sign(coSecret, input));

  const bytes = encode(map);
  const verdict = store.append(bytes, now);

  if (verdict.outcome === 'accept') {
    const r = verdict.record;
    out(`accepted  ${r.op}  ${r.name}.${r.tld}  seq ${r.seq}  ${bytes.length} bytes`);
    out(`log now holds ${store.length} record(s)`);
    return 0;
  }
  if (verdict.outcome === 'defer') {
    err(`deferred  ${verdict.reason}: ${verdict.detail}`);
    err('deferred, not rejected: the clock may be behind. Nothing was written.');
    return 2;
  }
  err(`rejected  ${verdict.code}: ${verdict.detail}`);
  return 1;
}

function cmdResolve(args: Args): number {
  const now = clockOf(args);
  const store = Store.open(required(args, 'log'), now);
  const { label, tld } = splitName(required(args, 'name'));

  const held = store.lookup(label, tld);
  if (held === null) {
    out(`${label}.${tld} is not registered in this log`);
    return 1;
  }

  const r = held.current.record;
  const state = held.revoked ? 'REVOKED' : stateAt(r, now);
  out(`${label}.${tld}`);
  out(`  state      ${state}`);
  out(`  owner      ${toHex(r.ownerKey)}`);
  out(`  seq        ${r.seq}`);
  out(`  term       ${r.notBefore} .. ${r.notAfter}`);
  out(`  log index  ${held.logIndex}`);

  if (state !== 'LIVE') {
    // A name that does not resolve must not print its records as though it did.
    out('');
    out('  This name does not currently resolve; its entries are shown for inspection only.');
  }
  out('  entries');
  if (r.entries.length === 0) out('    (none)');
  for (const e of r.entries) {
    const value = e.value instanceof Uint8Array ? toHex(e.value) : String(e.value);
    out(`    ${e.type}${e.known ? '' : ' (unknown type — never acted upon)'}  ${value}`);
  }
  return state === 'LIVE' ? 0 : 3;
}

function cmdList(args: Args): number {
  const now = clockOf(args);
  const store = Store.open(required(args, 'log'), now);
  const rows = store.list(now);
  if (rows.length === 0) {
    out('no names in this log');
    return 0;
  }
  for (const row of rows) out(`${row.state.padEnd(11)} ${row.name}.${row.tld}`);
  out('');
  out(`${rows.length} name(s), ${store.length} record(s)`);
  return 0;
}

function cmdDifficulty(args: Args): number {
  const now = clockOf(args);
  const store = Store.open(required(args, 'log'), now);
  const { label, tld } = splitName(required(args, 'name'));
  const count = store.registrationsInWindow(tld, now);
  out(`${label}.${tld}`);
  out(`  registrations in .${tld} over the trailing 30 days: ${count}`);
  out(`  required difficulty: ${store.difficultyFor(label, tld, now)} bits`);
  return 0;
}

function cmdVerify(args: Args): number {
  const now = clockOf(args);
  const store = Store.open(required(args, 'log'), now);
  const bytes = fromHex(readFileSync(required(args, 'record'), 'utf8').trim());
  const verdict = store.verifyAt(bytes, now);
  out(
    verdict.outcome === 'accept'
      ? 'accept'
      : verdict.outcome === 'defer'
        ? `defer ${verdict.reason}: ${verdict.detail}`
        : `reject ${verdict.code}: ${verdict.detail}`,
  );
  return verdict.outcome === 'accept' ? 0 : 1;
}

/**
 * Run the committed conformance vectors. This is the check another implementation runs to see
 * whether it agrees with this one — and the check this one runs to see whether it still agrees
 * with the specification.
 */
function cmdVectors(): number {
  let failed = 0;
  for (const vector of buildVectors()) {
    const predecessor =
      vector.state.predecessor === null
        ? null
        : (() => {
            const bytes = fromHex(vector.state.predecessor);
            return predecessorFrom(parseRecordBytes(bytes), bytes);
          })();
    const view: RegistryView = {
      current: () => predecessor,
      fullyReleased: () => vector.state.fullyReleased,
      revoked: () => vector.state.revoked,
      powVerified: () => vector.state.powVerified,
    };
    const v = verify(fromHex(vector.record), view, vector.now);
    const actual =
      v.outcome === 'accept'
        ? 'accept'
        : v.outcome === 'defer'
          ? `defer:${v.reason}`
          : `reject:${v.code}`;
    const want =
      vector.expect.outcome === 'accept'
        ? 'accept'
        : vector.expect.outcome === 'defer'
          ? `defer:${vector.expect.reason}`
          : `reject:${vector.expect.code}`;
    if (actual !== want) {
      failed += 1;
      err(`FAIL ${vector.name}`);
      err(`     rule:     ${vector.rule}`);
      err(`     expected: ${want}`);
      err(`     actual:   ${actual}`);
    }
  }
  const total = buildVectors().length;
  out(`${total - failed}/${total} vectors pass`);
  if (failed > 0) {
    out('');
    out('A disagreement is a bug here, a bug there, or an ambiguity in the specification.');
    out('The third is the most valuable. Please report it.');
  }
  return failed === 0 ? 0 : 1;
}

const USAGE = `vayuweb-registry — local name registry (Phase 1: no network)

  keygen     --key <file> [--seed <hex>] [--force]
  register   --log <file> --key <file> --name <label.tld> [--txt <s>] [--alias <n.tld>]
             [--peer <hex>] [--bits <n>] [--at <unix>]
  update     --log <file> --key <file> --name <label.tld> [--txt <s>] ...
  renew      --log <file> --key <file> --name <label.tld> [--bits <n>]
  transfer   --log <file> --key <file> --name <label.tld> --to <hex> --cosign <file>
  release    --log <file> --key <file> --name <label.tld>
  revoke     --log <file> --key <file> --name <label.tld>
  resolve    --log <file> --name <label.tld> [--at <unix>]
  list       --log <file> [--at <unix>]
  difficulty --log <file> --name <label.tld>
  verify     --log <file> --record <file containing hex>
  vectors

Exit codes: 0 accepted, 1 rejected or error, 2 deferred (clock skew), 3 not live.

--at pins the clock, so a result can be reproduced. ${RATIFIED_TLDS.size} extensions are
ratified, enumerated in docs/spec/NAMESPACE-CATALOGUE.md — the Namespace Annex. They are not
listed here: the list would bury every other line of this help, and a help text carrying the
namespace is one more copy that can drift from it.

This tool does not touch the network. Keys are files; back them up yourself.`;

export function main(argv: readonly string[]): number {
  const [command, ...rest] = argv;
  if (command === undefined || command === '--help' || command === 'help') {
    out(USAGE);
    return command === undefined ? 1 : 0;
  }

  try {
    const args = parseArgs(rest);
    switch (command) {
      case 'keygen':
        return cmdKeygen(args);
      case 'register':
        return cmdRegister(args);
      case 'update':
        return cmdSuccessor('UPDATE', args);
      case 'renew':
        return cmdSuccessor('RENEW', args);
      case 'transfer':
        return cmdSuccessor('TRANSFER', args);
      case 'release':
        return cmdSuccessor('RELEASE', args);
      case 'revoke':
        return cmdSuccessor('REVOKE', args);
      case 'resolve':
        return cmdResolve(args);
      case 'list':
        return cmdList(args);
      case 'difficulty':
        return cmdDifficulty(args);
      case 'verify':
        return cmdVerify(args);
      case 'vectors':
        return cmdVectors();
      default:
        err(`unknown command: ${command}`);
        err('');
        err(USAGE);
        return 1;
    }
  } catch (error) {
    if (error instanceof UsageError) {
      err(`usage: ${error.message}`);
      return 1;
    }
    err(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
