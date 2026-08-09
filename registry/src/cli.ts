/**
 * `vayuweb-registry` — the Phase 1 command-line tool.
 *
 * docs/ROADMAP.md Phase 1 is done when "a command-line tool can register a name into a local
 * log, resolve it back, reject every malformed and replayed record in the test-vector set, and a
 * second tool written from the specification agrees on every vector". This is the first of those
 * two tools; the second must come from someone working only from the specification, so this tool
 * cannot on its own satisfy the phase.
 *
 * Two things it deliberately does not do:
 *
 * - **No network.** Nothing here dials, discovers or replicates. That is Phase 2, and a Phase 1
 *   tool that quietly reached the network would make "verified locally" untestable.
 * - **No key management beyond a file.** A secret key lives in a file the user names, and the
 *   tool says so rather than implying a keystore it does not have. Pretending to more key
 *   hygiene than exists is worse than having none, because it stops the user providing their own.
 */

import { readFileSync, writeFileSync, chmodSync, existsSync, readdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { homedir } from 'node:os';

import { encode, type CborMap, type CborValue } from './cbor.ts';
import { signingInput } from './domain.ts';
import { sign, publicKeyFrom, SECRET_KEY_LENGTH } from './signature.ts';
import { parseRecordBytes, type RecordEntry, type RegistryRecord } from './record.ts';
import { RATIFIED_TLDS, assertValidName } from './names.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { Store, sinkOver } from './store.ts';
import { TERM_SECONDS, SETTLEMENT_SECONDS } from './verify.ts';
import { stateAt } from './lifecycle.ts';
import { buildVectors, fromHex } from './vectors.ts';
import { verify, predecessorFrom, type RegistryView } from './verify.ts';
import { MANIFEST_PATH, RESOLVE_ERRORS, resolveName, type ResolverPorts } from './resolve.ts';
import { ResolutionCache } from './cache.ts';
import { serveControl, serveProxy } from './serve.ts';
import { drivePeer, SWARM_LIMITS, type PeerOutcome } from './swarm.ts';
import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { contentCacheKey, sourceValueOf, type ContentPort, type IpnsPort } from './proxy.ts';
import { importSite, type SiteFile } from './unixfs.ts';
import { cidBytes, decodeCid } from './content.ts';
import { memorySource } from './blockstore.ts';
import { fetchPath, FetchError } from './fetch.ts';
import { proveInclusion, treeOf, type Proof, type Root } from './merkle.ts';
import { greatestCorroboratedLength, verifyNameInclusion } from './checkpoint.ts';
import { TOKEN_BYTES } from './control.ts';
import { EquivocationLedger, ledgerPathFor, type LedgerEntry } from './equivocation.ts';
import { CheckpointLedger } from './checkpoint.ts';
import {
  OBSERVATION_STALE_SECONDS,
  PinSet,
  type PinOutcome,
  UNPUBLISH_EFFECTS,
  onlyThisNodeHoldsIt,
  report,
  summarise,
} from './pins.ts';

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
/**
 * A `--cid` flag as the record stores it: binary, not the text the user typed.
 *
 * REGISTRY.md types a `cid` entry `bstr`, and `parseRecordBytes` enforces it — so passing the
 * `bafy…` string through unchanged produced a record the tool's own verifier rejected, after a
 * proof-of-work solve, with `cid value must be 1-64 bytes` on a 59-character string. Decoding
 * here also means a mistyped CID is refused before the work is spent rather than after it.
 */
function cidValue(text: string): Uint8Array {
  try {
    return cidBytes(decodeCid(text));
  } catch (error) {
    throw new UsageError(
      `--cid ${text}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Record entries from the flags.
 *
 * **`cid` and `ipns` were missing**, which meant this tool could register a name and could never
 * point one at content — every name it created resolved to nothing. They are the two entry types
 * `RESOLUTION.md`'s `SOURCE_ORDER` puts *first*, so their absence was not a gap at the edge of
 * the surface but a hole through the middle of it. Found by publishing a site, registering a name
 * for it, and getting a 502.
 */
function entriesFrom(args: Args): CborValue[] {
  const entries: CborValue[] = [];
  const txt = args.flags.get('txt');
  if (txt !== undefined) entries.push(entry('txt', txt));
  const cid = args.flags.get('cid');
  if (cid !== undefined) entries.push(entry('cid', cidValue(cid)));
  const ipns = args.flags.get('ipns');
  if (ipns !== undefined) entries.push(entry('ipns', ipns));
  const alias = args.flags.get('alias');
  if (alias !== undefined) entries.push(entry('alias', alias));
  const peer = args.flags.get('peer');
  if (peer !== undefined) entries.push(entry('peer', fromHex(peer)));
  return entries;
}

/** The flags that name a record entry. Shared, because three commands read exactly this set. */
const ENTRY_FLAGS = ['txt', 'cid', 'ipns', 'alias', 'peer'] as const;

/**
 * The entries a successor record carries.
 *
 * **`records` used to be hardcoded to `[]` for every operation but `UPDATE`, and that took names
 * down.** REGISTRY.md says `records` "is replaced wholesale; there is no partial update", so an
 * empty array is not "leave them alone" — it is "delete them". Renewing a name therefore emptied
 * it: the tool printed `accepted RENEW … seq 1`, the record was valid, the log was correct, and
 * the site stopped resolving until somebody noticed and ran `update`. Transferring a name did the
 * same to its new owner.
 *
 * So each operation now says what it means by silence:
 *
 * - `RENEW` and `TRANSFER` change the term and the owner. Entries are carried forward unchanged,
 *   which is what a renewal means to the person doing it, and either may still change them —
 *   REGISTRY.md permits it explicitly for `RENEW`, and constrains neither.
 * - `UPDATE` exists to replace the entries, so it refuses to guess: name them, or pass `--clear`
 *   to mean the empty set out loud.
 * - `RELINQUISH` and `REVOKE` require an empty `records` by specification, so there is nothing to
 *   decide.
 *
 * Entries are rebuilt rather than re-encoded, `ttl` included, so an entry of a type this build
 * does not recognise survives a renewal — `parseEntry` keeps those deliberately, and dropping
 * them here would undo that one operation later.
 */
function entriesForSuccessor(op: string, args: Args, prev: RegistryRecord): CborValue[] {
  if (op === 'RELINQUISH' || op === 'REVOKE') return [];
  const named = ENTRY_FLAGS.some((flag) => args.flags.get(flag) !== undefined);
  if (named) return entriesFrom(args);
  if (args.flags.get('clear') !== undefined) return [];
  if (op === 'UPDATE') {
    throw new UsageError(
      'update replaces every entry wholesale, so it will not guess: name the entries you want ' +
        '(--cid, --ipns, --txt, --alias, --peer) or pass --clear to remove them all',
    );
  }
  return prev.entries.map(
    (e: RecordEntry) =>
      new Map<string | Uint8Array, CborValue>([
        ['type', e.type],
        ['value', e.value],
        ['ttl', e.ttl],
      ]),
  );
}

/**
 * The flags each command understands, per command.
 *
 * Enumerated so an unrecognised one can be REFUSED rather than dropped. `--cid` was accepted and
 * silently ignored for as long as `entriesFrom` did not read it, and the tool answered
 * "accepted REGISTER … 329 bytes" for a record with no entries at all. A tool that discards
 * something you typed and then reports success is a tool that lies about what it did, and the
 * cost of finding out is a name on a real log that resolves to nothing.
 *
 * **Per command, and the first version was not.** One global union answers "does any command read
 * this flag?" when the question is "does THIS command read it?", so a flag belonging to another
 * verb was accepted and dropped by exactly the mechanism the enumeration was added to close.
 * `register --site ./public` — a natural mistake now that `serve --site` exists — spent a real
 * proof-of-work solve and wrote a record with no entries in it, and the fix as first written could
 * not tell that from a correct invocation.
 */
const FLAGS_FOR: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['keygen', new Set(['key', 'seed', 'force'])],
  ['register', new Set(['log', 'key', 'name', 'bits', 'at', ...ENTRY_FLAGS])],
  ['update', new Set(['log', 'key', 'name', 'at', 'clear', ...ENTRY_FLAGS])],
  ['renew', new Set(['log', 'key', 'name', 'bits', 'at', 'clear', ...ENTRY_FLAGS])],
  ['transfer', new Set(['log', 'key', 'name', 'to', 'cosign', 'at', 'clear', ...ENTRY_FLAGS])],
  ['release', new Set(['log', 'key', 'name', 'at'])],
  ['prove', new Set(['log', 'name', 'at'])],
  ['light-verify', new Set(['proof', 'claims', 'name', 'quorum', 'at'])],
  ['revoke', new Set(['log', 'key', 'name', 'at'])],
  ['resolve', new Set(['log', 'name', 'at'])],
  ['list', new Set(['log', 'at'])],
  ['equivocations', new Set(['log'])],
  ['difficulty', new Set(['log', 'name', 'at'])],
  ['verify', new Set(['log', 'record', 'at'])],
  ['vectors', new Set<string>()],
  ['serve', new Set(['log', 'port', 'socket', 'site', 'pointer'])],
  ['sync', new Set(['log', 'listen', 'connect', 'address'])],
]);

/** Every flag some command understands, for the "did you mean" hint only. */
const ALL_FLAGS: ReadonlySet<string> = new Set([...FLAGS_FOR.values()].flatMap((s) => [...s]));

/**
 * Refuse a flag this command does not read, naming the nearest thing it might have meant.
 *
 * The hint is drawn from every flag the tool knows, not only this command's, because a flag typed
 * at the wrong verb is a likelier mistake than a flag misspelled — and being told "`--site` is not
 * a flag of `register`" is more use than being told nothing resembles it.
 */
function assertKnownFlags(command: string, args: Args): void {
  const known = FLAGS_FOR.get(command);
  if (known === undefined) return; // An unknown command is refused by the dispatch below.
  for (const flag of args.flags.keys()) {
    if (known.has(flag)) continue;
    if (ALL_FLAGS.has(flag)) {
      const reads = [...FLAGS_FOR]
        .filter(([, set]) => set.has(flag))
        .map(([verb]) => verb)
        .sort();
      throw new UsageError(
        `--${flag} is not a flag of ${command}; it belongs to ${reads.join(', ')}`,
      );
    }
    const near = [...known].filter((k) => k.startsWith(flag.slice(0, 2))).sort();
    const hint = near.length > 0 ? `; did you mean ${near.map((k) => `--${k}`).join(', ')}?` : '';
    throw new UsageError(`unknown flag --${flag}${hint}`);
  }
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
  const { store, ledger } = openWithLedger(required(args, 'log'), clockOf(args));
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

  // Built before the solve, not inside the skeleton the solver calls. A mistyped `--cid` is a
  // refusal that is decidable from the flag alone, and deferring it until the first skeleton is
  // constructed means the tool has already announced "solving proof of work" before it says no.
  const records = entriesFrom(args);

  const skeleton = (nonce: Uint8Array): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['suite', 1],
      ['op', 'REGISTER'],
      ['name', label],
      ['tld', tld],
      ['ownerKey', publicKeyFrom(secret)],
      ['seq', 0],
      ['notBefore', now],
      ['notAfter', now + TERM_SECONDS],
      ['records', records],
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

  return finish(store, skeleton(nonce), secret, undefined, now, ledger);
}

function cmdSuccessor(op: string, args: Args): number {
  const { store, ledger } = openWithLedger(required(args, 'log'), clockOf(args));
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

  if (op === 'RELINQUISH') notAfter = now;

  const ownerKey = op === 'TRANSFER' ? fromHex(required(args, 'to')) : prev.ownerKey;

  // Computed once rather than inside `build`, which RENEW calls twice: the entries are an input to
  // the record and also the thing that decides whether this command is an unpublishing, and a
  // value read twice is a value that can be two things.
  const entries = entriesForSuccessor(op, args, prev);

  const build = (proof: CborValue): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['suite', 1],
      ['op', op],
      ['name', label],
      ['tld', tld],
      ['ownerKey', ownerKey],
      ['seq', prev.seq + 1],
      ['notBefore', now],
      ['notAfter', notAfter],
      ['records', entries],
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

  const code = finish(store, build(powProof), secret, coSecret, now, ledger);
  if (code === 0 && unpublishes(op, entries)) statePublicationCeasedNotErased(op);
  return code;
}

/**
 * Whether this command is one of the acts Constitution Article 19 calls unpublishing.
 *
 * `RELINQUISH` gives the name up and `REVOKE` withdraws the key's authority, both by definition.
 * `UPDATE` is included **when it leaves no entries**, because that is Article 19.2's third
 * guaranteed act — "break the name-to-content binding" — and a rule that fired on the verb rather
 * than on the outcome would let the one spelling an operator reaches for by habit go unannounced.
 *
 * `TOMBSTONE`, 19.2's fourth act, is not here because it does not exist: REGISTRY.md's operation
 * table records it as absent, and `update --clear` breaks the binding without carrying 19.4's cache
 * bound or 19.3's signing rule. The statement below still names it, since 19.2 says a registrant
 * can always publish one — trimming the line to match what is implemented would be editing the
 * Article to fit the code.
 */
function unpublishes(op: string, entries: readonly CborValue[]): boolean {
  return op === 'RELINQUISH' || op === 'REVOKE' || (op === 'UPDATE' && entries.length === 0);
}

/**
 * Say, at the moment of unpublishing, what it did and what it cannot do.
 *
 * **Article 19.8 is a MUST and it is specific about where**: an implementation "MUST state the
 * distinction in clause 19.7 at the point where unpublishing is offered, in the interface itself
 * rather than only in a manual". PUBLISHING.md section 4 says the same thing in the same words —
 * "at the moment of unpublishing rather than in documentation nobody reads". Both sentences were
 * written; neither was executed. `release`, `revoke` and `update --clear` printed an acceptance
 * line and stopped, and an interface that says nothing at that moment is an interface implying the
 * erasure 19.7 forbids implying.
 *
 * `UNPUBLISH_EFFECTS` is where the two lists live and it existed for exactly this. Its own comment
 * says they are data rather than prose "so that a user interface has to render both or
 * deliberately drop one", and until now nothing that ships imported it at all.
 *
 * **Both halves, always.** Printing only the limits reads as a warning about a failure; printing
 * only the guarantees is the overstatement the Article is about. The rendering iterates the arrays
 * rather than restating them, so a change to either list reaches this output without anyone
 * remembering to come back here.
 */
function statePublicationCeasedNotErased(op: string): void {
  out('');
  out(`${op} accepted. Article 19.7: VayuWeb ends authorised publication, and does not erase.`);
  out('  What you can always do — Article 19.2:');
  for (const effect of UNPUBLISH_EFFECTS.guaranteed) out(`    - ${effect}`);
  out('  What no implementation can do for you — Article 19.6:');
  for (const limit of UNPUBLISH_EFFECTS.notGuaranteed) out(`    - ${limit}`);
}

/** Sign, append, and report the verdict in the same words the verifier uses. */
/**
 * Open a log with its equivocation ledger attached, for the commands that can append.
 *
 * The ledger lives beside the log rather than inside it, because the log cannot hold what this
 * records: equivocation is found when a record arrives that conflicts with one already held, and
 * the arriving half is refused. Attaching it here rather than inside `Store.open` keeps the
 * decision to write a file beside somebody's log with the tool that owns the filesystem, which is
 * this one — a library that creates sidecar files its caller did not ask for is a library that
 * surprises people.
 */
function openWithLedger(path: string, now: number): { store: Store; ledger: EquivocationLedger } {
  const store = Store.open(path, now);
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  store.watchEquivocation(ledger);
  return { store, ledger };
}

/** One report, in one line an operator can act on without a hex editor. */
function describeReport(entry: LedgerEntry): string {
  const [owner, tld, name, seq] = entry.key.split(' ');
  return `${name}.${tld}  seq ${seq}  owner ${owner?.slice(0, 16)}…  (${entry.origin})`;
}

function finish(
  store: Store,
  map: CborMap,
  secret: Uint8Array,
  coSecret: Uint8Array | undefined,
  now: number,
  ledger?: EquivocationLedger,
): number {
  const input = signingInput(map);
  map.set('sig', sign(secret, input));
  if (coSecret !== undefined) map.set('coSig', sign(coSecret, input));

  const bytes = encode(map);
  const before = ledger?.size ?? 0;
  const verdict = store.append(bytes, now);
  // Reported here because a detection nobody is told about is the same defect as a detection
  // nobody wrote down. The operator asked for a registration and got a refusal; which refusal it
  // is — a name somebody else holds, or a second future they themselves signed for a name they
  // already hold — is the whole of what they need to know next.
  if (ledger !== undefined && ledger.size > before) {
    const recorded = ledger.entries()[ledger.size - 1]!;
    err(`equivocation recorded  ${describeReport(recorded)}`);
    err(`  written to ${ledger.path} — nothing is penalised by it; see REPLICATION.md 6.4`);
  }

  if (verdict.outcome === 'accept') {
    const r = verdict.record;
    out(`accepted  ${r.op}  ${r.name}.${r.tld}  seq ${r.seq}  ${bytes.length} bytes`);
    if (r.op === 'TRANSFER') {
      // Accepted is not the same as done, and this is the one operation where they differ.
      out(`transfer settles at ${r.notBefore + SETTLEMENT_SECONDS} (14 days); until then the`);
      out('outgoing key still controls the name and may cancel by transferring it back');
    }
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
  // During Article 33.4's settlement delay `ownerKey` names where the name is GOING; the
  // controlling key is still the transferor's. Printing ownerKey as "owner" for those fourteen
  // days would report a handover that has not happened yet.
  const settlesAt = r.op === 'TRANSFER' ? r.notBefore + SETTLEMENT_SECONDS : null;
  const settling = settlesAt !== null && now < settlesAt;
  out(`${label}.${tld}`);
  out(`  state      ${state}${settling ? '  (transfer settling)' : ''}`);
  out(`  owner      ${toHex(settling ? held.current.signerKey : r.ownerKey)}`);
  if (settling) {
    out(`  transfer   to ${toHex(r.ownerKey)}, taking effect at ${settlesAt}`);
    out('             until then the outgoing key still controls the name and may cancel');
  }
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
    // `sourceValueOf` renders a `cid` base32, the way REGISTRY.md renders one outside CBOR, so
    // what is printed here is comparable by eye to the `--cid` that was typed. Falling back to
    // hex is for the entry types it does not address (and for a malformed one), where the raw
    // bytes are the only honest thing to show.
    const rendered = e.known ? sourceValueOf(e) : null;
    const value = rendered ?? (e.value instanceof Uint8Array ? toHex(e.value) : String(e.value));
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

/**
 * Show what this peer knows about equivocation.
 *
 * REPLICATION.md 6.3 makes recording a MUST and Article 38 asks for a legible record; a file only
 * a hex editor can read is neither. This is the reading end of the ledger, and it is the only one
 * — nothing in the resolver, the verifier or the convergence rule consults it.
 *
 * The closing line is not decoration. 6.4 says the protocol does not punish equivocation, and a
 * list of names printed under the word "equivocation" with no further comment reads as a
 * blocklist to every operator who has ever seen one. A page that overstates what is enforcing is
 * a defect of the same kind as a control that does not work.
 */
function cmdEquivocations(args: Args): number {
  const path = required(args, 'log');
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  const held = ledger.entries();

  if (held.length === 0) {
    out(`no equivocation recorded for ${path}`);
    out(
      `  ledger: ${ledger.path} (${existsSync(ledger.path) ? 'present and empty' : 'not created yet'})`,
    );
  } else {
    out(`${held.length} report(s) in ${ledger.path}`);
    for (const report of held) out(`  ${describeReport(report)}`);
    out();
    out(
      `  detected here: ${ledger.countOf('detected')}   received from peers: ` +
        `${ledger.countOf('received')}`,
    );
  }

  // Printed always, including at zero, because "nothing was refused" and "nothing was looked at"
  // are different states and a counter shown only when it is non-zero cannot distinguish them.
  const refused = ledger.refused;
  out(
    `  refused: ${refused.unverified} unverified, ${refused.full} over budget, ` +
      `${refused.unreadable} unreadable`,
  );
  out();
  out('Nothing is penalised by this list. The protocol has no exclusion, no blacklist and no');
  out('loss of a name — see REPLICATION.md 6.4. It is a record, and what to do with it is yours.');
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
            const transferor = vector.state.transferorKey;
            return predecessorFrom(
              parseRecordBytes(bytes),
              bytes,
              transferor === undefined ? undefined : fromHex(transferor),
            );
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

/**
 * Run the resolver: the browsing proxy on loopback, the control API on a Unix socket.
 *
 * Long-running, so it is the one command that returns a promise. Everything policy-shaped lives
 * in `proxy.ts`, `control.ts` and `serve.ts`; this function's whole job is wiring and the two
 * things a running process owns that a pure function cannot -- a generated token and a signal
 * handler that puts the socket away.
 */
/* -------------------------------------------------------------------------- */
/* The light client — REGISTRY.md, "A light client verifies one name"          */
/* -------------------------------------------------------------------------- */

/**
 * Every entry in the log, as the leaves a merkle tree is built over.
 *
 * Read out rather than held, because `Store` is a file-backed log and the tree is derived state.
 * The cost is honest and stated in `proveInclusion`'s own comment: a production node keeps interior
 * nodes; this rebuilds. The *verification* side is O(log n) either way, and that is the side a
 * light client runs.
 */
function leavesOf(store: Store): Uint8Array[] {
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < store.length; i += 1) {
    const entry = store.entryAt(i);
    if (entry === null) break;
    leaves.push(entry.bytes);
  }
  return leaves;
}

const rootToJson = (root: Root): unknown => ({
  hash: toHex(root.hash),
  index: root.index,
  size: root.size,
});

/**
 * Read one node of a proof back, refusing anything that is not one.
 *
 * A proof arrives from a peer, so every field is attacker-chosen and none may be assumed. The
 * refusals are deliberately blunt — a malformed proof is a refusal, never a partially trusted
 * structure — because a verifier that repairs its input has stopped verifying it.
 */
function rootFromJson(value: unknown, where: string): Root {
  if (value === null || typeof value !== 'object')
    throw new UsageError(`${where} is not an object`);
  const node = value as Record<string, unknown>;
  const hash = node['hash'];
  const index = node['index'];
  const size = node['size'];
  if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/i.test(hash)) {
    throw new UsageError(`${where}.hash must be 32 bytes of hex`);
  }
  if (!Number.isInteger(index) || (index as number) < 0) {
    throw new UsageError(`${where}.index must be a non-negative integer`);
  }
  if (!Number.isInteger(size) || (size as number) < 0) {
    throw new UsageError(`${where}.size must be a non-negative integer`);
  }
  return { hash: fromHex(hash), index: index as number, size: size as number };
}

/**
 * Prove one name's presence in this log, for someone who does not hold it.
 *
 * Step 2 of REGISTRY.md's light-client procedure, from the side that has the log. What goes out is
 * the record's bytes and the sibling hashes needed to fold them up to a root.
 *
 * **The document deliberately carries no `treeRoot`.** `Proof`'s own comment says a proof that
 * carried its own leaf "would let a peer prove inclusion of something the light client never asked
 * about"; a proof carrying the root it is checked against is that defect one level up, with the
 * peer supplying both the evidence and the standard it is judged by. The root has to come from the
 * claims, which is why `light-verify` takes them separately and why this command prints its own
 * root to stderr, next to the sentence saying not to trust it from here.
 */
function cmdProve(args: Args): number {
  const now = clockOf(args);
  const store = Store.open(required(args, 'log'), now);
  const { label, tld } = splitName(required(args, 'name'));

  const held = store.lookup(label, tld);
  if (held === null) {
    err(`${label}.${tld} has no history in this log`);
    return 3;
  }

  const leaves = leavesOf(store);
  const leaf = leaves[held.logIndex];
  if (leaf === undefined) {
    err(`${label}.${tld} is indexed at ${held.logIndex}, past a log of ${leaves.length}`);
    return 1;
  }
  const proof = proveInclusion(leaves, held.logIndex);
  out(
    JSON.stringify({
      name: `${label}.${tld}`,
      logLength: leaves.length,
      // The LEAF, not a re-encoding of the parsed record. The proof is about these exact
      // bytes, and anything that round-tripped through a decoder would be a different
      // artefact that happens to mean the same thing.
      record: toHex(leaf),
      proof: {
        leafIndex: proof.leafIndex,
        leafSize: proof.leafSize,
        siblings: proof.siblings.map(rootToJson),
        siblingIsLeft: proof.siblingIsLeft,
        roots: proof.roots.map(rootToJson),
        rootIndex: proof.rootIndex,
      },
    }),
  );
  // On stderr, so piping the document to a file keeps the two apart — which is the point.
  err(`tree root at length ${leaves.length}: ${toHex(treeOf(leaves).root())}`);
  err("That root is THIS log's claim about itself. A light client must obtain the length and");
  err('root from peers instead; taking both from one source proves only self-consistency.');
  return 0;
}

/** One peer's checkpoint claim, as the light client receives it. */
interface Claim {
  readonly logLength: number;
  readonly treeRoot: string;
}

function claimsFrom(path: string): Claim[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new UsageError(
      `--claims ${path}: ${error instanceof Error ? error.message : 'unreadable'}`,
    );
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new UsageError(`--claims ${path}: expected a non-empty array of {logLength, treeRoot}`);
  }
  return parsed.map((value, i) => {
    if (value === null || typeof value !== 'object')
      throw new UsageError(`claim ${i} is not an object`);
    const claim = value as Record<string, unknown>;
    const logLength = claim['logLength'];
    const treeRoot = claim['treeRoot'];
    if (!Number.isInteger(logLength) || (logLength as number) < 0) {
      throw new UsageError(`claim ${i}: logLength must be a non-negative integer`);
    }
    if (typeof treeRoot !== 'string' || !/^[0-9a-f]{64}$/i.test(treeRoot)) {
      throw new UsageError(`claim ${i}: treeRoot must be 32 bytes of hex`);
    }
    return { logLength: logLength as number, treeRoot: treeRoot.toLowerCase() };
  });
}

/**
 * Verify one name against peers' claims, holding no log at all.
 *
 * Steps 1 and 2 of REGISTRY.md's light-client procedure. **Step 3 is not done here and the output
 * says so**: verifying the record's own chain — signatures, `prevHash` links, proof of work — is
 * `vw verify`'s job, and a command that implied it had checked the chain would be claiming the
 * more valuable half of the procedure on the strength of the cheaper one.
 *
 * Three refusals, each for a different reason a light client can be lied to:
 *
 * - **No corroborated length.** `greatestCorroboratedLength` takes the greatest length claimed by
 *   at least `--quorum` peers, which fails toward staleness rather than toward believing a single
 *   stranger. One peer therefore proves nothing by default, and `--quorum 1` is available and says
 *   in the answer what it gave up.
 * - **A fork.** Peers claiming the same length with different roots are surfaced and neither is
 *   taken — REPLICATION.md 7.3 says surface and MUST NOT pick one, and picking the first or the
 *   majority would be picking.
 * - **A proof for a different length.** The peaks in a proof are the peaks at the length it was
 *   built for, so checking it against another length's root would fail obscurely. Said plainly
 *   instead.
 */
function cmdLightVerify(args: Args): number {
  const now = clockOf(args);
  const { label, tld } = splitName(required(args, 'name'));
  const name = `${label}.${tld}`;
  const quorum = number(args, 'quorum', 2);
  if (quorum < 1) throw new UsageError('--quorum must be at least 1');

  let document: Record<string, unknown>;
  try {
    document = JSON.parse(readFileSync(required(args, 'proof'), 'utf8')) as Record<string, unknown>;
  } catch (error) {
    throw new UsageError(`--proof: ${error instanceof Error ? error.message : 'unreadable'}`);
  }
  if (document['name'] !== name) {
    err(`the proof is about ${String(document['name'])}, not ${name}`);
    return 1;
  }
  if (document['treeRoot'] !== undefined) {
    // Refused rather than ignored. A document that carries a root is one somebody built to be
    // checked against itself, and accepting it quietly would make that the normal shape.
    err('the proof carries a treeRoot; a proof checked against a root from the same source');
    err('proves only that the source is self-consistent. Obtain the root from peers.');
    return 1;
  }
  const record = document['record'];
  if (typeof record !== 'string' || !/^([0-9a-f]{2})+$/i.test(record)) {
    throw new UsageError("the proof's record must be a hex string");
  }
  const proofLength = document['logLength'];
  if (!Number.isInteger(proofLength) || (proofLength as number) <= 0) {
    throw new UsageError("the proof's logLength must be a positive integer");
  }
  const proof = proofFromJson(document['proof']);

  const claims = claimsFrom(required(args, 'claims'));
  const chosen = greatestCorroboratedLength(
    claims.map((c) => c.logLength),
    quorum,
  );
  if (chosen === null) {
    err(`no log length is corroborated by ${quorum} of the ${claims.length} claim(s) supplied`);
    err('A length one peer asserts is a length one peer can invent. Ask more peers, or');
    err('pass --quorum 1 and read the answer knowing what it rests on.');
    return 1;
  }

  const atLength = claims.filter((c) => c.logLength === chosen.length);
  const roots = new Set(atLength.map((c) => c.treeRoot));
  if (roots.size > 1) {
    err(`FORK at log length ${chosen.length}: ${roots.size} peers disagree about the tree root`);
    for (const root of roots) err(`  ${root}`);
    err('Neither is chosen. REPLICATION.md 7.3 surfaces a fork and does not resolve one, because');
    err('nothing on this side is evidence about which history is the real one.');
    return 1;
  }
  const treeRoot = atLength[0]!.treeRoot;

  if (proofLength !== chosen.length) {
    err(`the proof is for log length ${String(proofLength)}, and ${chosen.length} is what peers`);
    err('corroborate. A proof carries the tree peaks at its own length, so it can only be checked');
    err('against the root at that length. Ask the prover for a proof at the corroborated length.');
    return 1;
  }

  const answer = verifyNameInclusion(
    name,
    fromHex(record),
    proof,
    fromHex(treeRoot),
    chosen.length,
    now,
    chosen.peersAgreeing,
  );

  out(`${answer.verified ? 'verified' : 'NOT verified'}  ${answer.name}`);
  out(`  ${answer.detail}`);
  out(`  log length ${answer.logLength}, observed at ${answer.observedAt}`);
  // Unconditional, on both outcomes. REGISTRY.md: "show that length and the observation time with
  // every answer", and the freshness gap is the thing an inclusion proof most invites a reader to
  // forget it has not closed.
  out('  freshness is UNPROVEN: no inclusion proof shows the length handed over is current, so a');
  out('  peer withholding recent entries can present a stale but internally consistent view.');
  out('  This is steps 1 and 2 only. Run `verify` for the record chain — step 3.');
  return answer.verified ? 0 : 1;
}

/** Read a proof back from a document, refusing anything that is not one. */
function proofFromJson(value: unknown): Proof {
  if (value === null || typeof value !== 'object') throw new UsageError('the proof is missing');
  const raw = value as Record<string, unknown>;
  const leafIndex = raw['leafIndex'];
  const leafSize = raw['leafSize'];
  const rootIndex = raw['rootIndex'];
  for (const [field, at] of [
    ['leafIndex', leafIndex],
    ['leafSize', leafSize],
    ['rootIndex', rootIndex],
  ] as const) {
    if (!Number.isInteger(at) || (at as number) < 0) {
      throw new UsageError(`proof.${field} must be a non-negative integer`);
    }
  }
  const siblings = raw['siblings'];
  const siblingIsLeft = raw['siblingIsLeft'];
  const roots = raw['roots'];
  if (!Array.isArray(siblings) || !Array.isArray(roots) || !Array.isArray(siblingIsLeft)) {
    throw new UsageError('proof.siblings, proof.siblingIsLeft and proof.roots must be arrays');
  }
  if (siblings.length !== siblingIsLeft.length) {
    throw new UsageError('proof.siblings and proof.siblingIsLeft must be the same length');
  }
  if (!siblingIsLeft.every((flag) => typeof flag === 'boolean')) {
    throw new UsageError('proof.siblingIsLeft must be booleans');
  }
  return {
    leafIndex: leafIndex as number,
    leafSize: leafSize as number,
    siblings: siblings.map((s, i) => rootFromJson(s, `proof.siblings[${i}]`)),
    siblingIsLeft: siblingIsLeft as boolean[],
    roots: roots.map((r, i) => rootFromJson(r, `proof.roots[${i}]`)),
    rootIndex: rootIndex as number,
  };
}

/** The merkle root over the log's current entries, recomputed rather than remembered. */
function merkleRootOf(store: Store, length: number): Uint8Array {
  const entries: Uint8Array[] = [];
  for (let i = 0; i < length; i += 1) {
    const entry = store.entryAt(i);
    if (entry === null) break;
    entries.push(entry.bytes);
  }
  return treeOf(entries).root();
}

/**
 * The version the control API discloses, past the token check and nowhere else.
 *
 * A literal rather than a read of `package.json`: the file is not present in every way this is
 * run, and a version string that sometimes reads `unknown` is a worse answer than one that is
 * simply kept in step with the release commit.
 *
 * **The reasoning held and the second half did not.** The package went to 0.2.1 and this stayed at
 * 0.1.0, so `GET /v1/status` named a build that had shipped two releases earlier — worse than
 * having no version field at all, because the field is disclosed past the token check on the
 * stated grounds that a version string is a fingerprint and a vulnerability-matching aid. Its
 * entire purpose is to identify the build, and an operator matching a bug report against 0.1.0
 * was reading code that was not running.
 *
 * Still a literal, and `cli.test.ts` now compares it to `package.json`. The manifest is always
 * present *there*, which is where "kept in step" needed something doing the keeping.
 */
const RESOLVER_VERSION = '0.2.1';

/**
 * The one path inside a dot-directory that is published, and the directory holding it.
 *
 * **Derived from the resolver's own constant, not restated.** `MANIFEST_PATH` is a request path
 * (`/.vayu/manifest.json`) and a publish walk works in relative paths, which is exactly the kind of
 * near-miss that ends up as two literals: the publisher would keep writing the old path while the
 * resolver fetched the new one, and the manifest would simply stop being found. Both forms now come
 * from the one declaration in `resolve.ts`.
 */
const MANIFEST_RELATIVE = MANIFEST_PATH.replace(/^\//, '');
const MANIFEST_DIRECTORY = MANIFEST_RELATIVE.split('/').slice(0, -1).join('/');

/**
 * Whether a relative path inside a published directory must be kept out of the root CID.
 *
 * **Path-shaped rather than name-shaped, and that is the whole point.** The exemption belongs to
 * the manifest, not to the directory it sits in: a directory-wide exemption publishes whatever a
 * publisher left beside it — a deploy key, a draft, an editor's session file — into content that
 * is addressed, immutable, served, and fetchable forever by anyone holding the CID. Immutable is
 * the part with no remedy.
 *
 * PUBLISHING.md 2 defines exactly one path, `.vayu/manifest.json`, at the root of the tree.
 * Nothing else under `.vayu`, and no `.vayu` at any other depth, has a defined meaning, so nothing
 * else is worth publishing.
 */
function excludedFromPublish(rel: string): boolean {
  // The directory is walked so the manifest inside it can be reached; the manifest itself is the
  // exemption. Nothing else needs naming — anything else under `.vayu` still carries a dotted
  // segment, so the general rule below already catches it. An explicit `.vayu/` rejection was
  // written here first and survived its own mutation, which is how it was found to be redundant.
  if (rel === MANIFEST_DIRECTORY || rel === MANIFEST_RELATIVE) return false;
  // Every segment, not just the last. That is what excludes `.vayu/deploy.key` and `docs/.vayu`
  // by the same line that excludes `.env`, and what makes this predicate hold on its own rather
  // than only because the walk happens to stop descending at an excluded directory.
  return rel.split('/').some((segment) => segment.startsWith('.'));
}

/**
 * The files a directory publishes, with HOSTING.md's package rules applied.
 *
 * **A publish walk is a disclosure surface, and this one had no rules at all.** Measured against
 * an ordinary working directory it collected `.env` and `.git/config` and imported both into the
 * root CID — content addressed, immutable, and fetchable by anyone holding the CID. A git config
 * can carry a credential in a remote URL.
 *
 * HOSTING.md names the hazard in terms, for the neighbouring case: symbolic links "MUST NOT be
 * followed … since a followed link can silently pull a private key into a public CID". It just did
 * not anticipate the door it came through.
 *
 * Three rules, each from that document's package section:
 *
 * - **A leading dot is excluded.** The one exception is `.vayu/manifest.json` — the exact path
 *   PUBLISHING.md 2 defines, at the root of the tree. The exemption used to be written on the
 *   DIRECTORY, which published everything a publisher happened to leave beside the manifest, and
 *   said in a comment that `.vayu` "is not served" while the proxy answered 200 for it. It is in
 *   the signed tree like every other file; the manifest is metadata by convention, not by mechanism.
 * - **A symbolic link stops the publish.** It was already skipped, but by accident — `Dirent`
 *   methods are lstat-shaped, so a link is neither a file nor a directory and fell out of both
 *   branches. Silently omitting a file is neither "dereference" nor "refuse", and it publishes a
 *   site with a hole in it that the publisher is never told about.
 * - **A filename over 255 bytes stops the publish**, rather than being quietly renamed or dropped.
 *
 * Excluded entries are reported rather than dropped in silence, for the same reason: a site that
 * renders wrong because an asset vanished is worse than one that refused to publish.
 */
export function siteFilesFor(directory: string): SiteFile[] {
  const files: SiteFile[] = [];
  const excluded: string[] = [];

  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;

      if (entry.isSymbolicLink()) {
        throw new UsageError(
          `${rel} is a symbolic link. HOSTING.md requires a publisher to dereference links or ` +
            `refuse the import, because a followed link can pull a private key into a public CID. ` +
            `Replace it with the file it points at, or remove it.`,
        );
      }
      // HOSTING.md's 255-byte filename bound. Defensive rather than reachable here: every
      // filesystem this is likely to run on enforces the same limit itself, so a longer name
      // cannot be created to test against — which is exactly why it is worth keeping and not
      // worth claiming a test for.
      if (Buffer.byteLength(entry.name, 'utf8') > 255) {
        throw new UsageError(`${rel}: a filename may not exceed 255 bytes`);
      }
      if (excludedFromPublish(rel)) {
        excluded.push(rel);
        continue;
      }
      if (entry.isDirectory()) walk(join(dir, entry.name), rel);
      else if (entry.isFile())
        files.push({ path: rel, content: readFileSync(join(dir, entry.name)) });
    }
  };
  walk(directory, '');

  if (excluded.length > 0) {
    err(`excluded ${excluded.length} entr${excluded.length === 1 ? 'y' : 'ies'} from the publish:`);
    for (const path of excluded.slice(0, 8)) err(`  ${path}`);
    if (excluded.length > 8) err(`  … and ${excluded.length - 8} more`);
  }
  if (files.length === 0) throw new UsageError(`${directory} holds no files to publish`);
  return files;
}

/**
 * A content port over a directory published into memory.
 *
 * Returns null when no `--site` was given, which leaves the proxy answering a bare 200 -- the
 * truthful "this name resolves and nothing here serves it".
 */
function siteContentOf(
  directory: string | undefined,
): { content: ContentPort; root: string } | null {
  if (directory === undefined) return null;

  const files = siteFilesFor(directory);

  const built = importSite(files);
  const source = memorySource(built.blocks);
  out(`published ${files.length} file(s) from ${directory}`);
  out(`  root CID  ${built.root}`);

  const content: ContentPort = {
    fetch: (chosen, path) => {
      // Kept although step 10 now hands this port a CID and nothing else: `ContentPort` is a
      // published interface, and a guard at an interface boundary is not the same thing as a
      // branch nobody can reach from inside one module.
      if (chosen.type !== 'cid') return { ok: false, error: 'NO_USABLE_RECORD' };
      if (chosen.value !== built.root) return { ok: false, error: 'CONTENT_UNAVAILABLE' };
      // **An exact path, and no mapping.** This used to try `path`, then `path/index.html`, which
      // put half of RESOLUTION.md step 13 here and half in the resolver — and the manifest half,
      // which belongs to neither, ended up in nothing at all. Step 13 now lives in `serveStep13`
      // and a port is what it says it is: bytes for a path, or a numbered failure.
      try {
        const bytes = fetchPath(source, built.root, path);
        return { ok: true, bytes, contentType: contentTypeOf(path) };
      } catch (error) {
        if (!(error instanceof FetchError)) throw error;
      }
      return { ok: false, error: 'PATH_NOT_FOUND' };
    },
  };
  return { content, root: built.root };
}

/**
 * The control token, and the one thing that makes rotation work.
 *
 * A holder rather than a string, because `POST /v1/token/rotate` replaces the value while the
 * listener is bound. `serveControl` reads `current` per request; capturing it once would hand a
 * caller a fresh token and then go on refusing it, which is the shape of defect this codebase has
 * found repeatedly — a mechanism producing a new value while the thing that checks it reads the
 * old one.
 *
 * Exported so the wiring can be exercised directly. The policy is testable through a double at the
 * `serve.ts` level; what a double cannot show is whether the *shipping* holder actually replaces
 * anything, and "declared and never assigned" is precisely the defect that hides behind a double.
 *
 * Never written to a file or an environment variable, before or after a rotation: a token in a
 * config file is a token in a backup, in a screenshot and in a support ticket.
 */
export function rotatingToken(): { current: () => string; rotate: () => string } {
  let value = randomBytes(TOKEN_BYTES).toString('base64url');
  return {
    current: () => value,
    rotate: () => {
      value = randomBytes(TOKEN_BYTES).toString('base64url');
      return value;
    },
  };
}

/**
 * What a name currently resolves to, as `{type, value}` pairs a content key can be built from.
 *
 * A function rather than the `Store` itself so the flush below can be exercised without one.
 */
export type SourcesOf = (
  label: string,
  tld: string,
) => ReadonlyArray<{ type: string; value: string }>;

/**
 * Every content source that resolves to `cid`, so pinning it can drop each cached answer.
 *
 * Always includes the CID itself. A pointer is included only when it really resolves to this CID,
 * which the `IpnsPort` is asked rather than assumed — nothing else in the process knows.
 */
export type RelatedSources = (cid: string) => ReadonlyArray<{ type: string; value: string }>;

/**
 * Flush one name — including the content answer that name currently depends on.
 *
 * **`DELETE /v1/cache/{name}` reported success and left the entry making the site fail.** A content
 * failure is keyed by the SOURCE it is a fact about, which `proxy.ts` did deliberately and
 * correctly: keyed by name it was unreachable for lookups, because step 5 answers from the record
 * cache and skips the step that would have consulted it. What went unnoticed is the other half —
 * keyed by source, it is unreachable for every NAME-keyed flush. An operator clearing their own
 * name was told `{"flushed":1}` and got no change, which is worse than an error.
 *
 * RESOLUTION.md calls this endpoint "flush one name", and a content failure the name currently
 * depends on is part of that name's answer.
 *
 * **The limit, stated rather than papered over:** this drops the sources the name resolves to
 * *now*. If the record has been updated since the failure was cached, the previous CID's entry is
 * not reached — nothing here maps a name to sources it used to have. `DELETE /v1/cache` remains
 * the answer for that, and it clears everything.
 */
export function flushPorts(
  sources: SourcesOf,
  cache: ResolutionCache,
): (name: { label: string; tld: string }) => number {
  return (name) => {
    let gone = cache.forget(`${name.label}.${name.tld}`);
    for (const source of sources(name.label, name.tld)) {
      gone += cache.forget(contentCacheKey(source.type, source.value));
    }
    return gone;
  };
}

/**
 * Which content sources resolve to a given CID, for the pin path to invalidate.
 *
 * **The pointer is included only when it really resolves to this CID**, and the `IpnsPort` is
 * asked rather than assumed. Without that check, pinning *any* CID would drop the pointer's cached
 * answer — which on a resolver serving more than one publisher is the same shape as the refused
 * pin that flushed anyway: a caller turning an endpoint they cannot otherwise use into a cache
 * flush for somebody else's content.
 *
 * Extracted from `cmdServe` because a survived mutation showed the check was untestable where it
 * was. `rotatingToken` was extracted for the same reason, and this is the same lesson twice: the
 * wiring inside a long-running command is exactly where a guard goes unexercised.
 */
export function relatedSourcesFor(
  declared: string | undefined,
  ipns: IpnsPort | null,
): RelatedSources {
  return (cid) => {
    const sources = [{ type: 'cid', value: cid }];
    if (declared !== undefined && ipns?.resolve(declared) === cid) {
      sources.push({ type: 'ipns', value: declared });
    }
    return sources;
  };
}

/**
 * The pin and unpin ports, with the cache invalidation that makes them symmetric.
 *
 * **Unpinning took effect at once and re-pinning did not**, which is the defect this exists to
 * close. `DELETE /v1/pin/{cid}` is instant because it *creates* the failure; `POST /v1/pin` was
 * not, because the failure it undoes is negatively cached against the content source for ten
 * seconds. The operator saw `200 {"outcome":"pinned"}` and a site that was still down, with
 * nothing to explain the gap — found by driving a running resolver, not by testing one.
 *
 * The argument was already in the codebase: `setGeneration` drops every entry when the log grows,
 * because "a log that has not grown is a registry whose answers cannot have changed". The pin set
 * is a second thing that changes answers, and nothing invalidated on it. Both directions forget
 * the entry, because a stale *positive* is as wrong after an unpin as a stale negative is after a
 * pin.
 *
 * **`related` exists because the first fix reached only half the sites, and I wrote the other half
 * off.** A content failure is keyed by the source the RECORD names, so a name carrying an `ipns`
 * pointer caches under `content:ipns:<pointer>` and never under the CID — and re-pinning left that
 * name down for the full pointer TTL, on the arrangement HOSTING.md tells publishers to prefer.
 * The comment here used to call that an acceptable limitation that "expires on the pointer cache's
 * own bound", which was a limitation invented in place of finding the reverse mapping. The mapping
 * was never missing: an `IpnsPort` knows what its pointer resolves to, so the caller can be asked.
 * **Documenting a gap is not fixing one.**
 *
 * Grouped as a pair rather than written inline so the symmetry is a thing a test can hold.
 */
export function pinPorts(
  pinned: PinSet,
  cache: ResolutionCache,
  related: RelatedSources,
): { pin: (cid: string) => PinOutcome; unpin: (cid: string) => boolean } {
  // Only the `cid` key. This dropped an `ipns` one too until a surviving mutation showed nothing
  // could tell — and nothing could, because the two keyspaces do not overlap: an ipns entry is
  // keyed by the POINTER (`k51…`), and a pin names a CID (`bafy…`), so passing a CID as an ipns
  // key matched nothing that has ever existed. It read as a defence and could not fire.
  //
  // The honest limitation, since removing the line does not remove the question: if a pointer
  // resolves to the CID being pinned, its cached answer is not invalidated here, because this path
  // has no reverse mapping from a CID to the pointers that resolve to it. That entry expires on
  // the pointer cache's own bound — `min(record validity, 120 seconds)` — which is the shortest
  // TTL in the table precisely because the pointer is the mutable half.
  const forget = (cid: string): void => {
    for (const source of related(cid)) {
      cache.forget(contentCacheKey(source.type, source.value));
    }
  };
  return {
    pin: (cid) => {
      const outcome = pinned.add(cid);
      // Only when something changed. A refused pin has undone nothing and must not flush an
      // answer that is still true.
      if (outcome === 'pinned') forget(cid);
      return outcome;
    },
    unpin: (cid) => {
      const removed = pinned.remove(cid);
      if (removed) forget(cid);
      return removed;
    },
  };
}

/**
 * A content port that serves only what the pin set still holds.
 *
 * Extracted and exported so the behaviour can be exercised as data rather than by binding a
 * listener — the same split `serve.ts` keeps, and the reason a refusal expressed as a function is
 * testable while one expressed as "the socket stopped answering" is not.
 *
 * This is what gives `DELETE /v1/pin/{cid}` teeth. Article 19.2's second guaranteed act is "unpin
 * it locally", and an unpin that left the proxy handing out the same bytes would be the interface
 * saying one thing and the socket doing another. The blocks remain in memory; what changes is that
 * this node stops undertaking to serve them, which is the whole of what a local unpin can mean.
 */
export function pinGated(inner: ContentPort, pinned: PinSet): ContentPort {
  return {
    fetch: (chosen, path) =>
      chosen.type === 'cid' && pinned.has(chosen.value)
        ? inner.fetch(chosen, path)
        : { ok: false, error: 'CONTENT_UNAVAILABLE' },
  };
}

/**
 * The resolver's view of a local log.
 *
 * **An empty log is a resolver that has not synchronised, not a namespace with nothing in it.**
 * `hasVerifiedHead` said `true` unconditionally, so a node started against a log file that did not
 * exist answered every name with 1404 — "No one has registered this name" — a definite claim about
 * the *global* namespace made from a local file with nothing in it. No resolver can know that, and
 * the one making the claim knew least of all: it had not seen a single record. The two answers send
 * a reader somewhere different, too — 1404 says the name is free and invites them to take it.
 *
 * RESOLUTION.md step 7: "if the log has never synchronised (no verified head), return 1502
 * `REGISTRY_UNAVAILABLE`." A log with entries has a verified head by construction — `Store.open`
 * replays and re-verifies every one of them or refuses to open — so length is the whole question.
 *
 * A function rather than an object literal inside `cmdServe`, because the bug lived in the literal
 * and a literal inside a command that binds two sockets is a literal no test reaches.
 */
export function resolverPortsFor(store: Store): ResolverPorts {
  return {
    lookup: (label, tld) => store.lookup(label, tld)?.current.record ?? null,
    hasVerifiedHead: () => store.length > 0,
  };
}

/**
 * A local, operator-declared answer for one IPNS pointer.
 *
 * **Not a network resolution, and the difference is the whole of what this is.** Resolving an IPNS
 * name means the IPFS routing stack, which this package deliberately does not depend on. What
 * `--pointer` says is "the record I am testing carries this pointer, and it means the site I just
 * published from `--site`" — which is what a publisher needs to check the `ipns`-first path before
 * they publish, and it is exactly one mapping the operator typed.
 *
 * Every other pointer resolves to null, which is 1505 and is true: this resolver could not resolve
 * it. Returning the published root for any pointer at all would be the interesting lie — a
 * resolver that serves whatever it has to whatever it is asked for.
 */
export function pointerFor(declared: string | undefined, root: string | null): IpnsPort | null {
  if (declared === undefined) return null;
  if (root === null) {
    throw new UsageError('--pointer names what --site publishes, so it needs --site too');
  }
  out(`  pointer   ${declared} -> ${root} (declared locally, not resolved over a network)`);
  return { resolve: (asked) => (asked === declared ? root : null) };
}

/**
 * Content type by extension, from a closed list.
 *
 * Closed on purpose. Sniffing a type from bytes is how a resolver serves attacker-chosen content
 * as script, and `x-content-type-options: nosniff` is already on every response -- guessing here
 * would undo it from the other side.
 */
function contentTypeOf(path: string): string {
  const known: Record<string, string> = {
    html: 'text/html; charset=utf-8',
    css: 'text/css; charset=utf-8',
    js: 'text/javascript; charset=utf-8',
    json: 'application/json',
    svg: 'image/svg+xml',
    png: 'image/png',
    jpg: 'image/jpeg',
    webp: 'image/webp',
    txt: 'text/plain; charset=utf-8',
  };
  const ext = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  return known[ext] ?? 'application/octet-stream';
}

/**
 * Replicate with one peer over TCP, until interrupted.
 *
 * **The reference transport binding had no shipping caller.** `swarm.ts` has held the framing, the
 * discovery topic and a driver since Phase 2, and `registry/src/cli.ts` had no verb that opened a
 * socket — so every claim about replication rested on two objects joined by a pipe inside one
 * process. ROADMAP.md's own acceptance criterion asks for "independent peers, started in any order
 * and partitioned deliberately", and two operating-system processes with their own stores, talking
 * over a real socket, are that. What they are NOT is two machines: they share a kernel, a clock and
 * a filesystem, so this closes the gap between the code and its claims without closing the phase.
 *
 * **Loopback by default, and widening is a decision nobody has made.** `--address` exists and is
 * not defaulted to `0.0.0.0`: a default that publishes a registry to whatever network the machine
 * happens to be on is the kind of default an operator discovers afterwards. The protocol is built
 * to survive a hostile peer — REPLICATION.md 2.3, nothing about the channel is evidence about a
 * record — but surviving one and inviting one are different choices.
 */
async function cmdSync(args: Args): Promise<number> {
  const path = required(args, 'log');
  const listen = args.flags.get('listen');
  const connect = args.flags.get('connect');
  if ((listen === undefined) === (connect === undefined)) {
    throw new UsageError('sync takes exactly one of --listen <port> or --connect <host:port>');
  }

  const { store, ledger } = openWithLedger(path, Math.floor(Date.now() / 1000));
  const sink = sinkOver(store);
  // One ledger across every connection, because a fork is two peers disagreeing and a single
  // connection only ever hears one of them. Nothing in it picks a side; see REPLICATION.md 7.3.
  const forks = new CheckpointLedger();
  const now = (): number => Math.floor(Date.now() / 1000);
  out(`log ${path} holds ${store.length} record(s)`);

  /** Report what a connection did, so an operator watching sees progress rather than silence. */
  const report = (label: string, outcome: PeerOutcome): void => {
    out(
      `${label}  applied ${outcome.applied}  rejected ${outcome.rejected}  ` +
        `deferred ${outcome.deferred}  duplicate ${outcome.duplicates}  ` +
        `checkpoints ${outcome.checkpoints}${outcome.forks > 0 ? ` — ${outcome.forks} FORK(S)` : ''}  ` +
        `equivocations ${outcome.equivocations} (${outcome.recorded} new)  ` +
        `forwarded ${outcome.forwarded}${outcome.withheld > 0 ? ` (${outcome.withheld} withheld)` : ''}`,
    );
  };

  const sockets = new Set<Socket>();
  let server: Server | null = null;

  const closed = new Promise<void>((resolve) => {
    const stop = (): void => {
      for (const socket of sockets) socket.destroy();
      server?.close();
      resolve();
    };
    // A long-running command ends on a signal, not on a timer. `once` rather than `on`, so a
    // second interrupt reaches the default handler and kills a process that will not stop.
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });

  const drive = (socket: Socket, label: string): void => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    const outcome = drivePeer(socket, sink, now, {
      ledger,
      forks,
      checkpoints: () => store.checkpoint(now()),
    });
    // Printed on close rather than per message: a line per record turns a sync of a real log into
    // a wall of output, and the totals are what an operator is actually asking about.
    socket.on('close', () => report(label, outcome));
  };

  if (listen !== undefined) {
    const port = Number(listen);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new UsageError(`--listen ${listen} is not a port`);
    }
    const address = args.flags.get('address') ?? '127.0.0.1';
    let peers = 0;
    server = createServer((socket) => {
      if (peers >= SWARM_LIMITS.connections) {
        socket.destroy();
        return;
      }
      peers += 1;
      socket.on('close', () => {
        peers -= 1;
      });
      out(`peer connected from ${socket.remoteAddress ?? 'unknown'}`);
      drive(socket, 'peer');
    });
    await new Promise<void>((resolve, reject) => {
      server?.once('error', reject);
      server?.listen(port, address, resolve);
    });
    out(`listening on ${address}:${port} — interrupt to stop`);
  } else {
    const target = connect!;
    const split = target.lastIndexOf(':');
    if (split <= 0) throw new UsageError(`--connect ${target} is not host:port`);
    const host = target.slice(0, split);
    const port = Number(target.slice(split + 1));
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new UsageError(`--connect ${target} is not host:port`);
    }
    const socket = await new Promise<Socket>((resolve, reject) => {
      const dialled = createConnection({ host, port });
      dialled.once('connect', () => resolve(dialled));
      dialled.once('error', reject);
    });
    out(`connected to ${host}:${port} — interrupt to stop`);
    drive(socket, 'peer');
  }

  await closed;
  out(`log ${path} now holds ${store.length} record(s)`);
  // Printed after the connections close, because a fork found on one is a fact about the run and
  // not about that peer. Never resolved and never ranked: 7.3 says surface it and do not pick one,
  // so this says what was claimed and stops.
  for (const fork of forks.forks) {
    err(`FORK at log length ${fork.logLength}: two peers disagree (${fork.difference})`);
    err(
      `  tree  ${toHex(fork.first.treeRoot).slice(0, 16)}… vs ${toHex(fork.other.treeRoot).slice(0, 16)}…`,
    );
    err(
      `  index ${toHex(fork.first.indexRoot).slice(0, 16)}… vs ${toHex(fork.other.indexRoot).slice(0, 16)}…`,
    );
  }
  if (forks.forks.length > 0) {
    err('A checkpoint carries no signature, so this means "two peers told me different things"');
    err('and no more. It is not evidence a third party can check, and is never forwarded.');
  }
  return 0;
}

async function cmdServe(args: Args): Promise<number> {
  const store = Store.open(required(args, 'log'), Math.floor(Date.now() / 1000));
  const started = Math.floor(Date.now() / 1000);

  // Generated per run, never read from a file or an environment variable. A token in a config
  // file is a token in a backup, in a screenshot and in a support ticket; one that lives only in
  // this process's memory and this run's stdout cannot outlive the process that needs it.
  const token = rotatingToken();

  const socketPath =
    args.flags.get('socket') ??
    join(process.env['XDG_RUNTIME_DIR'] ?? join(homedir(), '.vayuweb'), 'control.sock');

  // `--site <dir>` publishes a directory into an in-memory blockstore and serves it for the CID
  // it produces. The tree goes through the same importer a real publish uses and comes back
  // through the same VERIFIED traversal a peer's blocks would, so this is the content path rather
  // than a shortcut around it -- the only thing it skips is the network.
  const clock = (): number => Math.floor(Date.now() / 1000);
  // One cache, shared by the two surfaces this command binds: the proxy reads it and the control
  // API's `DELETE /v1/cache` empties it. A second cache would make the flush a lie.
  const cache = new ResolutionCache();
  const site = siteContentOf(args.flags.get('site'));

  // Publishing a site IS pinning it: this node holds the blocks and undertakes to serve them, and
  // a pin set that started empty would make `GET /v1/pins` report nothing while the proxy served
  // the site regardless. `holds` is the honest predicate — the only CID this build can obtain
  // bytes for is the one it just imported, so every other pin is refused rather than recorded as
  // an intention that reads like a holding.
  const pinned = new PinSet((cid) => site !== null && cid === site.root);
  if (site !== null) pinned.add(site.root);

  // The wrapper is what gives `DELETE /v1/pin/{cid}` teeth. Article 19.2's second guaranteed act
  // is "unpin it locally", and an unpin that left the proxy serving the same bytes would be the
  // interface saying one thing and the socket doing another. The blocks stay in memory; what
  // changes is that this node stops undertaking to hand them out.
  const served: ContentPort | null = site === null ? null : pinGated(site.content, pinned);
  const pointer = pointerFor(args.flags.get('pointer'), site?.root ?? null);

  let diagnostics = false;
  // One function for both `GET /v1/config` and the answer `PATCH /v1/config` returns, so the two
  // cannot describe the same resolver differently. `redact` blanks the token by key name.
  const effectiveConfig = (): Record<string, unknown> => ({
    log: required(args, 'log'),
    socket: socketPath,
    token: token.current(),
    cacheSizes: cache.limits,
  });

  // The sources a name resolves to right now, read from the log the resolver is serving from.
  const flushName = flushPorts((label, tld) => {
    const held = store.lookup(label, tld);
    if (held === null) return [];
    const out: Array<{ type: string; value: string }> = [];
    for (const entry of held.current.record.entries) {
      const value = sourceValueOf(entry);
      if (value !== null) out.push({ type: entry.type, value });
    }
    return out;
  }, cache);

  const control = await serveControl({
    path: socketPath,
    token: token.current,
    ports: {
      status: () => ({
        mode: 'clearnet',
        uptime: Math.floor(Date.now() / 1000) - started,
        // Only what is actually bound. Reporting a proxy address for a proxy that was not
        // bound would be the same overstatement one field over.
        listeners: proxy === null ? [socketPath] : [proxy.address, socketPath],
      }),
      version: () => RESOLVER_VERSION,
      logHead: () => {
        // Measured by walking, not asked of a field. `entryAt` is the store's only length-shaped
        // API, and a counter cached here would be a second source of truth for a number the
        // control API exists to report honestly.
        let length = 0;
        while (store.entryAt(length) !== null) length += 1;
        return { length, root: toHex(merkleRootOf(store, length)) };
      },
      config: effectiveConfig,
      diagnostics: () => diagnostics,
      setDiagnostics: (on: boolean) => {
        diagnostics = on;
      },
      // What this node holds, and the honest denominator beside it. `asked: 0` is the true
      // number: there is no block-exchange session — VWIP-0005 is a Draft — so no peer has been
      // asked anything, and `summarise` renders that as "nothing is known about who holds this"
      // rather than as a zero that reads like an answer.
      // Everything below answers about a name the router has already validated against the
      // grammar, so nothing here is the first thing to look at an untrusted string.
      resolve: (label, tld) => {
        const outcome = resolveName(`${label}.${tld}`, resolverPortsFor(store), clock(), cache);
        return outcome.ok
          ? {
              outcome: 'ok',
              seq: outcome.record.seq,
              source: outcome.diagnostics.source,
              resolvedFrom: outcome.diagnostics.resolvedFrom,
              aliasHops: outcome.diagnostics.aliasHops,
              value: sourceValueOf(outcome.entry),
              notAfter: outcome.record.notAfter,
              ownerKey: toHex(outcome.record.ownerKey),
            }
          : {
              outcome: 'error',
              code: RESOLVE_ERRORS[outcome.error].code,
              error: outcome.error,
              detail: outcome.detail,
              resolvedFrom: outcome.diagnostics.resolvedFrom,
            };
      },
      cacheStats: () => ({
        negative: cache.negativeSize,
        positive: cache.positiveSize,
        manifests: cache.manifestSize,
        ...cache.counts,
      }),
      flushCache: (name) => (name === null ? cache.clear() : flushName(name)),
      // Honest and dull: this command serves, it does not sync. `vayuweb-registry sync` is where a
      // peer connection lives, and reporting a peer count from a process that never opens one
      // would be reporting a zero that reads like a measurement.
      peers: () => ({
        joined: false,
        peers: 0,
        detail: 'this command does not join a swarm; replication is `vayuweb-registry sync`',
      }),
      pins: () =>
        pinned
          .list()
          .map((cid) =>
            report(
              cid,
              0,
              [{ holder: { kind: 'self' }, observedAt: clock() }],
              OBSERVATION_STALE_SECONDS,
              clock(),
            ),
          ),
      ...pinPorts(pinned, cache, relatedSourcesFor(args.flags.get('pointer'), pointer)),
      // The new token is returned to the caller and goes nowhere else — not to stdout, which
      // already carries the startup one and would otherwise leave two live-looking tokens in one
      // terminal, and not to a file.
      rotateToken: () => token.rotate(),
      // The cache the proxy is actually reading, so a lowered bound trims what it is holding now
      // rather than only what it takes next. `serve` and the proxy share one instance for exactly
      // this reason — `DELETE /v1/cache` had the same requirement first.
      patchCacheSizes: (sizes) => {
        cache.setLimits(sizes);
        return effectiveConfig();
      },
    },
  });

  // **A browsing proxy with no content layer can only lie.** This build's only source of blocks
  // is `--site`, so without one every name that resolves would be answered from a proxy that
  // cannot fetch anything — and it WAS answered, `200 OK` with an empty body, until this. Not
  // binding it is the honest form: there is no request to answer wrongly, the control API still
  // runs, and the operator is told why rather than left to discover a blank page.
  if (served === null) {
    out('');
    out('no --site, so no browsing proxy: this build fetches content only from a published');
    out('directory, and a proxy with nothing to fetch with can only answer 200 with no body.');
    out('The control API below still answers about names.');
  }

  const proxy =
    served === null
      ? null
      : await serveProxy({
          port: number(args, 'port', 7654),
          // The process boundary is where the real clock is allowed to exist; every module below this
          // takes it as a parameter.
          now: () => Math.floor(Date.now() / 1000),
          options: {
            get diagnostics() {
              return diagnostics;
            },
            ...(served === null ? {} : { content: served }),
            ...(pointer === null ? {} : { ipns: pointer }),
          },
          ports: resolverPortsFor(store),
          cache,
          // The log's length is the registry's generation: every operation that could change an answer
          // this resolver has cached is an append, so a length that has not moved is a registry whose
          // answers cannot have changed.
          generation: () => store.length,
        });

  // HOSTING.md's first mitigation, said out loud. "One always-on node is the difference between a
  // site that loads and a site that does not", and this is precisely the state a publisher cannot
  // see from their own machine — from there the site always loads.
  if (site !== null) {
    const held = report(
      site.root,
      0,
      [{ holder: { kind: 'self' }, observedAt: clock() }],
      OBSERVATION_STALE_SECONDS,
      clock(),
    );
    out(`  holders   ${summarise(held)}`);
    if (onlyThisNodeHoldsIt(held)) {
      out('  Only this node is known to hold it. If it goes offline the site stops loading,');
      out('  and nothing here can tell you otherwise until a peer answers for it.');
    }
  }

  if (store.length === 0) {
    // Said plainly, because the alternative is an operator watching a resolver answer 503 to
    // everything and having to guess why. It is also the one place the read-once limitation
    // matters: registering a name in another terminal does not reach this process.
    out('');
    out('This log is empty, so every name answers 1502 — this resolver has no registry to');
    out('answer from. Register a name and restart: the log is read once, at startup.');
  }

  if (proxy !== null) out(`browsing proxy   http://${proxy.address}`);
  out(`control API      ${control.address}  (mode 0600)`);
  out('');
  out('control token (this run only, not written to disk):');
  out(`  ${token.current()}`);
  out('');
  out('Point a browser at the proxy. Ctrl-C to stop.');

  await new Promise<void>((resolve) => {
    const stop = (): void => {
      // The socket is removed on close. A resolver that leaves one behind makes the next start
      // fail on a path that looks like a running instance and is not.
      const closing = proxy === null ? [control.close()] : [proxy.close(), control.close()];
      void Promise.all(closing).then(() => resolve());
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  return 0;
}

const USAGE = `vayuweb-registry — local name registry (Phase 1: no network)

  keygen     --key <file> [--seed <hex>] [--force]
  register   --log <file> --key <file> --name <label.tld> [--cid <root>] [--ipns <key>]
             [--txt <s>] [--alias <n.tld>] [--peer <hex>] [--bits <n>] [--at <unix>]
  update     --log <file> --key <file> --name <label.tld> [--cid <root>] [--ipns <key>]
             [--txt <s>] [--alias <n.tld>] [--peer <hex>] [--clear <y>] [--at <unix>]
  renew      --log <file> --key <file> --name <label.tld> [--cid <root>] [--ipns <key>]
             [--txt <s>] [--alias <n.tld>] [--peer <hex>] [--clear <y>] [--bits <n>]
             [--at <unix>]
  transfer   --log <file> --key <file> --name <label.tld> --to <hex> --cosign <file>
             [--cid <root>] [--ipns <key>] [--txt <s>] [--alias <n.tld>] [--peer <hex>]
             [--clear <y>] [--at <unix>]
  release    --log <file> --key <file> --name <label.tld> [--at <unix>]
  revoke     --log <file> --key <file> --name <label.tld> [--at <unix>]
  resolve    --log <file> --name <label.tld> [--at <unix>]
  prove      --log <file> --name <label.tld> [--at <unix>]
  light-verify --proof <file> --claims <file> --name <label.tld> [--quorum <n>]
             [--at <unix>]
  list       --log <file> [--at <unix>]
  equivocations --log <file>
  difficulty --log <file> --name <label.tld> [--at <unix>]
  verify     --log <file> --record <file containing hex> [--at <unix>]
  vectors
  serve      --log <file> [--port <n>] [--socket <path>] [--site <dir>] [--pointer <ipns>]
  sync       --log <file> (--listen <port> [--address <ip>] | --connect <host:port>)

Flags are checked against the command that was typed, not against the tool as a whole, so
'register --site ./public' is refused rather than accepted and dropped. 'renew' and 'transfer'
carry the name's existing entries forward; naming any entry flag replaces them wholesale, and
'--clear y' empties them. 'update' always replaces, so it refuses to run with neither.

Exit codes: 0 accepted, 1 rejected or error, 2 deferred (clock skew), 3 not live.

--at pins the clock, so a result can be reproduced. ${RATIFIED_TLDS.size} extensions are
ratified, enumerated in docs/spec/NAMESPACE-CATALOGUE.md — the Namespace Annex. They are not
listed here: the list would bury every other line of this help, and a help text carrying the
namespace is one more copy that can drift from it.

\`serve\` binds a browsing proxy on 127.0.0.1 and a control API on a Unix domain socket with mode
0600. The control token is generated per run and printed once; it is never written to disk, so a
token in a backup or a screenshot is not a thing that can happen. No other command touches a
socket. Keys are files; back them up yourself.`;

/**
 * Turn anything thrown out of a command into the operator's exit code.
 *
 * Separate from `main` because it has to be reachable from two places: a synchronous `throw` and
 * a rejected promise. It used to exist only as the body of `main`'s catch, which meant `serve` —
 * the one command that returns a promise — had no error handling at all.
 */
function reportError(error: unknown): number {
  if (error instanceof UsageError) {
    err(`usage: ${error.message}`);
    return 1;
  }
  err(error instanceof Error ? error.message : String(error));
  return 1;
}

export function main(argv: readonly string[]): number | Promise<number> {
  const [command, ...rest] = argv;
  if (command === undefined || command === '--help' || command === 'help') {
    out(USAGE);
    return command === undefined ? 1 : 0;
  }

  try {
    const args = parseArgs(rest);
    assertKnownFlags(command, args);
    const result = dispatch(command, args);
    // `serve` and `sync` are asynchronous, so their refusals arrive as a rejection rather than as
    // a throw the block below can see. Routing both through the same reporter is what stops an
    // operator's first wrong invocation being answered with a stack trace.
    return typeof result === 'number' ? result : result.catch(reportError);
  } catch (error) {
    return reportError(error);
  }
}

/** The command table. Split out of `main` so that one `catch` covers both shapes of failure. */
function dispatch(command: string, args: Args): number | Promise<number> {
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
      return cmdSuccessor('RELINQUISH', args);
    case 'revoke':
      return cmdSuccessor('REVOKE', args);
    case 'resolve':
      return cmdResolve(args);
    case 'prove':
      return cmdProve(args);
    case 'light-verify':
      return cmdLightVerify(args);
    case 'equivocations':
      return cmdEquivocations(args);
    case 'list':
      return cmdList(args);
    case 'difficulty':
      return cmdDifficulty(args);
    case 'verify':
      return cmdVerify(args);
    case 'vectors':
      return cmdVectors();
    case 'serve':
      return cmdServe(args);
    case 'sync':
      return cmdSync(args);
    default:
      err(`unknown command: ${command}`);
      err('');
      err(USAGE);
      return 1;
  }
}
