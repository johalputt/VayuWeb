/**
 * The command-line tool, exercised through `main` rather than through its parts.
 *
 * Every defect these tests were written for was invisible to a unit test of any single function
 * involved: each function did what its own contract said, and the tool as a whole still lost what
 * the user typed. That is the level the bug lives at, so it is the level the test runs at.
 */
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  main,
  pinGated,
  pinPorts,
  pointerFor,
  resolverPortsFor,
  rotatingToken,
  siteFilesFor,
} from './cli.ts';
import { PinSet } from './pins.ts';
import { ResolutionCache } from './cache.ts';
import { contentCacheKey } from './proxy.ts';
import type { ContentPort } from './proxy.ts';
import { CID_PARAMETERS, cidBytes, encodeCid, sha256 } from './content.ts';
import { Store } from './store.ts';

/** A scratch directory that cleans itself up, so a failing test cannot leak into the next one. */
function scratch(): { dir: string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'vayuweb-cli-'));
  return { dir, done: () => rmSync(dir, { recursive: true, force: true }) };
}

/** Run `main`, capturing stdout and stderr instead of writing them to the test's output. */
function run(argv: string[]): { code: number; out: string; err: string } {
  const written: string[] = [];
  const errored: string[] = [];
  const stdout = process.stdout.write.bind(process.stdout);
  const stderr = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((chunk: string) => {
    written.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string) => {
    errored.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  try {
    const result = main(argv);
    assert.equal(
      typeof result,
      'number',
      '`serve` and `sync` are the async commands, and no test here runs one to completion',
    );
    return { code: result as number, out: written.join(''), err: errored.join('') };
  } finally {
    process.stdout.write = stdout;
    process.stderr.write = stderr;
  }
}

/**
 * A pinned clock. `--at` exists so a result can be reproduced, and a test is the first place that
 * matters: reading the real clock would make the record's term, and therefore whether `resolve`
 * finds it live, a function of when the suite happened to run.
 */
const NOW = 1_782_518_400;

const DIGEST = sha256(new TextEncoder().encode('atlas observatory'));
const CID_TEXT = encodeCid({ version: 1, codec: CID_PARAMETERS.codecDagPb, digest: DIGEST });

/** The name every test here registers. Sixteen characters sits at the four-bit floor. */
const NAME = 'atlasobservatory.vayu';

/**
 * One registered log, solved once and copied for each test that needs one.
 *
 * **Every solve here is a real Argon2id at 64 MiB**, which is the point — stubbing the solver would
 * take the register command's own ordering out of the test, and that ordering is half of what went
 * wrong. But four of them in one file put this file at 215 seconds locally and past the CI job's
 * timeout on a shared runner, which is a test suite that stops being run rather than a thorough one.
 *
 * A record is signed over its own content and not over the log it lands in, so registering once and
 * copying the log file is the same evidence as registering four times: the bytes were produced by
 * the CLI, through the solver, in the order the command performs. Each test still gets its own log
 * to mutate, so nothing here couples one test's outcome to another's.
 */
let solved: { key: string; log: string; dir: string } | null = null;

function registeredLog(into: string): { log: string; key: string } {
  if (solved === null) {
    const dir = mkdtempSync(join(tmpdir(), 'vayuweb-cli-fixture-'));
    const key = join(dir, 'key');
    const log = join(dir, 'log');
    assert.equal(run(['keygen', '--key', key]).code, 0);
    const registered = run([
      'register',
      '--log',
      log,
      '--key',
      key,
      '--name',
      NAME,
      '--cid',
      CID_TEXT,
      '--at',
      String(NOW),
    ]);
    assert.equal(registered.code, 0, registered.out + registered.err);
    solved = { key, log, dir };
  }
  const log = join(into, 'log');
  const key = join(into, 'key');
  copyFileSync(solved.log, log);
  copyFileSync(solved.key, key);
  return { log, key };
}

after(() => {
  if (solved !== null) rmSync(solved.dir, { recursive: true, force: true });
});

/* -------------------------------------------------------------------------- */
/* What you typed is what gets stored                                          */
/* -------------------------------------------------------------------------- */

test('AUDIT: --cid reaches the log as a binary CID entry, and resolve renders it back', () => {
  // Two defects met here and neither one showed on the way past.
  //
  // `entriesFrom` did not read `--cid` at all, so a name could be registered and could never be
  // pointed at content — and the tool printed "accepted REGISTER … 329 bytes" for a record with
  // no entries in it. Then, once it did read the flag, it stored the `bafy…` STRING in a field
  // REGISTRY.md types `bstr`, which the project's own parser rejected — but only after a full
  // proof-of-work solve had already been spent.
  //
  // So the assertion is not "the command exited 0". It is that the bytes on disk carry the CID
  // that was asked for, in the form the specification names.
  const { dir, done } = scratch();
  try {
    const key = join(dir, 'key');
    const log = join(dir, 'log');
    assert.equal(run(['keygen', '--key', key]).code, 0);

    // A sixteen-character label sits at the four-bit floor — the cheapest real proof this log
    // will accept. `store.test.ts` and `replicate.test.ts` solve at the same difficulty; the
    // alternative is stubbing the solver, which would take the register command's own ordering
    // out of the test and that ordering is half of what went wrong.
    const registered = run([
      'register',
      '--log',
      log,
      '--key',
      key,
      '--name',
      'atlasobservatory.vayu',
      '--cid',
      CID_TEXT,
      '--at',
      String(NOW),
    ]);
    assert.equal(registered.code, 0, registered.out + registered.err);

    const store = Store.open(log, NOW);
    const held = store.lookup('atlasobservatory', 'vayu');
    assert.ok(held, 'the name must be in the log');
    const entries = held.current.record.entries;
    assert.equal(entries.length, 1, 'exactly the one entry that was asked for');
    assert.equal(entries[0]!.type, 'cid');
    // The stored value is BYTES, and the specific bytes of the CID that was typed.
    assert.ok(entries[0]!.value instanceof Uint8Array, 'a cid entry is a bstr, not text');
    assert.deepEqual(
      entries[0]!.value,
      cidBytes({ version: 1, codec: CID_PARAMETERS.codecDagPb, digest: DIGEST }),
    );

    // And it renders back as the same string, so a person can compare what they typed by eye.
    const resolved = run([
      'resolve',
      '--log',
      log,
      '--name',
      'atlasobservatory.vayu',
      '--at',
      String(NOW),
    ]);
    assert.equal(resolved.code, 0);
    assert.match(resolved.out, new RegExp(`cid\\s+${CID_TEXT}`));
  } finally {
    done();
  }
});

test('a malformed --cid is refused before the proof of work, not after it', () => {
  // The refusal has to come from the flag, not from the record parser at the end of the pipeline:
  // a CID with one character mistyped otherwise costs a full solve to find out about, and the
  // error names a byte length rather than the thing that was wrong.
  const { dir, done } = scratch();
  try {
    const key = join(dir, 'key');
    const log = join(dir, 'log');
    run(['keygen', '--key', key]);
    for (const bad of [
      'Qmb1oCJTfQd3B5w9pTMPLLBJb5uCbBFCgNhLnMHNVJfEcm', // CIDv0, base58
      'bafybeibalvjmn2ktkdh3s4jjjfvgmw5n5kxoprohssdztz3kvr45v3lh', // truncated
      'not-a-cid',
      '',
    ]) {
      const result = run([
        'register',
        '--log',
        log,
        '--key',
        key,
        '--name',
        'atlasobservatory.vayu',
        '--cid',
        bad,
      ]);
      assert.equal(result.code, 1, `--cid ${bad} must be refused`);
      assert.match(result.err, /--cid/, 'the error must name the flag that was wrong');
      // The refusal came BEFORE the work, which is the half that costs the user something. If
      // the check had stayed inside the skeleton the solver builds, this line would already have
      // been printed and each case above would cost a full solve to reach.
      assert.doesNotMatch(result.err, /solving proof of work/);
      // Nothing was written either: the log does not exist yet.
      assert.throws(() => readFileSync(log), /ENOENT/, `--cid ${bad} must not reach the log`);
    }
  } finally {
    done();
  }
});

test('AUDIT: an unrecognised flag is refused, never silently dropped', () => {
  // `--cid` was accepted and ignored for as long as nothing read it, and the tool answered
  // "accepted" — a tool that discards what you typed and then reports success is a tool that
  // lies about what it did, and the cost of finding out is a name on a real log pointing nowhere.
  // Enumerating the flags is what turns "nothing read it" into an error instead of a shrug.
  const { dir, done } = scratch();
  try {
    const key = join(dir, 'key');
    run(['keygen', '--key', key]);
    const result = run([
      'register',
      '--log',
      join(dir, 'log'),
      '--key',
      key,
      '--name',
      'atlas.vayu',
      '--cidd',
      CID_TEXT,
    ]);
    assert.equal(result.code, 1);
    assert.match(result.err, /unknown flag --cidd/);
    // And it points at what was probably meant, because a rejection that leaves you guessing is
    // most of the way back to being ignored.
    assert.match(result.err, /--cid/);
  } finally {
    done();
  }
});

/** The flags each command's own usage line advertises, read out of the help the tool prints. */
function advertisedPerCommand(help: string): Map<string, Set<string>> {
  const lines = help.split('\n');
  const perCommand = new Map<string, Set<string>>();
  let current: Set<string> | null = null;
  for (const line of lines) {
    const start = /^ {2}([a-z]+)(?: |$)/.exec(line);
    if (start !== null) {
      current = new Set<string>();
      perCommand.set(start[1]!, current);
    } else if (!/^ {6,}\S/.test(line)) {
      // Anything that is neither a command line nor an indented continuation ends the block, so
      // the prose below the table cannot leak flags into the last command's set.
      current = null;
      continue;
    }
    if (current === null) continue;
    for (const match of line.matchAll(/--([a-z][a-z0-9-]*)/g)) current.add(match[1]!);
  }
  return perCommand;
}

/** Commands that open a listener instead of returning, and so are never run here. */
const BINDS = new Set(['serve', 'sync']);

test('AUDIT: each command accepts exactly the flags its own usage line advertises', () => {
  // **The first version of this test pinned the defect it was written to prevent.**
  //
  // `KNOWN_FLAGS` was one global union checked before the command was even known, so it answered
  // "does any command read this?" when the question is "does THIS command read it?" — and the test
  // fed all fourteen advertised flags to `resolve` and asserted none was refused, which is the
  // buggy behaviour stated as a requirement.
  //
  // The cost is not hypothetical. `register --site ./public`, a natural mistake now that
  // `serve --site` exists, was accepted, spent a full Argon2id solve, and wrote a record with no
  // entries in it — the same 329-byte empty record the enumeration was added to make impossible.
  //
  // So the test now runs in both directions, per command: everything a usage line advertises must
  // be accepted by that command, and every flag it does not advertise must be refused by name.
  const help = run(['--help']);
  assert.equal(help.code, 0);
  const perCommand = advertisedPerCommand(help.out);
  assert.ok(perCommand.size >= 13, `the help must list the commands; found ${perCommand.size}`);

  const everyFlag = new Set([...perCommand.values()].flatMap((s) => [...s]));
  assert.ok(everyFlag.size > 10, 'the help text must actually advertise flags');

  const { dir, done } = scratch();
  try {
    const key = join(dir, 'key');
    run(['keygen', '--key', key]);
    // Every value points inside the scratch directory, so a run that gets past the flag check
    // and reaches a command cannot write anything outside it.
    const value = join(dir, 'x');
    for (const [command, advertised] of perCommand) {
      // `serve` and `sync` are the commands that would BIND rather than return, so they are
      // exercised only in the refusing direction — which is safe, because the flag check runs
      // before the dispatch. Named rather than detected: there is no marker for "this one listens",
      // and a test that guessed would start a listener the first time somebody added a third.
      if (!BINDS.has(command)) {
        for (const flag of advertised) {
          const accepted = run([command, `--${flag}`, value]);
          assert.doesNotMatch(
            accepted.err,
            /unknown flag|is not a flag of/,
            `${command} advertises --${flag} and refuses it`,
          );
        }
      }
      // And the other direction, which is the half that was missing. `keygen` and `vectors` touch
      // no log, so a flag from another verb reaching them is the same silent drop.
      for (const flag of everyFlag) {
        if (advertised.has(flag)) continue;
        const refused = run([command, `--${flag}`, value]);
        assert.match(
          refused.err,
          new RegExp(`--${flag} is not a flag of ${command}`),
          `${command} accepts --${flag}, which it does not read`,
        );
      }
    }
  } finally {
    done();
  }
});

/* -------------------------------------------------------------------------- */
/* What `serve --site` puts into a public, immutable CID                       */
/* -------------------------------------------------------------------------- */

test('AUDIT: publishing a directory does not sweep .git or dotfiles into the CID', () => {
  // **HOSTING.md warns about exactly this hazard and the new publish path walked straight past
  // it.** Its package rules say filenames "MUST NOT contain … a leading `.` for any file intended
  // to be served", and that "Symbolic links MUST NOT be followed; a publisher SHALL either
  // dereference them at build time or refuse the import, since a followed link can silently pull
  // a private key into a public CID."
  //
  // `siteContentOf` enforced none of it. Measured before this test: publishing an ordinary working
  // directory collected `.env` and `.git/config` and imported both into the root CID — content
  // addressed, immutable, and fetchable by anyone holding the CID. A git config can carry a
  // credential in a remote URL. The specification names the consequence precisely for the
  // neighbouring case; it just did not anticipate the door it came through.
  const { dir, done } = scratch();
  try {
    const site = join(dir, 'site');
    mkdirSync(join(site, '.git'), { recursive: true });
    mkdirSync(join(site, 'assets'), { recursive: true });
    writeFileSync(join(site, 'index.html'), '<h1>real</h1>');
    writeFileSync(join(site, 'assets', 'style.css'), 'h1{color:red}');
    writeFileSync(join(site, '.env'), 'SECRET=abc123');
    writeFileSync(join(site, '.git', 'config'), '[remote]\n  url = https://token@example.com/r');

    const collected = siteFilesFor(site).map((f: { path: string }) => f.path);
    assert.deepEqual([...collected].sort(), ['assets/style.css', 'index.html']);
    // Named individually so a failure says which rule broke rather than only that the set differs.
    assert.equal(collected.includes('.env'), false, 'a dotfile must not reach the CID');
    assert.equal(
      collected.includes('.git/config'),
      false,
      'a dot-directory must not reach the CID',
    );

    // `.vayu` is the one dot-entry that belongs: HOSTING.md puts the manifest there, and it is
    // metadata rather than something served. Excluding it would break the manifest instead.
    mkdirSync(join(site, '.vayu'), { recursive: true });
    writeFileSync(join(site, '.vayu', 'manifest.json'), '{"version":1}');
    const withManifest = siteFilesFor(site).map((f: { path: string }) => f.path);
    assert.ok(withManifest.includes('.vayu/manifest.json'), 'the manifest is not build state');
  } finally {
    done();
  }
});

test('a symbolic link refuses the publish rather than vanishing from it', () => {
  // The link was already skipped before this change — but by accident, not by rule: `Dirent`
  // methods are lstat-shaped, so a link is neither a file nor a directory and fell out of both
  // branches. That is the safe direction and it is still not what HOSTING.md asks for. Silently
  // omitting a file is neither "dereference" nor "refuse": the site publishes with a hole in it
  // and the publisher is never told, which is a worse outcome than a refusal they can act on.
  const { dir, done } = scratch();
  try {
    const site = join(dir, 'site');
    mkdirSync(site, { recursive: true });
    writeFileSync(join(site, 'index.html'), '<h1>real</h1>');
    const secret = join(dir, 'outside.txt');
    writeFileSync(secret, 'PRIVATE KEY MATERIAL');
    symlinkSync(secret, join(site, 'linked.txt'));

    assert.throws(() => siteFilesFor(site), /linked\.txt is a symbolic link/);
    // And the refusal explains itself, because "refused" without a reason is a bug report.
    assert.throws(() => siteFilesFor(site), /private key into a public CID/);
  } finally {
    done();
  }
});

/* -------------------------------------------------------------------------- */
/* What a successor record does to the entries you already had                 */
/* -------------------------------------------------------------------------- */

test('AUDIT: renewing a name does not take it down', () => {
  // **Measured before the fix: a live name resolved to its CID, `renew` reported
  // `accepted RENEW … seq 1`, and the name then resolved to nothing.**
  //
  // `records` was hardcoded to `[]` for every operation but `UPDATE`. REGISTRY.md is explicit that
  // `records` "is replaced wholesale; there is no partial update", so an empty array is not
  // "unchanged" — it is "deleted". The signed record was valid, the log was correct, the exit code
  // was 0, and the site was unreachable until somebody noticed and ran `update`. `transfer` did
  // the same thing to the person receiving the name.
  //
  // Nothing was wrong at any single layer, which is why this test drives the tool rather than
  // `cmdSuccessor`: the record builder did what it was told and what it was told was the defect.
  const { dir, done } = scratch();
  try {
    const { log, key } = registeredLog(dir);

    // Inside the renewal window, which opens 60 days before a one-year term expires — 305 days in,
    // so 320 is comfortably inside it and comfortably past the 300-second minimum interval.
    // Nothing about the entries is mentioned, because a person renewing a name is not saying
    // anything about its contents.
    const later = NOW + 320 * 24 * 3600;
    const renewed = run([
      'renew',
      '--log',
      log,
      '--key',
      key,
      '--name',
      'atlasobservatory.vayu',
      '--at',
      String(later),
    ]);
    assert.equal(renewed.code, 0, renewed.out + renewed.err);

    const store = Store.open(log, later);
    const held = store.lookup('atlasobservatory', 'vayu');
    assert.ok(held, 'the name must still be in the log');
    assert.equal(held.current.record.op, 'RENEW');
    const entries = held.current.record.entries;
    assert.equal(entries.length, 1, 'the renewal must not have emptied the name');
    assert.equal(entries[0]!.type, 'cid');
    assert.deepEqual(
      entries[0]!.value,
      cidBytes({ version: 1, codec: CID_PARAMETERS.codecDagPb, digest: DIGEST }),
    );

    // And the name still answers, which is the thing the owner actually cares about.
    const resolved = run([
      'resolve',
      '--log',
      log,
      '--name',
      'atlasobservatory.vayu',
      '--at',
      String(later),
    ]);
    assert.equal(resolved.code, 0);
    assert.match(resolved.out, new RegExp(`cid\\s+${CID_TEXT}`));
    assert.doesNotMatch(resolved.out, /\(none\)/, 'a renewed name must not resolve to nothing');
  } finally {
    done();
  }
});

test('update refuses to guess when no entry is named, rather than emptying the name', () => {
  // `update` genuinely does replace wholesale, so it is the one command where an empty flag set is
  // ambiguous between "I forgot" and "remove them all". Carrying entries forward here would make
  // the command unable to express the second; emptying them silently is the defect above wearing
  // the right verb. It refuses, and names the way to mean it.
  const { dir, done } = scratch();
  try {
    const { log, key } = registeredLog(dir);

    const bare = run([
      'update',
      '--log',
      log,
      '--key',
      key,
      '--name',
      'atlasobservatory.vayu',
      '--at',
      String(NOW + 400),
    ]);
    assert.equal(bare.code, 1);
    assert.match(bare.err, /--clear/, 'the refusal must name the way to mean the empty set');

    // The entries are untouched by a refusal, or "refuses" is doing the damage it refused to do.
    const afterRefusal = Store.open(log, NOW + 400).lookup('atlasobservatory', 'vayu');
    assert.equal(afterRefusal?.current.record.entries.length, 1);

    // And --clear still empties them, said out loud.
    const cleared = run([
      'update',
      '--log',
      log,
      '--key',
      key,
      '--name',
      'atlasobservatory.vayu',
      '--clear',
      'y',
      '--at',
      String(NOW + 400),
    ]);
    assert.equal(cleared.code, 0, cleared.out + cleared.err);
    const held = Store.open(log, NOW + 400).lookup('atlasobservatory', 'vayu');
    assert.equal(held?.current.record.entries.length, 0);
  } finally {
    done();
  }
});

/* -------------------------------------------------------------------------- */
/* `serve --pointer` — a local declaration, not a network resolution           */
/* -------------------------------------------------------------------------- */

test('a declared pointer answers for itself and for nothing else', () => {
  // The interesting lie this could tell: return the published root for whatever pointer it is
  // asked about. A resolver that serves whatever it has to whatever it is asked for is not a
  // resolver, and every name pointing anywhere would render this operator's site. The flag says
  // "the record I am testing carries THIS pointer"; one mapping, not a wildcard.
  const port = pointerFor('k51qzi5uqu5dtestpointer', 'bafyrootcid');
  assert.ok(port);
  assert.equal(port.resolve('k51qzi5uqu5dtestpointer'), 'bafyrootcid');
  assert.equal(port.resolve('k51qzi5uqu5dsomeoneelse'), null, 'and null is 1505, which is true');
  assert.equal(port.resolve(''), null);
});

test('no --pointer means no resolver at all, rather than one that answers nothing', () => {
  // The distinction is visible at the proxy: an absent port and a port that always returns null
  // produce the same code, but only the absent one leaves `options.ipns` undefined, which is what
  // says "this resolver has no pointer resolution" rather than "this pointer did not resolve".
  assert.equal(pointerFor(undefined, 'bafyrootcid'), null);
});

test('--pointer without --site is refused, not quietly ignored', () => {
  // It names what `--site` publishes. Without one there is nothing for it to mean, and a flag
  // accepted and dropped is how an operator ends up debugging a pointer that was never wired.
  assert.throws(() => pointerFor('k51qzi5uqu5dtestpointer', null), /needs --site/);
});

/* -------------------------------------------------------------------------- */
/* Step 7 — the port that told every visitor a lie                            */
/* -------------------------------------------------------------------------- */

test('a resolver with an empty log has no verified head, whatever it used to claim', async () => {
  // This is where the defect lived: an object literal inside `cmdServe` saying
  // `hasVerifiedHead: () => true`, which no test could reach because reaching it meant binding two
  // sockets. Every name answered 1404 — a claim about the global namespace from an empty file.
  const { Store } = await import('./store.ts');
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-ports-'));
  const log = join(directory, 'log');

  const empty = Store.open(log, NOW);
  assert.equal(empty.length, 0);
  assert.equal(resolverPortsFor(empty).hasVerifiedHead(), false, 'nothing seen is nothing known');

  // And once it holds a record — which `Store.open` re-verifies on every load — it has one.
  assert.equal(main(['keygen', '--key', join(directory, 'key')]), 0);
  assert.equal(
    main([
      'register',
      '--log',
      log,
      '--key',
      join(directory, 'key'),
      '--name',
      'atlasobservatory.vayu',
    ]),
    0,
  );
  const populated = Store.open(log, NOW);
  assert.ok(populated.length > 0);
  assert.equal(resolverPortsFor(populated).hasVerifiedHead(), true);
  assert.ok(resolverPortsFor(populated).lookup('atlasobservatory', 'vayu'));
  rmSync(directory, { recursive: true, force: true });
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the interface that offers unpublishing says nothing about its limits  */
/* -------------------------------------------------------------------------- */

test('AUDIT: release, revoke and update --clear stated none of Article 19.7', () => {
  // Article 19.8 is a MUST and it is specific about WHERE: implementations "MUST state the
  // distinction in clause 19.7 at the point where unpublishing is offered, **in the interface
  // itself rather than only in a manual**". PUBLISHING.md 4 says the same thing in the same
  // words — "at the moment of unpublishing rather than in documentation nobody reads".
  //
  // `UNPUBLISH_EFFECTS` exists for exactly this. Its own comment says the two lists are data
  // rather than prose "so that a user interface has to render both or deliberately drop one".
  // Nothing that ships imported it. The three commands that unpublish — `release` (RELINQUISH),
  // `revoke` (REVOKE) and `update --clear` (breaking the binding) — each printed an
  // acceptance line and stopped, which is an interface implying the erasure 19.7 forbids
  // implying, by saying nothing at the one moment the Article names.
  const { dir, done } = scratch();
  try {
    for (const argv of [['release'], ['revoke'], ['update', '--clear', 'y']]) {
      const { log, key } = registeredLog(mkdtempSync(join(dir, 'case-')));
      const result = run([
        argv[0] as string,
        '--log',
        log,
        '--key',
        key,
        '--name',
        NAME,
        ...argv.slice(1),
        '--at',
        // Past the 300s minimum between a record and its predecessor, or the append is refused
        // and the assertions below would be about a rejection rather than about the interface.
        String(NOW + 400),
      ]);
      const said = `${result.out}\n${result.err}`;
      assert.equal(result.code, 0, said);
      // The distinction itself: cessation of authorised publication, not erasure.
      assert.match(said, /append-only|removes nothing/i, `${argv[0]}: 19.6.a`);
      assert.match(said, /re-pinned|already (retrieved|hold)/i, `${argv[0]}: 19.6.b`);
      assert.match(
        said,
        /cannot compel|will not pretend|no protocol mechanism/i,
        `${argv[0]}: 19.6.c`,
      );
      // And it must not be the only half rendered: the guaranteed acts belong there too, or the
      // interface reads as a warning rather than as what the operator just did.
      assert.match(said, /stop serving/i, `${argv[0]}: 19.2`);
      // 19.9's conformance test, applied to this interface's own strings.
      assert.doesNotMatch(said, /right to be forgotten/i, `${argv[0]}: 19.8`);
      assert.doesNotMatch(said, /permanently deleted|erased everywhere|gone for good/i, argv[0]);
    }
  } finally {
    done();
  }
});

test('an ordinary update or renew is not an unpublishing, and does not say it is', () => {
  // The negative half, and it is not decoration: a rule that fired on every successor would put
  // Article 19's limits under a routine republish, where they are false and would be read as
  // noise. The statement has to be rare enough to mean something at the moment it appears.
  const { dir, done } = scratch();
  try {
    const { log, key } = registeredLog(dir);
    const updated = run([
      'update',
      '--log',
      log,
      '--key',
      key,
      '--name',
      NAME,
      '--cid',
      CID_TEXT,
      '--at',
      String(NOW + 400),
    ]);
    assert.equal(updated.code, 0, updated.out + updated.err);
    const said = `${updated.out}\n${updated.err}`;
    assert.doesNotMatch(said, /Article 19/i, 'a republish is not an unpublishing');
    assert.doesNotMatch(said, /append-only/i);
  } finally {
    done();
  }
});

test('MUTATION: a refused unpublishing says nothing about Article 19, because nothing happened', () => {
  // Dropping the `code === 0` guard survived the whole suite: every test above appends
  // successfully, so nothing looked at what a REFUSED unpublishing prints. Without the guard it
  // prints `RELINQUISH accepted. Article 19.7: …` after a rejection — telling an operator their
  // name is relinquished when the log was never written to. A tool that reports an act it did not
  // perform is the defect this whole file was written for.
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    // A key that holds nothing, so the append is refused rather than accepted.
    const stranger = join(dir, 'stranger');
    assert.equal(run(['keygen', '--key', stranger]).code, 0);
    const refused = run([
      'release',
      '--log',
      log,
      '--key',
      stranger,
      '--name',
      NAME,
      '--at',
      String(NOW + 400),
    ]);
    assert.notEqual(refused.code, 0, 'the fixture must actually be refused');
    const said = `${refused.out}\n${refused.err}`;
    assert.doesNotMatch(said, /Article 19/i, 'a refusal is not an unpublishing');
    assert.doesNotMatch(said, /accepted/i);
  } finally {
    done();
  }
});

test('AUDIT: the version the control API discloses was two releases behind the package', () => {
  // `RESOLVER_VERSION` is a literal, and its comment gives the reason — the package manifest "is
  // not present in every way this is run, and a version string that sometimes reads `unknown` is a
  // worse answer than one that is simply kept in step with the release commit". The reasoning is
  // sound and the second half did not happen: the package went to 0.2.1 and the literal stayed at
  // 0.1.0, so `GET /v1/status` named a build that shipped two releases ago.
  //
  // That is worse than having no version field. The field is disclosed only past the token check,
  // on the stated grounds that a version string is a fingerprint and a vulnerability-matching aid
  // — so its entire purpose is to identify the build, and an operator matching a bug report
  // against 0.1.0 reads code that is not running.
  //
  // Kept as a literal and pinned by this test rather than read at runtime: the manifest is always
  // present HERE, which is where "kept in step" needed something keeping it.
  const manifest = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  ) as { version: string };
  const source = readFileSync(new URL('./cli.ts', import.meta.url), 'utf8');
  const declared = /const RESOLVER_VERSION = '([^']+)'/.exec(source);
  assert.ok(declared, 'RESOLVER_VERSION must be a plain literal this check can read');
  assert.equal(
    declared[1],
    manifest.version,
    'the disclosed version must equal the package version; bump both in the release commit',
  );
});

/* -------------------------------------------------------------------------- */
/* The light client, which had every part except a way to run it              */
/* -------------------------------------------------------------------------- */

/**
 * Prove a name; return the document and, separately, the root the prover claims.
 *
 * They come back on different streams because `prove` puts them on different streams: the document
 * on stdout, the root on stderr next to the sentence saying a light client must get it from peers
 * instead. Keeping them apart here is not tidiness — a test that read both out of one blob would
 * be modelling exactly the shortcut the command refuses to offer.
 */
function proveName(
  log: string,
  name = NAME,
): { document: Record<string, unknown>; claimedRoot: string } {
  const proved = run(['prove', '--log', log, '--name', name, '--at', String(NOW)]);
  assert.equal(proved.code, 0, proved.out + proved.err);
  const root = /tree root at length \d+: ([0-9a-f]{64})/.exec(proved.err);
  assert.ok(root, `prove must state the root it computed: ${proved.err}`);
  return {
    document: JSON.parse(proved.out) as Record<string, unknown>,
    claimedRoot: root[1] as string,
  };
}

/** Write peer claims — what checkpoint gossip hands a light client — to a file. */
function claimsFile(dir: string, claims: Array<{ logLength: number; treeRoot: string }>): string {
  const path = join(dir, `claims-${claims.length}-${claims[0]?.logLength ?? 0}.json`);
  writeFileSync(path, JSON.stringify(claims));
  return path;
}

test('a name is proved and then verified without the log that proved it', () => {
  // REGISTRY.md's light-client procedure: obtain a length and root from peers, check an inclusion
  // proof against that root, verify the record chain. Every piece existed — `proveInclusion`,
  // `verifyNameInclusion`, `greatestCorroboratedLength` — and no command could run any of them,
  // so the procedure the specification describes was not something this tool could do.
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document, claimedRoot: root } = proveName(log);
    const proofPath = join(dir, 'proof.json');
    writeFileSync(proofPath, JSON.stringify(document));
    const claims = claimsFile(dir, [
      { logLength: 1, treeRoot: root },
      { logLength: 1, treeRoot: root },
    ]);
    const verified = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      claims,
      '--at',
      String(NOW),
    ]);
    assert.equal(verified.code, 0, verified.out + verified.err);
    assert.match(verified.out, /verified/i);
    assert.match(verified.out, /corroborated by 2 peers/i);
    // REGISTRY.md: "show that length and the observation time with every answer", and nothing here
    // proves the length is current.
    assert.match(verified.out, /freshness/i);
    assert.match(verified.out, /log length 1/i);
  } finally {
    done();
  }
});

test('the proof document carries no root, so it cannot verify itself', () => {
  // `Proof`'s own comment says a proof that carried its own leaf "would let a peer prove inclusion
  // of something the light client never asked about". A proof carrying the root it is checked
  // against is the same defect one level up: the peer supplying the evidence would also be
  // supplying the standard it is judged by. The root must come from the claims.
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document } = proveName(log);
    assert.equal(document['treeRoot'], undefined, 'a proof must not carry its own root');
    assert.equal(typeof document['logLength'], 'number');
    assert.equal(typeof document['record'], 'string');
  } finally {
    done();
  }
});

test('a tampered record does not verify against an honest root', () => {
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document, claimedRoot: root } = proveName(log);
    const record = document['record'] as string;
    // Flip one nibble of the record the proof is about.
    document['record'] = `${record.slice(0, -1)}${record.endsWith('0') ? '1' : '0'}`;
    const proofPath = join(dir, 'tampered.json');
    writeFileSync(proofPath, JSON.stringify(document));
    const claims = claimsFile(dir, [
      { logLength: 1, treeRoot: root },
      { logLength: 1, treeRoot: root },
    ]);
    const verified = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      claims,
      '--at',
      String(NOW),
    ]);
    assert.notEqual(verified.code, 0);
    assert.match(`${verified.out}${verified.err}`, /does not check out|not verified/i);
  } finally {
    done();
  }
});

test('one peer is not corroboration, and the answer says which it had', () => {
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document, claimedRoot: root } = proveName(log);
    const proofPath = join(dir, 'proof.json');
    writeFileSync(proofPath, JSON.stringify(document));
    const single = claimsFile(dir, [{ logLength: 1, treeRoot: root }]);

    // Default quorum is 2, so one claim corroborates nothing and there is no length to trust.
    const refused = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      single,
      '--at',
      String(NOW),
    ]);
    assert.notEqual(refused.code, 0);
    assert.match(`${refused.out}${refused.err}`, /corroborat/i);

    // Asked for explicitly, a single peer verifies — and says a withholding peer is undetectable.
    const accepted = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      single,
      '--quorum',
      '1',
      '--at',
      String(NOW),
    ]);
    assert.equal(accepted.code, 0, accepted.out + accepted.err);
    assert.match(accepted.out, /single peer|undetectable/i);
  } finally {
    done();
  }
});

test('peers disagreeing about the root at one length is a fork, and neither is chosen', () => {
  // REPLICATION.md 7.3: surface a fork and MUST NOT pick one. A light client that took the first
  // root, or the majority root, would be choosing — and the whole reason forks are surfaced rather
  // than resolved is that this side has no evidence with which to choose.
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document, claimedRoot: root } = proveName(log);
    const proofPath = join(dir, 'proof.json');
    writeFileSync(proofPath, JSON.stringify(document));
    const forked = claimsFile(dir, [
      { logLength: 1, treeRoot: root },
      { logLength: 1, treeRoot: 'ff'.repeat(32) },
    ]);
    const answered = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      forked,
      '--at',
      String(NOW),
    ]);
    assert.notEqual(answered.code, 0);
    const said = `${answered.out}${answered.err}`;
    assert.match(said, /fork/i);
    assert.doesNotMatch(said, /verified: true/i, 'a fork must not resolve to an answer');
  } finally {
    done();
  }
});

test('MUTATION: a proof document that carries its own root is refused, not ignored', () => {
  // The test above checks that `prove` does not EMIT a root. That is the easy half, and removing
  // the refusal in `light-verify` survived the whole suite because of it — nothing ever handed the
  // verifier a rooted document. The refusal is the half that matters: `prove` is friendly, and the
  // document a light client actually receives comes from a peer who is not.
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document, claimedRoot: root } = proveName(log);
    document['treeRoot'] = root;
    const proofPath = join(dir, 'self-rooted.json');
    writeFileSync(proofPath, JSON.stringify(document));
    const claims = claimsFile(dir, [
      { logLength: 1, treeRoot: root },
      { logLength: 1, treeRoot: root },
    ]);
    const answered = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      claims,
      '--at',
      String(NOW),
    ]);
    // Refused even though the root it carries is the CORRECT one — the objection is to the shape,
    // not to the value. A verifier that accepted a correct self-supplied root would accept an
    // incorrect one by the same code path.
    assert.notEqual(answered.code, 0);
    assert.match(`${answered.out}${answered.err}`, /self-consistent|carries a treeRoot/i);
  } finally {
    done();
  }
});

test('MUTATION: a proof built at one length is refused against another, and says which', () => {
  // The peaks in a proof are the peaks at the length it was built for, so checking it against a
  // different length's root can only fail — obscurely, as an inclusion mismatch, which reads like
  // a forged record rather than a mismatched request.
  //
  // This test also pins the guard that makes the call below it correct: with it, the corroborated
  // length and the proof's own length are equal by the time `verifyNameInclusion` is reached, so
  // swapping one for the other there is a NO-OP mutation rather than an untested branch. Deleting
  // the guard is the mutation that matters, and this is what fails when it goes.
  const { dir, done } = scratch();
  try {
    const { log } = registeredLog(dir);
    const { document, claimedRoot: root } = proveName(log);
    assert.equal(document['logLength'], 1, 'the fixture log holds one record');
    const proofPath = join(dir, 'proof.json');
    writeFileSync(proofPath, JSON.stringify(document));
    // Two peers agreeing on a LONGER log than the proof was built for.
    const ahead = claimsFile(dir, [
      { logLength: 2, treeRoot: root },
      { logLength: 2, treeRoot: root },
    ]);
    const answered = run([
      'light-verify',
      '--proof',
      proofPath,
      '--name',
      NAME,
      '--claims',
      ahead,
      '--at',
      String(NOW),
    ]);
    assert.notEqual(answered.code, 0);
    const said = `${answered.out}${answered.err}`;
    assert.match(said, /log length 1/i, 'it must name the length the proof is for');
    assert.match(said, /2 is what peers/i, 'and the length the peers corroborate');
    assert.doesNotMatch(said, /does not check out/i, 'not reported as a bad proof');
  } finally {
    done();
  }
});

test('unpinning stops the proxy serving the site, which is what a local unpin means', () => {
  // Article 19.2's second guaranteed act is "unpin it locally". An unpin that left the proxy
  // handing out the same bytes would be the interface saying one thing and the socket doing
  // another — and until this gate existed, `DELETE /v1/pin/{cid}` would have been exactly that.
  const CID = 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e';
  const inner: ContentPort = {
    fetch: () => ({
      ok: true,
      bytes: new TextEncoder().encode('the app shell'),
      contentType: 'text/html',
    }),
  };
  const pinned = new PinSet(() => true);
  const gated = pinGated(inner, pinned);

  pinned.add(CID);
  const served = gated.fetch({ type: 'cid', value: CID }, '/index.html');
  assert.equal(served.ok, true, 'a pinned root is served');

  pinned.remove(CID);
  const refused = gated.fetch({ type: 'cid', value: CID }, '/index.html');
  assert.equal(refused.ok, false);
  assert.equal(refused.ok === false && refused.error, 'CONTENT_UNAVAILABLE');

  // And a CID that was never pinned is refused without ever reaching the inner port.
  const other = gated.fetch({ type: 'cid', value: 'bafkreiotherotherotherother' }, '/');
  assert.equal(other.ok, false);
});

test('MUTATION: the shipping token holder really replaces the value, and issues a fresh one', () => {
  // The rotation policy is exercised through a double at the `serve.ts` level — the old token
  // stops working, the new one starts. What a double cannot show is whether the holder that
  // actually ships replaces anything, and "declared and never assigned" is exactly the defect a
  // double hides. Asserted here on the real one.
  const token = rotatingToken();
  const first = token.current();
  assert.equal(Buffer.from(first, 'base64url').length, 32, 'a full-length token to begin with');

  const second = token.rotate();
  assert.notEqual(second, first, 'a rotation that returns the same value has rotated nothing');
  assert.equal(token.current(), second, 'and `current` must answer with the NEW one');
  assert.equal(Buffer.from(second, 'base64url').length, 32);

  // Fresh randomness rather than a counter or a derivation: a token predictable from its
  // predecessor is a token the holder of the predecessor still has.
  const seen = new Set([first, second]);
  for (let i = 0; i < 8; i += 1) seen.add(token.rotate());
  assert.equal(seen.size, 10, 'every rotation issues a distinct token');
});

test('AUDIT: re-pinning brought the site back in the pin set but not on the wire', () => {
  // Found by running a real resolver rather than by testing one. Unpin, request, re-pin, request:
  // the second request still failed. `DELETE /v1/pin/{cid}` takes effect instantly because it
  // CREATES the failure; `POST /v1/pin` did not, because the failure it should undo is negatively
  // cached against the content source for ten seconds. The operator sees `200 {"outcome":"pinned"}`
  // and a site that is still down, with nothing to explain the difference.
  //
  // The asymmetry is the tell, and the codebase already had the argument: `setGeneration` exists
  // because "a log that has not grown is a registry whose answers cannot have changed". The pin set
  // is another thing that changes answers, and nothing invalidated on it.
  const CID = 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e';
  const cache = new ResolutionCache({});
  const pinned = new PinSet(() => true);
  const ports = pinPorts(pinned, cache);

  // A reader has already been told this content is unavailable, and that answer is cached.
  cache.putNegative(contentCacheKey('cid', CID), 'CONTENT_UNAVAILABLE', 1);
  assert.equal(cache.negative(contentCacheKey('cid', CID), 1), 'CONTENT_UNAVAILABLE');

  assert.equal(ports.pin(CID), 'pinned');
  assert.equal(
    cache.negative(contentCacheKey('cid', CID), 1),
    null,
    'pinning must drop the cached failure it exists to undo',
  );

  // And unpinning drops any POSITIVE answer for the same reason, in the other direction: a reader
  // must not keep being served from a snapshot this node has stopped undertaking to serve.
  cache.putNegative(contentCacheKey('cid', CID), 'CONTENT_UNAVAILABLE', 1);
  assert.equal(ports.unpin(CID), true);
  assert.equal(cache.negative(contentCacheKey('cid', CID), 1), null);
});

test('MUTATION: a REFUSED pin flushes nothing, because it has undone nothing', () => {
  // `pinPorts` says "a refused pin has undone nothing and must not flush an answer that is still
  // true", and nothing tested it — making the guard flush unconditionally survived the suite.
  // It matters in the direction that is easy to miss: a caller who cannot pin a CID could
  // otherwise use `POST /v1/pin` as an unauthenticated-shaped cache flush for any content source
  // they can name, one 409 at a time.
  const CID = 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e';
  const cache = new ResolutionCache({});
  const ports = pinPorts(new PinSet(() => false), cache);

  cache.putNegative(contentCacheKey('cid', CID), 'CONTENT_UNAVAILABLE', 1);
  assert.equal(ports.pin(CID), 'not_held', 'the node does not hold it, so the pin is refused');
  assert.equal(
    cache.negative(contentCacheKey('cid', CID), 1),
    'CONTENT_UNAVAILABLE',
    'a refused pin must leave a cached answer that is still true exactly where it was',
  );

  // Unpinning something that was not pinned is the same story from the other side.
  assert.equal(ports.unpin(CID), false);
  assert.equal(cache.negative(contentCacheKey('cid', CID), 1), 'CONTENT_UNAVAILABLE');
});
