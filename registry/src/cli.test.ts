/**
 * The command-line tool, exercised through `main` rather than through its parts.
 *
 * Every defect these tests were written for was invisible to a unit test of any single function
 * involved: each function did what its own contract said, and the tool as a whole still lost what
 * the user typed. That is the level the bug lives at, so it is the level the test runs at.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { main, siteFilesFor } from './cli.ts';
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
    assert.equal(typeof result, 'number', 'only `serve` is async, and no test here runs it');
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

test('every flag the help text advertises is one the tool will accept', () => {
  // The two lists drift in opposite directions and both directions are bugs: a flag in the help
  // and not in the allow list is refused with "unknown flag" after being documented, and one in
  // the allow list and not in the help is undiscoverable. Read the help the tool prints rather
  // than a copy of it.
  const help = run(['--help']);
  assert.equal(help.code, 0);
  const advertised = new Set(
    [...help.out.matchAll(/--([a-z][a-z0-9-]*)/g)].map((m) => m[1]!).filter((f) => f !== 'help'),
  );
  assert.ok(advertised.size > 5, 'the help text must actually advertise flags');

  const { dir, done } = scratch();
  try {
    const key = join(dir, 'key');
    run(['keygen', '--key', key]);
    for (const flag of advertised) {
      const result = run(['resolve', '--log', join(dir, 'log'), `--${flag}`, 'x']);
      assert.doesNotMatch(
        result.err,
        /unknown flag/,
        `--${flag} is in the help text but not in KNOWN_FLAGS`,
      );
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
