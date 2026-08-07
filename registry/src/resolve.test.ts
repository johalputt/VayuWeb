import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  parseHost,
  selectSource,
  resolveName,
  mapPath,
  RESOLVE_ERRORS,
  ALIAS_BUDGET,
  SOURCE_ORDER,
  type ResolverPorts,
  type Outcome,
} from './resolve.ts';
import { parseRecord, type RegistryRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import { type CborMap, type CborValue } from './cbor.ts';

const NOW = 1_782_518_400;
const TERM = 31_536_000;

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

function rec(
  name: string,
  entries: CborValue[],
  over: Record<string, CborValue> = {},
): RegistryRecord {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['suite', 1],
    ['op', 'REGISTER'],
    ['name', name],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(0x11)],
    ['seq', 0],
    ['notBefore', NOW],
    ['notAfter', NOW + TERM],
    ['records', entries],
    ['powProof', pow()],
    ['prevHash', new Uint8Array(32)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(over)) m.set(k, v);
  return parseRecord(m);
}

const CID = new Uint8Array(32).fill(0xcc);

/** A registry holding whatever the test puts in it. */
function ports(records: Record<string, RegistryRecord>, synced = true): ResolverPorts {
  return {
    lookup: (label, tld) => records[`${label}.${tld}`] ?? null,
    hasVerifiedHead: () => synced,
  };
}

const code = (o: Outcome): string => (o.ok ? 'ok' : o.error);

/* -------------------------------------------------------------------------- */
/* Step 1: parsing                                                             */
/* -------------------------------------------------------------------------- */

test('a host is exactly label.tld, and a subdomain is refused rather than interpreted', () => {
  assert.deepEqual(parseHost('atlas.vayu'), { label: 'atlas', tld: 'vayu' });
  assert.deepEqual(parseHost('ATLAS.VAYU'), { label: 'atlas', tld: 'vayu' }, 'host is lowercased');
  assert.deepEqual(parseHost('atlas.vayu:7654'), { label: 'atlas', tld: 'vayu' }, 'port stripped');

  // Silently treating a.b.vayu as a name under .vayu would resolve something never registered.
  assert.equal(parseHost('a.b.vayu'), null);
  assert.equal(parseHost('vayu'), null);
  assert.equal(parseHost('.vayu'), null);
  assert.equal(parseHost('atlas.'), null);
});

/* -------------------------------------------------------------------------- */
/* Check ORDER — the rejection code is wire-visible                            */
/* -------------------------------------------------------------------------- */

test('a request wrong in several ways fails on the earliest step', () => {
  // The steps are normative AND ordered. Two resolvers checking in different orders return
  // different numbered errors for the same request, and the number is what the user sees and
  // what a second implementation is checked against.
  const empty = ports({});

  // Bad label AND unratified TLD: TLD classification is step 2, label validation is step 4.
  assert.equal(code(resolveName('AB.nope', empty, NOW)), 'TLD_UNKNOWN');

  // Valid TLD, bad label, and the name does not exist: label validation precedes lookup, so
  // malformed input never reaches the registry.
  assert.equal(code(resolveName('-atlas.vayu', empty, NOW)), 'LABEL_INVALID');

  // Well-formed and absent, with no synchronised log: 1502 beats 1404, because "we have not
  // looked" is a different answer from "it is not there".
  assert.equal(code(resolveName('atlas.vayu', ports({}, false), NOW)), 'REGISTRY_UNAVAILABLE');
  assert.equal(code(resolveName('atlas.vayu', empty, NOW)), 'NAME_NOT_FOUND');
});

test('every catalogue code has the HTTP status and message the spec assigns it', () => {
  assert.equal(RESOLVE_ERRORS.LABEL_INVALID.code, 1400);
  assert.equal(RESOLVE_ERRORS.TLD_UNKNOWN.http, 502, 'not 404: the resolver, not the name');
  assert.equal(RESOLVE_ERRORS.NAME_NOT_FOUND.http, 404);
  assert.equal(RESOLVE_ERRORS.NAME_EXPIRED.code, 1410);
  assert.equal(RESOLVE_ERRORS.NAME_QUARANTINED.code, 1409);
  assert.equal(RESOLVE_ERRORS.ALIAS_LOOP.http, 508);
  assert.equal(RESOLVE_ERRORS.CONTENT_INTEGRITY.code, 1512);
  // Codes are unique: a shared code makes two different failures indistinguishable to a client.
  const codes = Object.values(RESOLVE_ERRORS).map((e) => e.code);
  assert.equal(new Set(codes).size, codes.length);
});

/* -------------------------------------------------------------------------- */
/* Step 8: the validity window                                                 */
/* -------------------------------------------------------------------------- */

test('an expired name does not resolve even though its content is still held', () => {
  // The rule exists precisely because the content is usually still there. A resolver that
  // served it would keep a lapsed registration alive for anyone who never re-queried.
  const r = { 'atlas.vayu': rec('atlas', [entry('cid', CID)]) };
  assert.equal(code(resolveName('atlas.vayu', ports(r), NOW)), 'ok');
  assert.equal(code(resolveName('atlas.vayu', ports(r), NOW + TERM + 1)), 'NAME_EXPIRED');
  assert.equal(
    code(resolveName('atlas.vayu', ports(r), NOW + TERM + 2_592_000 + 1)),
    'NAME_QUARANTINED',
  );
});

test('a name whose term has not started yet is not found rather than served', () => {
  const r = { 'atlas.vayu': rec('atlas', [entry('cid', CID)]) };
  assert.equal(code(resolveName('atlas.vayu', ports(r), NOW - 1)), 'NAME_NOT_FOUND');
});

/* -------------------------------------------------------------------------- */
/* Step 9: record selection                                                    */
/* -------------------------------------------------------------------------- */

test('a weekly publisher is not frozen at their first snapshot', () => {
  // The defect, stated as what a reader experiences.
  //
  // HOSTING.md recommends carrying both entries: an `ipns` pointer for the living site, and a
  // `cid` for "the last snapshot the owner is willing to have served if the pointer cannot be
  // resolved". The registry record then stays still while the site behind it changes, which
  // HOSTING says in terms is "what an author republishing weekly actually wants".
  //
  // An earlier revision of this specification selected `cid` first, unconditionally, with both
  // entries present. So the publisher follows HOSTING, the resolver follows RESOLUTION, both
  // conform — and every reader is served the frozen snapshot forever while the author publishes
  // into a pointer nobody consults. The escape hatch made it worse rather than better: fallback
  // was `MAY`, and the entry that never fails is precisely the pinned snapshot.
  //
  // Nothing surfaces this. There is no error, no staleness signal on the default path, and the
  // author sees their own site correctly because they resolve their own pointer. It is a silent,
  // permanent failure produced by two documents that each looked right.
  const livingSite = rec('atlas', [
    entry('txt', 'v=vayuweb1'),
    entry('peer', new Uint8Array(32).fill(1)),
    entry('ipns', 'k51qzi5uqu5d'),
    entry('cid', CID),
  ]);
  assert.equal(
    selectSource(livingSite)?.type,
    'ipns',
    'with both present the living pointer wins; the snapshot is the fallback HOSTING says it is',
  );
});

test('sources are preferred owner-signed-and-current first, and txt is never a source', () => {
  // ipns before cid before alias. The content is CID-addressed and hash-verified
  // either way — an IPNS pointer yields a CID — so preferring the pointer costs no
  // verifiability. What it costs is a resolution step and a liveness assumption, which is the
  // right price for showing the reader what the author actually published.
  const all = rec('atlas', [
    entry('txt', 'v=vayuweb1'),
    entry('peer', new Uint8Array(32).fill(1)),
    entry('ipns', 'k51qzi5uqu5d'),
    entry('cid', CID),
  ]);
  assert.equal(selectSource(all)?.type, 'ipns');
  assert.equal(
    selectSource(
      rec('atlas', [entry('txt', 'x'), entry('cid', CID), entry('peer', new Uint8Array(32))]),
    )?.type,
    'cid',
    'without a pointer the snapshot is the content source',
  );

  assert.equal(
    selectSource(
      rec('atlas', [entry('txt', 'x'), entry('ipns', 'k5'), entry('peer', new Uint8Array(32))]),
    )?.type,
    'ipns',
  );
  // `peer` used to be selectable here and is not — see the AUDIT test below for why. A record
  // carrying only a transport hint has no content source at all.
  assert.equal(
    selectSource(rec('atlas', [entry('txt', 'x'), entry('peer', new Uint8Array(32))])),
    null,
  );
  assert.equal(
    selectSource(rec('atlas', [entry('txt', 'only text')])),
    null,
    'txt is not a source',
  );
  assert.deepEqual([...SOURCE_ORDER], ['ipns', 'cid', 'alias']);
});

test('an unknown entry type is never acted upon, however it is ordered', () => {
  // REGISTRY.md requires unknown types to be stored and replicated unchanged. That is not the
  // same as being usable, and a resolver that treated one as content would act on a meaning
  // this version does not have.
  const r = rec('atlas', [entry('future', 'something')]);
  assert.equal(selectSource(r), null);
  assert.equal(
    code(resolveName('atlas.vayu', ports({ 'atlas.vayu': r }), NOW)),
    'NO_USABLE_RECORD',
  );
});

/* -------------------------------------------------------------------------- */
/* Step 10: aliases and the budget                                             */
/* -------------------------------------------------------------------------- */

test('an alias is followed to its destination', () => {
  const r = {
    'atlas.vayu': rec('atlas', [entry('alias', 'zenith.vayu')]),
    'zenith.vayu': rec('zenith', [entry('cid', CID)]),
  };
  const out = resolveName('atlas.vayu', ports(r), NOW);
  assert.equal(out.ok, true);
  if (out.ok) {
    assert.equal(out.entry.type, 'cid');
    assert.equal(out.record.name, 'zenith', 'the destination record, not the pointer');
    assert.equal(out.diagnostics.aliasHops, 1);
  }
});

test('a two-name alias cycle is caught, not chased', () => {
  // The cycle a -> b -> a spans two records and is invisible from either one, which is why the
  // resolver has to detect it rather than relying on the record rules.
  const r = {
    'atlas.vayu': rec('atlas', [entry('alias', 'zenith.vayu')]),
    'zenith.vayu': rec('zenith', [entry('alias', 'atlas.vayu')]),
  };
  assert.equal(code(resolveName('atlas.vayu', ports(r), NOW)), 'ALIAS_LOOP');
});

test('the alias budget is three hops, counted per original request', () => {
  const chain: Record<string, RegistryRecord> = {};
  const names = ['hopone', 'hoptwo', 'hopthree', 'hopfour', 'hopfive', 'hopsix'];
  for (let i = 0; i < names.length - 1; i += 1) {
    chain[`${names[i]}.vayu`] = rec(names[i]!, [entry('alias', `${names[i + 1]}.vayu`)]);
  }
  chain['hopsix.vayu'] = rec('hopsix', [entry('cid', CID)]);

  // Three hops away resolves; further does not, even though no name repeats.
  assert.equal(code(resolveName('hopthree.vayu', ports(chain), NOW)), 'ok');
  assert.equal(code(resolveName('hopone.vayu', ports(chain), NOW)), 'ALIAS_LOOP');
  assert.equal(ALIAS_BUDGET, 3);
});

test('an alias to a name that does not exist reports the missing name', () => {
  const r = { 'atlas.vayu': rec('atlas', [entry('alias', 'zenith.vayu')]) };
  assert.equal(code(resolveName('atlas.vayu', ports(r), NOW)), 'NAME_NOT_FOUND');
});

test('an alias to an expired name fails as expired, not as a broken pointer', () => {
  const r = {
    'atlas.vayu': rec('atlas', [entry('alias', 'zenith.vayu')]),
    'zenith.vayu': rec('zenith', [entry('cid', CID)]),
  };
  assert.equal(code(resolveName('atlas.vayu', ports(r), NOW + TERM + 1)), 'NAME_EXPIRED');
});

/* -------------------------------------------------------------------------- */
/* Diagnostics are recorded, never disclosed by this layer                     */
/* -------------------------------------------------------------------------- */

test('every outcome carries diagnostics, including the failures', () => {
  // Recording is mandatory; disclosing to the page is the caller's decision and is off by
  // default. Keeping diagnostics a field on the outcome rather than a header is what makes the
  // default enforceable instead of aspirational.
  const out = resolveName('atlas.vayu', ports({}), NOW);
  assert.equal(out.ok, false);
  assert.equal(out.diagnostics.name, 'atlas.vayu');
  assert.equal(out.diagnostics.source, null);

  const good = resolveName(
    'atlas.vayu',
    ports({ 'atlas.vayu': rec('atlas', [entry('cid', CID)]) }),
    NOW,
  );
  assert.ok(good.ok);
  assert.equal(good.diagnostics.source, 'cid');
  assert.equal(good.diagnostics.seq, 0);
  assert.equal(good.diagnostics.resolvedFrom, 'registry');
});

/* -------------------------------------------------------------------------- */
/* Step 13: path mapping                                                       */
/* -------------------------------------------------------------------------- */

test('a directory path resolves to its index', () => {
  const listing = new Set(['index.html', 'about.html', 'docs/index.html', 'img/logo.png']);
  assert.equal(mapPath('/', listing), 'index.html');
  assert.equal(mapPath('/about.html', listing), 'about.html');
  assert.equal(mapPath('/docs/', listing), 'docs/index.html');
  assert.equal(mapPath('/docs', listing), 'docs/index.html', 'without the trailing slash too');
  assert.equal(mapPath('/img/logo.png', listing), 'img/logo.png');
});

test('a missing path is the site’s problem, and returns nothing to serve', () => {
  const listing = new Set(['index.html']);
  assert.equal(mapPath('/nope.html', listing), null);
  assert.equal(mapPath('/deep/', listing), null);
});

test('path traversal is refused before normalisation, not after', () => {
  // Normalising first and checking second is the shape that has produced traversal bugs for
  // thirty years.
  const listing = new Set(['index.html', 'secret.txt']);
  assert.equal(mapPath('/../secret.txt', listing), null);
  assert.equal(mapPath('/a/../../secret.txt', listing), null);
  assert.equal(mapPath('/..%2fsecret.txt', listing), null);
});

test('query and fragment are stripped before matching', () => {
  const listing = new Set(['index.html']);
  assert.equal(mapPath('/?utm=1', listing), 'index.html');
  assert.equal(mapPath('/#top', listing), 'index.html');
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: a conformance item that required a name to differ from itself */
/* -------------------------------------------------------------------------- */

test('AUDIT: the origin model is tested on both components of the tuple', () => {
  // URI-SCHEME.md 3.1 makes the origin `("vayu", label "." tld)`, so two names differ if either
  // component differs. Its conformance item 2 read `vayu://a.vayu` and `vayu://a.vayu` — the same
  // URI on both sides, requiring a name to be cross-origin with itself. That is not a test nobody
  // ran; it is a test nobody could pass, and the item it displaced was the one that would have
  // measured the label and the TLD separately.
  const spec = readFileSync(new URL('../../docs/spec/URI-SCHEME.md', import.meta.url), 'utf8');
  const item = /^2\. (.+?)(?=\n\n|\n\d\. )/ms.exec(spec.slice(spec.indexOf('## 7. Conformance')));
  assert.ok(item, 'conformance item 2 must exist, or this check is inert');

  const pairs = [...item[1]!.matchAll(/`vayu:\/\/([a-z0-9.]+)`/g)].map((m) => m[1]!);
  assert.ok(pairs.length >= 2, 'the item must name at least two URIs');
  for (let i = 0; i + 1 < pairs.length; i += 2) {
    assert.notEqual(pairs[i], pairs[i + 1], 'a name cannot be cross-origin with itself');
  }
  // Both components exercised: one pair differing by label, one by TLD.
  const byLabel = pairs.some((p, i) => {
    const other = pairs[i % 2 === 0 ? i + 1 : i - 1];
    return other !== undefined && p.split('.')[1] === other.split('.')[1] && p !== other;
  });
  const byTld = pairs.some((p, i) => {
    const other = pairs[i % 2 === 0 ? i + 1 : i - 1];
    return other !== undefined && p.split('.')[0] === other.split('.')[0] && p !== other;
  });
  assert.ok(byLabel, 'no pair differs by label alone');
  assert.ok(byTld, 'no pair differs by TLD alone');
});

test('AUDIT: a revoked name says so, rather than telling the reader to renew', () => {
  // `stateAt` reports a revoked name as GRACE for the remainder of its term, so this path
  // returned 1410 — "This name's registration has expired". The registration had not expired:
  // the holder declared the key compromised. The name never resolved, so this was not a security
  // hole; it was a message that named the wrong cause and implied the wrong remedy, and renewing
  // is the single action a revoked name must not invite.
  //
  // RESOLUTION.md step 8 also said to compare `now` against `notAfter` directly, which is right
  // for four operations and wrong for two: a RELINQUISH sets `notAfter == notBefore` and skips
  // grace, so the naive comparison reports EXPIRED through quarantine; a REVOKE keeps
  // `prev.notAfter`, so it reports the name LIVE and a resolver following the step literally
  // serves content from a key its holder has declared compromised.
  // The behavioural half, and the half the first version of this test was missing: it asserted
  // the constant and the specification and never resolved a revoked name, so deleting the branch
  // that returns 1412 left it passing. A test that checks a value exists is not a test that the
  // value is ever produced.
  const revoked = rec('atlas', [], {
    op: 'REVOKE',
    seq: 1,
    records: [],
    notBefore: NOW,
    notAfter: NOW + TERM,
    powProof: null,
    prevHash: new Uint8Array(32).fill(0x22),
  });
  const during = resolveName('atlas.vayu', ports({ 'atlas.vayu': revoked }), NOW + 1000);
  assert.equal(code(during), 'NAME_REVOKED');
  // Still revoked deep into what would otherwise be the live term — a naive notAfter comparison
  // reports this one as LIVE and serves it.
  const later = resolveName('atlas.vayu', ports({ 'atlas.vayu': revoked }), NOW + TERM - 1000);
  assert.equal(code(later), 'NAME_REVOKED');

  assert.equal(RESOLVE_ERRORS.NAME_REVOKED.code, 1412);
  assert.equal(/expired/i.test(RESOLVE_ERRORS.NAME_REVOKED.message), false);

  const spec = readFileSync(new URL('../../docs/spec/RESOLUTION.md', import.meta.url), 'utf8');
  assert.match(spec, /\| 1412 \| NAME_REVOKED \| 410 \|/);
  // The step no longer tells an implementer to compare against notAfter directly.
  const step8 = /^8\. \*\*Validity window\.\*\*([\s\S]*?)(?=^9\. )/m.exec(spec);
  assert.ok(step8, 'step 8 must exist');
  assert.match(step8[1]!, /lifecycle rules in\s+\[REGISTRY\.md\]/);
  assert.match(step8[1]!, /\*\*not\*\* by comparing `now` against `notAfter`/);
});

test('AUDIT: a peer entry is never a content source, because nothing can verify what it returns', () => {
  // **This is the substitution clause 12.1 exists to close, reachable through the front door.**
  //
  // `peer` sat third in the selection order with no condition attached. Step 11 says "Fetch the
  // CID over IPFS" and step 12 says "Verify the bytes hash to the requested CID" — for a `peer`
  // entry there IS no CID, so step 12 has no operand and the bytes' only authority is the dialled
  // host's own say-so. An implementer building from RESOLUTION.md, which is the document a
  // resolver is built from, dials the key in the record and serves whatever comes back.
  //
  // The one sentence in the corpus that would have refused this lived in a different document's
  // CONFORMANCE-TEST list (CONTENT-SECURITY.md section 6, item 10) and turned on the term
  // "snapshot-verified", which appears exactly once in the whole repository and is defined
  // nowhere. A rule stated only as a test of a term nobody defined is not a rule.
  //
  // And it was attacker-reachable rather than merely publisher-reachable: the fallback rule walks
  // the resolver down the list when an entry "fails", so denying `ipns` and `cid` at the network
  // layer — cheap — downgrades the reader from content-addressed verification to host trust,
  // silently, on a name whose record and owner are entirely genuine.
  //
  // A `peer` is now a transport hint: a host to ask for blocks whose CID still comes from a
  // content-addressed entry, which is exactly the shape VWIP-0005 gives block exchange.
  assert.equal(
    selectSource(rec('atlas', [entry('txt', 'x'), entry('peer', new Uint8Array(32))])),
    null,
    'a record whose only entry is peer has no content source',
  );
  assert.equal(
    code(
      resolveName(
        'atlas.vayu',
        ports({ 'atlas.vayu': rec('atlas', [entry('peer', new Uint8Array(32))]) }),
        NOW,
      ),
    ),
    'NO_USABLE_RECORD',
  );

  // A peer entry alongside a content-addressed one changes nothing about which is chosen — the
  // hint is carried, not acted on as a source.
  assert.equal(
    selectSource(rec('atlas', [entry('peer', new Uint8Array(32)), entry('cid', CID)]))?.type,
    'cid',
  );

  // The order no longer lists it, and the specification says why in the document a resolver is
  // built from rather than in another document's test list.
  assert.equal([...SOURCE_ORDER].includes('peer' as never), false);
  const spec = readFileSync(new URL('../../docs/spec/RESOLUTION.md', import.meta.url), 'utf8');
  assert.match(spec, /`peer` entry is \*?\*?not\*?\*? a content source/);
  assert.match(spec, /transport hint/);
});
