/**
 * The block-exchange wire format, attacked rather than exercised.
 *
 * The conformance vectors in `vectors.test.ts` pin what two implementations must agree about.
 * These pin the refusals a vector cannot express — the ones about *when* a check runs and what it
 * costs, which are invisible in a message's bytes and are where every limit in this project has
 * previously been found to be nominal.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  BLOCK_EXCHANGE_TOPIC_PREIMAGE,
  BLOCK_EXCHANGE_VERSION,
  BX_LIMITS,
  BlockExchangeError,
  decodeBlockMessage,
  encodeBlockMessage,
} from './blockx.ts';
import { encode, type CborValue } from './cbor.ts';

const CID = Uint8Array.from([0x01, 0x55, 0x12, 0x20, ...new Uint8Array(32).fill(0xab)]);

const refusal = (run: () => unknown): string => {
  try {
    run();
    return 'no refusal';
  } catch (error) {
    return error instanceof BlockExchangeError ? error.code : `threw:${String(error)}`;
  }
};

const raw = (entries: [string, CborValue][]): Uint8Array =>
  encode(new Map<string | Uint8Array, CborValue>(entries));

/* -------------------------------------------------------------------------- */
/* Round trips                                                                 */
/* -------------------------------------------------------------------------- */

test('every message type round-trips through its own encoder', () => {
  const messages = [
    { t: 'BHELLO' as const, v: BLOCK_EXCHANGE_VERSION, max: BX_LIMITS.blockBytes },
    { t: 'BWANT' as const, cids: [CID] },
    { t: 'BLOCKS' as const, blks: [Uint8Array.of(1, 2, 3), new Uint8Array(0)] },
    { t: 'BDONE' as const, cids: [CID] },
  ];
  for (const message of messages) {
    assert.deepEqual(decodeBlockMessage(encodeBlockMessage(message)), message);
  }
});

test('a zero-byte block survives the wire', () => {
  // A file of zero bytes is a file and it has an identifier. A wire format that cannot carry the
  // empty leaf makes a published placeholder unfetchable, and the case is easy to lose to a
  // truthiness check on the payload.
  const decoded = decodeBlockMessage(
    encodeBlockMessage({ t: 'BLOCKS', blks: [new Uint8Array(0)] }),
  );
  assert.equal(decoded.t, 'BLOCKS');
  assert.equal(decoded.t === 'BLOCKS' ? decoded.blks.length : -1, 1);
  assert.equal(decoded.t === 'BLOCKS' ? decoded.blks[0]!.length : -1, 0);
});

/* -------------------------------------------------------------------------- */
/* Limits, and when they are applied                                           */
/* -------------------------------------------------------------------------- */

test('AUDIT: an over-limit array is refused BEFORE its elements are examined', () => {
  // The defect this exists for is a limit applied after the loop it bounds: the peer is refused,
  // the vector passes, and the work has already been done. Ordering is invisible to an assertion
  // on the error code alone, so the message below is built to make the two orderings produce
  // DIFFERENT codes — 65 entries whose first element is not a byte string at all.
  //
  //   length checked first  -> LIMIT_EXCEEDED, having touched no element
  //   elements checked first -> MALFORMED, having touched element 0
  //
  // A first version of this test built an array of getters to count element access and then never
  // fed it to the decoder, so the counter was trivially empty and the assertion passed against
  // any implementation. That is the same dead-check shape this project has now found three times;
  // it is caught here by asking what the test would do if the code were wrong.
  const oversizedWithBadFirst = raw([
    ['t', 'BWANT'],
    ['cids', [42, ...Array.from({ length: BX_LIMITS.wantCids }, () => CID)]],
  ]);
  assert.equal(
    refusal(() => decodeBlockMessage(oversizedWithBadFirst)),
    'LIMIT_EXCEEDED',
  );

  // The control: the same bad first element, one entry fewer, so the length check passes and the
  // element check is reached. Without this line the assertion above would also pass against a
  // decoder that answered LIMIT_EXCEEDED to everything.
  const withinLimitWithBadFirst = raw([
    ['t', 'BWANT'],
    ['cids', [42, ...Array.from({ length: BX_LIMITS.wantCids - 1 }, () => CID)]],
  ]);
  assert.equal(
    refusal(() => decodeBlockMessage(withinLimitWithBadFirst)),
    'MALFORMED',
  );

  // And exactly at the limit is accepted: a boundary wrong in the restrictive direction refuses
  // honest peers, which no rejection test would notice.
  const atLimit = raw([
    ['t', 'BWANT'],
    ['cids', Array.from({ length: BX_LIMITS.wantCids }, () => CID)],
  ]);
  assert.equal(decodeBlockMessage(atLimit).t, 'BWANT');
});

test('a block one octet over the limit is refused, and one octet under is not', () => {
  const over = raw([
    ['t', 'BLOCKS'],
    ['blks', [new Uint8Array(BX_LIMITS.blockBytes + 1)]],
  ]);
  assert.equal(
    refusal(() => decodeBlockMessage(over)),
    'LIMIT_EXCEEDED',
  );

  const at = raw([
    ['t', 'BLOCKS'],
    ['blks', [new Uint8Array(BX_LIMITS.blockBytes)]],
  ]);
  assert.equal(decodeBlockMessage(at).t, 'BLOCKS');
});

test('an identifier over the cid bound is refused before it is decoded', () => {
  const over = raw([
    ['t', 'BWANT'],
    ['cids', [new Uint8Array(BX_LIMITS.cidBytes + 1)]],
  ]);
  assert.equal(
    refusal(() => decodeBlockMessage(over)),
    'LIMIT_EXCEEDED',
  );
});

test('a message over the whole-message bound is refused before it is parsed', () => {
  // Length first, parse second. A decoder asked to parse an unbounded input has already lost, and
  // the assertion that separates the two orderings is that the buffer need not be valid CBOR at
  // all: this one is a megabyte of zeros, which no canonical decoder would accept either — so the
  // CODE is what distinguishes them.
  const huge = new Uint8Array(BX_LIMITS.messageBytes + 1);
  assert.equal(
    refusal(() => decodeBlockMessage(huge)),
    'TOO_LARGE',
  );
});

test('the encoder refuses to emit what a conforming receiver must reject', () => {
  // A sender that emits an over-limit message produces a failure that looks like the receiver's
  // fault. The peer best placed to notice is the one that built the message.
  assert.equal(
    refusal(() =>
      encodeBlockMessage({
        t: 'BLOCKS',
        blks: Array.from({ length: 2 }, () => new Uint8Array(BX_LIMITS.blockBytes)),
      }),
    ),
    'TOO_LARGE',
  );
});

/* -------------------------------------------------------------------------- */
/* Shape                                                                       */
/* -------------------------------------------------------------------------- */

test('an unknown message type is named as unknown rather than treated as malformed', () => {
  // The distinction is the whole of VWIP-0005 3.2: an unknown type drops the MESSAGE, a malformed
  // one may drop the connection. Collapsing them into one code is how a protocol becomes
  // unextendable, and the collapse is invisible unless the codes are asserted apart.
  assert.equal(
    refusal(() => decodeBlockMessage(raw([['t', 'BHAVE']]))),
    'UNKNOWN_TYPE',
  );
  assert.equal(
    refusal(() => decodeBlockMessage(raw([['t', 42]]))),
    'MALFORMED',
  );
  assert.equal(
    refusal(() => decodeBlockMessage(encode([1, 2, 3]))),
    'MALFORMED',
  );
});

test('non-canonical CBOR is refused as non-canonical, not as malformed', () => {
  // A message whose encoding is not the canonical encoding of its own content is refused for the
  // same non-malleability reason records are. `a1` with a two-byte-encoded small integer key is
  // valid CBOR and is not canonical.
  const nonCanonical = Uint8Array.from([0xa1, 0x18, 0x01, 0x01]);
  assert.equal(
    refusal(() => decodeBlockMessage(nonCanonical)),
    'NON_CANONICAL',
  );
});

test('every field is type-checked, and a wrong type is never coerced', () => {
  assert.equal(
    refusal(() =>
      decodeBlockMessage(
        raw([
          ['t', 'BHELLO'],
          ['max', BX_LIMITS.blockBytes],
          ['v', 'one'],
        ]),
      ),
    ),
    'MALFORMED',
  );
  // A negative maximum cannot reach the decoder AT ALL, and that is a stronger statement than
  // "it is rejected": the CBOR profile has no negative integers in it, so there is no encoding of
  // one for a peer to send. This test asserted the weaker thing first and was wrong — the case it
  // described is unreachable, and a test describing an unreachable case is a test that will pass
  // whatever the decoder does with negatives.
  //
  // `uint`'s own `value < 0` guard stays regardless. It is unreachable through this profile and
  // becomes reachable the day the profile widens, which is exactly when nobody will be looking
  // for it.
  assert.throws(
    () =>
      raw([
        ['t', 'BHELLO'],
        ['max', -1],
        ['v', 1],
      ]),
    /NEGATIVE_INT/,
  );
  // Text where byte strings belong. `cids` holding strings would otherwise reach an identifier
  // decoder as something that has a `.length`.
  assert.equal(
    refusal(() =>
      decodeBlockMessage(
        raw([
          ['t', 'BWANT'],
          ['cids', ['bafy']],
        ]),
      ),
    ),
    'MALFORMED',
  );
});

test('AUDIT: an absurd BHELLO.max decodes and allocates nothing', () => {
  // VWIP-0005 5.1. The message is well-formed, so a decode failure would be the WRONG answer —
  // the defect is a receiver that sizes a buffer from a number a stranger asserted, which is not
  // expressible as a rejection. What is assertable is that the decoder itself does not grow with
  // the claim, so the cost of the absurd message is compared against the cost of the honest one.
  const absurd = encodeBlockMessage({ t: 'BHELLO', v: 1, max: Number.MAX_SAFE_INTEGER });
  const modest = encodeBlockMessage({ t: 'BHELLO', v: 1, max: 1 });
  assert.ok(absurd.length < 32, 'the absurd claim is a handful of bytes on the wire');

  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < 1_000; i += 1) decodeBlockMessage(absurd);
  const afterAbsurd = process.memoryUsage().heapUsed - before;

  const between = process.memoryUsage().heapUsed;
  for (let i = 0; i < 1_000; i += 1) decodeBlockMessage(modest);
  const afterModest = process.memoryUsage().heapUsed - between;

  // A decoder that allocated on `max` would differ here by gigabytes; garbage collection makes
  // the exact figures noisy, so the assertion is on the ORDER and is deliberately generous. A
  // tight bound on a noisy measurement is a flaky test pretending to be a strict one.
  assert.ok(
    afterAbsurd < afterModest + 8_000_000,
    `absurd max cost ${afterAbsurd} bytes against ${afterModest} for a modest one`,
  );
});

/* -------------------------------------------------------------------------- */
/* The specification is the authority, not this file                           */
/* -------------------------------------------------------------------------- */

test('every limit here is the number VWIP-0005 section 5 states', () => {
  // Read out of the document rather than restated. A second copy of a limit is a copy that
  // drifts, and this one is wire-visible: a bound loosened in code and not in the specification is
  // a relaxation nobody chose.
  const spec = readFileSync(new URL('../../docs/spec/VWIP-0005.md', import.meta.url), 'utf8');
  const row = (label: string): number => {
    const match = new RegExp(`^\\| ${label} \\| ([\\d,]+) `, 'm').exec(spec);
    assert.ok(match, `VWIP-0005 section 5 must carry a row for ${label}`);
    return Number(match[1]!.replace(/,/g, ''));
  };
  assert.equal(row('Message encoding'), BX_LIMITS.messageBytes);
  assert.equal(row('Block octets'), BX_LIMITS.blockBytes);
  assert.equal(row('`BWANT.cids` length'), BX_LIMITS.wantCids);
  assert.equal(row('`BLOCKS.blks` length'), BX_LIMITS.blocksPerMessage);
  assert.equal(row('Each identifier'), BX_LIMITS.cidBytes);
  assert.equal(row('Outstanding `BWANT`s per connection'), BX_LIMITS.outstandingWants);
  assert.equal(row('Unrequested blocks tolerated per connection'), BX_LIMITS.unrequestedBlocks);
});

test('the topic preimage and version are the strings the specification names', () => {
  const spec = readFileSync(new URL('../../docs/spec/VWIP-0005.md', import.meta.url), 'utf8');
  assert.match(spec, new RegExp(`BLAKE2b-256\\("${BLOCK_EXCHANGE_TOPIC_PREIMAGE}"\\)`));
  assert.match(spec, new RegExp(`\`v\` is \`${BLOCK_EXCHANGE_VERSION}\``));
});

test('AUDIT: the message set is exactly the four VWIP-0005 declares', () => {
  // A fifth message type added in code and not in the document is an extension nobody agreed to,
  // and it would be invisible to every test above — each of which asserts about one type it names
  // itself. The document's own table is the enumeration.
  const spec = readFileSync(new URL('../../docs/spec/VWIP-0005.md', import.meta.url), 'utf8');
  const declared = new Set([...spec.matchAll(/^\| `(B[A-Z]+)` \| /gm)].map((m) => m[1]!));
  assert.deepEqual([...declared].sort(), ['BDONE', 'BHELLO', 'BLOCKS', 'BWANT']);

  for (const type of declared) {
    assert.notEqual(
      refusal(() => decodeBlockMessage(raw([['t', type]]))),
      'UNKNOWN_TYPE',
      `${type} is declared in VWIP-0005 and not implemented`,
    );
  }
  // And nothing outside the set is accepted, including the ones deliberately NOT adopted from
  // bitswap — 6.1 and 6.5 are normative absences, so their presence would be a defect.
  for (const absent of ['BHAVE', 'BCANCEL', 'BLEDGER']) {
    assert.equal(
      refusal(() => decodeBlockMessage(raw([['t', absent]]))),
      'UNKNOWN_TYPE',
    );
  }
});
