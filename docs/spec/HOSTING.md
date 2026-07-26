# WebX Hosting and Publishing Specification

This document specifies how a WebX site is packaged, addressed, published,
pinned, replaced and withdrawn. It owns the content layer: everything between a
directory on an author's disk and a CID a resolver can verify.

The key words MUST, MUST NOT, SHALL, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

Nothing described here has been implemented. There is no running network, no
published site and no client binary. This is a design under review.

## Scope and conformance

A conforming publisher imports a directory tree into IPFS with the exact
parameters fixed below, pins the resulting root CID, optionally signs an IPNS
record over it, and writes `cid` and/or `ipns` entries into the name's registry
record as specified in [REGISTRY.md](REGISTRY.md). Record encoding, signing and
replication belong to that document and are not repeated here. How a resolver
consumes the result is specified in [RESOLUTION.md](RESOLUTION.md).

WebX hosting is static. There is no origin server, no request-time execution,
no server-side templating and no database behind a name. A site is a fixed set
of bytes; anything dynamic runs in the visitor's browser against those bytes.
This is a deliberate limit, not an omission awaiting a feature: a name that
resolves to a running server resolves to a machine somebody can seize.

## Site package format

A site is a directory tree. The tree is the unit of publication; there is no
archive format, no manifest requirement and no build step imposed by the
protocol.

The tree MUST contain `index.html` at its root. Every subdirectory intended to
be addressable as a path MUST contain its own `index.html`, because a resolver
maps a trailing `/` to that filename and has nothing to fall back on.

Filenames MUST be NFC-normalised UTF-8, MUST NOT exceed 255 bytes, and MUST NOT
contain `/`, `\`, a control character below U+0020, or a leading `.` for any
file intended to be served. Symbolic links MUST NOT be followed; a publisher
SHALL either dereference them at build time or refuse the import, since a
followed link can silently pull a private key into a public CID.

A publisher MAY include a manifest at `.webx/manifest.json` carrying `title`,
`description`, `entry` (default `index.html`) and `generator`. The manifest is
advisory. A resolver MUST render a site that has none, and MUST NOT trust the
manifest over the actual tree.

Modification times, owner IDs and Unix permission bits MUST NOT be recorded in
the imported DAG. They break reproducibility and they leak the author's build
environment, and neither is worth a byte on the wire.

## Content addressing

Import parameters are fixed so that two independent implementations importing
byte-identical trees produce byte-identical CIDs. A publisher SHALL use exactly:

```text
CID version       1
Multibase (text)  base32, lowercase ('b' prefix)
Multihash         sha2-256
File layout       UnixFS balanced DAG, max 174 links per node
Chunker           fixed-size, 262144 bytes (256 KiB)
Leaves            raw blocks (codec 0x55)
Directories       dag-pb UnixFS, entries sorted by raw byte order of name
Large directories HAMT-sharded when the encoded node exceeds 256 KiB, bitwidth 8
```

Fixed-size chunking is chosen over content-defined (Rabin) chunking because it
is deterministic across implementations and cheap to compute; the
deduplication Rabin buys matters for large mutating datasets, not for a site
that is republished whole. Raw leaves are chosen because a single-block file's
CID is then the hash of the file itself, which makes verification explainable
to a user and removes a wrapper block per leaf.

The multihash is sha2-256 rather than the BLAKE2b-256 used for registry record
hashes. The divergence is intentional: registry hashing is internal to WebX and
free to pick the faster function, while content hashing must interoperate with
the existing IPFS network, where sha2-256 is what other nodes and gateways
expect.

## The publish flow

A publisher SHALL perform these steps in order. Steps 5 and 6 are skipped for
an immutable-only publication.

1. Build the site to a directory tree and verify it satisfies the package rules
   above, including the root `index.html`.
2. Import the tree with the fixed parameters, producing a root CID. The import
   MUST be reproducible: a second import of the same bytes MUST yield the same
   CID.
3. Pin the root CID in the local blockstore and announce the blocks to the
   swarm. Until this succeeds the site exists nowhere.
4. Verify locally by fetching the CID back through the resolver and rendering
   it. A publisher SHOULD NOT proceed on an unverified import.
5. Sign an IPNS record binding the site key to `/ipfs/<root CID>`, with a
   sequence number one greater than the previously published record, a validity
   of 168 hours and a republish interval of 12 hours. Seven days of validity
   survives a laptop closed over a long weekend; a twelve-hour republish keeps
   the record alive against DHT churn without flooding it.
6. Publish that IPNS record to the DHT and wait for it to resolve from a second
   node before treating it as live.
7. Build a registry update for the name: `seq` incremented by one, `prevHash`
   set to the current record hash, `records` carrying an `ipns` entry, a `cid`
   entry, or both.
8. Sign the update with the owner key and append it to the log, where it
   replicates to peers.
9. Confirm end to end by resolving `name.tld` through a resolver that was not
   involved in publishing.

The site key SHALL be a distinct Ed25519 keypair from the registry owner key.
Separating them means a build machine can be given the ability to publish new
content without being given the ability to transfer or release the name.

## Pins and pointers

The two content entry types answer different questions and are not
interchangeable.

A `cid` entry names an exact immutable snapshot. It is verifiable with no
liveness assumption: a resolver that obtains the bytes from any source, however
hostile, can confirm they hash to the requested CID. Changing the site means
changing the registry record, which costs a signed append and is visible to
every peer in the log's history.

An `ipns` entry names a mutable pointer. The registry record stays still while
the site behind it changes, which is what an author republishing weekly
actually wants. The cost is a second trust and liveness dependency: the pointer
must be resolvable at read time, and whoever holds the site key controls what
the name shows without touching the registry at all.

A record MAY carry both. The recommended pattern is an `ipns` entry for the
living site and a `cid` entry for the last snapshot the owner is willing to
have served if the pointer cannot be resolved. Resolver preference order is
specified in [RESOLUTION.md](RESOLUTION.md) and is not restated here.

## Availability

WebX guarantees name resolution. It does not guarantee that a site loads.

Content survives only while at least one peer holds and serves the blocks. If
the owner's node is offline and no other peer pinned the content, the name
resolves correctly, the registry record is valid, and the visitor gets an
unavailability error. There is no protocol remedy, no replication requirement
and no uptime figure. Any document in this repository quoting an uptime number
is wrong.

Available mitigations, in the order most authors should consider them:

- Self-pinning on a machine that stays online. One always-on node is the
  difference between a site that loads and a site that does not.
- Friend-pinning. Peers who trust an author pin the root CID from the client's
  pin list. A handful of geographically separate friends is a stronger
  guarantee than one rented server.
- A volunteer pin set: an opt-in list of CIDs that public-spirited peers pin in
  bulk. Volunteers choose what to carry and may drop it at any time, so this is
  best-effort by construction.
- A paid third-party pinning service. This is legitimate and it works. It MUST
  remain optional and swappable: the client MUST NOT ship a default provider, a
  preferred provider or a bundled free tier, and MUST express any provider
  through a generic pinning interface so that switching is a configuration
  change. A default pinning service would recentralise the hosting layer within
  a release cycle.

## Size guidance

A site SHOULD stay under 256 MiB in total. The desktop client SHALL warn above
256 MiB, SHALL require explicit confirmation above 512 MiB, and MUST refuse by
default above 2 GiB. The reasoning is the volunteer's disk: a peer pinning
fifty sites at 512 MiB has donated 25 GiB, which is roughly the ceiling of what
an unpaid volunteer tolerates.

A single file SHOULD stay under 64 MiB. Resolvers reject any single resource
above 256 MiB outright, so a larger file is unservable regardless of pinning.

A tree SHOULD contain fewer than 10,000 entries. Beyond that, directory
traversal and pin bookkeeping dominate publish time; large media collections
belong in separate CIDs linked from the site, not inside it.

## Unpublishing and its limits

An owner can do three things, and no more.

The pointer can be withdrawn: publish an IPNS record with a higher sequence
number pointing at an empty or tombstone directory, and append a registry
update removing the `cid` and `ipns` entries. New resolutions then fail or
render the tombstone.

The local copy can be unpinned and garbage-collected, so the owner's own node
stops serving the blocks.

That is the whole of it. An owner CANNOT compel other peers to forget bytes
they already hold. Anyone who fetched or pinned the CID keeps it for as long as
they choose, and the CID itself remains in the registry log forever, because
the log is append-only and its history is what makes it verifiable. Removing an
entry hides nothing that was ever published.

Publication is therefore permanent in effect. Authors SHOULD treat every
publish as irreversible and MUST NOT rely on unpublishing to contain a mistake
such as a committed secret; the correct response to a published secret is to
rotate it.

## What makes a site renderable

A site is renderable when a resolver can serve it with no network access beyond
the WebX peer set. Concretely:

- A root `index.html` exists and is valid HTML.
- Every subresource — scripts, styles, images, fonts, media — resolves inside
  the site's own CID by relative path. Clearnet subresources are refused by the
  resolver's Content-Security-Policy, so a page depending on a hosted font, an
  analytics endpoint or a script host renders broken.
- No protocol-relative (`//host/...`) or absolute clearnet URLs appear in any
  served document, including inside stylesheets and inline scripts.
- File extensions are correct, since the served `Content-Type` is derived from
  the extension and nothing else.
- Primary text content SHOULD be readable without scripts. A site whose text
  only appears after a client-side fetch is one failed block away from blank.

A site that meets these conditions renders identically for every visitor,
because every visitor verifies the same bytes against the same CID.

## Status

Status: Draft — not yet implemented. This specification describes the
pre-implementation design; no publishing tool exists, no site has been
published, and every constant here is subject to change through the WXIP
process before a first release.

## See also

- [docs/spec/REGISTRY.md](REGISTRY.md)
- [docs/spec/RESOLUTION.md](RESOLUTION.md)
- [docs/ARCHITECTURE.md](../ARCHITECTURE.md)
- [docs/THREAT-MODEL.md](../THREAT-MODEL.md)
