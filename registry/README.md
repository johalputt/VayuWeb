# registry/ — the VayuWeb name registry

**Implementation started; the registry does not work yet.** This directory will hold the
peer-to-peer registry: a Hypercore append-only log with a Hyperbee index over it, holding every
signed name record.

What exists today is one module, and it is not a registry:

| Component | State |
|---|---|
| Deterministic CBOR codec (`src/cbor.ts`) | Implemented, tested |
| Domain-separated hashing and signing | Not started |
| Record schema and validation | Not started |
| Proof-of-work generation and verification | Not started |
| The six operations and the lifecycle state machine | Not started |
| Hyperbee index and keyspace | Not started |
| Peer replication and convergence | Not started |

Nothing here can register, resolve or replicate a name, and there is no network to join.

Its responsibilities, as specified in [../docs/spec/REGISTRY.md](../docs/spec/REGISTRY.md):

- Append and validate signed records for the `REGISTER`, `UPDATE`, `RENEW`, `TRANSFER`,
  `RELEASE` and `REVOKE` operations.
- Verify Ed25519 signatures over the canonical serialisation, with domain separation.
- Verify the memory-hard proof-of-work required at registration and renewal.
- Maintain the Hyperbee index that maps `name.tld` to its current record.
- Apply the convergence rule when peers disagree about a first registration.
- Replicate to peers found through Hyperswarm, and verify everything received.

What it MUST NOT do: hold a privileged writer, adjudicate ownership disputes, or trust a
record it has not verified locally.

See also: [Architecture](../docs/ARCHITECTURE.md) · [Threat Model](../docs/THREAT-MODEL.md)
