# registry/ — the WebX name registry

**Not yet implemented.** This directory will hold the peer-to-peer registry: a Hypercore
append-only log with a Hyperbee index over it, holding every signed name record.

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
