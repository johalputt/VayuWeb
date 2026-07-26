# client/ — the VayuWeb desktop application

**Not yet implemented.** This directory will hold the Tauri 2.x desktop client — the surface
for people who will never open a terminal.

Its responsibilities:

- Generate and hold the user's Ed25519 identity, with the secret key in the operating
  system keychain and never in a config file or the replicated log.
- Register, renew, transfer and release names, running the proof-of-work locally.
- Publish a site: build the tree, add it to IPFS, sign the IPNS pointer, write the record.
- Manage the local pin set, and make it obvious what is and is not being kept alive.
- Browse the VayuWeb namespace through the local proxy.

What it MUST NOT do: ship a default pinning service, a blessed bootstrap node, or any
default that quietly turns one operator into a mandatory intermediary.

See also: [Architecture](../docs/ARCHITECTURE.md) · [Roadmap](../docs/ROADMAP.md)
