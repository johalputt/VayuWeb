# client/ — the VayuWeb desktop application

**Started, at the end that matters most.** This directory holds the Rust crate for the Tauri 2.x desktop client — the surface
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

## What exists now

`src/secrets.rs` implements [PRIVACY.md](../docs/spec/PRIVACY.md) section 7 — the four
requirements on every secret this client holds, and in particular the clause with the sharp edge:
a private key or the content-cache key on a platform without a keystore is **a refusal, not a
downgrade**. That rule is expressed as a type rather than a convention, so relaxing it does not
compile.

`src/control.rs` is the client half of the resolver's control API. It existed as a claim before it
existed as code — `Cargo.toml` has described this crate as "identity handling and the control-API
client" since the crate held only the first half — which is the kind of statement that is true of
the intention and not of the artifact.

Its shape follows the server's. `ControlEndpoint` has **one variant**, a socket path, because the
server refusing to bind TCP is worth nothing if the client offers to speak it: the pair is what an
operator configures. Requests are an enumeration of constants, so no value a user typed reaches the
request line and request splitting is unreachable rather than defended against. The token is
borrowed from a `Secret` straight into the byte buffer that goes on the wire, never through an
owned `String`, and a test counts its occurrences rather than checking the header is present —
the failure worth catching is an extra copy, which a presence check cannot see.

It builds and tests with no display and no system GUI libraries, which is deliberate: a security
rule that can only be checked by launching a window is a security rule nobody checks in CI.

```sh
cd client && cargo test
```

**The window itself is not built.** Nor is its acceptance test runnable by anyone here — it asks
for a person who has never used a command line, and no amount of automation supplies one.
