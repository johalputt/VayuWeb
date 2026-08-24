# proxy/ — the standalone resolution proxy

**Reserved.** The resolution proxy itself is implemented and shipped inside the registry
package — `registry/src/proxy.ts` (browsing proxy), `registry/src/control.ts` (control API),
`registry/src/serve.ts` (the sockets that bind them) — and `vayuweb-registry serve` runs it.
Its acceptance test drives an unmodified browser end to end
(`registry/scripts/acceptance-browser.mjs`).

This directory is set aside for the **packaged form**: a standalone build of that resolver for
operators who want the loopback proxy without the registry tooling around it. Nothing lives here
yet, and until it does the implementation of record is the one under `registry/src`.

Whatever shape the packaged form takes, it inherits the rules the implementation already enforces:

- Serve an HTTP proxy on loopback and a separate, token-authenticated control API on a Unix
  domain socket — never TCP on the control surface.
- Resolve a VayuWeb name against the local verified index, select the applicable record, and
  fetch the content it points at through verified traversal.
- Cache positive and negative results under the specified TTL policy.
- Treat each name as its own origin and apply the default Content-Security-Policy.
- Return a defined error from the numbered catalogue for an unresolvable name.

What it MUST NOT do: fall through to clearnet DNS for a VayuWeb name, log queries by default,
phone home, or let a VayuWeb page reach the control API.

See also: [Architecture](../docs/ARCHITECTURE.md) · [Roadmap](../docs/ROADMAP.md)
