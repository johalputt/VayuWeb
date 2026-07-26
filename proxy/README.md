# proxy/ — the local resolution proxy

**Not yet implemented.** This directory will hold the lightweight local proxy that makes
`.vayu` and its sibling extensions resolve in an ordinary browser, with no extension required.

Its responsibilities, as specified in
[../docs/spec/RESOLUTION.md](../docs/spec/RESOLUTION.md):

- Serve an HTTP proxy on loopback and a separate, token-authenticated control API.
- Resolve a VayuWeb name against the local registry index, select the applicable record, and
  fetch the content it points at.
- Cache positive and negative results under the specified TTL policy.
- Treat each name as its own origin and apply the default Content-Security-Policy.
- Return a defined error for an unresolvable name.

What it MUST NOT do: fall through to clearnet DNS for a VayuWeb name, log queries by default,
phone home, or let a VayuWeb page reach the control API.

See also: [Architecture](../docs/ARCHITECTURE.md) · [Threat Model](../docs/THREAT-MODEL.md)
