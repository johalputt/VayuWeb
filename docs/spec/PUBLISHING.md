# VayuWeb Publishing and Authoring Specification

How a person puts a site on VayuWeb, and how the strict content-security profile is made survivable
for people who are not security engineers.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet deployed. Section 2.3's deep-link rule is implemented in
`registry/src/proxy.ts` and `registry/src/resolve.ts`, which read the manifest and serve `notFound`
with 404 or `fallback` with 200. Of the publish flow in section 1, steps 2, 3, 4 and 5 — build the
tree, address it, pin locally, sign the pointer — now exist in code: the desktop client builds
the UnixFS DAG and root CID in `client/src/publish.rs` and holds the blocks in a verified
content-addressed store in `client/src/store.rs`, pinned against this implementation's importer
through `conformance/client-built.json`. The authoring checks of section 3 and the
content-security profile's publish-time enforcement do not exist in any implementation, the flow
is wired together end to end nowhere, and serving pinned blocks to peers needs a transport that
does not exist yet; a Draft stays a Draft until someone can run it.

## 0. The design rule

> **Every restriction is paid at publish time, never at read time.**

A strict profile that fails silently in a reader's browser is a profile that gets switched off. A
strict profile that tells the author exactly what will not render, before they ship, costs the
author ten minutes once and costs the reader nothing ever.

This is the whole difference between a security control that survives and one that gets a
reputation for breaking things. VayuWeb therefore front-loads every failure into a checker the author
runs, and the checker's output is written for someone who does not know what a
Content-Security-Policy is.

## 1. Publishing a site

```text
vayu publish ./my-site --name example.vayu
```

The normative sequence:

1. **Check.** Run the conformance checks of section 3. Any error stops the publish. Nothing is
   uploaded, signed or announced until the tree passes.
2. **Build the tree.** Walk the directory, producing a UnixFS DAG.
3. **Address.** Compute the root CID.
4. **Pin locally.** The publisher's own node holds the content before anything points at it.
   Announcing a name that resolves to nothing is the most common self-inflicted failure in
   content-addressed systems, and step ordering prevents it.
5. **Sign the pointer.** Produce the registry record under the holder's key.
6. **Append.** Write the record to the log.

A publisher MUST NOT be required to run a server, obtain a certificate, configure DNS, or hold an
account with anybody at any step.

## 2. The site manifest

An optional `.vayu/manifest.json` inside the published tree, covered by the root CID and therefore
signed along with everything else. It cannot be tampered with independently of the content.

**This is the only normative definition of the manifest.** [HOSTING.md](HOSTING.md) once carried a
second, disjoint one — `title`, `description`, `entry`, `generator` — in which `entry` and `index`
were two names for one field. It now defers here; section 2.4 records what that cost.

```json
{
  "version": 1,
  "index": "index.html",
  "notFound": "404.html",
  "title": "Atlas Observatory",
  "description": "Field notes",
  "generator": "vayu-cli/0.2",
  "csp": {
    "wasm": false,
    "trustedTypes": null
  }
}
```

`fallback` is deliberately absent from that block, and its absence is the example's one piece of
advice: section 2.3 serves `notFound` first, so a manifest declaring both can never reach the
second. This block declared both for a period. A publisher with client-side routing who copied it
got HTTP 404 on every deep link — precisely and only the failure section 2.3 exists to prevent —
while the field they were relying on sat in their manifest looking as though it were doing
something. A worked example is the part of a specification that gets copied, so an example that
models a misconfiguration is worse than no example at all.

Every field is optional except `version`. `title`, `description` and `generator` are descriptive
and drive no resolver behaviour; they are here so a publisher has one place to put them rather
than two documents disagreeing about which.

### 2.1 Inline content: withdrawn, and why it is recorded rather than deleted

An earlier revision of this section let the resolver compute `'sha256-…'` source expressions for
inline `<style>` and `<script>` elements declared in the manifest and append them to `style-src`
and `script-src` for that site. It is withdrawn. The argument for it was good and is preserved
below, because a rejected design that leaves no trace gets reproposed every eighteen months by
someone who cannot find out why it was rejected.

**Why it was withdrawn.** [CONTENT-SECURITY.md](CONTENT-SECURITY.md) is the single source of
truth for the browser-security profile, and its section 2.3 enumerates the relaxations: two, for
WebAssembly and Trusted Types, with `None. Move to a stylesheet in the same CID.` against inline
style and script. [RESOLUTION.md](RESOLUTION.md) and [VWIP-0001](VWIP-0001.md) both say two as
well — VWIP-0001's rights-impact analysis states in terms that "sites using inline styles, inline
scripts, `data:` images or WASM must change to be rendered". This document was the only one that
said three, and it is not the document that owns the profile. Adding a relaxation to a security
profile from a subordinate specification is the defect, independent of whether the relaxation is
a good idea.

Two secondary conflicts came with it. The old text said "the reader-facing security indicator
MUST NOT change", against CONTENT-SECURITY.md 2.3's unconditional requirement that every
relaxation be "visible to the reader" and its conformance item 6. And this document's own next
section was titled "The two remaining relaxations", so the framing here had already been
outgrown by the section above it.

**The argument, kept intact for whoever proposes it properly.** The whole tree is verified
against its CID before a byte is served, so the resolver already knows the exact bytes of every
inline element, and an attacker cannot alter one without changing the CID and invalidating the
signed pointer. A hash-pinned inline script therefore permits exactly the bytes the holder signed
and nothing else — an injected script would not match a declared digest and would still be
refused. That is a materially different kind of widening from `'wasm-unsafe-eval'`, and the cost
of refusing it is real: it is the rule that breaks most hand-written pages and every single-file
document.

**What it would take.** A VWIP amending CONTENT-SECURITY.md section 2.3 to enumerate a third
relaxation, which must answer three things this section did not. Whether the emitted policy may
vary per page at all, since a per-page hash list makes the header a function of the content and
conformance item 1 is written against that. What the reader is shown, since 2.3 admits no
undisclosed relaxation. And whether the count is then three everywhere — CONTENT-SECURITY.md
2.3, RESOLUTION.md, VWIP-0001 and this document each state it, and they drifted apart last time.

### 2.2 The two relaxations

`csp.wasm: true` and `csp.trustedTypes: "<policy-name>"` are declared in the manifest, scoped to
the single site, and surfaced to the reader. They are genuine widenings and are treated as such —
see [CONTENT-SECURITY.md](CONTENT-SECURITY.md) section 2.3, which defines them and is
authoritative for both. This document declares them; it does not grant them.

### 2.3 Deep links

A site with client-side routing 404s on every deep link unless a fallback exists. On no path
match the resolver SHALL serve `notFound` with HTTP 404 if present; otherwise, if `fallback` is
declared, serve it with HTTP 200 so the site's own router can handle the path.

**Declaring both leaves `fallback` unreachable.** That follows from the precedence above rather
than adding to it, and it is stated here because it is the one reading a publisher gets wrong: the
two fields look complementary — a 404 page *and* a router fallback — and they are alternatives. A
resolver MUST NOT treat the combination as an error; a manifest that declares both is well-formed
and is served by the rule above, with `fallback` never consulted. A publisher choosing between
them is choosing what a deep link that the tree has no file for should mean: `notFound` says the
link is wrong and answers 404, `fallback` says the site's own router will decide and answers 200.
A site with client-side routing wants the second. Its cost is that a genuinely missing asset also
answers 200, with the router's shell in place of the image — which is why the choice is the
publisher's and not the resolver's.

[RESOLUTION.md](RESOLUTION.md) step 13 implements this. It did not for a period — it mapped
directories to `index.html` and returned `1414 PATH_NOT_FOUND` on no match, consulting no
manifest at all — so a `SHALL` here had no counterpart in the document that describes what a
resolver does, and a publisher declaring `notFound` got an ordinary 404 instead.

### 2.4 What the manifest may decide, and what it may not

The manifest is inside the published tree, covered by the root CID, and signed along with
everything else, so it cannot be tampered with independently of the content. That fact settles the
authority question that a competing definition in HOSTING.md left open for a period — one document
called the manifest "advisory" while this one gave it a `SHALL`.

Neither was quite right, and splitting the difference would have been worse than either:

- **It is authoritative about routing.** Which file answers `/`, and what to serve on no match,
  are decisions the site's owner is entitled to make about their own site. Trusting the manifest
  about them is trusting the owner exactly as much as trusting the content is — the same key
  signed both.
- **It is not evidence about the tree.** A resolver MUST NOT take a digest, a file's existence, or
  any content property from it: **the manifest declares intent; it does not confer permission.**

The `csp` relaxations of section 2.2 sit on the permission side of that line, not the routing
side, and are therefore constrained twice over. They are declared here, but they take effect only
under [CONTENT-SECURITY.md](CONTENT-SECURITY.md) section 2.3 — per-site, never global, and visible
to the reader, because a widening the reader cannot see is a widening that will be abused.

## 3. `vayu doctor`

The publish-time checker. It runs automatically as step 1 of `vayu publish` and can be run alone.

```text
$ vayu doctor ./my-site

  ✗  index.html:42   inline <style>
     VayuWeb blocks inline styles: an attribute selector plus a url() reads
     your page one character at a time, and a blocked one cannot.
     Fix: run `vayu doctor --fix`, or move the styles to a .css file.

  ✗  about.html:8    <img src="https://cdn.example.com/logo.png">
     Remote images do not load on VayuWeb. Every request to another server
     tells that server who is reading your page.
     Fix: save the file into your site folder and link it relatively.

  ⚠  index.html:15   <a href="https://example.com"> leaves VayuWeb
     This works, but the reader gets a warning. That is intended.

  2 errors, 1 warning.
```

### 3.1 Requirements

3.1.1 Every diagnostic MUST name the file, the line, what will not work, **why**, and a concrete
fix. A message that states a rule without a remedy is a defect in the checker.

3.1.2 Diagnostics MUST be written for someone who has never heard of a Content-Security-Policy.
"Inline styles are blocked" is acceptable; "style-src does not include 'unsafe-inline'" is not.

3.1.3 `--fix` MUST resolve mechanically fixable findings by extracting inline blocks to files in
the same tree. It MUST NOT alter document semantics, and MUST show a diff before writing. It has
no option that declares an inline block instead of moving it, because no such declaration is
honoured — see section 2.1.

3.1.4 The checker MUST detect at minimum: inline `<style>` and `<script>`; any
non-same-origin subresource; `data:` images; `<base>`; `<iframe>`; forms with a non-same-origin
action; the speculative-loading `<link rel>` values; `<meta name="referrer">` and
`<meta http-equiv="refresh">`; WebAssembly without the manifest declaration; service-worker
registration; a missing index document; and a total tree size over the snapshot ceiling.

3.1.5 The checker MUST NOT require network access. It reads a directory and exits.

3.1.6 The checker's rule set and the resolver's enforcement MUST be generated from one shared
definition, so the two cannot drift. A checker that passes a site the resolver then refuses is
worse than no checker, because it converts a clear failure into a mystery.

## 4. Updating and unpublishing

**Update:** republish. A new CID, a new signed record, `seq` incremented. Readers see the new
version the next time they resolve.

**Unpublish:** withdraw the pointer and unpin locally. This stops VayuWeb serving it. It does not
reach copies others already hold — see [PRIVACY.md](PRIVACY.md) and Constitution Article 19. The
client MUST state this plainly at the moment of unpublishing rather than in documentation nobody
reads.

## 5. What a publisher never has to do

Stated as a list because it is the substance of the "easy" commitment in
[POSITION.md](../POSITION.md), and because each line is a real task that a clearnet publisher
does have to do:

- Register with, or pay, a registrar.
- Configure DNS records or nameservers, or wait for propagation.
- Obtain, install, renew or monitor a TLS certificate.
- Run, patch or monitor a server, or respond to a dependency advisory.
- Hold a hosting account, or a payment method, or a support relationship.
- Choose a region, a plan, or a content-network configuration.

## 6. Conformance

1. `vayu publish` on a tree that fails `vayu doctor` does not write a record.
2. Every `vayu doctor` diagnostic carries a file, a line, a reason and a fix.
3. A tree containing an inline `<style>` or `<script>` fails `vayu doctor`, and no manifest
   field makes it pass. The withdrawn exception of section 2.1 has no residue in the checker.
4. The manifest changes routing and never permission: a `csp` field the reader was not shown, or
   any content claim taken from the manifest rather than from the verified tree, fails.
5. The checker runs with no network access.
6. The checker's rule set and the resolver's enforcement derive from one shared definition, and a
   test asserts a site passing the checker is served without a policy violation.
7. Local pinning completes before the pointer record is appended.

## See also

- [Position](../POSITION.md) — the four commitments this specification serves
- [Content security](CONTENT-SECURITY.md) — the profile authors are checked against
- [Hosting](HOSTING.md) — what happens to the bytes after publishing
- [Resolution](RESOLUTION.md) — how a reader reaches them
