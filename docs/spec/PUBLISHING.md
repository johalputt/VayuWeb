# WebX Publishing and Authoring Specification

How a person puts a site on WebX, and how the strict content-security profile is made survivable
for people who are not security engineers.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented.

## 0. The design rule

> **Every restriction is paid at publish time, never at read time.**

A strict profile that fails silently in a reader's browser is a profile that gets switched off. A
strict profile that tells the author exactly what will not render, before they ship, costs the
author ten minutes once and costs the reader nothing ever.

This is the whole difference between a security control that survives and one that gets a
reputation for breaking things. WebX therefore front-loads every failure into a checker the author
runs, and the checker's output is written for someone who does not know what a
Content-Security-Policy is.

## 1. Publishing a site

```text
webx publish ./my-site --name example.webx
```

The normative sequence:

1. **Check.** Run the conformance checks of section 3. Any error stops the publish. Nothing is
   uploaded, signed or announced until the tree passes.
2. **Build the tree.** Walk the directory, producing a UnixFS DAG.
3. **Compute inline digests.** For each inline `<style>` and `<script>` element in each HTML
   document, compute the SHA-256 and record it in the manifest (section 2.1).
4. **Address.** Compute the root CID.
5. **Pin locally.** The publisher's own node holds the content before anything points at it.
   Announcing a name that resolves to nothing is the most common self-inflicted failure in
   content-addressed systems, and step ordering prevents it.
6. **Sign the pointer.** Produce the registry record under the holder's key.
7. **Append.** Write the record to the log.

A publisher MUST NOT be required to run a server, obtain a certificate, configure DNS, or hold an
account with anybody at any step.

## 2. The site manifest

An optional `.webx/manifest.json` inside the published tree, covered by the root CID and therefore
signed along with everything else. It cannot be tampered with independently of the content.

```json
{
  "version": 1,
  "index": "index.html",
  "fallback": "index.html",
  "notFound": "404.html",
  "inline": {
    "style":  ["sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="],
    "script": []
  },
  "csp": {
    "wasm": false,
    "trustedTypes": null
  }
}
```

### 2.1 Inline content, made safe by addressing

The strict profile forbids inline `<style>` and `<script>`. For ordinary authors this is the
single most disruptive rule, and a plain refusal would break most hand-written pages and every
single-file document.

Content addressing makes a narrow, safe exception possible. Because the entire tree is verified
against its CID before anything is served, **the resolver already knows the exact bytes of every
inline element**, and an attacker cannot alter one without changing the CID and invalidating the
signed pointer.

The resolver therefore MAY compute `'sha256-…'` source expressions for the inline elements
declared in the manifest and append them to `style-src` and `script-src` for that site only.

Constraints, all normative:

- Digests MUST be computed by the resolver from the **verified** content, never taken on trust
  from the manifest. The manifest declares intent; it does not confer permission.
- A digest that does not match an element present in the verified tree MUST be discarded.
- This applies to inline elements only. It never widens the source list for remote or `data:`
  resources.
- The reader-facing security indicator MUST NOT change. Nothing has been weakened: the bytes were
  already verified.

This is the one place where content addressing buys back usability without buying risk, and it is
worth taking.

### 2.2 The two remaining relaxations

`csp.wasm: true` and `csp.trustedTypes: "<policy-name>"` are declared in the manifest, scoped to
the single site, and surfaced to the reader. Both are genuine widenings, unlike section 2.1, and
are treated as such — see [CONTENT-SECURITY.md](CONTENT-SECURITY.md) section 2.3.

### 2.3 Deep links

A site with client-side routing 404s on every deep link unless a fallback exists. On no path
match the resolver SHALL serve `notFound` with HTTP 404 if present; otherwise, if `fallback` is
declared, serve it with HTTP 200 so the site's own router can handle the path.

## 3. `webx doctor`

The publish-time checker. It runs automatically as step 1 of `webx publish` and can be run alone.

```text
$ webx doctor ./my-site

  ✗  index.html:42   inline <style> not declared in manifest
     WebX blocks inline styles unless they are declared, because an
     undeclared one is indistinguishable from an injected one.
     Fix: run `webx doctor --fix`, or move the styles to a .css file.

  ✗  about.html:8    <img src="https://cdn.example.com/logo.png">
     Remote images do not load on WebX. Every request to another server
     tells that server who is reading your page.
     Fix: save the file into your site folder and link it relatively.

  ⚠  index.html:15   <a href="https://example.com"> leaves WebX
     This works, but the reader gets a warning. That is intended.

  2 errors, 1 warning.
```

### 3.1 Requirements

3.1.1 Every diagnostic MUST name the file, the line, what will not work, **why**, and a concrete
fix. A message that states a rule without a remedy is a defect in the checker.

3.1.2 Diagnostics MUST be written for someone who has never heard of a Content-Security-Policy.
"Inline styles are blocked" is acceptable; "style-src does not include 'unsafe-inline'" is not.

3.1.3 `--fix` MUST resolve mechanically fixable findings: extracting inline blocks to files, or
declaring their digests in the manifest. It MUST NOT alter document semantics, and MUST show a
diff before writing.

3.1.4 The checker MUST detect at minimum: undeclared inline `<style>` and `<script>`; any
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

**Unpublish:** withdraw the pointer and unpin locally. This stops WebX serving it. It does not
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

1. `webx publish` on a tree that fails `webx doctor` does not write a record.
2. Every `webx doctor` diagnostic carries a file, a line, a reason and a fix.
3. Inline digests are computed from verified content; a manifest digest with no matching element
   is discarded.
4. The declared inline exception never widens the source list for remote or `data:` resources.
5. The checker runs with no network access.
6. The checker's rule set and the resolver's enforcement derive from one shared definition, and a
   test asserts a site passing the checker is served without a policy violation.
7. Local pinning completes before the pointer record is appended.

## See also

- [Position](../POSITION.md) — the four commitments this specification serves
- [Content security](CONTENT-SECURITY.md) — the profile authors are checked against
- [Hosting](HOSTING.md) — what happens to the bytes after publishing
- [Resolution](RESOLUTION.md) — how a reader reaches them
