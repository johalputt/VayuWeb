/**
 * The content type of a served file, and the table that decides it.
 *
 * ## Why this is its own module
 *
 * RESOLUTION.md step 14 says a resolver emits "a `Content-Type` from the file extension". It
 * does not say which extensions map to which types, so the table is an implementation choice —
 * and two implementations of it in one project are two answers to a question a browser asks on
 * every single request.
 *
 * The client's serving surface answered it with twenty-eight extensions. **The browsing proxy
 * answered it with nine**, and everything else — a webfont, a module script, an icon, a video —
 * was served as `application/octet-stream` under `X-Content-Type-Options: nosniff`. A browser
 * refuses a stylesheet, a font or a module script whose type it does not recognise, so a site
 * published with a webfont and a `.mjs` module rendered with no typeface and no script, and the
 * Phase 3 acceptance test passed anyway because it exercised exactly the three types the nine
 * covered.
 *
 * ## Why the table is pinned rather than merely written
 *
 * The table is wire-visible and it is the kind of fact that drifts quietly: an extension added
 * to one implementation and not the other is a site that renders in the preview and not in the
 * proxy. The `mime` suite in `conformance/vectors.json` states the table — one vector per
 * extension, with the type every implementation must answer — and both implementations are
 * checked against it.
 */

/**
 * The extensions and their types.
 *
 * The same set the client's serving surface answers, extension for extension and type for type.
 * The order is the order the client's table uses, so the two read alike.
 */
export const MIME_TYPES: Readonly<Record<string, string>> = {
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  json: 'application/json',
  map: 'application/json',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  ico: 'image/x-icon',
  txt: 'text/plain; charset=utf-8',
  text: 'text/plain; charset=utf-8',
  log: 'text/plain; charset=utf-8',
  csv: 'text/plain; charset=utf-8',
  md: 'text/markdown; charset=utf-8',
  xml: 'application/xml',
  pdf: 'application/pdf',
  wasm: 'application/wasm',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  otf: 'font/otf',
  mp3: 'audio/mpeg',
  ogg: 'audio/ogg',
  oga: 'audio/ogg',
  wav: 'audio/wav',
  mp4: 'video/mp4',
  webm: 'video/webm',
};

/** What a file with no recognised extension is served as. */
export const DEFAULT_CONTENT_TYPE = 'application/octet-stream';

/**
 * The content type of a path, from its extension.
 *
 * The extension is everything after the LAST dot, lowercased. A path with no dot at all has no
 * extension — the whole path is compared, matches nothing, and is served as bytes.
 */
export function contentTypeOf(path: string): string {
  const extension = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  return MIME_TYPES[extension] ?? DEFAULT_CONTENT_TYPE;
}
