/**
 * Label grammar, reserved labels and the ratified TLD set.
 *
 * docs/spec/NAMES.md is authoritative. Nothing here relaxes it, and where the specification
 * and this module could disagree the specification wins — a peer that accepts a name others
 * reject has forked the namespace, which is indistinguishable from a bug until someone loses
 * a name over it.
 *
 * Two defects were found in NAMES.md while writing this and corrected there rather than
 * worked around here:
 *
 *   1. The ABNF read `tld = 2*12( %x61-7A )` — lowercase letters only — while the founding
 *      extension list contains `.p2p`. The founding set was invalid under its own grammar.
 *      Since REGISTRY.md validates a TLD by membership of the ratified set rather than by
 *      re-deriving the grammar, and the grammar governs what a *new* TLD may be, the grammar
 *      was widened to admit digits after the first character. Deleting `.p2p` would have
 *      removed a namespace; inventing a digit rule for one TLD would have been worse.
 *   2. `.vayu` was listed twice with two different descriptions, so a list introduced as
 *      "twelve" held eleven distinct entries. The duplicate was an editing error; the count
 *      was corrected rather than a twelfth namespace invented.
 */

/**
 * The ratified TLDs at launch.
 *
 * REGISTRY.md validates by membership of this set — `if rec.tld not in RATIFIED_TLDS: reject
 * UNKNOWN_TLD` — so this constant is wire-visible. Adding to it requires a ratified VWIP with
 * a two-thirds supermajority and a collision analysis, per NAMES.md. It is frozen here so that
 * an accidental edit is a failing test rather than a silent namespace change.
 */
export const RATIFIED_TLDS: ReadonlySet<string> = new Set([
  'vayu',
  'p2p',
  'free',
  'decent',
  'libre',
  'sov',
  'dao',
  'indie',
  'open',
  'news',
  'blog',
]);

/** Maximum label length in characters, which for ASCII is also bytes. */
export const MAX_LABEL_LENGTH = 63;

/** Maximum TLD length in characters. */
export const MAX_TLD_LENGTH = 12;

/** Why a name was refused. Distinct codes so a resolver can report precisely. */
export type NameRejection =
  | 'EMPTY'
  | 'TOO_LONG'
  | 'BAD_CHARACTER'
  | 'LEADING_HYPHEN'
  | 'TRAILING_HYPHEN'
  | 'RESERVED_IDN_SHAPE'
  | 'RESERVED_LABEL'
  | 'UNKNOWN_TLD'
  | 'BAD_TLD_SHAPE';

export class NameError extends Error {
  readonly code: NameRejection;
  constructor(code: NameRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'NameError';
    this.code = code;
  }
}

const LABEL_CHARACTER = /^[a-z0-9-]$/;

/**
 * Validate a label against NAMES.md, returning the specific rejection or null when valid.
 *
 * The checks are ordered from cheapest and most specific to most general, so that the code a
 * caller sees is the most informative one available rather than whichever happened to run
 * first. Order does not affect *whether* a label is accepted, only which reason is reported,
 * and two implementations reporting different reasons for the same refusal still interoperate.
 */
export function labelRejection(label: string): NameRejection | null {
  if (label.length === 0) return 'EMPTY';
  if (label.length > MAX_LABEL_LENGTH) return 'TOO_LONG';

  for (const character of label) {
    // Explicitly ASCII: a non-ASCII character is a BAD_CHARACTER rather than something to
    // normalise. NAMES.md requires a peer to "reject a non-conforming label rather than
    // silently canonicalising it, so that the byte sequence a user signs is exactly the one
    // the log stores".
    if (!LABEL_CHARACTER.test(character)) return 'BAD_CHARACTER';
  }

  if (label.startsWith('-')) return 'LEADING_HYPHEN';
  if (label.endsWith('-')) return 'TRAILING_HYPHEN';

  // Positions 3 and 4, one-indexed, must not both be hyphens. This reserves the `xx--` shape
  // used to signal internationalised labels elsewhere, so a future IDN VWIP can adopt a
  // prefixed encoding without colliding with names already registered.
  if (label.length >= 4 && label[2] === '-' && label[3] === '-') return 'RESERVED_IDN_SHAPE';

  // All 36 single-character and all 1,296 two-character labels are withheld in every TLD,
  // pending an allocation VWIP. Their value comes from scarcity, so first-come allocation
  // would turn a governance question into a race.
  if (label.length <= 2) return 'RESERVED_LABEL';

  return null;
}

/** True when `label` satisfies the grammar and is not reserved. */
export function isValidLabel(label: string): boolean {
  return labelRejection(label) === null;
}

/**
 * Validate a TLD string's *shape*, independent of ratification.
 *
 * Membership of {@link RATIFIED_TLDS} is what REGISTRY.md validates against; this function
 * exists for the VWIP path, where a proposed TLD must satisfy the grammar before it can be
 * considered. A string can be well-shaped and unratified, and that combination is a
 * legitimate proposal rather than an error.
 */
export function isWellShapedTld(tld: string): boolean {
  if (tld.length < 2 || tld.length > MAX_TLD_LENGTH) return false;
  if (!/^[a-z]/.test(tld)) return false;
  return /^[a-z][a-z0-9]*$/.test(tld);
}

/** True when `tld` is in the ratified launch set. */
export function isRatifiedTld(tld: string): boolean {
  return RATIFIED_TLDS.has(tld);
}

/**
 * Validate a full `label.tld` pair, returning the rejection or null.
 *
 * Takes the parts separately rather than a joined string: the record carries `name` and `tld`
 * as distinct fields, and re-splitting a joined form would introduce a parsing step that the
 * wire format does not have.
 */
export function nameRejection(label: string, tld: string): NameRejection | null {
  if (!isWellShapedTld(tld)) return 'BAD_TLD_SHAPE';
  if (!isRatifiedTld(tld)) return 'UNKNOWN_TLD';
  return labelRejection(label);
}

/** Throw {@link NameError} unless `label.tld` is valid. */
export function assertValidName(label: string, tld: string): void {
  const rejection = nameRejection(label, tld);
  if (rejection !== null) {
    throw new NameError(rejection, `${label}.${tld} is not a valid VayuWeb name`);
  }
}

/**
 * Parse an `alias` entry value into its parts.
 *
 * Returns null when the value is not a well-formed, ratified `label.tld`. An alias pointing at
 * a name that cannot exist is a defect in the record, not a resolution failure to discover
 * later: REGISTRY.md has resolvers follow at most three hops and fail on a cycle, and a
 * malformed target would otherwise consume a hop before failing.
 */
export function parseAlias(value: string): { label: string; tld: string } | null {
  const separator = value.indexOf('.');
  if (separator <= 0 || separator === value.length - 1) return null;
  // Exactly one dot: `a.b.c` is not a VayuWeb name, and accepting it would invite a resolver
  // to guess which part is the TLD.
  if (value.indexOf('.', separator + 1) !== -1) return null;

  const label = value.slice(0, separator);
  const tld = value.slice(separator + 1);
  if (nameRejection(label, tld) !== null) return null;
  return { label, tld };
}
