/**
 * Pin sets, availability reporting, and unpublishing.
 *
 * docs/spec/HOSTING.md "Availability", and Constitution Articles 19, 21 and 23.
 *
 * ## This module's job is to refuse to overstate
 *
 * Almost everything here exists to stop a true number being reported in a way that means something
 * false. That is unusual for a module and it is the point: Article 21 imposes a duty of honest
 * claiming, Article 23 says availability is not guaranteed, and Article 19.7 says VayuWeb
 * guarantees the cessation of authorised publication and **not** erasure — "and no implementation
 * or document SHALL state or imply that it does".
 *
 * Three ways a correct count lies, each closed by construction rather than by careful wording:
 *
 * **Silence is not absence.** A peer that did not answer is not a peer that lacks the content. A
 * client cannot distinguish "no peer holds this" from "no peer told me", and a report that renders
 * both as `0` has invented a fact. {@link AvailabilityReport} therefore carries how many peers
 * were *asked* alongside how many answered, and never a bare count.
 *
 * **Your own pin is not redundancy.** "1 peer holds this site" reads as reassurance and means
 * nothing if that peer is you — and self-pinning-only is the single most common self-inflicted
 * failure in content-addressed publishing. Self pins are counted separately and cannot be summed
 * into the total by accident, because the total does not exist as a field.
 *
 * **A snapshot is not a forecast.** Every observation is stamped, and nothing here produces an
 * uptime percentage, a durability estimate or a projection. Article 23 forbids the figure and
 * HOSTING.md says in terms that "any document in this repository quoting an uptime number is
 * wrong". A number that cannot be computed honestly is not computed.
 */

/** How a peer came to be holding this content, which changes what its holding is worth. */
export type Holder =
  | { readonly kind: 'self' }
  | { readonly kind: 'peer'; readonly id: string }
  /** A paid service. Legitimate, and never a default — see HOSTING.md "Availability". */
  | { readonly kind: 'service'; readonly name: string };

/** One observation that a holder had the content at a moment. Never a claim about now. */
export interface Observation {
  readonly holder: Holder;
  readonly observedAt: number;
}

/**
 * What this node can honestly say about whether a CID is being kept alive.
 *
 * Deliberately awkward to summarise. There is no `total`, no `percentage` and no `durable` field,
 * because each would be a place for a caller to render a guarantee the protocol does not make.
 */
export interface AvailabilityReport {
  readonly cid: string;
  /** Peers this node asked. Without it, `answered` is a number with no denominator. */
  readonly asked: number;
  /** Peers that answered at all. Silence is recorded as silence, never as a negative answer. */
  readonly answered: number;
  /** Distinct third-party peers observed holding it. Excludes this node and excludes services. */
  readonly peersHolding: number;
  /** Paid services observed holding it, counted apart because they are a different dependency. */
  readonly servicesHolding: number;
  /** Whether this node holds it. Never added into any other count. */
  readonly selfPinned: boolean;
  /** When the newest observation was made. A report is about a past moment, not about now. */
  readonly observedAt: number | null;
  /**
   * Always true, and not removable.
   *
   * Carried as a field rather than left to documentation because a caller destructuring this
   * object has to see it. The same device is used by `checkpoint.ts` for freshness, for the same
   * reason: a caveat in prose is a caveat that does not survive being turned into a dashboard.
   */
  readonly availabilityUnguaranteed: true;
}

export class PinError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PinError';
  }
}

/**
 * A holder's identity for counting purposes.
 *
 * Two observations of one peer are one holder. Without this, a peer answering twice would read as
 * two independent copies, which is the exact overstatement this module exists to prevent — and it
 * would be an overstatement an adversary could manufacture by answering repeatedly.
 */
function identity(holder: Holder): string {
  switch (holder.kind) {
    case 'self':
      return 'self';
    case 'peer':
      return `peer:${holder.id}`;
    case 'service':
      return `service:${holder.name}`;
  }
}

/**
 * Build a report from what was asked and what came back.
 *
 * `asked` is supplied by the caller because this module cannot know it: the number of peers a
 * query reached is a property of the network layer. It is required rather than optional so that a
 * caller cannot omit the denominator and leave `answered` looking like a total.
 */
export function report(
  cid: string,
  asked: number,
  observations: readonly Observation[],
  staleAfter: number,
  now: number,
): AvailabilityReport {
  if (!Number.isSafeInteger(asked) || asked < 0) {
    throw new PinError('the number of peers asked must be a non-negative integer');
  }
  if (observations.length > asked + 1) {
    // +1 because this node may hold it without having asked itself. More answers than askees
    // otherwise means the caller has miscounted, and a report built on a miscount is worse than
    // no report: it is a wrong denominator presented with the authority of a measurement.
    throw new PinError(
      `${observations.length} observations from ${asked} peers asked — the denominator is wrong`,
    );
  }

  const fresh = observations.filter((o) => o.observedAt > now - staleAfter);
  const seen = new Map<string, Observation>();
  for (const observation of fresh) {
    const key = identity(observation.holder);
    const existing = seen.get(key);
    if (existing === undefined || observation.observedAt > existing.observedAt) {
      seen.set(key, observation);
    }
  }

  let peersHolding = 0;
  let servicesHolding = 0;
  let selfPinned = false;
  let observedAt: number | null = null;
  for (const observation of seen.values()) {
    if (observation.holder.kind === 'peer') peersHolding += 1;
    if (observation.holder.kind === 'service') servicesHolding += 1;
    if (observation.holder.kind === 'self') selfPinned = true;
    if (observedAt === null || observation.observedAt > observedAt) {
      observedAt = observation.observedAt;
    }
  }

  return {
    cid,
    asked,
    answered: seen.size,
    peersHolding,
    servicesHolding,
    selfPinned,
    observedAt,
    availabilityUnguaranteed: true,
  };
}

/**
 * The one-line summary a client may show, written so it cannot be read as a promise.
 *
 * Provided here rather than left to each caller because this is exactly the sentence that gets
 * written optimistically. Every branch names what is *observed*, never what is assured, and the
 * zero case says "nobody answered" rather than "nobody has it" — because those are different
 * facts and only one of them is known.
 */
export function summarise(report: AvailabilityReport): string {
  const parts: string[] = [];
  if (report.selfPinned) parts.push('pinned here');
  if (report.peersHolding > 0) {
    parts.push(`${report.peersHolding} other peer${report.peersHolding === 1 ? '' : 's'} answered`);
  }
  if (report.servicesHolding > 0) {
    parts.push(
      `${report.servicesHolding} pinning service${report.servicesHolding === 1 ? '' : 's'}`,
    );
  }

  if (parts.length === 0) {
    return report.asked === 0
      ? 'No peers were asked. Nothing is known about who holds this.'
      : `No peer answered out of ${report.asked} asked. That is not the same as nobody holding it.`;
  }
  if (!report.selfPinned && report.peersHolding === 0 && report.servicesHolding === 0) {
    return 'Nothing observed holding this.';
  }
  return `${parts.join(', ')}. Observed, not guaranteed.`;
}

/**
 * Whether a site is at risk of vanishing when this node goes offline.
 *
 * The warning HOSTING.md's first mitigation exists for: "one always-on node is the difference
 * between a site that loads and a site that does not". True precisely when we are the only
 * observed holder — a state that looks fine from the publisher's own machine, because from there
 * the site always loads.
 */
export function onlyThisNodeHoldsIt(report: AvailabilityReport): boolean {
  return report.selfPinned && report.peersHolding === 0 && report.servicesHolding === 0;
}

/* -------------------------------------------------------------------------- */
/* Unpublishing                                                                */
/* -------------------------------------------------------------------------- */

/** Longest a tombstoned binding may survive in any cache. Article 19.4. */
export const TOMBSTONE_CACHE_SECONDS = 3_600;

/**
 * What unpublishing actually does, enumerated so a client cannot imply more.
 *
 * Article 19.1 opens by saying it is "stated with deliberate precision, because unpublishing is
 * where charters lie". The two lists below are that precision, and they are data rather than prose
 * so that a user interface has to render both or deliberately drop one.
 */
export const UNPUBLISH_EFFECTS = {
  /** Article 19.2: what a registrant can always do. */
  guaranteed: [
    'stop serving the content from your own infrastructure',
    'unpin it locally',
    'break the name-to-content binding',
    'publish a signed tombstone that conformant clients must honour',
    'relinquish the name',
    'destroy the ownership key',
  ],
  /** Article 19.6: what cannot be guaranteed, and must be stated plainly everywhere. */
  notGuaranteed: [
    'the registry is append-only: that the name existed, which key signed for it, what it pointed to and when, is permanent for anyone who has already replicated it',
    'a tombstone adds a record; it removes nothing',
    'content already retrieved by others may be re-pinned and re-served indefinitely, by parties you will never identify',
    'no protocol mechanism can compel a third party to delete bytes they already hold',
  ],
} as const;

/**
 * Whether a cached binding must now be dropped because a tombstone was observed.
 *
 * Article 19.4 caps retention at 3600 seconds after observation — long enough to survive ordinary
 * propagation delay, short enough to bound exposure. The bound runs from when the tombstone was
 * *observed*, not from when it was signed: a client cannot be held to a deadline that started
 * before it heard anything.
 */
export function tombstonedBindingExpired(observedAt: number, now: number): boolean {
  return now - observedAt >= TOMBSTONE_CACHE_SECONDS;
}
