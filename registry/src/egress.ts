/**
 * The single choke point.
 *
 * PRIVACY.md section 3.1: "Every outbound byte — registry replication, peer discovery, content
 * fetch, and any future subsystem — MUST pass through **one** guarded transport constructor. No
 * component may open a socket by any other means."
 *
 * The section's own words say why this file exists: "The recurring failure in systems like this
 * is not a broken guard — it is a **new call site that never called the guard**, added a year
 * later by someone who did not know it existed." A guard that lives in one place is still a guard
 * that a later author can bypass by not knowing about it, which is why the same paragraph asks for
 * a build-time check as well. `scripts/check-single-choke-point.py` is that check: it fails when
 * any file outside this one opens an outbound socket, so the second author finds out from CI
 * rather than from a leak.
 *
 * ## What the guard does today, and what it cannot do yet
 *
 * The guard is the mode. In Private Mode the anonymising transport is mandatory, and section 3.3
 * is unambiguous that when the transport is unavailable the resolver **refuses**: it does not fall
 * back to a direct connection, does not queue the request, does not offer a "continue anyway", and
 * does not degrade to Standard Mode.
 *
 * **The transport itself does not exist yet.** It is Phase 4, and Phase 4 is waiting on an
 * editorial transition this project cannot perform alone. So the private branch of this guard
 * refuses rather than dialling, and it says why in the message: the honest behaviour of a build
 * with no anonymising transport is to refuse every outbound byte, not to open a socket and hope
 * nobody was relying on it. When the transport arrives, the private branch stops refusing and
 * starts dialling through it — and the test that pins the refusal will be rewritten to pin the
 * dial, because a test that passes for the wrong reason is worse than no test.
 *
 * There is no private mode in this implementation yet either, so the only mode the rest of the
 * tree can name is `clearnet`. The mode is a parameter of this function rather than a constant
 * read from a global, because a guard that reads its own configuration from somewhere it does not
 * control is a guard whose behaviour depends on who is asking.
 *
 * ## What this does not do
 *
 * It does not decide whether a destination is part of the VayuWeb network. Section 3.2's
 * destination policy is the browsing proxy's, and it lives with the proxy, which refuses a
 * destination before anything is dialled. This file is about the socket, not the destination.
 *
 * It does not authenticate the peer, and nothing here treats a connection as evidence about a
 * record. REPLICATION.md 2.3 is load-bearing and this module does not weaken it: the channel
 * carries bytes, and the bytes carry their own signatures.
 */

import { createConnection, type Socket } from 'node:net';

/**
 * What a socket is for.
 *
 * Not decoration. A purpose is what a later author has to name to open a socket, and naming it
 * is the moment they have to think about whether the byte they are about to send is one this
 * project is allowed to send.
 */
export type Purpose = 'peer' | 'replication' | 'fetch';

/** The mode the resolver is in. PRIVACY.md section 2. */
export type Mode = 'clearnet' | 'private';

/** A destination, as a host and a port. */
export interface Address {
  host: string;
  port: number;
}

/**
 * The refusal.
 *
 * Its own type rather than a bare `Error`, so a caller can tell a refusal from a failure to
 * connect: the first is a decision, and the second is a fact about the network.
 */
export class EgressRefused extends Error {
  readonly purpose: Purpose;

  constructor(purpose: Purpose, reason: string) {
    super(reason);
    this.name = 'EgressRefused';
    this.purpose = purpose;
  }
}

/**
 * Open the one socket this implementation is allowed to open.
 *
 * Throws {@link EgressRefused} in Private Mode, before any socket is created, and never falls
 * back to a direct connection.
 */
export function dial(purpose: Purpose, address: Address, mode: Mode): Promise<Socket> {
  if (mode === 'private') {
    // No socket, no queue, no fallback, no prompt. Section 3.3 forbids all four, and the message
    // says which of them is missing rather than implying the network is down.
    return Promise.reject(
      new EgressRefused(
        purpose,
        `refusing to open a ${purpose} socket to ${address.host}:${address.port}: ` +
          'this resolver is in Private Mode and the anonymising transport is not available. ' +
          'PRIVACY.md 3.3 forbids a direct connection, a queue, and a fallback.',
      ),
    );
  }
  return new Promise<Socket>((resolve, reject) => {
    const socket = createConnection({ host: address.host, port: address.port });
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}
