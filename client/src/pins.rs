//! What this node may honestly say about whether a pin is being kept alive.
//!
//! The Rust counterpart of `registry/src/pins.ts`, and it exists for the same reason that
//! module does: **almost everything in it exists to stop a true number being reported in a way
//! that means something false.** Constitution Article 21 imposes a duty of honest claiming,
//! Article 23 says availability is not guaranteed, and Article 19.7 says VayuWeb guarantees the
//! cessation of authorised publication and **not** erasure.
//!
//! Three ways a correct count lies, each closed by construction rather than by careful wording:
//!
//! - **Silence is not absence.** A peer that did not answer is not a peer that lacks the content.
//!   A report carries how many peers were *asked* alongside how many answered, and never a bare
//!   count.
//! - **Your own pin is not redundancy.** "1 peer holds this site" reads as reassurance and means
//!   nothing if that peer is you. Self pins are counted separately and cannot be summed into a
//!   total, because the total does not exist as a field.
//! - **A snapshot is not a forecast.** Every observation is stamped, and nothing here produces an
//!   uptime percentage, a durability estimate or a projection. Article 23 forbids the figure, so
//!   the number is not computed.
//!
//! ## What is NOT mirrored, and why
//!
//! The reference module also carries a bounded `PinSet` — a set of CIDs this node undertakes to
//! serve, with a capacity and a refusal to evict. The client does not mirror it, and that is a
//! deliberate difference rather than an omission: the client has no separate notion of "undertaken
//! to keep". Everything in its block store is kept, and `vayu unpublish` removes blocks outright
//! rather than releasing a promise about them. A mirror of the class would be a class with no
//! caller, and a module that exists only to mirror something is not what this one is for.

use std::collections::HashMap;

/// How a peer came to be holding the content, which changes what its holding is worth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// This node.
    ThisNode,
    /// A peer.
    Peer(String),
    /// A paid service. Legitimate, and never a default — see HOSTING.md "Availability".
    Service(String),
}

impl Holder {
    /// A holder's identity for counting purposes: two sightings of the same peer are one holder.
    fn identity(&self) -> String {
        match self {
            Self::ThisNode => "self".to_string(),
            Self::Peer(id) => format!("peer:{id}"),
            Self::Service(name) => format!("service:{name}"),
        }
    }
}

/// One observation that a holder had the content at a moment. Never a claim about now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub holder: Holder,
    pub observed_at: u64,
}

/// What this node can honestly say about whether a CID is being kept alive.
///
/// Deliberately awkward to summarise. There is no `total`, no `percentage` and no `durable`
/// field, because each would be a place for a caller to render a guarantee the protocol does not
/// make — and the type itself is where that is enforced: a caller cannot read a number that is
/// not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityReport {
    pub cid: String,
    /// Peers this node asked. Without it, `answered` is a number with no denominator.
    pub asked: u64,
    /// Peers that answered at all. Silence is recorded as silence, never as a negative answer.
    pub answered: u64,
    /// Distinct third-party peers observed holding it. Excludes this node and excludes services.
    pub peers_holding: u64,
    /// Paid services observed holding it, counted apart because they are a different dependency.
    pub services_holding: u64,
    /// Whether this node holds it. Never added into any other count.
    pub self_pinned: bool,
    /// When the newest observation was made. A report is about a past moment, not about now.
    pub observed_at: Option<u64>,
    /// Always true, and not removable.
    ///
    /// Carried as a field rather than left to documentation because a caller destructuring this
    /// value has to see it.
    pub availability_unguaranteed: bool,
}

/// Why a report could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The number of peers asked is not a count.
    AskedNotACount,
    /// More answers than askees: the denominator is wrong, and a report built on a miscount is
    /// worse than no report.
    DenominatorWrong { observations: usize, asked: u64 },
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AskedNotACount => {
                write!(
                    f,
                    "the number of peers asked must be a non-negative integer"
                )
            }
            Self::DenominatorWrong {
                observations,
                asked,
            } => write!(
                f,
                "{observations} observations from {asked} peers asked — the denominator is wrong"
            ),
        }
    }
}

impl std::error::Error for PinError {}

/// Build a report from what was asked and what came back.
///
/// `asked` is supplied by the caller because this module cannot know it: the number of peers a
/// query reached is a property of the network layer. It is required rather than optional so that
/// a caller cannot omit the denominator and leave `answered` looking like a total.
pub fn report(
    cid: &str,
    asked: u64,
    observations: &[Observation],
    stale_after: u64,
    now: u64,
) -> Result<AvailabilityReport, PinError> {
    // +1 because this node may hold it without having asked itself. More answers than askees
    // otherwise means the caller has miscounted, and a report built on a miscount is worse than
    // no report: it is a wrong denominator presented with the authority of a measurement.
    if observations.len() as u64 > asked.saturating_add(1) {
        return Err(PinError::DenominatorWrong {
            observations: observations.len(),
            asked,
        });
    }

    let mut seen: HashMap<String, &Observation> = HashMap::new();
    for observation in observations {
        // A sighting older than the window is not a sighting. `>` and not `>=`: an observation
        // exactly `stale_after` old has expired.
        if observation.observed_at <= now.saturating_sub(stale_after) {
            continue;
        }
        let key = observation.holder.identity();
        match seen.get(&key) {
            Some(existing) if existing.observed_at >= observation.observed_at => {}
            _ => {
                seen.insert(key, observation);
            }
        }
    }

    let mut peers_holding = 0u64;
    let mut services_holding = 0u64;
    let mut self_pinned = false;
    let mut observed_at: Option<u64> = None;
    for observation in seen.values() {
        match observation.holder {
            Holder::Peer(_) => peers_holding += 1,
            Holder::Service(_) => services_holding += 1,
            Holder::ThisNode => self_pinned = true,
        }
        observed_at = Some(match observed_at {
            Some(current) => current.max(observation.observed_at),
            None => observation.observed_at,
        });
    }

    Ok(AvailabilityReport {
        cid: cid.to_string(),
        asked,
        answered: seen.len() as u64,
        peers_holding,
        services_holding,
        self_pinned,
        observed_at,
        availability_unguaranteed: true,
    })
}

/// The one-line summary a client may show, written so it cannot be read as a promise.
///
/// Provided here rather than left to each caller because this is exactly the sentence that gets
/// written optimistically. Every branch names what is *observed*, never what is assured, and the
/// zero case says "nobody answered" rather than "nobody has it" — because those are different
/// facts and only one of them is known.
pub fn summarise(report: &AvailabilityReport) -> String {
    let mut parts: Vec<String> = Vec::new();
    if report.self_pinned {
        parts.push("pinned here".to_string());
    }
    if report.peers_holding > 0 {
        parts.push(format!(
            "{} other peer{} answered",
            report.peers_holding,
            if report.peers_holding == 1 { "" } else { "s" }
        ));
    }
    if report.services_holding > 0 {
        parts.push(format!(
            "{} pinning service{}",
            report.services_holding,
            if report.services_holding == 1 {
                ""
            } else {
                "s"
            }
        ));
    }

    if parts.is_empty() {
        return if report.asked == 0 {
            "No peers were asked. Nothing is known about who holds this.".to_string()
        } else {
            format!(
                "No peer answered out of {} asked. That is not the same as nobody holding it.",
                report.asked
            )
        };
    }

    // **The self-only case says the consequence, and it did not.** It produced "pinned here.
    // Observed, not guaranteed." — a true sentence that reads as reassurance, which is the exact
    // failure this module's own header names: "'1 peer holds this site' reads as reassurance and
    // means nothing if that peer is you". The warning is IN the sentence, so a caller who does not
    // think to ask for it still gets it.
    if only_this_node_holds_it(report) {
        return if report.asked == 0 {
            "pinned here, and no peer has been asked. Nothing is known about who else holds it — \
             if this node goes offline the site stops loading."
                .to_string()
        } else {
            format!(
                "pinned here, and none of the {} peers asked answered for it — if this node goes \
                 offline the site stops loading. Observed, not guaranteed.",
                report.asked
            )
        };
    }
    format!("{}. Observed, not guaranteed.", parts.join(", "))
}

/// Whether a site is at risk of vanishing when this node goes offline.
///
/// The warning HOSTING.md's first mitigation exists for: "one always-on node is the difference
/// between a site that loads and a site that does not". True precisely when we are the only
/// observed holder — a state that looks fine from the publisher's own machine, because from there
/// the site always loads.
pub fn only_this_node_holds_it(report: &AvailabilityReport) -> bool {
    report.self_pinned && report.peers_holding == 0 && report.services_holding == 0
}

/// How long an observation counts for, when the caller has no policy of its own.
///
/// A policy question rather than a protocol number: the specification says a report is about a
/// past moment and never says how long a moment stays interesting. Five minutes is the client's
/// own choice, and it is a choice this module names rather than hides.
pub const DEFAULT_STALE_AFTER_SECONDS: u64 = 300;

/// Article 19.4's bound on retaining a tombstoned binding: one hour after it is observed.
///
/// The client does not implement tombstone honouring — the operation set has no TOMBSTONE record,
/// and REGISTRY.md's own table says so — but the bound belongs with the rest of Article 19's
/// limits, and a client that later grows one must not grow it without the hour.
pub const TOMBSTONE_CACHE_SECONDS: u64 = 3_600;

/// Whether a tombstoned binding may now be dropped from a cache.
pub fn tombstoned_binding_expired(observed_at: u64, now: u64) -> bool {
    now.saturating_sub(observed_at) >= TOMBSTONE_CACHE_SECONDS
}

/// What unpublishing does, held as lists rather than prose so that an interface has to render
/// them or deliberately drop them.
///
/// Article 19.1 opens by saying it is stated with deliberate precision, because unpublishing is
/// where charters lie. The `guaranteed` list is Article 19.2's list of acts — and it is the
/// CHARTER's list, not a list of things an implementation can do today: one of the six cannot be
/// done by any conformant implementation, because the operation set has no record that carries it.
/// `not_expressible` names that act, and the substitute the specification itself names.
pub const UNPUBLISH_EFFECTS_GUARANTEED: [&str; 6] = [
    "stop serving the content from your own infrastructure",
    "unpin it locally",
    "break the name-to-content binding",
    "publish a signed tombstone that conformant clients must honour",
    "relinquish the name",
    "destroy the ownership key",
];

/// Article 19.6: what cannot be guaranteed, and must be stated plainly everywhere.
pub const UNPUBLISH_EFFECTS_NOT_GUARANTEED: [&str; 4] = [
    "the registry is append-only: that the name existed, which key signed for it, what it pointed \
     to and when, is permanent for anyone who has already replicated it",
    "a tombstone adds a record; it removes nothing",
    "content already retrieved by others may be re-pinned and re-served indefinitely, by parties \
     you will never identify",
    "no protocol mechanism can compel a third party to delete bytes they already hold",
];

/// An act the charter grants and the current operation set cannot express.
///
/// Kept apart from [`UNPUBLISH_EFFECTS_GUARANTEED`] so that a client can render the charter's
/// list without claiming a capability no conformant peer would accept: REGISTRY.md's own operation
/// table records `TOMBSTONE` as absent, and Article 29.4 requires a record of an unrecognised type
/// to be refused.
pub struct NotExpressible {
    pub act: &'static str,
    pub why: &'static str,
    pub substitute: &'static str,
}

/// The one act the protocol cannot express, and what it uses instead.
pub const UNPUBLISH_EFFECTS_NOT_EXPRESSIBLE: [NotExpressible; 1] = [NotExpressible {
    act: "publish a signed tombstone that conformant clients must honour",
    why:
        "the operation set closes at six and TOMBSTONE is not among them: Article 29.4 requires a \
          record of an unrecognised type to be refused, so no conformant peer would honour one",
    substitute: "an UPDATE carrying no entries breaks the binding, which is the substitute \
                 REGISTRY.md names in the same table; it has no record of its own to carry a cache \
                 bound or a signer rule",
}];

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_782_518_400;
    const STALE: u64 = 300;

    fn self_at(at: u64) -> Observation {
        Observation {
            holder: Holder::ThisNode,
            observed_at: at,
        }
    }
    fn peer(id: &str, at: u64) -> Observation {
        Observation {
            holder: Holder::Peer(id.to_string()),
            observed_at: at,
        }
    }
    fn service(name: &str, at: u64) -> Observation {
        Observation {
            holder: Holder::Service(name.to_string()),
            observed_at: at,
        }
    }

    #[test]
    fn silence_is_not_absence() {
        let report = report("cid", 3, &[], STALE, NOW).expect("reports");
        assert_eq!(report.answered, 0);
        assert_eq!(report.peers_holding, 0);
        assert_eq!(report.observed_at, None);
        assert_eq!(
            summarise(&report),
            "No peer answered out of 3 asked. That is not the same as nobody holding it."
        );
    }

    #[test]
    fn a_self_pin_is_not_redundancy() {
        let report = report("cid", 3, &[self_at(NOW)], STALE, NOW).expect("reports");
        assert!(report.self_pinned);
        assert!(only_this_node_holds_it(&report));
        assert_eq!(
            summarise(&report),
            "pinned here, and none of the 3 peers asked answered for it — if this node goes offline \
             the site stops loading. Observed, not guaranteed."
        );
    }

    #[test]
    fn one_peer_answering_twice_is_one_holder() {
        let report = report(
            "cid",
            2,
            &[peer("one", NOW - 10), peer("one", NOW)],
            STALE,
            NOW,
        )
        .expect("reports");
        assert_eq!(report.answered, 1);
        assert_eq!(report.peers_holding, 1);
    }

    #[test]
    fn a_stale_sighting_is_not_a_current_one() {
        let report =
            report("cid", 2, &[peer("one", NOW - STALE - 1)], STALE, NOW).expect("reports");
        assert_eq!(report.answered, 0);
        assert_eq!(report.observed_at, None);
    }

    #[test]
    fn a_service_is_counted_apart_from_a_peer() {
        // A paid service is a legitimate holder and a different dependency from a peer. Folding
        // the two together would report "1 peer answered" for a site whose only other holder is
        // a service — a claim about a peer that does not exist.
        let report = report("cid", 2, &[service("pin-service", NOW)], STALE, NOW).expect("reports");
        assert_eq!(report.peers_holding, 0);
        assert_eq!(report.services_holding, 1);
        assert_eq!(report.answered, 1);
        assert!(!only_this_node_holds_it(&report));
        assert_eq!(
            summarise(&report),
            "1 pinning service. Observed, not guaranteed."
        );
    }

    #[test]
    fn a_wrong_denominator_is_refused() {
        // Asked nobody, yet two holders are claimed. The bound is asked + 1, because this node
        // may hold it without having asked itself.
        assert_eq!(
            report("cid", 0, &[self_at(NOW), peer("one", NOW)], STALE, NOW),
            Err(PinError::DenominatorWrong {
                observations: 2,
                asked: 0
            })
        );
        // And asked one, with this node and one peer, is exactly the bound.
        assert!(report("cid", 1, &[self_at(NOW), peer("one", NOW)], STALE, NOW).is_ok());
    }

    #[test]
    fn a_report_carries_no_figure_article_23_forbids() {
        // The type has no `total`, no `percentage` and no `uptime`, and this test is what a
        // reader checks when they want to add one.
        let report = report("cid", 1, &[peer("one", NOW)], STALE, NOW).expect("reports");
        let text = format!("{report:?}");
        for word in ["percentage", "uptime", "total", "durable"] {
            assert!(!text.contains(word), "the report must not carry {word}");
        }
    }
}
