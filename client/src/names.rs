//! Label grammar, reserved labels and the ratified TLD set.
//!
//! The client-side counterpart of `registry/src/names.ts`; docs/spec/NAMES.md is authoritative
//! and nothing here relaxes it. Where this module and the specification could disagree the
//! specification wins — a client that offers to register a name its peers will reject has not
//! merely failed to register it, it has signed bytes attesting an ownership fact nobody else
//! will ever accept.
//!
//! The ratified TLD set lives in [`crate::namespace_generated`], generated from the Namespace
//! Annex by `scripts/generate-namespace.py` alongside the registry's own copy. Article 2.31:
//! a Node decides TLD validity from the copy it holds, computed offline, with no query to any
//! party — which is why the set is compiled in rather than fetched.

use crate::namespace_generated::NAMESPACE_ANNEX;

/// Labels withheld in every extension. NAMES.md, "Reserved labels".
///
/// "A registration operation naming one of them is invalid and MUST be rejected by every peer,
/// not merely ignored; an invalid operation never becomes an ownership fact."
///
/// `_vayu` appears in the specification's table and not here: underscore is not in the label
/// character set, so the grammar refuses it before reservation is ever consulted. Listing it
/// would be a second, weaker check for a string the first check already cannot admit.
pub const RESERVED_LABELS: [&str; 12] = [
    // Host-prefix confusion.
    "www",
    // RFC 6761 special-use: a resolver must treat it as loopback, never resolve it through
    // VayuWeb.
    "localhost",
    // RFC 2606, reserved for documentation and testing.
    "example",
    "invalid",
    "test",
    // Protocol identity, withheld in every extension including `.vayu` so no holder speaks as
    // the protocol.
    "vayu",
    // The resolver's own control surface, and proxy auto-configuration conventions.
    "control",
    "api",
    "resolver",
    "proxy",
    "pac",
    "wpad",
];

/// Maximum label length in characters, which for ASCII is also bytes.
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum TLD length in characters.
pub const MAX_TLD_LENGTH: usize = 12;

/// Why a name was refused. Distinct codes so a caller can report precisely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameRejection {
    Empty,
    TooLong,
    BadCharacter,
    LeadingHyphen,
    TrailingHyphen,
    ReservedIdnShape,
    ReservedLabel,
    UnknownTld,
    BadTldShape,
}

impl NameRejection {
    /// The wire-visible code the registry's verifier reports for the same refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "EMPTY",
            Self::TooLong => "TOO_LONG",
            Self::BadCharacter => "BAD_CHARACTER",
            Self::LeadingHyphen => "LEADING_HYPHEN",
            Self::TrailingHyphen => "TRAILING_HYPHEN",
            Self::ReservedIdnShape => "RESERVED_IDN_SHAPE",
            Self::ReservedLabel => "RESERVED_LABEL",
            Self::UnknownTld => "UNKNOWN_TLD",
            Self::BadTldShape => "BAD_TLD_SHAPE",
        }
    }
}

fn is_label_character(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

/// Validate a label against NAMES.md, returning the specific rejection or None when valid.
///
/// The checks are ordered from cheapest and most specific to most general, matching the
/// reference implementation, so the reason a caller sees is the most informative one available.
/// Order does not affect WHETHER a label is accepted, only which reason is reported, and two
/// implementations reporting different reasons for one refusal still interoperate.
pub fn label_rejection(label: &str) -> Option<NameRejection> {
    if label.is_empty() {
        return Some(NameRejection::Empty);
    }
    if label.chars().count() > MAX_LABEL_LENGTH {
        return Some(NameRejection::TooLong);
    }

    for character in label.chars() {
        // Explicitly ASCII: a non-ASCII character is a refusal rather than something to
        // normalise. NAMES.md requires a peer to reject a non-conforming label rather than
        // silently canonicalising it, so the byte sequence a user signs is exactly the one the
        // log stores.
        if !is_label_character(character) {
            return Some(NameRejection::BadCharacter);
        }
    }

    if label.starts_with('-') {
        return Some(NameRejection::LeadingHyphen);
    }
    if label.ends_with('-') {
        return Some(NameRejection::TrailingHyphen);
    }

    // Positions 3 and 4, one-indexed, must not both be hyphens. This reserves the `xx--`
    // shape used to signal internationalised labels elsewhere, so a future IDN VWIP can adopt
    // a prefixed encoding without colliding with names already registered. Bytes are safe
    // here: the character check above has already refused every non-ASCII input.
    let bytes = label.as_bytes();
    if bytes.len() >= 4 && bytes[2] == b'-' && bytes[3] == b'-' {
        return Some(NameRejection::ReservedIdnShape);
    }

    // All 36 single-character and all 1,296 two-character labels are withheld in every TLD,
    // pending an allocation VWIP. Their value comes from scarcity, so first-come allocation
    // would turn a governance question into a race.
    if label.chars().count() <= 2 {
        return Some(NameRejection::ReservedLabel);
    }

    if RESERVED_LABELS.contains(&label) {
        return Some(NameRejection::ReservedLabel);
    }

    None
}

/// Validate a TLD string's SHAPE, independent of ratification.
///
/// Membership of the ratified set is what REGISTRY.md validates against; shape checking exists
/// for the VWIP path, where a proposed TLD must satisfy the grammar before it can be
/// considered. A string can be well-shaped and unratified, and that combination is a
/// legitimate proposal rather than an error.
pub fn is_well_shaped_tld(tld: &str) -> bool {
    let length = tld.chars().count();
    if !(2..=MAX_TLD_LENGTH).contains(&length) {
        return false;
    }
    let mut characters = tld.chars();
    match characters.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// True when `tld` is in the ratified launch set.
pub fn is_ratified_tld(tld: &str) -> bool {
    NAMESPACE_ANNEX.contains(&tld)
}

/// Validate a full `label.tld` pair, returning the rejection or None.
///
/// Takes the parts separately rather than a joined string: the record carries `name` and `tld`
/// as distinct fields, and re-splitting a joined form would introduce a parsing step the wire
/// format does not have.
pub fn name_rejection(label: &str, tld: &str) -> Option<NameRejection> {
    if !is_well_shaped_tld(tld) {
        return Some(NameRejection::BadTldShape);
    }
    if !is_ratified_tld(tld) {
        return Some(NameRejection::UnknownTld);
    }
    label_rejection(label)
}

/// A well-formed alias target: exactly one dot separating a valid label from a ratified TLD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub label: String,
    pub tld: String,
}

/// Parse an `alias` entry value into its parts.
///
/// Returns None when the value is not a well-formed, ratified `label.tld`. An alias pointing
/// at a name that cannot exist is a defect in the record, not a resolution failure to discover
/// later: REGISTRY.md has resolvers follow at most three hops and fail on a cycle, and a
/// malformed target would otherwise consume a hop before failing.
pub fn parse_alias(value: &str) -> Option<Alias> {
    let separator = value.find('.')?;
    if separator == 0 || separator == value.len() - 1 {
        return None;
    }
    // Exactly one dot: `a.b.c` is not a VayuWeb name, and accepting it would invite a resolver
    // to guess which part is the TLD.
    if value[separator + 1..].contains('.') {
        return None;
    }

    let label = &value[..separator];
    let tld = &value[separator + 1..];
    if name_rejection(label, tld).is_some() {
        return None;
    }
    Some(Alias {
        label: label.to_string(),
        tld: tld.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_generated::NAMESPACE_ANNEX_SIZE;

    #[test]
    fn the_annex_copies_agree_between_the_two_languages() {
        // The Rust copy is generated from the same Annex run as the registry's TypeScript
        // constant; both carry the count so a miscount is visible in either language.
        assert_eq!(NAMESPACE_ANNEX.len(), NAMESPACE_ANNEX_SIZE);
        // The founding extensions named in the charter text itself survive loss of the Annex;
        // they must therefore always be present in whatever the generator produced.
        for founding in [
            "vayu", "p2p", "free", "decent", "libre", "sov", "dao", "indie", "open", "news", "blog",
        ] {
            assert!(NAMESPACE_ANNEX.contains(&founding), ".{founding}");
        }
        // Sorted, because the generator sorts and an unsorted copy would still pass
        // membership checks while making drift review impossible.
        let mut sorted = NAMESPACE_ANNEX.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted.as_slice(), NAMESPACE_ANNEX);
    }

    #[test]
    fn every_grammar_rule_has_its_own_reason() {
        use NameRejection::*;
        let too_long = "a".repeat(MAX_LABEL_LENGTH + 1);
        let longest_ok = "a".repeat(MAX_LABEL_LENGTH);
        let cases: &[(&str, Option<NameRejection>)] = &[
            ("", Some(Empty)),
            ("a", Some(ReservedLabel)), // length <= 2 is the scarcity reservation
            ("ab", Some(ReservedLabel)),
            ("abc", None),
            (too_long.as_str(), Some(TooLong)),
            (longest_ok.as_str(), None),
            ("has space", Some(BadCharacter)),
            ("UPPER", Some(BadCharacter)),
            ("under_score", Some(BadCharacter)),
            ("café", Some(BadCharacter)),
            ("-lead", Some(LeadingHyphen)),
            ("trail-", Some(TrailingHyphen)),
            ("xx--idn", Some(ReservedIdnShape)),
            ("ab--cd", Some(ReservedIdnShape)),
            ("x-y-z", None),
            ("www", Some(ReservedLabel)),
            ("wpad", Some(ReservedLabel)),
            ("pac", Some(ReservedLabel)),
            ("api", Some(ReservedLabel)),
            ("vayu", Some(ReservedLabel)),
            ("hello-world", None),
        ];
        for (label, expected) in cases {
            assert_eq!(&label_rejection(label), expected, "{label}");
        }
        // The TooLong boundary is counted in characters, matching the reference.
        assert_eq!(
            label_rejection(&"a".repeat(MAX_LABEL_LENGTH + 1)),
            Some(NameRejection::TooLong)
        );
        // Length is measured before shape: a 65-character label carrying an invalid
        // character reports TOO_LONG, because that is where the checks sit. Order does not
        // change acceptance, only the reason — pinned so the ordering stays deliberate.
        let long_and_invalid = format!("{} ", "a".repeat(MAX_LABEL_LENGTH + 1));
        assert_eq!(
            label_rejection(&long_and_invalid),
            Some(NameRejection::TooLong)
        );
    }

    #[test]
    fn short_labels_are_withheld_before_the_named_reservations_are_consulted() {
        // "ww" is not on the reserved list, but every one- and two-character label is
        // withheld anyway; the reason reported must be the scarcity reservation.
        assert_eq!(label_rejection("ww"), Some(NameRejection::ReservedLabel));
        assert_eq!(label_rejection("w2"), Some(NameRejection::ReservedLabel));
        // Three characters is where ordinary names begin.
        assert_eq!(label_rejection("www"), Some(NameRejection::ReservedLabel));
        assert_eq!(label_rejection("app"), None);
    }

    #[test]
    fn tlds_need_shape_and_then_ratification() {
        assert!(is_well_shaped_tld("vayu"));
        assert!(is_well_shaped_tld("p2p"));
        assert!(!is_well_shaped_tld("2ch"));
        assert!(!is_well_shaped_tld("v"));
        assert!(!is_well_shaped_tld("abcdefghijklm")); // 13 > MAX_TLD_LENGTH
        assert!(is_well_shaped_tld("abcdefghijkl")); // exactly 12 is the boundary
        assert!(!is_well_shaped_tld("has-dash"));
        assert!(!is_well_shaped_tld(""));
        assert!(is_ratified_tld("vayu"));
        assert!(!is_ratified_tld("vayuu"));

        assert_eq!(
            name_rejection("hello", "nope-nope"),
            Some(NameRejection::BadTldShape)
        );
        assert_eq!(
            name_rejection("hello", "wellshapeds"),
            Some(NameRejection::UnknownTld)
        );
        assert_eq!(name_rejection("hello", "vayu"), None);
        // The full-name path reports the LABEL problem even against a valid TLD.
        assert_eq!(
            name_rejection("wpad", "vayu"),
            Some(NameRejection::ReservedLabel)
        );
    }

    #[test]
    fn aliases_parse_only_well_formed_targets() {
        assert_eq!(
            parse_alias("blog.vayu"),
            Some(Alias {
                label: "blog".into(),
                tld: "vayu".into()
            })
        );
        assert_eq!(parse_alias(".vayu"), None);
        assert_eq!(parse_alias("blog."), None);
        assert_eq!(parse_alias("a.b.c"), None);
        assert_eq!(parse_alias("wpad.vayu"), None);
        assert_eq!(parse_alias("blog.notatld"), None);
        // No dot at all.
        assert_eq!(parse_alias("blogvayu"), None);
    }
}
