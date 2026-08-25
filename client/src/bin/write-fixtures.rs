//! Regenerate `conformance/client-built.json`: records built HERE, verified THERE.
//!
//! This binary is deliberately part of the repository rather than a scratch script. The
//! fixtures it writes are consumed by `registry/src/clientbuilt.test.ts`, which feeds every
//! byte through the reference implementation's own verifier; CI regenerates the file and fails
//! on any drift, so the two languages cannot silently disagree about what a record is.
//!
//! Determinism, and why these seeds may exist at all: Ed25519 signing is deterministic
//! (RFC 8032), the nonce search walks upward from zero, the difficulty schedule is pure, and
//! the seeds below are FIXED BYTE PATTERNS documented as test-only. They never protect
//! anything — they exist so the same input produces the same bytes on every machine, which is
//! the property the CI diff check relies on. Production identities come from
//! [`vayuweb_client::identity::Identity::generate`] and its OS CSPRNG, full stop.

use vayuweb_client::doctor::RULES;
use vayuweb_client::domain::record_hash_from_bytes;
use vayuweb_client::identity::Identity;
use vayuweb_client::publish::{import_site, SiteFile};
use vayuweb_client::record::{self, BuildError, Entry, EntryValue, Predecessor};

/// Fixed epoch for every fixture timestamp. Chosen once, written down here; nothing about the
/// protocol depends on the value, only on its being identical across regenerations.
const T0: u64 = 1_800_000_000;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn alice() -> Identity {
    let mut seed = vec![0xa1u8; 32];
    Identity::from_seed(&mut seed).expect("test seed")
}

fn bob() -> Identity {
    let mut seed = vec![0xbbu8; 32];
    Identity::from_seed(&mut seed).expect("test seed")
}

struct Case {
    op: &'static str,
    label: &'static str,
    tld: &'static str,
    seq: u64,
    not_before: u64,
    not_after: u64,
    bytes: Vec<u8>,
    claimed_bits: Option<u32>,
    /// The key that signed the PREDECESSOR of this record, when authority tracking needs it.
    transferor_key: Option<[u8; 32]>,
    description: &'static str,
    /// For publish cases: the exact site the record's cid entry points at, so the consumer
    /// can rebuild the tree with its own importer and compare roots.
    site: Option<SiteFixture>,
}

/// A deterministic site plus the root CID the client computed for it.
#[derive(Clone)]
struct SiteFixture {
    files: Vec<SiteFileInput>,
    root_cid: String,
    blocks: Vec<(String, Vec<u8>)>,
}

#[derive(Clone)]
struct SiteFileInput {
    path: String,
    content: Vec<u8>,
}

fn describe(error: &BuildError) -> String {
    format!("{error}")
}

fn main() {
    let alice = alice();
    let bob = bob();
    let mut cases: Vec<Case> = Vec::new();

    // ------------------------------------------------------------------ chain A: the working
    // life of one name — register, update content, transfer to a second party, who then
    // exercises their own ownership. Four operations, three owners' worth of state changes.
    let registered = record::build_register(
        &alice,
        "fixture-register",
        "vayu",
        T0,
        &[Entry {
            value: EntryValue::Txt("v=vayuweb-client".into()),
            ttl: None,
        }],
        0,
        None,
        10_000,
    )
    .unwrap_or_else(|error| panic!("register failed: {}", describe(&error)));
    let registered_pred = Predecessor::from_bytes(&registered).expect("parses");
    cases.push(Case {
        op: "REGISTER",
        label: "fixture-register",
        tld: "vayu",
        seq: 0,
        not_before: registered_pred.not_before,
        not_after: registered_pred.not_after,
        claimed_bits: Some(4),
        transferor_key: None,
        bytes: registered.clone(),
        description: "REGISTER by the launch suite: 16-character label at the 4-bit floor",
        site: None,
    });

    let updated = record::build_update(
        &alice,
        &registered_pred,
        "fixture-register",
        "vayu",
        T0 + 600,
        &[
            Entry {
                value: EntryValue::Txt("v=vayuweb-client-updated".into()),
                ttl: Some(120),
            },
            Entry {
                value: EntryValue::Cid(vec![0x01, 0x70, 0x12, 0x20]),
                ttl: None,
            },
        ],
    )
    .unwrap_or_else(|error| panic!("update failed: {}", describe(&error)));
    let updated_pred = Predecessor::from_bytes(&updated).expect("parses");
    cases.push(Case {
        op: "UPDATE",
        label: "fixture-register",
        tld: "vayu",
        seq: updated_pred.seq,
        not_before: updated_pred.not_before,
        not_after: updated_pred.not_after,
        claimed_bits: None,
        transferor_key: None,
        bytes: updated.clone(),
        description: "UPDATE replaces content and adds a cid entry; no proof of work",
        site: None,
    });

    let transferred = record::build_transfer(
        &alice,
        &bob,
        &updated_pred,
        "fixture-register",
        "vayu",
        T0 + 1200,
    )
    .unwrap_or_else(|error| panic!("transfer failed: {}", describe(&error)));
    let transferred_pred = Predecessor::from_bytes(&transferred).expect("parses");
    cases.push(Case {
        op: "TRANSFER",
        label: "fixture-register",
        tld: "vayu",
        seq: transferred_pred.seq,
        not_before: transferred_pred.not_before,
        not_after: transferred_pred.not_after,
        claimed_bits: None,
        transferor_key: Some(*alice.public_key()),
        bytes: transferred.clone(),
        description: "TRANSFER signed by the outgoing owner, countersigned by the recipient key",
        site: None,
    });

    // The new owner acts only once the transfer has SETTLED: until fourteen days have passed
    // since the transfer's own notBefore, the verifier accepts nothing else on that name. The
    // fixture honours that, jumping past the settlement horizon.
    let adopted_at = transferred_pred.not_before + record::SETTLEMENT_SECONDS + 600;
    let adopted = record::build_update(
        &bob,
        &transferred_pred,
        "fixture-register",
        "vayu",
        adopted_at,
        &[Entry {
            value: EntryValue::Txt("v=new-owner".into()),
            ttl: None,
        }],
    )
    .unwrap_or_else(|error| panic!("post-transfer update failed: {}", describe(&error)));
    let adopted_pred = Predecessor::from_bytes(&adopted).expect("parses");
    cases.push(Case {
        op: "UPDATE",
        label: "fixture-register",
        tld: "vayu",
        seq: adopted_pred.seq,
        not_before: adopted_pred.not_before,
        not_after: adopted_pred.not_after,
        claimed_bits: None,
        // The predecessor was a TRANSFER, so the verifier tracks the outgoing key as well.
        transferor_key: Some(*alice.public_key()),
        bytes: adopted.clone(),
        description:
            "UPDATE by the incoming owner after settlement proves the countersignature took effect",
        site: None,
    });

    // ------------------------------------------------------------------ chain B: release
    let released_name = record::build_register(
        &alice,
        "fixture-release-01",
        "vayu",
        T0 + 2400,
        &[],
        0,
        None,
        10_000,
    )
    .unwrap_or_else(|error| panic!("release-chain register failed: {}", describe(&error)));
    let released_pred = Predecessor::from_bytes(&released_name).expect("parses");
    cases.push(Case {
        op: "REGISTER",
        label: "fixture-release-01",
        tld: "vayu",
        seq: 0,
        not_before: released_pred.not_before,
        not_after: released_pred.not_after,
        claimed_bits: Some(4),
        transferor_key: None,
        bytes: released_name.clone(),
        description: "REGISTER with no entries, destined for RELINQUISH",
        site: None,
    });

    let released = record::build_relinquish(
        &alice,
        &released_pred,
        "fixture-release-01",
        "vayu",
        T0 + 3000,
    )
    .unwrap_or_else(|error| panic!("relinquish failed: {}", describe(&error)));
    cases.push(Case {
        op: "RELINQUISH",
        label: "fixture-release-01",
        tld: "vayu",
        seq: released_pred.seq + 1,
        not_before: T0 + 3000,
        not_after: T0 + 3000,
        claimed_bits: None,
        transferor_key: None,
        bytes: released,
        description: "RELINQUISH collapses both timestamps to now and empties the record",
        site: None,
    });

    // ------------------------------------------------------------------ chain C: revoke
    let revoked_name = record::build_register(
        &alice,
        "fixture-revoke-001",
        "vayu",
        T0 + 3600,
        &[],
        0,
        None,
        10_000,
    )
    .unwrap_or_else(|error| panic!("revoke-chain register failed: {}", describe(&error)));
    let revoked_pred = Predecessor::from_bytes(&revoked_name).expect("parses");
    cases.push(Case {
        op: "REGISTER",
        label: "fixture-revoke-001",
        tld: "vayu",
        seq: 0,
        not_before: revoked_pred.not_before,
        not_after: revoked_pred.not_after,
        claimed_bits: Some(4),
        transferor_key: None,
        bytes: revoked_name.clone(),
        description: "REGISTER destined for REVOKE",
        site: None,
    });

    let revoked = record::build_revoke(
        &alice,
        &revoked_pred,
        "fixture-revoke-001",
        "vayu",
        T0 + 4200,
    )
    .unwrap_or_else(|error| panic!("revoke failed: {}", describe(&error)));
    cases.push(Case {
        op: "REVOKE",
        label: "fixture-revoke-001",
        tld: "vayu",
        seq: revoked_pred.seq + 1,
        not_before: T0 + 4200,
        not_after: revoked_pred.not_after,
        claimed_bits: None,
        transferor_key: None,
        bytes: revoked,
        description: "REVOKE keeps the term frozen and stops resolution at once",
        site: None,
    });

    // ------------------------------------------------------------------ chain D: renewal
    // The renewal happens thirty days before expiry — inside the sixty-day window, outside
    // grace — with the TLD's trailing-window count at TWICE the rate floor, the first rung
    // where the rate term contributes a bit, so the required difficulty gains one over the
    // register's base.
    let renew_at = T0 + 4800 + record::TERM_SECONDS - 2_592_000;
    let renewed_name = record::build_register(
        &alice,
        "fixture-renew-0001",
        "vayu",
        T0 + 4800,
        &[],
        0,
        None,
        10_000,
    )
    .unwrap_or_else(|error| panic!("renew-chain register failed: {}", describe(&error)));
    let renewed_pred = Predecessor::from_bytes(&renewed_name).expect("parses");
    cases.push(Case {
        op: "REGISTER",
        label: "fixture-renew-0001",
        tld: "vayu",
        seq: 0,
        not_before: renewed_pred.not_before,
        not_after: renewed_pred.not_after,
        claimed_bits: Some(4),
        transferor_key: None,
        bytes: renewed_name.clone(),
        description: "REGISTER destined for RENEW",
        site: None,
    });

    let renewed = record::build_renew(
        &alice,
        &renewed_pred,
        "fixture-renew-0001",
        "vayu",
        renew_at,
        1024,
        10_000,
    )
    .unwrap_or_else(|error| panic!("renew failed: {}", describe(&error)));
    let renewed_result = Predecessor::from_bytes(&renewed).expect("parses");
    assert_eq!(
        renewed_result.not_after,
        renewed_pred.not_after + record::TERM_SECONDS
    );
    cases.push(Case {
        op: "RENEW",
        label: "fixture-renew-0001",
        tld: "vayu",
        seq: renewed_result.seq,
        not_before: renewed_result.not_before,
        not_after: renewed_result.not_after,
        claimed_bits: Some(5),
        transferor_key: None,
        bytes: renewed,
        description: "RENEW inside the window extends from the old expiry at base+1 rate bits",
        site: None,
    });

    // ------------------------------------------------------------------ chain E: a pointer
    // An alias is a name whose only content is another name — "a pointer or a destination,
    // never both". Its single-entry shape is itself part of what the fixtures pin.
    let aliased = record::build_register(
        &alice,
        "fixture-alias-0001",
        "vayu",
        T0 + 6000,
        &[Entry {
            value: EntryValue::Alias(
                vayuweb_client::record::alias("fixture-register", "vayu").expect("alias"),
            ),
            ttl: None,
        }],
        0,
        None,
        10_000,
    )
    .unwrap_or_else(|error| panic!("alias register failed: {}", describe(&error)));
    let aliased_pred = Predecessor::from_bytes(&aliased).expect("parses");
    cases.push(Case {
        op: "REGISTER",
        label: "fixture-alias-0001",
        tld: "vayu",
        seq: 0,
        not_before: aliased_pred.not_before,
        not_after: aliased_pred.not_after,
        claimed_bits: Some(4),
        transferor_key: None,
        bytes: aliased,
        description: "REGISTER carrying exactly one alias entry: a pure pointer name",
        site: None,
    });

    // ------------------------------------------------------------------ chain F: a published
    // site. The publish path builds a UnixFS DAG from the files, addresses it with the root
    // CID, and the record's cid entry carries that root in binary form — PUBLISHING.md section
    // 1, steps 2, 3 and 5, with steps 1 (authoring checks) and 4 (local pinning) honestly still
    // unbuilt in this crate. The consumer rebuilds the tree with its own importer and compares.
    let site_files = vec![
        SiteFile {
            path: "index.html".into(),
            content: b"<!doctype html><title>fixture</title>vayuweb publish fixture\n".to_vec(),
        },
        SiteFile {
            path: "docs/a.txt".into(),
            content: b"alpha\n".to_vec(),
        },
    ];
    let (site_blocks, site_root) = import_site(&site_files).expect("imports");
    // A cid entry value is the BINARY CID — REGISTRY.md: "Binary CIDv1, 1-64 bytes; rendered
    // base32 in JSON" — so the record stores 36 bytes, not the text form.
    let site_entry = Entry {
        value: EntryValue::Cid(site_root.to_bytes()),
        ttl: None,
    };
    let site_registered = record::build_register(
        &alice,
        "fixture-site-0001",
        "vayu",
        T0 + 6600,
        &[site_entry],
        0,
        None,
        10_000,
    )
    .unwrap_or_else(|error| panic!("site register failed: {}", describe(&error)));
    let site_pred = Predecessor::from_bytes(&site_registered).expect("parses");
    cases.push(Case {
        op: "REGISTER",
        label: "fixture-site-0001",
        tld: "vayu",
        seq: 0,
        not_before: site_pred.not_before,
        not_after: site_pred.not_after,
        claimed_bits: Some(4),
        transferor_key: None,
        bytes: site_registered,
        description: "REGISTER whose cid entry points at a built UnixFS site tree",
        site: Some(SiteFixture {
            files: site_files
                .iter()
                .map(|file| SiteFileInput {
                    path: file.path.clone(),
                    content: file.content.clone(),
                })
                .collect(),
            root_cid: site_root.to_text(),
            blocks: site_blocks
                .iter()
                .map(|block| (block.cid.to_text(), block.bytes.clone()))
                .collect(),
        }),
    });

    write_json(&cases);
    write_rules();
}

/// Emit `conformance/rules.json`: the checker's rule set as data, per PUBLISHING.md 3.1.6's
/// "one shared definition". The Rust table is the SOURCE; this file is its deterministic
/// serialization, verified from the other language by `registry/src/rules.test.ts` and kept
/// honest by CI's regenerate-and-diff step. Order is RULES order and is itself part of the
/// artifact: a reordering is a diff like any other.
fn write_rules() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../conformance/rules.json");
    let mut json = String::from("{\n  \"_comment\": [\n");
    json.push_str(
        "    \"Generated by client/src/bin/write-fixtures.rs from the doctor's RULES table -- \
         the one shared definition of PUBLISHING.md 3.1.6. Do not edit by hand.\",\n",
    );
    json.push_str(
        "    \"Verified from the registry side by registry/src/rules.test.ts; CI regenerates \
         and fails on any diff, so the two languages cannot drift apart.\",\n",
    );
    json.push_str(
        "    \"what/why/fix are the exact strings a finding renders; id is the contract both \
         sides compile against; enforcement says how READING enforces each rule (csp = the \
         emitted headers block it, evidence names the substrings; scan = no header can express \
         it, serving surfaces must refuse the document; publish-check = meaningful only at \
         publish).\"\n  ],\n",
    );
    json.push_str("  \"rules\": [\n");
    for (index, rule) in RULES.iter().enumerate() {
        json.push_str("    {\n");
        json.push_str(&format!("      \"id\": {},\n", json_string(rule.id)));
        json.push_str(&format!("      \"what\": {},\n", json_string(rule.what)));
        json.push_str(&format!("      \"why\": {},\n", json_string(rule.why)));
        json.push_str(&format!("      \"fix\": {},\n", json_string(rule.fix)));
        // 3.1.6's second half: HOW reading enforces the rule. `evidence` names the header
        // substrings that do the blocking; the registry-side test checks them against the REAL
        // header constants, so a header that drifts fails CI even though this file still
        // matches its Rust source.
        json.push_str(&format!(
            "      \"enforcement\": {},\n",
            json_string(rule.enforcement.as_str())
        ));
        json.push_str("      \"evidence\": [\n");
        for (at, (header, substring)) in rule.evidence.iter().enumerate() {
            let comma = if at + 1 == rule.evidence.len() {
                ""
            } else {
                ","
            };
            json.push_str(&format!(
                "        {{\"header\": {}, \"contains\": {}}}{}\n",
                json_string(header),
                json_string(substring),
                comma
            ));
        }
        json.push_str("      ],\n");
        json.push_str("      \"absent\": [\n");
        for (at, (header, substring)) in rule.evidence_absent.iter().enumerate() {
            let comma = if at + 1 == rule.evidence_absent.len() {
                ""
            } else {
                ","
            };
            json.push_str(&format!(
                "        {{\"header\": {}, \"omit\": {}}}{}\n",
                json_string(header),
                json_string(substring),
                comma
            ));
        }
        json.push_str("      ]\n");
        if index + 1 == RULES.len() {
            json.push_str("    }\n");
        } else {
            json.push_str("    },\n");
        }
    }
    json.push_str("  ]\n}\n");
    std::fs::write(path, json.as_bytes()).expect("writes conformance/rules.json");
    println!("wrote {path}: {} rules", RULES.len());
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_json(cases: &[Case]) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../conformance/client-built.json"
    );
    let mut json = String::from("{\n  \"_comment\": [\n");
    json.push_str(
        "    \"Built by client/src/bin/write-fixtures.rs; verified by \
         registry/src/clientbuilt.test.ts.\",\n",
    );
    json.push_str(
        "    \"CI regenerates this file and fails on any diff: the two languages must agree \
         byte for byte.\",\n",
    );
    json.push_str("    \"Seeds in the builder are fixed byte patterns, test-only.\"\n  ],\n");
    json.push_str("  \"cases\": [\n");
    for (index, case) in cases.iter().enumerate() {
        let comma = if index + 1 == cases.len() { "" } else { "," };
        json.push_str("    {\n");
        json.push_str(&format!(
            "      \"description\": \"{}\",\n",
            case.description
        ));
        json.push_str(&format!("      \"op\": \"{}\",\n", case.op));
        json.push_str(&format!(
            "      \"name\": \"{}\",\n      \"tld\": \"{}\",\n",
            case.label, case.tld
        ));
        json.push_str(&format!("      \"seq\": {},\n", case.seq));
        json.push_str(&format!("      \"notBefore\": {},\n", case.not_before));
        json.push_str(&format!("      \"notAfter\": {},\n", case.not_after));
        match case.claimed_bits {
            Some(bits) => json.push_str(&format!("      \"claimedBits\": {bits},\n")),
            None => json.push_str("      \"claimedBits\": null,\n"),
        }
        match case.transferor_key {
            Some(key) => json.push_str(&format!("      \"transferorKey\": \"{}\",\n", hex(&key))),
            None => json.push_str("      \"transferorKey\": null,\n"),
        }
        // The hash field is last unless a site follows, so its comma depends on that.
        json.push_str(&format!("      \"bytes\": \"{}\",\n", hex(&case.bytes)));
        match &case.site {
            Some(site) => {
                json.push_str(&format!(
                    "      \"hash\": \"{}\",\n",
                    hex(&record_hash_from_bytes(&case.bytes))
                ));
                json.push_str("      \"site\": {\n");
                json.push_str("        \"files\": [\n");
                for (file_index, file) in site.files.iter().enumerate() {
                    let file_comma = if file_index + 1 == site.files.len() {
                        ""
                    } else {
                        ","
                    };
                    json.push_str(&format!(
                        "          {{\"path\": \"{}\", \"content\": \"{}\"}}{file_comma}\n",
                        file.path,
                        hex(&file.content)
                    ));
                }
                json.push_str("        ],\n");
                json.push_str(&format!("        \"rootCid\": \"{}\",\n", site.root_cid));
                json.push_str("        \"blocks\": [\n");
                for (block_index, (cid, bytes)) in site.blocks.iter().enumerate() {
                    let block_comma = if block_index + 1 == site.blocks.len() {
                        ""
                    } else {
                        ","
                    };
                    json.push_str(&format!(
                        "          {{\"cid\": \"{cid}\", \"bytes\": \"{}\"}}{block_comma}\n",
                        hex(bytes)
                    ));
                }
                json.push_str("        ]\n      }\n");
            }
            None => {
                json.push_str(&format!(
                    "      \"hash\": \"{}\"\n",
                    hex(&record_hash_from_bytes(&case.bytes))
                ));
            }
        }
        json.push_str(&format!("    }}{comma}\n"));
    }
    json.push_str("  ]\n}\n");

    std::fs::write(path, json.as_bytes()).expect("writes conformance/client-built.json");
    println!("wrote {path}: {} cases", cases.len());
}
