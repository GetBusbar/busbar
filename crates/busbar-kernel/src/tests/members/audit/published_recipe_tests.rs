// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use sha2::{Digest as _, Sha256};

fn published_spec() -> String {
    published_page("audit-chain-digest-v4.md")
}

fn published_page(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs")
            .join(name),
    )
    .expect("the published digest spec is in the tree")
}

/// How one published value is framed into the preimage, as the document's `Kind` column names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Length-prefixed UTF-8 bytes.
    Text,
    /// Big-endian eight bytes, itself length-prefixed with 8.
    Num,
}

fn published_field_order(doc: &str) -> Vec<(String, Kind)> {
    let mut order = Vec::new();
    let mut expected_position = 1usize;
    for line in doc.lines() {
        let line = line.trim();
        if !line.starts_with('|') || !line.ends_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() != 3 {
            continue;
        }
        let Ok(position) = cells[0].parse::<usize>() else {
            continue;
        };
        let name = cells[1].trim_matches('`');
        let kind = match cells[2] {
            "text" => Kind::Text,
            "number" => Kind::Num,
            _ => continue,
        };
        assert_eq!(
            position, expected_position,
            "the published field table skips or repeats position {expected_position}; a reader \
             walking it in order would frame the wrong bytes"
        );
        expected_position += 1;
        order.push((name.to_string(), kind));
    }
    assert!(
        order.len() >= 40,
        "the published field table yielded only {} rows — either the table moved or the parser \
         stopped reading it, and both mean an outside reader cannot follow the document",
        order.len()
    );
    order
}

/// How a page's body spells a recipe number.
///
/// Every page whose body this build can be asked to answer with, and every page the out-of-process
/// verifier checks, publishes a recipe number as its canonical decimal text in a JSON string: a
/// `u64` above 2^53 does not survive a reader that maps JSON numbers to doubles. The `v1` page,
/// whose body no node can serve, is kept as it was published, with bare JSON numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Numbers {
    /// Canonical decimal text in a JSON string (`"seq": "1"`).
    AsText,
    /// A bare JSON number (`"seq": 1`): the kept `v1` page only.
    AsJson,
}

fn canonical_decimal(s: &str) -> Option<u64> {
    let canonical =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if canonical {
        s.parse().ok()
    } else {
        None
    }
}

fn frame(out: &mut Vec<u8>, value: &serde_json::Value, kind: Kind, numbers: Numbers) {
    match kind {
        Kind::Text => {
            let s = value
                .as_str()
                .unwrap_or_else(|| panic!("a published text field is not a JSON string: {value}"));
            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Kind::Num => {
            let n = match numbers {
                Numbers::AsText => value.as_str().and_then(canonical_decimal),
                Numbers::AsJson => value.as_u64(),
            };
            let n = n.unwrap_or_else(|| {
                panic!("a published number field is not spelled {numbers:?}: {value}")
            });
            out.extend_from_slice(&8u64.to_be_bytes());
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn preimage_from_published(
    order: &[(String, Kind)],
    record: &serde_json::Value,
    numbers: Numbers,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < order.len() {
        let (name, kind) = &order[i];
        let Some(marker) = name.find("[]") else {
            let value = record.get(name).unwrap_or_else(|| {
                panic!("the published record carries no member `{name}` the field table names")
            });
            frame(&mut out, value, *kind, numbers);
            i += 1;
            continue;
        };
        let array_name = &name[..marker];

        let mut members: Vec<(String, Kind)> = Vec::new();
        while i < order.len() && order[i].0.starts_with(&format!("{array_name}[]")) {
            let member = order[i].0[array_name.len() + 2..].trim_start_matches('.');
            members.push((member.to_string(), order[i].1));
            i += 1;
        }
        let array = record
            .get(array_name)
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| {
                panic!("the published record carries no array `{array_name}` the table names")
            });
        for element in array {
            for (member, kind) in &members {
                let value = if member.is_empty() {
                    element
                } else {
                    element.get(member).unwrap_or_else(|| {
                        panic!("a published `{array_name}` element carries no `{member}`")
                    })
                };
                frame(&mut out, value, *kind, numbers);
            }
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_from_published(
    order: &[(String, Kind)],
    record: &serde_json::Value,
    numbers: Numbers,
) -> String {
    hex(&Sha256::digest(preimage_from_published(
        order, record, numbers,
    )))
}

fn spec_json_block(doc: &str, nth: usize) -> serde_json::Value {
    let block = doc
        .split("```json")
        .nth(nth + 1)
        .unwrap_or_else(|| panic!("the published spec has no json block {nth}"))
        .split("```")
        .next()
        .expect("a fenced block closes");
    serde_json::from_str(block).expect("the published spec's example is valid JSON")
}

#[test]
fn the_published_table_reproduces_the_published_examples_digest() {
    let doc = published_spec();
    let order = published_field_order(&doc);
    let range = spec_json_block(&doc, 0);
    let record = &range["records"][0];

    let published_hash = record["hash"]
        .as_str()
        .expect("the example carries its digest");
    assert_eq!(
        digest_from_published(&order, record, Numbers::AsText),
        published_hash,
        "the published field table does not reproduce the published example's own digest — the \
         page is not followable"
    );
}

#[test]
fn the_v1_page_is_kept_and_v2_is_v1_less_the_three_priced_fields() {
    let v1 = published_page("audit-chain-digest-v1.md");
    let v1_order = published_field_order(&v1);
    let v1_record = &spec_json_block(&v1, 0)["records"][0];
    assert_eq!(
        digest_from_published(&v1_order, v1_record, Numbers::AsJson),
        v1_record["hash"]
            .as_str()
            .expect("the v1 example carries its digest"),
        "the v1 page no longer reproduces its own example — a v1 body could not be verified"
    );
    assert_eq!(
        spec_json_block(&v1, 0)["recipe"].as_str(),
        Some("busbar.audit.digest.v1")
    );

    let priced = ["pre_tier", "priced", "hooks[].priced_delta"];
    let v1_less_priced: Vec<_> = v1_order
        .iter()
        .filter(|(name, _)| !priced.contains(&name.as_str()))
        .cloned()
        .collect();
    assert_eq!(v1_less_priced.len() + priced.len(), v1_order.len());
    assert_eq!(
        published_field_order(&published_page("audit-chain-digest-v2.md")),
        v1_less_priced,
        "the v2 page is not the v1 page less exactly the three priced fields"
    );
}

#[test]
fn the_v2_page_is_kept_and_v3_is_v2_less_currency() {
    let v2 = published_page("audit-chain-digest-v2.md");
    let v2_order = published_field_order(&v2);
    let v2_record = &spec_json_block(&v2, 0)["records"][0];
    assert_eq!(
        digest_from_published(&v2_order, v2_record, Numbers::AsText),
        v2_record["hash"]
            .as_str()
            .expect("the v2 example carries its digest"),
        "the v2 page no longer reproduces its own example — a v2 record could not be verified"
    );
    assert_eq!(
        spec_json_block(&v2, 0)["recipe"].as_str(),
        Some("busbar.audit.digest.v2")
    );

    let v2_less_currency: Vec<_> = v2_order
        .iter()
        .filter(|(name, _)| name != "currency")
        .cloned()
        .collect();
    assert_eq!(v2_less_currency.len() + 1, v2_order.len());
    assert_eq!(
        published_field_order(&published_page("audit-chain-digest-v3.md")),
        v2_less_currency,
        "the v3 page is not the v2 page less exactly `currency`"
    );
}

#[test]
fn the_v3_page_is_kept_and_v4_is_v3_plus_incarnation_and_node() {
    let v3 = published_page("audit-chain-digest-v3.md");
    let v3_order = published_field_order(&v3);
    let v3_record = &spec_json_block(&v3, 0)["records"][0];
    assert_eq!(
        digest_from_published(&v3_order, v3_record, Numbers::AsText),
        v3_record["hash"]
            .as_str()
            .expect("the v3 example carries its digest"),
        "the v3 page no longer reproduces its own example"
    );
    assert_eq!(
        spec_json_block(&v3, 0)["recipe"].as_str(),
        Some("busbar.audit.digest.v3")
    );

    let v4_order = published_field_order(&published_spec());
    let after = |name: &str| {
        v3_order
            .iter()
            .position(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("the v3 page frames {name}"))
            + 1
    };
    let mut v3_plus = v3_order.clone();

    let hook = after("hooks[].hook");
    v3_plus.insert(hook, ("hooks[].failed".to_string(), Kind::Num));
    v3_plus.insert(hook, ("hooks[].head".to_string(), Kind::Text));
    v3_plus.insert(after("mono"), ("node".to_string(), Kind::Num));
    v3_plus.insert(after("unit_key"), ("incarnation".to_string(), Kind::Num));
    assert_eq!(
        v4_order, v3_plus,
        "the v4 page is not the v3 page plus exactly `incarnation` after `unit_key`, `node` \
         after `mono` and `hooks[].head` and `hooks[].failed` after `hooks[].hook`"
    );
    assert_eq!(
        spec_json_block(&published_spec(), 0)["recipe"].as_str(),
        Some("busbar.audit.digest.v4")
    );
}

#[test]
fn the_published_table_still_describes_what_this_build_seals() {
    use busbar_contract::caps::{Audit as AuditStep, KernelSeal, Pass};

    let doc = published_spec();
    let order = published_field_order(&doc);

    let token: Pass<AuditStep> = Pass::mint(&KernelSeal::acquire_for_kernel());
    let key = busbar_kernel_audit::sign::AuditSigningKey::from_hex_seed(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .expect("the test seed is 64 lowercase hex");
    let mut chain = busbar_kernel_audit::record::AuditChain::new().signing_with(key);
    let sealed = busbar_kernel_audit::record::Audit::seal(
        &mut chain,
        super::sign_tests::rich_inputs(1),
        &token,
    );

    let body: serde_json::Value = serde_json::from_str(&busbar_kernel_audit::expose::range_body(
        &chain,
        std::slice::from_ref(&sealed),
        1,
        1,
    ))
    .expect("a published body is JSON");

    assert_eq!(
        digest_from_published(&order, &body["records"][0], Numbers::AsText),
        sealed.hash,
        "this build seals a digest the PUBLISHED field order does not reproduce. The chain still \
         verifies against itself, so nothing else in this crate goes red — and the chain has \
         become unverifiable by anyone outside this repository. Either restore the published \
         order or publish a NEW recipe version beside it."
    );
}

#[test]
fn the_published_key_set_checks_the_published_examples_signature() {
    let doc = published_spec();
    let range = spec_json_block(&doc, 0);
    let keys = spec_json_block(&doc, 2);
    let record = &range["records"][0];

    let domain = range["signature_domain"]
        .as_str()
        .expect("the published body names its signature domain");
    let published_key = &keys["keys"][0];
    let key_hex = published_key["public_key"]
        .as_str()
        .expect("a published key");
    let mut key_bytes = [0u8; 32];
    for (i, slot) in key_bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&key_hex[i * 2..i * 2 + 2], 16).expect("the key is hex");
    }

    assert_eq!(
        &hex(&Sha256::digest(key_bytes))[..16],
        published_key["key_id"]
            .as_str()
            .expect("a published key id"),
        "the published key id is not the SHA-256 derivation the page documents"
    );
    assert_eq!(
        record["key_id"].as_str(),
        published_key["key_id"].as_str(),
        "the example names a key the published set does not hold"
    );

    let mut preimage = Vec::new();
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(record["hash"].as_str().expect("a digest").as_bytes());

    let sig_hex = record["signature"].as_str().expect("a published signature");
    let mut sig_bytes = [0u8; 64];
    for (i, slot) in sig_bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).expect("the signature is hex");
    }

    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).expect("a public key");
    verifying
        .verify_strict(&preimage, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
        .expect("the published example's signature does not verify under the published recipe");
}

#[test]
fn the_recomputation_rejects_the_published_example_with_one_cosmetic_field_altered() {
    let doc = published_spec();
    let order = published_field_order(&doc);
    let range = spec_json_block(&doc, 0);
    let mut record = range["records"][0].clone();
    let published_hash = record["hash"].as_str().expect("a digest").to_string();

    let was = record["mono"]
        .as_str()
        .and_then(canonical_decimal)
        .expect("the example carries a mono");
    record["mono"] = serde_json::json!((was + 1).to_string());
    assert_ne!(
        digest_from_published(&order, &record, Numbers::AsText),
        published_hash,
        "altering the monotonic clock left the recomputed digest unchanged — the preimage builder \
         is not reading its inputs"
    );
}

#[test]
fn the_published_bodies_expose_a_window_that_stops_short() {
    use busbar_contract::caps::{Audit as AuditStep, KernelSeal, Pass};

    let token: Pass<AuditStep> = Pass::mint(&KernelSeal::acquire_for_kernel());
    let mut chain = busbar_kernel_audit::record::AuditChain::new();
    let records: Vec<_> = (1..=5)
        .map(|i| {
            busbar_kernel_audit::record::Audit::seal(
                &mut chain,
                super::sign_tests::rich_inputs(i),
                &token,
            )
        })
        .collect();

    let short: serde_json::Value = serde_json::from_str(&busbar_kernel_audit::expose::range_body(
        &chain,
        &records[..4],
        1,
        5,
    ))
    .expect("a published body is JSON");
    let head: serde_json::Value =
        serde_json::from_str(&busbar_kernel_audit::expose::head_body(&chain))
            .expect("a published body is JSON");

    let asked_to = short["to"]
        .as_u64()
        .expect("the range says which window it answers");
    let head_seq = head["head"]["seq"]
        .as_u64()
        .expect("the head says where the chain is");
    let delivered = short["records"]
        .as_array()
        .and_then(|r| r.last())
        .and_then(|r| r["seq"].as_str().and_then(canonical_decimal))
        .expect("the window delivered something");

    assert!(
        delivered < asked_to.min(head_seq),
        "a window that stopped short is not detectable from the published bodies: asked to {asked_to}, \
         head at {head_seq}, delivered {delivered}"
    );
}
