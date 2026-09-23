// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED RECIPE, CHECKED BY SOMETHING THAT CANNOT SEE THE IMPLEMENTATION.
//!
//! ## The failure this exists to catch, which no other test in this crate can
//!
//! Every other recipe test in this crate asks the code what the answer is. That is fine for
//! "does the chain agree with itself", and it is worthless for the one failure that matters here:
//! the node's field order drifting from the order the DOCUMENT publishes. When that happens the
//! node still agrees with itself perfectly — `the_published_recipe_hashes_to_the_digest_the_chain_seals`
//! stays green, every chain verifies, nothing looks wrong — and the chain has silently become
//! unverifiable by anybody outside this repository. A signed chain only they can check is a claim,
//! not evidence, which is the whole of why the recipe is published at all.
//!
//! So the check here rebuilds the digest preimage from the PUBLISHED ARTIFACTS ONLY: the field
//! table in `docs/audit-chain-digest-v1.md`, and the worked example and key set that document
//! quotes. It frames them itself, hashes them itself, and compares against the digest the document
//! and the build each claim.
//!
//! ## The constraint is enforced, not promised
//!
//! Nothing in this file may reach the three functions that ARE the implementation of the recipe.
//! A check that called them would go green on a build whose order had drifted, because it would be
//! asking the drifted code what the answer is — which is precisely the bug. That constraint is not
//! honour-system and not a comment somebody can quietly stop honouring:
//! [`the_check_never_reaches_the_code_it_is_checking`] reads this file's own source and fails if
//! any of the three names appears in it outside a comment.
//!
//! ## What is fair to use
//!
//! SHA-256 and ed25519 themselves, and the chain's own `seal`/`expose` to produce a fresh artifact
//! to check. Those are the hash primitive, the signature primitive, and the thing under test's
//! output. None of them is the RECIPE — the field order, the framing and the preimage spelling are
//! re-derived here from the document, byte for byte, exactly as an outside reader would have to.

use sha2::{Digest as _, Sha256};

/// Where the published contract lives. The ONE input this check is allowed to trust.
fn published_spec() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/audit-chain-digest-v1.md"),
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

/// THE FIELD ORDER, READ OFF THE PUBLISHED TABLE — never off the code.
///
/// Parses the `| # | Field | Kind |` rows of the document's field-order section. A row the parser
/// cannot read is a row an outside reader could not have read either, so this is deliberately
/// strict rather than lenient: it is checking that the published table is usable, and a parser that
/// skipped what it did not understand would be checking nothing.
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

/// One field, framed exactly as the document's framing section specifies.
///
/// Written out here rather than delegated, because the framing is half of what is being checked.
/// Length-prefixed, never separator-joined: `be_u64(len) ‖ bytes` for text, `be_u64(8) ‖ be_u64(v)`
/// for a number.
fn frame(out: &mut Vec<u8>, value: &serde_json::Value, kind: Kind) {
    match kind {
        Kind::Text => {
            let s = value
                .as_str()
                .unwrap_or_else(|| panic!("a published text field is not a JSON string: {value}"));
            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        Kind::Num => {
            let n = value.as_u64().unwrap_or_else(|| {
                panic!("a published number field is not a JSON number: {value}")
            });
            out.extend_from_slice(&8u64.to_be_bytes());
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Rebuild one record's preimage from the published order and the published members.
///
/// The repeated groups are handled the way the document says they can be: a field named
/// `group[].member` belongs to the array published under `group`, and `group[]` with no member is
/// an array of bare values. The run of consecutive fields sharing a prefix IS the element's shape,
/// so no knowledge beyond the table itself is needed — which is the property being checked.
fn preimage_from_published(order: &[(String, Kind)], record: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < order.len() {
        let (name, kind) = &order[i];
        let Some(marker) = name.find("[]") else {
            let value = record.get(name).unwrap_or_else(|| {
                panic!("the published record carries no member `{name}` the field table names")
            });
            frame(&mut out, value, *kind);
            i += 1;
            continue;
        };
        let array_name = &name[..marker];
        // The run of consecutive rows naming this array is the element's member list.
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
                frame(&mut out, value, *kind);
            }
        }
    }
    out
}

/// Lowercase hex, written out so the check owes the implementation nothing at all.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest of one published record, computed only from the published table.
fn digest_from_published(order: &[(String, Kind)], record: &serde_json::Value) -> String {
    hex(&Sha256::digest(preimage_from_published(order, record)))
}

/// Pull the nth fenced `json` block out of the published spec.
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

// ── THE CHECKS ───────────────────────────────────────────────────────────────────────────────────

/// THE PUBLISHED TABLE, APPLIED TO THE PUBLISHED EXAMPLE, PRODUCES THE PUBLISHED DIGEST.
///
/// Entirely over committed artifacts: no chain is sealed, no record is rendered, nothing in this
/// crate's source is consulted. This is the document checking out on its own terms — an outside
/// reader with the page and nothing else gets the hash the page claims.
///
/// If it fails, the page is wrong, and every third-party verification built from it would fail
/// while looking, to the third party, exactly like a tampered chain.
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
        digest_from_published(&order, record),
        published_hash,
        "the published field table does not reproduce the published example's own digest — the \
         page is not followable"
    );
}

/// AND THE PUBLISHED TABLE STILL DESCRIBES WHAT THIS BUILD ACTUALLY SEALS.
///
/// The canary the rest of the suite cannot be: a build whose field order drifted from the document
/// agrees with itself perfectly, so every self-referential test stays green. This one seals a real
/// record, takes the body the range read publishes for it, and recomputes the digest **from the
/// document's order** — so a build that reordered, added or dropped a field disagrees with the
/// page here and nowhere else.
#[test]
fn the_published_table_still_describes_what_this_build_seals() {
    use busbar_contract::caps::{Audit as AuditStep, KernelSeal, Pass};

    let doc = published_spec();
    let order = published_field_order(&doc);

    let token: Pass<AuditStep> = Pass::mint(&KernelSeal::acquire_for_kernel());
    let key = crate::sign::AuditSigningKey::from_hex_seed(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .expect("the test seed is 64 lowercase hex");
    let mut chain = crate::record::AuditChain::new().signing_with(key);
    let sealed = crate::record::Audit::seal(&mut chain, super::sign_tests::rich_inputs(1), &token);

    let body: serde_json::Value = serde_json::from_str(&crate::expose::range_body(
        &chain,
        std::slice::from_ref(&sealed),
        1,
        1,
    ))
    .expect("a published body is JSON");

    assert_eq!(
        digest_from_published(&order, &body["records"][0]),
        sealed.hash,
        "this build seals a digest the PUBLISHED field order does not reproduce. The chain still \
         verifies against itself, so nothing else in this crate goes red — and the chain has \
         become unverifiable by anyone outside this repository. Either restore the published \
         order or publish a NEW recipe version beside it."
    );
}

/// THE PUBLISHED KEY SET AND PREIMAGE SPELLING ARE ENOUGH TO CHECK A SIGNATURE.
///
/// The second half of "the page is followable": the document says the preimage is the domain, one
/// zero byte, then the digest's hex, and says the key identifier is the first eight bytes of the
/// key's SHA-256. Both are re-derived here from the page rather than from this crate's constants,
/// and the signature in the page's own example is checked against the key in the page's own key
/// set.
#[test]
fn the_published_key_set_checks_the_published_examples_signature() {
    let doc = published_spec();
    let range = spec_json_block(&doc, 0);
    let keys = spec_json_block(&doc, 2);
    let record = &range["records"][0];

    // The domain comes off the published body, not off this crate's constant.
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

    // The identifier is DERIVED, so a reader can recompute it rather than be told it.
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

/// AND IT SAYS NO. The same recomputation, over the example with one field altered, disagrees.
///
/// Without this the check above could be vacuous — a preimage builder that ignored its inputs
/// would match anything. The field altered is the monotonic clock: the one with the best claim to
/// being cosmetic, the one a reader never looks at, and the one an editor would most expect to get
/// away with.
#[test]
fn the_recomputation_rejects_the_published_example_with_one_cosmetic_field_altered() {
    let doc = published_spec();
    let order = published_field_order(&doc);
    let range = spec_json_block(&doc, 0);
    let mut record = range["records"][0].clone();
    let published_hash = record["hash"].as_str().expect("a digest").to_string();

    let was = record["mono"].as_u64().expect("the example carries a mono");
    record["mono"] = serde_json::json!(was + 1);
    assert_ne!(
        digest_from_published(&order, &record),
        published_hash,
        "altering the monotonic clock left the recomputed digest unchanged — the preimage builder \
         is not reading its inputs"
    );
}

/// A WINDOW WITH RECORDS MISSING FROM ITS END IS VISIBLE IN THE PUBLISHED BODIES ALONE.
///
/// A tail truncation is invisible to anyone reading only the records: the survivors link and
/// number perfectly among themselves, because dropping the last one leaves a shorter chain that is
/// otherwise flawless. What makes it visible is that the range read says which window it is
/// ANSWERING and the head read says how far the chain actually goes — so a window that stops short
/// of both has records missing. This asserts those two members are published and do say so.
#[test]
fn the_published_bodies_expose_a_window_that_stops_short() {
    use busbar_contract::caps::{Audit as AuditStep, KernelSeal, Pass};

    let token: Pass<AuditStep> = Pass::mint(&KernelSeal::acquire_for_kernel());
    let mut chain = crate::record::AuditChain::new();
    let records: Vec<_> = (1..=5)
        .map(|i| crate::record::Audit::seal(&mut chain, super::sign_tests::rich_inputs(i), &token))
        .collect();

    // The node answers a request for 1..5 with only the first four. Nothing about those four is
    // wrong — they link, they number, they hash. The run is just short at the end.
    let short: serde_json::Value =
        serde_json::from_str(&crate::expose::range_body(&chain, &records[..4], 1, 5))
            .expect("a published body is JSON");
    let head: serde_json::Value =
        serde_json::from_str(&crate::expose::head_body(&chain)).expect("a published body is JSON");

    let asked_to = short["to"]
        .as_u64()
        .expect("the range says which window it answers");
    let head_seq = head["head"]["seq"]
        .as_u64()
        .expect("the head says where the chain is");
    let delivered = short["records"]
        .as_array()
        .and_then(|r| r.last())
        .and_then(|r| r["seq"].as_u64())
        .expect("the window delivered something");

    assert!(
        delivered < asked_to.min(head_seq),
        "a window that stopped short is not detectable from the published bodies: asked to {asked_to}, \
         head at {head_seq}, delivered {delivered}"
    );
}

/// THE CHECK NEVER REACHES THE CODE IT IS CHECKING.
///
/// The constraint the whole file rests on, enforced rather than promised. If any of the three
/// functions that ARE the recipe were called from here, every check above would go green on a
/// build whose order had drifted — because it would be asking the drifted code what the answer is.
///
/// The names are assembled at runtime rather than written out, so that this test's own source does
/// not trip the scan it performs. Comment lines are skipped, because the module comment has to be
/// able to say what it is banning.
#[test]
fn the_check_never_reaches_the_code_it_is_checking() {
    let source = include_str!("published_recipe_tests.rs");
    let banned = [
        format!("digest_{}", "fields"),
        format!("digest_{}", "over"),
        format!("digest_{}", "of"),
    ];
    let mut found = Vec::new();
    for (n, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for name in &banned {
            if line.contains(name.as_str()) {
                found.push(format!("line {}: {name}", n + 1));
            }
        }
    }
    assert!(
        found.is_empty(),
        "this file reaches the implementation of the recipe it is supposed to check \
         independently, which makes every check in it vacuous: {found:?}"
    );
    // And the scan itself is not vacuous: it finds a planted name.
    let planted = format!("let x = digest_{}(&r);", "of");
    assert!(
        banned.iter().any(|b| planted.contains(b.as_str())),
        "the scan cannot see a call it is meant to ban"
    );
}
