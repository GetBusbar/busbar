// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::JsonValueMutTrait;
use busbar_kernel_audit::{
    AuditKeySet, AuditSigningKey, BootstrapSigner, BreakNotice, BreakReason, Fingerprint,
    LiveSigner, Notary, Stamp, StampKind, LINK_RECIPE, STAMP_DOMAIN,
};

fn signer() -> AuditSigningKey {
    AuditSigningKey::from_seed(&[42; 32])
}

fn keys() -> Value {
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).unwrap());
    json::parse_value(busbar_kernel_audit::expose::keys_body(&keys).as_bytes()).unwrap()
}

fn lines() -> Vec<Value> {
    let order = fields(V7).unwrap();
    let mut previous = String::new();
    (1u64..=3)
        .map(|seq| {
            let mut line = json::json!({"recipe": LINK_RECIPE,
                "linked_ms": "1700000000000", "seq": seq.to_string(), "prev_hash": previous,
                "lines": [], "hooks": [], "children": [], "attempts": []});
            for &(name, kind) in order.iter().skip(2) {
                if !name.contains("[]") {
                    line[name] = json::json!(match kind {
                        Kind::Text => "",
                        Kind::Number => "0",
                        Kind::Bytes32 => unreachable!("v7 has no raw fingerprint field"),
                    });
                }
            }
            line["node"] = json::json!("21");
            line["rate_card_key_present"] = json::json!("0");
            let mut digest = Digest::new(Framing::LengthPrefixed);
            for &(name, kind) in order.iter().skip(2) {
                if !name.contains("[]") {
                    feed(&mut digest, &line[name], kind).unwrap();
                }
            }
            digest.num(1700000000000).num(seq);
            digest
                .raw(&32u64.to_be_bytes())
                .raw(&Fingerprint::from_hex(&previous).unwrap().0);
            previous = digest.finish();
            line["hash"] = json::json!(previous);
            line
        })
        .collect()
}

fn page(lines: &[Value], from: u64, to: u64) -> Value {
    let (grant, _) = signer().into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let stamp = Notary::new(grant)
        .sign_stamp(Stamp {
            node: 21,
            from,
            to,
            fingerprint: Fingerprint::from_hex(lines[(to - 1) as usize]["hash"].as_str().unwrap())
                .unwrap(),
            kind: StampKind::Live,
            sealer: 21,
            host: "host-a".into(),
            every: 1,
            stamped_ms: 1700000000001,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: Vec::new(),
        })
        .unwrap();
    json::json!({"node": stamp.node, "from": stamp.from, "to": stamp.to,
        "fingerprint": stamp.fingerprint.to_string(), "kind": stamp.kind.as_str(),
        "sealer": stamp.sealer, "host": stamp.host, "every": stamp.every,
        "stamped_ms": stamp.stamped_ms, "down_from_ms": stamp.down_from_ms,
        "down_to_ms": stamp.down_to_ms, "crypto": stamp.crypto, "sig_alg": stamp.sig_alg,
        "key_id": stamp.key_id, "key_cert": stamp.key_cert, "signature": hex::encode(stamp.signature)})
}

fn notice(from: u64, to: u64) -> Value {
    let (_, grant) = signer().into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let notice = BootstrapSigner::new(grant)
        .sign_break(BreakNotice {
            node: 21,
            sealer: 22,
            last_good: from - 1,
            unsealed_from: from,
            unsealed_to: to,
            journal_from: 5,
            journal_to: 6,
            reason: BreakReason::Unsigned,
            detected_ms: 1700000000001,
            host: "host-b".into(),
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            signature: Vec::new(),
        })
        .unwrap();
    json::json!({"kind": "break", "node": notice.node, "sealer": notice.sealer,
        "last_good": notice.last_good, "unsealed_from": notice.unsealed_from,
        "unsealed_to": notice.unsealed_to, "journal_from": notice.journal_from,
        "journal_to": notice.journal_to, "reason": notice.reason.as_str(),
        "detected_ms": notice.detected_ms, "host": notice.host, "crypto": notice.crypto,
        "sig_alg": notice.sig_alg, "key_id": notice.key_id, "signature": hex::encode(notice.signature)})
}

fn range(lines: &[Value], stamps: Vec<Value>) -> Value {
    json::json!({"recipe": LINK_RECIPE, "signature_domain": STAMP_DOMAIN,
        "algorithm": SIGNATURE_ALGORITHM, "from": 1, "to": 2,
        "records": &lines[..2], "cover": &lines[2..], "stamps": stamps,
        "certs": [], "anchor": null})
}

#[test]
fn linked_range_is_authenticated_by_the_covering_stamp() {
    let lines = lines();
    let report = verify(&keys(), &range(&lines, vec![page(&lines, 1, 3)]), None).unwrap();
    assert_eq!(report["pages"], 1);
    assert!(report["unauthenticated_tail"].is_null());
    assert_eq!(report["result"], "signed-consistent-window");
}

#[test]
fn missing_cover_never_reports_a_signed_window() {
    let lines = lines();
    let mut body = range(&lines, vec![page(&lines, 1, 3)]);
    body["cover"] = json::json!([]);
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["unchecked_stamps"], 1);
    assert_eq!(
        report["unauthenticated_tail"],
        json::json!({"from": 1, "to": 2})
    );
    assert!(report["result"].is_null());
}

#[test]
fn signed_break_accounts_for_a_gap_but_authenticates_no_line() {
    let lines = lines();
    let body = range(
        &lines,
        vec![page(&lines, 1, 1), notice(2, 2), page(&lines, 3, 3)],
    );
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["breaks"][0]["unsealed_from"], 2);
    assert_eq!(report["authenticated_records"], 1);
    assert_eq!(report["result"], "signed-consistent-window");
    let report = verify(&keys(), &range(&lines, vec![notice(1, 2)]), None).unwrap();
    assert!(report["result"].is_null());
}

#[test]
fn duplicate_pages_and_rewritten_cover_are_rejected() {
    let lines = lines();
    let stamp = page(&lines, 1, 3);
    assert!(verify(
        &keys(),
        &range(&lines, vec![stamp.clone(), stamp.clone()]),
        None
    )
    .is_err());
    let mut body = range(&lines, vec![stamp]);
    body["cover"][0]["op_class"] = json::json!("rewritten");
    assert!(verify(&keys(), &body, None).is_err());
}

#[test]
fn break_signature_ranges_and_page_overlap_are_checked() {
    let lines = lines();
    let mut broken = notice(2, 2);
    broken["reason"] = json::json!("digest");
    assert!(verify(
        &keys(),
        &range(&lines, vec![page(&lines, 1, 1), broken]),
        None
    )
    .is_err());
    assert!(verify(
        &keys(),
        &range(&lines, vec![page(&lines, 1, 3), notice(2, 2)]),
        None
    )
    .is_err());
    assert!(verify(&keys(), &range(&lines, vec![notice(3, 1)]), None).is_err());
    let report = verify(&keys(), &range(&lines, vec![notice(2, 1)]), None).unwrap();
    assert_eq!(report["breaks"].as_array().unwrap().len(), 1);
    assert!(report["result"].is_null());
}

#[test]
fn stamp_aliases_and_anchor_must_match_the_signed_page() {
    let lines = lines();
    for (name, value) in [
        ("seq", json::json!(2)),
        ("hash", json::json!("00".repeat(32))),
        ("wall", json::json!(0)),
    ] {
        let mut stamp = page(&lines, 1, 3);
        stamp[name] = value;
        assert!(
            verify(&keys(), &range(&lines, vec![stamp]), None).is_err(),
            "{name}"
        );
    }
    let mut body = range(&lines, vec![page(&lines, 1, 3)]);
    body["anchor"] = page(&lines, 1, 2);
    assert!(verify(&keys(), &body, None).is_err());
}

#[test]
fn trusted_head_requires_complete_coverage_and_exact_aliases() {
    let lines = lines();
    let stamp = page(&lines, 1, 2);
    let mut body = range(&lines, vec![stamp.clone()]);
    body["cover"] = json::json!([]);
    let mut head = json::json!({"recipe": LINK_RECIPE, "signature_domain": STAMP_DOMAIN,
        "algorithm": SIGNATURE_ALGORITHM, "next_seq": 3, "head": stamp});
    let report = verify(&keys(), &body, Some(&head)).unwrap();
    assert_eq!(report["result"], "complete-through-trusted-head");
    head["head"]["wall"] = json::json!(0);
    assert!(verify(&keys(), &body, Some(&head)).is_err());
}

#[test]
fn linked_records_keep_the_optional_records_tail_in_the_fingerprint() {
    let mut lines = lines();
    let line = &mut lines[0];
    line["user_present"] = json::json!("1");
    line["user"] = json::json!("alice");
    line["labels_count"] = json::json!("1");
    line["labels"] = json::json!([{"name": "team", "value": "support"}]);
    let mut digest = Digest::new(Framing::LengthPrefixed);
    for &(name, kind) in fields(V7).unwrap().iter().skip(2) {
        if !name.contains("[]") {
            feed(&mut digest, &line[name], kind).unwrap();
        }
    }
    digest
        .num(1)
        .text("alice")
        .num(1)
        .text("team")
        .text("support");
    digest.num(1700000000000).num(1);
    digest.raw(&32u64.to_be_bytes()).raw(&[0; 32]);
    line["hash"] = json::json!(digest.finish());
    let mut body = range(&lines, vec![page(&lines, 1, 1)]);
    body["to"] = json::json!(1);
    body["records"] = json::json!(&lines[..1]);
    body["cover"] = json::json!([]);
    assert_eq!(
        verify(&keys(), &body, None).unwrap()["authenticated_records"],
        1
    );
    body["records"][0]["labels"][0]["value"] = json::json!("changed");
    assert!(verify(&keys(), &body, None).is_err());
}

#[test]
fn malformed_stamp_fields_and_delegated_authority_are_refused() {
    let lines = lines();
    for (name, value) in [
        ("node", json::json!(22)),
        ("node", json::json!("21")),
        ("sealer", json::json!(22)),
        ("kind", json::json!("unknown")),
        ("sig_alg", json::json!("unknown")),
        ("key_cert", json::json!(1)),
        ("signature", json::json!("AA".repeat(64))),
        ("fingerprint", json::json!("AA".repeat(32))),
    ] {
        let mut stamp = page(&lines, 1, 3);
        stamp[name] = value;
        assert!(
            verify(&keys(), &range(&lines, vec![stamp]), None).is_err(),
            "{name}"
        );
    }
    let mut set = AuditKeySet::new();
    for seed in [42, 43] {
        let key = AuditSigningKey::from_seed(&[seed; 32]);
        set.insert(AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap());
    }
    let keys = json::parse_value(busbar_kernel_audit::expose::keys_body(&set).as_bytes()).unwrap();
    assert!(verify(&keys, &range(&lines, vec![page(&lines, 1, 3)]), None).is_err());
}

#[test]
fn a_cover_only_page_cannot_authenticate_the_requested_window() {
    let lines = lines();
    let mut body = range(&lines, vec![page(&lines, 3, 3)]);
    body["from"] = json::json!(2);
    body["records"] = json::json!(&lines[1..2]);
    assert!(verify(&keys(), &body, None).is_err());
}

#[test]
fn a_mixed_window_preserves_the_legacy_line_signature() {
    let mut lines = lines();
    lines[0]["recipe"] = json::json!(DIGEST_RECIPE_V7);
    let hash = record_digest(&lines[0], DIGEST_RECIPE_V7).unwrap();
    lines[0]["hash"] = json::json!(hash);
    lines[0]["signature"] = json::json!(signer().sign_digest(&hash));
    lines[0]["key_id"] = json::json!(signer().key_id());
    for index in 1..3 {
        lines[index]["prev_hash"] = lines[index - 1]["hash"].clone();
        let mut digest = Digest::new(Framing::LengthPrefixed);
        for &(name, kind) in fields(V7).unwrap().iter().skip(2) {
            if !name.contains("[]") {
                feed(&mut digest, &lines[index][name], kind).unwrap();
            }
        }
        digest.num(1700000000000).num(index as u64 + 1);
        digest.raw(&32u64.to_be_bytes()).raw(
            &Fingerprint::from_hex(text(&lines[index], "prev_hash").unwrap())
                .unwrap()
                .0,
        );
        lines[index]["hash"] = json::json!(digest.finish());
    }
    let mut body = range(&lines, vec![page(&lines, 2, 3)]);
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["authenticated_records"], 2);
    assert_eq!(report["legacy_signed_lines"], 1);
    body["records"][0]["signature"] = json::json!("00".repeat(64));
    assert!(verify(&keys(), &body, None).is_err());
}

#[test]
fn linked_lines_cannot_bypass_page_authority_via_a_legacy_envelope() {
    let lines = lines();
    let mut body = range(&lines, vec![]);
    body["recipe"] = json::json!(DIGEST_RECIPE_V7);
    body["signature_domain"] = json::json!(SIGNATURE_DOMAIN);
    for index in 0..2 {
        let hash = text(&body["records"][index], "hash").unwrap().to_owned();
        body["records"][index]["signature"] = json::json!(signer().sign_digest(&hash));
        body["records"][index]["key_id"] = json::json!(signer().key_id());
    }
    assert!(verify(&keys(), &body, None).is_err());
}
