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
    page_kind(lines, from, to, StampKind::Live)
}

fn page_kind(lines: &[Value], from: u64, to: u64, kind: StampKind) -> Value {
    let (notary, bootstrap) = signer().into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let stamp = Stamp {
        node: 21,
        from,
        to,
        fingerprint: Fingerprint::from_hex(lines[(to - 1) as usize]["hash"].as_str().unwrap())
            .unwrap(),
        kind,
        sealer: if kind == StampKind::AfterRestart {
            22
        } else {
            21
        },
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
    };
    let stamp = if kind == StampKind::AfterRestart {
        BootstrapSigner::new(bootstrap).sign_restart_page(stamp)
    } else {
        Notary::new(notary).sign_stamp(stamp)
    }
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

#[test]
fn final_and_restart_pages_report_their_actual_kind() {
    let lines = lines();
    let report = verify(
        &keys(),
        &range(&lines, vec![page_kind(&lines, 1, 3, StampKind::Final)]),
        None,
    )
    .unwrap();
    assert_eq!(report["pages"], 0);
    assert_eq!(report["final_pages"], 1);
    assert_eq!(report["authenticated_records"], 2);
    let report = verify(
        &keys(),
        &range(
            &lines,
            vec![page_kind(&lines, 1, 3, StampKind::AfterRestart)],
        ),
        None,
    )
    .unwrap();
    assert_eq!(report["pages"], 0);
    assert_eq!(report["restart_sealed"][0]["sealer"], 22);
    assert_eq!(report["restart_sealed"][0]["from"], 1);
    assert_eq!(report["restart_sealed"][0]["to"], 2);
}

#[test]
fn a_signed_break_prevents_trusted_head_completeness() {
    let lines = lines();
    let terminal = page(&lines, 3, 3);
    let mut body = range(
        &lines,
        vec![page(&lines, 1, 1), notice(2, 2), terminal.clone()],
    );
    body["to"] = json::json!(3);
    body["records"] = json::json!(lines);
    body["cover"] = json::json!([]);
    let head = json::json!({"recipe": LINK_RECIPE, "signature_domain": STAMP_DOMAIN,
        "algorithm": SIGNATURE_ALGORITHM, "next_seq": 4, "head": terminal});
    assert!(verify(&keys(), &body, Some(&head)).is_err());
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["authenticated_records"], 2);
    assert_eq!(report["all_requested_records_authenticated"], false);
}

#[test]
fn a_page_authenticates_only_the_returned_suffix() {
    let lines = lines();
    let mut body = range(&lines, vec![page(&lines, 1, 3)]);
    body["from"] = json::json!(2);
    body["records"] = json::json!(&lines[1..2]);
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["from"], 2);
    assert_eq!(report["authenticated_records"], 1);
    assert_eq!(report["starts_at_genesis"], false);
}

#[test]
fn signed_page_fields_cannot_be_rewritten() {
    let lines = lines();
    for (name, value) in [
        ("host", json::json!("another-host")),
        ("every", json::json!(2)),
        ("stamped_ms", json::json!(1700000000002u64)),
        ("down_from_ms", json::json!(1)),
        ("down_to_ms", json::json!(1)),
        ("crypto", json::json!("another-backend")),
        ("from", json::json!(2)),
    ] {
        let mut stamp = page(&lines, 1, 3);
        stamp[name] = value;
        assert!(
            verify(&keys(), &range(&lines, vec![stamp]), None).is_err(),
            "{name}"
        );
    }
    let mut body = range(&lines, vec![page(&lines, 1, 3)]);
    body["records"][0]["linked_ms"] = json::json!("01700000000000");
    assert!(verify(&keys(), &body, None).is_err());
}

/// The per-boot notary key the certified tests delegate to.
fn delegate() -> busbar_contract::crypto::LocalSigner {
    busbar_contract::crypto::LocalSigner::from_seed(&[9; 32]).unwrap()
}

/// The deployment Bootstrap key as a seam signer (the same seed as [`signer`]).
fn bootstrap() -> busbar_contract::crypto::LocalSigner {
    busbar_contract::crypto::LocalSigner::from_seed(&[42; 32]).unwrap()
}

/// Unit lines `from .. from + count` of node 21, linked after `prev` (hex; empty at genesis).
fn units_after(prev: &str, from: u64, count: u64) -> Vec<Value> {
    let order = fields(V7).unwrap();
    let mut previous = prev.to_owned();
    (from..from + count)
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

/// A `notary_key.v2` line of node 21 at chain `seq` after `prev`, certifying [`delegate`], signed
/// by `by`.
fn certificate(
    seq: u64,
    prev: &str,
    by: &busbar_contract::crypto::LocalSigner,
) -> busbar_kernel_audit::NotaryKeyRecord {
    use busbar_contract::crypto::Signer;
    let delegate = delegate();
    let public = delegate.public_key();
    let prev_link = Fingerprint::from_hex(prev).unwrap();
    let mut certificate = busbar_kernel_audit::NotaryKeyCertificate {
        key_id: public.key_id.to_string(),
        sig_alg: public.alg.as_str().to_owned(),
        public_key: public.bytes.to_vec(),
        signed_by: by.public_key().key_id.to_string(),
        signature: Vec::new(),
    };
    by.sign(
        &certificate.preimage(21, seq, prev_link),
        &mut certificate.signature,
    )
    .unwrap();
    let mut record = busbar_kernel_audit::NotaryKeyRecord {
        node: 21,
        seq,
        linked_ms: 1700000000000,
        prev_link,
        fingerprint: Fingerprint::ZERO,
        certificate,
    };
    record.fingerprint = record.recompute_fingerprint();
    record
}

fn certificate_json(at: u64, record: &busbar_kernel_audit::NotaryKeyRecord) -> Value {
    json::parse_value(busbar_kernel_audit::expose::notary_key_json(at, record).as_bytes()).unwrap()
}

/// A stamp over `from ..= to` ending at the line whose hash is `fingerprint`, read at WAL
/// position `at`, naming certificate `key_cert`, signed by [`delegate`] (by the notary grant for
/// `live` and `final`; directly for any other kind, which no grant would sign).
fn delegated_page(
    fingerprint: &Value,
    from: u64,
    to: u64,
    kind: StampKind,
    key_cert: u64,
    at: u64,
) -> Value {
    use busbar_contract::crypto::Signer;
    let mut stamp = Stamp {
        node: 21,
        from,
        to,
        fingerprint: Fingerprint::from_hex(fingerprint.as_str().unwrap()).unwrap(),
        kind,
        sealer: 21,
        host: "host-a".into(),
        every: 1,
        stamped_ms: 1700000000001,
        down_from_ms: 0,
        down_to_ms: 0,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert,
        signature: Vec::new(),
    };
    if matches!(kind, StampKind::Live | StampKind::Final) {
        let (notary, _) = signer()
            .into_grants(LiveSigner::Delegated(Box::new(delegate())))
            .unwrap();
        stamp = Notary::new(notary).sign_stamp(stamp).unwrap();
    } else {
        let delegate = delegate();
        stamp.crypto = busbar_contract::crypto::BACKEND.to_owned();
        stamp.sig_alg = delegate.public_key().alg.as_str().to_owned();
        stamp.key_id = delegate.public_key().key_id.to_string();
        delegate
            .sign(&stamp.preimage(), &mut stamp.signature)
            .unwrap();
    }
    json::parse_value(busbar_kernel_audit::expose::stamp_json(Some(at), &stamp).as_bytes()).unwrap()
}

/// Node 21's chain: a certificate line at seq 1 (WAL 1), then unit lines 2, 3 and 4. The range
/// is [2, 3] with line 4 as cover, and one live page over 1..=4 under the certified key (WAL 5).
fn certified() -> (busbar_kernel_audit::NotaryKeyRecord, Vec<Value>, Value) {
    let cert = certificate(1, "", &bootstrap());
    let units = units_after(&cert.fingerprint.to_string(), 2, 3);
    let body = json::json!({"recipe": LINK_RECIPE, "signature_domain": STAMP_DOMAIN,
        "algorithm": SIGNATURE_ALGORITHM, "from": 2, "to": 3,
        "records": &units[..2], "cover": &units[2..],
        "stamps": [delegated_page(&units[2]["hash"], 1, 4, StampKind::Live, 1, 5)],
        "certs": [certificate_json(1, &cert)], "anchor": null, "seal_row": null});
    (cert, units, body)
}

/// §3.7 rule 3 (decision 159): a `live` page signed by the per-boot notary key that the
/// Bootstrap key certified at the `notary_key` line its `key_cert` names authenticates its page.
#[test]
fn a_live_stamp_under_a_certified_notary_key_authenticates_its_page() {
    let (_, _, body) = certified();
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["pages"], 1);
    assert_eq!(report["authenticated_records"], 2);
    assert_eq!(report["all_requested_records_authenticated"], true);
    assert!(report["unauthenticated_tail"].is_null());
    assert_eq!(report["result"], "signed-consistent-window");
}

/// §3.7 rule 3's key map: which key may sign which kind, and for how long a notary key stays
/// current. Every case fails verify ("stamp key not certified" or a bad signature).
#[test]
fn notary_key_authority_follows_the_key_map() {
    use busbar_contract::crypto::Signer;
    let (cert, units, body) = certified();
    let last = &units[2]["hash"];
    let refused = |body: &Value, why: &str| {
        assert!(verify(&keys(), body, None).is_err(), "{why}");
    };

    let mut restart = body.clone();
    restart["stamps"] = json::json!([delegated_page(last, 1, 4, StampKind::AfterRestart, 1, 5)]);
    refused(&restart, "an after_restart page is Bootstrap-only");

    let mut forged = body.clone();
    let other = busbar_contract::crypto::LocalSigner::from_seed(&[43; 32]).unwrap();
    forged["certs"] = json::json!([certificate_json(1, &certificate(1, "", &other))]);
    refused(&forged, "a certificate not signed by the Bootstrap key");

    let mut missing = body.clone();
    missing["certs"] = json::json!([]);
    refused(&missing, "no certificate at key_cert");

    let mut superseded = body.clone();
    superseded["certs"] = json::json!([certificate_json(1, &cert), certificate_json(3, &cert)]);
    refused(&superseded, "a later certificate supersedes the key");

    let mut after_final = body.clone();
    after_final["stamps"] = json::json!([
        delegated_page(&units[1]["hash"], 1, 3, StampKind::Final, 1, 5),
        delegated_page(last, 4, 4, StampKind::Live, 1, 6),
    ]);
    refused(&after_final, "a final page ends the key");
    let mut two_live = body.clone();
    two_live["stamps"] = json::json!([
        delegated_page(&units[1]["hash"], 1, 3, StampKind::Live, 1, 5),
        delegated_page(last, 4, 4, StampKind::Live, 1, 6),
    ]);
    assert_eq!(
        verify(&keys(), &two_live, None).unwrap()["authenticated_records"],
        2,
        "two live pages under one current key"
    );

    let mut before = body.clone();
    before["certs"] = json::json!([certificate_json(6, &cert)]);
    before["stamps"] = json::json!([delegated_page(last, 1, 4, StampKind::Live, 6, 5)]);
    refused(&before, "a stamp read before its certificate");

    let mut relocated = cert.clone();
    relocated.node = 22;
    relocated.fingerprint = relocated.recompute_fingerprint();
    let mut moved = body.clone();
    moved["certs"] = json::json!([certificate_json(1, &relocated)]);
    refused(&moved, "a certificate relabelled to another node");

    let mut break_by_delegate = body.clone();
    let mut notice_value = notice(2, 2);
    notice_value["key_id"] = json::json!(delegate().public_key().key_id.to_string());
    break_by_delegate["stamps"] = json::json!([notice_value]);
    refused(&break_by_delegate, "a break notice is Bootstrap-only");
}

/// §3.7 rule 1: a certificate line among the walked lines is digested by its own recipe and
/// linked like any line; a page over it authenticates it.
#[test]
fn a_certificate_line_in_the_walk_is_digested_and_linked() {
    let (cert, units, mut body) = certified();
    body["from"] = json::json!(1);
    body["records"] = json::json!([
        certificate_json(1, &cert),
        units[0].clone(),
        units[1].clone()
    ]);
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["authenticated_records"], 3);
    body["records"][0]["linked_ms"] = json::json!("1700000000001");
    assert!(verify(&keys(), &body, None).is_err());
}

/// §3.7 rule 4: a seal row must decode, name its node, and its stamp or break must pass rules 3
/// and 4; a valid restart page in it authenticates like a journal stamp.
#[test]
fn the_seal_row_is_checked_like_the_journal_evidence() {
    let lines = lines();
    let mut body = range(&lines, vec![]);
    body["seal_row"] = json::json!({"outcome": "undecodable"});
    assert!(verify(&keys(), &body, None).is_err(), "undecodable");

    body["seal_row"] = json::json!({"sealer": 22, "outcome": "clean", "through": 3});
    let report = verify(&keys(), &body, None).unwrap();
    assert!(
        report["result"].is_null(),
        "a clean row authenticates nothing"
    );

    let mut restart = page_kind(&lines, 1, 3, StampKind::AfterRestart);
    body["seal_row"] = json::json!({"sealer": 22, "outcome": "stamp", "stamp": restart.clone()});
    let report = verify(&keys(), &body, None).unwrap();
    assert_eq!(report["authenticated_records"], 2);
    assert_eq!(report["restart_sealed"][0]["sealer"], 22);

    body["seal_row"] = json::json!({"sealer": 23, "outcome": "stamp", "stamp": restart.clone()});
    assert!(verify(&keys(), &body, None).is_err(), "the row's sealer");
    restart["host"] = json::json!("rewritten");
    body["seal_row"] = json::json!({"sealer": 22, "outcome": "stamp", "stamp": restart});
    assert!(verify(&keys(), &body, None).is_err(), "the row's signature");
}
