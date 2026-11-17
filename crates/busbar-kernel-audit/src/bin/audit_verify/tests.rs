// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::JsonValueMutTrait;
use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditSigningKey};

fn example(page: &str, index: usize) -> Value {
    let body = page
        .split("```json")
        .nth(index + 1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    json::parse_value(body.as_bytes()).unwrap()
}

fn signer() -> AuditSigningKey {
    AuditSigningKey::from_seed(&[42; 32])
}

fn keys() -> Value {
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).unwrap());
    json::parse_value(busbar_kernel_audit::expose::keys_body(&keys).as_bytes()).unwrap()
}

fn sign(record: &mut Value) {
    let hash = record_digest(record, DIGEST_RECIPE).unwrap();
    record["hash"] = json::json!(hash);
    record["signature"] = json::json!(signer().sign_digest(&hash));
    record["key_id"] = json::json!(signer().key_id());
}

fn head(record: &Value) -> Value {
    json::json!({
        "recipe": DIGEST_RECIPE,
        "signature_domain": SIGNATURE_DOMAIN,
        "algorithm": SIGNATURE_ALGORITHM,
        "next_seq": record_number(record, "seq").unwrap() + 1,
        "head": {
            "seq": record_number(record, "seq").unwrap(),
            "wall": record_number(record, "wall").unwrap(),
            "hash": record["hash"],
            "signature": record["signature"],
            "key_id": record["key_id"]
        }
    })
}

fn chain() -> (Value, Value, Value) {
    let mut range = example(V4, 0);
    let mut previous = String::new();
    let mut records = Vec::new();
    for seq in 1..=3 {
        let mut record = range["records"][0].clone();
        record["seq"] = json::json!(seq.to_string());
        record["prev_hash"] = json::json!(previous);
        sign(&mut record);
        previous = text(&record, "hash").unwrap().to_owned();
        records.push(record);
    }
    let head = head(records.last().unwrap());
    range["to"] = json::json!(3);
    range["anchor"] = head["head"].clone();
    range["records"] = json::json!(records);
    (keys(), range, head)
}

#[test]
fn published_v2_and_v4_examples_verify_with_their_original_signatures() {
    for page in [V2, V4] {
        let report = verify(
            &example(page, 2),
            &example(page, 0),
            Some(&example(page, 1)),
        )
        .unwrap();
        assert_eq!(report["result"], "complete-through-trusted-head");
        assert_eq!(report["starts_at_genesis"], true);
    }
}

#[test]
fn current_producer_output_verifies_with_wide_numbers_and_repeated_groups() {
    use busbar_contract::caps::{Outcome, UnitKey};
    use busbar_kernel_audit::{
        AuditRecord, Controls, FinishClass, HookApplied, HookHead, OpClassId, OutcomeFacts,
        QuantitySource, Recipe, Subject, Usage, UsageLine, What,
    };
    let mut record = AuditRecord {
        subject: Subject::PrincipalId("operator\nquoted\"".into()),
        what: What {
            unit_key: UnitKey::new(9),
            incarnation: u64::MAX,
            op_class: OpClassId::new("example.operation"),
            destination: Some("λ|é".into()),
            parent: Some(UnitKey::new(8)),
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1700000000,
        mono: u64::MAX,
        node: u64::MAX,
        origin_kind: "client",
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: true,
            emission_delta: i64::MIN,
            stale_policy: true,
        },
        usage: Usage {
            lines: vec![
                UsageLine {
                    class: busbar_contract::MeterClassId::new("input"),
                    quantity: u64::MAX.into(),
                    source: QuantitySource::Count,
                    estimated: false,
                },
                UsageLine {
                    class: busbar_contract::MeterClassId::new("output"),
                    quantity: 9007199254740993u64.into(),
                    source: QuantitySource::KernelFrames { factor: 7 },
                    estimated: true,
                },
            ],
            tier_bp: 10000,
            fee_count: 1,
            rate_card_version: Some([0x4a; 20]),
            bucket_chain_ref: "a|b".into(),
        },
        controls: Controls {
            hooks_applied: vec![
                HookApplied {
                    hook: "first".into(),
                    head: HookHead::Modify,
                    failed: false,
                },
                HookApplied {
                    hook: "second".into(),
                    head: HookHead::Veto,
                    failed: true,
                },
            ],
            children: vec![UnitKey::new(11), UnitKey::new(12)],
            ..Controls::default()
        },
        correlation_hash: None,
        unit: busbar_kernel_audit::UnitFacts::default(),
        linked_ms: 0,
        seq: 1,
        prev_hash: String::new(),
        recipe: Recipe::V8,
        hash: String::new(),
        signature: None,
        key_id: None,
    };
    record.linked_ms = 1_700_000_000_123;
    record.hash = AuditChain::digest_of(&record);
    let records = vec![record];
    let mut range: Value =
        json::parse_value(busbar_kernel_audit::expose::range_body(&records, 1, 1).as_bytes())
            .unwrap();
    assert_eq!(
        range["recipe"], LINK_RECIPE,
        "the range names the link recipe"
    );
    assert_eq!(range["signature_domain"], busbar_kernel_audit::STAMP_DOMAIN);
    assert_eq!(range["records"][0]["recipe"], LINK_RECIPE);
    assert_eq!(
        range["records"][0]["prev_hash"], "",
        "genesis is the empty text"
    );
    let report = verify(&keys(), &range, None).unwrap();
    assert!(
        report["result"].is_null(),
        "no page stamp, no authentication"
    );
    assert_eq!(
        report["unauthenticated_tail"],
        json::json!({"from": 1, "to": 1})
    );

    // The covering stamp verifies, and an edit breaks it.
    let (notary, _) = signer()
        .into_grants(busbar_kernel_audit::LiveSigner::SameAsBootstrap)
        .unwrap();
    let stamp = busbar_kernel_audit::Notary::new(notary)
        .sign_stamp(busbar_kernel_audit::Stamp {
            node: u64::MAX,
            from: 1,
            to: 1,
            fingerprint: busbar_kernel_audit::Fingerprint::from_hex(&records[0].hash).unwrap(),
            kind: busbar_kernel_audit::StampKind::Live,
            sealer: u64::MAX,
            host: "host-a".into(),
            every: 1000,
            stamped_ms: 1_700_000_000_124,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: Vec::new(),
        })
        .unwrap();
    range["stamps"] = json::json!([json::parse_value(
        busbar_kernel_audit::expose::stamp_json(Some(2), &stamp).as_bytes()
    )
    .unwrap()]);
    let report = verify(&keys(), &range, None).unwrap();
    assert_eq!(report["result"], "signed-consistent-window");
    assert_eq!(report["authenticated_records"], 1);
    assert_eq!(report["all_requested_records_authenticated"], true);
    for (member, value) in [
        ("destination", json::json!("μ|é")),
        ("incarnation", json::json!("0")),
        ("linked_ms", json::json!("1700000000122")),
    ] {
        let mut edited = range.clone();
        edited["records"][0][member] = value;
        assert!(verify(&keys(), &edited, None).is_err(), "{member}");
    }
}

#[test]
fn a_signed_window_does_not_claim_external_anchoring_or_freshness() {
    let (keys, mut range, head) = chain();
    range["from"] = json::json!(2);
    range["records"].as_array_mut().unwrap().remove(0);
    let report = verify(&keys, &range, None).unwrap();
    assert_eq!(report["result"], "signed-consistent-window");
    assert_eq!(report["trusted_terminal_head"], false);
    assert_eq!(report["source_anchor_is_external_trust"], false);
    assert_eq!(report["freshness_verified"], false);
    assert_eq!(report["starts_at_genesis"], false);
    let anchored = verify(&keys, &range, Some(&head)).unwrap();
    assert_eq!(anchored["result"], "complete-through-trusted-head");
    assert_eq!(anchored["starts_at_genesis"], false);
}

#[test]
fn tamper_deletion_reorder_and_broken_link_are_refused() {
    let (keys, range, _) = chain();
    let mut tamper = range.clone();
    tamper["records"][1]["op_class"] = json::json!("changed");
    assert!(verify(&keys, &tamper, None).is_err());
    let mut deletion = range.clone();
    deletion["records"].as_array_mut().unwrap().remove(1);
    assert!(verify(&keys, &deletion, None).is_err());
    let mut reorder = range.clone();
    reorder["records"].as_array_mut().unwrap().swap(1, 2);
    assert!(verify(&keys, &reorder, None).is_err());
    let mut link = range;
    link["records"][1]["prev_hash"] = json::json!("00".repeat(32));
    sign(&mut link["records"][1]);
    assert!(verify(&keys, &link, None).is_err());
}

#[test]
fn incomplete_fetch_is_not_reported_as_tampering() {
    let (keys, mut range, _) = chain();
    range["records"].as_array_mut().unwrap().pop();
    assert_eq!(
        verify(&keys, &range, None).unwrap_err(),
        "the requested fetch is incomplete or contains extra records"
    );
    range["records"] = json::json!([]);
    assert!(verify(&keys, &range, None).is_err());
}

#[test]
fn a_rewritten_truncation_envelope_needs_an_independently_retained_head() {
    let (keys, mut range, trusted) = chain();
    range["records"].as_array_mut().unwrap().pop();
    range["to"] = json::json!(2);
    range["anchor"] = head(&range["records"][1])["head"].clone();
    assert!(verify(&keys, &range, None).is_ok());
    assert!(verify(&keys, &range, Some(&trusted)).is_err());
}

#[test]
fn a_resigned_rewrite_cannot_match_the_retained_terminal_head() {
    let (keys, mut range, trusted) = chain();
    range["records"][2]["op_class"] = json::json!("rewritten");
    sign(&mut range["records"][2]);
    range["anchor"] = head(&range["records"][2])["head"].clone();
    assert!(verify(&keys, &range, None).is_ok());
    assert!(verify(&keys, &range, Some(&trusted)).is_err());
}

#[test]
fn wrong_key_bad_signature_unsigned_and_forged_anchor_metadata_are_refused() {
    let (keys, range, trusted) = chain();
    assert!(verify(&example(V4, 2), &range, None).is_err());
    let mut altered = range.clone();
    altered["records"][0]["signature"] = json::json!("00".repeat(64));
    assert!(verify(&keys, &altered, None).is_err());
    altered["records"][0]["signature"] = Value::new();
    assert!(verify(&keys, &altered, None).is_err());
    let mut altered = range.clone();
    altered["anchor"]["wall"] = json::json!(1);
    assert!(verify(&keys, &altered, None).is_err());
    let mut altered = trusted;
    altered["head"]["seq"] = json::json!(2);
    assert!(verify(&keys, &range, Some(&altered)).is_err());
}

#[test]
fn unknown_versions_domains_algorithms_and_key_identifiers_are_refused() {
    let (keys, range, _) = chain();
    for member in ["recipe", "signature_domain", "algorithm"] {
        let mut bad = range.clone();
        bad[member] = json::json!("unknown");
        assert!(verify(&keys, &bad, None).is_err());
    }
    let mut bad = range.clone();
    bad["records"][0]["recipe"] = json::json!("busbar.audit.digest.v99");
    assert!(verify(&keys, &bad, None).is_err());
    let mut bad = keys;
    bad["keys"][0]["key_id"] = json::json!("00".repeat(8));
    assert!(verify(&bad, &range, None).is_err());
}

#[test]
fn malformed_numbers_group_counts_and_genesis_are_refused() {
    let (keys, range, _) = chain();
    for value in [
        json::json!(7),
        json::json!("07"),
        json::json!("+7"),
        json::json!("18446744073709551616"),
    ] {
        let mut bad = range.clone();
        bad["records"][0]["node"] = value;
        assert!(verify(&keys, &bad, None).is_err());
    }
    let mut bad = range.clone();
    bad["records"][0]["children_count"] = json::json!("1");
    assert!(verify(&keys, &bad, None).is_err());
    let mut bad = range;
    bad["records"][0]["prev_hash"] = json::json!("00".repeat(32));
    sign(&mut bad["records"][0]);
    assert!(verify(&keys, &bad, None).is_err());
}

#[test]
fn mixed_v2_v4_records_and_a_rotated_trusted_key_verify() {
    let (mut keys, mut range, _) = chain();
    let mut old = example(V2, 0)["records"][0].clone();
    old["recipe"] = json::json!(DIGEST_RECIPE_V2);
    range["records"][0] = old;
    keys["keys"]
        .as_array_mut()
        .unwrap()
        .push(example(V2, 2)["keys"][0].clone());
    for index in 1..3 {
        range["records"][index]["prev_hash"] = range["records"][index - 1]["hash"].clone();
        sign(&mut range["records"][index]);
    }
    let trusted = head(&range["records"][2]);
    range["anchor"] = trusted["head"].clone();
    assert!(verify(&keys, &range, Some(&trusted)).is_ok());
}

#[test]
fn absent_or_weak_trusted_keys_cannot_authenticate_a_range() {
    let (keys, range, _) = chain();
    let mut bad = keys.clone();
    bad["keys"] = json::json!([]);
    assert!(verify(&bad, &range, None).is_err());
    bad = keys.clone();
    bad["keys"][0]["public_key"] = json::json!(format!("01{}", "00".repeat(31)));
    assert!(verify(&bad, &range, None).is_err());
    bad = keys;
    let duplicate = bad["keys"][0].clone();
    bad["keys"].as_array_mut().unwrap().push(duplicate);
    assert!(verify(&bad, &range, None).is_err());
}

#[test]
fn file_options_run_offline_and_refuse_missing_or_repeated_trust_inputs() {
    struct Files(std::path::PathBuf);
    impl Drop for Files {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let files = Files(std::env::temp_dir().join(format!(
        "busbar-audit-verify-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&files.0).unwrap();
    let (keys, range, head) = chain();
    for (name, body) in [("keys", keys), ("range", range), ("head", head)] {
        std::fs::write(files.0.join(name), json::to_vec(&body).unwrap()).unwrap();
    }
    let args = vec![
        "--keys".into(),
        files.0.join("keys").into_os_string(),
        "--range".into(),
        files.0.join("range").into_os_string(),
        "--trusted-head".into(),
        files.0.join("head").into_os_string(),
    ];
    let report = crate::run(args.clone()).unwrap();
    assert_eq!(report["result"], "complete-through-trusted-head");
    let mut duplicate = args.clone();
    duplicate.extend(["--keys".into(), files.0.join("keys").into_os_string()]);
    assert!(crate::run(duplicate).is_err());
    assert!(crate::run(args[2..].to_vec()).is_err());
    std::fs::write(files.0.join("range"), b"not JSON").unwrap();
    assert!(crate::run(args).is_err());
}

#[test]
fn keyed_recipe_rejects_noncanonical_presence_and_key_spelling() {
    let (_, range, _) = chain();
    let mut record = range["records"][0].clone();
    record["recipe"] = json::json!(DIGEST_RECIPE);
    for (present, key) in [
        ("0", "".to_string()),
        ("1", "00".repeat(20)),
        ("1", "4a".repeat(20)),
    ] {
        record["rate_card_key_present"] = json::json!(present);
        record["rate_card_version"] = json::json!(key);
        assert!(record_digest(&record, DIGEST_RECIPE).is_ok());
    }
    for (present, key) in [
        ("01", "".to_string()),
        ("2", "00".repeat(20)),
        ("0", "00".repeat(20)),
        ("1", "".to_string()),
        ("1", "A0".repeat(20)),
        ("1", "0".repeat(39)),
        ("1", "0".repeat(41)),
        ("1", "é".repeat(20)),
    ] {
        record["rate_card_key_present"] = json::json!(present);
        record["rate_card_version"] = json::json!(key);
        assert!(record_digest(&record, DIGEST_RECIPE).is_err());
    }
}

#[test]
fn mixed_v2_v4_v5_window_verifies_without_rewriting_old_signed_record() {
    let (mut keys, mut range, _) = chain();
    let original = example(V2, 0)["records"][0].clone();
    range["records"][0] = original.clone();
    keys["keys"]
        .as_array_mut()
        .unwrap()
        .push(example(V2, 2)["keys"][0].clone());
    range["records"][1]["prev_hash"] = original["hash"].clone();
    sign(&mut range["records"][1]);
    range["records"][2]["recipe"] = json::json!(DIGEST_RECIPE);
    range["records"][2]["rate_card_key_present"] = json::json!("1");
    range["records"][2]["rate_card_version"] = json::json!("00".repeat(20));
    range["records"][2]["prev_hash"] = range["records"][1]["hash"].clone();
    sign(&mut range["records"][2]);
    let trusted = head(&range["records"][2]);
    range["anchor"] = trusted["head"].clone();
    assert_eq!(range["recipe"], DIGEST_RECIPE_V4);
    assert!(original.get("recipe").is_none());
    assert_eq!(range["records"][1]["recipe"], DIGEST_RECIPE_V4);
    assert_eq!(range["records"][2]["recipe"], DIGEST_RECIPE);
    assert_eq!(
        verify(&keys, &range, Some(&trusted)).unwrap_err(),
        "a record recipe is absent"
    );

    range["recipe"] = json::json!(DIGEST_RECIPE_V2);
    let report = verify(&keys, &range, Some(&trusted)).unwrap();
    assert_eq!(report["result"], "complete-through-trusted-head");
    assert_eq!(report["records"], 3);
    assert_eq!(report["trusted_terminal_head"], true);
    assert_eq!(report["to"], trusted["head"]["seq"]);
    assert_eq!(trusted["head"]["seq"], 3);
    assert_eq!(trusted["head"]["hash"], range["records"][2]["hash"]);
    assert_eq!(
        range["records"][0], original,
        "the original old signature/preimage stays exact"
    );
}

#[test]
fn mixed_v5_v6_v5_exact_quantity_chain_verifies_with_explicit_dispatch() {
    let (keys, mut range, _) = chain();
    let mut previous = String::new();
    for index in 0..3 {
        let record = &mut range["records"][index];
        record["recipe"] = json::json!(if index == 1 {
            DIGEST_RECIPE_V6
        } else {
            DIGEST_RECIPE
        });
        record["rate_card_key_present"] = json::json!("0");
        record["rate_card_version"] = json::json!("");
        record["prev_hash"] = json::json!(previous);
        record["lines_count"] = json::json!("1");
        record["lines"] = json::json!([{
            "class": "input",
            "quantity": if index == 1 { "27.5" } else { "27" },
            "source": "Count",
            "estimated": "0"
        }]);
        sign(record);
        previous = record["hash"].as_str().unwrap().to_owned();
    }
    range["recipe"] = json::json!(DIGEST_RECIPE);
    let trusted = head(&range["records"][2]);
    range["anchor"] = trusted["head"].clone();
    assert_eq!(verify(&keys, &range, Some(&trusted)).unwrap()["records"], 3);
    let original = range["records"][0].clone();
    range["records"][1]["lines"][0]["quantity"] = json::json!("27.50");
    assert_eq!(
        record_digest(&range["records"][1], DIGEST_RECIPE).unwrap_err(),
        "noncanonical exact audit quantity"
    );
    assert_eq!(range["records"][0], original);
}

/// A LINK RANGE VERIFIES AGAINST THE PUBLISHED LINK PAGE (`docs/audit-link-v1.md`) UNDER ITS
/// COVERING STAMP: an outside verifier recomputes every line from the page's field table, the
/// attempts group and the records tail included; the covering stamp verifies, and an edit breaks
/// it.
#[test]
fn v7_records_verify_against_the_published_page() {
    use busbar_contract::caps::{Outcome, UnitKey};
    use busbar_kernel_audit::{
        Attempt, AttemptOutcome, AuditRecord, Controls, FinishClass, OpClassId, OutcomeFacts,
        QuantitySource, Recipe, RecordFacts, Subject, UnitFacts, Usage, UsageLine, What,
    };
    let mut records = Vec::new();
    let mut previous = String::new();
    for seq in 1..=2u64 {
        let mut record = AuditRecord {
            subject: Subject::PrincipalId("key-1".into()),
            what: What {
                unit_key: UnitKey::new(seq),
                incarnation: 3,
                op_class: OpClassId::new("chat.completion"),
                destination: Some("pools-lane".into()),
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: 1_700_000_000,
            mono: seq,
            node: 9,
            origin_kind: "client",
            outcome: OutcomeFacts {
                unit_end: Outcome::Completed,
                step: None,
                finish: FinishClass::Complete,
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: Usage {
                lines: vec![UsageLine {
                    class: busbar_contract::MeterClassId::new("input"),
                    quantity: busbar_contract::Count::parse(if seq == 1 { "27" } else { "27.5" })
                        .unwrap(),
                    source: QuantitySource::Count,
                    estimated: false,
                }],
                tier_bp: 10_000,
                fee_count: 1,
                rate_card_version: Some([0x4a; 20]),
                bucket_chain_ref: String::new(),
            },
            controls: Controls::default(),
            correlation_hash: None,
            unit: UnitFacts {
                wall_ms: 1_700_000_000_250,
                attribution: busbar_kernel_audit::attribution("team", "default", "acme"),
                boot_nonce: [0xab; 16],
                status: 200,
                ttft_us: 1_500,
                total_us: 9_000,
                attempts: [
                    Some(Attempt {
                        outcome: AttemptOutcome::Failover,
                        target: "lane-a".into(),
                        reason: "upstream_5xx".into(),
                        us: 0,
                    }),
                    Some(Attempt {
                        outcome: AttemptOutcome::Ok,
                        target: "lane-b".into(),
                        reason: String::new(),
                        us: 0,
                    }),
                    None,
                    None,
                ],
                attempts_total: 2,
                records: RecordFacts::default(),
            },
            linked_ms: 1_700_000_000_000 + seq,
            seq,
            prev_hash: previous.clone(),
            recipe: Recipe::V8,
            hash: String::new(),
            signature: None,
            key_id: None,
        };
        // The second record keeps `records.user` and `records.labels`: the optional tail.
        if seq == 2 {
            record.unit.records = RecordFacts {
                user: Some("u_00112233445566778899aabbccddeeff".into()),
                labels: vec![(std::sync::Arc::from("x-team"), "payments".into())],
            };
        }
        record.hash = AuditChain::digest_of(&record);
        previous.clone_from(&record.hash);
        records.push(record);
    }
    let mut range: Value =
        json::parse_value(busbar_kernel_audit::expose::range_body(&records, 1, 2).as_bytes())
            .unwrap();
    assert_eq!(range["recipe"], LINK_RECIPE);
    assert_eq!(range["records"][1]["recipe"], LINK_RECIPE);
    let (notary, _) = signer()
        .into_grants(busbar_kernel_audit::LiveSigner::SameAsBootstrap)
        .unwrap();
    let stamp = busbar_kernel_audit::Notary::new(notary)
        .sign_stamp(busbar_kernel_audit::Stamp {
            node: 9,
            from: 1,
            to: 2,
            fingerprint: busbar_kernel_audit::Fingerprint::from_hex(&records[1].hash).unwrap(),
            kind: busbar_kernel_audit::StampKind::Live,
            sealer: 9,
            host: "host-a".into(),
            every: 1000,
            stamped_ms: 1_700_000_000_003,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: Vec::new(),
        })
        .unwrap();
    range["stamps"] = json::json!([json::parse_value(
        busbar_kernel_audit::expose::stamp_json(Some(3), &stamp).as_bytes()
    )
    .unwrap()]);
    let report = verify(&keys(), &range, None).unwrap();
    assert_eq!(report["records"], 2);
    assert_eq!(report["authenticated_records"], 2);

    assert!(
        range["records"][0].get("user_present").is_none(),
        "a record that keeps neither user nor labels frames no tail"
    );
    assert_eq!(
        range["records"][1]["user"],
        "u_00112233445566778899aabbccddeeff"
    );
    let mut tampered = range.clone();
    tampered["records"][1]["labels"][0]["value"] = json::json!("billing");
    assert!(
        verify(&keys(), &tampered, None).is_err(),
        "a label is digested"
    );
    let mut tampered = range.clone();
    tampered["records"][1]["user"] = json::json!("u_ffeeddccbbaa99887766554433221100");
    assert!(
        verify(&keys(), &tampered, None).is_err(),
        "the user is digested"
    );
    let mut stripped = range.clone();
    let second = stripped["records"][1].as_object_mut().unwrap();
    for member in ["user_present", "user", "labels_count", "labels"] {
        second.remove(&member);
    }
    assert!(
        verify(&keys(), &stripped, None).is_err(),
        "the records tail cannot be dropped"
    );

    let mut tampered = range.clone();
    tampered["records"][0]["attribution"] = json::json!("team\u{1f}default\u{1f}other");
    assert!(
        verify(&keys(), &tampered, None).is_err(),
        "the attribution is digested"
    );
    let mut tampered = range;
    tampered["records"][1]["attempts"][0]["outcome"] = json::json!("ok");
    assert!(
        verify(&keys(), &tampered, None).is_err(),
        "an attempt is digested"
    );
}
