// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel_audit::{AuditChain, AuditKeySet, AuditSigningKey};

fn example(page: &str, index: usize) -> Value {
    let body = page
        .split("```json")
        .nth(index + 1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    serde_json::from_str(body).unwrap()
}

fn signer() -> AuditSigningKey {
    AuditSigningKey::from_seed(&[42; 32])
}

fn keys() -> Value {
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).unwrap());
    serde_json::from_str(&busbar_kernel_audit::expose::keys_body(&keys)).unwrap()
}

fn sign(record: &mut Value) {
    let hash = record_digest(record, DIGEST_RECIPE).unwrap();
    record["hash"] = json!(hash);
    record["signature"] = json!(signer().sign_digest(&hash));
    record["key_id"] = json!(signer().key_id());
}

fn head(record: &Value) -> Value {
    json!({
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
        record["seq"] = json!(seq.to_string());
        record["prev_hash"] = json!(previous);
        sign(&mut record);
        previous = text(&record, "hash").unwrap().to_owned();
        records.push(record);
    }
    let head = head(records.last().unwrap());
    range["to"] = json!(3);
    range["anchor"] = head["head"].clone();
    range["records"] = json!(records);
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
                    quantity: u64::MAX,
                    source: QuantitySource::Count,
                    estimated: false,
                },
                UsageLine {
                    class: busbar_contract::MeterClassId::new("output"),
                    quantity: 9007199254740993,
                    source: QuantitySource::KernelFrames { factor: 7 },
                    estimated: true,
                },
            ],
            tier_bp: 10000,
            fee_count: 1,
            rate_card_version: u64::MAX,
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
        seq: 1,
        prev_hash: String::new(),
        recipe: Recipe::V4,
        hash: String::new(),
        signature: None,
        key_id: None,
    };
    record.hash = AuditChain::digest_of(&record);
    record.signature = Some(signer().sign_digest(&record.hash));
    record.key_id = Some(signer().key_id().to_owned());
    let records = vec![record];
    let chain = AuditChain::resume(&records);
    let range = serde_json::from_str(&busbar_kernel_audit::expose::range_body(
        &chain, &records, 1, 1,
    ))
    .unwrap();
    let head = serde_json::from_str(&busbar_kernel_audit::expose::head_body(&chain)).unwrap();
    assert!(verify(&keys(), &range, Some(&head)).is_ok());
}

#[test]
fn a_signed_window_does_not_claim_external_anchoring_or_freshness() {
    let (keys, mut range, head) = chain();
    range["from"] = json!(2);
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
    tamper["records"][1]["op_class"] = json!("changed");
    assert!(verify(&keys, &tamper, None).is_err());
    let mut deletion = range.clone();
    deletion["records"].as_array_mut().unwrap().remove(1);
    assert!(verify(&keys, &deletion, None).is_err());
    let mut reorder = range.clone();
    reorder["records"].as_array_mut().unwrap().swap(1, 2);
    assert!(verify(&keys, &reorder, None).is_err());
    let mut link = range;
    link["records"][1]["prev_hash"] = json!("00".repeat(32));
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
    range["records"] = json!([]);
    assert!(verify(&keys, &range, None).is_err());
}

#[test]
fn a_rewritten_truncation_envelope_needs_an_independently_retained_head() {
    let (keys, mut range, trusted) = chain();
    range["records"].as_array_mut().unwrap().pop();
    range["to"] = json!(2);
    range["anchor"] = head(&range["records"][1])["head"].clone();
    assert!(verify(&keys, &range, None).is_ok());
    assert!(verify(&keys, &range, Some(&trusted)).is_err());
}

#[test]
fn a_resigned_rewrite_cannot_match_the_retained_terminal_head() {
    let (keys, mut range, trusted) = chain();
    range["records"][2]["op_class"] = json!("rewritten");
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
    altered["records"][0]["signature"] = json!("00".repeat(64));
    assert!(verify(&keys, &altered, None).is_err());
    altered["records"][0]["signature"] = Value::Null;
    assert!(verify(&keys, &altered, None).is_err());
    let mut altered = range.clone();
    altered["anchor"]["wall"] = json!(1);
    assert!(verify(&keys, &altered, None).is_err());
    let mut altered = trusted;
    altered["head"]["seq"] = json!(2);
    assert!(verify(&keys, &range, Some(&altered)).is_err());
}

#[test]
fn unknown_versions_domains_algorithms_and_key_identifiers_are_refused() {
    let (keys, range, _) = chain();
    for member in ["recipe", "signature_domain", "algorithm"] {
        let mut bad = range.clone();
        bad[member] = json!("unknown");
        assert!(verify(&keys, &bad, None).is_err());
    }
    let mut bad = range.clone();
    bad["records"][0]["recipe"] = json!("busbar.audit.digest.v99");
    assert!(verify(&keys, &bad, None).is_err());
    let mut bad = keys;
    bad["keys"][0]["key_id"] = json!("00".repeat(8));
    assert!(verify(&bad, &range, None).is_err());
}

#[test]
fn malformed_numbers_group_counts_and_genesis_are_refused() {
    let (keys, range, _) = chain();
    for value in [
        json!(7),
        json!("07"),
        json!("+7"),
        json!("18446744073709551616"),
    ] {
        let mut bad = range.clone();
        bad["records"][0]["node"] = value;
        assert!(verify(&keys, &bad, None).is_err());
    }
    let mut bad = range.clone();
    bad["records"][0]["children_count"] = json!("1");
    assert!(verify(&keys, &bad, None).is_err());
    let mut bad = range;
    bad["records"][0]["prev_hash"] = json!("00".repeat(32));
    sign(&mut bad["records"][0]);
    assert!(verify(&keys, &bad, None).is_err());
}

#[test]
fn mixed_v2_v4_records_and_a_rotated_trusted_key_verify() {
    let (mut keys, mut range, _) = chain();
    let mut old = example(V2, 0)["records"][0].clone();
    old["recipe"] = json!(DIGEST_RECIPE_V2);
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
    bad["keys"] = json!([]);
    assert!(verify(&bad, &range, None).is_err());
    bad = keys.clone();
    bad["keys"][0]["public_key"] = json!(format!("01{}", "00".repeat(31)));
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
        std::fs::write(files.0.join(name), serde_json::to_vec(&body).unwrap()).unwrap();
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
