// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::test_support::tokens::pass;
use busbar_contract::{
    caps::{
        Audit as AuditStep, KernelSeal, LocatorPtr, MeterClassId, Origin, OriginKind, Outcome,
        ReasonCode, StepName, UnitKey,
    },
    ClassDirection,
};

use busbar_kernel_audit::expose;
use busbar_kernel_audit::heads::{HeadHistory, HEAD_SAMPLE_SECONDS};
use busbar_kernel_audit::recipe::{digest_fields, digest_over, DigestValue};
use busbar_kernel_audit::record::{
    Audit, AuditChain, AuditInputs, AuditRecord, Controls, FinishClass, HookApplied, HookHead,
    OpClassId, OutcomeFacts, QuantitySource, Subject, Usage, UsageLine, What,
};
use busbar_kernel_audit::sign::{AuditKeySet, AuditSigningKey, AuditVerifyingKey, KeyError};
use busbar_kernel_audit::test_support;

const TEST_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn origin() -> Origin {
    Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client)
}

fn signer() -> AuditSigningKey {
    AuditSigningKey::from_hex_seed(TEST_SEED_HEX).expect("the test seed is 64 lowercase hex")
}

fn inputs(unit: u64) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: Some(UnitKey::new(unit + 500)),
            pre_hook_head: Some("hook-head-before".into()),
            post_hook_head: Some("hook-head-after".into()),
        },
        wall: 1_700_000_000 + unit,
        mono: unit * 1_000,
        origin: origin(),
        outcome: OutcomeFacts {
            unit_end: Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
            step: Some(StepName::Admit),
            finish: FinishClass::Error,
            hook_failed: true,
            emission_delta: -7,
            stale_policy: true,
        },
        usage: Usage {
            lines: vec![
                UsageLine {
                    class: MeterClassId::new("tokens_out"),
                    quantity: 120,
                    source: QuantitySource::Locator {
                        direction: ClassDirection::Response,
                        ptr: LocatorPtr::new("/usage/output_tokens"),
                    },
                    estimated: false,
                },
                UsageLine {
                    class: MeterClassId::new("tokens_in"),
                    quantity: 44,
                    source: QuantitySource::Count,
                    estimated: true,
                },
            ],
            tier_bp: 9_000,
            fee_count: 1,
            rate_card_version: 3,
            bucket_chain_ref: "chain:free>paid".into(),
        },
        controls: Controls {
            hold_ref: Some("hold-1".into()),
            settle_ref: Some("settle-1".into()),
            slice_ref: Some("slice-1".into()),
            lease_ref: Some("lease-1".into()),
            lease_epoch: 4,
            policy_epoch: 7,
            hooks_applied: vec![HookApplied {
                hook: "compress".into(),
                head: HookHead::Modify,
                failed: false,
            }],
            replayed: true,
            children: vec![UnitKey::new(unit + 1000), UnitKey::new(unit + 1001)],
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

pub(super) fn rich_inputs(unit: u64) -> AuditInputs {
    inputs(unit)
}

fn empty_group_inputs() -> AuditInputs {
    let mut i = inputs(9);
    i.usage.lines.clear();
    i.controls.hooks_applied.clear();
    i.controls.children.clear();
    i.what.destination = None;
    i.what.parent = None;
    i.what.pre_hook_head = None;
    i.what.post_hook_head = None;
    i.outcome.step = None;
    i.outcome.unit_end = Outcome::Completed;
    i.correlation_label = None;
    i.controls.hold_ref = None;
    i.controls.settle_ref = None;
    i.controls.slice_ref = None;
    i.controls.lease_ref = None;
    i.subject = Subject::Arrival;
    i
}

#[test]
fn the_published_recipe_hashes_to_the_digest_the_chain_seals() {
    let mut chain = AuditChain::new();
    for record in [
        chain.seal(inputs(1), &pass::<AuditStep>()),
        chain.seal(empty_group_inputs(), &pass::<AuditStep>()),
        chain.seal(inputs(3), &pass::<AuditStep>()),
    ] {
        assert_eq!(
            digest_over(&digest_fields(&record)),
            AuditChain::digest_of(&record),
            "the published recipe does not reproduce the sealed digest"
        );
        assert_eq!(record.hash, digest_over(&digest_fields(&record)));
    }
}

#[test]
fn every_recipe_field_is_published_under_its_own_name() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(inputs(1), &pass::<AuditStep>());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);
    for field in digest_fields(&record) {
        let name = field
            .name
            .split("[]")
            .next()
            .expect("a split always yields one");
        assert!(
            body.contains(&format!("\"{name}\"")),
            "recipe field {} is not published in the range body",
            field.name
        );
    }

    assert!(body.contains("\"hash\""));
    assert!(body.contains("\"signature\""));
    assert!(body.contains("\"key_id\""));
}

#[test]
fn a_sealed_record_verifies_against_the_published_key() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(inputs(1), &pass::<AuditStep>());

    let published = AuditVerifyingKey::from_hex(&signer().public_key_hex())
        .expect("the published key is 64 lowercase hex");
    assert_eq!(record.key_id.as_deref(), Some(published.key_id()));
    assert_eq!(
        AuditChain::verify_signature(&record, &published),
        Ok(()),
        "a record this node sealed does not verify against the key this node publishes"
    );
    assert_eq!(
        record.signature.as_deref().map(str::len),
        Some(128),
        "an ed25519 signature is 64 bytes, which is 128 lowercase hex characters"
    );
}

#[test]
fn altering_any_field_breaks_the_signature_including_the_cosmetic_ones() {
    let mut chain = AuditChain::new().signing_with(signer());
    let sealed = chain.seal(inputs(1), &pass::<AuditStep>());
    let published =
        AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a published key");

    type Edit = (&'static str, fn(&mut AuditRecord));
    let edits: Vec<Edit> = vec![
        ("the monotonic clock", |r| r.mono += 1),
        ("the wall clock", |r| r.wall += 1),
        ("where it came from", |r| r.origin_kind = "internal"),
        ("a usage line's estimated flag", |r| {
            r.usage.lines[0].estimated = !r.usage.lines[0].estimated
        }),
        ("the tier's basis points", |r| r.usage.tier_bp += 1),
        ("the rate card version", |r| r.usage.rate_card_version += 1),
        ("whether a hook failed", |r| {
            r.outcome.hook_failed = !r.outcome.hook_failed
        }),
        ("whether the policy was stale", |r| {
            r.outcome.stale_policy = !r.outcome.stale_policy
        }),
        ("whether it was replayed", |r| {
            r.controls.replayed = !r.controls.replayed
        }),
        ("a child unit's number", |r| {
            r.controls.children[1] = UnitKey::new(1)
        }),
        ("the order of two usage lines", |r| r.usage.lines.swap(0, 1)),
        ("a hook's name", |r| {
            r.controls.hooks_applied[0].hook = "compres".into()
        }),
        ("a hook's head", |r| {
            r.controls.hooks_applied[0].head = HookHead::Pass
        }),
        ("whether a hook failed", |r| {
            r.controls.hooks_applied[0].failed = true
        }),
        ("the correlation hash", |r| {
            r.correlation_hash = Some("0".repeat(64))
        }),
        ("the lease epoch", |r| r.controls.lease_epoch += 1),
        ("the position in the chain", |r| r.seq += 1),
        ("the link to the predecessor", |r| {
            r.prev_hash = "0".repeat(64)
        }),
        ("the fee count", |r| r.usage.fee_count += 1),
        ("the destination", |r| {
            r.what.destination = Some("upstream-b".into())
        }),
    ];

    for (what, edit) in edits {
        let mut altered = sealed.clone();
        edit(&mut altered);
        assert_ne!(
            altered, sealed,
            "the edit to {what} did not actually change the record"
        );

        assert_eq!(
            AuditChain::verify_signature(&altered, &published),
            Err(KeyError::DigestMismatch),
            "editing {what} left a record that is not reported as edited"
        );

        let mut rehashed = altered.clone();
        rehashed.hash = AuditChain::digest_of(&rehashed);
        assert_eq!(
            AuditChain::verify_signature(&rehashed, &published),
            Err(KeyError::BadSignature),
            "editing {what} and rehashing left a record that still verifies"
        );
    }
}

#[test]
fn a_foreign_key_and_an_absent_signature_are_different_answers() {
    let mut signed_chain = AuditChain::new().signing_with(signer());
    let signed = signed_chain.seal(inputs(1), &pass::<AuditStep>());
    let mut unsigned_chain = AuditChain::new();
    let unsigned = unsigned_chain.seal(inputs(1), &pass::<AuditStep>());
    assert_eq!(unsigned.signature, None);
    assert_eq!(unsigned.key_id, None);

    let other = AuditSigningKey::from_seed(&[7u8; 32]);
    let other_published =
        AuditVerifyingKey::from_hex(&other.public_key_hex()).expect("a published key");
    assert_eq!(
        AuditChain::verify_signature(&signed, &other_published),
        Err(KeyError::BadSignature)
    );
    assert_eq!(
        AuditChain::verify_signature(&unsigned, &other_published),
        Err(KeyError::Unsigned)
    );
}

#[test]
fn turning_signing_on_does_not_move_the_sealed_digest() {
    let mut unsigned = AuditChain::new();
    let mut signed = AuditChain::new().signing_with(signer());
    let a = unsigned.seal(inputs(1), &pass::<AuditStep>());
    let b = signed.seal(inputs(1), &pass::<AuditStep>());
    assert_eq!(a.hash, b.hash, "the signature entered the digest");
    assert!(a.signature.is_none());
    assert!(b.signature.is_some());
}

#[test]
fn a_small_order_public_key_is_refused() {
    let identity = "0100000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(
        AuditVerifyingKey::from_hex(identity),
        Err(KeyError::WeakKey)
    );
    assert_eq!(
        AuditVerifyingKey::from_hex("00".repeat(32).as_str()),
        Err(KeyError::WeakKey)
    );
}

#[test]
fn debug_never_shows_the_secret() {
    let key = signer();
    let chain = AuditChain::new().signing_with(signer());
    let rendered = format!("{key:?} | {chain:?} | {:?}", (&key, &chain));

    assert!(
        !rendered.contains(TEST_SEED_HEX),
        "the seed's hex is in a Debug rendering: {rendered}"
    );

    let seed_bytes: Vec<u8> = (0..32)
        .map(|i| {
            u8::from_str_radix(&TEST_SEED_HEX[i * 2..i * 2 + 2], 16).expect("test seed is hex")
        })
        .collect();
    assert!(
        !rendered.contains(&format!("{seed_bytes:?}")),
        "the seed's bytes are in a Debug rendering: {rendered}"
    );

    assert!(!rendered.contains("secret"), "a Debug named a secret field");
    assert!(
        rendered.contains(key.key_id()),
        "a Debug that shows nothing is not the same as one that shows the identifier"
    );
    assert!(rendered.contains("ed25519"));
}

#[test]
fn a_rejected_key_is_never_quoted_back() {
    let nearly = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7fZZ";
    let short = "9d61b19deffd5a60ba844af492ec2cc4";
    for bad in [nearly, short] {
        let err = AuditSigningKey::from_hex_seed(bad).expect_err("that is not a seed");
        let said = format!("{err} | {err:?}");
        for window in 4..=8 {
            for start in 0..bad.len().saturating_sub(window) {
                let fragment = &bad[start..start + window];
                assert!(
                    !said.contains(fragment),
                    "the error quoted {fragment:?} out of the rejected key: {said}"
                );
            }
        }

        assert!(!said.contains("index"), "the error named an offset: {said}");
        assert!(
            !said.contains(&(bad.len() - 1).to_string()),
            "the error named a position: {said}"
        );
    }
}

#[test]
fn the_key_set_publishes_only_the_public_half() {
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a public key"));
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a public key"));
    assert_eq!(keys.len(), 1, "one key added twice is one key");

    let body = expose::keys_body(&keys);
    assert!(body.contains(&signer().public_key_hex()));
    assert!(body.contains(signer().key_id()));
    assert!(
        !body.contains(TEST_SEED_HEX),
        "the key set published the secret: {body}"
    );
    assert!(body.contains("\"algorithm\":\"ed25519\""));
}

#[test]
fn head_history_survives_a_restart_rebuilt_from_its_records() {
    let mut chain = AuditChain::new().signing_with(signer());
    let start = 1_700_000_000u64;
    let mut records = Vec::new();
    for step in 0..18u64 {
        let mut i = inputs(step + 1);
        i.wall = start + step * 1_200;
        records.push(chain.seal(i, &pass::<AuditStep>()));
    }
    let anchors_before = chain.heads().anchors();
    assert_eq!(
        anchors_before.len(),
        7,
        "six hourly samples plus the live tip"
    );

    let resumed = AuditChain::resume(&records).signing_with(signer());
    assert_eq!(resumed.head(), chain.head());
    assert_eq!(resumed.next_seq(), chain.next_seq());
    assert_eq!(
        resumed.heads().anchors(),
        anchors_before,
        "the restart lost or moved an anchor"
    );
    assert_eq!(
        expose::head_body(&resumed),
        expose::head_body(&chain),
        "the head read after a restart is not the head read before it"
    );
    assert!(
        !expose::head_body(&resumed).contains("\"head\":null"),
        "a resumed non-empty chain answered a null head"
    );
    let window_anchor = resumed
        .heads()
        .anchor_at(3)
        .expect("the anchor for an early window survives the restart");
    assert_eq!(Some(window_anchor.clone()), chain.heads().anchor_at(3));
    assert!(
        window_anchor.signature.is_some(),
        "an anchor that is not signed is not evidence"
    );
    assert_eq!(
        expose::range_body(&resumed, &records[..3], 1, 3),
        expose::range_body(&chain, &records[..3], 1, 3),
        "a window's published anchor moved across the restart"
    );

    let empty = AuditChain::resume(&[]);
    assert!(expose::head_body(&empty).contains("\"head\":null"));
    assert_eq!(empty.next_seq(), 1);
}

#[test]
fn the_genesis_head_is_always_an_anchor() {
    let mut history = HeadHistory::every(86_400);
    let mut chain = AuditChain::new();
    let first = chain.seal(inputs(1), &pass::<AuditStep>());
    let second = chain.seal(inputs(2), &pass::<AuditStep>());
    test_support::observe(&mut history, &first);
    test_support::observe(&mut history, &second);
    assert_eq!(history.series().len(), 1);
    assert_eq!(history.series()[0].seq, first.seq);
    assert_eq!(history.series()[0].hash, first.hash);
}

#[test]
fn a_chain_that_has_sealed_nothing_publishes_a_null_head() {
    let chain = AuditChain::new();
    assert!(chain.heads().is_empty());
    let body = expose::head_body(&chain);
    assert!(body.contains("\"head\":null"), "{body}");
    assert!(body.contains("\"next_seq\":1"));
}

#[test]
fn nothing_shrinks_the_head_history() {
    let mut history = HeadHistory::every(0);
    let mut chain = AuditChain::new();
    let mut last = 0;
    for i in 1..=50u64 {
        let record = chain.seal(inputs(i), &pass::<AuditStep>());
        test_support::observe(&mut history, &record);
        assert!(
            history.series().len() > last,
            "a head history shrank or stalled"
        );
        last = history.series().len();
    }
    assert_eq!(history.series().len(), 50);

    const TWO_YEARS_AND_AN_HOUR: u64 = 2 * 8_760 + 1;
    let mut hourly = HeadHistory::new();
    let mut record = AuditChain::new().seal(inputs(1), &pass::<AuditStep>());
    let genesis_wall = record.wall;
    for hour in 0..TWO_YEARS_AND_AN_HOUR {
        record.seq = hour + 1;
        record.wall = genesis_wall + hour * HEAD_SAMPLE_SECONDS;
        history_grows_by_one(&mut hourly, &record);
    }
    let series = hourly.series();
    assert_eq!(
        series.len() as u64,
        TWO_YEARS_AND_AN_HOUR,
        "a head history dropped anchors past its costed size"
    );
    assert_eq!(series[0].seq, 1, "the genesis anchor was dropped");
    assert_eq!(series[series.len() - 1].seq, TWO_YEARS_AND_AN_HOUR);
}

fn history_grows_by_one(history: &mut HeadHistory, record: &AuditRecord) {
    let before = history.series().len();
    test_support::observe(history, record);
    assert_eq!(
        history.series().len(),
        before + 1,
        "an hourly head did not join the series at position {}",
        record.seq
    );
}

#[test]
fn the_head_read_answers_with_the_tip_and_the_recipe_it_was_sealed_under() {
    let mut chain = AuditChain::new().signing_with(signer());
    let last = (1..=3)
        .map(|i| chain.seal(inputs(i), &pass::<AuditStep>()))
        .last();
    let last = last.expect("three records were sealed");
    let body = expose::head_body(&chain);
    assert!(
        body.contains("\"recipe\":\"busbar.audit.digest.v4\""),
        "{body}"
    );
    assert!(
        body.contains("\"signature_domain\":\"busbar.audit.record.v1\""),
        "{body}"
    );
    assert!(body.contains(&format!("\"seq\":{}", last.seq)), "{body}");
    assert!(body.contains(&last.hash), "{body}");
    assert!(
        body.contains(last.signature.as_deref().expect("a signed record")),
        "{body}"
    );
    assert!(body.contains("\"next_seq\":4"), "{body}");
}

#[test]
fn the_range_read_is_inclusive_and_clips_rather_than_refusing() {
    let mut chain = AuditChain::new().signing_with(signer());
    let records: Vec<_> = (1..=5)
        .map(|i| chain.seal(inputs(i), &pass::<AuditStep>()))
        .collect();

    let two_three = expose::range_body(&chain, &records, 2, 3);
    assert_eq!(two_three.matches("\"prev_hash\"").count(), 2);
    assert!(two_three.contains(&records[1].hash));
    assert!(two_three.contains(&records[2].hash));

    let past_the_end = expose::range_body(&chain, &records, 4, 400);
    assert_eq!(past_the_end.matches("\"prev_hash\"").count(), 2);

    let empty = expose::range_body(&chain, &records, 90, 99);
    assert!(empty.contains("\"records\":[]"), "{empty}");
}

#[test]
fn an_empty_group_publishes_an_empty_array() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(empty_group_inputs(), &pass::<AuditStep>());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);
    assert!(
        body.contains("\"lines_count\":\"0\",\"lines\":[]"),
        "{body}"
    );
    assert!(
        body.contains("\"hooks_count\":\"0\",\"hooks\":[]"),
        "{body}"
    );
    assert!(
        body.contains("\"children_count\":\"0\",\"children\":[]"),
        "{body}"
    );
}

#[test]
fn caller_named_text_survives_into_the_published_body() {
    let mut chain = AuditChain::new().signing_with(signer());
    let mut i = inputs(1);
    i.what.op_class = OpClassId::new("tool\"a\\b\nc\u{1}d|e");
    let record = chain.seal(i, &pass::<AuditStep>());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);

    let expected = format!("tool{}\"a{}{}b{}nc{}u0001d|e", "\\", "\\", "\\", "\\", "\\");
    assert!(body.contains(&expected), "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("the body is valid JSON");
    assert_eq!(
        parsed["records"][0]["op_class"].as_str(),
        Some("tool\"a\\b\nc\u{1}d|e")
    );
}

#[test]
fn the_published_bodies_parse_and_the_wide_numbers_are_text() {
    let mut chain = AuditChain::new().signing_with(signer());
    let records: Vec<_> = (1..=2)
        .map(|i| chain.seal(inputs(i), &pass::<AuditStep>()))
        .collect();
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a public key"));

    for body in [
        expose::head_body(&chain),
        expose::range_body(&chain, &records, 1, 2),
        expose::keys_body(&keys),
    ] {
        serde_json::from_str::<serde_json::Value>(&body).expect("every published body is JSON");
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&expose::range_body(&chain, &records, 1, 2)).expect("JSON");
    assert_eq!(parsed["records"][0]["emission_delta"].as_str(), Some("-7"));

    let record = parsed["records"][0]
        .as_object()
        .expect("a published record is an object");
    for stored_price in ["pre_tier", "priced", "amount"] {
        assert!(
            !record.contains_key(stored_price),
            "the published record carries a stored price `{stored_price}`: {record:?}"
        );
    }

    let hooks = parsed["records"][0]["hooks"]
        .as_array()
        .expect("the hooks are an array");
    assert!(!hooks.is_empty(), "the record names the hook that ran");
    for hook in hooks {
        let hook = hook.as_object().expect("a hook is an object");
        let mut keys: Vec<&str> = hook.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["failed", "head", "hook"],
            "a hook that ran is named with its head and failure, never priced"
        );
        for priced in ["price", "priced", "priced_delta", "cost", "amount"] {
            assert!(
                !hook.keys().any(|k| k.contains(priced)),
                "a hook entry carries a price field `{priced}`: {hook:?}"
            );
        }
    }
    assert_eq!(parsed["recipe"].as_str(), Some("busbar.audit.digest.v4"));

    assert_eq!(parsed["records"][0]["tier_bp"].as_str(), Some("9000"));
    assert_eq!(parsed["records"][0]["fee_count"].as_str(), Some("1"));
    assert_eq!(
        parsed["records"][0]["rate_card_version"].as_str(),
        Some("3")
    );

    assert_eq!(parsed["records"][0]["seq"].as_str(), Some("1"));
    assert!(parsed["records"][0]["lines"][0]["quantity"].is_string());

    assert_eq!(parsed["from"].as_u64(), Some(1));
    assert_eq!(parsed["to"].as_u64(), Some(2));
}

#[test]
fn the_body_keeps_the_texts_texts_and_the_numbers_decimal_text() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(inputs(1), &pass::<AuditStep>());
    let parsed: serde_json::Value = serde_json::from_str(&expose::range_body(
        &chain,
        std::slice::from_ref(&record),
        1,
        1,
    ))
    .expect("JSON");
    let published = &parsed["records"][0];
    for field in digest_fields(&record) {
        let Some(name) = field.name.strip_suffix("").filter(|n| !n.contains("[]")) else {
            continue;
        };
        match field.value {
            DigestValue::Text(_) => assert!(
                published[name].is_string(),
                "{name} is a recipe text but is not published as a string"
            ),
            DigestValue::Num(n) => assert_eq!(
                published[name].as_str(),
                Some(n.to_string().as_str()),
                "{name} is a recipe number but is not published as its decimal text"
            ),
        }
    }
}

#[test]
fn a_node_above_two_to_the_fifty_three_is_published_exactly() {
    let node: u64 = 16_045_690_984_833_335_023;
    let mut chain = AuditChain::new().signing_with(signer()).sealing_as(node);
    let record = chain.seal(inputs(1), &pass::<AuditStep>());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);
    assert!(
        body.contains("\"node\":\"16045690984833335023\","),
        "{body}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(
        parsed["records"][0]["node"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok()),
        Some(node)
    );
}

fn worked_example_inputs() -> AuditInputs {
    let mut i = empty_group_inputs();
    i.subject = Subject::Node(7);
    i.what.op_class = OpClassId::new("chat.completion");
    i.wall = 1_700_000_000;
    i.mono = 42;
    i.usage.bucket_chain_ref = "chain:free>paid".into();
    i.usage.tier_bp = 9_000;
    i.usage.fee_count = 1;
    i.usage.rate_card_version = 3;
    i.what.incarnation = 2;
    i
}

const WORKED_EXAMPLE_NODE: u64 = 5;

fn spec_json_block(doc: &str, nth: usize) -> serde_json::Value {
    let block = doc
        .split("```json")
        .nth(nth + 1)
        .unwrap_or_else(|| panic!("the spec has no json block {nth}"))
        .split("```")
        .next()
        .expect("a fenced block closes");
    serde_json::from_str(block).expect("the spec's worked example is valid JSON")
}

#[test]
fn the_worked_example_in_the_published_spec_is_what_this_build_answers_with() {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/audit-chain-digest-v4.md"),
    )
    .expect("the published spec is in the tree");

    let mut chain = AuditChain::new()
        .signing_with(signer())
        .sealing_as(WORKED_EXAMPLE_NODE);
    let record = chain.seal(worked_example_inputs(), &pass::<AuditStep>());
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a public key"));

    let parse = |body: String| -> serde_json::Value {
        serde_json::from_str(&body).expect("a published body is JSON")
    };
    assert_eq!(
        spec_json_block(&doc, 0),
        parse(expose::range_body(
            &chain,
            std::slice::from_ref(&record),
            1,
            1
        )),
        "the spec's range example is not what this build answers with"
    );
    assert_eq!(
        spec_json_block(&doc, 1),
        parse(expose::head_body(&chain)),
        "the spec's head example is not what this build answers with"
    );
    assert_eq!(
        spec_json_block(&doc, 2),
        parse(expose::keys_body(&keys)),
        "the spec's key-set example is not what this build answers with"
    );

    assert!(
        doc.contains(&record.hash),
        "the spec quotes a digest this build does not produce"
    );
    assert!(doc.contains(&signer().public_key_hex()));
    assert!(doc.contains(signer().key_id()));
    assert!(
        doc.contains(&format!("preimage is {} bytes", 489)),
        "the spec quotes a preimage length this build does not produce"
    );
    assert_eq!(
        digest_over(&digest_fields(&record)).len(),
        64,
        "a digest is 64 lowercase hex characters"
    );
}

#[test]
fn the_worked_examples_preimage_is_the_length_the_spec_quotes() {
    let mut chain = AuditChain::new()
        .signing_with(signer())
        .sealing_as(WORKED_EXAMPLE_NODE);
    let record = chain.seal(worked_example_inputs(), &pass::<AuditStep>());
    let framed: usize = digest_fields(&record)
        .iter()
        .map(|f| {
            8 + match &f.value {
                DigestValue::Text(s) => s.len(),
                DigestValue::Num(_) => 8,
            }
        })
        .sum();
    assert_eq!(framed, 489);
}

const CHECKPOINT_BODY: &[u8] = b"checkpoint 1: bucket b, window 1, settled 450";

#[test]
fn a_checkpoint_signed_by_the_audit_chain_verifies_with_the_audit_keyset() {
    let chain = AuditChain::new().signing_with(signer());
    let signature = chain
        .sign_checkpoint_body(CHECKPOINT_BODY)
        .expect("a chain given a key signs checkpoints with it");

    let mut keys = AuditKeySet::new();
    keys.insert(
        AuditVerifyingKey::from_hex(&chain.public_key_hex().unwrap()).expect("a real public key"),
    );
    assert_eq!(
        keys.verify_checkpoint_body(CHECKPOINT_BODY, &signature),
        Ok(())
    );
}

#[test]
fn a_tampered_checkpoint_body_refuses_with_the_bad_signature_text() {
    let chain = AuditChain::new().signing_with(signer());
    let signature = chain.sign_checkpoint_body(CHECKPOINT_BODY).unwrap();
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a public key"));
    let tampered = b"checkpoint 1: bucket b, window 1, settled 451";
    let refused = keys
        .verify_checkpoint_body(tampered, &signature)
        .expect_err("an edited body must not verify");
    assert_eq!(refused, KeyError::BadSignature);
    assert_eq!(
        refused.to_string(),
        "the signature does not verify against this key"
    );
}

#[test]
fn a_checkpoint_signature_and_a_record_signature_cannot_stand_in_for_each_other() {
    let key = signer();
    let digest_hex = busbar_kernel_audit::digest::sha256_hex(CHECKPOINT_BODY);
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&key.public_key_hex()).expect("a public key"));

    let record_sig = key.sign_digest(&digest_hex);
    let raw: Vec<u8> = (0..record_sig.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&record_sig[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(
        keys.verify_checkpoint_body(CHECKPOINT_BODY, &raw),
        Err(KeyError::BadSignature)
    );

    let checkpoint_sig: String = key
        .sign_checkpoint_body(CHECKPOINT_BODY)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex()).unwrap();
    assert_eq!(
        public.verify_digest(&digest_hex, &checkpoint_sig),
        Err(KeyError::BadSignature)
    );
}

#[test]
fn a_chain_with_no_key_seals_checkpoints_unsigned_and_a_short_signature_is_malformed() {
    assert_eq!(
        AuditChain::new().sign_checkpoint_body(CHECKPOINT_BODY),
        None
    );
    let mut keys = AuditKeySet::new();
    keys.insert(AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a public key"));
    let refused = keys
        .verify_checkpoint_body(CHECKPOINT_BODY, &[0u8; 10])
        .unwrap_err();
    assert_eq!(
        refused.to_string(),
        "the signature is not 128 lowercase hexadecimal characters"
    );
}
