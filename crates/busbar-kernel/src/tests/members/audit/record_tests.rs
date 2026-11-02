// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::Pass;
use busbar_contract::caps::{
    Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome, ReasonCode, StepName, UnitKey,
};

use busbar_kernel_audit::record::{
    Audit, AuditBreakKind, AuditChain, AuditInputs, Controls, FinishClass, HookApplied, HookHead,
    OpClassId, OutcomeFacts, QuantitySource, Subject, Usage, UsageLine, What,
};

fn origin() -> Origin {
    Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client)
}

fn inputs(unit: u64) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: None,
            pre_hook_head: Some("hook-head-before".into()),
            post_hook_head: Some("hook-head-after".into()),
        },
        wall: 1_700_000_000 + unit,
        mono: unit * 1_000,
        origin: origin(),
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
                class: busbar_contract::caps::MeterClassId::new("tokens_out"),
                quantity: 120,
                source: QuantitySource::Locator {
                    direction: busbar_contract::ClassDirection::Response,
                    ptr: busbar_contract::caps::LocatorPtr::new("/usage/output_tokens"),
                },
                estimated: false,
            }],
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
            replayed: false,
            children: vec![UnitKey::new(unit + 1000)],
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

fn frozen_record() -> busbar_kernel_audit::record::AuditRecord {
    let mut chain = AuditChain::new().sealing_as(FROZEN_NODE);
    let mut with_payloads = inputs(1);
    with_payloads.outcome.unit_end = Outcome::Refused(StepName::Admit, ReasonCode::OverBudget);
    with_payloads.outcome.step = Some(StepName::Admit);
    with_payloads.outcome.finish = FinishClass::Error;
    with_payloads.what.incarnation = 3;
    chain.seal(
        with_payloads,
        &Pass::<AuditStep>::mint(&crate::seal::acquire()),
    )
}

const FROZEN_NODE: u64 = 9;

const FROZEN_V2: &str = "ea279d25a42d6345875b06b44fa7bb558f0d05655f985d376cd37fe2e0422293";

fn frozen_v2_record() -> busbar_kernel_audit::record::AuditRecord {
    let mut record = frozen_record();
    record.recipe = busbar_kernel_audit::recipe::Recipe::V2 {
        currency: "USD".into(),
    };
    record.hash = FROZEN_V2.to_string();
    record
}

#[test]
fn the_sealed_digest_of_a_fully_populated_record_is_the_frozen_hex() {
    let record = frozen_record();
    assert_eq!(record.recipe, busbar_kernel_audit::recipe::Recipe::V4);
    assert_eq!(record.node, FROZEN_NODE);
    assert_eq!(
        record.hash, "c52e40669e4afb81c8a244a7dfbd9142281e3b74179d51426075ad2564b2668b",
        "the sealed digest moved: every persisted chain would now report itself tampered"
    );
}

#[test]
fn a_new_record_is_sealed_under_v4_and_its_preimage_is_v2_less_currency_plus_incarnation_and_node()
{
    use busbar_kernel_audit::recipe::{digest_fields, DigestValue};
    let v4 = digest_fields(&frozen_record());
    let v4_names: Vec<_> = v4.iter().map(|f| f.name).collect();
    let v2: Vec<_> = digest_fields(&frozen_v2_record())
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert!(
        !v4_names.contains(&"currency"),
        "a v4 preimage still frames a currency: {v4_names:?}"
    );
    let mut expected: Vec<_> = v2.iter().copied().filter(|n| *n != "currency").collect();
    let after = |names: &[&str], name: &str| {
        names
            .iter()
            .position(|n| *n == name)
            .unwrap_or_else(|| panic!("v2 frames {name}"))
            + 1
    };
    let at = after(&expected, "mono");
    expected.insert(at, "node");
    let at = after(&expected, "unit_key");
    expected.insert(at, "incarnation");
    let at = after(&expected, "hooks[].hook");
    expected.insert(at, "hooks[].failed");
    expected.insert(at, "hooks[].head");
    assert_eq!(
        v4_names, expected,
        "v4 is not v2 less `currency` plus `incarnation`, `node` and each hook's head and failure"
    );
    let node = v4
        .iter()
        .find(|f| f.name == "node")
        .expect("v4 frames the node");
    assert_eq!(
        node.value,
        DigestValue::Num(FROZEN_NODE),
        "the node is framed as a number"
    );
    assert_eq!(
        frozen_record().recipe,
        busbar_kernel_audit::recipe::Recipe::V4
    );
    assert!(AuditChain::verify_chain(std::slice::from_ref(&frozen_record())).is_ok());
}

#[test]
fn a_record_names_the_node_that_sealed_it_in_its_digest_and_its_range_read() {
    let seal = |node: u64| {
        let mut chain = AuditChain::new().sealing_as(node);
        let record = chain.seal(inputs(1), &Pass::<AuditStep>::mint(&crate::seal::acquire()));
        (chain, record)
    };
    let ((chain_a, a), (_, b)) = (seal(11), seal(12));
    assert_eq!((a.node, b.node), (11, 12));
    assert_eq!(chain_a.node(), 11);
    assert_eq!(a.mono, b.mono);
    assert_ne!(a.hash, b.hash, "the sealing node is not in the digest");
    assert!(AuditChain::verify_chain(std::slice::from_ref(&a)).is_ok());

    let mut relabelled = a.clone();
    relabelled.node = 12;
    assert_eq!(
        AuditChain::verify_chain(std::slice::from_ref(&relabelled)).map_err(|b| b.kind),
        Err(AuditBreakKind::DigestMismatch),
        "a record relabelled to another node still verifies"
    );

    let raw = busbar_kernel_audit::expose::range_body(&chain_a, std::slice::from_ref(&a), 1, 1);
    assert!(
        raw.contains("\"mono\":\"1000\",\"node\":\"11\","),
        "the range read does not publish the node, as its decimal text, straight after mono: {raw}"
    );
    let body: serde_json::Value = serde_json::from_str(&raw).expect("a published body is JSON");
    assert_eq!(body["records"][0]["node"], serde_json::json!("11"));
}

#[test]
fn two_boots_minting_the_same_unit_key_seal_distinct_verified_records() {
    let seal = |incarnation: u64| {
        let mut chain = AuditChain::new();
        let mut i = inputs(1);
        i.what.incarnation = incarnation;
        chain.seal(i, &Pass::<AuditStep>::mint(&crate::seal::acquire()))
    };
    let (first, second) = (seal(1), seal(2));
    assert_eq!(first.what.unit_key, second.what.unit_key);
    assert_ne!(first.hash, second.hash, "the boot is not in the digest");
    assert!(AuditChain::verify_chain(std::slice::from_ref(&first)).is_ok());
    assert!(AuditChain::verify_chain(std::slice::from_ref(&second)).is_ok());
    let mut swapped = first.clone();
    swapped.what.incarnation = 2;
    assert_eq!(
        AuditChain::verify_chain(std::slice::from_ref(&swapped)).map_err(|b| b.kind),
        Err(AuditBreakKind::DigestMismatch),
        "a record relabelled to another boot still verifies"
    );
}

#[test]
fn a_record_sealed_under_v2_still_verifies_by_the_v2_rules() {
    let record = frozen_v2_record();
    assert_eq!(AuditChain::digest_of(&record), FROZEN_V2);
    assert!(AuditChain::verify_chain(std::slice::from_ref(&record)).is_ok());
}

#[test]
fn tampering_fails_under_either_recipe_and_so_does_relabelling_one() {
    use busbar_kernel_audit::recipe::Recipe;
    type Edit = fn(&mut busbar_kernel_audit::record::AuditRecord);
    let arms: Vec<(&str, busbar_kernel_audit::record::AuditRecord, Edit)> = vec![
        ("a v2 record's currency text", frozen_v2_record(), |r| {
            r.recipe = Recipe::V2 {
                currency: "EUR".into(),
            }
        }),
        ("a v2 record relabelled v4", frozen_v2_record(), |r| {
            r.recipe = Recipe::V4
        }),
        ("a v4 record relabelled v2", frozen_record(), |r| {
            r.recipe = Recipe::V2 {
                currency: "USD".into(),
            }
        }),
        ("a v4 record's incarnation", frozen_record(), |r| {
            r.what.incarnation += 1
        }),
        ("a v4 record's node", frozen_record(), |r| r.node += 1),
        ("a v2 record's count", frozen_v2_record(), |r| {
            r.usage.lines[0].quantity += 1
        }),
        ("a v4 record's count", frozen_record(), |r| {
            r.usage.lines[0].quantity += 1
        }),
    ];
    for (what, mut record, edit) in arms {
        assert!(AuditChain::verify_chain(std::slice::from_ref(&record)).is_ok());
        edit(&mut record);
        assert_eq!(
            AuditChain::verify_chain(std::slice::from_ref(&record)).map_err(|b| b.kind),
            Err(AuditBreakKind::DigestMismatch),
            "{what}: the edited record still verifies"
        );
    }
}

#[test]
fn the_v1_frozen_digest_is_reproduced_by_v1_rules_from_a_v2_record() {
    use busbar_kernel_audit::recipe::{digest_fields, digest_over, DigestField, DigestValue};
    let text = |name: &'static str, v: &str| DigestField {
        name,
        value: DigestValue::Text(v.to_string()),
    };
    let record = frozen_v2_record();
    let mut v1 = Vec::new();
    for field in digest_fields(&record) {
        match field.name {
            "tier_bp" => {
                v1.push(text("pre_tier", "600"));
                v1.push(text("priced", "540"));
                v1.push(field);
            }
            "hooks[].hook" => {
                v1.push(field);
                v1.push(text("hooks[].priced_delta", "-10"));
            }
            _ => v1.push(field),
        }
    }
    assert_eq!(
        digest_over(&v1),
        "0161f86736b3ed067dcdbaa80259c52ceb25946076879a8968e3f84570626358",
        "the v1 digest is no longer reproducible: a v1 record would stop verifying"
    );
    assert_ne!(digest_over(&v1), record.hash, "v2 is its own recipe");
}

#[test]
fn a_record_links_to_the_one_before_it_and_the_run_verifies() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4)
        .map(|i| chain.seal(inputs(i), &Pass::<AuditStep>::mint(&crate::seal::acquire())))
        .collect();
    assert_eq!(records[0].prev_hash, "");
    for pair in records.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }
    assert!(AuditChain::verify_chain(&records).is_ok());
    assert_eq!(chain.head(), records[3].hash);
    assert_eq!(chain.sealed(), 4);
}

#[test]
fn the_correlation_label_is_hashed_and_the_label_itself_is_gone() {
    let mut chain = AuditChain::new();
    let record = chain.seal(inputs(1), &Pass::<AuditStep>::mint(&crate::seal::acquire()));
    let hash = record.correlation_hash.clone().unwrap();
    assert_eq!(
        hash,
        busbar_kernel_audit::digest::sha256_hex(b"customer-order-99"),
        "the record carries the digest of the label"
    );

    let rendered = format!("{record:?}");
    assert!(
        !rendered.contains("customer-order-99"),
        "the correlation label reached the record: {rendered}"
    );
}

#[test]
fn a_record_with_no_correlation_label_carries_no_hash() {
    let mut chain = AuditChain::new();
    let mut without = inputs(1);
    without.correlation_label = None;
    let record = chain.seal(without, &Pass::<AuditStep>::mint(&crate::seal::acquire()));
    assert!(record.correlation_hash.is_none());
}

#[test]
fn editing_any_recorded_fact_is_caught() {
    let mut chain = AuditChain::new();
    let mut records: Vec<_> = (1..=3)
        .map(|i| chain.seal(inputs(i), &Pass::<AuditStep>::mint(&crate::seal::acquire())))
        .collect();

    let edits: Vec<(&str, Edit)> = vec![
        ("the tier", |r| r.usage.tier_bp += 1),
        ("the fee count", |r| r.usage.fee_count += 1),
        ("a quantity", |r| r.usage.lines[0].quantity += 1),
        ("a quantity's source", |r| {
            r.usage.lines[0].source = QuantitySource::KernelBytes { divisor: 4 }
        }),
        ("the estimated mark", |r| r.usage.lines[0].estimated = true),
        ("the card version", |r| r.usage.rate_card_version += 1),
        ("the bucket chain", |r| {
            r.usage.bucket_chain_ref = "chain:other".into()
        }),
        ("the subject", |r| {
            r.subject = Subject::PrincipalId("somebody-else".into())
        }),
        ("the destination", |r| {
            r.what.destination = Some("upstream-b".into())
        }),
        ("the operation class", |r| {
            r.what.op_class = OpClassId::new("something.else")
        }),
        ("the finish class", |r| {
            r.outcome.finish = FinishClass::Error
        }),
        ("the outcome", |r| {
            r.outcome.unit_end = Outcome::Failed(StepName::Route, ReasonCode::OverBudget)
        }),
        ("the hook-failed mark", |r| r.outcome.hook_failed = true),
        ("the emission delta", |r| r.outcome.emission_delta -= 5),
        ("the stale-policy mark", |r| r.outcome.stale_policy = true),
        ("the hold reference", |r| {
            r.controls.hold_ref = Some("hold-2".into())
        }),
        ("the lease epoch", |r| r.controls.lease_epoch += 1),
        ("the policy epoch", |r| r.controls.policy_epoch += 1),
        ("a hook's name", |r| {
            r.controls.hooks_applied[0].hook = "decompress".into()
        }),
        ("a hook's head", |r| {
            r.controls.hooks_applied[0].head = HookHead::Veto
        }),
        ("whether a hook failed", |r| {
            r.controls.hooks_applied[0].failed = true
        }),
        ("the replay mark", |r| r.controls.replayed = true),
        ("the wall clock", |r| r.wall += 1),
        ("the correlation hash", |r| {
            r.correlation_hash = Some("something".into())
        }),
    ];

    for (what, edit) in edits {
        let mut edited = records.clone();
        edit(&mut edited[1]);
        let brk = AuditChain::verify_chain(&edited)
            .err()
            .unwrap_or_else(|| panic!("editing {what} went undetected"));
        assert_eq!(brk.kind, AuditBreakKind::DigestMismatch, "editing {what}");
        assert_eq!(brk.at_index, 2);
    }

    records.remove(1);
    let brk = AuditChain::verify_chain(&records).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

#[test]
fn two_nodes_do_not_digest_the_same() {
    let mut chain = AuditChain::new();
    let mut a = inputs(1);
    a.subject = Subject::Node(1);
    let first = chain.seal(a, &Pass::<AuditStep>::mint(&crate::seal::acquire()));
    let mut chain = AuditChain::new();
    let mut b = inputs(1);
    b.subject = Subject::Node(2);
    let second = chain.seal(b, &Pass::<AuditStep>::mint(&crate::seal::acquire()));
    assert_ne!(first.hash, second.hash);
}

#[test]
fn a_plane_contributes_exactly_two_identifiers() {
    let mut chain = AuditChain::new();
    let mut other_plane = inputs(1);
    other_plane.what.op_class = OpClassId::new("tool.call");
    other_plane.outcome.finish = FinishClass::TurnComplete;
    let record = chain.seal(
        other_plane,
        &Pass::<AuditStep>::mint(&crate::seal::acquire()),
    );

    assert_eq!(record.what.op_class.as_str(), "tool.call");
    assert_eq!(record.outcome.finish, FinishClass::TurnComplete);
    assert_eq!(record.recipe, busbar_kernel_audit::recipe::Recipe::V4);
    assert!(record.controls.hold_ref.is_some());
}

#[test]
fn a_chain_resumed_from_a_persisted_tail_continues_it() {
    let mut chain = AuditChain::new();
    let first: Vec<_> = (1..=2)
        .map(|i| chain.seal(inputs(i), &Pass::<AuditStep>::mint(&crate::seal::acquire())))
        .collect();

    let mut resumed = AuditChain::resume(&first);
    let third = resumed.seal(inputs(3), &Pass::<AuditStep>::mint(&crate::seal::acquire()));
    assert_eq!(third.prev_hash, first[1].hash);

    let mut all = first;
    all.push(third);
    assert!(AuditChain::verify_chain(&all).is_ok());
}

#[test]
fn a_record_carries_its_position_and_the_position_is_digested() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=3)
        .map(|i| chain.seal(inputs(i), &Pass::<AuditStep>::mint(&crate::seal::acquire())))
        .collect();
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );

    let mut renumbered = records.clone();
    renumbered[1].seq = 7;
    assert_eq!(
        AuditChain::verify_chain(&renumbered).unwrap_err().kind,
        AuditBreakKind::SequenceMismatch {
            expected: 2,
            found: 7
        }
    );
    assert_ne!(
        AuditChain::digest_of(&renumbered[1]),
        renumbered[1].hash,
        "the position is inside the digest"
    );
}

#[test]
fn a_run_missing_its_oldest_records_does_not_verify_against_the_genesis() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4)
        .map(|i| chain.seal(inputs(i), &Pass::<AuditStep>::mint(&crate::seal::acquire())))
        .collect();

    let brk = AuditChain::verify_chain(&records[1..]).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(
        brk.at_index, 1,
        "the break is at the record that should be the genesis"
    );

    assert!(AuditChain::verify_window(&records[1..]).is_ok());
}

#[test]
fn a_window_verifies_a_contiguous_middle_run_and_not_a_gapped_one() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=6)
        .map(|i| chain.seal(inputs(i), &Pass::<AuditStep>::mint(&crate::seal::acquire())))
        .collect();

    assert!(AuditChain::verify_window(&records[2..5]).is_ok());

    let mut gapped = records[2..5].to_vec();
    gapped.remove(1);
    let brk = AuditChain::verify_window(&gapped).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

#[test]
fn an_empty_run_verifies_and_the_limit_is_deliberate() {
    assert!(AuditChain::verify_chain(&[]).is_ok());
}

type Edit = fn(&mut busbar_kernel_audit::record::AuditRecord);

#[path = "break_reporting_tests.rs"]
mod break_reporting_tests;
