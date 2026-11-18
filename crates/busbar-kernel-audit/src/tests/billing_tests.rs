// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::{record::billing::*, *};
use busbar_contract::{
    caps::{Outcome, UnitKey},
    Count,
};
use std::collections::BTreeMap;

fn facts(attempts: u32) -> BillingFacts {
    let quantity = SelectedQuantity {
        count: 12u64.into(),
        source: UsageSource::Reported,
    };
    BillingFacts {
        revision: 9,
        request_pool: "p\u{1f}original".into(),
        routing_generation: 3,
        era: BillingEra {
            effective_from: 17,
            entry_id: Some([1; 12]),
        },
        session_origin: SessionOrigin {
            instance: "p".into(),
            lane: "p\u{1f}".into(),
            provider: None,
        },
        logical_request: LogicalRequest::DeliveredPreparation(attempts),
        fee: LogicalFee {
            state: FeeState::Charged,
            lane: Some("p\u{1f}".into()),
            era: BillingEra {
                effective_from: 19,
                entry_id: Some([2; 12]),
            },
        },
        disposition: BillingDisposition::End,
        far_end_answered: true,
        caller_bytes_committed: true,
        final_target: Some(attempts),
        partitions: (1..=attempts)
            .map(|preparation| BillingPartition {
                scope: PartitionScope::Attempt {
                    preparation,
                    dispatch: Some(preparation),
                },
                kind: TargetKind::Model,
                instance: "p".into(),
                lane: "p\u{1f}model".into(),
                provider: Some("configured".into()),
                selected_pool: Some("p\u{1f}selected".into()),
                resource: None,
                transport: Some(Transport::Committed),
                finality: Finality::Complete,
                classes: BTreeMap::from([(
                    "tokens".into(),
                    BillingClass {
                        reported: Some(quantity.count),
                        floor: Some(3u64.into()),
                        estimated: Some(50u64.into()),
                        selected: Some(quantity),
                        billed: Some(quantity),
                        rate_high_water: quantity.count,
                    },
                )]),
            })
            .collect(),
    }
}
fn record(billing: PartitionedBillingV1) -> AuditRecord {
    AuditRecord {
        subject: Subject::principal("principal"),
        what: What {
            unit_key: UnitKey::new(7),
            incarnation: 8,
            op_class: OpClassId::new("test"),
            destination: Some("p\u{1f}model".into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 20,
        mono: 21,
        node: 22,
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
            lines: Vec::new(),
            tier_bp: 10000,
            fee_count: 1,
            rate_card_version: Some([3; 20]),
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_hash: None,
        unit: UnitFacts {
            billing: Some(billing),
            ..UnitFacts::at(20000)
        },
        linked_ms: 21000,
        seq: 1,
        prev_hash: String::new(),
        recipe: Recipe::V9,
        hash: String::new(),
        signature: None,
        key_id: None,
    }
}
#[test]
fn full_attempt_history_and_records_tail_roundtrip_without_a_class_registry() {
    for user in [None, Some("user".into())] {
        for labels in [vec![], vec![("label".into(), "value".into())]] {
            let mut line = record(PartitionedBillingV1::new(facts(6)).unwrap());
            line.unit.records = RecordFacts {
                user: user.clone(),
                labels,
            };
            line.hash = digest_record(&line);
            let bytes = journal_body(&line).unwrap();
            assert_eq!(
                from_journal_body(&bytes, &|_| None).unwrap(),
                Some(line.clone())
            );
            assert_eq!(
                line.unit.billing.as_ref().unwrap().facts().partitions.len(),
                6
            );
            assert_eq!(line.recipe.name(), "busbar.audit.link.v2");
            let json = expose::range_body(&[line], 1, 1);
            assert!(json.contains("\"billing_partitions_count\":\"6\""));
            assert!(json.contains("\"labels_count\""));
        }
    }
}
#[test]
fn known_zero_and_unknown_are_distinct_and_sources_change_the_fingerprint() {
    let original = facts(1);
    let mut zero = original.clone();
    let class = zero.partitions[0].classes.get_mut("tokens").unwrap();
    class.reported = Some(Count::ZERO);
    class.selected = Some(SelectedQuantity {
        count: Count::ZERO,
        source: UsageSource::Reported,
    });
    class.billed = class.selected;
    let known = record(PartitionedBillingV1::new(zero.clone()).unwrap());
    let class = zero.partitions[0].classes.get_mut("tokens").unwrap();
    class.reported = None;
    class.floor = None;
    class.estimated = None;
    class.selected = None;
    class.billed = None;
    zero.partitions[0].finality = Finality::Unknown;
    let unknown = record(PartitionedBillingV1::new(zero).unwrap());
    assert_ne!(digest_record(&known), digest_record(&unknown));
    assert_ne!(
        digest_record(&known),
        digest_record(&record(PartitionedBillingV1::new(original).unwrap()))
    );
}
#[test]
fn malformed_partition_identities_and_estimated_bills_are_refused() {
    let mut invalid = facts(2);
    invalid.partitions[1].scope = invalid.partitions[0].scope;
    assert!(PartitionedBillingV1::new(invalid).is_err());
    let mut invalid = facts(1);
    invalid.partitions[0]
        .classes
        .get_mut("tokens")
        .unwrap()
        .billed
        .as_mut()
        .unwrap()
        .source = UsageSource::Estimated;
    assert!(PartitionedBillingV1::new(invalid).is_err());
    let mut invalid = facts(1);
    invalid.final_target = Some(99);
    assert!(PartitionedBillingV1::new(invalid).is_err());
    assert!(PartitionedBillingV1::new(facts(257)).is_err());
}
#[test]
fn legacy_recipe_cannot_carry_unsigned_billing_and_trailing_bytes_refuse() {
    let mut line = record(PartitionedBillingV1::new(facts(1)).unwrap());
    line.recipe = Recipe::V8;
    assert!(journal_body(&line).is_err());
    assert!(AuditChain::verify_window(&[line.clone()]).is_err());
    line.recipe = Recipe::V9;
    line.hash = digest_record(&line);
    let mut bytes = journal_body(&line).unwrap();
    bytes.push(0);
    assert!(from_journal_body(&bytes, &|_| None).is_err());
}

#[test]
fn undeployed_preparation_and_recovered_terminal_unknown_fee_survive() {
    let mut value = facts(2);
    value.final_target = Some(1);
    value.logical_request = LogicalRequest::DeliveredPreparation(1);
    value.fee.state = FeeState::Unknown;
    value.disposition = BillingDisposition::Cancel("client_gone".into());
    let second = &mut value.partitions[1];
    second.scope = PartitionScope::Attempt {
        preparation: 2,
        dispatch: None,
    };
    second.transport = Some(Transport::NoSend);
    second.finality = Finality::Unknown;
    second
        .classes
        .values_mut()
        .for_each(|class| class.billed = None);
    let mut line = record(PartitionedBillingV1::new(value).unwrap());
    line.usage.fee_count = 0;
    line.hash = digest_record(&line);
    let decoded = from_journal_body(&journal_body(&line).unwrap(), &|_| None)
        .unwrap()
        .unwrap();
    assert_eq!(decoded, line);
    let facts = decoded.unit.billing.unwrap();
    assert_eq!(facts.facts().fee.state, FeeState::Unknown);
    assert!(matches!(
        facts.facts().disposition,
        BillingDisposition::Cancel(_)
    ));
    assert_eq!(facts.facts().partitions.len(), 2);
}

#[test]
fn declared_class_grammar_and_bounds_refuse_whole_records() {
    for class in ["Upper", "with-dash", "", "wrong space"] {
        let mut value = facts(1);
        let quantity = value.partitions[0].classes.remove("tokens").unwrap();
        value.partitions[0].classes.insert(class.into(), quantity);
        assert!(PartitionedBillingV1::new(value).is_err());
    }
    let mut value = facts(1);
    let quantity = value.partitions[0].classes.remove("tokens").unwrap();
    value.partitions[0]
        .classes
        .insert("vendor:tokens".into(), quantity);
    let mut line = record(PartitionedBillingV1::new(value).unwrap());
    line.controls.hold_ref = Some("x".repeat(BILLING_RECORD_BYTES));
    line.hash = digest_record(&line);
    assert!(journal_body(&line).is_err());
    line.controls.hold_ref = None;
    line.unit.records.user = Some("x".repeat(4097));
    assert!(journal_body(&line).is_err());
}

/// `n` V9 (link.v2) lines with billing evidence, linked from the genesis as a chain seals them.
fn v9_chain(n: u64) -> Vec<AuditRecord> {
    let mut previous = String::new();
    (1..=n)
        .map(|k| {
            let mut line = record(PartitionedBillingV1::new(facts(2)).unwrap());
            line.what.unit_key = UnitKey::new(k);
            line.seq = k;
            line.linked_ms = 21_000 + k;
            line.prev_hash = std::mem::take(&mut previous);
            line.hash = digest_record(&line);
            previous.clone_from(&line.hash);
            line
        })
        .collect()
}

/// PM ruling D-AUDIT (2026-11-17): every tampering case is detected on a V9 chain. An edited line or
/// an edited count is a digest mismatch; an edited, dropped or reordered link breaks the walk; a
/// truncated tail walks (a prefix is a chain) but no longer ends at the head the chain published.
#[test]
fn every_tampering_of_a_v9_chain_is_detected() {
    use crate::record::{AuditBreakKind, AuditChain};
    let lines = v9_chain(4);
    assert!(lines.iter().all(|l| l.recipe == Recipe::V9));
    assert_eq!(AuditChain::verify_chain(&lines), Ok(()));
    let head = lines.last().unwrap().hash.clone();
    let kind = |chain: &[AuditRecord]| AuditChain::verify_chain(chain).map_err(|b| b.kind);

    let mut edited = lines.clone();
    edited[1].wall += 1;
    assert_eq!(
        kind(&edited),
        Err(AuditBreakKind::DigestMismatch),
        "edit a line"
    );

    let mut edited = lines.clone();
    edited[2].usage.fee_count += 1;
    assert_eq!(
        kind(&edited),
        Err(AuditBreakKind::DigestMismatch),
        "change a count"
    );
    let mut edited = lines.clone();
    edited[2].unit.billing = Some(PartitionedBillingV1::new(facts(3)).unwrap());
    assert_eq!(
        kind(&edited),
        Err(AuditBreakKind::DigestMismatch),
        "change the partition count"
    );

    let mut edited = lines.clone();
    edited[2].prev_hash = lines[0].hash.clone();
    assert!(
        kind(&edited).is_err(),
        "edit a prev link to another real line"
    );
    let mut rehashed = edited.clone();
    rehashed[2].hash = digest_record(&rehashed[2]);
    assert!(
        kind(&rehashed).is_err(),
        "an edited prev link stays detected even when its line is rehashed"
    );

    let mut dropped = lines.clone();
    dropped.remove(1);
    assert!(
        matches!(
            kind(&dropped),
            Err(AuditBreakKind::LinkMismatch | AuditBreakKind::SequenceMismatch { .. })
        ),
        "drop a line: {:?}",
        kind(&dropped)
    );

    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    assert!(
        matches!(
            kind(&reordered),
            Err(AuditBreakKind::LinkMismatch | AuditBreakKind::SequenceMismatch { .. })
        ),
        "reorder two lines: {:?}",
        kind(&reordered)
    );

    let truncated = &lines[..3];
    assert_eq!(kind(truncated), Ok(()), "a prefix walks");
    assert_ne!(
        truncated.last().unwrap().hash,
        head,
        "a truncated tail no longer ends at the published head"
    );
}
