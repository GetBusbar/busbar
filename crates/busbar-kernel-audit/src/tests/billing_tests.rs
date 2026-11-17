// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use busbar_contract::{caps::{Outcome, UnitKey}, Count};
use crate::{record::billing::*, *};

fn facts(attempts: u32) -> BillingFacts {
    let quantity = SelectedQuantity { count: 12u64.into(), source: UsageSource::Reported };
    BillingFacts {
        revision: 9, request_pool: "p\u{1f}original".into(), routing_generation: 3,
        era: BillingEra { effective_from: 17, entry_id: Some([1; 12]) },
        session_origin: SessionOrigin { instance: "p".into(), lane: "p\u{1f}".into(), provider: None },
        logical_request: LogicalRequest::DeliveredPreparation(attempts),
        fee: LogicalFee { state: FeeState::Charged, lane: Some("p\u{1f}".into()), era: BillingEra { effective_from: 19, entry_id: Some([2; 12]) } },
        disposition: BillingDisposition::End, far_end_answered: true, caller_bytes_committed: true,
        final_target: Some(attempts),
        partitions: (1..=attempts).map(|preparation| BillingPartition {
            scope: PartitionScope::Attempt { preparation, dispatch: Some(preparation) },
            kind: TargetKind::Model, instance: "p".into(), lane: "p\u{1f}model".into(),
            provider: Some("configured".into()), selected_pool: Some("p\u{1f}selected".into()), resource: None,
            transport: Some(Transport::Committed), finality: Finality::Complete,
            classes: BTreeMap::from([("tokens".into(), BillingClass { reported: Some(quantity.count), floor: Some(3u64.into()), estimated: Some(50u64.into()), selected: Some(quantity), billed: Some(quantity), rate_high_water: quantity.count })]),
        }).collect(),
    }
}
fn record(billing: PartitionedBillingV1) -> AuditRecord {
    AuditRecord {
        subject: Subject::PrincipalId("principal".into()),
        what: What { unit_key: UnitKey::new(7), incarnation: 8, op_class: OpClassId::new("test"), destination: Some("p\u{1f}model".into()), parent: None, pre_hook_head: None, post_hook_head: None },
        wall: 20, mono: 21, node: 22, origin_kind: "client",
        outcome: OutcomeFacts { unit_end: Outcome::Completed, step: None, finish: FinishClass::Complete, hook_failed: false, emission_delta: 0, stale_policy: false },
        usage: Usage { lines: Vec::new(), tier_bp: 10000, fee_count: 1, rate_card_version: Some([3; 20]), bucket_chain_ref: String::new() },
        controls: Controls::default(), correlation_hash: None,
        unit: UnitFacts { billing: Some(billing), ..UnitFacts::at(20000) },
        linked_ms: 21000, seq: 1, prev_hash: String::new(), recipe: Recipe::V9,
        hash: String::new(), signature: None, key_id: None,
    }
}
#[test]
fn full_attempt_history_and_records_tail_roundtrip_without_a_class_registry() {
    for user in [None, Some("user".into())] {
        for labels in [vec![], vec![("label".into(), "value".into())]] {
            let mut line = record(PartitionedBillingV1::new(facts(6)).unwrap());
            line.unit.records = RecordFacts { user: user.clone(), labels };
            line.hash = digest_record(&line);
            let bytes = journal_body(&line).unwrap();
            assert_eq!(from_journal_body(&bytes, &|_| None).unwrap(), Some(line.clone()));
            assert_eq!(line.unit.billing.as_ref().unwrap().facts().partitions.len(), 6);
            assert_eq!(line.recipe.name(), "busbar.audit.link.v2");
            let json = expose::range_records_body(&[line], 1, 1);
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
    class.selected = Some(SelectedQuantity { count: Count::ZERO, source: UsageSource::Reported });
    class.billed = class.selected;
    let known = record(PartitionedBillingV1::new(zero.clone()).unwrap());
    let class = zero.partitions[0].classes.get_mut("tokens").unwrap();
    class.reported = None; class.floor = None; class.estimated = None; class.selected = None; class.billed = None;
    zero.partitions[0].finality = Finality::Unknown;
    let unknown = record(PartitionedBillingV1::new(zero).unwrap());
    assert_ne!(digest_record(&known), digest_record(&unknown));
    assert_ne!(digest_record(&known), digest_record(&record(PartitionedBillingV1::new(original).unwrap())));
}
#[test]
fn malformed_partition_identities_and_estimated_bills_are_refused() {
    let mut invalid = facts(2);
    invalid.partitions[1].scope = invalid.partitions[0].scope;
    assert!(PartitionedBillingV1::new(invalid).is_err());
    let mut invalid = facts(1);
    invalid.partitions[0].classes.get_mut("tokens").unwrap().billed.as_mut().unwrap().source = UsageSource::Estimated;
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
