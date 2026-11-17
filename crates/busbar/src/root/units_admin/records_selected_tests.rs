// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel_audit::{Controls, OpClassId, OutcomeFacts, UnitFacts, Usage, What};
use busbar_kernel_ledger::cost::{Author, CardEntryDraft, History, RateCard};

fn line(era: signed::BillingEra) -> AuditRecord {
    let billing = signed::PartitionedBillingV1::new(signed::BillingFacts {
        revision: 1,
        request_pool: "p\u{1f}original".into(),
        routing_generation: 3,
        era,
        session_origin: signed::SessionOrigin {
            instance: "p".into(),
            lane: "p\u{1f}".into(),
            provider: None,
        },
        logical_request: signed::LogicalRequest::DeliveredPreparation(6),
        fee: signed::LogicalFee {
            state: signed::FeeState::Charged,
            lane: None,
            era,
        },
        disposition: signed::BillingDisposition::End,
        far_end_answered: true,
        caller_bytes_committed: true,
        final_target: Some(6),
        partitions: (1..=6)
            .map(|n| signed::BillingPartition {
                scope: signed::PartitionScope::Attempt {
                    preparation: n,
                    dispatch: Some(n),
                },
                kind: signed::TargetKind::Model,
                instance: "p".into(),
                lane: "p\u{1f}model".into(),
                provider: Some("actual-provider".into()),
                selected_pool: Some("p\u{1f}selected".into()),
                resource: None,
                transport: Some(signed::Transport::Committed),
                finality: signed::Finality::Unknown,
                classes: BTreeMap::from([(
                    "generic:class".into(),
                    signed::BillingClass {
                        reported: None,
                        floor: None,
                        estimated: Some(1u64.into()),
                        selected: Some(signed::SelectedQuantity {
                            count: 1u64.into(),
                            source: signed::UsageSource::Estimated,
                        }),
                        billed: None,
                        rate_high_water: 0u64.into(),
                    },
                )]),
            })
            .collect(),
    })
    .unwrap();
    AuditRecord {
        subject: Subject::PrincipalId("principal".into()),
        what: What {
            unit_key: busbar_contract::caps::UnitKey::new(1),
            incarnation: 2,
            op_class: OpClassId::new("test"),
            destination: Some("wrong-legacy-target".into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 20,
        mono: 0,
        node: 7,
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
            rate_card_version: None,
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_hash: None,
        unit: UnitFacts {
            billing: Some(billing),
            ..UnitFacts::at(20000)
        },
        linked_ms: 20001,
        seq: 1,
        prev_hash: String::new(),
        recipe: Recipe::V9,
        hash: String::new(),
        signature: None,
        key_id: None,
    }
}

#[test]
fn full_history_prices_original_fee_without_winner_or_arrival_card() {
    let mut history = History::new();
    for fee in [7, 99] {
        history.append(CardEntryDraft {
            effective_from: 0,
            effective_until: None,
            card: RateCard::absent(fee),
            appended_at: 0,
            author: Author::Config {
                policy_epoch: fee as u64,
            },
        });
    }
    let original = history.entries()[0].key();
    let record = line(signed::BillingEra {
        effective_from: 0,
        entry_id: Some(original.id().0),
    });
    let (mut projected, input) = project(&record, &|_| None);
    assert_eq!(projected.schema, wire::UNIT_RECORD_SCHEMA_V2);
    assert_eq!(projected.billing.as_ref().unwrap().partitions.len(), 6);
    assert_eq!(projected.provider.as_deref(), Some("actual-provider"));
    assert_eq!(projected.pool.as_deref(), Some("p\u{1f}original"));
    assert_eq!(projected.target.as_deref(), Some("p\u{1f}model"));
    price(&mut projected, input.unwrap(), &history.current());
    assert!(projected.priced);
    assert_eq!(projected.priced_by, Some(original.hex()));
    let mut tally =
        busbar_kernel_ledger::cost::Tally::at_card_seq(original, history.entries()[0].card());
    tally.fee(0, 10000, 1u64.into()).unwrap();
    let nanos = busbar_kernel_ledger::cost::nanos_of_exact(tally.exact().unwrap()).unwrap();
    assert_eq!(projected.spend_micros, Some(micros_text(nanos)));
}

#[test]
fn missing_or_conflicting_era_and_unknown_fee_never_price_as_zero() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: RateCard::absent(7),
        appended_at: 0,
        author: Author::Config { policy_epoch: 0 },
    });
    let id = history.entries()[0].key().id().0;
    for era in [
        signed::BillingEra {
            effective_from: 0,
            entry_id: None,
        },
        signed::BillingEra {
            effective_from: 1,
            entry_id: Some(id),
        },
    ] {
        let (mut output, input) = project(&line(era), &|_| None);
        price(&mut output, input.unwrap(), &history.current());
        assert!(!output.priced);
        assert_eq!(output.spend_micros, None);
    }
    let mut record = line(signed::BillingEra {
        effective_from: 0,
        entry_id: Some(id),
    });
    let mut facts = record.unit.billing.take().unwrap().facts().clone();
    facts.fee.state = signed::FeeState::Unknown;
    facts.disposition = signed::BillingDisposition::Failed;
    record.unit.billing = Some(signed::PartitionedBillingV1::new(facts).unwrap());
    record.usage.fee_count = 0;
    let (mut output, input) = project(&record, &|_| None);
    price(&mut output, input.unwrap(), &history.current());
    assert!(!output.priced);
    assert_eq!(output.billing.unwrap().disposition, "failed");
}
