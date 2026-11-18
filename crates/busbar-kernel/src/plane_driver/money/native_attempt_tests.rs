// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// Pure factual staging tests. These values are not selected/send authority and do not mint
// PreparedRateAttempt. The composed invocation/Open tests exercise that separate boundary.
use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::Count;
use busbar_plugin_abi::plane::{FB_ATTEMPT_USAGE, UNIT_COUNT, UNIT_TOKENS};
use busbar_ports::codec::fallback_usage::{
    AttemptEnd, AttemptUsage, Completeness, Declaration, UsageSource,
};
use busbar_ports::plane::UsageClass;

use crate::governance::unit_checkpoint::partitions::{
    AttemptPartition, Finality, TargetKind, Transport, UsagePartition, UsageSource as StoredSource,
};

use super::stage_attempt_facts;

fn classes() -> Vec<UsageClass> {
    vec![
        UsageClass {
            class: "tokens.in".into(),
            unit: UNIT_TOKENS,
            expected_units: None,
        },
        UsageClass {
            class: "session.work".into(),
            unit: UNIT_COUNT,
            expected_units: None,
        },
    ]
}

fn attempt() -> AttemptPartition {
    AttemptPartition {
        preparation: 3,
        dispatch: Some(2),
        kind: TargetKind::Model,
        instance: "llm".into(),
        selected_pool: "llm\u{1f}fallback".into(),
        resource: Some("provider-model".into()),
        usage: UsagePartition {
            lane: "llm\u{1f}m0".into(),
            provider: Some("provider".into()),
            classes: BTreeMap::new(),
        },
        transport: Transport::Committed,
        finality: Finality::Live,
    }
}

fn report(source: UsageSource, amount: u64) -> AttemptUsage<'static> {
    AttemptUsage {
        attempt: 3,
        class: "tokens.in",
        amount,
        scale: 0,
        source,
    }
}

#[test]
fn corrections_replace_sources_without_lowering_rate_highwater() {
    let classes = classes();
    let attempt_classes = vec!["tokens.in".into()];
    let declaration = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes).unwrap();
    let physical = BTreeSet::from(["tokens.in".to_owned()]);
    let before = attempt();
    let staged = stage_attempt_facts(
        &before,
        &physical,
        declaration,
        &[
            report(UsageSource::Estimated, 20),
            report(UsageSource::Floor, 10),
            report(UsageSource::Reported, 12),
            report(UsageSource::Reported, 8),
        ],
        None,
    )
    .unwrap();
    let facts = &staged.partition.usage.classes["tokens.in"];
    let selected = facts.selected().unwrap();
    assert_eq!(selected.source, StoredSource::Reported);
    assert_eq!(selected.count, Count::from(8));
    assert_eq!(facts.estimated, Some(Count::from(20)));
    assert_eq!(facts.floor, Some(Count::from(10)));
    assert_eq!(facts.rate_high_water, Count::from(20));
    assert!(before.usage.classes.is_empty());

    let repeated = stage_attempt_facts(
        &staged.partition,
        &physical,
        declaration,
        &[report(UsageSource::Reported, 8)],
        None,
    )
    .unwrap();
    assert_eq!(repeated.partition, staged.partition);
}

#[test]
fn explicit_reported_zero_can_complete_without_falling_back_to_floor() {
    let classes = classes();
    let attempt_classes = vec!["tokens.in".into()];
    let declaration = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes).unwrap();
    let physical = BTreeSet::from(["tokens.in".to_owned()]);
    let staged = stage_attempt_facts(
        &attempt(),
        &physical,
        declaration,
        &[
            report(UsageSource::Floor, 16),
            report(UsageSource::Reported, 0),
        ],
        Some(AttemptEnd {
            attempt: 3,
            completeness: Completeness::Complete,
        }),
    )
    .unwrap();
    let facts = &staged.partition.usage.classes["tokens.in"];
    assert_eq!(facts.selected().unwrap().count, Count::ZERO);
    assert_eq!(facts.selected().unwrap().source, StoredSource::Reported);
    assert_eq!(facts.rate_high_water, Count::from(16));
    assert_eq!(staged.partition.finality, Finality::Complete);
}

#[test]
fn floor_or_estimate_does_not_prove_complete_coverage() {
    let classes = classes();
    let attempt_classes = vec!["tokens.in".into()];
    let declaration = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes).unwrap();
    let physical = BTreeSet::from(["tokens.in".to_owned()]);
    for source in [UsageSource::Estimated, UsageSource::Floor] {
        let before = attempt();
        assert!(stage_attempt_facts(
            &before,
            &physical,
            declaration,
            &[report(source, 0)],
            Some(AttemptEnd {
                attempt: 3,
                completeness: Completeness::Complete,
            }),
        )
        .is_err());
        assert!(before.usage.classes.is_empty());
        assert_eq!(before.finality, Finality::Live);
    }
}

#[test]
fn wrong_preparation_or_session_class_refuses_the_entire_batch() {
    let classes = classes();
    let attempt_classes = vec!["tokens.in".into()];
    let declaration = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes).unwrap();
    let physical = BTreeSet::from(["tokens.in".to_owned()]);
    let good = report(UsageSource::Reported, 7);
    for bad in [
        AttemptUsage { attempt: 2, ..good }, // Dispatch ordinal is not preparation ordinal.
        AttemptUsage {
            class: "session.work",
            ..good
        },
        AttemptUsage { scale: 10, ..good },
    ] {
        let before = attempt();
        assert!(stage_attempt_facts(&before, &physical, declaration, &[good, bad], None).is_err());
        assert_eq!(before, attempt());
    }
}

#[test]
fn prepared_no_send_and_sealed_attempts_cannot_accept_usage() {
    let classes = classes();
    let attempt_classes = vec!["tokens.in".into()];
    let declaration = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes).unwrap();
    let physical = BTreeSet::from(["tokens.in".to_owned()]);
    for (transport, finality) in [
        (Transport::Prepared, Finality::Live),
        (Transport::NoSend, Finality::Unknown),
        (Transport::Committed, Finality::Complete),
        (Transport::Committed, Finality::Partial),
        (Transport::Committed, Finality::Unknown),
    ] {
        let mut before = attempt();
        before.transport = transport;
        before.finality = finality;
        let original = before.clone();
        assert!(stage_attempt_facts(
            &before,
            &physical,
            declaration,
            &[report(UsageSource::Reported, 7)],
            None,
        )
        .is_err());
        assert_eq!(before, original);
    }
}

#[test]
fn accepted_fractional_usage_preserves_existing_half_even_rounding_signal() {
    let classes = classes();
    let attempt_classes = vec!["tokens.in".into()];
    let declaration = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes).unwrap();
    let physical = BTreeSet::from(["tokens.in".to_owned()]);
    let staged = stage_attempt_facts(
        &attempt(),
        &physical,
        declaration,
        &[AttemptUsage {
            amount: 25,
            scale: 7,
            ..report(UsageSource::Reported, 0)
        }],
        None,
    )
    .unwrap();
    assert_eq!(
        staged.partition.usage.classes["tokens.in"].reported,
        Some(Count::from_micros(2))
    );
    assert!(staged.rounded);
}

#[test]
fn preparation_gaps_are_valid_but_live_or_exhausted_predecessors_are_not() {
    let mut prior = attempt();
    assert!(!super::preparation_follows(7, &[prior.clone()], 4));
    prior.finality = Finality::Partial;
    assert!(super::preparation_follows(7, &[prior.clone()], 5));
    assert!(!super::preparation_follows(7, &[prior.clone()], 3));
    assert!(!super::preparation_follows(7, &[prior.clone()], 8));
    prior.transport = Transport::NoSend;
    prior.dispatch = None;
    prior.finality = Finality::Unknown;
    assert!(super::preparation_follows(7, &[prior], 7));
    assert!(!super::preparation_follows(7, &[], 0));
}

#[test]
fn rate_observation_keeps_peak_and_requires_reported_coverage_including_zero() {
    use crate::governance::unit_checkpoint::partitions::ClassFacts;
    let mut partition = attempt();
    partition.usage.classes.insert(
        "tokens.in".into(),
        ClassFacts {
            reported: Some(Count::from(8)),
            floor: Some(Count::from(16)),
            estimated: Some(Count::from(20)),
            rate_high_water: Count::from(20),
        },
    );
    partition.usage.classes.insert(
        "tokens.zero".into(),
        ClassFacts {
            reported: Some(Count::ZERO),
            ..Default::default()
        },
    );
    partition.usage.classes.insert(
        "tokens.floor".into(),
        ClassFacts {
            floor: Some(Count::from(5)),
            rate_high_water: Count::from(5),
            ..Default::default()
        },
    );
    let classes: Vec<Box<str>> = ["tokens.in", "tokens.zero", "tokens.floor", "tokens.missing"]
        .into_iter()
        .map(Into::into)
        .collect();
    let view = super::effective_tokens(&classes, &partition);
    assert_eq!(view.0[0].quantity, Some(Count::from(20)));
    assert!(view.0[0].authoritative);
    assert_eq!(view.0[1].quantity, Some(Count::ZERO));
    assert!(view.0[1].authoritative);
    assert_eq!(view.0[2].quantity, Some(Count::from(5)));
    assert!(!view.0[2].authoritative);
    assert_eq!(view.0[3].quantity, None);
    assert!(!view.0[3].authoritative);
}

#[test]
fn spill_member_scope_does_not_replace_original_request_pool() {
    let grants = crate::plane_driver::request_admission::MemberGrants::from([
        ("seat\u{1f}p".into(), ["seat\u{1f}a".into()].into()),
        ("seat\u{1f}q".into(), ["seat\u{1f}b".into()].into()),
    ]);
    assert!(super::member_granted(&grants, "seat\u{1f}q", "seat\u{1f}b"));
    assert!(!super::member_granted(
        &grants,
        "seat\u{1f}q",
        "seat\u{1f}a"
    ));
    assert!(!super::member_granted(
        &grants,
        "seat\u{1f}other",
        "seat\u{1f}b"
    ));
}
