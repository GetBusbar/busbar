// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Signing, the published recipe, the three reads, and the anchors that outlive the records.

// ONE `use`, not two, and the merge is deliberate rather than tidy: `kind-isolation`'s matrix
// counts every naming of another crate, so two import lines are two recorded couplings where the
// test needs exactly one. The types are the contract's own — a record is built out of them, so a
// test that builds a fully populated record cannot avoid naming them once.
use busbar_contract::{
    caps::{
        Audit as AuditStep, KernelSeal, LocatorPtr, MeterClassId, Origin, OriginKind, Outcome,
        Pass, ReasonCode, StepName, UnitKey,
    },
    ClassDirection,
};

use crate::heads::HeadHistory;
use crate::record::{
    Audit, AuditChain, AuditInputs, Controls, FinishClass, HookApplied, OpClassId, OutcomeFacts,
    QuantitySource, Subject, Usage, UsageLine, What,
};

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

fn origin() -> Origin {
    Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client)
}

/// A record with something in every arm that carries a payload, because those are the fields whose
/// encoding is easiest to move by accident.
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
            }],
            replayed: true,
            children: vec![UnitKey::new(unit + 1000), UnitKey::new(unit + 1001)],
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

/// THE RICH FIXTURE, lent to the sibling module that checks the published recipe.
///
/// `pub(super)` rather than copied: the published-recipe check must run over a record with
/// something in every arm that carries a payload, and two fixtures drifting apart would leave it
/// checking a shape this crate no longer seals.
pub(super) fn rich_inputs(unit: u64) -> AuditInputs {
    inputs(unit)
}

/// A head history has no way to lose anything: no pruning method, no cutoff, no capacity.
///
/// Stated as a test rather than only as a comment because the guarantee is the ABSENCE of an
/// operation, and an absence is the one thing a reader stops noticing. `observe` only ever grows
/// the series.
///
/// Driven PAST the size heads.rs costs the history at — 8 760 hourly heads a year — at the
/// default hourly rate, for two years and one hour. A capacity bound is the one a tidy-up would
/// reach for, and the number it would reach for is that one; fifty observations could not see it.
/// One sealed record is re-observed at each hour with its position advanced: `observe` reads only
/// the head fields, and sealing (and signing) seventeen thousand records would cost the suite far
/// more than the property needs.
#[test]
fn nothing_shrinks_the_head_history() {
    let mut history = HeadHistory::every(0);
    let mut chain = AuditChain::new();
    let mut last = 0;
    for i in 1..=50u64 {
        let record = chain.seal(inputs(i), &token());
        history.observe(&record);
        assert!(
            history.series().len() > last,
            "a head history shrank or stalled"
        );
        last = history.series().len();
    }
    assert_eq!(history.series().len(), 50);

    const TWO_YEARS_AND_AN_HOUR: u64 = 2 * 8_760 + 1;
    let mut hourly = HeadHistory::new();
    let mut record = AuditChain::new().seal(inputs(1), &token());
    let genesis_wall = record.wall;
    for hour in 0..TWO_YEARS_AND_AN_HOUR {
        record.seq = hour + 1;
        record.wall = genesis_wall + hour * crate::heads::HEAD_SAMPLE_SECONDS;
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

fn history_grows_by_one(history: &mut HeadHistory, record: &crate::record::AuditRecord) {
    let before = history.series().len();
    history.observe(record);
    assert_eq!(
        history.series().len(),
        before + 1,
        "an hourly head did not join the series at position {}",
        record.seq
    );
}
