// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: one shape, no content, and a chain that catches an edit.

use busbar_caps::{
    Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome, ReasonCode, StepName, UnitKey,
    UnitToken,
};

use crate::record::{
    Amount, Audit, AuditBreakKind, AuditChain, AuditInputs, Controls, FinishClass, HookApplied,
    OpClassId, OutcomeFacts, QuantitySource, Subject, UsageLine, What,
};

fn token() -> UnitToken<AuditStep> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

fn origin() -> Origin {
    Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client)
}

fn inputs(unit: u64) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
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
        amount: Amount {
            lines: vec![UsageLine {
                class: "tokens_out".into(),
                quantity: 120,
                source: QuantitySource::Locator,
                estimated: false,
            }],
            pre_tier: 600,
            priced: 540,
            tier_bp: 9_000,
            fee_count: 1,
            currency: "USD".into(),
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
                priced_delta: -10,
            }],
            replayed: false,
            children: vec![UnitKey::new(unit + 1000)],
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

#[test]
fn a_record_links_to_the_one_before_it_and_the_run_verifies() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();
    assert_eq!(records[0].prev_hash, "");
    for pair in records.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }
    assert!(AuditChain::verify(&records).is_ok());
    assert_eq!(chain.head(), records[3].hash);
    assert_eq!(chain.sealed(), 4);
}

#[test]
fn the_correlation_label_is_hashed_and_the_label_itself_is_gone() {
    let mut chain = AuditChain::new();
    let record = chain.seal(inputs(1), &token());
    let hash = record.correlation_hash.clone().unwrap();
    assert_eq!(
        hash,
        crate::legacy::sha256_hex(b"customer-order-99"),
        "the record carries the digest of the label"
    );
    // And the label is nowhere in the record. Checked over the whole rendered record rather than
    // field by field, because the point is that there is NO path that keeps it.
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
    let record = chain.seal(without, &token());
    assert!(record.correlation_hash.is_none());
}

#[test]
fn editing_any_recorded_fact_is_caught() {
    let mut chain = AuditChain::new();
    let mut records: Vec<_> = (1..=3).map(|i| chain.seal(inputs(i), &token())).collect();

    // Every one of these is a fact somebody would have a reason to change.
    let edits: Vec<(&str, Edit)> = vec![
        ("the priced amount", |r| r.amount.priced += 1),
        ("the pre-tier amount", |r| r.amount.pre_tier += 1),
        ("the tier", |r| r.amount.tier_bp += 1),
        ("the fee count", |r| r.amount.fee_count += 1),
        ("a quantity", |r| r.amount.lines[0].quantity += 1),
        ("a quantity's source", |r| {
            r.amount.lines[0].source = QuantitySource::KernelBytes
        }),
        ("the estimated mark", |r| r.amount.lines[0].estimated = true),
        ("the currency", |r| r.amount.currency = "EUR".into()),
        ("the card version", |r| r.amount.rate_card_version += 1),
        ("the bucket chain", |r| {
            r.amount.bucket_chain_ref = "chain:other".into()
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
        ("a hook's priced delta", |r| {
            r.controls.hooks_applied[0].priced_delta -= 1
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
        let brk = AuditChain::verify(&edited)
            .unwrap_err_or_else(|| panic!("editing {what} went undetected"));
        assert_eq!(brk.kind, AuditBreakKind::DigestMismatch, "editing {what}");
        assert_eq!(brk.at_index, 2);
    }

    // And a record removed from the middle breaks the link rather than the digest.
    records.remove(1);
    let brk = AuditChain::verify(&records).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

#[test]
fn two_nodes_do_not_digest_the_same() {
    // A subject whose identity was left out of the digest would let one node's record stand in for
    // another's.
    let mut chain = AuditChain::new();
    let mut a = inputs(1);
    a.subject = Subject::Node(1);
    let first = chain.seal(a, &token());
    let mut chain = AuditChain::new();
    let mut b = inputs(1);
    b.subject = Subject::Node(2);
    let second = chain.seal(b, &token());
    assert_ne!(first.hash, second.hash);
}

#[test]
fn a_plane_contributes_exactly_two_identifiers() {
    // The claim the fixed record is FOR. A plane says what kind of operation this was and how it
    // finished; every other field is the same shape whichever door the request came in through.
    let mut chain = AuditChain::new();
    let mut other_plane = inputs(1);
    other_plane.what.op_class = OpClassId::new("tool.call");
    other_plane.outcome.finish = FinishClass::TurnComplete;
    let record = chain.seal(other_plane, &token());

    // Same shape, different two ids.
    assert_eq!(record.what.op_class.as_str(), "tool.call");
    assert_eq!(record.outcome.finish, FinishClass::TurnComplete);
    assert_eq!(record.amount.currency, "USD");
    assert!(record.controls.hold_ref.is_some());
}

#[test]
fn a_chain_resumed_from_a_persisted_tail_continues_it() {
    let mut chain = AuditChain::new();
    let first: Vec<_> = (1..=2).map(|i| chain.seal(inputs(i), &token())).collect();

    let mut resumed = AuditChain::resume(chain.head().to_string(), chain.next_seq());
    let third = resumed.seal(inputs(3), &token());
    assert_eq!(third.prev_hash, first[1].hash);

    let mut all = first;
    all.push(third);
    assert!(AuditChain::verify(&all).is_ok());
}

#[test]
fn an_empty_run_verifies_and_the_limit_is_deliberate() {
    // Nothing in the records themselves can tell "no records" from "every record deleted", so
    // claiming otherwise would be claiming a guarantee this cannot provide.
    assert!(AuditChain::verify(&[]).is_ok());
}

/// One hand-edit to a sealed record.
type Edit = fn(&mut crate::record::AuditRecord);

/// A small helper so the edit battery reads as one line per fact rather than four.
trait UnwrapErrOrElse<T, E> {
    fn unwrap_err_or_else(self, f: impl FnOnce() -> E) -> E;
}

impl<T, E> UnwrapErrOrElse<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, f: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => f(),
            Err(e) => e,
        }
    }
}
