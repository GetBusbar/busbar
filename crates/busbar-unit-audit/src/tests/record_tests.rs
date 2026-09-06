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
                class: busbar_caps::MeterClassId::new("tokens_out"),
                quantity: 120,
                source: QuantitySource::Locator {
                    direction: busbar_contract::ClassDirection::Response,
                    ptr: busbar_caps::LocatorPtr::new("/usage/output_tokens"),
                },
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

/// THE SEALED DIGEST IS A FROZEN VALUE, not whatever today's encoder happens to produce.
///
/// Every record a deployment has already written is verified by recomputing this digest, so a
/// change that moves it makes every persisted chain report itself TAMPERED at the next boot. The
/// hex below was produced by an earlier build; it is a value to preserve, never one to re-capture
/// from a failing run. The inputs deliberately use the enum arms that carry payloads, because those
/// are the ones whose encoding is easiest to move by accident.
#[test]
fn the_sealed_digest_of_a_fully_populated_record_is_the_frozen_hex() {
    let mut chain = AuditChain::new();
    let mut with_payloads = inputs(1);
    with_payloads.outcome.unit_end = Outcome::Refused(StepName::Admit, ReasonCode::OverBudget);
    with_payloads.outcome.step = Some(StepName::Admit);
    with_payloads.outcome.finish = FinishClass::Error;
    let record = chain.seal(with_payloads, &token());
    assert_eq!(
        record.hash, "1218355de479c5340448935264ad0c96d78511a22f2ade945fd4aff35b3c7525",
        "the sealed digest moved: every persisted chain would now report itself tampered"
    );
}

#[test]
fn a_record_links_to_the_one_before_it_and_the_run_verifies() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();
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
            r.amount.lines[0].source = QuantitySource::KernelBytes { divisor: 4 }
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
        let brk = AuditChain::verify_chain(&edited)
            .unwrap_err_or_else(|| panic!("editing {what} went undetected"));
        assert_eq!(brk.kind, AuditBreakKind::DigestMismatch, "editing {what}");
        assert_eq!(brk.at_index, 2);
    }

    // And a record removed from the middle breaks the link rather than the digest.
    records.remove(1);
    let brk = AuditChain::verify_chain(&records).unwrap_err();
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
    assert!(AuditChain::verify_chain(&all).is_ok());
}

/// A record carries WHERE it sits, and the position is digested — so a run cannot be renumbered to
/// hide a hole, and a walk can tell a contiguous run from one with records taken out of it.
#[test]
fn a_record_carries_its_position_and_the_position_is_digested() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=3).map(|i| chain.seal(inputs(i), &token())).collect();
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // Renumbering is caught twice over: the walk sees a position that is not the next one, and the
    // record no longer hashes to its own fields — so nobody can close a hole by renumbering what is
    // left of a run.
    let mut renumbered = records.clone();
    renumbered[1].seq = 7;
    assert_eq!(
        AuditChain::verify_chain(&renumbered).unwrap_err().kind,
        AuditBreakKind::LinkMismatch
    );
    assert_ne!(
        AuditChain::digest_of(&renumbered[1]),
        renumbered[1].hash,
        "the position is inside the digest"
    );
}

/// HEAD truncation: the oldest records dropped. What is left links and numbers perfectly among
/// itself, and the only thing that says anything is missing is that the run does not begin where
/// the chain does — which is exactly what the genesis-anchored entry point requires.
#[test]
fn a_run_missing_its_oldest_records_does_not_verify_against_the_genesis() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();

    let brk = AuditChain::verify_chain(&records[1..]).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(brk.at_index, 1, "the break is at the record that should be the genesis");

    // The same run read as a WINDOW of a longer chain is fine: a bounded store's oldest retained
    // record has legitimately lost its predecessor.
    assert!(AuditChain::verify_window(&records[1..]).is_ok());
}

/// A cut INSIDE a window is still caught, so the window anchor excuses the missing head and
/// nothing else.
#[test]
fn a_window_verifies_a_contiguous_middle_run_and_not_a_gapped_one() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=6).map(|i| chain.seal(inputs(i), &token())).collect();

    assert!(AuditChain::verify_window(&records[2..5]).is_ok());

    let mut gapped = records[2..5].to_vec();
    gapped.remove(1);
    let brk = AuditChain::verify_window(&gapped).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

/// TAIL truncation: the newest records dropped. Nothing in the surviving records can say so — they
/// link, they number from one, they hash — so it takes the chain's own head to notice, which is
/// what verifying AGAINST THE HEAD is for.
#[test]
fn a_run_missing_its_newest_records_does_not_verify_against_the_head() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();

    assert!(chain.verify_to_head(&records).is_ok());

    let cut = &records[..3];
    let brk = chain.verify_to_head(cut).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(brk.at_index, 3);

    // And the limit this makes explicit: reading only the records, a cut tail is a whole chain.
    assert!(AuditChain::verify_chain(cut).is_ok());

    // Emptied entirely, against a chain that has sealed records, is a truncation too.
    assert!(chain.verify_to_head(&[]).is_err());
}

#[test]
fn an_empty_run_verifies_and_the_limit_is_deliberate() {
    // Nothing in the records themselves can tell "no records" from "every record deleted", so
    // claiming otherwise would be claiming a guarantee this cannot provide.
    assert!(AuditChain::verify_chain(&[]).is_ok());
}

/// EVERY FROZEN TAG STILL SPELLS WHAT THE CHAIN FROZE.
///
/// The digested text for these enumerations used to be whatever the derived `Debug` printed, so a
/// rename moved the sealed hash and every stored record would have reported itself tampered. The
/// text is written out in the production file now; this checks each spelling against today's derive
/// output, so a rename shows up here — as a difference somebody has to look at — instead of in the
/// hash. If this test fails, the tag is the thing to keep and the rename is the thing to reconsider.
#[test]
fn the_frozen_tags_match_the_text_the_chain_was_sealed_with() {
    use crate::record::{
        abort_tag, direction_tag, finish_tag, outcome_tag, quantity_source_tag, reason_tag,
        step_tag,
    };
    use busbar_caps::{Abort, LocatorPtr};

    for step in [
        StepName::Arrival,
        StepName::Decode,
        StepName::Authenticate,
        StepName::Verify,
        StepName::Approve,
        StepName::Admit,
        StepName::Route,
        StepName::Meter,
        StepName::Audit,
        StepName::Encode,
    ] {
        assert_eq!(step_tag(step), format!("{step:?}"), "step name");
    }

    // The reason list is open, so the tag is a RULE rather than a table: the wire name in upper
    // camel case. Checked against every reason declared today, which is what makes the rule safe to
    // apply to one declared tomorrow.
    for reason in ReasonCode::ALL {
        assert_eq!(
            reason_tag(*reason),
            format!("{reason:?}"),
            "reason `{}`",
            reason.as_str()
        );
    }

    for finish in [
        FinishClass::Complete,
        FinishClass::TurnComplete,
        FinishClass::Partial,
        FinishClass::Error,
    ] {
        assert_eq!(finish_tag(finish), format!("{finish:?}"), "finish class");
    }

    for abort in [
        Abort::Kernel {
            reason: ReasonCode::ClientGone,
        },
        Abort::Kernel {
            reason: ReasonCode::OverBudget,
        },
        Abort::Kernel {
            reason: ReasonCode::Drain,
        },
        Abort::Superseded {
            by: UnitKey::new(77),
        },
    ] {
        assert_eq!(abort_tag(abort), format!("{abort:?}"), "abort");
    }

    for outcome in [
        Outcome::Completed,
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
        Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
        Outcome::Aborted(Abort::Superseded {
            by: UnitKey::new(9),
        }),
        Outcome::TimedOut(StepName::Meter),
    ] {
        assert_eq!(outcome_tag(outcome), format!("{outcome:?}"), "outcome");
    }

    for direction in [
        busbar_contract::ClassDirection::Input,
        busbar_contract::ClassDirection::Response,
        busbar_contract::ClassDirection::CacheRead,
        busbar_contract::ClassDirection::CacheWrite,
        busbar_contract::ClassDirection::Kernel,
    ] {
        assert_eq!(
            direction_tag(direction),
            format!("{direction:?}"),
            "class direction"
        );
    }

    for source in [
        QuantitySource::Locator {
            direction: busbar_contract::ClassDirection::Response,
            // A pointer with a quote and a backslash in it, because the frozen text quotes and
            // escapes the pointer and an unescaped one would digest differently.
            ptr: LocatorPtr::new("/usage/\"odd\\name\""),
        },
        QuantitySource::KernelBytes { divisor: 4 },
        QuantitySource::KernelFrames { factor: 2 },
        QuantitySource::TransportUnits,
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
        QuantitySource::PlaneCount {
            content_fact_key: "messages".into(),
        },
    ] {
        assert_eq!(
            quantity_source_tag(&source),
            format!("{source:?}"),
            "quantity source"
        );
    }
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
