// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What each of these types SAYS about itself, read back.
//!
//! Every rendering in this crate is hand-written, and each is written for a reader who has nothing
//! else: the operator looking at a refused admission, the transport author reading a log line while
//! an accrual is being turned away, the proof battery printing a canary that did not balance. A
//! rendering that quietly produced nothing would leave each of them with an empty string where the
//! only evidence was, and every one of them was reachable without a test naming it.
//!
//! Two of the types here carry something they are NOT allowed to say — the hold's principal is a
//! customer identity and the nonce behind a one-shot secret is the secret — so this file asserts on
//! both sides: what has to appear, and what must not.

use crate::*;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

#[test]
fn a_holds_debug_shows_the_four_figures_a_reader_has_to_reconcile() {
    let k = seal();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&k);
    let mut hold = Hold::open(&admit, PrincipalId::new("acct-77"), 1_000);
    hold.spend(1_500, 200);

    let printed = format!("{hold:?}");
    assert!(printed.starts_with("Hold"), "{printed}");
    // Whose it is, and the reservation INCLUDING the top-up: a reader reconciling a posting against
    // a hold needs the figure the accrual was actually measured against, not the door's first guess.
    assert!(printed.contains("acct-77"), "{printed}");
    assert!(printed.contains("1200"), "reserved plus top-up: {printed}");
    assert!(printed.contains("1500"), "accrued: {printed}");
    assert!(printed.contains("300"), "overdraft: {printed}");
    assert!(printed.contains("false"), "not recovered: {printed}");
}

#[test]
fn a_recovered_holds_debug_says_it_came_back_from_a_journal_record() {
    // The one hold that exists without passing the door. A reader who cannot tell it apart from an
    // admitted one cannot tell which postings the crash is responsible for.
    let k = seal();
    let hold = Hold::materialize(
        &RecoveryToken::mint(&k),
        PrincipalId::new("acct-9"),
        500,
        120,
    );
    let printed = format!("{hold:?}");
    assert!(printed.contains("recovered"), "{printed}");
    assert!(printed.contains("true"), "{printed}");
    assert!(
        printed.contains("120"),
        "the checkpointed accrual: {printed}"
    );
}

#[test]
fn every_refusal_the_cell_can_give_says_which_one_it_was() {
    // Three ways an accrual is turned away and two ways a hold is, each read off a log line by
    // somebody deciding whether a child has to post late. A rendering that collapsed them would
    // make the two decisions indistinguishable.
    let refusals = [
        (AccrualRefused::ParentNotAdmitted, "parent not admitted"),
        (AccrualRefused::ParentExited, "parent already exited"),
        (AccrualRefused::PrincipalMismatch, "principal mismatch"),
    ];
    for (refusal, spelling) in refusals {
        assert_eq!(refusal.to_string(), spelling);
        let as_error: &dyn std::error::Error = &refusal;
        assert_eq!(as_error.to_string(), spelling);
    }
    let mut spellings: Vec<&str> = refusals.iter().map(|(_, s)| *s).collect();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(spellings.len(), 3, "two refusals render as one sentence");

    let cell_errors = [
        (CellError::AlreadyAdmitted, "cell already admitted"),
        (CellError::AlreadyTaken, "cell already taken"),
    ];
    for (error, spelling) in cell_errors {
        assert_eq!(error.to_string(), spelling);
        let as_error: &dyn std::error::Error = &error;
        assert_eq!(as_error.to_string(), spelling);
    }
    assert_ne!(
        CellError::AlreadyAdmitted.to_string(),
        CellError::AlreadyTaken.to_string()
    );
}

#[test]
fn a_broken_canary_prints_all_four_counts_and_says_which_side_is_short() {
    // The canary's whole value is arithmetic nobody can reconstruct from a boolean. Its rendering is
    // the evidence: four numbers, in the shape the invariant is stated in.
    let canary = Canary::new();
    for _ in 0..5 {
        canary.draft_accepted();
    }
    canary.hold_opened();
    canary.hold_opened();
    canary.accrual_taken();
    canary.settled();

    let broken = canary.balanced().expect_err("five drafts, three openings");
    let printed = broken.to_string();
    assert!(printed.contains("canary broken"), "{printed}");
    assert!(printed.contains("5 drafts"), "{printed}");
    assert!(printed.contains("2 holds"), "{printed}");
    assert!(printed.contains("1 accruals"), "{printed}");
    assert!(printed.contains("1 settlements"), "{printed}");

    let as_error: &dyn std::error::Error = &broken;
    assert_eq!(as_error.to_string(), printed);
    assert_eq!(broken, canary.counts(), "the break IS the counts");
}

#[test]
fn a_usage_refusal_says_the_record_could_not_hold_it() {
    let error = UsageError::TooManyLines;
    assert_eq!(
        error.to_string(),
        "more usage lines than the record can hold"
    );
    let as_error: &dyn std::error::Error = &error;
    assert!(!as_error.to_string().is_empty());
}

#[test]
fn a_decisions_debug_names_its_own_step_and_the_reason_it_refused() {
    // A decision is opaque to everything but the kernel, so its `Debug` is the only way a loop that
    // is mid-flight can be looked at at all. It has to say which step, and — when it is a refusal —
    // which reason, because "a decision" tells a reader nothing they did not already know.
    let k = seal();
    let admit: UnitToken<Admit> = UnitToken::mint(&k);
    let proceed = Decision::proceed(&admit, Admission::ZeroHold);
    let printed = format!("{proceed:?}");
    assert!(printed.contains("admit"), "{printed}");
    assert!(printed.contains("Proceed"), "{printed}");

    let route: UnitToken<Route> = UnitToken::mint(&k);
    let refused = Decision::refuse(&route, Refusal::new(ReasonCode::BreakerOpen));
    let printed = format!("{refused:?}");
    assert!(printed.contains("route"), "{printed}");
    assert!(printed.contains("Refuse"), "{printed}");
    assert!(printed.contains("breaker_open"), "{printed}");

    // And the two are not the same rendering, which is the whole point of printing either.
    assert_ne!(format!("{proceed:?}"), format!("{refused:?}"));
    let _ = proceed.into_result(&k);
    let _ = refused.into_result(&k);
}

#[test]
fn a_token_prints_the_capability_it_seals_and_nothing_else() {
    // A token is a zero-sized proof, so its rendering is its NAME — which is exactly what a reader
    // needs when the question is "which unit was holding this". The step tokens carry the step too,
    // because an admit token for the wrong step is the mistake the type is there to stop.
    let k = seal();
    assert_eq!(
        format!("{:?}", KernelSeal::acquire_for_kernel()),
        "KernelSeal"
    );
    assert_eq!(format!("{:?}", LedgerToken::mint(&k)), "LedgerToken");
    assert_eq!(format!("{:?}", UsageToken::mint(&k)), "UsageToken");
    assert_eq!(format!("{:?}", TrustToken::mint(&k)), "TrustToken");
    assert_eq!(format!("{:?}", ExitToken::mint(&k)), "ExitToken");
    assert_eq!(format!("{:?}", RecoveryToken::mint(&k)), "RecoveryToken");
    assert_eq!(format!("{:?}", AdminToken::mint(&k)), "AdminToken");
    assert_eq!(
        format!("{:?}", DurabilityToken::mint(&k)),
        "DurabilityToken"
    );
    assert_eq!(
        format!("{:?}", EgressAuthToken::mint(&k)),
        "EgressAuthToken"
    );
    assert_eq!(
        format!("{:?}", TransportKeyToken::mint(&k)),
        "TransportKeyToken"
    );

    let meter: UnitToken<Meter> = UnitToken::mint(&k);
    assert_eq!(format!("{meter:?}"), "UnitToken<meter>");
    let admit: AdmitToken<Admit> = AdmitToken::mint(&k);
    assert_eq!(format!("{admit:?}"), "AdmitToken<admit>");
}

#[test]
fn every_token_names_itself_as_the_contract_seal_it_satisfies() {
    // The seam the other way round: the contract sits BELOW this crate and cannot name a token, so
    // a token satisfies the contract's marker instead. `seal_origin` is what a kernel-built view
    // records about who opened it, and a marker that answered with somebody else's name would put
    // the wrong unit on the record.
    use busbar_contract::plugin::KernelSeal as ContractSeal;
    let k = seal();
    let table: Vec<(&str, String)> = vec![
        (
            "LedgerToken",
            LedgerToken::mint(&k).seal_origin().to_string(),
        ),
        ("UsageToken", UsageToken::mint(&k).seal_origin().to_string()),
        ("TrustToken", TrustToken::mint(&k).seal_origin().to_string()),
        ("ExitToken", ExitToken::mint(&k).seal_origin().to_string()),
        ("AdminToken", AdminToken::mint(&k).seal_origin().to_string()),
        (
            "RecoveryToken",
            RecoveryToken::mint(&k).seal_origin().to_string(),
        ),
        (
            "DurabilityToken",
            DurabilityToken::mint(&k).seal_origin().to_string(),
        ),
        (
            "EgressAuthToken",
            EgressAuthToken::mint(&k).seal_origin().to_string(),
        ),
        (
            "TransportKeyToken",
            TransportKeyToken::mint(&k).seal_origin().to_string(),
        ),
    ];
    for (name, origin) in &table {
        assert_eq!(name, origin, "a token answered with another's name");
    }
    let step_token: UnitToken<Verify> = UnitToken::mint(&k);
    assert_eq!(step_token.seal_origin(), "UnitToken");
    let door: AdmitToken<Admit> = AdmitToken::mint(&k);
    assert_eq!(door.seal_origin(), "AdmitToken");
}

#[test]
fn a_secret_slot_says_where_the_substitution_happens_and_nothing_about_the_secret() {
    // The slot names a LOCATION; the secret never enters it. Its `Debug` is hand-rolled all the same,
    // because the type sits in the family that touches secrets and a derived one would follow the
    // struct wherever it grows.
    let k = seal();
    let slot = SecretSlot::declare(&EgressAuthToken::mint(&k), "header:authorization");
    assert_eq!(slot.location(), "header:authorization");
    let printed = format!("{slot:?}");
    assert!(printed.contains("SecretSlot"), "{printed}");
    assert!(printed.contains("header:authorization"), "{printed}");

    // Two slots at two locations are two different renderings; one that had stopped reading the
    // field would print the same thing for both.
    let other = SecretSlot::declare(&EgressAuthToken::mint(&k), "body:/auth/token");
    assert_ne!(format!("{slot:?}"), format!("{other:?}"));
    assert_ne!(slot, other);
}

#[test]
fn a_one_shot_secret_is_bound_to_one_unit_and_one_target() {
    // The mint is reversed unless the nonce appears exactly once at exactly this target, so both
    // facts have to be readable — and the nonce, which IS the secret, must not be.
    let k = seal();
    let once = SecretOnce::mint(&AdminToken::mint(&k), 42, UnitKey::new(6), "/body/token");
    assert_eq!(once.target(), "/body/token");
    assert_eq!(once.unit(), UnitKey::new(6));
    assert!(once.matches(42));
    assert!(!once.matches(43));

    // A second placeholder at a different target is a different capability, and the accessor is what
    // the substitution site reads to tell them apart.
    let elsewhere = SecretOnce::mint(&AdminToken::mint(&k), 42, UnitKey::new(6), "/header/x-key");
    assert_ne!(once.target(), elsewhere.target());
    assert_ne!(once, elsewhere);
}

#[test]
fn a_durability_loss_names_the_step_the_write_was_attempted_at() {
    // A unit that reaches the exit with one of these delivered value it cannot prove it recorded.
    // Which step it happened at is what decides whether the posting is retained or the unit is
    // refused outright, so it travels with the loss rather than being inferred at the far end.
    let k = seal();
    let lost = DurabilityLost::observed(&DurabilityToken::mint(&k), StepName::Audit);
    assert_eq!(lost.step(), StepName::Audit);
    let at_route = DurabilityLost::observed(&DurabilityToken::mint(&k), StepName::Route);
    assert_eq!(at_route.step(), StepName::Route);
    assert_ne!(lost, at_route);
}
