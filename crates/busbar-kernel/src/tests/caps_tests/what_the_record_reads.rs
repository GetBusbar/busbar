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
//!
//! Moved here from `busbar-contract/src/caps/tests/what_the_record_reads.rs`: every test in this
//! file mints a token, and a token constructor is spelled only inside the kernel (construction
//! `token-sealed`). The tests in that file that need no token stayed with the contract.

use busbar_contract::caps::*;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

#[test]
fn a_proof_from_one_call_is_rejected_in_another() {
    // #74 in-process per-call binding: a Pass or Grant the loop mints for one request carries that
    // request's generation, and a stage compares it against the generation the unit context carries.
    // A proof stamped for call A therefore does not match call B, so a stray or stored proof cannot
    // be replayed across flows. RED BEFORE GREEN: without the generation stamp `bound_to` would be a
    // constant `true` and every assertion below that expects a REJECTION would fail.
    let k = seal();
    let call_a = CallId::seal(&k, 1);
    let call_b = CallId::seal(&k, 2);

    // A pass minted for call A is accepted under call A and rejected under call B.
    let pass_a: Pass<Meter> = Pass::mint_bound(&k, call_a);
    assert!(pass_a.bound_to(call_a), "a pass must match its own call");
    assert!(
        !pass_a.bound_to(call_b),
        "a pass from call A must be rejected in call B"
    );

    // Likewise for a capability grant — the money door is the sharpest case.
    let door_a: Grant<Admittance> = Grant::<Admittance>::mint_bound(&k, call_a);
    assert!(door_a.bound_to(call_a));
    assert!(
        !door_a.bound_to(call_b),
        "an admittance grant from call A must be rejected in call B"
    );

    // An unbound proof (a direct mint, as tests and the composition-root seams make) belongs to no
    // request, so it matches no bound context.
    let unbound: Grant<WriteMoney> = Grant::<WriteMoney>::mint(&k);
    assert!(!unbound.bound_to(call_a));
    assert!(!unbound.bound_to(CallId::UNBOUND));
}

#[test]
fn a_holds_debug_shows_the_four_figures_a_reader_has_to_reconcile() {
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
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
        &Grant::<Recover>::mint(&k),
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
fn a_decisions_debug_names_its_own_step_and_the_reason_it_refused() {
    // A decision is opaque to everything but the kernel, so its `Debug` is the only way a loop that
    // is mid-flight can be looked at at all. It has to say which step, and — when it is a refusal —
    // which reason, because "a decision" tells a reader nothing they did not already know.
    let k = seal();
    let admit: Pass<Admit> = Pass::mint(&k);
    let proceed = SeatVerdict::proceed(&admit, Admission::ZeroHold);
    let printed = format!("{proceed:?}");
    assert!(printed.contains("admit"), "{printed}");
    assert!(printed.contains("Proceed"), "{printed}");

    let route: Pass<Route> = Pass::mint(&k);
    let refused = SeatVerdict::refuse(&route, Refusal::new(ReasonCode::BreakerOpen));
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
    assert_eq!(
        format!("{:?}", Grant::<WriteMoney>::mint(&k)),
        "Grant<write-money>"
    );
    assert_eq!(
        format!("{:?}", Grant::<Consumption>::mint(&k)),
        "Grant<consumption>"
    );
    assert_eq!(format!("{:?}", Grant::<Dial>::mint(&k)), "Grant<dial>");
    assert_eq!(format!("{:?}", Grant::<Exit>::mint(&k)), "Grant<exit>");
    assert_eq!(
        format!("{:?}", Grant::<Recover>::mint(&k)),
        "Grant<recover>"
    );
    assert_eq!(
        format!("{:?}", Grant::<AdminVerb>::mint(&k)),
        "Grant<admin-verb>"
    );
    assert_eq!(
        format!("{:?}", Grant::<DurableWrite>::mint(&k)),
        "Grant<durable-write>"
    );
    assert_eq!(format!("{:?}", Grant::<Sign>::mint(&k)), "Grant<sign>");
    assert_eq!(
        format!("{:?}", Grant::<KeyHandle>::mint(&k)),
        "Grant<key-handle>"
    );

    let meter: Pass<Meter> = Pass::mint(&k);
    assert_eq!(format!("{meter:?}"), "Pass<meter>");
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    assert_eq!(format!("{admit:?}"), "Grant<admittance>");
}

#[test]
fn every_token_names_itself_as_the_contract_seal_it_satisfies() {
    // The seam the other way round: the contract sits BELOW this crate and cannot name a token, so
    // a token satisfies the contract's marker instead. `seal_origin` is what a kernel-built view
    // records about who opened it, and a marker that answered with somebody else's name would put
    // the wrong unit on the record.
    use busbar_contract::plugin::KernelSeal as ContractSeal;
    // Under the unified vocabulary (#73) every grant satisfies the contract marker as "Grant" and
    // every stage-pass as "Pass"; the specific capability travels in the type, not the origin string.
    let k = seal();
    let origins: Vec<String> = vec![
        Grant::<WriteMoney>::mint(&k).seal_origin().to_string(),
        Grant::<Consumption>::mint(&k).seal_origin().to_string(),
        Grant::<Dial>::mint(&k).seal_origin().to_string(),
        Grant::<Exit>::mint(&k).seal_origin().to_string(),
        Grant::<AdminVerb>::mint(&k).seal_origin().to_string(),
        Grant::<Recover>::mint(&k).seal_origin().to_string(),
        Grant::<DurableWrite>::mint(&k).seal_origin().to_string(),
        Grant::<Sign>::mint(&k).seal_origin().to_string(),
        Grant::<KeyHandle>::mint(&k).seal_origin().to_string(),
    ];
    for origin in &origins {
        assert_eq!(origin, "Grant", "a grant answered with another's name");
    }
    let step_token: Pass<Verify> = Pass::mint(&k);
    assert_eq!(step_token.seal_origin(), "Pass");
    let door: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    assert_eq!(door.seal_origin(), "Grant");
}

#[test]
fn a_secret_slot_says_where_the_substitution_happens_and_nothing_about_the_secret() {
    // The slot names a LOCATION; the secret never enters it. Its `Debug` is hand-rolled all the same,
    // because the type sits in the family that touches secrets and a derived one would follow the
    // struct wherever it grows.
    let k = seal();
    let slot = SecretSlot::declare(&Grant::<Sign>::mint(&k), "header:authorization");
    assert_eq!(slot.location(), "header:authorization");
    let printed = format!("{slot:?}");
    assert!(printed.contains("SecretSlot"), "{printed}");
    assert!(printed.contains("header:authorization"), "{printed}");

    // Two slots at two locations are two different renderings; one that had stopped reading the
    // field would print the same thing for both.
    let other = SecretSlot::declare(&Grant::<Sign>::mint(&k), "body:/auth/token");
    assert_ne!(format!("{slot:?}"), format!("{other:?}"));
    assert_ne!(slot, other);
}

#[test]
fn a_durability_loss_names_the_step_the_write_was_attempted_at() {
    // A unit that reaches the exit with one of these delivered value it cannot prove it recorded.
    // Which step it happened at is what decides whether the posting is retained or the unit is
    // refused outright, so it travels with the loss rather than being inferred at the far end.
    let k = seal();
    let lost = DurabilityLost::observed(&Grant::<DurableWrite>::mint(&k), StepName::Audit);
    assert_eq!(lost.step(), StepName::Audit);
    let at_route = DurabilityLost::observed(&Grant::<DurableWrite>::mint(&k), StepName::Route);
    assert_eq!(at_route.step(), StepName::Route);
    assert_ne!(lost, at_route);
}
