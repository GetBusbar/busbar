// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::*;

use crate::canary::Canary;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

#[test]
fn a_proof_from_one_call_is_rejected_in_another() {
    let k = seal();
    let call_a = CallId::seal(&k, 1);
    let call_b = CallId::seal(&k, 2);

    let pass_a: Pass<Meter> = Pass::mint_bound(&k, call_a);
    assert!(pass_a.bound_to(call_a), "a pass must match its own call");
    assert!(
        !pass_a.bound_to(call_b),
        "a pass from call A must be rejected in call B"
    );

    let door_a: Grant<Admittance> = Grant::<Admittance>::mint_bound(&k, call_a);
    assert!(door_a.bound_to(call_a));
    assert!(
        !door_a.bound_to(call_b),
        "an admittance grant from call A must be rejected in call B"
    );

    let unbound: Grant<WriteMoney> = Grant::<WriteMoney>::mint(&k);
    assert!(!unbound.bound_to(call_a));
    assert!(!unbound.bound_to(CallId::UNBOUND));
}

#[test]
fn a_holds_debug_shows_whose_it_is_and_nothing_else() {
    let k = seal();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&k);
    let hold = Hold::open(&admit, PrincipalId::new("acct-77"));
    let printed = format!("{hold:?}");
    assert!(printed.starts_with("Hold"), "{printed}");
    assert!(printed.contains("acct-77"), "{printed}");
}

#[test]
fn a_decisions_debug_names_its_own_step_and_the_reason_it_refused() {
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

    assert_ne!(format!("{proceed:?}"), format!("{refused:?}"));
    let _ = proceed.into_result(&k);
    let _ = refused.into_result(&k);
}

#[test]
fn a_token_prints_the_capability_it_seals_and_nothing_else() {
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
    use busbar_contract::plugin::KernelSeal as ContractSeal;

    let k = seal();
    let origins: Vec<String> = vec![
        Grant::<WriteMoney>::mint(&k).seal_origin().to_string(),
        Grant::<Consumption>::mint(&k).seal_origin().to_string(),
        Grant::<Dial>::mint(&k).seal_origin().to_string(),
        Grant::<Exit>::mint(&k).seal_origin().to_string(),
        Grant::<AdminVerb>::mint(&k).seal_origin().to_string(),
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
    let slot = busbar_contract::SecretSlot {
        target: "header:authorization",
        len: 32,
    };
    let printed = format!("{slot:?}");
    assert!(printed.contains("SecretSlot"), "{printed}");
    assert!(printed.contains("header:authorization"), "{printed}");

    let other = busbar_contract::SecretSlot {
        target: "body:/auth/token",
        len: 32,
    };
    assert_ne!(format!("{slot:?}"), format!("{other:?}"));
    assert_ne!(slot, other);
}

#[test]
fn a_durability_loss_names_the_step_the_write_was_attempted_at() {
    let k = seal();
    let lost = DurabilityLost::observed(&Grant::<DurableWrite>::mint(&k), StepName::Audit);
    assert_eq!(lost.step(), StepName::Audit);
    let at_route = DurabilityLost::observed(&Grant::<DurableWrite>::mint(&k), StepName::Route);
    assert_eq!(at_route.step(), StepName::Route);
    assert_ne!(lost, at_route);
}

#[test]
fn a_broken_canary_prints_all_four_counts_and_says_which_side_is_short() {
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
