// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `inbound_table`: the truth table of inbound admission. One row per case: a route of the
//! reference plane (or no route), what is known of the request, and the one decision. The table is
//! the product's order of checks; a change to `decide` that moves a refusal ahead of another turns
//! a row red.

use busbar_contract::route::{METHOD_GET, METHOD_POST};
use busbar_plugin_abi::fail::refused::{R_AUTH_REQUIRED, R_BAD_CREDENTIAL};

use crate::auth::admission_table::{
    admission_of, decide, decide_forward, mounted, plan, Admission, Authority, BodyAt, BodyBy,
    BodyRead, Decision, Facts, ForwardFacts, Gate, JudgedAt, Limits, NotMounted, Offered, Policy,
    Refusal, ScopeJudged, Step, Target, Unit, UpgradeAsked, Verified, VerifyBy,
};
use crate::auth::core_answer;
use crate::auth::reference_plane::{self, ReferenceRoute};
use crate::auth::route_record::{
    contested_kind, CallerState, KindClaim, Money, PlaneMethods, RecordRefused, RouteClass,
    RouteRecord, Scope, Who,
};

const ALL: [Admission; 10] = [
    Admission::Walk,
    Admission::Selected,
    Admission::PrincipalOnly,
    Admission::Catalog,
    Admission::Public,
    Admission::Optional,
    Admission::Ticket,
    Admission::SignedIngress,
    Admission::Upgrade,
    Admission::Operator,
];

fn reference(admission: Admission) -> ReferenceRoute {
    reference_plane::route_of(admission).expect("the reference plane has every reachable admission")
}

fn none() -> Facts {
    Facts::arrived(false, false)
}

fn keyed() -> Facts {
    Facts::arrived(true, false)
}

const DISTINCT: Verified = Verified::Identity { shared: false };
const SHARED: Verified = Verified::Identity { shared: true };

fn run(step: Step) -> Decision {
    Decision::Run(step)
}

fn refused(refusal: Refusal, verified: bool) -> Decision {
    Decision::Refuse { refusal, verified }
}

fn unverified(presented: bool) -> Decision {
    refused(Refusal::Unverified { presented }, false)
}

/// Every fact of a request that passes every step of every sequence.
fn passing(verified: Verified) -> Facts {
    Facts {
        gate: Gate::Open,
        presented: true,
        ticket_presented: false,
        verified: Some(verified),
        policy: Some(Policy::Valid),
        body: Some(BodyRead::Taken),
        scope: Some(ScopeJudged::Permitted),
        limits: Some(Limits::Within),
        unit: Some(Unit::Admitted),
        upgrade: Some(UpgradeAsked::Carried),
    }
}

/// What the verifier of an admission answers for a caller it admits.
fn verifier_of(admission: Admission) -> Verified {
    match admission {
        Admission::SignedIngress => Verified::Signature,
        Admission::Operator => Verified::Operator,
        _ => DISTINCT,
    }
}

#[test]
fn every_reference_record_is_valid_and_names_its_admission() {
    for route in reference_plane::routes() {
        assert_eq!(
            route
                .record
                .validate(route.methods, reference_plane::METHODS),
            Ok(()),
            "{}",
            route.pattern
        );
        assert_eq!(
            admission_of(&route.record),
            route.admission,
            "{}",
            route.pattern
        );
    }
    for admission in ALL {
        assert!(
            reference_plane::route_of(admission).is_some(),
            "{admission:?}"
        );
    }
}

#[test]
fn every_reachable_admission_has_a_sequence_and_internal_has_none() {
    for admission in ALL {
        for money in [Money::None, Money::Unit] {
            assert!(plan(admission, money).is_some(), "{admission:?}");
        }
    }
    assert_eq!(plan(Admission::Internal, Money::Unit), None);
}

/// The sequences of design C4, one row per admission.
#[test]
fn the_sequences_are_the_designs() {
    use Authority as A;
    use BodyAt::{AfterVerify, BoundedBeforeVerify, Never};
    use JudgedAt::{BeforeServe, InWalk, Nowhere};
    use Money::{None as Free, Unit as Paid};
    use VerifyBy as V;
    #[rustfmt::skip]
    let rows = [
        (Admission::Walk, Paid, V::Chain, true, AfterVerify, InWalk, InWalk, A::Walk),
        (Admission::Walk, Free, V::Chain, true, AfterVerify, InWalk, Nowhere, A::Unbilled),
        (Admission::Selected, Paid, V::Chain, true, AfterVerify, BeforeServe, BeforeServe, A::Billed),
        (Admission::PrincipalOnly, Paid, V::Chain, true, AfterVerify, Nowhere, BeforeServe, A::Billed),
        (Admission::PrincipalOnly, Free, V::Chain, true, AfterVerify, Nowhere, Nowhere, A::Unbilled),
        (Admission::Catalog, Free, V::Chain, true, AfterVerify, BeforeServe, Nowhere, A::Catalog),
        (Admission::Public, Free, V::Nobody, false, AfterVerify, Nowhere, Nowhere, A::Public),
        (Admission::Optional, Free, V::ChainIfPresented, true, AfterVerify, Nowhere, Nowhere, A::Unbilled),
        (Admission::Ticket, Paid, V::TicketOrChain, true, AfterVerify, Nowhere, BeforeServe, A::Billed),
        (Admission::SignedIngress, Free, V::Signature, false, BoundedBeforeVerify, Nowhere, Nowhere, A::Unbilled),
        (Admission::Upgrade, Paid, V::Chain, true, Never, BeforeServe, BeforeServe, A::Upgrade),
        (Admission::Operator, Free, V::AdminChain, false, AfterVerify, Nowhere, Nowhere, A::Operator),
    ];
    for (admission, money, verify, policy, body, scope, charged, serves) in rows {
        let plan = plan(admission, money).expect("reachable");
        assert_eq!(
            (
                plan.verify,
                plan.policy,
                plan.body,
                plan.scope,
                plan.money,
                plan.serves
            ),
            (verify, policy, body, scope, charged, serves),
            "{admission:?} {money:?}"
        );
        assert_eq!(plan.upgrade, admission == Admission::Upgrade);
    }
}

/// Step 0 answers before anything else is looked at, on every route and on none.
#[test]
fn a_full_or_draining_gateway_answers_before_any_step() {
    for (gate, refusal) in [
        (Gate::Full, Refusal::GatewayFull),
        (Gate::Draining, Refusal::Draining),
    ] {
        let mut facts = passing(DISTINCT);
        facts.gate = gate;
        for admission in ALL {
            let route = reference(admission);
            assert_eq!(
                decide(Target::Route(&route.record), &facts),
                refused(refusal, false)
            );
        }
        assert_eq!(decide(Target::NoRoute, &facts), refused(refusal, false));
    }
}

/// No route: the data chain judges the caller. 404 and 405 only for a verified one (gap G4).
#[test]
fn no_route() {
    let allow = METHOD_GET | METHOD_POST;
    let with = |verified: Option<Verified>, policy: Option<Policy>, presented: bool| Facts {
        verified,
        policy,
        ..Facts::arrived(presented, false)
    };
    #[rustfmt::skip]
    let rows = [
        (with(None, None, false), run(Step::Verify)),
        (with(Some(Verified::Denied), None, false), unverified(false)),
        (with(Some(Verified::Denied), None, true), unverified(true)),
        (with(Some(Verified::Unavailable), None, true), refused(Refusal::VerifierUnavailable, false)),
        (with(Some(DISTINCT), None, true), run(Step::Policy)),
        (with(Some(DISTINCT), Some(Policy::NoKey), true), unverified(true)),
        (with(Some(DISTINCT), Some(Policy::Disabled), true), refused(Refusal::KeyDisabled, true)),
        (with(Some(DISTINCT), Some(Policy::Replayed), true), refused(Refusal::Replayed, false)),
        (with(Some(DISTINCT), Some(Policy::Valid), true), refused(Refusal::NoRoute, true)),
        (with(Some(SHARED), Some(Policy::Valid), false), refused(Refusal::NoRoute, true)),
        // A ticket, a signature and an operator are not data-chain identities.
        (with(Some(Verified::Ticket), Some(Policy::Valid), true), unverified(true)),
        (with(Some(Verified::Operator), Some(Policy::Valid), true), unverified(true)),
    ];
    for (facts, expected) in rows {
        assert_eq!(decide(Target::NoRoute, &facts), expected, "{facts:?}");
    }
    let verified = with(Some(DISTINCT), Some(Policy::Valid), true);
    assert_eq!(
        decide(Target::WrongMethod { allow }, &verified),
        refused(Refusal::WrongMethod { allow }, true)
    );
    assert_eq!(
        decide(
            Target::WrongMethod { allow },
            &with(Some(Verified::Denied), None, true)
        ),
        unverified(true),
        "an unverified caller is not told the path exists"
    );
}

/// Steps 2 and 3 on every route that verifies: the caller is judged on the head, before the body.
#[test]
fn verify_and_policy_come_first_and_before_the_body() {
    for admission in [
        Admission::Walk,
        Admission::Selected,
        Admission::PrincipalOnly,
        Admission::Catalog,
        Admission::Ticket,
        Admission::Upgrade,
    ] {
        let route = reference(admission);
        let target = Target::Route(&route.record);
        // Nothing known, and a body the listener must not have taken yet.
        assert_eq!(decide(target, &keyed()), run(Step::Verify), "{admission:?}");
        let mut facts = keyed();
        // Every later fault is present; the unverified answer still wins.
        facts.body = Some(BodyRead::OverCap);
        facts.scope = Some(ScopeJudged::Denied);
        facts.limits = Some(Limits::InFlight);
        facts.unit = Some(Unit::BudgetSpent {
            retry_after_s: None,
        });
        facts.upgrade = Some(UpgradeAsked::NotAnUpgrade);
        facts.verified = Some(Verified::Denied);
        assert_eq!(decide(target, &facts), unverified(true), "{admission:?}");
        facts.verified = Some(Verified::Unavailable);
        assert_eq!(
            decide(target, &facts),
            refused(Refusal::VerifierUnavailable, false),
            "{admission:?}"
        );
        facts.verified = Some(DISTINCT);
        assert_eq!(decide(target, &facts), run(Step::Policy), "{admission:?}");
        facts.policy = Some(Policy::NoKey);
        assert_eq!(decide(target, &facts), unverified(true), "{admission:?}");
        facts.policy = Some(Policy::Disabled);
        assert_eq!(
            decide(target, &facts),
            refused(Refusal::KeyDisabled, true),
            "{admission:?}"
        );
        facts.policy = Some(Policy::Replayed);
        assert_eq!(
            decide(target, &facts),
            refused(Refusal::Replayed, false),
            "{admission:?}"
        );
        // A verifier answer the record does not admit is not a verification.
        facts.policy = Some(Policy::Valid);
        facts.verified = Some(Verified::Operator);
        assert_eq!(decide(target, &facts), unverified(true), "{admission:?}");
        facts.verified = Some(Verified::Signature);
        assert_eq!(decide(target, &facts), unverified(true), "{admission:?}");
    }
}

struct Case {
    admission: Admission,
    set: fn(&mut Facts),
    expected: Decision,
}

/// The order of the refusals after verification, per admission: the first fault in the sequence
/// is the answer, whatever else is also wrong.
#[test]
fn refusals_follow_the_sequence() {
    use Admission as Ad;
    let spent_refusal = Refusal::BudgetSpent {
        retry_after_s: None,
    };
    #[rustfmt::skip]
    let cases = [
        // Walk: body, then the unit's record; scope and limits belong to FORWARD.
        Case { admission: Ad::Walk, set: |f| f.body = None, expected: run(Step::Body) },
        Case { admission: Ad::Walk, set: |f| f.body = Some(BodyRead::OverCap), expected: refused(Refusal::BodyTooLarge, true) },
        Case { admission: Ad::Walk, set: |f| f.body = Some(BodyRead::Trailers), expected: refused(Refusal::Trailers, true) },
        Case { admission: Ad::Walk, set: |f| f.body = Some(BodyRead::DigestMismatch), expected: refused(Refusal::DigestMismatch, false) },
        Case { admission: Ad::Walk, set: |f| f.unit = None, expected: run(Step::Unit) },
        Case { admission: Ad::Walk, set: |f| f.unit = Some(Unit::Unwritable), expected: refused(Refusal::MoneyUnavailable, true) },
        Case { admission: Ad::Walk, set: |f| { f.scope = Some(ScopeJudged::Denied); f.limits = Some(Limits::InFlight); }, expected: Decision::Serve(Authority::Walk) },
        Case { admission: Ad::Walk, set: |f| { f.scope = None; f.limits = None; }, expected: Decision::Serve(Authority::Walk) },
        // Principal only, with a unit: body, limits, unit.
        Case { admission: Ad::PrincipalOnly, set: |f| f.body = None, expected: run(Step::Body) },
        Case { admission: Ad::PrincipalOnly, set: |f| { f.scope = None; f.limits = None; }, expected: run(Step::Limits) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.limits = Some(Limits::GroupFrozen), expected: refused(Refusal::GroupFrozen, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.limits = Some(Limits::GroupUnknown), expected: refused(Refusal::GroupUnknown, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.limits = Some(Limits::InFlight), expected: refused(Refusal::InFlight, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.limits = Some(Limits::Window { retry_after_s: 7 }), expected: refused(Refusal::Window { retry_after_s: 7 }, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| { f.limits = Some(Limits::InFlight); f.unit = Some(Unit::Unpriced); }, expected: refused(Refusal::InFlight, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.unit = None, expected: run(Step::Unit) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.unit = Some(Unit::Unpriced), expected: refused(Refusal::Unpriced, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.unit = Some(Unit::Unwritable), expected: refused(Refusal::MoneyUnavailable, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.unit = Some(Unit::BudgetSpent { retry_after_s: Some(60) }), expected: refused(Refusal::BudgetSpent { retry_after_s: Some(60) }, true) },
        Case { admission: Ad::PrincipalOnly, set: |f| f.scope = Some(ScopeJudged::Denied), expected: Decision::Serve(Authority::Billed) },
        // Selected: body, scope, limits, unit.
        Case { admission: Ad::Selected, set: |f| { f.body = None; f.scope = Some(ScopeJudged::Denied); }, expected: run(Step::Body) },
        Case { admission: Ad::Selected, set: |f| f.scope = None, expected: run(Step::Scope) },
        Case { admission: Ad::Selected, set: |f| { f.scope = Some(ScopeJudged::Denied); f.limits = Some(Limits::InFlight); }, expected: refused(Refusal::ScopeDenied, true) },
        Case { admission: Ad::Selected, set: |f| { f.limits = Some(Limits::InFlight); f.unit = Some(Unit::Unpriced); }, expected: refused(Refusal::InFlight, true) },
        Case { admission: Ad::Selected, set: |f| f.unit = Some(Unit::BudgetSpent { retry_after_s: None }), expected: refused(spent_refusal, true) },
        Case { admission: Ad::Selected, set: |_| {}, expected: Decision::Serve(Authority::Billed) },
        // Catalog: scope (core builds the list), no limits, no unit.
        Case { admission: Ad::Catalog, set: |f| f.scope = None, expected: run(Step::Scope) },
        Case { admission: Ad::Catalog, set: |f| f.scope = Some(ScopeJudged::Denied), expected: refused(Refusal::ScopeDenied, true) },
        Case { admission: Ad::Catalog, set: |f| { f.limits = Some(Limits::InFlight); f.unit = Some(Unit::Unwritable); }, expected: Decision::Serve(Authority::Catalog) },
        Case { admission: Ad::Catalog, set: |f| { f.limits = None; f.unit = None; }, expected: Decision::Serve(Authority::Catalog) },
        // Ticket (with a key presented): limits and unit, no scope.
        Case { admission: Ad::Ticket, set: |f| f.scope = Some(ScopeJudged::Denied), expected: Decision::Serve(Authority::Billed) },
        Case { admission: Ad::Ticket, set: |f| f.limits = Some(Limits::InFlight), expected: refused(Refusal::InFlight, true) },
        Case { admission: Ad::Ticket, set: |f| f.unit = Some(Unit::Unwritable), expected: refused(Refusal::MoneyUnavailable, true) },
        // Upgrade: the upgrade request, then scope, limits, unit; the body is never taken.
        Case { admission: Ad::Upgrade, set: |f| { f.upgrade = None; f.scope = Some(ScopeJudged::Denied); }, expected: run(Step::Upgrade) },
        Case { admission: Ad::Upgrade, set: |f| f.upgrade = Some(UpgradeAsked::NotAnUpgrade), expected: refused(Refusal::NotAnUpgrade, true) },
        Case { admission: Ad::Upgrade, set: |f| f.upgrade = Some(UpgradeAsked::NoTransport), expected: refused(Refusal::NoUpgradeTransport, true) },
        Case { admission: Ad::Upgrade, set: |f| f.body = Some(BodyRead::OverCap), expected: Decision::Serve(Authority::Upgrade) },
        Case { admission: Ad::Upgrade, set: |f| f.body = None, expected: Decision::Serve(Authority::Upgrade) },
        Case { admission: Ad::Upgrade, set: |f| f.scope = Some(ScopeJudged::Denied), expected: refused(Refusal::ScopeDenied, true) },
        Case { admission: Ad::Upgrade, set: |f| f.limits = Some(Limits::Window { retry_after_s: 3 }), expected: refused(Refusal::Window { retry_after_s: 3 }, true) },
        Case { admission: Ad::Upgrade, set: |f| f.unit = Some(Unit::BudgetSpent { retry_after_s: None }), expected: refused(spent_refusal, true) },
        // Operator: the admin chain, the body, then the admin walk's own scope and rate.
        Case { admission: Ad::Operator, set: |f| f.body = None, expected: run(Step::Body) },
        Case { admission: Ad::Operator, set: |f| { f.policy = None; f.scope = None; f.limits = None; f.unit = None; }, expected: Decision::Serve(Authority::Operator) },
        // Signed ingress: the signature, nothing else.
        Case { admission: Ad::SignedIngress, set: |f| { f.policy = None; f.scope = None; f.limits = None; f.unit = None; }, expected: Decision::Serve(Authority::Unbilled) },
    ];
    for (index, case) in cases.iter().enumerate() {
        let route = reference(case.admission);
        let mut facts = passing(verifier_of(case.admission));
        (case.set)(&mut facts);
        assert_eq!(
            decide(Target::Route(&route.record), &facts),
            case.expected,
            "case {index}: {:?}",
            case.admission
        );
    }
}

#[test]
fn a_request_that_passes_everything_is_served_by_its_authority() {
    let rows = [
        (Admission::Walk, Authority::Walk),
        (Admission::Selected, Authority::Billed),
        (Admission::PrincipalOnly, Authority::Billed),
        (Admission::Catalog, Authority::Catalog),
        (Admission::Public, Authority::Public),
        (Admission::Optional, Authority::Unbilled),
        (Admission::Ticket, Authority::Billed),
        (Admission::SignedIngress, Authority::Unbilled),
        (Admission::Upgrade, Authority::Upgrade),
        (Admission::Operator, Authority::Operator),
    ];
    for (admission, authority) in rows {
        let route = reference(admission);
        let facts = passing(verifier_of(admission));
        assert_eq!(
            decide(Target::Route(&route.record), &facts),
            Decision::Serve(authority),
            "{admission:?}"
        );
    }
    // The principal-only route that moves no money: verified, recorded, not billed.
    let free = reference_plane::routes()
        .into_iter()
        .find(|route| route.pattern == "/ref/principal-free")
        .expect("declared");
    let mut facts = passing(DISTINCT);
    facts.limits = None;
    facts.unit = None;
    assert_eq!(
        decide(Target::Route(&free.record), &facts),
        Decision::Serve(Authority::Unbilled)
    );
}

/// A public route runs no verifier and reads no credential: nothing a caller presents changes it.
#[test]
fn public_runs_no_verifier() {
    let route = reference(Admission::Public);
    let target = Target::Route(&route.record);
    for presented in [false, true] {
        let mut facts = Facts::arrived(presented, presented);
        assert_eq!(decide(target, &facts), run(Step::Body));
        facts.body = Some(BodyRead::Taken);
        assert_eq!(decide(target, &facts), Decision::Serve(Authority::Public));
        // A verifier answer nobody asked for is not read.
        facts.verified = Some(Verified::Denied);
        assert_eq!(decide(target, &facts), Decision::Serve(Authority::Public));
        facts.body = Some(BodyRead::OverCap);
        assert_eq!(
            decide(target, &facts),
            refused(Refusal::BodyTooLarge, false)
        );
    }
}

/// An optional route verifies only a caller that presents a credential; a bad one is refused.
#[test]
fn optional_verifies_only_what_is_presented() {
    let route = reference(Admission::Optional);
    let target = Target::Route(&route.record);
    let mut absent = none();
    assert_eq!(decide(target, &absent), run(Step::Body));
    absent.body = Some(BodyRead::Taken);
    assert_eq!(
        decide(target, &absent),
        Decision::Serve(Authority::Unbilled)
    );
    let mut present = keyed();
    assert_eq!(decide(target, &present), run(Step::Verify));
    present.verified = Some(Verified::Denied);
    assert_eq!(decide(target, &present), unverified(true));
    present.verified = Some(DISTINCT);
    assert_eq!(decide(target, &present), run(Step::Policy));
    present.policy = Some(Policy::Valid);
    present.body = Some(BodyRead::Taken);
    assert_eq!(
        decide(target, &present),
        Decision::Serve(Authority::Unbilled)
    );
}

/// A key-or-ticket route admits either; a ticket earns no key policy of its own.
#[test]
fn ticket_or_key() {
    let route = reference(Admission::Ticket);
    let target = Target::Route(&route.record);
    let mut facts = Facts::arrived(false, true);
    assert_eq!(decide(target, &facts), run(Step::Verify));
    facts.verified = Some(Verified::Denied);
    assert_eq!(decide(target, &facts), unverified(true));
    facts.verified = Some(Verified::Ticket);
    assert_eq!(
        decide(target, &facts),
        run(Step::Body),
        "no policy step for a ticket"
    );
    facts.body = Some(BodyRead::Taken);
    assert_eq!(decide(target, &facts), run(Step::Limits));
    facts.limits = Some(Limits::Within);
    assert_eq!(decide(target, &facts), run(Step::Unit));
    facts.unit = Some(Unit::Admitted);
    assert_eq!(decide(target, &facts), Decision::Serve(Authority::Billed));
    // A ticket-only route refuses a key.
    let mut only = route.record.clone();
    only.who = Who::TICKET;
    assert_eq!(
        only.validate(route.methods, reference_plane::METHODS),
        Ok(())
    );
    assert_eq!(admission_of(&only), Admission::Ticket);
    assert_eq!(
        decide(Target::Route(&only), &passing(DISTINCT)),
        unverified(true)
    );
    assert_eq!(
        decide(Target::Route(&only), &passing(Verified::Ticket)),
        Decision::Serve(Authority::Billed)
    );
}

/// A signed route reads its bounded body first; nothing else reads a body before step 2.
#[test]
fn signed_ingress_reads_a_bounded_body_then_verifies() {
    let route = reference(Admission::SignedIngress);
    let target = Target::Route(&route.record);
    let mut facts = keyed();
    assert_eq!(decide(target, &facts), run(Step::Body));
    facts.body = Some(BodyRead::OverCap);
    assert_eq!(
        decide(target, &facts),
        refused(Refusal::BodyTooLarge, false)
    );
    facts.body = Some(BodyRead::Taken);
    assert_eq!(decide(target, &facts), run(Step::Verify));
    facts.verified = Some(Verified::Denied);
    assert_eq!(decide(target, &facts), unverified(true));
    facts.verified = Some(DISTINCT);
    assert_eq!(
        decide(target, &facts),
        unverified(true),
        "a key is not a signature"
    );
    facts.verified = Some(Verified::Signature);
    assert_eq!(decide(target, &facts), Decision::Serve(Authority::Unbilled));
    for admission in ALL {
        if admission == Admission::SignedIngress {
            continue;
        }
        let body = plan(admission, Money::Unit).expect("reachable").body;
        assert_ne!(body, BodyAt::BoundedBeforeVerify, "{admission:?}");
    }
}

/// Field 4: a route that keeps state per caller is never served to the shared subject.
#[test]
fn distinct_routes_are_not_served_to_a_shared_subject() {
    let route = reference(Admission::Selected);
    assert_eq!(route.record.caller_state, CallerState::Distinct);
    assert_eq!(
        decide(Target::Route(&route.record), &passing(SHARED)),
        refused(Refusal::NoRoute, true)
    );
    assert_eq!(
        decide(Target::Route(&route.record), &passing(DISTINCT)),
        Decision::Serve(Authority::Billed)
    );
    // A shared-state route serves the anonymous principal like any other.
    let walk = reference(Admission::Walk);
    assert_eq!(
        decide(Target::Route(&walk.record), &passing(SHARED)),
        Decision::Serve(Authority::Walk)
    );
}

/// Steps 5 to 7 at the plane's FORWARD: scope, price, limits, money, in that order.
#[test]
fn forward_order() {
    let ok = ForwardFacts {
        scope: ScopeJudged::Permitted,
        priced: true,
        limits: Limits::Within,
        unit: Unit::Admitted,
    };
    assert_eq!(decide_forward(Money::Unit, &ok), Ok(()));
    let everything_wrong = ForwardFacts {
        scope: ScopeJudged::Denied,
        priced: false,
        limits: Limits::InFlight,
        unit: Unit::BudgetSpent {
            retry_after_s: None,
        },
    };
    assert_eq!(
        decide_forward(Money::Unit, &everything_wrong),
        Err(Refusal::ScopeDenied)
    );
    assert_eq!(
        decide_forward(Money::None, &everything_wrong),
        Err(Refusal::ScopeDenied)
    );
    let unpriced = ForwardFacts {
        scope: ScopeJudged::Permitted,
        ..everything_wrong
    };
    assert_eq!(
        decide_forward(Money::Unit, &unpriced),
        Err(Refusal::Unpriced)
    );
    assert_eq!(
        decide_forward(Money::None, &unpriced),
        Ok(()),
        "no money, nothing counted"
    );
    let limited = ForwardFacts {
        priced: true,
        ..unpriced
    };
    assert_eq!(
        decide_forward(Money::Unit, &limited),
        Err(Refusal::InFlight)
    );
    let spent = ForwardFacts {
        limits: Limits::Within,
        ..limited
    };
    assert_eq!(
        decide_forward(Money::Unit, &spent),
        Err(Refusal::BudgetSpent {
            retry_after_s: None
        })
    );
    for (limits, refusal) in [
        (Limits::GroupFrozen, Refusal::GroupFrozen),
        (Limits::GroupUnknown, Refusal::GroupUnknown),
        (
            Limits::Window { retry_after_s: 9 },
            Refusal::Window { retry_after_s: 9 },
        ),
    ] {
        assert_eq!(
            decide_forward(Money::Unit, &ForwardFacts { limits, ..ok }),
            Err(refusal)
        );
    }
    assert_eq!(
        decide_forward(
            Money::Unit,
            &ForwardFacts {
                unit: Unit::Unwritable,
                ..ok
            }
        ),
        Err(Refusal::MoneyUnavailable)
    );
}

/// The refusal table (design C7): status, code and headers of every row.
#[test]
fn the_refusal_rows() {
    #[rustfmt::skip]
    let rows: [(Refusal, &str, u16, bool, Option<u32>); 21] = [
        (Refusal::GatewayFull, "1", 503, false, Some(1)),
        (Refusal::Unverified { presented: false }, "2", 401, true, None),
        (Refusal::VerifierUnavailable, "2a", 503, false, None),
        (Refusal::KeyDisabled, "3", 403, false, None),
        (Refusal::NoRoute, "4", 404, false, None),
        (Refusal::WrongMethod { allow: METHOD_GET }, "5", 405, false, None),
        (Refusal::BodyTooLarge, "6", 413, false, None),
        (Refusal::DigestMismatch, "7", 401, true, None),
        (Refusal::Trailers, "8", 400, false, None),
        (Refusal::ScopeDenied, "10", 403, false, None),
        (Refusal::Unpriced, "12", 400, false, None),
        (Refusal::GroupFrozen, "13", 403, false, None),
        (Refusal::GroupUnknown, "14", 403, false, None),
        (Refusal::InFlight, "15", 429, false, None),
        (Refusal::Window { retry_after_s: 12 }, "16", 429, false, Some(12)),
        (Refusal::BudgetSpent { retry_after_s: Some(30) }, "17", 402, false, Some(30)),
        (Refusal::MoneyUnavailable, "18", 503, false, None),
        (Refusal::Replayed, "19", 409, false, None),
        (Refusal::NotAnUpgrade, "20", 400, false, None),
        (Refusal::NoUpgradeTransport, "20", 501, false, None),
        (Refusal::Draining, "22", 503, false, None),
    ];
    for (refusal, row, status, challenge, retry) in rows {
        let found = refusal.row(true);
        assert_eq!(
            (
                found.row,
                found.status,
                found.challenge,
                found.retry_after_s
            ),
            (row, status, challenge, retry),
            "{refusal:?}"
        );
        assert_eq!(
            found.dialect_status,
            matches!(refusal, Refusal::BudgetSpent { .. })
        );
        assert_eq!(
            found.allow.is_some(),
            matches!(refusal, Refusal::WrongMethod { .. })
        );
        // Before verification no plugin code runs: core writes every body.
        assert_eq!(refusal.row(false).by, BodyBy::Core, "{refusal:?}");
    }
    // A shed request is counted, not audited; every other row writes a record.
    assert!(!Refusal::GatewayFull.row(false).audited);
    assert!(!Refusal::Draining.row(false).audited);
    assert!(Refusal::Unverified { presented: true }.row(false).audited);
    // The recorded code differs; nothing on the wire does.
    assert_eq!(
        Refusal::Unverified { presented: false }.row(false).code,
        R_AUTH_REQUIRED
    );
    assert_eq!(
        Refusal::Unverified { presented: true }.row(false).code,
        R_BAD_CREDENTIAL
    );
}

/// The one 401 (gap G11, decision 12): identical bytes with and without a credential, on a route
/// and on none; a JSON body; `WWW-Authenticate` always.
#[test]
fn the_one_401() {
    let absent = core_answer::unverified(false, None);
    let wrong = core_answer::unverified(true, None);
    assert_eq!(absent, wrong);
    assert_eq!(absent.status, 401);
    assert_eq!(
        absent.fields,
        vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"www-authenticate".to_vec(), b"Bearer".to_vec()),
        ]
    );
    assert_eq!(
        absent.body,
        br#"{"error":{"code":"authentication_required","message":"authentication required"}}"#
    );
    // A body that does not match its signed digest is answered as any bad credential is.
    let digest = Refusal::DigestMismatch;
    assert_eq!(
        core_answer::answer(digest, &digest.row(false), "", None),
        absent
    );
    // A declared challenge changes that one header and nothing else.
    let declared = core_answer::unverified(
        false,
        Some(
            "Bearer resource_metadata=\"https://gw.example/.well-known/oauth-protected-resource/mcp\"",
        ),
    );
    assert_eq!(declared.status, absent.status);
    assert_eq!(declared.body, absent.body);
    assert_eq!(declared.fields[0], absent.fields[0]);
    assert_eq!(declared.fields[1].0, b"www-authenticate".to_vec());
    assert_ne!(declared.fields[1].1, absent.fields[1].1);
}

#[test]
fn core_answers_carry_their_headers_and_escape_their_text() {
    let full = Refusal::GatewayFull;
    let answer = core_answer::answer(full, &full.row(false), "", None);
    assert_eq!(answer.status, 503);
    assert!(answer
        .fields
        .contains(&(b"retry-after".to_vec(), b"1".to_vec())));
    let method = Refusal::WrongMethod {
        allow: METHOD_GET | METHOD_POST,
    };
    let answer = core_answer::answer(method, &method.row(true), "", None);
    assert_eq!(answer.status, 405);
    assert!(answer
        .fields
        .contains(&(b"allow".to_vec(), b"GET, POST".to_vec())));
    let window = Refusal::Window { retry_after_s: 12 };
    let answer = core_answer::answer(window, &window.row(true), "Rate limit \"x\"\n", None);
    assert!(answer
        .fields
        .contains(&(b"retry-after".to_vec(), b"12".to_vec())));
    assert_eq!(
        answer.body,
        br#"{"error":{"code":"rate_limited","message":"Rate limit \"x\"\n"}}"#
    );
    assert_eq!(
        core_answer::body("a", "\u{1}\\"),
        br#"{"error":{"code":"a","message":"\u0001\\"}}"#
    );
}

fn stated(class: RouteClass, who: Who, scope: Scope, money: Money) -> RouteRecord {
    RouteRecord {
        class,
        who,
        cred_header: None,
        challenge: None,
        scope,
        scope_stated: true,
        money,
        caller_state: CallerState::Shared,
    }
}

/// What refuses a plugin at load: one row per rule of design C5.
#[test]
fn the_record_rules() {
    use Money::{None as Free, Unit as Paid};
    use RecordRefused as R;
    use RouteClass as C;
    let all = reference_plane::METHODS;
    let no_render = PlaneMethods {
        render: false,
        ..all
    };
    let no_select = PlaneMethods {
        select_resources: false,
        ..all
    };
    let no_upstream = PlaneMethods {
        upstream: false,
        ..all
    };
    let key_or_ticket = Who::PRINCIPAL.with(Who::TICKET);
    #[rustfmt::skip]
    let rows: Vec<(RouteRecord, u32, PlaneMethods, RecordRefused)> = vec![
        (stated(C::Data, Who::PUBLIC.with(Who::PRINCIPAL), Scope::none(), Free), METHOD_GET, all, R::Who),
        (stated(C::Data, Who::OPTIONAL.with(Who::TICKET), Scope::none(), Free), METHOD_GET, all, R::Who),
        (stated(C::Data, Who::PUBLIC, Scope::walk("pool"), Free), METHOD_GET, all, R::OpenRouteCarriesScopeOrMoney),
        (stated(C::Data, Who::PUBLIC, Scope::none(), Paid), METHOD_GET, all, R::OpenRouteCarriesScopeOrMoney),
        (stated(C::Data, Who::OPTIONAL, Scope::none(), Paid), METHOD_GET, all, R::OpenRouteCarriesScopeOrMoney),
        (stated(C::Data, Who::SIGNED_INGRESS, Scope::selected(&["x"]), Free), METHOD_POST, all, R::OpenRouteCarriesScopeOrMoney),
        (stated(C::Catalog, Who::PRINCIPAL, Scope::none(), Free), METHOD_GET, all, R::Catalog),
        (stated(C::Catalog, Who::PRINCIPAL, Scope::walk("pool"), Paid), METHOD_GET, all, R::Catalog),
        (stated(C::Catalog, Who::PRINCIPAL, Scope::walk("pool"), Free), METHOD_GET, no_render, R::Catalog),
        (stated(C::Data, Who::PRINCIPAL, Scope::selected(&["tool"]), Paid), METHOD_POST, no_select, R::SelectedWithoutSelector),
        (stated(C::Data, Who::PRINCIPAL, Scope::walk("pool"), Paid), METHOD_POST, no_upstream, R::WalkWithoutUpstream),
        (stated(C::Data, Who::OPERATOR, Scope::none(), Free), METHOD_GET, all, R::OperatorAdmin),
        (stated(C::Admin, Who::PRINCIPAL, Scope::none(), Free), METHOD_GET, all, R::OperatorAdmin),
        (stated(C::Admin, Who::OPERATOR, Scope::none(), Paid), METHOD_GET, all, R::AdminCarriesScopeOrMoney),
        (stated(C::Upgrade, Who::PRINCIPAL, Scope::none(), Paid), METHOD_POST, all, R::UpgradeMethods),
        (stated(C::Upgrade, Who::PRINCIPAL, Scope::none(), Paid), METHOD_GET | METHOD_POST, all, R::UpgradeMethods),
        (stated(C::Recovery, key_or_ticket, Scope::none(), Paid), METHOD_GET, all, R::InternalAuth),
        (stated(C::Data, Who::PRINCIPAL, Scope::walk_and_selected("a", &["a"]), Paid), METHOD_POST, all, R::Kind("a".into())),
        (stated(C::Data, Who::PRINCIPAL, Scope::walk("Pool"), Paid), METHOD_POST, all, R::Kind("Pool".into())),
    ];
    for (record, methods, plane, refused) in rows {
        assert_eq!(record.validate(methods, plane), Err(refused), "{record:?}");
    }
    // Scope left out is refused; "none" said outright is a statement.
    let mut silent = stated(C::Data, Who::PRINCIPAL, Scope::none(), Paid);
    assert_eq!(silent.validate(METHOD_POST, all), Ok(()));
    silent.scope_stated = false;
    assert_eq!(silent.validate(METHOD_POST, all), Err(R::ScopeNotStated));
    // A challenge only where a 401 can be answered, and only a header value.
    let mut public = stated(C::Data, Who::PUBLIC, Scope::none(), Free);
    public.challenge = Some("Bearer".into());
    assert_eq!(public.validate(METHOD_GET, all), Err(R::Challenge));
    let mut broken = stated(C::Data, Who::PRINCIPAL, Scope::none(), Paid);
    broken.challenge = Some("Bearer\r\nx-injected: 1".into());
    assert_eq!(broken.validate(METHOD_POST, all), Err(R::Challenge));
    // Per-caller state needs a caller.
    let mut stateful = stated(C::Data, Who::PUBLIC, Scope::none(), Free);
    stateful.caller_state = CallerState::Distinct;
    assert_eq!(
        stateful.validate(METHOD_GET, all),
        Err(R::DistinctWithoutCaller)
    );
    // A credential header where there is a credential to read; lowercase.
    let mut header = stated(C::Data, Who::PUBLIC, Scope::none(), Free);
    header.cred_header = Some("authorization".into());
    assert_eq!(header.validate(METHOD_GET, all), Err(R::CredHeader));
    let mut upper = stated(C::Data, Who::PRINCIPAL, Scope::none(), Paid);
    upper.cred_header = Some("Authorization".into());
    assert_eq!(upper.validate(METHOD_POST, all), Err(R::CredHeader));
}

#[test]
fn a_challenge_is_resolved_once_at_mount() {
    let route = reference(Admission::Selected);
    assert_eq!(
        route.record.mounted_challenge(Some("https://gw.example/")),
        Ok(Some(
            "Bearer resource_metadata=\"https://gw.example/.well-known/reference\"".into()
        ))
    );
    assert_eq!(route.record.mounted_challenge(None), Err(()));
    let plain = reference(Admission::Walk);
    assert_eq!(plain.record.mounted_challenge(None), Ok(None));
}

/// A kind other than `pool` belongs to one image.
#[test]
fn a_scope_kind_has_one_owner() {
    let llm: [Box<str>; 1] = ["pool".into()];
    let mcp: [Box<str>; 2] = ["mcp_server".into(), "mcp_tool".into()];
    let streaming: [Box<str>; 1] = ["pool".into()];
    let thief: [Box<str>; 1] = ["mcp_tool".into()];
    let honest = [
        KindClaim {
            image: "plane-llm",
            kinds: &llm,
        },
        KindClaim {
            image: "plane-mcp",
            kinds: &mcp,
        },
        KindClaim {
            image: "plane-streaming",
            kinds: &streaming,
        },
    ];
    assert_eq!(contested_kind(&honest), None);
    let contested = [
        KindClaim {
            image: "plane-mcp",
            kinds: &mcp,
        },
        KindClaim {
            image: "plane-x",
            kinds: &thief,
        },
    ];
    assert_eq!(
        contested_kind(&contested),
        Some(("mcp_tool", "plane-mcp", "plane-x"))
    );
}

/// Not mounted (design C6): only for reasons that are the operator's configuration.
#[test]
fn what_is_not_mounted_and_why() {
    let everything = Offered {
        verifier_reads_header: true,
        chain_yields_shared: false,
        upgrade_transport: true,
        signature_verifier: true,
        challenge_unresolved: false,
    };
    for route in reference_plane::routes() {
        assert_eq!(
            mounted(&route.record, everything),
            Ok(route.admission),
            "{}",
            route.pattern
        );
    }
    let nothing = Offered {
        verifier_reads_header: false,
        chain_yields_shared: false,
        upgrade_transport: false,
        signature_verifier: false,
        challenge_unresolved: false,
    };
    let unread = Err(NotMounted::NoVerifierReadsItsHeader);
    let rows = [
        (Admission::Walk, unread),
        (Admission::Selected, unread),
        (Admission::PrincipalOnly, unread),
        (Admission::Catalog, unread),
        (Admission::Optional, unread),
        (Admission::Ticket, unread),
        (Admission::Upgrade, unread),
        (
            Admission::SignedIngress,
            Err(NotMounted::NoSignatureVerifier),
        ),
        // Nobody to verify, or the admin chain: mounted whatever the data chain is.
        (Admission::Public, Ok(Admission::Public)),
        (Admission::Operator, Ok(Admission::Operator)),
    ];
    for (admission, expected) in rows {
        assert_eq!(
            mounted(&reference(admission).record, nothing),
            expected,
            "{admission:?}"
        );
    }
    let open = Offered {
        chain_yields_shared: true,
        ..everything
    };
    assert_eq!(
        mounted(&reference(Admission::Selected).record, open),
        Err(NotMounted::DistinctCallersUnderAnOpenChain)
    );
    assert_eq!(
        mounted(&reference(Admission::Walk).record, open),
        Ok(Admission::Walk)
    );
    let no_socket = Offered {
        upgrade_transport: false,
        ..everything
    };
    assert_eq!(
        mounted(&reference(Admission::Upgrade).record, no_socket),
        Err(NotMounted::NoUpgradeTransport)
    );
    let no_url = Offered {
        challenge_unresolved: true,
        ..everything
    };
    assert_eq!(
        mounted(&reference(Admission::Selected).record, no_url),
        Err(NotMounted::NoPublicUrlForItsChallenge)
    );
    // An internal route is never on a listener.
    let recovery = RouteRecord {
        class: RouteClass::Recovery,
        ..reference(Admission::PrincipalOnly).record
    };
    assert_eq!(mounted(&recovery, everything), Err(NotMounted::Internal));
    assert_eq!(
        decide(Target::Route(&recovery), &passing(DISTINCT)),
        refused(Refusal::NoRoute, true)
    );
}

/// The record of an image that predates it: what today's five planes mean, written once.
#[test]
fn a_record_read_from_what_an_image_declares() {
    use busbar_plugin_abi::plane::{
        AUTH_OPERATOR, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS, AUTH_TICKET, ROUTE_ADMIN,
        ROUTE_CATALOG, ROUTE_UPGRADE,
    };
    use Admission as Ad;
    let none: [Box<str>; 0] = [];
    let tools: [Box<str>; 1] = ["mcp_tool".into()];
    let key_or_ticket = AUTH_PRINCIPAL | AUTH_TICKET;
    #[rustfmt::skip]
    let rows = [
        (0, AUTH_PRINCIPAL, &none[..], Some("pool"), false, Ad::Walk, Money::Unit),
        (0, AUTH_PRINCIPAL, &tools[..], Some("mcp_server"), true, Ad::Selected, Money::Unit),
        (0, AUTH_PRINCIPAL, &none[..], None, false, Ad::PrincipalOnly, Money::Unit),
        (ROUTE_CATALOG, AUTH_PRINCIPAL, &none[..], Some("pool"), false, Ad::Catalog, Money::None),
        (0, AUTH_PUBLIC, &none[..], Some("pool"), true, Ad::Public, Money::None),
        (0, key_or_ticket, &none[..], None, false, Ad::Ticket, Money::Unit),
        (0, AUTH_SIGNED_INGRESS, &none[..], Some("pool"), false, Ad::SignedIngress, Money::None),
        (ROUTE_UPGRADE, AUTH_PRINCIPAL, &none[..], Some("pool"), false, Ad::Upgrade, Money::Unit),
        (ROUTE_ADMIN, AUTH_OPERATOR, &none[..], Some("pool"), false, Ad::Operator, Money::None),
    ];
    for (flags, auth, kinds, walk, distinct, admission, money) in rows {
        let record = RouteRecord::from_declared(flags, auth, None, kinds, walk, distinct)
            .expect("a declared route has a class and callers");
        assert_eq!(admission_of(&record), admission, "{flags} {auth}");
        assert_eq!(record.money, money, "{flags} {auth}");
        let methods = if flags == 0 { METHOD_POST } else { METHOD_GET };
        assert_eq!(
            record.validate(methods, reference_plane::METHODS),
            Ok(()),
            "{flags} {auth}"
        );
    }
    assert_eq!(
        RouteRecord::from_declared(3, AUTH_PRINCIPAL, None, &none, None, false),
        None
    );
    assert_eq!(
        RouteRecord::from_declared(0, 0, None, &none, None, false),
        None
    );
}

/// The record on the wire: what a plane writes is what core reads, and a word outside the
/// vocabulary is no record.
#[test]
fn the_record_on_the_wire() {
    use crate::auth::route_record::wire::{
        decode_admission, encode_admission, AdmissionItem, CALLERS_DISTINCT, CALLERS_SHARED,
        MONEY_NONE, MONEY_UNIT, SCOPE_NONE, SCOPE_SELECTED, SCOPE_WALK,
    };
    use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, AUTH_PUBLIC, ROUTE_CATALOG};
    let none: [Box<str>; 0] = [];
    let tools: [Box<str>; 1] = ["mcp_tool".into()];
    let item = AdmissionItem {
        route: 2,
        scope: SCOPE_WALK | SCOPE_SELECTED,
        money: MONEY_UNIT,
        callers: CALLERS_DISTINCT,
        walk_kind: "mcp_server",
    };
    let body = encode_admission(&item);
    assert_eq!(body.len(), 16 + "mcp_server".len());
    assert_eq!(decode_admission(&body), Some(item));
    assert_eq!(decode_admission(&body[..15]), None);
    let record = RouteRecord::from_wire(0, AUTH_PRINCIPAL, None, &tools, &item, Some("Bearer"))
        .expect("a stated record");
    assert_eq!(admission_of(&record), Admission::Selected);
    assert_eq!(record.scope.walk.as_deref(), Some("mcp_server"));
    assert_eq!(record.caller_state, CallerState::Distinct);
    assert_eq!(record.money, Money::Unit);
    assert_eq!(record.challenge.as_deref(), Some("Bearer"));
    let stated = |scope, money, callers, walk_kind| AdmissionItem {
        route: 1,
        scope,
        money,
        callers,
        walk_kind,
    };
    let catalog = stated(SCOPE_WALK, MONEY_NONE, CALLERS_SHARED, "pool");
    let record = RouteRecord::from_wire(ROUTE_CATALOG, AUTH_PRINCIPAL, None, &none, &catalog, None)
        .expect("a stated record");
    assert_eq!(admission_of(&record), Admission::Catalog);
    let public = stated(SCOPE_NONE, MONEY_NONE, CALLERS_SHARED, "");
    let record = RouteRecord::from_wire(0, AUTH_PUBLIC, None, &none, &public, None)
        .expect("a stated record");
    assert_eq!(admission_of(&record), Admission::Public);
    assert!(record.scope_stated);
    #[rustfmt::skip]
    let broken = [
        stated(0, MONEY_UNIT, CALLERS_SHARED, ""),
        stated(SCOPE_NONE | SCOPE_WALK, MONEY_UNIT, CALLERS_SHARED, "pool"),
        stated(SCOPE_WALK, MONEY_UNIT, CALLERS_SHARED, ""),
        stated(SCOPE_NONE, MONEY_UNIT, CALLERS_SHARED, "pool"),
        stated(SCOPE_SELECTED, MONEY_UNIT, CALLERS_SHARED, ""),
        stated(SCOPE_NONE, 0, CALLERS_SHARED, ""),
        stated(SCOPE_NONE, MONEY_UNIT, 0, ""),
        stated(8, MONEY_UNIT, CALLERS_SHARED, ""),
    ];
    for item in broken {
        assert_eq!(
            RouteRecord::from_wire(0, AUTH_PRINCIPAL, None, &none, &item, None),
            None,
            "{item:?}"
        );
    }
}
