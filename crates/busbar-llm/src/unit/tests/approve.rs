//! Tests for `approve.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_caps::{KernelSeal, StepName};

struct Always;
impl VetoSeat for Always {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        true
    }
}

struct Never;
impl VetoSeat for Never {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        false
    }
}

/// A seat that records whether it was asked, so "the first veto wins" can be checked as a fact
/// about who was CONSULTED rather than only about the answer returned.
struct Recording(std::cell::Cell<bool>);
impl VetoSeat for Recording {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        self.0.set(true);
        false
    }
}

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

fn caller() -> PrincipalId {
    PrincipalId::new("vk_live_key")
}

/// IDENTITY WITH THE LIVE PATH. Today nothing is seated at Approve — the migrated hooks fire
/// after the door — so the step must be a no-op for every input: same unit in, same unit on to
/// the door, nothing refused and no resource locator invented. This is the whole of the parity
/// claim for this step, and it is one assertion because there is one behaviour.
#[test]
fn with_no_seat_installed_the_step_is_a_no_op_exactly_as_the_live_path_is() {
    let seal = seal();
    let facts = approve(
        &UnitToken::<Approve>::mint(&seal),
        &caller(),
        &[],
        &[], // today's deployment: nothing is seated here
    )
    .into_result(&seal)
    .expect("nothing is seated, so nothing can refuse");
    assert_eq!(facts, ScopeFacts::default());
    assert!(
        facts.resources.as_slice().is_empty(),
        "the LLM plane's resource is its destination, sealed at verify"
    );
}

/// A seat that abstains changes nothing either — a gate is consulted, not obeyed by default.
#[test]
fn a_seat_that_abstains_leaves_the_unit_exactly_as_it_found_it() {
    let seal = seal();
    let never = Never;
    let seats: [&dyn VetoSeat; 1] = [&never];
    let facts = approve(&UnitToken::<Approve>::mint(&seal), &caller(), &[], &seats)
        .into_result(&seal)
        .expect("an abstaining gate refuses nothing");
    assert_eq!(facts, ScopeFacts::default());
}

/// A veto stops the unit HERE — before the door, so nothing is charged — and it is recorded
/// under the one reason a veto may carry.
#[test]
fn a_veto_refuses_at_approve_which_is_before_the_door() {
    let seal = seal();
    let always = Always;
    let seats: [&dyn VetoSeat; 1] = [&always];
    let refusal = approve(&UnitToken::<Approve>::mint(&seal), &caller(), &[], &seats)
        .into_result(&seal)
        .expect_err("the seat vetoed");
    assert_eq!(refusal.reason(), ReasonCode::HookVeto);
    assert_eq!(refusal.step(), Some(StepName::Approve));
    assert!(
        !refusal.under_hold(),
        "a veto at approve is raised before the door, so nothing was charged"
    );
}

/// THE FIRST VETO WINS, and a gate after it is not consulted at all: a refused unit's facts are
/// not handed to something with no decision left to make.
#[test]
fn the_first_veto_wins_and_nothing_after_it_is_consulted() {
    let seal = seal();
    let always = Always;
    let after = Recording(std::cell::Cell::new(false));
    let seats: [&dyn VetoSeat; 2] = [&always, &after];
    let refusal = approve(&UnitToken::<Approve>::mint(&seal), &caller(), &[], &seats)
        .into_result(&seal)
        .expect_err("the first seat vetoed");
    assert_eq!(refusal.reason(), ReasonCode::HookVeto);
    assert!(!after.0.get(), "the seat after the veto was never asked");
}

/// A gate seated BEFORE a vetoing one is consulted, so "first" means first in the caller's
/// order rather than "any".
#[test]
fn a_seat_before_the_vetoing_one_is_consulted() {
    let seal = seal();
    let before = Recording(std::cell::Cell::new(false));
    let always = Always;
    let seats: [&dyn VetoSeat; 2] = [&before, &always];
    let _ = approve(&UnitToken::<Approve>::mint(&seal), &caller(), &[], &seats)
        .into_result(&seal)
        .expect_err("the second seat vetoed");
    assert!(before.0.get(), "the seat before the veto was asked");
}

/// THE CLOSED REFUSAL SET IS ONE. Approve on this plane raises `HookVeto` and nothing else: the
/// scope half has no closed lookup to fail against here (see the module docs), so a
/// `ScopeDenied` from this step would be a permission answer with no table behind it.
#[test]
fn the_closed_refusal_set_is_exactly_the_veto() {
    let seal = seal();
    let always = Always;
    for seats in [
        Vec::<&dyn VetoSeat>::new(),
        vec![&always as &dyn VetoSeat],
        vec![&always as &dyn VetoSeat, &always as &dyn VetoSeat],
    ] {
        let d = approve(&UnitToken::<Approve>::mint(&seal), &caller(), &[], &seats);
        if let Err(refusal) = d.into_result(&seal) {
            assert_eq!(refusal.reason(), ReasonCode::HookVeto);
        }
    }
}
