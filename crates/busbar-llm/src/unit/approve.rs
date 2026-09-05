// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEP 3 — WHETHER THE CALLER MAY DO THIS AT ALL.
//!
//! Approve is two halves. The scope half is the required scope for a `(claim, op class)` pair,
//! compared against what the principal holds; the hook half is the facts the seats produce, where
//! the first veto at any seat wins. On the LLM plane, today, the first half has nothing to ask and
//! the second half has nothing seated. This file says so, and says why, rather than leaving a step
//! that looks unimplemented.
//!
//! ## Why the scope half is silent here
//!
//! The scope unit's lookup that is CLOSED today is the admin matrix — a method-and-path table
//! answering for operations under the frozen admin prefix. The LLM plane mounts nothing under it: a
//! `/v1/chat/completions` is not an admin operation, has no row in that table, and the scope word
//! it would be compared against does not exist for it. What DOES gate an LLM caller's access to a
//! pool is the key's allow-list, and that is not a scope comparison — it is the verify step's first
//! guard, one step earlier, refusing with its own reason and its own status. Asking a second,
//! differently-shaped permission question here would be two doors for one condition.
//!
//! So the plane's contribution to the scope half is the resource locators, and the LLM plane names
//! none: its resource IS its destination, and the destination set was sealed at verify. `ScopeFacts`
//! with no resources is the accurate answer, not a placeholder.
//!
//! ## Why the hook half carries only the native seat
//!
//! The migrated hooks fire AFTER the door on the live path — the request-log and completion taps run
//! around admission and around the response, never before it. A hook that fires after Admit cannot
//! veto at Approve, because by the time it runs the unit is already admitted and charged. Seating
//! them here would move a veto from after a charge to before one, which changes what is billed; that
//! is a behaviour change wearing a refactor's clothes, and this step does not make it.
//!
//! What this step carries is therefore exactly one seat: the 1.6.0-native [`VetoSeat`], which
//! nothing installs today. With no seat installed the step is a no-op that always proceeds — which
//! is the same unit-for-unit behaviour as the live path, and is the property the tests below pin.
//! When a native gate is seated, the first veto wins and the unit stops here, BEFORE the door, which
//! is the whole point of having the seat at this step rather than the next one.

use busbar_caps::{
    Approve, Decision, PrincipalId, ReasonCode, Refusal, ScopeFacts, UnitToken, VerifiedDestination,
};

/// A 1.6.0-native gate seated at Approve.
///
/// One method, returning nothing but "stop" or silence: a gate at this seat may veto and may do
/// nothing else. It cannot narrow the destination set — that set was sealed at verify and a gate
/// that could re-open it could widen it — and it cannot rewrite the request, because a step that
/// rewrites is a step that has to be metered.
///
/// The veto is a bare "no" rather than a reason of the gate's choosing, because the reason a unit
/// ended is a CLOSED vocabulary and a hook is not entitled to add to it. Every veto at this seat is
/// recorded as one reason, so the record cannot be made to say something a reader has no definition
/// for.
pub trait VetoSeat {
    /// Whether this gate stops the unit. `true` is a veto.
    ///
    /// It is handed what the step knows and no more: who is calling, and where the unit was cleared
    /// to go. Not the body, not the credential, not the hold — a gate that could read the body would
    /// be a step, and a gate that could read the hold would be the door.
    fn vetoes(&self, principal: &PrincipalId, destinations: &[VerifiedDestination]) -> bool;
}

/// Whether the caller may do this at all.
///
/// `seats` is the ordered list of native gates. It is empty on every deployment today, and an empty
/// list is not a special case: the fold below simply finds nothing, which is why the no-op path and
/// the vetoing path are one expression rather than two.
///
/// THE FIRST VETO WINS, and order is the caller's. A gate that vetoes stops the walk, so a later
/// gate is not consulted about a unit that has already been refused — consulting it would hand a
/// refused unit's facts to something that has no decision left to make.
pub fn approve(
    token: &UnitToken<Approve>,
    principal: &PrincipalId,
    destinations: &[VerifiedDestination],
    seats: &[&dyn VetoSeat],
) -> Decision<Approve> {
    match seats.iter().position(|s| s.vetoes(principal, destinations)) {
        Some(at) => {
            // The operator's diagnostic names WHICH seat stopped it, because "a hook vetoed" without
            // a position is unactionable on a deployment with more than one seated.
            tracing::info!(
                principal = %principal,
                seat = at,
                "approve: a seated gate vetoed the unit before the door"
            );
            Decision::refuse(token, Refusal::new(ReasonCode::HookVeto))
        }
        // The LLM plane names no resource locators: its resource is its destination, and the
        // destination set was sealed one step earlier.
        None => Decision::proceed(token, ScopeFacts::default()),
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(refusal.step(), StepName::Approve);
        assert!(
            !refusal.step().under_hold(),
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
}
