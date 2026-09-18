// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK-VETO SEAT — the operator hook-gate half of the APPROVE step.
//!
//! [`crate::approve`] answers "does the principal hold enough scope"; this answers the OTHER half of
//! the same step: "did an operator hook say no anyway". The design keeps the two apart on purpose —
//! the scope check is a pure comparison against a policy table, and a veto is an operator's own
//! runtime opinion — and it composes them in one fixed way:
//!
//! - **The scope check runs FIRST.** A veto is consulted after it, never instead of it, so the
//!   record always carries whichever refusal the earlier gate would have raised had the later one
//!   stayed silent.
//! - **A veto WINS regardless of what the scope check returned.** A hook that vetoes turns an
//!   otherwise-approving scope answer into a refusal, and its reason is the one reported even when
//!   the scope check would itself have refused — an operator who wired a veto seat asked to be the
//!   last word, and a veto buried under a scope refusal it agrees with is a seat the operator cannot
//!   tell fired.
//! - **The FIRST veto at any seat wins.** Seats are consulted in the order the operator declared
//!   them, and the first that vetoes ends the walk. A later seat's veto is never reached, so the
//!   reason an operator reads is stable: it does not flap with which seat happened to be evaluated
//!   first or which looked worst.
//!
//! ## Why the seat is HERE and the hook machinery is not
//!
//! This crate depends on no hook registry, no store and no plane host, and it still must not — the
//! whole point of a pure APPROVE crate is that it can be proven on its own. So a seat supplies its
//! own already-evaluated answer through [`HookGate::veto`]: the machinery that ran the hook, read its
//! facts and decided lives in the plane host, and what reaches here is only the VERDICT. That is the
//! same shape [`crate::PolicyView`] has for the scope table — a trait the composition root binds,
//! never a table this crate owns — so the veto seat and the scope lookup compose without either
//! dragging the hook seat machinery or the policy store into this crate.

use busbar_caps::ReasonCode;

use crate::Refused;

/// A veto raised by one hook seat.
///
/// It carries the seat's own name and an operator-facing detail so a refused principal's record can
/// say WHICH hook stopped it and WHY, not merely that "a hook did". The [`reason`](Veto::reason) is
/// the closed-vocabulary [`ReasonCode::HookVeto`], the same word the journal and every dialect
/// renderer already spell a veto with, so a veto raised here is indistinguishable from one raised at
/// any other seat once it reaches the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Veto {
    /// The hook seat's configured name — an operator's own label, so it is owned rather than a
    /// `&'static str`: a hook is named in config, not in this crate's source.
    pub seat: String,
    /// The operator-facing detail, verbatim. Rendered beside the seat name so "which hook, and what
    /// did it object to" is answerable from the record alone.
    pub detail: String,
}

impl Veto {
    /// Raise a veto from `seat` carrying `detail`.
    pub fn new(seat: impl Into<String>, detail: impl Into<String>) -> Self {
        Veto {
            seat: seat.into(),
            detail: detail.into(),
        }
    }

    /// The closed-vocabulary reason a veto is recorded under — always [`ReasonCode::HookVeto`].
    ///
    /// Named through the kernel's own vocabulary rather than a string of this seat's, so a veto here
    /// and a veto raised at any other seat in the loop are the same reason to everything that reads
    /// the record.
    #[must_use]
    pub fn reason(&self) -> ReasonCode {
        ReasonCode::HookVeto
    }
}

/// ONE HOOK SEAT, as the gate sees it: a thing that either vetoes or stays silent.
///
/// The trait is deliberately this small. Whatever the operator's hook actually reads — the request,
/// the principal's facts, the resource it named — has already been read by the plane host by the
/// time a seat is asked here; this crate is handed the VERDICT and nothing that produced it. A seat
/// that returns `None` did not object, which is not the same as approving: approval is the scope
/// check's word, and a silent seat merely declines to overrule it.
pub trait HookGate {
    /// This seat's verdict for the unit under judgement: `Some(veto)` to stop it, `None` to stay
    /// silent and let the earlier scope answer stand.
    fn veto(&self) -> Option<Veto>;
}

/// THE COMPOSED VERDICT of the APPROVE step: the scope answer and the hook seats, resolved into one
/// outcome.
///
/// `Refused` is the SCOPE refusal ([`crate::Refused`]) and `Vetoed` is a HOOK's — kept apart rather
/// than collapsed into one refusal, because they carry different reasons on the wire and an operator
/// diagnosing a stopped principal needs to know which of the two gates closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// The scope check passed and no seat vetoed.
    Approved,
    /// The scope check refused and no seat vetoed — the scope refusal stands.
    Refused(Refused),
    /// A hook seat vetoed. This is the answer whether or not the scope check itself would have
    /// refused, and it is the FIRST vetoing seat's in declaration order.
    Vetoed(Veto),
}

/// COMPOSE the scope answer with the hook seats, in the design's fixed order.
///
/// `scope` is the result of [`crate::approve`] (or of any equivalent policy-scope comparison the
/// caller ran first), and `seats` are the operator's veto seats in the order they were declared. The
/// scope answer is computed BEFORE the seats are walked, so it is the refusal the record carries if
/// no seat objects; the first seat that vetoes then WINS regardless of that answer.
///
/// A veto overriding an approving scope answer is the whole reason the seat exists; a veto
/// overriding a REFUSING one is the subtler case the ordering also settles — the operator's seat is
/// the last word, so its reason is the one reported even when the scope gate would have refused too.
#[must_use]
pub fn gate(scope: Result<(), Refused>, seats: &[&dyn HookGate]) -> Approval {
    // The first veto at any seat wins, so the walk stops at it — a later seat's veto is never
    // reached and the reason an operator reads does not depend on evaluation order past the first.
    for seat in seats {
        if let Some(veto) = seat.veto() {
            return Approval::Vetoed(veto);
        }
    }
    match scope {
        Ok(()) => Approval::Approved,
        Err(refused) => Approval::Refused(refused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Grants, Scope};

    /// A seat with a fixed verdict, for stating a gate as data.
    struct Seat(Option<Veto>);
    impl HookGate for Seat {
        fn veto(&self) -> Option<Veto> {
            self.0.clone()
        }
    }

    fn silent() -> Seat {
        Seat(None)
    }
    fn vetoing(seat: &str) -> Seat {
        Seat(Some(Veto::new(seat, format!("{seat} objected"))))
    }

    /// Scope passes and no seat objects: approved.
    #[test]
    fn scope_pass_no_veto_is_approved() {
        let s = crate::approve(Grants::of(Scope::Full), Scope::Full);
        let seats = [&silent() as &dyn HookGate, &silent()];
        assert_eq!(gate(s, &seats), Approval::Approved);
        // No seats at all is the same as every seat silent.
        assert_eq!(gate(s, &[]), Approval::Approved);
    }

    /// Scope refuses and no seat objects: the SCOPE refusal stands, unchanged.
    #[test]
    fn scope_refuse_no_veto_keeps_the_scope_refusal() {
        let s = crate::approve(Grants::of(Scope::ReadOnly), Scope::Full);
        assert_eq!(
            gate(s, &[&silent() as &dyn HookGate]),
            Approval::Refused(Refused::InsufficientScope {
                needed: Scope::Full
            })
        );
    }

    /// A veto turns an APPROVING scope answer into a refusal — the reason the seat exists.
    #[test]
    fn a_veto_overrides_a_scope_pass() {
        let s = crate::approve(Grants::of(Scope::Full), Scope::Full);
        assert_eq!(
            gate(s, &[&vetoing("data-residency") as &dyn HookGate]),
            Approval::Vetoed(Veto::new("data-residency", "data-residency objected"))
        );
    }

    /// A veto WINS even when the scope check would itself have refused — the operator's seat is the
    /// last word, and its reason is the one reported.
    #[test]
    fn a_veto_wins_over_a_scope_refusal() {
        let s = crate::approve(Grants::of(Scope::ReadOnly), Scope::Full);
        match gate(s, &[&vetoing("kill-switch") as &dyn HookGate]) {
            Approval::Vetoed(v) => {
                assert_eq!(v.seat, "kill-switch");
                assert_eq!(v.reason(), ReasonCode::HookVeto);
            }
            other => panic!("a veto must win over a scope refusal, got {other:?}"),
        }
    }

    /// The FIRST veto in declaration order wins; a later seat's veto is never reached.
    #[test]
    fn the_first_veto_in_order_wins() {
        let s = crate::approve(Grants::of(Scope::Full), Scope::Full);
        let first = vetoing("first");
        let second = vetoing("second");
        let seats = [&silent() as &dyn HookGate, &first, &second];
        match gate(s, &seats) {
            Approval::Vetoed(v) => assert_eq!(v.seat, "first"),
            other => panic!("the first veto must win, got {other:?}"),
        }
    }
}
