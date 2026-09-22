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
