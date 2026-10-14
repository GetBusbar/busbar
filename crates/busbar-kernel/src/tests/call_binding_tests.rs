use super::Kernel;
use busbar_contract::caps::CallId;

#[test]
fn each_request_opens_a_distinct_generation() {
    // #74: the loop bumps one generation per unit, so no two requests share one.
    let kernel = Kernel::new();
    let a = kernel.next_call();
    let b = kernel.next_call();
    assert_ne!(a.get(), b.get(), "two requests must not share a generation");
    assert_ne!(a, CallId::UNBOUND);
    assert_ne!(b, CallId::UNBOUND);
}

#[test]
fn a_door_grant_bound_to_one_call_is_rejected_in_another() {
    // The money door is the sharpest case: an admittance grant minted for call A must not open a
    // hold under call B. RED BEFORE GREEN: with an unbound mint (the plain `admit_token`) the
    // second assertion below would fail, because an unbound grant matches nothing but also the
    // bound one would match every call.
    let kernel = Kernel::new();
    let call_a = kernel.next_call();
    let call_b = kernel.next_call();
    let door = kernel.admit_token_for(call_a);
    assert!(door.bound_to(call_a), "a grant must match its own call");
    assert!(
        !door.bound_to(call_b),
        "a grant from call A must be rejected in call B"
    );
}

fn unit() -> super::UnitCtx {
    super::UnitCtx {
        call: CallId::UNBOUND,
        key: busbar_contract::caps::UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: crate::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// RED (#74, THE STAGE'S COMPARE): a unit entering the loop unbound is bound to a fresh call, and
/// one already bound keeps its own. A pass minted for another call is not presented at the unit's
/// stage, nor is an unbound one; the unit's own pass is. Without the compare, a pass of call A
/// would be handed to call B's Route stage as B's.
#[test]
fn a_pass_of_another_call_is_not_presented_at_the_stage() {
    use busbar_contract::caps::{Pass, Route};
    let kernel = Kernel::new();
    let ctx = super::bound(&kernel, &unit());
    assert_ne!(ctx.call, CallId::UNBOUND, "the loop left the unit unbound");
    assert_eq!(
        super::bound(&kernel, &ctx).call,
        ctx.call,
        "a bound unit was re-bound"
    );
    let other = kernel.next_call();
    let seal = &kernel.seal;
    assert!(super::presented(
        &Pass::<Route>::mint_bound(seal, ctx.call),
        &ctx
    ));
    assert!(
        !super::presented(&Pass::<Route>::mint_bound(seal, other), &ctx),
        "a pass of another call was presented as this unit's"
    );
    assert!(
        !super::presented(&Pass::<Route>::mint(seal), &ctx),
        "an unbound pass was presented as this unit's"
    );
}
