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
