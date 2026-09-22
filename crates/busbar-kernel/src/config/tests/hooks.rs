//! Tests for `hooks.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// Binding: a migrated hook's `on_error` defaults to `nothing` — a failing or timed-out gate
/// does not participate in the decision (it cannot steer, it cannot displace another gate's
/// verdict) rather than the request being refused. `on_failure: closed` is a 1.6.0-native-only
/// knob and plays no part in this default.
#[test]
fn the_serde_default_is_nothing() {
    assert_eq!(default_on_error(), ON_ERROR_NOTHING);
}

/// `nothing` and `weighted` resolve to the SAME terminal — "didn't participate" and "busbar's
/// normal ordering" are the same behavior — so a migrated gate that fails or times out under
/// the default takes exactly the non-participating path a `weighted` gate would.
#[test]
fn nothing_resolves_to_the_same_terminal_as_weighted() {
    assert_eq!(
        on_error_terminal(ON_ERROR_NOTHING),
        on_error_terminal(ON_ERROR_WEIGHTED)
    );
    assert_eq!(
        on_error_terminal(ON_ERROR_NOTHING),
        Some(PolicyOnError::Weighted)
    );
}

/// The reserved terminals stay distinct from `nothing`: only `reject` refuses on error.
#[test]
fn reject_is_not_the_default_terminal() {
    assert_ne!(
        on_error_terminal(ON_ERROR_REJECT),
        on_error_terminal(ON_ERROR_NOTHING)
    );
}
