use super::*;

#[test]
fn the_serde_default_is_nothing() {
    assert_eq!(default_on_error(), ON_ERROR_NOTHING);
}

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

#[test]
fn reject_is_not_the_default_terminal() {
    assert_ne!(
        on_error_terminal(ON_ERROR_REJECT),
        on_error_terminal(ON_ERROR_NOTHING)
    );
}
