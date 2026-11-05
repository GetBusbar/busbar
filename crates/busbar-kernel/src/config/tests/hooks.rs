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

#[test]
fn runtime_hook_config_accepts_only_canonical_module_and_phase() {
    use crate::config::{HookCfg, HookStage, CORE_HOOK_PHASES};
    let canonical: HookCfg =
        serde_json::from_str(r#"{"kind":"tap","module":"observer","phase":["response"]}"#).unwrap();
    assert_eq!(canonical.resolved_stages(), vec![HookStage::Response]);
    assert!(!canonical.fires_at_stage(HookStage::Request));
    for text in [
        r#"{"kind":"tap","plugin":"observer"}"#,
        r#"{"kind":"tap","module":"observer","at":"response"}"#,
    ] {
        assert!(serde_json::from_str::<HookCfg>(text).is_err(), "{text}");
    }
    let default: HookCfg = serde_json::from_str(r#"{"kind":"tap","module":"observer"}"#).unwrap();
    assert_eq!(default.resolved_stages(), CORE_HOOK_PHASES);
}
