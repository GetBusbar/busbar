use super::*;

#[test]
fn decl_names_the_ruled_verb_and_key() {
    assert_eq!(PLANE_DECL.key, "decision");
    assert_eq!(PLANE_DECL.config_section, "decisions");
    const { assert!(!PLANE_DECL.fallback) };
    assert_eq!(PLANE_DECL.scope_kinds, &["decision_provider"]);
}

#[test]
fn decl_declares_the_jev_dialect() {
    assert_eq!((PLANE_DECL.wire_format_names)(), &["jev"]);
}

#[test]
fn decl_owns_no_config_section_yet_stage_one_contract() {
    assert!(PLANE_DECL.owned_config_sections.is_empty());
    assert!(PLANE_DECL.resolve_provider.is_none());
}

#[test]
fn decl_builds_no_runtime_slot_yet() {
    // Nothing wires a `BuildCtx` for this plane yet (see the module doc): `build` answers `None`
    // honestly rather than panicking or downcasting a slot that can never arrive. This is checked
    // with a real `BuildCtx` value from the substrate crate so a future field addition that makes
    // this constructible does not silently drift the constant it is built from.
    let nothing: &dyn std::any::Any = &();
    let ctx = busbar_kernel::plane::registry::BuildCtx {
        endpoint_slot: None,
        agent_defs: nothing,
        public_url: None,
        prior: None,
    };
    assert!((PLANE_DECL.build)(&ctx).is_none());
}
