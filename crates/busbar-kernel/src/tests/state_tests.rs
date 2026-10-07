// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `App`'s field docs sit on the fields they describe (item 565).

const STATE_SRC: &str = include_str!("../state.rs");

/// The `///` block rustdoc attaches to the field declared on the line starting with `field`.
fn doc_of(field: &str) -> String {
    let lines: Vec<&str> = STATE_SRC.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with(field))
        .unwrap_or_else(|| panic!("state.rs declares `{field}`"));
    let mut doc: Vec<&str> = lines[..at]
        .iter()
        .rev()
        .map(|l| l.trim_start())
        .take_while(|l| l.starts_with("///"))
        .map(|l| l.trim_start_matches("///").trim())
        .collect();
    doc.reverse();
    doc.join(" ")
}

/// The hooks REGISTRY and the hooks plugin ENVIRONMENT are two different things, and the registry's
/// doc exists to say which one it is ("distinct from the RESOLVED transports"). Run together, both
/// blocks bound to `hook_env` and the registry — read by the admin hooks surface — documented nothing.
#[test]
fn the_hook_registry_and_the_hook_env_each_carry_their_own_doc() {
    let registry = doc_of("pub hook_registry:");
    assert!(
        registry.starts_with("The raw `hooks:` registry"),
        "hook_registry is undocumented or carries another field's doc: {registry:?}"
    );
    let env = doc_of("pub hook_env:");
    assert!(
        env.starts_with("The plugin-resolution environment for hooks"),
        "{env}"
    );
    assert!(
        !env.contains("registry (name → definition)"),
        "hook_env's doc opens by describing the registry: {env}"
    );
}

/// Item 562: `App` carries no client-settings snapshot. The warm-pool reuse decision it was the
/// input to moved IN-PLANE with the client build (busbar-llm `build_runtime` compares its own
/// `ClientSettingsInput`), so a core copy is a value written on every build and read by nothing —
/// and a rule wired through it ("rebuild so a changed timeout takes effect") would be wired through
/// a value nothing consults.
#[test]
fn app_carries_no_client_settings_nothing_reads() {
    assert!(!STATE_SRC.contains("pub client_settings:"));
    assert!(!STATE_SRC.contains("pub struct UpstreamClientSettings"));
}
