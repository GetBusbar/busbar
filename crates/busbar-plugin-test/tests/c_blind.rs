// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-BLIND (ABI-MIN3-INTERFACE §14): No other plugin's identity reaches a plugin, and a stamp name appears only
//! inside `plugin_diag` (round 34). The fixtures fail and log with declared ERROR numbers.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L2"]
fn no_stamp_name_reaches_a_config_view_or_need_result() {
    todo!("owner: W1-L2 (C-BLIND)")
}

#[test]
#[ignore = "owner: W1-K8C"]
fn no_stamp_name_reaches_a_deliver_batch_or_render_snapshot() {
    todo!("owner: W1-K8C (C-BLIND)")
}

/// Round 34: a stamp name appears only inside `plugin_diag` (the code core wrote beside the text); the plugin's
/// raw text member carries no stamp name, and a plugin that writes a `BUSBAR-...` itself is not rewritten.
#[test]
fn a_stamp_name_appears_only_inside_plugin_diag() {
    use busbar_kernel::plugin_text::PluginText;
    use busbar_plugin_loader::instance::PluginCode;

    let code = PluginCode {
        plugin: "acme-auth",
        number: 42,
    };
    let shown = PluginText::new(Some(code), "the directory refused the bind");
    assert!(!shown.text().contains("acme-auth"));
    assert_eq!(
        shown.code.map(|c| c.to_string()).as_deref(),
        Some("BUSBAR-acme-auth-0042")
    );
    assert_eq!(
        shown.to_string(),
        "BUSBAR-acme-auth-0042: the directory refused the bind"
    );
    let own = PluginText::new(None, "BUSBAR-other-0001 is mine");
    assert_eq!(own.text(), "BUSBAR-other-0001 is mine");
    assert_eq!(own.to_string(), own.text());
}
