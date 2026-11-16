// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store suite body (IF §14). Owned by the store agent: this is the only file it edits (plus the `tests/`
//! cases that call it). Drive the plugin with [`super::harness::Harness`].

use busbar_plugin_abi::plugin::Plugin;

use crate::fake_needs::FakeNeeds;

pub(super) fn run(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    let _ = (plugin, config, needs);
    todo!("suites (store): the per-kind body, over suites::harness::Harness")
}
