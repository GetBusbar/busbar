// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret suite body (IF §14). Owned by the secret agent: this is the only file it edits (plus the `tests/`
//! cases that call it). Drive the plugin with [`super::harness::Harness`].

use busbar_plugin_abi::plugin::Plugin;

use crate::fake_needs::FakeNeeds;

pub(super) fn run(
    plugin: &'static Plugin,
    config: &[u8],
    needs: FakeNeeds,
    known: &[(&[u8], &[u8])],
) {
    let _ = (plugin, config, needs, known);
    todo!("suites (secret): the per-kind body, over suites::harness::Harness")
}
