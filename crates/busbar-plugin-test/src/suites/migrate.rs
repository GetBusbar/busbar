// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migrate suite body (IF §14). Owned by the migrate agent: this is the only file it edits (plus the `tests/`
//! cases that call it). Drive the plugin with [`super::harness::Harness`].

use busbar_plugin_abi::plugin::Plugin;

use super::MigrateExpect;
use crate::fake_needs::FakeNeeds;

pub(super) fn run(
    plugin: &'static Plugin,
    bag: &[u8],
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
) {
    let _ = (plugin, bag, needs, expect);
    todo!("suites (migrate): the per-kind body, over suites::harness::Harness")
}
