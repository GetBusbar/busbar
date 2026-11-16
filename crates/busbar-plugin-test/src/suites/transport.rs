// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport suite body (IF §14). Owned by the transport agent: this is the only file it edits (plus the
//! `tests/` cases that call it). Drive the plugin with [`super::harness::Harness`].

use super::TransportCase;
use busbar_plugin_abi::plugin::Plugin;

pub(super) fn run(plugin: &'static Plugin, config: &[u8], cases: &[TransportCase<'_>]) {
    let _ = (plugin, config, cases);
    todo!("suites (transport): the per-kind body, over suites::harness::Harness")
}
