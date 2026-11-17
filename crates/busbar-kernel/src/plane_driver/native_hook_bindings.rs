// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure native hook assembly over already-opened ports and admitted descriptors.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::port_hooks::Call;
use crate::config::hooks::HookRegistry;
#[cfg(test)]
use crate::config::HookCfg;
use busbar_ports::hook::HookPort;

/// One S8-opened instance; `image` keys the frozen admitted word catalog.
pub struct OpenedHook {
    pub port: Arc<dyn HookPort>,
    pub image: Arc<str>,
    pub words: Vec<Box<str>>,
}

struct Calls<'a> {
    hooks: &'a HookRegistry,
    opened: &'a BTreeMap<String, OpenedHook>,
    words: &'a BTreeMap<String, Vec<Box<str>>>,
}

impl Calls<'_> {
    fn named(&self, _name: &str, _point: u32) -> Result<Arc<Call>, String> {
        Err("native hook construction is not implemented".into())
    }
    fn strategy(&self, _word: &str) -> Result<Arc<Call>, String> {
        Err("native strategy construction is not implemented".into())
    }
}

#[cfg(test)]
#[path = "native_hook_bindings/tests/construction.rs"]
mod tests;
