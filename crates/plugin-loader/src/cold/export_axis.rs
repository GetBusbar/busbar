// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::export_axis`.

use std::sync::Arc;

use busbar_contract::route::Route;
use busbar_contract::secure::SecureVec;

use crate::dispatch::kinds::export::ExportFacts;
use crate::export_axis::NO_DOOR;
use crate::registry::{RowRefusal, SkippedPlugin};
use crate::PluginRegistry;

const SECTION: &str = busbar_contract::plugin::Kind::Export.root();

/// An export instance's label, named when config loads it.
#[cold]
pub(crate) fn label(instance: &str) -> String {
    format!("{SECTION}.{instance}")
}

/// Boot: a loaded export instance keeps its label.
#[cold]
pub(crate) fn instance(label: &str) -> Arc<str> {
    Arc::from(label)
}

/// Boot: names the export plugin that did not load.
#[cold]
pub(crate) fn load_refused(name: &str, e: RowRefusal) -> String {
    match e {
        RowRefusal::Stated(e) | RowRefusal::Bind(e) => e,
        RowRefusal::NoDoor => format!("export plugin '{name}': {NO_DOOR}"),
        RowRefusal::Load(e) => format!("export plugin '{name}': {e}"),
    }
}

/// Config: an export probe's or check's settings did not render.
#[cold]
pub(crate) fn settings_unrendered(error: &serde_json::Error) -> Vec<String> {
    vec![error.to_string()]
}

/// Config: lists the export modules config may name: every export row, linked or dropped in, by
/// its alias, once, in registration order (the linked rows lead).
#[cold]
pub(crate) fn linked_modules(registry: &PluginRegistry) -> Vec<String> {
    let mut modules: Vec<String> = Vec::new();
    for p in registry
        .linked()
        .iter()
        .chain(registry.loadable())
        .filter(|p| p.manifest.kind == SECTION)
    {
        if !modules.contains(&p.manifest.alias) {
            modules.push(p.manifest.alias.clone());
        }
    }
    modules
}

/// Config: an export module's routes, read when config names it.
#[cold]
pub(crate) fn routes(facts: &ExportFacts) -> Vec<Route> {
    facts.routes.clone()
}

/// Config: an export module's public routes, read when config names it.
#[cold]
pub(crate) fn public_routes(facts: &ExportFacts) -> Vec<String> {
    facts.public_routes.clone()
}

/// Config: an export module's persistent routes, read when config names it.
#[cold]
pub(crate) fn persistent_routes(facts: &ExportFacts) -> Vec<String> {
    facts.persistent_routes.clone()
}

/// Config: an export check with no instances checks the empty settings.
#[cold]
pub(crate) fn empty_candidate(module: &str) -> [(String, SecureVec); 1] {
    [(module.to_string(), SecureVec::from(&b"{}"[..]))]
}

/// Config: names the export module a check could not run, or whose check failed.
#[cold]
pub(crate) fn check_refused(module: &str, why: &str) -> Vec<String> {
    vec![format!("export `module: {module}`: {why}")]
}

/// Boot: names a configured export module that did not load.
#[cold]
pub(crate) fn module_unloaded(module: &str, skipped: Option<&SkippedPlugin>) -> String {
    match skipped {
        Some(s) => format!(
            "export plugin '{module}' is present ({}) but was not loaded: {}",
            s.file, s.reason
        ),
        None => format!("no `kind: export` plugin answers to '{module}'"),
    }
}
