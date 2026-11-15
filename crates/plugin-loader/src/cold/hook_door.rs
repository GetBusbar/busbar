// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::hook_door`: refusal text, and the names, routes and candidate lookups a
//! hook instance takes at boot and config time.

use std::sync::Arc;

use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::plugin_settings::ResolvedSettings;

use crate::boot::Candidate;
use crate::dispatch::kinds::hook::{Hook, HookContext};
use crate::dispatch::{Dispatcher, LoadError, Plugin};
use crate::hook_door::{answers, validate, HookRows, JSON_HOOK_REFUSED};

/// `hook '<name>' <rest>`: the one spelling of a failed hook call's message.
#[cold]
pub(crate) fn broken(name: &str, rest: std::fmt::Arguments<'_>) -> String {
    format!("hook '{name}' {rest}")
}

/// The hook's configuration checkpoint did not decode.
#[cold]
pub(crate) fn checkpoint_undecoded(error: &str) -> String {
    error.to_owned()
}

/// A recovering hook did not restore its configuration.
#[cold]
pub(crate) fn reconfigure_refused(version: u64, error: Option<Vec<u8>>) -> String {
    error.map_or_else(
        || format!("it did not acknowledge settings version {version} again"),
        crate::dispatch::lifecycle::lossy,
    )
}

/// The hook's recovery worker panicked.
#[cold]
pub(crate) fn recovery_panicked() -> String {
    "hook recovery worker panicked".to_owned()
}

/// A quarantined hook cannot recover while its configuration is unresolved.
#[cold]
pub(crate) fn recovery_unresolved() -> String {
    "hook configuration result is unresolved; recovery is unavailable".to_owned()
}

/// A name a hook instance or its configuration keeps: an opened instance's name, a pushed
/// configuration's name, a rebind's label.
#[cold]
pub(crate) fn kept_name(name: &str) -> String {
    name.to_owned()
}

/// The routes an opened hook instance keeps: its declared ones.
#[cold]
pub(crate) fn kept_routes(plugin: &Plugin<Hook>) -> Vec<Route> {
    plugin
        .context::<HookContext>()
        .map_or_else(Vec::new, |f| f.routes.clone())
}

/// A bound hook instance keeps its label.
#[cold]
pub(crate) fn instance_label(label: &str) -> Arc<str> {
    Arc::from(label)
}

/// An order-free hook answered an order, which is refused.
#[cold]
pub(crate) fn order_refused(name: &str) -> String {
    format!(
        "hook plugin '{name}' declared `hook.orders: false` and answered an order: its \
             `decide` must always abstain, so the order is refused"
    )
}

/// A configuration push the hook did not acknowledge.
#[cold]
pub(crate) fn unacknowledged(hook: &str, version: u64) -> String {
    format!("hook '{hook}' did not acknowledge settings version {version}")
}

/// A configuration push the hook failed with its own words.
#[cold]
pub(crate) fn configure_failed(hook: &str, why: &str) -> String {
    format!("hook '{hook}': {why}")
}

/// A configuration push the hook did not acknowledge within its budget.
#[cold]
pub(crate) fn unacknowledged_in_budget(hook: &str, version: u64) -> String {
    format!("hook '{hook}' did not acknowledge settings version {version} within its budget")
}

/// A configuration push the hook answered out of turn.
#[cold]
pub(crate) fn configure_out_of_turn(hook: &str) -> String {
    format!("hook '{hook}' answered out of turn")
}

/// A hook's settings did not render (for a push, a validation or an opening).
#[cold]
pub(crate) fn settings_unrendered(error: &serde_json::Error) -> String {
    error.to_string()
}

/// The hook served a malformed response header.
#[cold]
pub(crate) fn serve_header_malformed() -> String {
    "hook serve returned a malformed response header".to_owned()
}

/// A linked hook door states another kind.
#[cold]
pub(crate) fn linked_other_kind(name: &str) -> String {
    format!("the linked hook door '{name}' states another kind")
}

/// A dropped hook speaks the refused JSON contract.
#[cold]
pub(crate) fn json_hook_refused(plugin: &str) -> String {
    format!("plugin '{plugin}': {JSON_HOOK_REFUSED}")
}

/// A hook plugin that did not load, bind or declare its routes, named.
#[cold]
pub(crate) fn plugin_refused(name: &str, error: &LoadError) -> String {
    format!("hook plugin '{name}': {error}")
}

/// A configured hook module no plugin answers to.
#[cold]
pub(crate) fn no_hook_answers(module: &str) -> String {
    format!("no `kind: hook` plugin answers to '{module}'")
}

/// The candidate a configured hook module names, matched when config is read.
#[cold]
pub(crate) fn find<'a>(rows: &'a HookRows, module: &str) -> Option<&'a Candidate> {
    HookRows::candidates(rows)
        .iter()
        .find(|c| answers(c, module))
}

/// The problems a probe's validation found in the hook's settings, one per line.
#[cold]
pub(crate) fn probe_problems(
    plugin: &Plugin<Hook>,
    dispatcher: &Dispatcher,
    settings: &ResolvedSettings,
) -> Vec<String> {
    let validated = settings
        .encode()
        .map_err(|error| error.to_string())
        .and_then(|text| {
            let seal = dispatcher
                .seal()
                .ok_or("hook probe requires the host settings seal")?;
            validate(plugin, text.expose(seal))
        });
    match validated {
        Ok(()) => Vec::new(),
        Err(words) => words.lines().map(str::to_string).collect(),
    }
}
