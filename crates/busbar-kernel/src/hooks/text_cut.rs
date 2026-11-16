// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-supplied text cut at its cap, reported by the layer that knows who sent it.
//!
//! The contract's cap functions keep the 1.5.5 bytes and return the cut as a fact
//! ([`busbar_contract::hook_wire::reply::TextCuts`]); this module turns that fact into the
//! attributed record: every cut counts on [`crate::snapshot::PLUGIN_TEXT_CUT_TOTAL`], and the first
//! cut of each (plugin, field) pair logs BUSBAR-6013 once for the life of the process.

use busbar_contract::hook_wire::reply::{
    TextCuts, TextField, MAX_METRIC_HELP_CHARS, MAX_METRIC_LABEL_CHARS, MAX_METRIC_UNIT_CHARS,
    REJECT_MESSAGE_MAX_CHARS,
};
use foldhash::HashMap;
use std::sync::{Arc, RwLock};

/// What [`report`] did with a cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    /// The first cut of this (plugin, field): counted and logged at WARN.
    Warned,
    /// A repeat: counted only.
    Counted,
}

/// The (plugin, field) pairs already warned, one bit per [`TextField`] under each plugin name, so a
/// repeat is found by a borrowed `&str` under the read lock. The name is keyed once, on its first
/// cut, and shared from then on as the counter's `plugin` label. Never cleared in-process.
static WARNED: RwLock<Option<HashMap<Arc<str>, u8>>> = RwLock::new(None);

const fn bit(field: TextField) -> u8 {
    1 << field as u8
}

/// The shared name `plugin` is keyed under, if it has been cut before, and whether `field` has.
fn warned(plugin: &str, field: TextField) -> Option<(Arc<str>, bool)> {
    let guard = WARNED.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|m| m.get_key_value(plugin))
        .map(|(name, bits)| (Arc::clone(name), bits & bit(field) != 0))
}

/// Marks `field` cut for `plugin`: its shared name, and whether this was the first such cut.
fn latch(plugin: &str, field: TextField) -> (Arc<str>, bool) {
    let mut guard = WARNED.write().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::default);
    match map.get_key_value(plugin).map(|(name, _)| Arc::clone(name)) {
        Some(name) => {
            let bits = map.entry(Arc::clone(&name)).or_default();
            let first = *bits & bit(field) == 0;
            *bits |= bit(field);
            (name, first)
        }
        None => (crate::cold::first_text_cut(map, plugin, bit(field)), true),
    }
}

/// Records that `count` values of `field` from `plugin` were over `cap`, the longest
/// `max_sanitised` chars after sanitising. `plugin` is the configured hook instance name for a
/// reject or status cut, and the plugin module name for a reported metric or diagnostic.
pub fn report(
    plugin: &str,
    field: TextField,
    cap: usize,
    count: u32,
    max_sanitised: usize,
) -> Reported {
    let (name, first) = match warned(plugin, field) {
        Some((name, true)) => (name, false),
        _ => latch(plugin, field),
    };
    metrics::counter!(
        crate::snapshot::PLUGIN_TEXT_CUT_TOTAL,
        "plugin" => name,
        "field" => field.as_str()
    )
    .increment(u64::from(count));
    if !first {
        return Reported::Counted;
    }
    crate::diagnostics::diag_warn!(
        crate::diagnostics::PLUGIN_TEXT_CUT,
        plugin = %plugin,
        field = %field.as_str(),
        cap,
        sanitised_chars = max_sanitised,
        "plugin-supplied text exceeded its cap and was cut to the first `cap` sanitised characters; \
         further cuts of this field from this plugin are counted on busbar_plugin_text_cut_total"
    );
    Reported::Warned
}

/// [`report`] once for each field `cuts` holds, at the cap `caps` names for it.
pub(crate) fn report_cuts(plugin: &str, cuts: &TextCuts, caps: impl Fn(TextField) -> usize) {
    for (field, count, max_sanitised) in cuts.iter() {
        report(plugin, field, caps(field), count, max_sanitised);
    }
}

/// The cap each field is cut at.
#[must_use]
pub fn cap_of(field: TextField) -> usize {
    match field {
        TextField::RejectMessage => REJECT_MESSAGE_MAX_CHARS,
        TextField::MetricHelp => MAX_METRIC_HELP_CHARS,
        TextField::MetricLabel | TextField::MetricLabelValue => MAX_METRIC_LABEL_CHARS,
        TextField::MetricUnit => MAX_METRIC_UNIT_CHARS,
        TextField::DiagMessage => crate::snapshot::observe::MAX_DIAG_MESSAGE_CHARS,
        TextField::DiagField => crate::snapshot::observe::MAX_DIAG_FIELD_CHARS,
    }
}

pub use crate::off_path::hooks::parse_hook_status_metrics;

#[cfg(test)]
#[path = "tests/text_cut_tests.rs"]
pub(crate) mod text_cut_tests;
