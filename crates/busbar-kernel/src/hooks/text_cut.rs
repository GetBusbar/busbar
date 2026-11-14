// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-supplied text cut at its cap, reported by the layer that knows who sent it.
//!
//! The contract's cap functions keep the 1.5.5 bytes and return the cut as a fact
//! ([`busbar_contract::hook_wire::reply::TextCuts`]); this module turns that fact into the
//! attributed record: every cut counts on [`crate::snapshot::PLUGIN_TEXT_CUT_TOTAL`], and the first
//! cut of each (plugin, field) pair logs BUSBAR-6013 once for the life of the process.

use busbar_contract::hook_wire::reply::{
    parse_status_metrics_counted, HookMetric, TextCuts, TextField, MAX_METRIC_HELP_CHARS,
    MAX_METRIC_LABEL_CHARS, MAX_METRIC_UNIT_CHARS, REJECT_MESSAGE_MAX_CHARS,
};
use std::collections::HashMap;
use std::sync::RwLock;

/// What [`report`] did with a cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    /// The first cut of this (plugin, field): counted and logged at WARN.
    Warned,
    /// A repeat: counted only.
    Counted,
}

/// The (plugin, field) pairs already warned, one bit per [`TextField`] under each plugin name, so a
/// repeat is found by a borrowed `&str` under the read lock. Never cleared in-process.
static WARNED: RwLock<Option<HashMap<Box<str>, u8>>> = RwLock::new(None);

const fn bit(field: TextField) -> u8 {
    1 << field as u8
}

fn warned(plugin: &str, field: TextField) -> bool {
    let guard = WARNED.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|m| m.get(plugin))
        .is_some_and(|bits| bits & bit(field) != 0)
}

fn latch(plugin: &str, field: TextField) -> bool {
    let mut guard = WARNED.write().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    match map.get_mut(plugin) {
        Some(bits) => {
            let first = *bits & bit(field) == 0;
            *bits |= bit(field);
            first
        }
        None => {
            map.insert(Box::from(plugin), bit(field));
            true
        }
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
    metrics::counter!(
        crate::snapshot::PLUGIN_TEXT_CUT_TOTAL,
        "plugin" => plugin.to_string(),
        "field" => field.as_str()
    )
    .increment(u64::from(count));
    if warned(plugin, field) || !latch(plugin, field) {
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
pub fn report_cuts(plugin: &str, cuts: &TextCuts, caps: impl Fn(TextField) -> usize) {
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

/// A hook's `status` metrics, parsed as 1.5.5 does, with every cut reported against hook `name`.
pub fn parse_hook_status_metrics(name: &str, raw: &[serde_json::Value]) -> Vec<HookMetric> {
    let (metrics, cuts) = parse_status_metrics_counted(raw);
    report_cuts(name, &cuts, cap_of);
    metrics
}

#[cfg(test)]
#[path = "tests/text_cut_tests.rs"]
pub(crate) mod text_cut_tests;
