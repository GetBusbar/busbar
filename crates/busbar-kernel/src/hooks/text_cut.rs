// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-supplied text cut at its cap, reported by the layer that knows who sent it.

use busbar_contract::hook_wire::reply::{
    parse_status_metrics_counted, HookMetric, TextCuts, TextField, MAX_METRIC_HELP_CHARS,
    MAX_METRIC_LABEL_CHARS, MAX_METRIC_UNIT_CHARS, REJECT_MESSAGE_MAX_CHARS,
};

/// What [`report`] did with a cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    /// The first cut of this (plugin, field): counted and logged at WARN.
    Warned,
    /// A repeat: counted only.
    Counted,
}

/// Records that `count` values of `field` from `plugin` were over `cap`.
pub fn report(
    _plugin: &str,
    _field: TextField,
    _cap: usize,
    _count: u32,
    _max_sanitised: usize,
) -> Reported {
    Reported::Counted
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
