// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `suites::export` end to end (ABI-MIN3-INTERFACE §14): a `plugin!`-built accepting sink admitted through
//! `admit_header` and driven through the registry. The red-first proof of the harness and the export suite.

use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites;

use crate::min3_export::PLUGIN;

#[test]
fn the_export_suite_passes_over_a_plugin_built_sink() {
    suites::export(PLUGIN.plugin(), b"{}", FakeNeeds::new());
}

/// A metrics-only exporter (STREAM_METRICS and M_RENDER, the SDK's default `deliver`) passes too: core never
/// pushes on the metrics stream, so the suite requires no delivery of it.
#[test]
fn the_export_suite_passes_over_a_metrics_only_exporter() {
    suites::export(
        crate::min3_export_metrics::PLUGIN.plugin(),
        b"{}",
        FakeNeeds::new(),
    );
}
