// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook message cap, as 1.5.5 applied it: an over-long value is cut to the cap and nothing is
//! added.
//!
//! In 1.5.5 (`crates/busbar/src/hooks/wire.rs` at the `v1.5.5` tag) `sanitize_reject_message`
//! kept the first `REJECT_MESSAGE_MAX_CHARS` characters, and `sanitize_cap` kept the first `n`
//! characters of a status metric's `help`, `label` and `unit`. Predev replaces the last kept
//! character with `…`. A hook's reject message is the error text the client receives, and the
//! metric strings reach `/metrics/hooks` and the admin hook status, so the extra character is a
//! customer-visible change that nobody signed. These tests hold the 1.5.5 bytes.

use busbar_kernel::hooks::wire::{
    parse_status_metrics, sanitize_reject_message, MAX_METRIC_HELP_CHARS, MAX_METRIC_LABEL_CHARS,
    MAX_METRIC_UNIT_CHARS, REJECT_MESSAGE_MAX_CHARS,
};

#[test]
fn an_over_cap_reject_message_is_cut_with_nothing_added() {
    let long = "x".repeat(1000);
    assert_eq!(
        sanitize_reject_message(&long),
        "x".repeat(REJECT_MESSAGE_MAX_CHARS),
        "1.5.5 cuts the message at the cap and appends no marker"
    );
}

#[test]
fn a_message_at_the_cap_is_unchanged() {
    let exact = "y".repeat(REJECT_MESSAGE_MAX_CHARS);
    assert_eq!(sanitize_reject_message(&exact), exact);
}

#[test]
fn over_cap_metric_hints_are_cut_with_nothing_added() {
    let long_euro = "€".repeat(400);
    let raw = [serde_json::json!({
        "name": "ok_total", "type": "counter", "value": 1.0,
        "help": long_euro, "label": long_euro, "unit": long_euro
    })];
    let parsed = parse_status_metrics(&raw);
    assert_eq!(parsed.len(), 1);
    let metric = &parsed[0];
    assert_eq!(
        metric.help.as_deref(),
        Some("€".repeat(MAX_METRIC_HELP_CHARS).as_str())
    );
    assert_eq!(
        metric.label.as_deref(),
        Some("€".repeat(MAX_METRIC_LABEL_CHARS).as_str())
    );
    assert_eq!(
        metric.unit.as_deref(),
        Some("€".repeat(MAX_METRIC_UNIT_CHARS).as_str())
    );
}
