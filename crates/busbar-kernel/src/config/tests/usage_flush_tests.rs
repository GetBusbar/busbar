// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn resolved_with(yaml: &str) -> LimitsResolved {
    let advanced: AdvancedCfg = busbar_contract::yaml::from_str(yaml).expect("parses");
    LimitsResolved::from_sections(
        &LimitsCfg::default(),
        &advanced,
        &OutboundCfg::default(),
        ExportLimits::default(),
        &HealthDefaultsCfg::default(),
        &RoutingCfg::default(),
    )
}

#[test]
fn a_zero_flush_interval_is_converted_so_the_writer_loop_always_pauses() {
    let limits = resolved_with("usage_flush_interval_ms: 0\n");
    assert_eq!(
        limits.usage_flush_interval_ms, 1,
        "0 would run the flush loop with no pause between passes"
    );
}

#[test]
fn a_converted_interval_comes_with_one_log_line_and_a_kept_one_with_none() {
    use super::limits::{effective_usage_flush_interval_ms as rule, MIN_USAGE_FLUSH_INTERVAL_MS};
    assert_eq!(
        rule(MIN_USAGE_FLUSH_INTERVAL_MS),
        (MIN_USAGE_FLUSH_INTERVAL_MS, None)
    );
    assert_eq!(rule(100), (100, None));
    let (ms, note) = rule(0);
    assert_eq!(ms, MIN_USAGE_FLUSH_INTERVAL_MS);
    let note = note.expect("a converted value says so");
    assert!(
        note.contains("advanced.usage_flush_interval_ms: 0"),
        "{note}"
    );
    assert!(!note.contains('\n'), "one line: {note}");
}

#[test]
fn an_interval_the_timer_can_wait_is_kept_as_written() {
    for ms in [1u64, 5, 100, 60_000] {
        let limits = resolved_with(&format!("usage_flush_interval_ms: {ms}\n"));
        assert_eq!(limits.usage_flush_interval_ms, ms);
    }
}
