// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The counted cap forms return the same bytes as the uncounted ones, plus the cut as a fact:
//! `Some(sanitised length)` exactly when the sanitised text was over the cap.

use busbar_contract::hook_wire::reply::{
    parse_status_metrics, parse_status_metrics_counted, sanitize_cap, sanitize_cap_counted,
    sanitize_reject_message, sanitize_reject_message_counted, TextField, MAX_METRIC_HELP_CHARS,
    MAX_METRIC_LABEL_CHARS, MAX_METRIC_UNIT_CHARS, REJECT_MESSAGE_MAX_CHARS,
};

/// The length the cap counts: chars left after control and format characters are removed.
fn sanitised_len(raw: &str) -> usize {
    sanitize_cap(raw, usize::MAX).chars().count()
}

/// A deterministic mix of plain, multibyte, control and format characters.
fn inputs() -> Vec<String> {
    const ALPHABET: [char; 10] = [
        'a', 'é', '€', '😀', '\n', '\u{0}', '\u{200B}', '\u{202E}', ' ', 'Z',
    ];
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::new();
    for _ in 0..300 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let len = (seed >> 33) as usize % 400;
        let mut s = String::new();
        for _ in 0..len {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            s.push(ALPHABET[(seed >> 33) as usize % ALPHABET.len()]);
        }
        out.push(s);
    }
    for n in [16usize, 64, 200, 300] {
        for len in [n - 1, n, n + 1] {
            out.push("x".repeat(len));
            out.push("€".repeat(len));
            out.push(format!("{}\u{7}\u{200B}", "y".repeat(len)));
        }
    }
    out
}

#[test]
fn the_counted_cap_keeps_the_bytes_and_reports_exactly_the_over_cap_inputs() {
    for raw in inputs() {
        for n in [0usize, 1, 16, 64, 200, 300] {
            let (value, cut) = sanitize_cap_counted(&raw, n);
            assert_eq!(value, sanitize_cap(&raw, n), "{raw:?} at {n}");
            let len = sanitised_len(&raw);
            assert_eq!(cut, (len > n).then_some(len), "{raw:?} at {n}");
        }
        let (message, cut) = sanitize_reject_message_counted(&raw);
        assert_eq!(message, sanitize_reject_message(&raw), "{raw:?}");
        let len = sanitised_len(&raw);
        assert_eq!(
            cut,
            (len > REJECT_MESSAGE_MAX_CHARS).then_some(len),
            "{raw:?}"
        );
    }
}

#[test]
fn an_at_cap_or_shorter_value_reports_no_cut() {
    for n in [16usize, 64, 300] {
        assert_eq!(sanitize_cap_counted(&"x".repeat(n), n).1, None);
        assert_eq!(sanitize_cap_counted(&"x".repeat(n - 1), n).1, None);
        assert_eq!(
            sanitize_cap_counted(&format!("{}\u{0}\u{FEFF}", "x".repeat(n)), n).1,
            None
        );
    }
    assert_eq!(sanitize_reject_message_counted(&"x".repeat(300)).1, None);
    assert_eq!(sanitize_reject_message_counted("").1, None);
}

#[test]
fn an_all_whitespace_over_cap_reject_falls_back_and_still_reports_the_cut() {
    let (message, cut) = sanitize_reject_message_counted(&" ".repeat(400));
    assert_eq!(message, sanitize_reject_message(&" ".repeat(400)));
    assert_eq!(cut, Some(400));
}

#[test]
fn the_counted_metric_parse_keeps_the_metrics_and_counts_each_cut_field() {
    let entry = |help: usize, label: usize, unit: usize, value: usize| {
        serde_json::json!({
            "name": "x_total", "type": "counter", "value": 1,
            "help": "h".repeat(help), "label": "b".repeat(label), "unit": "u".repeat(unit),
            "labels": {"a": "v".repeat(value), "b": "v".repeat(value / 2)},
        })
    };
    let raw = vec![
        entry(
            MAX_METRIC_HELP_CHARS,
            MAX_METRIC_LABEL_CHARS,
            MAX_METRIC_UNIT_CHARS,
            64,
        ),
        entry(MAX_METRIC_HELP_CHARS + 1, 70, 17, 200),
        entry(250, 64, 40, 130),
    ];
    let (counted, cuts) = parse_status_metrics_counted(&raw);
    assert_eq!(
        format!("{counted:?}"),
        format!("{:?}", parse_status_metrics(&raw))
    );
    let got: Vec<_> = cuts.iter().collect();
    assert_eq!(
        got,
        vec![
            (TextField::MetricHelp, 2, 250),
            (TextField::MetricLabel, 1, 70),
            (TextField::MetricUnit, 2, 40),
            (TextField::MetricLabelValue, 4, 200),
        ]
    );

    let (_, none) = parse_status_metrics_counted(&raw[..1]);
    assert!(none.is_empty(), "values at the cap are not cut");
}

#[test]
fn only_kept_label_values_are_counted() {
    let labels: serde_json::Map<String, serde_json::Value> = (0..12)
        .map(|i| (format!("l{i:02}"), serde_json::Value::from("v".repeat(100))))
        .collect();
    let raw =
        [serde_json::json!({"name": "x_total", "type": "counter", "value": 1, "labels": labels})];
    let (_, cuts) = parse_status_metrics_counted(&raw);
    assert_eq!(
        cuts.iter().collect::<Vec<_>>(),
        vec![(TextField::MetricLabelValue, 8, 100)],
        "labels past MAX_METRIC_LABELS are dropped, not counted"
    );
}
