// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::export::{SCRAPE_KIND_HISTOGRAM, SCRAPE_KIND_UNTYPED};
use busbar_contract::export_calls::codes::{SCRAPE_KIND_COUNTER, SCRAPE_KIND_GAUGE};

fn sample(name: &str, labels: &[(&str, &str)], value: &str) -> Sample {
    Sample {
        name: name.into(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        value: value.into(),
    }
}

fn family(name: &str, help: Option<&str>, kind: u8, samples: Vec<Sample>) -> Family {
    Family {
        name: name.into(),
        help: help.map(Into::into),
        unit: None,
        kind,
        samples,
    }
}

fn text(families: &[Family], format: Format) -> String {
    let mut out = String::new();
    encode(&mut out, families, format).unwrap();
    out
}

#[test]
fn metrics_text_escapes_and_sanitises() {
    let families = [family(
        "bad name-1.x",
        Some("line one\nline \\ two \"quoted\""),
        SCRAPE_KIND_GAUGE,
        vec![sample(
            "bad name-1.x",
            &[
                ("9lead", "a\"b\\c\nd"),
                ("has:colon", "plain"),
                ("", "empty"),
            ],
            "1.5",
        )],
    )];
    assert_eq!(
        text(&families, Format::Prometheus),
        "# HELP bad_name_1_x line one\\nline \\\\ two \"quoted\"\n\
         # TYPE bad_name_1_x gauge\n\
         bad_name_1_x{_lead=\"a\\\"b\\\\c\\nd\",has_colon=\"plain\",_=\"empty\"} 1.5\n"
    );
}

#[test]
fn metrics_text_a_value_that_is_not_a_number_cannot_break_the_line() {
    let families = [family(
        "m",
        None,
        SCRAPE_KIND_UNTYPED,
        vec![
            sample("m", &[], "1\nevil 2"),
            sample("m", &[], "inf"),
            sample("m", &[], "-inf"),
            sample("m", &[], "42"),
        ],
    )];
    assert_eq!(
        text(&families, Format::Prometheus),
        "# HELP m \n# TYPE m untyped\nm NaN\nm +Inf\nm -Inf\nm 42\n"
    );
}

#[test]
fn metrics_histogram_cumulative_buckets() {
    let families = [family(
        "busbar_d_seconds",
        Some("d"),
        SCRAPE_KIND_HISTOGRAM,
        vec![
            sample(
                "busbar_d_seconds_bucket",
                &[("pool", "p"), ("le", "0.1")],
                "1",
            ),
            sample(
                "busbar_d_seconds_bucket",
                &[("pool", "p"), ("le", "1")],
                "3",
            ),
            sample(
                "busbar_d_seconds_bucket",
                &[("pool", "p"), ("le", "+Inf")],
                "4",
            ),
            sample("busbar_d_seconds_sum", &[("pool", "p")], "2.5"),
            sample("busbar_d_seconds_count", &[("pool", "p")], "4"),
        ],
    )];
    assert_eq!(
        text(&families, Format::Prometheus),
        "# HELP busbar_d_seconds d\n\
         # TYPE busbar_d_seconds histogram\n\
         busbar_d_seconds_bucket{pool=\"p\",le=\"0.1\"} 1\n\
         busbar_d_seconds_bucket{pool=\"p\",le=\"1\"} 3\n\
         busbar_d_seconds_bucket{pool=\"p\",le=\"+Inf\"} 4\n\
         busbar_d_seconds_sum{pool=\"p\"} 2.5\n\
         busbar_d_seconds_count{pool=\"p\"} 4\n"
    );
}

#[test]
fn metrics_openmetrics_ends_with_eof() {
    assert_eq!(text(&[], Format::OpenMetrics), "# EOF\n");
    assert_eq!(text(&[], Format::Prometheus), "");
    let one = [family(
        "g",
        Some("h"),
        SCRAPE_KIND_GAUGE,
        vec![sample("g", &[], "1")],
    )];
    assert!(text(&one, Format::OpenMetrics).ends_with("g 1\n# EOF\n"));
}

#[test]
fn metrics_openmetrics_counter_family_drops_total_and_samples_keep_it() {
    let both = [
        family(
            "busbar_requests_total",
            Some("r"),
            SCRAPE_KIND_COUNTER,
            vec![sample("busbar_requests_total", &[("pool", "p")], "7")],
        ),
        family(
            "busbar_bare",
            Some("b"),
            SCRAPE_KIND_COUNTER,
            vec![sample("busbar_bare", &[], "1")],
        ),
    ];
    assert_eq!(
        text(&both, Format::OpenMetrics),
        "# HELP busbar_requests r\n# TYPE busbar_requests counter\n\
         busbar_requests_total{pool=\"p\"} 7\n\
         # HELP busbar_bare b\n# TYPE busbar_bare counter\n\
         busbar_bare_total 1\n# EOF\n"
    );
    // The 0.0.4 form keeps the names as the registry holds them.
    assert!(text(&both, Format::Prometheus).contains("# TYPE busbar_requests_total counter\n"));
    assert!(text(&both, Format::Prometheus).contains("busbar_bare 1\n"));
}

#[test]
fn metrics_openmetrics_untyped_is_unknown() {
    let f = [family(
        "u",
        None,
        SCRAPE_KIND_UNTYPED,
        vec![sample("u", &[], "1")],
    )];
    assert!(text(&f, Format::OpenMetrics).contains("# TYPE u unknown\n"));
    assert!(text(&f, Format::Prometheus).contains("# TYPE u untyped\n"));
}

#[test]
fn metrics_text_keeps_the_recorders_order() {
    let f = [
        family(
            "z",
            None,
            SCRAPE_KIND_GAUGE,
            vec![
                sample("z", &[("k", "b")], "1"),
                sample("z", &[("k", "a")], "2"),
            ],
        ),
        family("a", None, SCRAPE_KIND_GAUGE, vec![sample("a", &[], "3")]),
    ];
    let out = text(&f, Format::Prometheus);
    let (zb, za, a) = (
        out.find("z{k=\"b\"}").unwrap(),
        out.find("z{k=\"a\"}").unwrap(),
        out.find("\na ").unwrap(),
    );
    assert!(zb < za && za < a, "the encoder sorts nothing: {out}");
}

#[test]
fn metrics_text_appends_and_never_shrinks_the_buffer() {
    let f = [family(
        "g",
        None,
        SCRAPE_KIND_GAUGE,
        vec![sample("g", &[], "1")],
    )];
    let mut out = String::with_capacity(1024);
    out.push_str("keep\n");
    let before = out.capacity();
    encode(&mut out, &f, Format::Prometheus).unwrap();
    assert!(out.starts_with("keep\n# HELP g \n"));
    assert_eq!(
        out.capacity(),
        before,
        "one scrape fits the reserved buffer"
    );
}
