// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const FROZEN_METRIC_WORDS: [&str; 4] = ["requests", "tokens", "budget", "concurrent"];

fn refusal(yaml: &str) -> String {
    match busbar_contract::yaml::from_str::<LimitCfg>(yaml) {
        Ok(ok) => panic!("expected a refusal, parsed {ok:?}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn the_unknown_field_list_is_1_5_5s() {
    let got = refusal("{ requests: 1, per: day, bogus: 1 }");
    assert!(
        got.contains(
            "unknown field `bogus`, expected one of `requests`, `tokens`, `budget`, \
             `concurrent`, `per`, `pool`, `on_exhaust`, `downgrade_to`"
        ),
        "BOOT-P29 refusal does not keep 1.5.5's list: {got}"
    );
    assert!(
        !got.contains("tokens_input")
            && !got.contains("admission")
            && !got.contains("on_exhaustion"),
        "BOOT-P29 lists a removed 1.6.0 key: {got}"
    );
}

#[test]
fn the_no_metric_key_refusal_is_1_5_5s() {
    let got = refusal("{ per: day }");
    assert!(
        got.contains(
            "a limit needs exactly one metric key (requests | tokens | budget | concurrent)"
        ),
        "BOOT-P20 refusal does not list 1.5.5's four metrics: {got}"
    );
}

#[test]
fn the_expecting_line_is_1_5_5s() {
    let got = refusal("requests");
    assert!(
        got.contains(
            "expected a limit map `{ <metric>: <amount>, per: <window>, pool: <name> }` where \
             <metric> is one of requests|tokens|budget|concurrent and <window> one of \
             minute|hour|day|month|total (omit `per` for concurrent; `pool` is optional and \
             scopes the limit to one pool's traffic)"
        ),
        "BOOT-P30 refusal does not list 1.5.5's four metrics: {got}"
    );
}

#[test]
fn the_four_frozen_metrics_still_parse() {
    for word in FROZEN_METRIC_WORDS {
        let yaml = if word == "concurrent" {
            format!("{{ {word}: 7 }}")
        } else {
            format!("{{ {word}: 7, per: day }}")
        };
        let parsed: LimitCfg = busbar_contract::yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("`{word}` no longer parses: {e}"));
        assert_eq!(parsed.metric.as_str(), word);
        assert_eq!(parsed.amount, 7);
    }
}

/// A minimal valid value for each `LIMIT_KEYS` entry. A key missing here fails the guard below.
fn minimal_value(key: &str) -> &'static str {
    match key {
        "per" => "day",
        "pool" | "downgrade_to" => "p",
        "on_exhaust" => "block",
        k if LimitMetric::from_key(k).is_some() => "1",
        other => panic!("no minimal value for limit key `{other}`; add one"),
    }
}

#[test]
fn limit_tables_agree() {
    for m in LimitMetric::ALL {
        assert!(
            LIMIT_KEYS.contains(&m.as_str()),
            "metric `{}` is missing from LIMIT_KEYS",
            m.as_str()
        );
    }
    for key in LIMIT_KEYS {
        let yaml = format!("{{ {key}: {} }}", minimal_value(key));
        if let Err(e) = busbar_contract::yaml::from_str::<LimitCfg>(&yaml) {
            let e = e.to_string();
            assert!(
                !e.contains("unknown field"),
                "LIMIT_KEYS lists `{key}` but the parser refuses it as unknown: {e}"
            );
        }
    }
    let got = refusal("{ requests: 1, per: day, bogus: 1 }");
    let listed: Vec<&str> = got
        .split_once("expected one of ")
        .and_then(|(_, rest)| rest.split(" at line ").next())
        .map(|list| list.split(", ").map(|key| key.trim_matches('`')).collect())
        .unwrap_or_default();
    for key in LIMIT_KEYS {
        assert!(listed.contains(key), "BOOT-P29 omits `{key}`: {got}");
    }
}

#[test]
fn every_metric_is_in_all() {
    // Exhaustive on purpose (no `_`): a new metric fails to compile here until placed in ALL.
    fn idx(m: LimitMetric) -> usize {
        match m {
            LimitMetric::Requests => 0,
            LimitMetric::Tokens => 1,
            LimitMetric::Budget => 2,
            LimitMetric::Concurrent => 3,
        }
    }
    assert_eq!(LimitMetric::ALL.len(), 4);
    for m in LimitMetric::ALL {
        assert_eq!(LimitMetric::ALL[idx(m)], m);
        assert_eq!(LimitMetric::from_key(m.as_str()), Some(m));
    }
}
