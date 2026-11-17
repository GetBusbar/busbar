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
fn selected_limit_roundtrip_keeps_complete_scope_and_maximum_amount() {
    for metric in ["requests", "tokens"] {
        let source = format!("{{id: Rule, upstream_resource: plane/a/b, per_key: true, enforcement: process, {metric}: 18446744073709551615, per: minute}}");
        let row: LimitCfg = busbar_contract::yaml::from_str(&source).unwrap();
        assert_eq!(row.amount, u64::MAX);
        assert!(row.scope.is_none());
        let encoded = busbar_contract::yaml::to_string(&row).unwrap();
        for word in ["Rule", "plane/a/b", "per_key", "enforcement", "process"] {
            assert!(encoded.contains(word), "missing {word}: {encoded}");
        }
        assert_eq!(
            busbar_contract::yaml::from_str::<LimitCfg>(&encoded).unwrap(),
            row
        );
    }
}

#[test]
fn selected_limit_scope_cannot_fall_back_to_ordinary_limit() {
    for suffix in [
        "",
        ", per_key: false, enforcement: process",
        ", per_key: true",
        ", per_key: true, enforcement: hard",
        ", per_key: true, enforcement: global",
        ", per_key: true, enforcement: process, pool: p",
        ", per_key: true, enforcement: process, on_exhaust: block",
        ", per_key: true, enforcement: process, downgrade_to: p",
    ] {
        let source =
            format!("{{id: r, upstream_resource: plane/r, requests: 1, per: minute{suffix}}}");
        assert!(
            busbar_contract::yaml::from_str::<LimitCfg>(&source).is_err(),
            "{source}"
        );
    }
    for source in [
        "{id: r, requests: 1, per: minute}",
        "{upstream_resource: plane/r, per_key: true, enforcement: process, requests: 1, per: minute}",
        "{id: r, upstream_resource: plane/r, per_key: true, enforcement: process, budget: 1, per: minute}",
        "{id: r, upstream_resource: plane/r, per_key: true, enforcement: process, concurrent: 1}",
        "{id: r, upstream_resource: plane/r, per_key: true, enforcement: process, tokens: 1, per: hour}",
        "{id: r, upstream_resource: plane/r, per_key: true, enforcement: process, requests: -1, per: minute}",
        "{id: r, id: s, upstream_resource: plane/r, per_key: true, enforcement: process, requests: 1, per: minute}",
    ] {
        assert!(busbar_contract::yaml::from_str::<LimitCfg>(source).is_err(), "{source}");
    }
}

#[test]
fn selected_rule_ids_are_unique_across_metrics_in_each_group() {
    let groups = busbar_contract::yaml::from_str("team:\n  limits:\n    - {id: same, upstream_resource: p/r, per_key: true, enforcement: process, requests: 1, per: minute}\n    - {id: same, upstream_resource: p/r, per_key: true, enforcement: process, tokens: 2, per: minute}").unwrap();
    let mut errors = Vec::new();
    validate_groups(&groups, &|_| true, &mut errors);
    assert!(
        errors.iter().any(|error| error.contains("same")),
        "{errors:?}"
    );
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
        "id" => "r",
        "upstream_resource" => "p/r",
        "per_key" => "true",
        "enforcement" => "process",
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
