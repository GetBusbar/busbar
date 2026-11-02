use super::*;

const FROZEN_METRIC_WORDS: [&str; 4] = ["requests", "tokens", "budget", "concurrent"];

const ADDITIVE_METRIC_WORDS: [&str; 4] = [
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];

fn refusal(yaml: &str) -> String {
    match serde_yaml::from_str::<LimitCfg>(yaml) {
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
        "BOOT-P29 refusal is not 1.5.5's: {got}"
    );
    for word in ADDITIVE_METRIC_WORDS {
        assert!(
            !got.contains(word),
            "BOOT-P29 names the 1.6.0-additive metric `{word}`: {got}"
        );
    }
}

#[test]
fn the_no_metric_key_refusal_is_1_5_5s() {
    let got = refusal("{ per: day }");
    assert!(
        got.contains(
            "a limit needs exactly one metric key (requests | tokens | budget | concurrent)"
        ),
        "BOOT-P20 refusal is not 1.5.5's: {got}"
    );
    for word in ADDITIVE_METRIC_WORDS {
        assert!(
            !got.contains(word),
            "BOOT-P20 names the 1.6.0-additive metric `{word}`: {got}"
        );
    }
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
        "BOOT-P30 refusal is not 1.5.5's: {got}"
    );
    for word in ADDITIVE_METRIC_WORDS {
        assert!(
            !got.contains(word),
            "BOOT-P30 names the 1.6.0-additive metric `{word}`: {got}"
        );
    }
}

#[test]
fn the_four_additive_metrics_still_parse() {
    let expected = [
        LimitMetric::TokensInput,
        LimitMetric::TokensOutput,
        LimitMetric::TokensCacheRead,
        LimitMetric::TokensCacheWrite,
    ];
    for (word, metric) in ADDITIVE_METRIC_WORDS.iter().zip(expected) {
        let parsed: LimitCfg = serde_yaml::from_str(&format!("{{ {word}: 7, per: day }}"))
            .unwrap_or_else(|e| panic!("`{word}` no longer parses: {e}"));
        assert_eq!(parsed.metric, metric);
        assert_eq!(parsed.amount, 7);
        assert_eq!(parsed.per, Some(LimitWindow::Day));
    }
}

#[test]
fn the_four_frozen_metrics_still_parse() {
    for word in FROZEN_METRIC_WORDS {
        let yaml = if word == "concurrent" {
            format!("{{ {word}: 7 }}")
        } else {
            format!("{{ {word}: 7, per: day }}")
        };
        let parsed: LimitCfg = serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("`{word}` no longer parses: {e}"));
        assert_eq!(parsed.metric.as_str(), word);
        assert_eq!(parsed.amount, 7);
    }
}
