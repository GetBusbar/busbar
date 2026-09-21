//! THE FROZEN LIMIT GRAMMAR: the three operator-facing refusals a malformed `limits:` entry
//! produces are 1.5.5's, byte for byte, and the four 1.6.0 token-class metrics still parse.
//!
//! A limit's refusal text is not prose — it is the parse surface an operator reads and greps. The
//! published 1.5.5 binary names FOUR metric words in each of these three sentences (`requests`,
//! `tokens`, `budget`, `concurrent`), and 1.6.0 adds four more metrics to what the grammar
//! ACCEPTS. Naming the new ones in the refusal grows an operator-visible list that a 1.5.5 log
//! matcher already reads, which is the same defect the config pre-pass exists to prevent for the
//! 1.6.0-additive top-level keys: the additive keys parse, and the frozen key list does not move.
//! The rule is the same one line for line here — the four `tokens_*` metrics are accepted by the
//! visitor and absent from every frozen sentence.
//!
//! The three expected strings below are transcribed from the COMMITTED 1.5.5 golden
//! (`testing/shadow-oracle/golden/1.5.5/cells/boot.refusal__BOOT-P{20,29,30}__validate.json`), not
//! from this tree's source, so a change to the source cannot quietly change what "1.5.5's words"
//! means.

use super::*;

/// The metric words 1.5.5's refusals name, in 1.5.5's order. Every frozen sentence below is
/// checked against THIS list, so a metric added to the grammar cannot join a refusal by accident.
const FROZEN_METRIC_WORDS: [&str; 4] = ["requests", "tokens", "budget", "concurrent"];

/// The four metrics 1.6.0 adds. They must PARSE (the grammar accepts them) and must appear in NO
/// frozen refusal (the operator-visible list does not move).
const ADDITIVE_METRIC_WORDS: [&str; 4] = [
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];

/// Deserialize one limit from YAML and return the refusal text.
fn refusal(yaml: &str) -> String {
    match serde_yaml::from_str::<LimitCfg>(yaml) {
        Ok(ok) => panic!("expected a refusal, parsed {ok:?}"),
        Err(e) => e.to_string(),
    }
}

/// BOOT-P29. serde's `unknown_field` list is the one an operator is told to choose from. 1.5.5
/// prints eight keys; this asserts the whole sentence, so an inserted metric name is a failure
/// rather than a widened list nobody reads.
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

/// BOOT-P20. A limit with no metric key at all. The parenthesised list is 1.5.5's four words.
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

/// BOOT-P30. A scalar where a limit map belongs — serde prints the visitor's `expecting` line,
/// which is the fullest statement of the grammar an operator ever sees.
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

/// THE OTHER HALF OF THE CONTRACT. Freezing the refusal must not narrow the grammar: each of the
/// four 1.6.0 metrics still parses, to its own variant, with its amount and window intact.
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

/// 1.5.5's own four metrics parse unchanged — the freeze is a text freeze, not a grammar edit.
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
