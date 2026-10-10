// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY BEDROCK CONVERSE USAGE COUNT IS LEDGERED OR A DECLARED SLICE (MONEY-AUDIT A-F1/A-F4;
//! owner LEDGER-100, 2026-10-03: every reported unit is a ledger line under its meter class). The census is the pinned wire lock
//! (`testing/llm-conformance/wire/bedrock.wire.json`): every integer member under `usage` and under
//! `trace.guardrail` has a declared class below, and the reader is driven on the buffered response,
//! the stream's `metadata` frame and a truncated-body recovery to prove it.
//!
//! - `totalTokens` is AWS's sum, not a unit of its own: a gap between it and the ledgered classes
//!   is reported on the usage identity note (with its WARN), and a total ABOVE them ledgers the
//!   remainder as the open class `unitemized_tokens`.
//! - The guardrail policy units AWS bills separately are each their own open class
//!   (`open_class::GUARDRAIL_COUNT_CLASSES`), summed over every guardrail on both sides.

use super::*;
use busbar_contract::testkit::WarnCapture;

/// What one count IS, per AWS's Converse semantics.
#[derive(Clone, Copy, Debug)]
enum Class {
    /// A ledgered count: the move one more reported unit makes on (input, cache read, cache write,
    /// output).
    Ledgered(i64, i64, i64, i64),
    /// The per-TTL split of `cacheWriteInputTokens`: attribution inside the one cache-write class.
    CacheWriteTtlSlice,
    /// AWS's stated total: checked against the ledgered classes; a total above them ledgers the
    /// remainder as `unitemized_tokens`.
    StatedTotal,
    /// A guardrail policy-unit count: ledgered under its own open class.
    GuardrailUnits,
    /// A measurement of the assessment itself (its latency, the characters and images it covered):
    /// not a unit AWS bills, which are the policy units above. Read nowhere, ledgered nowhere,
    /// named on no WARN.
    AssessmentMetric,
}

/// Every count the wire lock declares under the response's `usage`, by its path below `usage`.
const BEDROCK_USAGE_CLASSES: &[(&str, Class)] = &[
    ("inputTokens", Class::Ledgered(1, 0, 0, 0)),
    ("outputTokens", Class::Ledgered(0, 0, 0, 1)),
    ("cacheReadInputTokens", Class::Ledgered(0, 1, 0, 0)),
    ("cacheWriteInputTokens", Class::Ledgered(0, 0, 1, 0)),
    ("cacheDetails[].inputTokens", Class::CacheWriteTtlSlice),
    ("totalTokens", Class::StatedTotal),
];

/// Every count of a guardrail assessment's `invocationMetrics.usage` (`GuardrailUsage`).
const GUARDRAIL_COUNTS: &[&str] = &[
    "automatedReasoningPolicies",
    "automatedReasoningPolicyUnits",
    "contentPolicyImageUnits",
    "contentPolicyUnits",
    "contextualGroundingPolicyUnits",
    "sensitiveInformationPolicyFreeUnits",
    "sensitiveInformationPolicyUnits",
    "topicPolicyUnits",
    "wordPolicyUnits",
];

/// Every other integer of a guardrail assessment's `invocationMetrics` (`GuardrailInvocationMetrics`):
/// the assessment's latency and its coverage, by their path below `invocationMetrics`.
const GUARDRAIL_METRICS: &[&str] = &[
    "guardrailProcessingLatency",
    "guardrailCoverage.textCharacters.guarded",
    "guardrailCoverage.textCharacters.total",
    "guardrailCoverage.images.guarded",
    "guardrailCoverage.images.total",
];

/// The integer members the pinned wire lock declares under `usage` and `trace.guardrail` on
/// `section`, with `prefix` (the stream's `metadata.`) removed.
fn lock_counts(section: &str, prefix: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/llm-conformance/wire/bedrock.wire.json");
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the pinned bedrock wire lock"),
    )
    .expect("wire lock json");
    let mut counts: Vec<String> = lock[section]
        .as_object()
        .expect("lock section")
        .iter()
        .filter(|(_, v)| v["type"] == "integer")
        .filter_map(|(k, _)| k.strip_prefix(prefix).map(str::to_string))
        .filter(|k| k.starts_with("usage.") || k.starts_with("trace.guardrail."))
        .collect();
    counts.sort();
    counts
}

/// A lock path's class: `usage.<field>` from the usage table, a guardrail path by its side and
/// count. Panics on a count nobody classed.
fn class_of(path: &str) -> (Class, Option<(&'static str, String)>) {
    if let Some(field) = path.strip_prefix("usage.") {
        let class = BEDROCK_USAGE_CLASSES
            .iter()
            .find(|(f, _)| *f == field)
            .map(|(_, c)| *c)
            .unwrap_or_else(|| panic!("`{path}` is in the wire lock with no class"));
        return (class, None);
    }
    let (side, member) = [
        (
            "inputAssessment",
            "trace.guardrail.inputAssessment{}.invocationMetrics.",
        ),
        (
            "outputAssessments",
            "trace.guardrail.outputAssessments{}[].invocationMetrics.",
        ),
    ]
    .into_iter()
    .find_map(|(side, prefix)| path.strip_prefix(prefix).map(|m| (side, m)))
    .unwrap_or_else(|| panic!("`{path}` is in the wire lock with no class"));
    let class = match member.strip_prefix("usage.") {
        Some(count) if GUARDRAIL_COUNTS.contains(&count) => Class::GuardrailUnits,
        None if GUARDRAIL_METRICS.contains(&member) => Class::AssessmentMetric,
        _ => panic!("`{path}` is in the wire lock with no class"),
    };
    (class, Some((side, member.to_string())))
}

/// Two guardrails on `side`, each carrying 7 at `member` (a path below `invocationMetrics`).
fn guardrail_trace(side: &str, member: &str) -> serde_json::Value {
    let usage = member.rsplit('.').fold(
        serde_json::json!(7),
        |inner, key| serde_json::json!({ key: inner }),
    );
    let usage = serde_json::json!({ "invocationMetrics": usage });
    let assessment = |u: &serde_json::Value| {
        if side == "inputAssessment" {
            u.clone()
        } else {
            serde_json::json!([u])
        }
    };
    serde_json::json!({"guardrail": {side: {"g1": assessment(&usage), "g2": assessment(&usage)}}})
}

type Units = (i64, i64, i64, i64);

/// The open classes a usage ledgers, by class.
type Open = std::collections::BTreeMap<String, u64>;

/// One path's read: the ledgered units, the identity note, the 5m cache-write attribution, the
/// open classes.
type Read = (Units, Option<(u64, u64, i64)>, Option<u64>, Open);

fn units(u: &busbar_contract::billing::TokenUsage) -> Units {
    let n = |x: u64| i64::try_from(x).expect("small fixture");
    (
        n(u.input),
        n(u.cache_read.unwrap_or(0)),
        n(u.cache_creation.unwrap_or(0)),
        n(u.output),
    )
}

fn read_of(u: &crate::codec::ir::IrUsage) -> Read {
    let t = u.to_token_usage();
    assert!(
        t.residual_units.is_empty(),
        "no reported unit is a residual"
    );
    (
        units(&t),
        u.detail
            .usage_identity_note
            .as_ref()
            .map(|n| (n.reported_total, n.summed_total, n.unaccounted)),
        u.detail.cache_creation_5m_input_tokens,
        t.open_units,
    )
}

/// The read on each path: buffered, the stream's `metadata` frame, a truncated-body recovery (units
/// only).
fn read_all_paths(usage: &serde_json::Value, trace: Option<&serde_json::Value>) -> [Read; 3] {
    let mut body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": usage
    });
    let mut metadata = serde_json::json!({"type": "metadata", "usage": usage});
    if let Some(trace) = trace {
        body["trace"] = trace.clone();
        metadata["trace"] = trace.clone();
    }
    let buffered = BedrockReader.read_response(&body).expect("read").usage;
    let mut state = crate::codec::ir::StreamDecodeState::default();
    BedrockReader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        &mut state,
    );
    let streamed = BedrockReader
        .read_response_events("", &metadata, &mut state)
        .into_iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the metadata frame emits a MessageDelta");
    let recovered = BedrockReader
        .recover_truncated_usage(body.to_string().as_bytes())
        .expect("the trailing usage is recoverable");
    [
        read_of(&buffered),
        read_of(&streamed),
        (units(&recovered), None, None, recovered.open_units),
    ]
}

/// EVERY COUNT IN THE WIRE LOCK HAS A CLASS, AND THE READER HONOURS IT ON EVERY PATH. 7 more of a
/// ledgered count moves (input, cache read, cache write, output) by exactly its class; a per-TTL
/// cache-write entry moves nothing beyond its cache write and is attributed to its TTL; 7 more on
/// `totalTokens` alone is reported as a 7-unit gap and ledgers 7 `unitemized_tokens` (a truncated
/// body recovers the same `usage`, so the same 7); 7 of a guardrail count on each of two
/// guardrails ledgers 14 under that count's own class (buffered and streamed; a truncated body
/// recovers the turn's `usage` only). RED when the reader drops a count (a usage-table row, a
/// guardrail count), mis-classes one, stops checking the stated total, or the lock gains a count
/// nobody classed.
#[test]
fn every_usage_count_in_the_wire_lock_is_ledgered_in_its_class() {
    let counts = lock_counts("response", "");
    assert_eq!(
        counts,
        lock_counts("stream", "metadata."),
        "the stream's metadata frame carries the response's counts"
    );
    assert_eq!(
        counts.len(),
        BEDROCK_USAGE_CLASSES.len() + 2 * (GUARDRAIL_COUNTS.len() + GUARDRAIL_METRICS.len()),
        "the lock's counts {counts:?} each need exactly one class"
    );
    let base = serde_json::json!({"inputTokens": 1000, "outputTokens": 100, "totalTokens": 1100});
    let before = read_all_paths(&base, None);
    let open = |class: &str, n: u64| Open::from([(class.to_string(), n)]);
    for (path, read) in ["buffered", "streamed", "truncated"].iter().zip(&before) {
        assert_eq!(read.1, None, "{path}: the base usage reconciles");
    }
    for field in &counts {
        let (class, guardrail) = class_of(field);
        let mut usage = base.clone();
        let mut trace = None;
        let mut baseline = before.clone();
        let mut ttl_5m = None;
        let mut opened = Open::new();
        let mut truncated_opened = Open::new();
        let (moved, gap) = match class {
            Class::Ledgered(di, dc, dw, dout) => {
                let name = field.strip_prefix("usage.").expect("usage field");
                // 7 MORE than the base states (the base carries input and output already).
                usage[name] = serde_json::json!(base[name].as_u64().unwrap_or(0) + 7);
                // The stated total moves by what the count adds, so the identity still closes.
                let adds = u64::try_from(di + dc + dw + dout).expect("non-negative");
                usage["totalTokens"] = serde_json::json!(1100 + 7 * adds);
                ((7 * di, 7 * dc, 7 * dw, 7 * dout), None)
            }
            Class::CacheWriteTtlSlice => {
                usage["cacheWriteInputTokens"] = serde_json::json!(7);
                usage["totalTokens"] = serde_json::json!(1107);
                baseline = read_all_paths(&usage, None);
                usage["cacheDetails"] = serde_json::json!([{"ttl": "5m", "inputTokens": 7}]);
                ttl_5m = Some(7);
                ((0, 0, 0, 0), None)
            }
            Class::StatedTotal => {
                usage["totalTokens"] = serde_json::json!(1107);
                opened = open(crate::codec::ir::open_class::UNITEMIZED_TOKENS_CLASS, 7);
                truncated_opened = opened.clone();
                ((0, 0, 0, 0), Some((1107, 1100, 7)))
            }
            Class::GuardrailUnits | Class::AssessmentMetric => {
                let (side, member) = guardrail.as_ref().expect("a guardrail member");
                trace = Some(guardrail_trace(side, member));
                if let Class::GuardrailUnits = class {
                    let count = member.strip_prefix("usage.").expect("a policy-unit count");
                    let (_, class) = crate::codec::ir::open_class::GUARDRAIL_COUNT_CLASSES
                        .iter()
                        .find(|(c, _)| *c == count)
                        .expect("every guardrail count has a class");
                    opened = open(class, 14);
                }
                ((0, 0, 0, 0), None)
            }
        };
        let cap = WarnCapture::default();
        let after = tracing::subscriber::with_default(cap.clone(), || {
            read_all_paths(&usage, trace.as_ref())
        });
        for (path, (b, a)) in ["buffered", "streamed", "truncated"]
            .iter()
            .zip(baseline.iter().zip(after.iter()))
        {
            assert_eq!(
                (
                    a.0 .0 - b.0 .0,
                    a.0 .1 - b.0 .1,
                    a.0 .2 - b.0 .2,
                    a.0 .3 - b.0 .3
                ),
                moved,
                "{path}: `{field}` must move (input, cache read, cache write, output) by its class"
            );
            if *path != "truncated" {
                assert_eq!(a.1, gap, "{path}: `{field}` reports (total, ledgered, gap)");
                assert_eq!(a.2, ttl_5m, "{path}: `{field}` 5m cache-write attribution");
            }
            let want = if *path == "truncated" {
                &truncated_opened
            } else {
                &opened
            };
            assert_eq!(&a.3, want, "{path}: `{field}` ledgers its open class");
            assert!(b.3.is_empty(), "{path}: the base ledgers no open class");
        }
        if let (Class::AssessmentMetric, Some((_, member))) = (class, &guardrail) {
            assert!(
                !cap.messages().iter().any(|m| m.contains(member.as_str())),
                "`{field}` is no billed unit and is named on no WARN: {:?}",
                cap.messages()
            );
        }
    }
}

/// A TRUNCATED BODY RECOVERS THE TURN'S `usage`, NOT A GUARDRAIL'S. When `trace` follows the turn's
/// `usage`, the last `"usage"` in the tail is a guardrail's `invocationMetrics.usage`, which names
/// policy units and no token; it used to read as a zero-token turn.
#[test]
fn a_truncated_body_recovers_the_turns_usage_not_a_guardrails() {
    let tail = br#"...cut"}]}},"stopReason":"end_turn","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15},"trace":{"guardrail":{"inputAssessment":{"g1":{"invocationMetrics":{"usage":{"contentPolicyUnits":3,"topicPolicyUnits":1}}}}}}}"#;
    let u = BedrockReader
        .recover_truncated_usage(tail)
        .expect("the turn's usage is in the tail");
    assert_eq!((u.input, u.output), (10, 5));
    let only_guardrail =
        br#"...cut"}}},"trace":{"guardrail":{"inputAssessment":{"g1":{"invocationMetrics":{"usage":{"contentPolicyUnits":3}}}}}}}"#;
    assert_eq!(
        BedrockReader.recover_truncated_usage(only_guardrail),
        None,
        "a tail holding only a guardrail's usage recovers nothing (the caller's floor), never zero"
    );
}

/// A STATED TOTAL THAT DISAGREES WITH THE LEDGERED CLASSES: AWS counts cache tokens inside
/// `totalTokens`, so 10 in + 5 out + 1000 cache read + 200 cache write is 1215; a body stating 15
/// is reported (gap -1200), and the ledger holds the itemized counts: a total BELOW its terms is no
/// unit, so no `unitemized_tokens` line.
#[test]
fn a_total_that_disagrees_is_reported_never_ledgered() {
    let usage = serde_json::json!({
        "inputTokens": 10,
        "outputTokens": 5,
        "cacheReadInputTokens": 1000,
        "cacheWriteInputTokens": 200,
        "totalTokens": 15
    });
    let cap = WarnCapture::default();
    let read = tracing::subscriber::with_default(cap.clone(), || read_all_paths(&usage, None));
    for (path, r) in ["buffered", "streamed"].iter().zip(&read) {
        assert_eq!(r.0, (10, 1000, 200, 5), "{path}: the itemized counts only");
        assert_eq!(r.1, Some((15, 1215, -1200)), "{path}: the gap is reported");
        assert!(r.3.is_empty(), "{path}: no open class: {:?}", r.3);
    }
    assert!(
        cap.contains("usage does not reconcile") && cap.contains("identity=bedrock.usage"),
        "the gap is WARN-logged: {:?}",
        cap.messages()
    );
}

/// The ledger projection (`TokenUsage`) the buffered read and the stream's `metadata` frame each
/// carry.
fn usage_on_both_paths(
    usage: &serde_json::Value,
    trace: Option<&serde_json::Value>,
) -> [busbar_contract::billing::TokenUsage; 2] {
    let mut body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": usage
    });
    let mut metadata = serde_json::json!({"type": "metadata", "usage": usage});
    if let Some(trace) = trace {
        body["trace"] = trace.clone();
        metadata["trace"] = trace.clone();
    }
    let buffered = BedrockReader.read_response(&body).expect("read").usage;
    let mut state = crate::codec::ir::StreamDecodeState::default();
    BedrockReader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
        &mut state,
    );
    let streamed = BedrockReader
        .read_response_events("", &metadata, &mut state)
        .into_iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the metadata frame emits a MessageDelta");
    [buffered.to_token_usage(), streamed.to_token_usage()]
}

/// THE REPORTED UNITS TRAVEL ON THE USAGE, BILLED (owner LEDGER-100, 2026-10-03). Guardrail policy
/// units (7 on each of two guardrails, on both sides) and a stated total 7 above the itemized sum
/// each reach both ledger projections as exactly one line under their open class, on the buffered
/// read and the streamed one, while the token tiers stay the itemized counts and nothing is a
/// residual. A total BELOW its terms is no unit and adds none. RED before this lane: both were
/// residuals (`usage.residual`, unbilled).
#[test]
fn the_reported_units_travel_on_the_usage_billed() {
    use crate::codec::ir::open_class::{
        GUARDRAIL_TOPIC_POLICY_UNITS_CLASS, UNITEMIZED_TOKENS_CLASS,
    };
    let closes = serde_json::json!({"inputTokens": 1000, "outputTokens": 100, "totalTokens": 1100});
    let mut trace = guardrail_trace("inputAssessment", "usage.topicPolicyUnits");
    trace["guardrail"]["outputAssessments"] =
        guardrail_trace("outputAssessments", "usage.topicPolicyUnits")["guardrail"]
            ["outputAssessments"]
            .clone();
    for (path, u) in ["buffered", "streamed"]
        .iter()
        .zip(usage_on_both_paths(&closes, Some(&trace)))
    {
        assert!(u.residual_units.is_empty(), "{path}: no residual");
        assert_eq!((u.input, u.output), (1000, 100), "{path}: the token tiers");
        let lines = crate::codec::usage_census::ledgered(&u);
        assert_eq!(
            lines[crate::codec::usage_census::slot(GUARDRAIL_TOPIC_POLICY_UNITS_CLASS)],
            28,
            "{path}: 7 on each of two guardrails on both sides, one line"
        );
        assert_eq!(lines[4..].iter().filter(|n| **n != 0).count(), 1, "{path}");
    }
    let above = serde_json::json!({"inputTokens": 1000, "outputTokens": 100, "totalTokens": 1107});
    for (path, u) in ["buffered", "streamed"]
        .iter()
        .zip(usage_on_both_paths(&above, None))
    {
        assert!(u.residual_units.is_empty(), "{path}: no residual");
        assert_eq!((u.input, u.output), (1000, 100), "{path}: the token tiers");
        let lines = crate::codec::usage_census::ledgered(&u);
        assert_eq!(
            lines[crate::codec::usage_census::slot(UNITEMIZED_TOKENS_CLASS)],
            7,
            "{path}: the stated total above the itemized sum, one line"
        );
        assert_eq!(lines[4..].iter().filter(|n| **n != 0).count(), 1, "{path}");
    }
    let below = serde_json::json!({"inputTokens": 1000, "outputTokens": 100, "totalTokens": 15});
    for (path, u) in ["buffered", "streamed"]
        .iter()
        .zip(usage_on_both_paths(&below, None))
    {
        assert!(
            u.open_units.is_empty() && u.residual_units.is_empty(),
            "{path}: a total below its terms is no unit: {u:?}"
        );
    }
}

/// AN UNREADABLE GUARDRAIL COUNT REFUSES (#42, the rule every billed count reads under): it cannot
/// be ledgered, and a zero in its place is a bill that disagrees with AWS's invoice. `null` is
/// absence.
#[test]
fn an_unreadable_guardrail_count_refuses_and_null_is_absence() {
    let usage = serde_json::json!({"inputTokens": 10, "outputTokens": 5});
    let body = |units: serde_json::Value| {
        serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": usage,
            "trace": {"guardrail": {"inputAssessment": {"g1": {"invocationMetrics": {
                "usage": {"topicPolicyUnits": units}}}}}}
        })
    };
    assert!(BedrockReader
        .read_response(&body(serde_json::json!("seven")))
        .is_err());
    assert!(BedrockReader
        .read_response(&body(serde_json::json!(7.5)))
        .is_err());
    let absent = BedrockReader
        .read_response(&body(serde_json::Value::Null))
        .expect("null is absence")
        .usage
        .to_token_usage();
    assert!(absent.open_units.is_empty());
}
