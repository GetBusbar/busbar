// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY RESPONSES USAGE COUNT IS LEDGERED, A DECLARED SLICE, OR THE CHECKED TOTAL (MONEY-AUDIT
//! A-F4). The census is the pinned wire lock (`testing/llm-conformance/wire/responses.wire.json`):
//! every integer member under `usage` has a declared class below, and the reader is driven on the
//! buffered response, the streamed `response.completed` terminal and a truncated-body recovery to
//! prove the class. `total_tokens` is OpenAI's sum, never a unit: a gap between it and the
//! ledgered classes is reported on the usage identity note (with its WARN) and never ledgered.

use super::*;
use crate::codec::ir::StreamDecodeState;

/// What one `usage` count IS, per OpenAI's usage semantics.
#[derive(Clone, Copy, Debug)]
enum Class {
    /// A ledgered count: the move one more reported unit makes on (input, cache read, cache write,
    /// output).
    Ledgered(i64, i64, i64, i64),
    /// A slice inside the named ledgered count: attribution, never ledgered a second time.
    SliceOf(&'static str),
    /// The provider's stated total: checked against the ledgered classes, never a unit.
    StatedTotal,
}

/// Every count the wire lock declares under `usage`, by its path below `usage`.
const RESPONSES_COUNT_CLASSES: &[(&str, Class)] = &[
    ("input_tokens", Class::Ledgered(1, 0, 0, 0)),
    (
        "input_tokens_details.cached_tokens",
        Class::Ledgered(-1, 1, 0, 0),
    ),
    (
        "input_tokens_details.cache_write_tokens",
        Class::Ledgered(-1, 0, 1, 0),
    ),
    ("output_tokens", Class::Ledgered(0, 0, 0, 1)),
    (
        "output_tokens_details.reasoning_tokens",
        Class::SliceOf("output_tokens"),
    ),
    ("total_tokens", Class::StatedTotal),
];

/// The integer members the pinned wire lock declares under `usage` on a response, by their path
/// below `usage`.
fn lock_usage_counts() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/llm-conformance/wire/responses.wire.json");
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the pinned responses wire lock"),
    )
    .expect("wire lock json");
    lock["response"]
        .as_object()
        .expect("lock section")
        .iter()
        .filter(|(_, v)| v["type"] == "integer")
        .filter_map(|(k, _)| k.strip_prefix("usage.").map(str::to_string))
        .collect()
}

/// Add `by` to the count at `path` (dotted, below `usage`), creating parents as needed.
fn bump(usage: &mut serde_json::Value, path: &str, by: u64) {
    let mut at = usage;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            let was = at
                .get(part)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            at[part] = serde_json::json!(was + by);
        } else {
            if at.get(part).is_none() {
                at[part] = serde_json::json!({});
            }
            at = &mut at[part];
        }
    }
}

type Units = (i64, i64, i64, i64);
type Note = Option<(u64, u64, i64)>;

fn units(u: &busbar_contract::billing::TokenUsage) -> Units {
    let n = |x: u64| i64::try_from(x).expect("small fixture");
    (
        n(u.input),
        n(u.cache_read.unwrap_or(0)),
        n(u.cache_creation.unwrap_or(0)),
        n(u.output),
    )
}

fn note_of(u: &crate::codec::ir::IrUsage) -> Note {
    u.detail
        .usage_identity_note
        .as_ref()
        .map(|n| (n.reported_total, n.summed_total, n.unaccounted))
}

/// The ledgered units and the identity note on each read path: buffered, streamed, truncated
/// (the truncated recovery carries units only).
fn read_all_paths(usage: &serde_json::Value) -> [(Units, Note); 3] {
    let body = serde_json::json!({
        "id": "resp_census",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [{
            "type": ITEM_TYPE_MESSAGE,
            "role": "assistant",
            "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
        }],
        "usage": usage
    });
    let buffered = ResponsesReader.read_response(&body).expect("read").usage;
    let completed = serde_json::json!({
        "response": {"status": STATUS_COMPLETED, "usage": usage}
    });
    let streamed = ResponsesReader
        .read_response_events(
            EVT_RESPONSE_COMPLETED,
            &completed,
            &mut StreamDecodeState::default(),
        )
        .into_iter()
        .find_map(|e| match e {
            crate::codec::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("response.completed emits a MessageDelta");
    let recovered = ResponsesReader
        .recover_truncated_usage(body.to_string().as_bytes())
        .expect("the trailing usage is recoverable");
    [
        (units(&buffered.to_token_usage()), note_of(&buffered)),
        (units(&streamed.to_token_usage()), note_of(&streamed)),
        (units(&recovered), None),
    ]
}

/// EVERY COUNT IN THE WIRE LOCK HAS A CLASS, AND THE READER HONOURS IT ON EVERY PATH. Reporting 7
/// more of a ledgered count moves (input, cache read, cache write, output) by exactly its class; 7
/// more of a slice moves nothing; 7 more on `total_tokens` alone ledgers nothing and is reported
/// as a 7-unit gap. RED when the reader drops a ledgered count (a usage-table row removed),
/// mis-classes one, stops checking the stated total, or the lock gains a count nobody classed.
#[test]
fn every_usage_count_in_the_wire_lock_is_ledgered_or_a_declared_slice() {
    let counts = lock_usage_counts();
    assert_eq!(
        counts.len(),
        RESPONSES_COUNT_CLASSES.len(),
        "the lock's usage counts {counts:?} each need exactly one class"
    );
    let base =
        serde_json::json!({"input_tokens": 1000, "output_tokens": 100, "total_tokens": 1100});
    let before = read_all_paths(&base);
    for (path, (_, note)) in ["buffered", "streamed", "truncated"].iter().zip(&before) {
        assert_eq!(*note, None, "{path}: the base usage reconciles");
    }
    for field in &counts {
        let class = RESPONSES_COUNT_CLASSES
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, c)| *c)
            .unwrap_or_else(|| panic!("`usage.{field}` is in the wire lock with no class"));
        let mut usage = base.clone();
        bump(&mut usage, field, 7);
        let (moved, gap) = match class {
            Class::Ledgered(di, dc, dw, dout) => {
                // The stated total moves by what the count adds to the ledgered classes, so the
                // identity still closes.
                let adds = u64::try_from(di + dc + dw + dout).expect("non-negative");
                bump(&mut usage, "total_tokens", 7 * adds);
                ((7 * di, 7 * dc, 7 * dw, 7 * dout), None)
            }
            Class::SliceOf(parent) => {
                assert!(
                    RESPONSES_COUNT_CLASSES
                        .iter()
                        .any(|(f, c)| *f == parent && matches!(c, Class::Ledgered(..))),
                    "`{field}` is declared a slice of `{parent}`, which must be ledgered"
                );
                ((0, 0, 0, 0), None)
            }
            Class::StatedTotal => ((0, 0, 0, 0), Some((1107, 1100, 7))),
        };
        let after = read_all_paths(&usage);
        for (path, ((b, _), (a, note))) in ["buffered", "streamed", "truncated"]
            .iter()
            .zip(before.iter().zip(after.iter()))
        {
            assert_eq!(
                (a.0 - b.0, a.1 - b.1, a.2 - b.2, a.3 - b.3),
                moved,
                "{path}: 7 more `{field}` must move (input, cache read, cache write, output) by its class"
            );
            if *path != "truncated" {
                assert_eq!(
                    *note, gap,
                    "{path}: 7 more `{field}` reports (total, ledgered, gap)"
                );
            }
        }
    }
}

/// A STATED TOTAL ABOVE ITS TERMS (a compatible backend counting reasoning outside
/// `output_tokens`): total 35 against input 10 + output 5. The ledger holds what the counts itemize
/// (10 in, 5 out); the 20-unit gap is reported with its WARN and never ledgered.
#[test]
fn a_total_above_the_ledgered_classes_is_reported_never_ledgered() {
    let usage = serde_json::json!({
        "input_tokens": 10,
        "output_tokens": 5,
        "output_tokens_details": {"reasoning_tokens": 20},
        "total_tokens": 35
    });
    let cap = busbar_contract::testkit::WarnCapture::default();
    let read = tracing::subscriber::with_default(cap.clone(), || read_all_paths(&usage));
    for (path, (units, note)) in ["buffered", "streamed"].iter().zip(&read) {
        assert_eq!(*units, (10, 0, 0, 5), "{path}: the itemized counts only");
        assert_eq!(*note, Some((35, 15, 20)), "{path}: the gap is reported");
    }
    assert_eq!(
        read[2].0,
        (10, 0, 0, 5),
        "truncated: the itemized counts only"
    );
    assert!(
        cap.contains("usage does not reconcile") && cap.contains("unaccounted=20"),
        "the gap is WARN-logged: {:?}",
        cap.messages()
    );
}
