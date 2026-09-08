//! A provider that says it used more than busbar could account for.
//!
//! The codec goes to some trouble to notice this. A Gemini answer states its own
//! `usageMetadata.totalTokenCount`, the reader sums the buckets it decoded, and where the two
//! disagree it builds a note carrying the stated total, the summed total and the signed shortfall —
//! and the streaming fold threads that note through every chunk on purpose, so a discrepancy seen
//! on any one of them survives to the end of the stream.
//!
//! Nothing reads it. Not the plane, not the money path, not the journal. A turn whose provider
//! reported one total against a smaller sum of decoded buckets is metered on the smaller number and
//! the note saying the rest is unaccounted for goes nowhere. The mechanism built to notice a
//! provider under-reporting is wired to nothing at all.
//!
//! # This test is RED BY DESIGN and must stay that way until an owner decides
//!
//! Fixing it moves MONEY, and the shape of the fix is a decision rather than a patch:
//!
//! * The plane's job is to LOCATE quantities, never to compute one. So the shortfall must not be
//!   folded into `tokens_in` or any other existing line — that is shifting a quantity onto a class
//!   it does not belong to, which is a money defect in its own right and would silently change what
//!   every recorded Gemini cell bills.
//! * What the plane CAN honestly do is locate the shortfall as its own quantity, under a class of
//!   its own, and leave what to do with it — price it, alert on it, dispute the posting — to the
//!   unit that prices things. That is the seam the metering step already is.
//! * Which means a new declared meter class, and a declared class with no rate REFUSES the unit.
//!   So this cannot land without the class being declared, priced (or explicitly allowed unpriced),
//!   registered in the change log and reconciled against the recorded Gemini cells.
//!
//! The codec's own contract also disagrees with the naive reading, and deliberately: it says in so
//! many words that nothing is zeroed, clamped or back-filled to make the sum close, that the
//! decoded buckets stay exactly as the provider sent them, and that the answer to a discrepancy is
//! a new recording and a new table entry rather than an adjustment. This test does not argue with
//! that. It asserts only that the discrepancy REACHES the money path instead of being computed,
//! threaded and dropped.
//!
//! Remove the `#[ignore]` when the class is declared and priced. Do not remove it any other way,
//! and do not soften the assertion into a test of what the plane does today.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Plane, Progress};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};

/// One configured upstream, speaking the dialect that reports a total of its own.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-gemini"),
    host: "gemini.invalid",
    dialect: "gemini",
    model: "gemini-2.0-flash",
}];

/// The request that opens the unit.
const REQUEST: &str = r#"{"contents":[{"role":"user","parts":[{"text":"Hello"}]}]}"#;

/// An answer whose stated total is larger than the buckets it states.
///
/// A hundred prompt tokens and fifty candidate tokens is a hundred and fifty; the provider says two
/// hundred. Fifty tokens were charged for by the provider and decoded into no bucket busbar knows.
const UNDER_REPORTED: &str = r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},
"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50,
"totalTokenCount":200}}"#;

/// Meter one answer and return the lines as (class, quantity) pairs.
fn meter(answer: &str) -> Vec<(String, Option<u64>)> {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("gemini"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("gemini.invalid", LaneId::new("lane-gemini"));

    let request = vec![harness::frame(REQUEST.as_bytes())];
    let mut cursor = FrameCursor::new(&request);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("decodes")
    {
        busbar_contract::plane::Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);

    let frames = vec![harness::frame(answer.as_bytes())];
    let mut answers = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("reads the answer")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer must be terminal, got {other:?}"),
    };
    plane
        .meter(&unit, &response, &ctx)
        .lines
        .as_slice()
        .iter()
        .map(|l| (l.class.as_str().to_string(), l.quantity))
        .collect()
}

/// A provider that charges for more than busbar decoded has that shortfall LOCATED, not dropped.
///
/// The number the customer is invoiced on is the provider's own stated total. Metering the smaller
/// sum and discarding the note is busbar quietly deciding the provider is wrong, on the one axis
/// where being quietly wrong costs the operator money on every affected turn.
#[test]
#[ignore = "RED BY DESIGN: the codec detects a provider usage shortfall and nothing reads it. The \
            fix needs a declared meter class for the unaccounted quantity, a rate for it, and a \
            registered change against the recorded gemini cells — an owner decision, not a patch"]
fn a_provider_usage_shortfall_reaches_the_money_path() {
    let lines = meter(UNDER_REPORTED);
    let accounted: u64 = lines.iter().filter_map(|(_, q)| *q).sum();
    assert_eq!(
        accounted, 200,
        "the provider charged for 200 tokens and the metering step located {accounted}; the \
         shortfall the codec detected reaches nothing"
    );
}

/// The reading the fix must NOT take, pinned so the mistake is visible if anyone makes it.
///
/// Folding the shortfall into an existing class would make the assertion above pass while putting
/// tokens on a class they were not consumed under. This checks the four classes still partition
/// exactly what the buckets say, so a fix that closes the gap the wrong way goes red here.
#[test]
fn the_shortfall_is_never_folded_into_a_class_it_was_not_consumed_under() {
    let lines = meter(UNDER_REPORTED);
    let of = |class: &str| -> Option<u64> {
        lines.iter().find(|(c, _)| c == class).and_then(|(_, q)| *q)
    };
    assert_eq!(
        of("tokens_in"),
        Some(100),
        "the input line must state the input bucket the provider stated, and nothing else"
    );
    assert_eq!(
        of("tokens_out"),
        Some(50),
        "the output line must state the output bucket the provider stated, and nothing else"
    );
}
