// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit coverage for [`crate::ir::facts`] — the properties the projection owes, asserted against IR
//! values built by hand so that a failure here names the projection and never a reader.
//!
//! The CROSS-implementation coverage (this projection versus the raw-body one it replaces, over a
//! real corpus in every wire format) is `proxy/tests/hook_ir_differential_tests.rs`. These are the
//! properties that must hold regardless of what the other implementation does.

use super::*;
use crate::ir::{CacheControl, CacheKind, IrImageSource, IrMessage};
use serde_json::json;

fn text(t: &str) -> IrBlock {
    IrBlock::Text {
        text: t.to_string(),
        cache_control: None,
        citations: Vec::new(),
    }
}

fn turn(role: IrRole, content: Vec<IrBlock>) -> IrMessage {
    IrMessage { role, content }
}

fn req(system: Vec<IrBlock>, messages: Vec<IrMessage>) -> IrRequest {
    IrRequest {
        system,
        messages,
        ..IrRequest::default()
    }
}

/// The flat rendering a consumer builds: system text, then one `(role, joined text)` per turn.
/// Written here ONCE, the way [`project`]'s doc comment says to build it, so these tests exercise
/// the documented grouping rather than a private one.
fn flatten(r: &IrRequest) -> (Option<String>, Vec<(IrRole, String)>) {
    let items = project(r);
    let sys: Vec<String> = items
        .iter()
        .filter(|i| i.slot() == Slot::System)
        .map(|i| i.screenable_text().into_owned())
        .collect();
    let mut turns: Vec<(IrRole, Vec<String>)> = Vec::new();
    for i in &items {
        let Some(idx) = i.slot().turn_index() else {
            continue;
        };
        while turns.len() <= idx {
            turns.push((IrRole::User, Vec::new()));
        }
        turns[idx].0 = i.role();
        turns[idx].1.push(i.screenable_text().into_owned());
    }
    (
        Some(sys.join("\n")).filter(|s| !s.is_empty()),
        turns.into_iter().map(|(r, p)| (r, p.join("\n"))).collect(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OPACITY — the property this whole design turns on.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE BYPASS THAT MUST NOT REOPEN
///
/// All three opaque reasoning shapes project the MARKER, and none of them projects its payload.
/// Two of them park provider ciphertext in `Thinking.text` (so a naive `text` passthrough is a new
/// disclosure of provider ciphertext to the operator's sidecar); the third has EMPTY `text` with the
/// blob on `signature` (so a naive `if redacted` check shows a hook an empty turn for a request the
/// provider receives in full — the original bug, restored).
///
/// The three are asserted TOGETHER, in one test, because the defect was never "one shape is wrong":
/// it was that the three were decided in different places and only two of them agreed.
#[test]
fn every_opaque_reasoning_shape_projects_the_marker_and_never_its_payload() {
    let shapes = [
        // `text` IS the ciphertext, flagged by the reader.
        (
            "flagged, ciphertext in text",
            IrBlock::Thinking {
                text: "OPAQUE_CIPHERTEXT_BYTES".to_string(),
                signature: None,
                redacted: true,
                cache_control: None,
            },
            "OPAQUE_CIPHERTEXT_BYTES",
        ),
        // The same, with a signature alongside — still flagged, still ciphertext.
        (
            "flagged, ciphertext in text, signed",
            IrBlock::Thinking {
                text: "OPAQUE_BEDROCK_BYTES".to_string(),
                signature: Some("sig".to_string()),
                redacted: true,
                cache_control: None,
            },
            "OPAQUE_BEDROCK_BYTES",
        ),
        // NOT flagged: no plaintext at all, the whole payload is a carrier blob.
        (
            "unflagged, blob on the signature",
            IrBlock::Thinking {
                text: String::new(),
                signature: Some("OPAQUE_BLOB_XYZ".to_string()),
                redacted: false,
                cache_control: None,
            },
            "OPAQUE_BLOB_XYZ",
        ),
    ];

    for (name, block, payload) in shapes {
        let r = req(Vec::new(), vec![turn(IrRole::Assistant, vec![block])]);
        let items = project(&r);
        assert_eq!(items.len(), 1, "{name}: one block, one item");
        assert!(
            matches!(items[0], ContentItem::Opaque { .. }),
            "{name}: an opaque block must project as Opaque, not as text — a consumer has to be \
             able to tell 'nothing here' from 'something here I cannot show you'"
        );
        assert_eq!(
            items[0].screenable_text(),
            OPAQUE_CONTENT_MARKER,
            "{name}: the marker stands in for the payload"
        );
        assert_eq!(
            items[0].role(),
            IrRole::Assistant,
            "{name}: an opaque blob still has an author, and a policy asks who wrote it first"
        );
        let rendered = flatten(&r).1[0].1.clone();
        assert!(
            !rendered.contains(payload),
            "{name}: the payload reached the projection. That is a NEW DISCLOSURE to the \
             operator's hook sidecar, and for the unflagged shape it is the fixed bypass reopened."
        );
    }
}

/// Reasoning busbar CAN read is ordinary content and is shown. A client replaying a multi-turn body
/// sends this text to the provider, so a gate that cannot see it is a gate with a hole in it.
#[test]
fn readable_reasoning_is_projected_as_text() {
    let r = req(
        Vec::new(),
        vec![turn(
            IrRole::Assistant,
            vec![
                IrBlock::Thinking {
                    text: "CHAIN OF THOUGHT".to_string(),
                    signature: Some("sig".to_string()),
                    redacted: false,
                    cache_control: None,
                },
                text("the answer"),
            ],
        )],
    );
    assert_eq!(
        flatten(&r).1,
        vec![(
            IrRole::Assistant,
            "CHAIN OF THOUGHT\nthe answer".to_string()
        )],
        "block order is preserved and readable reasoning joins the turn's text"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE EMPTY-TURN RULE — the surviving half of the index-alignment contract.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A turn whose every block is structurally text-less still appears. The old contract's LETTER
/// (index alignment with the wire `messages` array) cannot survive the move onto the IR; its
/// PURPOSE — a screening hook sees every turn — is asserted here against `IrRequest::messages`.
#[test]
fn a_turn_with_no_projectable_content_still_appears() {
    let r = req(
        Vec::new(),
        vec![
            turn(IrRole::User, vec![text("before")]),
            turn(
                IrRole::User,
                vec![IrBlock::Image {
                    source: IrImageSource::Url("https://example.test/a.png".to_string()),
                    cache_control: None,
                }],
            ),
            turn(IrRole::Assistant, vec![text("after")]),
        ],
    );
    assert_eq!(
        flatten(&r).1,
        vec![
            (IrRole::User, "before".to_string()),
            (IrRole::User, String::new()),
            (IrRole::Assistant, "after".to_string()),
        ],
        "the media-only turn keeps its entry, with its role, and reads as empty rather than \
         vanishing — a hook told there are two turns where the provider sees three has been told \
         the request is something it is not"
    );
    assert_eq!(r.shape().turn_count, 3);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// SLOTS — the protocol dimension, carried as provenance.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Tool-call ARGUMENTS and tool-result CONTENT are projected, attributed to the turn that carried
/// them, and distinguishable from ordinary prose by their slot. The arguments are the half no
/// projection saw before this module: attacker-influenceable, sent upstream verbatim.
#[test]
fn tool_arguments_and_results_carry_the_turn_they_belong_to() {
    let r = req(
        Vec::new(),
        vec![
            turn(IrRole::User, vec![text("run it")]),
            turn(
                IrRole::Assistant,
                vec![IrBlock::ToolUse {
                    id: "c1".to_string(),
                    name: "search".to_string(),
                    input: json!({"q": "ARGUMENT PAYLOAD"}),
                    cache_control: None,
                    thought_signature: None,
                }],
            ),
            turn(
                IrRole::Tool,
                vec![IrBlock::ToolResult {
                    tool_use_id: "c1".to_string(),
                    content: vec![text("TOOL RESULT PAYLOAD")],
                    is_error: false,
                    cache_control: None,
                }],
            ),
        ],
    );
    let items = project(&r);
    let slots: Vec<Slot> = items.iter().map(ContentItem::slot).collect();
    assert_eq!(
        slots,
        vec![Slot::Turn(0), Slot::ToolArgs(1), Slot::ToolResult(2)],
        "each tool slot names the TURN it belongs to, so a guardrail can attribute a payload to \
         the exchange that produced it"
    );
    assert_eq!(
        slots.iter().map(|s| s.turn_index()).collect::<Vec<_>>(),
        vec![Some(0), Some(1), Some(2)],
    );
    assert!(
        items[1].screenable_text().contains("ARGUMENT PAYLOAD"),
        "the arguments are visible; nothing projected them before"
    );
    assert_eq!(items[2].screenable_text(), "TOOL RESULT PAYLOAD");
    assert_eq!(
        items[2].role(),
        IrRole::Tool,
        "the result keeps the authoring role of the turn that carried it"
    );
}

/// The system slot is its own slot, never turn 0, on every dialect — because on the IR there is one
/// place a system prompt lives and the reader already put it there. This is the mechanical reason
/// the shipped system-prompt-shredding bug cannot exist under this projection: there is no dialect
/// on which the operator's instructions arrive as an ordinary turn.
#[test]
fn the_system_prompt_is_its_own_slot_and_never_a_turn() {
    let r = req(
        vec![text("one"), text("two")],
        vec![turn(IrRole::User, vec![text("hi")])],
    );
    let (system, turns) = flatten(&r);
    assert_eq!(system.as_deref(), Some("one\ntwo"));
    assert_eq!(turns, vec![(IrRole::User, "hi".to_string())]);
    assert_eq!(
        r.shape().turn_count,
        1,
        "the system prompt does not inflate the turn count"
    );
}

/// A request with no system prompt yields no system items at all — "absent" and "present but empty"
/// stay distinguishable, which is what a hook keys its grant detection off.
#[test]
fn an_absent_system_prompt_projects_no_system_items() {
    let r = req(Vec::new(), vec![turn(IrRole::User, vec![text("hi")])]);
    assert_eq!(flatten(&r).0, None);
    assert!(project(&r).iter().all(|i| i.slot() != Slot::System));
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// SHAPE — the signals, and the drift that cannot happen any more.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE TRIPWIRE THAT IS NOW A STRUCTURAL FACT
///
/// `Shape::text_chars` is a SUM over the same items a content-granted hook is shown, so the size
/// signal and the content projection cannot drift apart. The two tripwires this supersedes
/// (`system_text_chars_counts_block_arrays`, `size_signal_and_projection_agree_on_reasoning`) were
/// written because two functions computing the same answer diverged once. There is one function
/// now; this test states the invariant that makes the tripwires unnecessary rather than merely
/// passing.
#[test]
fn text_chars_is_exactly_what_a_content_granted_hook_is_shown() {
    let r = req(
        vec![text("SYSTEM")],
        vec![
            turn(IrRole::User, vec![text("hello"), text("again")]),
            turn(
                IrRole::Assistant,
                vec![IrBlock::Thinking {
                    text: "ciphertext".to_string(),
                    signature: None,
                    redacted: true,
                    cache_control: None,
                }],
            ),
            turn(
                IrRole::User,
                vec![IrBlock::Image {
                    source: IrImageSource::Url("https://example.test/a.png".to_string()),
                    cache_control: None,
                }],
            ),
        ],
    );
    let shown: usize = project(&r)
        .iter()
        .map(|i| i.screenable_text().chars().count())
        .sum();
    assert_eq!(r.shape().text_chars, shown);
    assert_eq!(
        r.shape().text_chars,
        6 + 5 + 5 + OPAQUE_CONTENT_MARKER.chars().count(),
        "system + both text blocks + the marker standing in for the opaque one; the media-only \
         turn's empty entry contributes nothing"
    );
}

/// The `max_tokens` signal is the READER's normalized value, whatever field the dialect spelled it
/// in. Reading it here is a fix rather than a move: the raw-body projection is dialect-aware for one
/// dialect's spelling only, and a body that spells the cap in a nested config object reads `None`
/// there while the provider receives the cap in full.
#[test]
fn the_shape_signals_come_from_the_normalized_ir() {
    let r = IrRequest {
        messages: vec![turn(IrRole::User, vec![text("hi")])],
        max_tokens: Some(128),
        tools: Vec::new(),
        stream: true,
        user: Some("alice".to_string()),
        ..IrRequest::default()
    };
    assert_eq!(r.shape().max_tokens, Some(128));
    assert!(!r.shape().has_tools);
    assert!(r.wants_stream());
    assert_eq!(r.end_user(), Some("alice"));
    assert_eq!(r.verb(), Operation::Chat);
    assert_eq!(
        r.content(),
        project(&r),
        "the family-blind seam and the family's own walk are the SAME projection — the trait is \
         where a second protocol family plugs in, never a second answer for this one"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE MARKER — pinned against the implementation this one replaces.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The marker is BYTE-IDENTICAL to the one the raw-body projection substitutes today.
///
/// Both constants exist for the duration of the changeover: this module cannot depend on
/// `proxy/hooks.rs` (the dependency runs the other way, and inverting it is the whole point), and
/// `proxy/hooks.rs` must not change while it is still the live implementation. This test is what
/// makes the duplication safe: the day the cutover lands, the shape both implementations already
/// agreed on must not ALSO become a wire change for the operator's sidecar.
#[test]
fn opaque_marker_is_byte_identical_to_the_projection_it_replaces() {
    // The projection this replaced is GONE, so the comparison can no longer be made against it.
    // What survives, and is the thing that mattered, is the literal itself: this exact string is
    // what every deployed hook already receives for an opaque reasoning turn, and the cutover was
    // not allowed to also be a wire change for the one shape both implementations agreed on.
    assert_eq!(OPAQUE_CONTENT_MARKER, "[busbar:redacted_reasoning]");
}

/// Structured tool-result members are content, not silence. A dialect's `{"json": …}`
/// tool-result member reaches the IR as [`IrBlock::Json`] and is projected — it is exactly the
/// "largest untrusted blob in a modern agent request" class the content grant exists to screen.
#[test]
fn a_structured_tool_result_member_is_projected_as_data() {
    let r = req(
        Vec::new(),
        vec![turn(
            IrRole::Tool,
            vec![IrBlock::ToolResult {
                tool_use_id: "c1".to_string(),
                content: vec![IrBlock::Json(json!({"rows": ["UNTRUSTED"]}))],
                is_error: false,
                cache_control: None,
            }],
        )],
    );
    let items = project(&r);
    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0],
        ContentItem::Data {
            label: LABEL_JSON,
            slot: Slot::ToolResult(0),
            ..
        }
    ));
    assert!(items[0].screenable_text().contains("UNTRUSTED"));
}

/// A cache breakpoint on a block changes nothing about what is projected. Recorded because
/// `cache_control` is the field most likely to be added to a block in a future unit, and a walk that
/// accidentally keyed on it would be a silent content-visibility change.
#[test]
fn cache_breakpoints_do_not_change_what_is_projected() {
    let r = req(
        Vec::new(),
        vec![turn(
            IrRole::User,
            vec![IrBlock::Text {
                text: "hello".to_string(),
                cache_control: Some(CacheControl {
                    kind: CacheKind::Ephemeral,
                }),
                citations: Vec::new(),
            }],
        )],
    );
    assert_eq!(flatten(&r).1, vec![(IrRole::User, "hello".to_string())]);
}
