// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIFFERENTIAL TEST, INVERTED — the corpus that proved busbar had two answers to "what is the
//! text in this request", now guarding the one answer that is left.
//!
//! # What this file WAS
//!
//! busbar had two implementations. One was the hook prompt projection, built from the **raw ingress
//! body**, carrying its own content flattening and its own per-dialect dispatch across thirty-eight
//! branch arms. The other was `proto/*/reader.rs`, which normalizes the same body into `IrRequest`.
//! They disagreed, and the disagreement was security-shaped rather than untidy: a PII/DLP gate wired
//! as a `prompt: ro` hook screened the first view while the request that went upstream was built
//! from the second — **so a redactor could pass a request whose real payload it never saw.** One
//! instance of that class had already shipped and been fixed as a one-off.
//!
//! This file compared the two, fixture by fixture, across all six wire formats, and it went RED on
//! nine of them. That was the deliverable: the defect stated as a failing test rather than as a
//! paragraph.
//!
//! # What this file IS
//!
//! **The cutover landed and the raw-body projection is gone, so there is no longer a second view to
//! compare against.** The comparison could not survive that and was never meant to: its own plan
//! said it INVERTS — the same corpus and the same normalization now compare the surviving
//! projection against a PINNED GOLDEN per fixture, so the one implementation cannot drift either.
//!
//! Two things are asserted here, and the second is the one that carries the argument:
//!
//!   * [`the_surviving_projection_matches_its_pinned_golden`] — every fixture's projected view,
//!     pinned field by field. A change to `ir::facts`, to any reader, or to what a hook is shown
//!     lands here as a diff a reviewer reads.
//!   * [`the_nine_intended_divergences_are_the_ones_that_landed`] — the nine rows this file was RED
//!     on are re-asserted as the NEW behaviour, each naming what an operator now sees that they did
//!     not before. The old diff list was a list of bugs; the same list is now a list of the
//!     CHANGELOG entries that shipped, checked rather than claimed. A row that did NOT change is a
//!     cutover that did not do what it said.
//!
//! The corpus is protocol-blind — `crate::proto_codec::protocol_for(f.proto)`, no protocol name anywhere in the walk —
//! so a seventh protocol joins by appearing in `KNOWN_PROTOCOLS` and getting fixtures. If it ever
//! needs an arm here, the standard is not held.
//!
//! Sibling coverage that is not duplicated here: `hook_ir_divergence_characterisation_tests.rs`
//! pins each individual divergence with the reasoning for what the RIGHT behaviour is. This file is
//! the SWEEP.

use super::*;
use crate::ir::IrRequest;
use busbar_substrate_values::ir::facts::IrFacts;
use busbar_substrate_values::proto::known_protocols;
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE NORMALIZED VIEW — the canonical form both implementations reduce to.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One request, as seen by ONE of the two implementations.
///
/// Every field is something a shipped hook actually receives: `system`/`turns` are the `prompt: ro`
/// content projection, `text_chars` is the `total_chars` SIZE signal, `max_tokens` and `end_user`
/// are the other two dialect-aware body reads on the same seam.
#[derive(Debug, PartialEq, Eq)]
struct View {
    system: Option<String>,
    turns: Vec<(String, String)>,
    text_chars: usize,
    max_tokens: Option<u32>,
    end_user: Option<String>,
}

/// A corpus entry: a real request body at a named ingress protocol.
struct Fixture {
    name: &'static str,
    proto: &'static str,
    body: Value,
}

/// THE view: the protocol's real reader, then the surviving projection.
///
/// `Err` is a first-class outcome, not a test failure: five readers hard-reject bodies the deleted
/// projection screened happily, and turning that asymmetry into a 400 is one of the shipped
/// behaviour changes rather than an accident of this test.
fn ir_view(f: &Fixture) -> Result<View, String> {
    let proto = crate::proto_codec::protocol_for(f.proto)
        .unwrap_or_else(|| panic!("no protocol registered for '{}'", f.proto));
    let ir = proto
        .reader()
        .read_request(&f.body)
        .map_err(|e| format!("{e:?}"))?;
    Ok(project_ir(&ir))
}

/// Reduce the successor projection to the same [`View`] the LHS reduces to.
///
/// This is the ONLY place the differential still does any flattening of its own, and it is
/// deliberately the grouping `ir::facts::project` documents rather than a private one: group the
/// item stream on `Slot::turn_index`, take the role from the items, join with a newline. The
/// system slot is its own bucket and is never merged into the turn list — structural difference is
/// what this file is for.
///
/// `text_chars` and `max_tokens` come from `IrFacts::shape()` and the end-user id from
/// `IrFacts::end_user()`, so the SIZE-signal half of the comparison exercises the production
/// accessors too and not just the content walk.
fn project_ir(ir: &IrRequest) -> View {
    let mut system_pieces: Vec<String> = Vec::new();
    let mut turns: Vec<(String, Vec<String>)> = Vec::new();
    for item in crate::ir::project(ir) {
        let piece = item.screenable_text().into_owned();
        match item.slot().turn_index() {
            None => system_pieces.push(piece),
            Some(i) => {
                while turns.len() <= i {
                    turns.push((String::new(), Vec::new()));
                }
                turns[i].0 = item.author().to_string();
                turns[i].1.push(piece);
            }
        }
    }
    let shape = ir.shape();
    View {
        system: Some(system_pieces.join("\n")).filter(|s| !s.is_empty()),
        turns: turns
            .into_iter()
            .map(|(role, pieces)| (role, pieces.join("\n")))
            .collect(),
        // Counted like the SIZE signal counts: text, never the join separators.
        text_chars: shape.text_chars,
        max_tokens: shape.max_tokens,
        end_user: ir.end_user().map(str::to_string),
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CORPUS — every wire format, plus the shapes that were each once a bug.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Real request bodies across all six formats.
///
/// It carries the eight shapes today's projection tests were written for, because each one was once
/// a defect (an in-band system turn, an Anthropic `thinking` block, a Bedrock `reasoningContent`, a
/// Responses summary-only `reasoning` item, a Responses `encrypted_content`-only item with
/// `content: []`, a Gemini `thought: true` part, a media-only turn, a tool-result turn), a plain
/// baseline per dialect so an "agreeing" row is real evidence rather than an absence of coverage,
/// and the shapes named as divergences.
fn corpus() -> Vec<Fixture> {
    vec![
        // ── OPENAI ────────────────────────────────────────────────────────────────────────────
        Fixture {
            name: "openai_plain",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "max_tokens": 256,
                "user": "alice",
                "messages": [
                    {"role": "user", "content": "hello"},
                    {"role": "assistant", "content": "hi there"}
                ]
            }),
        },
        Fixture {
            name: "openai_block_array_content",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "first"},
                    {"type": "text", "text": "second"}
                ]}]
            }),
        },
        // The divergence that already shipped a bug: the operator's system prompt in `messages[0]`.
        Fixture {
            name: "openai_in_band_system_turn",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
                    {"role": "user", "content": "hi"}
                ]
            }),
        },
        // A media-only turn: the shape the index-alignment contract exists for.
        Fixture {
            name: "openai_media_only_turn",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://example.test/a.png"}}
                ]}]
            }),
        },
        // A guardrail cannot currently screen a replayed refusal.
        Fixture {
            name: "openai_refusal_part",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "assistant", "content": [
                    {"type": "refusal", "refusal": "I cannot help with that"}
                ]}]
            }),
        },
        // Tool call + tool result. The ARGUMENTS are the half the projection cannot see.
        Fixture {
            name: "openai_tool_call_and_result",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [
                        {"id": "c1", "type": "function",
                         "function": {"name": "search", "arguments": "{\"q\":\"ARGUMENT PAYLOAD\"}"}}
                    ]},
                    {"role": "tool", "tool_call_id": "c1", "content": "TOOL RESULT PAYLOAD"}
                ]
            }),
        },
        // THE SEVENTH DIVERGENCE AS RECORDED — a tool-role message's BARE-STRING content, claimed
        // to be counted by `total_text_chars` and never projected. See
        // `tool_role_bare_string_content_is_counted_and_projected_alike` below for what actually
        // happens.
        Fixture {
            name: "openai_tool_role_bare_string_only",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "user", "content": "run the tool"},
                    {"role": "tool", "tool_call_id": "c1", "content": "TOOL RESULT PAYLOAD"}
                ]
            }),
        },
        // A top-level `system` key on an OpenAI body: projected as a system prompt, swept into
        // `extra` by the reader.
        Fixture {
            name: "openai_top_level_system_key",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "system": "TOP LEVEL SYSTEM",
                "messages": [{"role": "user", "content": "hi"}]
            }),
        },
        // A role five readers refuse and the projection screens as `role: "wizard"`.
        Fixture {
            name: "openai_unknown_role",
            proto: "openai",
            body: serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "wizard", "content": "hi"}]
            }),
        },
        // ── ANTHROPIC ─────────────────────────────────────────────────────────────────────────
        Fixture {
            name: "anthropic_plain",
            proto: "anthropic",
            body: serde_json::json!({
                "model": "claude", "max_tokens": 64,
                "system": "SYSTEM",
                "metadata": {"user_id": "bob"},
                "messages": [{"role": "user", "content": "hello"}]
            }),
        },
        Fixture {
            name: "anthropic_system_block_array",
            proto: "anthropic",
            body: serde_json::json!({
                "model": "claude", "max_tokens": 64,
                "system": [{"type": "text", "text": "one"}, {"type": "text", "text": "two"}],
                "messages": [{"role": "user", "content": "hello"}]
            }),
        },
        Fixture {
            name: "anthropic_thinking_block",
            proto: "anthropic",
            body: serde_json::json!({
                "model": "claude", "max_tokens": 64,
                "messages": [{"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "CHAIN OF THOUGHT", "signature": "sig"},
                    {"type": "text", "text": "the answer"}
                ]}]
            }),
        },
        // The IR parks provider ciphertext in `Thinking.text`; the projection substitutes a marker.
        Fixture {
            name: "anthropic_redacted_thinking",
            proto: "anthropic",
            body: serde_json::json!({
                "model": "claude", "max_tokens": 64,
                "messages": [{"role": "assistant", "content": [
                    {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
                ]}]
            }),
        },
        // ── BEDROCK ───────────────────────────────────────────────────────────────────────────
        Fixture {
            name: "bedrock_plain",
            proto: "bedrock",
            body: serde_json::json!({
                "system": [{"text": "sys"}],
                "messages": [{"role": "user", "content": [{"text": "hello"}, {"text": "again"}]}]
            }),
        },
        // `inferenceConfig.maxTokens` is Bedrock's spelling of the cap.
        Fixture {
            name: "bedrock_inference_config_max_tokens",
            proto: "bedrock",
            body: serde_json::json!({
                "inferenceConfig": {"maxTokens": 128},
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            }),
        },
        Fixture {
            name: "bedrock_reasoning_content",
            proto: "bedrock",
            body: serde_json::json!({
                "messages": [{"role": "assistant", "content": [
                    {"reasoningContent": {"reasoningText": {"text": "BEDROCK COT", "signature": "s"}}},
                    {"text": "the answer"}
                ]}]
            }),
        },
        Fixture {
            name: "bedrock_redacted_content",
            proto: "bedrock",
            body: serde_json::json!({
                "messages": [{"role": "assistant", "content": [
                    {"reasoningContent": {"redactedContent": "OPAQUE_BEDROCK_BYTES"}}
                ]}]
            }),
        },
        // ── GEMINI ────────────────────────────────────────────────────────────────────────────
        Fixture {
            name: "gemini_plain",
            proto: "gemini",
            body: serde_json::json!({
                "systemInstruction": {"parts": [{"text": "SYSTEM"}]},
                "contents": [
                    {"role": "user", "parts": [{"text": "hello"}]},
                    {"role": "model", "parts": [{"text": "hi there"}]}
                ]
            }),
        },
        // A legal wire shape: an omitted role means `user`.
        Fixture {
            name: "gemini_roleless_turn",
            proto: "gemini",
            body: serde_json::json!({"contents": [{"parts": [{"text": "hello"}]}]}),
        },
        Fixture {
            name: "gemini_thought_part",
            proto: "gemini",
            body: serde_json::json!({
                "contents": [{"role": "model", "parts": [
                    {"text": "GEMINI COT", "thought": true},
                    {"text": "the answer"}
                ]}]
            }),
        },
        // ── OPENAI RESPONSES ──────────────────────────────────────────────────────────────────
        Fixture {
            name: "responses_bare_string_input",
            proto: "responses",
            body: serde_json::json!({
                "model": "gpt-5",
                "instructions": "INSTRUCTIONS",
                "max_output_tokens": 512,
                "input": "hello"
            }),
        },
        Fixture {
            name: "responses_input_items",
            proto: "responses",
            body: serde_json::json!({
                "model": "gpt-5",
                "input": [
                    {"role": "user", "content": [{"type": "input_text", "text": "hello"}]},
                    {"role": "assistant", "content": [{"type": "output_text", "text": "hi there"}]}
                ]
            }),
        },
        Fixture {
            name: "responses_reasoning_summary_only",
            proto: "responses",
            body: serde_json::json!({
                "model": "gpt-5",
                "input": [{"type": "reasoning", "summary": [{"type": "summary_text", "text": "SUMMARY COT"}]}]
            }),
        },
        // Admitted upstream on the opaque blob ALONE, with `content` present but empty.
        Fixture {
            name: "responses_encrypted_content_only",
            proto: "responses",
            body: serde_json::json!({
                "model": "gpt-5",
                "input": [{"type": "reasoning", "content": [], "encrypted_content": "OPAQUE_BLOB_XYZ"}]
            }),
        },
        // ── COHERE ────────────────────────────────────────────────────────────────────────────
        Fixture {
            name: "cohere_plain",
            proto: "cohere",
            body: serde_json::json!({
                "model": "command-r",
                "max_tokens": 32,
                "messages": [
                    {"role": "user", "content": "hello"},
                    {"role": "assistant", "content": "hi there"}
                ]
            }),
        },
        Fixture {
            name: "cohere_in_band_system_turn",
            proto: "cohere",
            body: serde_json::json!({
                "model": "command-r",
                "messages": [
                    {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
                    {"role": "user", "content": "hi"}
                ]
            }),
        },
        Fixture {
            name: "cohere_top_level_system_key",
            proto: "cohere",
            body: serde_json::json!({
                "model": "command-r",
                "system": "TOP LEVEL SYSTEM",
                "messages": [{"role": "user", "content": "hi"}]
            }),
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE GOLDEN — the surviving projection, pinned per fixture so it cannot drift either.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One fixture's view rendered as a single canonical line. Deliberately a string rather than a
/// struct table: the assertion is a whole-corpus diff a reviewer reads top to bottom, and a
/// hand-maintained struct table invites updating one field and calling it a review.
///
/// `REJECTED` stands for a body the reader refuses — the shape that is now a 400 rather than
/// something a guardrail is asked to screen best-effort while it goes upstream anyway.
fn render_view(measured: &Result<View, String>) -> String {
    match measured {
        Err(_) => "REJECTED".to_string(),
        Ok(v) => format!(
            "system={:?} turns={:?} text_chars={} max_tokens={:?} end_user={:?}",
            v.system, v.turns, v.text_chars, v.max_tokens, v.end_user
        ),
    }
}

/// The whole corpus, rendered. One line per fixture, sorted by fixture name.
fn render_corpus() -> String {
    let mut rows: Vec<(&'static str, String)> = corpus()
        .into_iter()
        .map(|f| {
            let name = f.name;
            (name, render_view(&ir_view(&f)))
        })
        .collect();
    rows.sort_by_key(|(name, _)| *name);
    rows.into_iter()
        .map(|(name, view)| format!("{name} :: {view}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// THE PIN. Regenerate deliberately, never reflexively: every line here is what a `prompt: ro` hook
/// is shown for that request and what the size signal reports for it, so a moved line is an
/// operator-visible behaviour change and belongs in the CHANGELOG with a reason.
const CORPUS_GOLDEN: &str = include_str!("golden/hook_ir_projection.txt");

#[test]
fn the_surviving_projection_matches_its_pinned_golden() {
    let measured = render_corpus();
    assert_eq!(
        measured.trim(),
        CORPUS_GOLDEN.trim(),
        "the surviving projection moved.\n\nMEASURED:\n{measured}\n\nA changed line is what a \
         content-granted hook SEES for that request, or what the size signal reports for it. \
         Regenerate `tests/golden/hook_ir_projection.txt` in the same commit that moved it, with \
         the reason, and check whether the move belongs in the CHANGELOG."
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE NINE. The rows this file was RED on, re-asserted as the behaviour that shipped.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE NINE INTENDED DIVERGENCES, CHECKED RATHER THAN CLAIMED
///
/// Before the cutover this file measured nine fixtures on which the two implementations disagreed.
/// Each one was a decision, not an accident, and each is a CHANGELOG line. Here each is asserted as
/// the NEW behaviour — because "the divergence list went to zero" is only meaningful if the list
/// went to zero in the direction that was chosen.
///
/// A failure here means the cutover did not do what it said it did, in a named way.
#[test]
fn the_nine_intended_divergences_are_the_ones_that_landed() {
    let view = |name: &str| -> Result<View, String> {
        let f = corpus()
            .into_iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("'{name}' is in the corpus"));
        ir_view(&f)
    };

    // ── THE FIX. `inferenceConfig.maxTokens` is Bedrock Converse's spelling of the output cap. The
    // deleted projection was dialect-aware for exactly one dialect's spelling and read `max_tokens`
    // everywhere else, so on Bedrock ingress it reported `None` — a routing policy keyed on the
    // size signal was BLIND to the caller's cap. The reader reads it; the signal now carries it.
    assert_eq!(
        view("bedrock_inference_config_max_tokens")
            .unwrap()
            .max_tokens,
        Some(128),
        "the Bedrock cap is a FIX, not a divergence: a policy keyed on the size signal used to be \
         blind to it"
    );

    // ── THE IN-BAND SYSTEM TURN, on both dialects that carry it inside the turns array. This is the
    // divergence that already shipped a bug: a compression hook shredded the operator's system
    // prompt on the dialects that put it in `messages` and not on the one that does not. The system
    // prompt is now in ONE place on every dialect, and `message_count` is one lower for these
    // bodies — wire-visible to every deployed hook.
    for name in ["openai_in_band_system_turn", "cohere_in_band_system_turn"] {
        let v = view(name).unwrap();
        assert_eq!(
            v.system.as_deref(),
            Some("OPERATOR SYSTEM PROMPT"),
            "{name}: the operator's system prompt must reach the hook as a SYSTEM prompt"
        );
        assert_eq!(v.turns.len(), 1, "{name}: the system turn is not a turn");
        assert_eq!(v.turns[0].0, "user");
    }

    // ── THE TOP-LEVEL `system` KEY on a dialect that does not model one. It is legal to send, the
    // old projection showed it to a hook as a system prompt, and the reader sweeps it into `extra`
    // — so a hook was being shown a "system prompt" the provider would never receive as one.
    for name in ["openai_top_level_system_key", "cohere_top_level_system_key"] {
        assert_eq!(
            view(name).unwrap().system,
            None,
            "{name}: a key this dialect does not model as a system prompt must not be shown as one"
        );
    }

    // ── THE ROLELESS GEMINI TURN. Legal on the wire, where an omitted role means `user`. The old
    // projection emitted `""`, so a hook that switches on role — "screen user turns strictly, trust
    // assistant turns" is the common shape — took its DEFAULT arm on caller-supplied input.
    assert_eq!(
        view("gemini_roleless_turn").unwrap().turns[0].0,
        "user",
        "an omitted gemini role means `user`, and a role-switching guardrail must see that"
    );

    // ── THE OPENAI `refusal` PART. `generic_block_text` probed only `text`, so both the content
    // projection AND the size signal read zero for a turn carrying real model-authored prose: a
    // guardrail could not screen a replayed refusal.
    let refusal = view("openai_refusal_part").unwrap();
    assert_eq!(refusal.turns[0].1, "I cannot help with that");
    assert!(refusal.text_chars > 0, "the refusal now counts as content");

    // ── TOOL-CALL ARGUMENTS. Attacker-influenceable, sent upstream verbatim, and projected by
    // nothing before the cutover. A gate that cannot see the arguments of a tool call cannot screen
    // the most attacker-influenceable field in an agent request. A WIDENING, in the CHANGELOG, and
    // bounded by `limits.hook_content_max_bytes`.
    let tools = view("openai_tool_call_and_result").unwrap();
    assert!(
        tools.turns[0].1.contains("ARGUMENT PAYLOAD"),
        "tool-call arguments must be screenable: {:?}",
        tools.turns[0].1
    );
    assert!(
        tools.turns[1].1.contains("TOOL RESULT PAYLOAD"),
        "the tool result stays visible too"
    );

    // ── THE UNKNOWN ROLE. The old projection could not fail: it screened `role: "wizard"` and the
    // request went upstream regardless. Five readers hard-reject it, and the ruling is that a body
    // busbar cannot read is the REQUEST's failure — stricter, in the safe direction, and NOT keyed
    // on whether a content hook happens to be configured.
    assert!(
        view("openai_unknown_role").is_err(),
        "a role no reader recognises is a 400, not something to screen best-effort and forward"
    );
}

/// The opacity decisions, asserted as a set rather than one fixture at a time: three wire shapes
/// across three dialects are opaque for the same reason, and a consumer must not be able to tell
/// which one it is looking at. An opacity decision that silently regresses is a provider-ciphertext
/// disclosure on two dialects and a policy bypass on the third.
#[test]
fn every_opaque_shape_projects_the_marker_and_never_the_bytes() {
    for (name, secret) in [
        ("anthropic_redacted_thinking", "OPAQUE_CIPHERTEXT_BYTES"),
        ("bedrock_redacted_content", "OPAQUE_BEDROCK_BYTES"),
        ("responses_encrypted_content_only", "OPAQUE_BLOB_XYZ"),
    ] {
        let f = corpus()
            .into_iter()
            .find(|f| f.name == name)
            .expect("in the corpus");
        let v = ir_view(&f).expect("the reader accepts this body");
        assert_eq!(
            v.turns[0].1,
            busbar_substrate_values::ir::facts::OPAQUE_CONTENT_MARKER,
            "{name}: an opaque shape must read as the marker, never as an empty turn"
        );
        assert!(
            !format!("{v:?}").contains(secret),
            "{name}: provider ciphertext reached the projection"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ACCEPTANCE PROPERTY: a protocol is covered by REGISTERING, not by adding an arm here.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE CORPUS WALK IS PROTOCOL-BLIND
///
/// The standard's acceptance test is *"if adding a protocol requires touching anything outside
/// `proto/`, its handler and its codec, the standard is not held"*. This file is one of the places
/// that would break first, so it asserts the weaker half it CAN assert today: every registered
/// protocol has fixtures in the corpus, and the walk needs no per-protocol code — it contains no
/// protocol name at all, only `crate::proto_codec::protocol_for(f.proto)`.
///
/// A seventh protocol therefore joins by appearing in `KNOWN_PROTOCOLS` and getting fixtures. If it
/// ever needs an arm in the walk, the standard is not held and this test's neighbours are the place
/// to say so.
#[test]
fn corpus_covers_every_known_protocol() {
    let covered: std::collections::BTreeSet<&str> = corpus().iter().map(|f| f.proto).collect::<_>();
    let known: std::collections::BTreeSet<&str> = known_protocols().iter().copied().collect();
    assert_eq!(
        covered, known,
        "every registered protocol needs fixtures; a protocol with none is a protocol whose \
         projection has never been checked"
    );
}
