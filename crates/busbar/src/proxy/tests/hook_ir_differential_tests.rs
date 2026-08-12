// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIFFERENTIAL TEST — busbar's two answers to "what is the text in this request", compared
//! fixture by fixture across all six wire formats.
//!
//! # What this file is
//!
//! busbar has **two implementations of "what is the text in this request"**:
//!
//!   * **LHS — the hook prompt projection.** `proxy/hooks.rs::build_prompt_projection`, built from
//!     the **raw ingress body**, carrying its own `flatten_content` and `flatten_gemini_parts` and
//!     its own per-`PROTO_*` dispatch (17 protocol-dispatch sites, 38 branch arms across
//!     `block_text`, `conversation_turns`, `turn_count`, `max_tokens_for`, `system_text_chars`,
//!     `total_text_chars`, `body_end_user`, `build_prompt_projection` and `apply_rewrite_to_body`).
//!   * **RHS — the IR.** `proto/*/reader.rs::read_request`, which normalizes the same body into
//!     `IrRequest`, and `ir::facts::project` — the successor projection — walking the blocks it
//!     produced.
//!
//! They disagree, and the disagreement is security-shaped rather than untidy: a PII/DLP gate wired
//! as a `prompt: ro` hook screens LHS while the request that goes upstream is built from RHS — **so
//! a redactor can pass a request whose real payload it never saw.** One instance of that class has
//! already shipped and been fixed as a one-off (the Headroom hook's system-prompt shredding, which
//! behaved differently per client dialect).
//!
//! **A unit suite written alongside a defect cannot prove the defect's absence; a differential test
//! between the two implementations can prove its presence — today, before a line of production code
//! moves.** That is this file's whole job. It makes NO production change and fixes NOTHING.
//!
//! # The two tests, and why one of them is ignored
//!
//!   * [`differential_projection_and_ir_agree_on_every_fixture`] is **THE RED**. It asserts the two
//!     views AGREE and it FAILS today, naming every disagreement. It is `#[ignore]`d so the suite
//!     stays green while the defect is open — **never delete it.** It is the deliverable: the defect
//!     stated as a failing test rather than as a paragraph. Run it with
//!     `cargo test -p busbar hook_ir_differential -- --ignored --nocapture`.
//!   * [`differential_diff_list_is_exactly_the_pinned_divergences`] is **THE RATCHET**, and it is
//!     green. It pins the diff list as a snapshot, field by field, so that between now and the
//!     cutover **no divergence can appear and none can vanish unnoticed.** It has moved once: when
//!     `ir::facts` became the RHS the list went from twelve rows to nine — three closed, **none
//!     opened** — and that "none opened" was the landing criterion for the unit, not a pleasant
//!     side effect. A tenth row would have been a bug in the new projection, and this test is where
//!     it would have shown up.
//!
//! # `normalize`
//!
//! Both sides reduce to the same [`View`]: the system text, the ordered `(role, text)` per turn, the
//! total text-char count, `max_tokens`, and the end-user id. **Structural difference is what the
//! test is for, so the normalization must not paper over it** — it does not sort, does not drop
//! empty turns, and does not merge the system slot into the turn list.
//!
//! # The RHS is now REAL CODE — the successor projection, not a sketch
//!
//! This file originally carried its own hand-written walk over `IrBlock`, deliberately NAIVE: it
//! read `Thinking.text` without asking whether the block was opaque, because that is the port a
//! reasonable person writes if they do not read the warnings, and the differential is where the
//! warning had to come from. **That sketch is gone.** The RHS is now
//! [`crate::ir::facts::project`] plus [`crate::ir::facts::IrFacts`], so both sides of this
//! comparison are code that ships, and every remaining row below is a real disagreement between two
//! implementations rather than between one implementation and a test helper.
//!
//! Reading the two sketch-era decisions in the pinned list is worth doing, because the successor
//! took a different one on each:
//!
//!   * **opacity** — the sketch showed provider ciphertext; `project` asks
//!     [`crate::ir::IrBlock::is_opaque`] first and substitutes the marker. Three rows closed.
//!   * **tool-call arguments** — the sketch projected them and so does `project`, because a gate
//!     that cannot see the arguments of a tool call cannot screen them. That row stays open on
//!     purpose: it is a widening, and a widening is a CHANGELOG entry, not a bug.
//!
//! The RHS is still **protocol-blind** — no `PROTO_*` in sight on either side of the walk, and none
//! in `ir/facts.rs` at all. That is the shape a single implementation has to have.
//!
//! # It supersedes two tripwires this project already invented
//!
//! `system_text_chars_counts_block_arrays` (whose comment reads *"they diverged once — this is the
//! tripwire"*) and `size_signal_and_projection_agree_on_reasoning`, both in
//! `hook_opt_in_projection_tests.rs`, are this idea pointed at the wrong pair: they check two halves
//! of **the same** implementation against each other. The instinct was right and the aim was short.
//! Their blind spot is demonstrable rather than theoretical — injecting a `role == "tool"` blind
//! spot into `build_prompt_projection` leaves BOTH of them green.
//!
//! Sibling coverage that is not duplicated here: `hook_ir_divergence_characterisation_tests.rs`
//! pins each individual divergence, on both sides, with the reasoning for what the RIGHT behaviour
//! is. This file is the SWEEP — the corpus walk that finds the ones nobody thought to characterise.

use super::*;
use crate::ir::facts::IrFacts;
use crate::ir::{IrRequest, IrRole};
use crate::proto::{ProtocolRegistry, KNOWN_PROTOCOLS};
use std::collections::BTreeMap;

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

/// LHS — today's raw-body flattening, exactly as the hook seam calls it.
fn projection_view(f: &Fixture) -> View {
    let p = build_prompt_projection(&f.body, f.proto);
    let system_chars = system_text_chars(&f.body, f.proto);
    View {
        system: p.system.map(|c| c.into_owned()),
        turns: p
            .messages
            .into_iter()
            .map(|(r, t)| (r.into_owned(), t.into_owned()))
            .collect(),
        text_chars: total_text_chars(&f.body, f.proto, system_chars),
        max_tokens: max_tokens_for(&f.body, f.proto),
        end_user: body_end_user(&f.body),
    }
}

/// RHS — the IR's view: the protocol's real reader, then the successor projection.
///
/// `Err` is a first-class outcome, not a test failure: five readers hard-reject bodies the
/// projection screens happily, and that asymmetry is itself one of the divergences (on the
/// same-protocol path such a body is forwarded upstream today while the hook is told `role: ""`).
fn ir_view(f: &Fixture) -> Result<View, String> {
    let registry = ProtocolRegistry::with_builtins();
    let proto = registry
        .get(f.proto)
        .unwrap_or_else(|| panic!("no protocol registered for '{}'", f.proto));
    let ir = proto
        .reader()
        .read_request(&f.body)
        .map_err(|e| format!("{e:?}"))?;
    Ok(project_ir(&ir))
}

fn role_name(r: IrRole) -> &'static str {
    match r {
        IrRole::System => "system",
        IrRole::User => "user",
        IrRole::Assistant => "assistant",
        IrRole::Tool => "tool",
    }
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
    for item in crate::ir::facts::project(ir) {
        let piece = item.screenable_text().into_owned();
        match item.slot().turn_index() {
            None => system_pieces.push(piece),
            Some(i) => {
                while turns.len() <= i {
                    turns.push((String::new(), Vec::new()));
                }
                turns[i].0 = role_name(item.role()).to_string();
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
// THE DIFF — field-level, so a snapshot names WHAT disagreed, not merely THAT something did.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The stable KEYS of the fields that disagree, sorted. Turn-level disagreements are keyed by
/// index so a text difference on turn 3 cannot silently swap with one on turn 0.
fn diff_keys(lhs: &View, rhs: &View) -> Vec<String> {
    let mut keys = Vec::new();
    if lhs.system != rhs.system {
        keys.push("system".to_string());
    }
    if lhs.turns.len() != rhs.turns.len() {
        keys.push("turn_count".to_string());
    }
    for i in 0..lhs.turns.len().min(rhs.turns.len()) {
        if lhs.turns[i].0 != rhs.turns[i].0 {
            keys.push(format!("turn[{i}].role"));
        }
        if lhs.turns[i].1 != rhs.turns[i].1 {
            keys.push(format!("turn[{i}].text"));
        }
    }
    if lhs.text_chars != rhs.text_chars {
        keys.push("text_chars".to_string());
    }
    if lhs.max_tokens != rhs.max_tokens {
        keys.push("max_tokens".to_string());
    }
    if lhs.end_user != rhs.end_user {
        keys.push("end_user".to_string());
    }
    keys.sort();
    keys
}

/// The whole corpus reduced to `fixture name -> the diff between the two views`.
///
/// `REJECTED` is the marker for a body the reader refuses outright — a divergence of a different
/// kind (the projection cannot fail; five readers can), and one that becomes a real behaviour
/// change when the hook path moves onto the IR.
fn measure() -> BTreeMap<&'static str, Vec<String>> {
    let mut out = BTreeMap::new();
    for f in corpus() {
        let keys = match ir_view(&f) {
            Ok(rhs) => diff_keys(&projection_view(&f), &rhs),
            Err(_) => vec!["REJECTED".to_string()],
        };
        out.insert(f.name, keys);
    }
    out
}

/// A human-readable rendering of one fixture's disagreement, for the RED test's message.
fn render(f: &Fixture) -> String {
    let lhs = projection_view(f);
    match ir_view(f) {
        Err(e) => format!(
            "  {} [{}]\n      projection: {} turn(s), screened without complaint\n      IR:         \
             READER REJECTED THE BODY ({e})",
            f.name,
            f.proto,
            lhs.turns.len()
        ),
        Ok(rhs) => format!(
            "  {} [{}]  diff: {:?}\n      projection: {:?}\n      IR:         {:?}",
            f.name,
            f.proto,
            diff_keys(&lhs, &rhs),
            lhs,
            rhs
        ),
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
// THE RED. Ignored so the suite stays green while the defect is open — never deleted.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE DIFFERENTIAL ASSERTION — RED BY DESIGN
///
/// For every fixture body `b` at protocol `p`:
///
/// ```text
/// lhs = normalize(build_prompt_projection(&b, p))   // today's raw-body flattening
/// rhs = normalize(project(read_request(&b)?))       // the IR's view
/// assert_eq!(lhs, rhs)
/// ```
///
/// **This test FAILS. That is the deliverable** — the defect proven rather than argued. A
/// differential test that went green on today's code would mean the divergence is theoretical, and
/// it is not.
///
/// It is `#[ignore]`d rather than deleted or weakened, so that a run of the workspace suite stays
/// green while the whole failure list remains one command away:
///
/// ```text
/// cargo test -p busbar hook_ir_differential -- --ignored --nocapture
/// ```
///
/// It stops being ignored the day the cutover lands and the two views become one. **Whoever removes
/// the `#[ignore]` must NOT also relax the assertion** — the pinned-snapshot sibling below exists
/// so that a weakening shows up as a failure rather than as a smaller number.
#[test]
#[ignore = "RED BY DESIGN: the projection↔IR divergence, stated as a failing test. Run with \
            --ignored to read the full diff list. Delete this attribute only when the two \
            implementations have become one."]
fn differential_projection_and_ir_agree_on_every_fixture() {
    let mut failures: Vec<String> = Vec::new();
    for f in corpus() {
        let diverges = match ir_view(&f) {
            Ok(rhs) => !diff_keys(&projection_view(&f), &rhs).is_empty(),
            Err(_) => true,
        };
        if diverges {
            failures.push(render(&f));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} fixtures: the hook projection and the IR disagree about the SAME request body. \
         A `prompt: ro` gate screens the first view; the provider receives the second.\n{}",
        failures.len(),
        corpus().len(),
        failures.join("\n")
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE RATCHET. Green: the diff list pinned as a snapshot, field by field.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE PINNED DIFF LIST
///
/// The measured divergence set, per fixture, as it stands **before** any of the unification work.
/// Every entry is a fixture name mapped to the exact fields on which the two implementations
/// disagree (`REJECTED` = the reader refuses a body the projection screens without complaint).
///
/// **This is a two-way ratchet and both directions matter.**
///
///   * A **new** entry means a divergence appeared — either a new one was introduced, or one that
///     was always there has been found by a fixture somebody added. Either way it is news.
///   * A **vanished** entry means a divergence was closed. Every one of them is an operator-visible
///     behaviour change (what a screening hook sees, or what `message_count` reports) and belongs in
///     the CHANGELOG. Closing one *silently*, inside a commit described as a refactor, is exactly
///     what this pin exists to make impossible.
///
/// The list is expected to change exactly once per landed unit, with the unit's commit updating it
/// and saying why.
///
/// **Measured, not predicted.** Six divergences were named in advance from reading the code; all
/// six reproduced, two of them on a second dialect each. Three more that no test asserted in either
/// direction reproduced as well, and one — `bedrock_inference_config_max_tokens` — was named by
/// nothing and found only by running the sweep. Six fixtures that were expected to diverge did NOT
/// (see [`AGREEING_SHAPES_WORTH_NAMING`]); their agreement is evidence, not silence.
///
/// # MOVED ONCE: 12 rows → 9, when `ir::facts` became the RHS
///
/// The RHS used to be a hand-written sketch in this file. It is now [`crate::ir::facts::project`],
/// and **three rows closed and none opened.** Both halves of that sentence are the unit's
/// acceptance criterion, and the second half is the load-bearing one: an unexpected tenth row would
/// have been a bug in the successor projection rather than a test to update.
///
/// The three that closed were all the SAME defect — content busbar cannot read, decided in the
/// wrong place — and they are now named in [`AGREEING_SHAPES_WORTH_NAMING`] instead:
///
///   * `anthropic_redacted_thinking`, `bedrock_redacted_content`: `IrBlock::is_opaque()` is
///     asked BEFORE `Thinking.text` is touched, so provider ciphertext parked there never reaches
///     an operator's sidecar; the marker does, byte-identically.
///   * `responses_encrypted_content_only`: the opacity predicate recognises the third opaque
///     shape, so the projection reads that answer rather than re-deriving it from the wire.
///
/// **What deliberately did NOT close: `openai_tool_call_and_result`.** The successor projects
/// `ToolUse.input` on purpose — a gate that cannot see a tool call's arguments cannot screen the
/// most attacker-influenceable field in an agent request. That row is a WIDENING and it stays open
/// until the cutover ships it with a CHANGELOG entry and a byte cap.
const PINNED_DIVERGENCES: &[(&str, &[&str])] = &[
    // ── FOUND BY THE SWEEP, NAMED BY NOBODY. `max_tokens_for` is dialect-aware for exactly one
    // dialect (`max_output_tokens` on Responses) and reads `max_tokens` everywhere else — but
    // Bedrock Converse spells the cap `inferenceConfig.maxTokens`, which the reader reads and the
    // projection does not. So on Bedrock ingress a routing policy or tap keying on the `max_tokens`
    // SIZE signal is BLIND to the caller's cap, in the same way every Responses request was blind
    // before that arm was added. Same defect, same function, one dialect further along.
    //
    // The successor reads the reader's normalized `IrRequest.max_tokens` and therefore gets it
    // RIGHT, so this row is now a divergence in which the LHS is the wrong half: it survives as
    // evidence of a defect the cutover FIXES, not of one it must be careful about.
    ("bedrock_inference_config_max_tokens", &["max_tokens"]),
    // ── D1: the in-band system turn. The divergence that already shipped a bug (Headroom shredding
    // the operator's system prompt on the dialects that carry it inside the turns array). The
    // projection is contracted index-aligned with the wire `messages`; every reader HOISTS
    // system-role turns into `IrRequest.system`. `turn_count` therefore differs by one, which is
    // wire-visible to every deployed hook via `message_count`.
    (
        "cohere_in_band_system_turn",
        &["system", "turn[0].role", "turn[0].text", "turn_count"],
    ),
    (
        "openai_in_band_system_turn",
        &["system", "turn[0].role", "turn[0].text", "turn_count"],
    ),
    // ── D2': a TOP-LEVEL `system` key on an OpenAI or Cohere body — legal to send, projected as a
    // system prompt, and swept into `extra` by those readers. Recorded as a divergence with no test
    // in either direction; this is that test.
    ("cohere_top_level_system_key", &["system", "text_chars"]),
    ("openai_top_level_system_key", &["system", "text_chars"]),
    // ── D1': a Gemini turn with no `role` — legal on the wire, where the omission means `user`.
    // The projection emits `""`; a hook that switches on role ("screen user turns strictly, trust
    // assistant turns" is the common shape) takes its DEFAULT arm on caller-supplied input.
    ("gemini_roleless_turn", &["turn[0].role"]),
    // ── D4: an OpenAI `refusal` content part. `generic_block_text` probes only `text`, so both the
    // content projection AND the size signal read zero for a turn carrying real model-authored
    // prose. A guardrail cannot currently screen a replayed refusal.
    ("openai_refusal_part", &["text_chars", "turn[0].text"]),
    // ── D5, the half of it that is real: TOOL-CALL ARGUMENTS. `ToolUse.input` — attacker-
    // influenceable, sent upstream verbatim — is retained by the IR and projected by nothing on the
    // LHS. (The tool RESULT is projected and counted correctly on both sides; see
    // `tool_role_bare_string_content_is_counted_and_projected_alike`.) The successor projects the
    // arguments, in their own `Slot::ToolArgs` so the turn that made the call keeps the
    // attribution. It is a WIDENING and stays open on purpose — a widening is a CHANGELOG entry
    // and a byte cap, not a row to make disappear.
    (
        "openai_tool_call_and_result",
        &["text_chars", "turn[0].text"],
    ),
    // ── D6: the projection CANNOT FAIL; five readers hard-400 an unknown role. On the
    // same-protocol path this body is forwarded upstream today while the hook is told
    // `role: "wizard"`. Moving the projection onto the IR turns it into a 400 — a real behaviour
    // change, in the safe direction, and one that must NOT end up keyed on whether a content hook
    // happens to be configured.
    ("openai_unknown_role", &["REJECTED"]),
];

/// The fixtures on which the two implementations AGREE, kept as a named list because an agreement
/// measured is worth as much as a disagreement measured — and because each of these was a
/// hypothesis somebody would otherwise re-derive by reading.
///
/// **The first six were expected to diverge and did not.** A media-only turn keeps its entry on both
/// sides. Anthropic `thinking`, Bedrock `reasoningContent.reasoningText`, Responses summary-only
/// `reasoning` and a Gemini `thought: true` part all project their text identically through both
/// implementations. And a tool-role bare-string turn agrees in both content and char count — the
/// divergence recorded against it does not exist (see
/// [`tool_role_bare_string_content_is_counted_and_projected_alike`]).
///
/// **The last three diverged and were CLOSED**, when `ir::facts` replaced this file's hand-written
/// RHS. All three are the same defect: content busbar cannot read, decided from the wire shape in
/// one implementation and from `IrBlock::is_opaque()` in the other. They are promoted from the
/// pinned diff list to here rather than deleted, because "these two shapes agree" is a claim that
/// must keep being checked — an opacity decision that silently regresses is a provider-ciphertext
/// disclosure on two dialects and a policy bypass on the third.
const AGREEING_SHAPES_WORTH_NAMING: &[&str] = &[
    "anthropic_thinking_block",
    "bedrock_reasoning_content",
    "gemini_thought_part",
    "openai_media_only_turn",
    "openai_tool_role_bare_string_only",
    "responses_reasoning_summary_only",
    // ── CLOSED by `ir::facts`, and each one is an OPERATOR-VISIBLE behaviour change on the day the
    // cutover lands: a hook that today sees a redacted turn's ciphertext-bearing text keeps seeing
    // the marker (no change), and a hook that today sees an EMPTY turn for an encrypted-only
    // Responses reasoning item starts seeing the marker instead (a change, in the safe direction).
    "anthropic_redacted_thinking",
    "bedrock_redacted_content",
    "responses_encrypted_content_only",
];

/// The named agreements are asserted, not assumed: if one of them starts to diverge, the pinned
/// list above catches it, and this test says which hypothesis changed answer.
#[test]
fn the_named_agreeing_shapes_still_agree() {
    let measured = measure();
    for name in AGREEING_SHAPES_WORTH_NAMING {
        let keys = measured
            .get(name)
            .unwrap_or_else(|| panic!("'{name}' is not in the corpus"));
        assert!(
            keys.is_empty(),
            "'{name}' was recorded as an AGREEMENT between the two implementations and now \
             diverges on {keys:?}. That is a finding: either the shape always diverged and the \
             earlier reading was wrong, or something moved."
        );
    }
}

#[test]
fn differential_diff_list_is_exactly_the_pinned_divergences() {
    let measured: BTreeMap<&str, Vec<String>> = measure()
        .into_iter()
        .filter(|(_, keys)| !keys.is_empty())
        .collect();
    let pinned: BTreeMap<&str, Vec<String>> = PINNED_DIVERGENCES
        .iter()
        .map(|(name, keys)| (*name, keys.iter().map(|k| (*k).to_string()).collect()))
        .collect();

    assert_eq!(
        measured, pinned,
        "the projection↔IR diff list moved.\n\
         MEASURED: {measured:#?}\n\
         PINNED:   {pinned:#?}\n\
         A NEW entry is a divergence that appeared — read it as a finding, not as a test to fix. A \
         VANISHED entry is a divergence that was CLOSED, which is an operator-visible behaviour \
         change and belongs in the CHANGELOG. Update this pin in the same commit that moved it, \
         with the reason."
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE SEVENTH DIVERGENCE THAT ISN'T. Recorded because a false finding costs more than a missing one.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE RECORDED SEVENTH DIVERGENCE DOES NOT REPRODUCE
///
/// It has been recorded, more than once, that a tool-role message's bare-string `content` is
/// **counted** by `total_text_chars` and **never projected** by `build_prompt_projection` — "the
/// size signal and the content projection disagree today, and it got past two dedicated anti-drift
/// tripwires".
///
/// **Executed rather than read: the two views AGREE, and this test is the execution.**
/// `flatten_content`'s `Some(Value::String(s)) => Cow::Borrowed(s)` arm is role-BLIND, exactly as
/// `total_text_chars`'s `Some(Value::String(s)) => s.chars().count()` arm is. A tool-role
/// bare-string turn is projected verbatim AND counted, and the IR keeps it too, inside
/// `ToolResult.content`.
///
/// **The meta-claim survives its own instance, and this is the important half.** The shape really
/// does sit in the blind spot of both dedicated tripwires: injecting the claimed divergence — a
/// `role == "tool"` arm returning `""` in `build_prompt_projection` — leaves both
/// `system_text_chars_counts_block_arrays` and `size_signal_and_projection_agree_on_reasoning`
/// GREEN. So the tripwires do not cover the class they were written for; it is only the specific
/// defect that was never there. `size_signal_and_projection_agree_on_tool_role_content` (in
/// `hook_opt_in_projection_tests.rs`) now pins the agreement, and was itself proven load-bearing by
/// that same mutation.
///
/// **Why this is kept as a test and not deleted as a non-finding:** every other divergence in this
/// area was named by READING code. This one was named the same way and did not survive execution.
/// A test that pins the absence is what stops it being re-derived — by reading — a fourth time.
#[test]
fn tool_role_bare_string_content_is_counted_and_projected_alike() {
    let f = corpus()
        .into_iter()
        .find(|f| f.name == "openai_tool_role_bare_string_only")
        .expect("the fixture is in the corpus");

    let p = build_prompt_projection(&f.body, f.proto);
    assert_eq!(p.messages.len(), 2, "both turns are projected");
    assert_eq!(p.messages[1].0, "tool");
    assert_eq!(
        p.messages[1].1, "TOOL RESULT PAYLOAD",
        "the CLAIM was that this is empty. It is not: `flatten_content`'s bare-string arm is \
         role-blind."
    );

    // …and the size signal counts EXACTLY what was projected — the disagreement that was reported
    // does not exist in either direction.
    let projected_chars: usize = p
        .messages
        .iter()
        .map(|(_, t)| t.chars().count())
        .sum::<usize>()
        + p.system.as_deref().map(|s| s.chars().count()).unwrap_or(0);
    assert_eq!(
        total_text_chars(&f.body, f.proto, system_text_chars(&f.body, f.proto)),
        projected_chars,
        "size signal and content projection agree on a tool-role bare-string turn"
    );

    // The IR keeps it too, structured as a tool result rather than flat text.
    let ir = ir_view(&f).expect("the reader accepts this body");
    assert_eq!(
        ir.turns[1],
        ("tool".to_string(), "TOOL RESULT PAYLOAD".to_string()),
        "the IR retains the same payload; the difference here is STRUCTURE, not visibility"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ACCEPTANCE PROPERTY: a protocol is covered by REGISTERING, not by adding an arm here.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # THE CORPUS WALK IS PROTOCOL-BLIND
///
/// The standard's acceptance test is *"if adding a protocol requires touching anything outside
/// `proto/`, its handler and its codec, the standard is not held"*. This file is one of the places
/// that would break first, so it asserts the weaker half it CAN assert today: every registered
/// protocol has fixtures in the corpus, and the walk needs no per-protocol code — `measure()`
/// contains no protocol name at all, only `registry.get(f.proto)`.
///
/// A seventh protocol therefore joins by appearing in `KNOWN_PROTOCOLS` and getting fixtures. If it
/// ever needs an arm in the walk, the standard is not held and this test's neighbours are the place
/// to say so.
#[test]
fn corpus_covers_every_known_protocol() {
    let covered: std::collections::BTreeSet<&str> = corpus().iter().map(|f| f.proto).collect::<_>();
    let known: std::collections::BTreeSet<&str> = KNOWN_PROTOCOLS.iter().copied().collect();
    assert_eq!(
        covered, known,
        "every registered protocol needs differential fixtures; a protocol with none is a \
         protocol whose two implementations have never been compared"
    );
}
