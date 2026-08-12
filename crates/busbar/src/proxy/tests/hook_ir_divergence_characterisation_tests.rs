//! CHARACTERISATION tests for the hook-projection ↔ IR divergences.
//!
//! # What these are, and what they are NOT
//!
//! busbar has **two implementations of "what is the text in this request"**: the hook prompt
//! projection (`proxy/hooks.rs::build_prompt_projection`, built from the **raw ingress body**, with
//! its own `flatten_content`/`flatten_gemini_parts` and its own per-`PROTO_*` dispatch), and the
//! protocol readers (`proto/*/reader.rs`, which build the normalized `IrRequest`). They disagree.
//!
//! That is security-shaped rather than merely untidy: a PII/DLP gate wired as a `prompt: ro` hook
//! screens implementation A while the request that goes upstream was built from implementation B —
//! **so a redactor can pass a request whose real payload it never saw.** A shipped instance of this
//! class was already found and fixed as a one-off, inside the Headroom hook plugin: the operator's
//! own system prompt was shredded on the four dialects that carry it inside the turns array and left
//! alone on the one that carries it as a body field, so the same deployment behaved differently
//! depending on which dialect the client spoke.
//!
//! Six such divergences are known and, until this file, **no test asserted them in either
//! direction**. This file is that missing assertion. Every test below:
//!
//!   * **PINS TODAY'S BEHAVIOUR ON BOTH SIDES** — the projection's view and the IR's view of the
//!     same body — including where today's behaviour is WRONG;
//!   * says, in a `WRONG TODAY` / `RIGHT BEHAVIOUR` comment, what the correct behaviour is;
//!   * **fixes nothing.** Deliberately. The unification onto the IR must *consciously update* each
//!     of these rather than silently pass through it. A characterisation test that a change edits
//!     with a reason attached is a decision on the record; a change that runs green over a
//!     divergence it moved is a divergence that shipped twice.
//!
//! **Every `assert` in this file that the IR cutover has to edit is an operator-visible behaviour
//! change and belongs in the CHANGELOG.** That is the whole purpose of the file.
//!
//! Sibling coverage that already exists and is not duplicated here:
//! `hook_opt_in_projection_tests.rs` pins the *projection* side of the redaction cases
//! (`prompt_projection_marks_anthropic_redacted_thinking`,
//! `prompt_projection_marks_responses_encrypted_content_only_reasoning`, …). What was missing, and
//! what this file adds, is the **IR side of the same body** — the half that makes the disagreement
//! visible.

use super::*;
use crate::ir::{IrBlock, IrRole};
use crate::proto::Protocol;

/// Read a body into the IR through the named protocol's real reader, panicking with the reader's
/// own error. Kept tiny and local: the point of each test is the pair of views, not the plumbing.
fn ir_of(proto: &Protocol, body: &Value) -> crate::ir::IrRequest {
    proto
        .reader()
        .read_request(body)
        .unwrap_or_else(|e| panic!("reader rejected the fixture: {e:?}"))
}

/// Flatten a `Vec<IrBlock>` to the plain text a projection built from the IR would show.
fn ir_text(blocks: &[IrBlock]) -> String {
    blocks
        .iter()
        .filter_map(|b| match b {
            IrBlock::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// An IN-BAND SYSTEM TURN. The divergence that already shipped a bug.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # An IN-BAND SYSTEM TURN
///
/// An OpenAI-dialect body that puts the operator's
/// system prompt in `messages[0]`.
///
/// The projection is contracted **index-aligned with the wire `messages` array**
/// (`crates/api/src/hooks.rs`, the public plugin-facing crate; and `proxy/hooks.rs`'s own
/// "entries stay index-aligned with the body's `messages` and with `message_count`" guarantee), so
/// the system turn stays a turn and `system` is absent. Every LLM reader instead **hoists** every
/// system-role message out of the turns array into `IrRequest.system`
/// (`openai_chat/reader.rs`: "Promote EVERY system-role message to the top-level system field,
/// regardless of position"; likewise `anthropic`, `cohere`, `openai_responses`).
///
/// So a hook that screens "the system prompt" sees it in `messages[0]` on OpenAI/Cohere/Gemini/
/// Responses ingress and in `system` on Anthropic ingress — **the same deployment behaving
/// differently by client dialect, with nothing in the code acknowledging the split.** That is
/// verbatim the Headroom compression bug described in this file's header, and it is still live for
/// every other hook.
///
/// **WRONG TODAY:** the projection's dialect-dependent placement.
/// **RIGHT BEHAVIOUR:** one place a system prompt lives, on all six dialects — `IrRequest.system` —
/// which is what makes that class of bug mechanically impossible rather than fixed once.
/// **COST OF FIXING IT:** wire-visible. `message_count` drops by one on such bodies and the
/// index-alignment sentence in `crates/api/src/hooks.rs` stops being true. That is a real
/// operator-visible change and must ship as one, not inside a commit described as a refactor.
#[test]
fn characterise_in_band_system_turn_projection_vs_ir() {
    let v: Value = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
            {"role": "user", "content": "hi"}
        ]
    });

    // ── projection: TWO turns, the system prompt in-band, `system` absent.
    let p = build_prompt_projection(&v, "openai");
    assert_eq!(
        p.system, None,
        "projection: no top-level system on this body"
    );
    assert_eq!(
        p.messages.len(),
        2,
        "projection: index-aligned with the wire"
    );
    assert_eq!(p.messages[0].0, "system");
    assert_eq!(p.messages[0].1, "OPERATOR SYSTEM PROMPT");
    assert_eq!(turn_count(&v, "openai"), 2);

    // ── IR: the system turn is HOISTED. One fewer message.
    let ir = ir_of(&Protocol::openai(), &v);
    assert_eq!(
        ir_text(&ir.system),
        "OPERATOR SYSTEM PROMPT",
        "IR: hoisted into the dedicated system slot"
    );
    assert_eq!(ir.messages.len(), 1, "IR: the system turn is NOT a turn");
    assert_eq!(ir.messages[0].role, IrRole::User);

    // ── THE DIVERGENCE, stated as one assertion so it cannot be read past.
    assert_ne!(
        p.messages.len(),
        ir.messages.len(),
        "projection and IR disagree on the turn count of the same body"
    );

    // Anthropic ingress carries the same prompt as a BODY FIELD, and there the two agree — which
    // is precisely why the divergence was invisible: it is dialect-conditional.
    let anth: Value = serde_json::json!({
        "model": "claude", "max_tokens": 16,
        "system": "OPERATOR SYSTEM PROMPT",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let pa = build_prompt_projection(&anth, "anthropic");
    let ira = ir_of(&Protocol::anthropic(), &anth);
    assert_eq!(pa.system.as_deref(), Some("OPERATOR SYSTEM PROMPT"));
    assert_eq!(ir_text(&ira.system), "OPERATOR SYSTEM PROMPT");
    assert_eq!(pa.messages.len(), ira.messages.len(), "agree on anthropic");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// RESPONSES `encrypted_content`-ONLY REASONING. The sharpest one: the IR is the wrong half.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # RESPONSES `encrypted_content`-ONLY REASONING
///
/// A Responses `reasoning` input item admitted on its opaque
/// `encrypted_content` blob ALONE, with `content: []` present-but-empty.
///
/// The projection gets this RIGHT: `BlockText::Redacted` → [`REDACTED_REASONING_MARKER`], so a
/// screening hook is told "there is content here I cannot show you" rather than "this turn is
/// empty". Fixing that was closing a real policy-enforcement-point bypass — the reader admits the
/// item to the provider on the blob alone, so an unmarked item ships upstream unscreened.
///
/// **The IR gets it WRONG, and this test is here to pin exactly how.**
/// `openai_responses/reader.rs` reads the item as
/// `Thinking { text: "", signature: Some(blob), redacted: false }`: the opacity flag is `false`,
/// the text is EMPTY, and the blob is parked in `signature`. The IR models "this block is opaque
/// to busbar" for Anthropic and Bedrock and **not** for Responses, even though the Responses case
/// is opaque for exactly the same reason.
///
/// **WRONG TODAY:** `redacted: false` on a block that is, in fact, entirely opaque.
/// **RIGHT BEHAVIOUR:** the IR reports opacity for all three opaque shapes — either
/// `Thinking.redacted = true` here, or (if `redacted` must stay Anthropic/Bedrock-shaped for
/// writer reasons) an explicit `IrBlock::is_opaque()` that all three answer true to. That IR-side
/// fix must land BEFORE anything reads opacity off the IR — see the `BlockText::Redacted` doc
/// comment in `proxy/hooks.rs`.
#[test]
fn characterise_responses_encrypted_content_only_reasoning_projection_vs_ir() {
    let v: Value = serde_json::json!({
        "model": "gpt-5",
        "input": [{"type": "reasoning", "content": [], "encrypted_content": "OPAQUE_BLOB_XYZ"}]
    });

    // ── projection: correctly marked opaque, and the raw blob NEVER reaches the hook.
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].0, "assistant");
    assert_eq!(p.messages[0].1, REDACTED_REASONING_MARKER);
    assert!(
        !p.messages[0].1.contains("OPAQUE_BLOB_XYZ"),
        "the opaque blob must never be disclosed to an operator's sidecar"
    );

    // ── IR: opacity is NOT modeled. This is the bug, pinned.
    let ir = ir_of(&Protocol::responses(), &v);
    assert_eq!(ir.messages.len(), 1);
    assert_eq!(ir.messages[0].role, IrRole::Assistant);
    match &ir.messages[0].content[0] {
        IrBlock::Thinking {
            text,
            signature,
            redacted,
            ..
        } => {
            assert_eq!(text, "", "IR: the block reads as EMPTY text");
            assert_eq!(signature.as_deref(), Some("OPAQUE_BLOB_XYZ"));
            assert!(
                !*redacted,
                "PINNED BUG: the IR calls a wholly-opaque block un-redacted. When the IR learns \
                 to model this shape as opaque, this assertion flips to `assert!(*redacted)` \
                 (or to `is_opaque()`), and that flip is the fix."
            );
        }
        other => panic!("expected a Thinking block, got {other:?}"),
    }

    // ── THE TRAP THIS PINS. The naive IR port of the projection —
    //        `if thinking.redacted { MARKER } else { thinking.text }`
    //    — yields EMPTY here, restoring the original bypass verbatim: a hook sees an empty turn
    //    for a request the provider receives in full.
    let naive_port = match &ir.messages[0].content[0] {
        IrBlock::Thinking {
            text,
            redacted: true,
            ..
        } => {
            let _ = text;
            REDACTED_REASONING_MARKER.to_string()
        }
        IrBlock::Thinking { text, .. } => text.clone(),
        other => panic!("expected a Thinking block, got {other:?}"),
    };
    assert_eq!(
        naive_port, "",
        "the naive `redacted`-keyed port reopens the bypass — this is why the IR fix must come first"
    );
    assert_ne!(naive_port, p.messages[0].1);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// ANTHROPIC/BEDROCK CIPHERTEXT. Here the IR is right and a naive PASSTHROUGH is the hazard.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # ANTHROPIC / BEDROCK CIPHERTEXT
///
/// Anthropic `redacted_thinking` (and Bedrock `reasoningContent.redactedContent`).
///
/// The mirror image of D2, and worth pinning next to it because the two hazards point in OPPOSITE
/// directions — which is why neither can be handled by a single naive rule.
///
/// Here the IR **does** model opacity (`redacted: true`), but `Thinking.text` **holds the opaque
/// ciphertext bytes themselves** (`ir/mod.rs`: "`text` holds the opaque bytes, NOT plaintext").
/// The projection never shows them; it substitutes the marker.
///
/// **NOT WRONG TODAY — this test pins a correct behaviour whose correctness is fragile.** An
/// IR-based projection that reads `Thinking.text` without first checking opacity is a **new
/// disclosure of provider ciphertext to the operator's hook sidecar**, which is a regression this
/// file exists to catch.
/// **RIGHT BEHAVIOUR (unchanged):** substitute the marker whenever the block is opaque, on all
/// three shapes. Note that this case and the Responses case together mean the IR-side projection
/// must key on an opacity predicate that is true for all three AND must not emit `text` when it is
/// true — neither half alone is sufficient.
#[test]
fn characterise_anthropic_ciphertext_projection_vs_ir() {
    let v: Value = serde_json::json!({
        "model": "claude", "max_tokens": 16,
        "messages": [{"role": "assistant", "content": [
            {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
        ]}]
    });

    // ── projection: marker only; the ciphertext never leaves.
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.messages[0].1, REDACTED_REASONING_MARKER);
    assert!(!p.messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));

    // ── IR: opacity IS modeled here — and `text` is the ciphertext.
    let ir = ir_of(&Protocol::anthropic(), &v);
    match &ir.messages[0].content[0] {
        IrBlock::Thinking { text, redacted, .. } => {
            assert!(*redacted, "IR: anthropic DOES set the opacity flag");
            assert_eq!(
                text, "OPAQUE_CIPHERTEXT_BYTES",
                "PINNED HAZARD: the IR parks provider ciphertext in `text`. A projection \
                 that reads `text` without checking opacity DISCLOSES it to the operator's \
                 sidecar — a new leak, introduced by a refactor described as a no-op."
            );
        }
        other => panic!("expected a Thinking block, got {other:?}"),
    }

    // The naive passthrough that D3 forbids, shown failing the projection's own contract.
    let naive_passthrough = match &ir.messages[0].content[0] {
        IrBlock::Thinking { text, .. } => text.clone(),
        other => panic!("expected a Thinking block, got {other:?}"),
    };
    assert_ne!(
        naive_passthrough, p.messages[0].1,
        "reading `Thinking.text` blindly diverges from the shipped no-disclosure contract"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OPENAI `refusal` CONTENT PART. The projection is blind; the IR sees it.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # OPENAI `refusal` CONTENT PART
///
/// An OpenAI Chat `{"type":"refusal","refusal":"…"}` content part.
///
/// `generic_block_text` probes only the `text` key, so the refusal string is **invisible to the
/// projection** — a `prompt: ro` gate sees `{role:"assistant", text:""}` for a turn that carries
/// real model-authored prose. The reader reads it into `IrBlock::Text`
/// (`openai_chat/mod.rs`), so it is fully present in the IR and goes upstream verbatim.
///
/// **WRONG TODAY:** the projection is blind to it. Concretely: **a guardrail cannot currently
/// screen a replayed refusal.** Replaying a prior refusal as context is a routine jailbreak
/// primitive, and it is exactly the content an operator wired a screening hook to catch.
/// **RIGHT BEHAVIOUR:** refusal text is projected like any other assistant text — which the IR
/// already does, so the cutover fixes this for free. It is a **widening** of what a `prompt: ro`
/// hook sees and therefore belongs in the CHANGELOG with the same candour `docs/hooks.md` used for
/// the reasoning-text widening.
///
/// Note the second-order consequence pinned below: the SIZE signal is blind too, so a body can
/// carry unbounded refusal text and report `total_text_chars == 0`.
#[test]
fn characterise_openai_refusal_part_projection_vs_ir() {
    let v: Value = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "assistant", "content": [
            {"type": "refusal", "refusal": "I cannot help with that"}
        ]}]
    });

    // ── projection: BLIND. Pinned as the bug it is.
    let p = build_prompt_projection(&v, "openai");
    assert_eq!(p.messages.len(), 1);
    assert_eq!(
        p.messages[0].1, "",
        "PINNED BUG: refusal text is invisible to a screening hook. When the projection \
         moves to the IR this becomes \"I cannot help with that\"."
    );
    assert_eq!(
        total_text_chars(&v, "openai", 0),
        0,
        "PINNED BUG, size half: the SIZE signal is blind too — arbitrary refusal text \
         reports zero chars"
    );

    // ── IR: present, as ordinary assistant text.
    let ir = ir_of(&Protocol::openai(), &v);
    assert_eq!(ir.messages[0].role, IrRole::Assistant);
    assert_eq!(ir_text(&ir.messages[0].content), "I cannot help with that");
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// TOOL-ROLE CONTENT. The claim of a divergence here is FALSE; see the agreement tripwire.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # TOOL-ROLE CONTENT — and a CORRECTION to a claim made about it
///
/// It has been asserted, in planning the move onto the IR, that a tool-role message's bare-string
/// `content` is *counted* by `total_text_chars` but *never projected* by
/// `build_prompt_projection` — "a live, present-tense disagreement between two views of the same
/// request, inside the same file, with two dedicated anti-drift tests that do not catch it".
///
/// **Verified against the code: the two views AGREE.** `flatten_content`'s
/// `Some(Value::String(s))` arm is role-blind, exactly as `total_text_chars`'s is; a tool-role turn
/// is projected verbatim with the matching char count. The behavioural half of that claim does not
/// survive, and the agreement is pinned by `size_signal_and_projection_agree_on_tool_role_content`
/// in `hook_opt_in_projection_tests.rs`, which was verified load-bearing by injecting the claimed
/// divergence and confirming that it — and only it, not the two existing tripwires — detected it.
///
/// What IS real, and is pinned here, is the **structural** half: a tool result is flat `(role,
/// text)` to the projection and structured `IrRole::Tool` + `IrBlock::ToolResult { tool_use_id,
/// content, is_error }` in the IR, and **tool-call ARGUMENTS are projected by neither**.
///
/// **WRONG TODAY:** `ToolUse.input` — a tool call's arguments — is invisible to a screening hook.
/// **RIGHT BEHAVIOUR:** a `prompt: ro` gate sees tool arguments and tool results; a gate that
/// cannot see a tool result cannot screen the largest untrusted blob in a modern agent request.
/// That widening must be BOUNDED (`hooks.<name>.max_content_bytes`, enforced on serialized bytes,
/// with over-cap content **omitted and flagged**, never truncated mid-value): a guardrail that
/// screens half a payload and passes it is worse than one that refuses.
#[test]
fn characterise_tool_role_content_projection_vs_ir() {
    let v: Value = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "assistant", "content": null, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "search", "arguments": "{\"q\":\"ARGUMENT PAYLOAD\"}"}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "TOOL RESULT PAYLOAD"}
        ]
    });

    // ── projection: the tool RESULT is visible (correcting the claim above); ARGUMENTS are not.
    let p = build_prompt_projection(&v, "openai");
    assert_eq!(p.messages.len(), 2);
    assert_eq!(p.messages[0].1, "", "tool-call arguments are not projected");
    assert_eq!(p.messages[1].0, "tool");
    assert_eq!(
        p.messages[1].1, "TOOL RESULT PAYLOAD",
        "CORRECTION: contrary to the claim above, the tool result IS projected"
    );
    // …and the size signal agrees with it, which is the half the doc got backwards.
    assert_eq!(
        total_text_chars(&v, "openai", 0),
        "TOOL RESULT PAYLOAD".chars().count()
    );

    // ── IR: structured, and it retains the arguments the projection drops.
    let ir = ir_of(&Protocol::openai(), &v);
    assert_eq!(ir.messages[1].role, IrRole::Tool);
    match &ir.messages[1].content[0] {
        IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => {
            assert_eq!(tool_use_id, "c1");
            assert!(!*is_error);
            assert_eq!(ir_text(content), "TOOL RESULT PAYLOAD");
        }
        other => panic!("expected a ToolResult block, got {other:?}"),
    }
    match &ir.messages[0].content[0] {
        IrBlock::ToolUse { name, input, .. } => {
            assert_eq!(name, "search");
            assert!(
                input.to_string().contains("ARGUMENT PAYLOAD"),
                "PINNED: the IR retains tool-call arguments that no hook can see today"
            );
        }
        other => panic!("expected a ToolUse block, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// GEMINI ROLELESS TURN.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// # GEMINI ROLELESS TURN
///
/// A Gemini `contents[]` turn with no `role` key — legal on the wire, where
/// an omitted role means `user`.
///
/// The projection emits `role: ""` (its documented tolerance for malformed input: it never fails).
/// `gemini/reader.rs` resolves the omission to `IrRole::User`.
///
/// **WRONG TODAY:** `""` is not a role. A hook that switches on role — "screen user turns
/// strictly, trust assistant turns" is the common shape — falls into its default arm for a turn
/// that is unambiguously caller-supplied input, which is the *fail-open* direction for the
/// conservative-screening default a projection should have.
/// **RIGHT BEHAVIOUR:** `user`, as the reader already resolves it.
///
/// The tolerance itself is a third divergence axis and is noted rather than fixed: today's
/// projection **cannot fail**, while five readers hard-400 an unknown role. Moving the
/// projection onto the IR therefore turns some currently-forwarded bodies into 400s **only on
/// deployments that configure a content hook** — a behaviour difference keyed on hook config,
/// which is the exact class of conditional divergence the unification exists to remove. The ruling
/// on record is that the parse failure must become the request's failure UNCONDITIONALLY, so the
/// strictness does not depend on whether a hook is wired; that is a real, CHANGELOG-worthy change.
#[test]
fn characterise_gemini_roleless_turn_projection_vs_ir() {
    let v: Value = serde_json::json!({"contents": [{"parts": [{"text": "hello"}]}]});

    // ── projection: empty role.
    let p = build_prompt_projection(&v, "gemini");
    assert_eq!(p.messages.len(), 1);
    assert_eq!(
        p.messages[0].0, "",
        "PINNED BUG: a roleless gemini turn projects an empty role, so a role-switching \
         hook takes its default arm on caller-supplied input. Becomes \"user\" on the IR."
    );
    assert_eq!(p.messages[0].1, "hello");

    // ── IR: resolved to User.
    let ir = ir_of(&Protocol::gemini(), &v);
    assert_eq!(ir.messages[0].role, IrRole::User);
    assert_eq!(ir_text(&ir.messages[0].content), "hello");

    // The related tolerance axis, pinned on the dialect where it is starkest: an unknown role is
    // projected verbatim and never rejected, while the reader refuses the same body outright.
    let bad: Value = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "wizard", "content": "hi"}]
    });
    let pb = build_prompt_projection(&bad, "openai");
    assert_eq!(
        pb.messages[0].0, "wizard",
        "projection: tolerates, never fails"
    );
    assert!(
        Protocol::openai().reader().read_request(&bad).is_err(),
        "PINNED: the reader HARD-REJECTS the body the projection happily screens. On the \
         same-protocol path this body is forwarded upstream today."
    );
}
