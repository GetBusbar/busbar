//! Gemini `usageMetadata` → billed [`crate::ir::IrUsage`].

use super::*;

/// Parse a Gemini `usageMetadata` block into `IrUsage`, defaulting every counter to 0 when the
/// field (or an individual counter) is absent — and REFUSING (#42) when a billed counter is present
/// but unreadable, where the old read defaulted it to zero and ledgered no work for work that
/// happened. Shared by the streaming and prompt-block paths so usage accounting stays identical
/// regardless of how a response terminates.
///
/// Cache tokens: Gemini reports context-cache hits as `usageMetadata.cachedContentTokenCount`
/// (the google-genai SDK's `cached_content_token_count`). Map it into the IR's
/// `cache_read_input_tokens` — the SAME field Bedrock's `cacheReadInputTokens` and Anthropic's
/// `cache_read_input_tokens` populate — so cached-prompt accounting survives the cross-protocol seam
/// instead of being dropped. `None` when absent (no cache hit / older response).
pub(super) fn gemini_billed_usage(data: &serde_json::Value) -> Result<crate::ir::IrUsage, IrError> {
    let u = data.get(FIELD_USAGE_METADATA);
    let prompt = billed(u, FIELD_PROMPT_TOKEN_COUNT)?;
    let cached = billed_opt(u, FIELD_CACHED_CONTENT_TOKEN_COUNT)?;
    // What this turn will BILL, computed here so the identity cross-check below can compare it
    // against Google's own stated total. Mirrors the field construction that follows exactly:
    // uncached input + cache read + visible output + thinking output.
    let candidates = billed(u, FIELD_CANDIDATES_TOKEN_COUNT)?;
    let thoughts = billed_opt(u, FIELD_THOUGHTS_TOKEN_COUNT)?;
    // THE FOURTH ADDITIVE TERM. `toolUsePromptTokenCount` is not a slice of `promptTokenCount` —
    // see [`GEMINI_USAGE_ADDITIVE_TERMS`] for the recording that settles it — and Google charges it
    // at the INPUT rate, so it belongs in `input_tokens` beside the uncached prompt.
    let tool_use = billed_opt(u, FIELD_TOOL_USE_PROMPT_TOKEN_COUNT)?;
    let billed_total = prompt
        .saturating_add(candidates)
        .saturating_add(thoughts.unwrap_or(0))
        .saturating_add(tool_use.unwrap_or(0));
    Ok(crate::ir::IrUsage {
        // NORMALIZE to the additive-cache convention: Gemini's `promptTokenCount` is a TOTAL that
        // already INCLUDES `cachedContentTokenCount`, so subtract the cached tokens to leave only
        // the uncached input. `saturating_sub` guards an odd upstream where cached > prompt.
        //
        // Then ADD the tool-use prompt term, which `promptTokenCount` does NOT include (busbar
        // 1.6.0 money change — see the CHANGELOG line "Gemini `toolUsePromptTokenCount` is billed").
        // Dropping it under-counted every grounded/server-tool turn by exactly that many tokens
        // (32 of 222 — 14% — on the grounding recording).
        input_tokens: prompt
            .saturating_sub(cached.unwrap_or(0))
            .saturating_add(tool_use.unwrap_or(0)),
        // THINKING TOKENS ARE OUTPUT TOKENS. `candidatesTokenCount` counts only the VISIBLE answer;
        // the 2.5-series models' reasoning tokens arrive in the separate, ADDITIVE
        // `thoughtsTokenCount` (Google's own `totalTokenCount` is prompt + candidates + thoughts).
        // Reading only `candidatesTokenCount` ledgered every thinking token as ZERO while Google
        // billed it at the output rate — and 2.5 Flash/Pro think BY DEFAULT with no `thinkingConfig`
        // in the request, so this was ordinary traffic, not a reasoning opt-in, and the undercount
        // is unbounded (a large thinking budget dwarfs the visible answer). Summing them here is
        // what makes `IrUsage.output_tokens` mean the same thing it means for every other provider:
        // all tokens GENERATED, billed at the output rate. Anthropic already counts its thinking
        // tokens inside `output_tokens` upstream, and OpenAI's `reasoning_tokens` is a SUBSET of
        // `completion_tokens` — Gemini is the only family that splits the term out, so it is the
        // only one that needs the add.
        //
        // WIRE: the Gemini WRITER splits the two back apart — `candidatesTokenCount` is
        // `output_tokens` minus the reasoning sub-bucket and `thoughtsTokenCount` is that sub-bucket
        // (IR audit GEM-13, `insert_gemini_output_counts`) — so a read→write keeps Google's shape and
        // the synthesized `totalTokenCount` still counts every generated token once.
        output_tokens: candidates.saturating_add(thoughts.unwrap_or(0)),
        cache_creation_input_tokens: None,
        cache_read_input_tokens: cached,
        // The thinking tokens are ALSO recorded as the reasoning sub-bucket. They are already folded
        // into `output_tokens` above (Google bills them at the output rate and every other family
        // counts reasoning inside its output total), so this is pure ATTRIBUTION and changes no
        // total: it is what lets a Gemini-backed request answer "how many of those output tokens
        // were thinking?" on an OpenAI-dialect egress, which previously returned a hard 0.
        detail: crate::ir::IrUsageDetail {
            reasoning_tokens: thoughts,
            // Gemini's `toolUsePromptTokenCount`, kept here as ATTRIBUTION: it answers "how many of
            // those input tokens were server-side tool use?" and it is what lets the Gemini writer
            // put the term back BESIDE `promptTokenCount` on the wire instead of inside it.
            //
            // IT IS NOT A SUB-BUCKET, and unlike every other field on this struct it is NOT free of
            // the bill. `GEMINI_USAGE_ADDITIVE_TERMS` records the measurement that overturned the
            // old reading: the grounding recording reports 32 tool-use tokens against a
            // `promptTokenCount` of 18, so it cannot be a slice of the prompt, and Google's stated
            // `totalTokenCount` reconciles only when it is ADDED. Since 1.6.0 it therefore rides in
            // `input_tokens` above (a registered money change with its own CHANGELOG line) and is
            // recorded here as well, so the attribution survives without being double-counted:
            // `billable_tokens` reads the totals, never this struct.
            tool_use_prompt_tokens: tool_use,
            // The cross-check that makes the paragraph above impossible to lose again: Google's own
            // `totalTokenCount` versus the counters busbar decoded. `None` when they agree.
            usage_identity_note: gemini_usage_identity_note(u, billed_total),
            // `usageMetadata.trafficType` — INFORMATIONAL (ON_DEMAND vs PROVISIONED), never a count.
            // Read here rather than dropped so it round-trips; kept OUT of every billed total above
            // (OWNER RULING Q1, docs/design/1.6.0-QUESTIONS.md Q36).
            traffic_type: u
                .and_then(|u| u.get(FIELD_TRAFFIC_TYPE))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            // Top-level `createTime` (a sibling of `usageMetadata`, not a member of it) — read here
            // rather than dropped so it round-trips; see the field's own doc comment for why it
            // rides the usage-detail bag (OWNER RULING Q1, docs/design/1.6.0-QUESTIONS.md Q36).
            create_time: read_gemini_create_time(data),
            // The AUDIO slices of the prompt and of the answer (GEM-12) — attribution only.
            input_audio_tokens: gemini_modality_count(u, "promptTokensDetails", "AUDIO"),
            output_audio_tokens: gemini_modality_count(u, "candidatesTokensDetails", "AUDIO"),
            ..Default::default()
        },
    })
}

/// [`gemini_billed_usage`] for a fixture the test already knows carries readable counts. Test-only:
/// production goes through the refusing form, never through a read that could default a count.
#[cfg(test)]
pub(super) fn gemini_usage(data: &serde_json::Value) -> crate::ir::IrUsage {
    gemini_billed_usage(data).expect("test fixture carries readable usage counts")
}

// ── BILLED COUNTS (#42) ──────────────────────────────────────────────────────────────────────────

/// Read one BILLED count off a usage object under `usage_count::billed_count`'s contract: an absent
/// usage object, an absent field or a JSON `null` is 0 (exactly as before), a readable count is the
/// count (through the crate's one seam, `read_count_u64`), and a present-but-UNREADABLE count
/// REFUSES. The lenient read this replaces defaulted an unreadable count to zero, so a stringified
/// `"1500"` was ledgered as no work at all.
///
/// The read itself IS `usage_count::billed_count` — this adapter only lifts its absent-usage-object
/// case (zero) and maps its refusal onto this reader's error shape, so the contract and the bounded
/// spelling live in one place and cannot drift per dialect.
pub(super) fn billed(
    usage: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<u64, IrError> {
    usage.map_or(Ok(0), |u| {
        crate::usage_count::billed_count(u, field).map_err(refuse_unreadable_count)
    })
}

/// [`billed`] for a count whose ABSENCE the IR keeps distinct from zero (a cache tier): absent or
/// `null` is `None`, readable is `Some`, unreadable REFUSES.
pub(super) fn billed_opt(
    usage: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<Option<u64>, IrError> {
    match usage.and_then(|u| u.get(field)) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(_) => billed(usage, field).map(Some),
    }
}

/// The refusal a present-but-unreadable billed count becomes — the same `ir_parse` shape as every
/// other response this reader cannot read, with the field and the BOUNDED spelling `billed_count`
/// quoted (cut on a character boundary there, so a hostile multi-byte spelling cannot panic the cut).
pub(super) fn refuse_unreadable_count(unreadable: crate::usage_count::UnreadableCount) -> IrError {
    tracing::warn!(
        protocol = "gemini",
        field = unreadable.field,
        spelling = %unreadable.spelling,
        "usage count is present but unreadable; refusing rather than billing it as zero (#42)"
    );
    IrError {
        class: StatusClass::ClientError,
        provider_signal: Some(busbar_substrate_values::proto::SIGNAL_IR_PARSE.into()),
        retry_after: None,
    }
}
