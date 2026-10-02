//! Gemini `usageMetadata` → [`crate::codec::ir::IrUsage`].

use super::*;
use crate::codec::usage_count::{read_usage, CountRead, CountSlot, UsageCount};

/// GEMINI'S USAGE COUNTS, AS DATA (#42). Cache tokens: `cachedContentTokenCount` is a slice INSIDE
/// `promptTokenCount`, so it is subtracted (saturating) there and carried as the IR's
/// `cache_read_input_tokens` — the SAME field Bedrock's `cacheReadInputTokens` and Anthropic's
/// `cache_read_input_tokens` populate. `toolUsePromptTokenCount` is ADDITIVE beside the prompt (see
/// [`GEMINI_USAGE_ADDITIVE_TERMS`] for the recording that settles it: 32 tool-use tokens against an
/// 18-token prompt) and Google counts it at the input rate, so it is added to `input_tokens` and also
/// recorded as attribution. THINKING TOKENS ARE OUTPUT TOKENS: `candidatesTokenCount` counts only the
/// visible answer and the 2.5-series reasoning arrives in the separate, additive `thoughtsTokenCount`
/// (Google's own `totalTokenCount` is prompt + candidates + thoughts), so it is added to
/// `output_tokens` — what `output_tokens` means for every other provider — and recorded as the
/// reasoning sub-bucket; the Gemini writer splits the two back apart (GEM-13). The AUDIO entries of
/// the per-modality lists are attribution slices (GEM-12).
///
/// THE LEDGER RECORDS EXACTLY WHAT GOOGLE REPORTS (owner 2026-10-02: ledger what the plane
/// reports; fix Gemini ledging). Every count the pinned wire lock
/// (`testing/llm-conformance/wire/gemini.wire.json`) declares under `usageMetadata` is itemized
/// into an EXISTING meter class by what Google's protocol says the count is: prompt -> input,
/// `cachedContentTokenCount` -> cache read (out of the prompt), `toolUsePromptTokenCount` -> input,
/// candidates -> output, `thoughtsTokenCount` -> output. `totalTokenCount` is Google's sum, not a
/// unit: it is never ledgered and nothing is derived from it. A total above the itemized parts is a
/// residual gap the plane does NOT invent units for; `gemini_usage_identity_note` WARNs naming it.
/// The plane decides units only; the rate card prices what the ledger holds. The streaming
/// frames, the buffered response and a truncated-body recovery all read this one table, so a
/// truncated or streamed turn counts the same as a complete one.
pub(super) const USAGE: &[UsageCount] = &[
    (
        CountSlot::Input,
        CountRead::Zero(&[FIELD_PROMPT_TOKEN_COUNT]),
    ),
    (
        CountSlot::Input,
        CountRead::Less(&[FIELD_CACHED_CONTENT_TOKEN_COUNT]),
    ),
    (
        CountSlot::Input,
        CountRead::More(&[FIELD_TOOL_USE_PROMPT_TOKEN_COUNT]),
    ),
    (
        CountSlot::Output,
        CountRead::Zero(&[FIELD_CANDIDATES_TOKEN_COUNT]),
    ),
    (
        CountSlot::Output,
        CountRead::More(&[FIELD_THOUGHTS_TOKEN_COUNT]),
    ),
    (
        CountSlot::CacheRead,
        CountRead::Opt(&[FIELD_CACHED_CONTENT_TOKEN_COUNT]),
    ),
    (
        CountSlot::Reasoning,
        CountRead::Opt(&[FIELD_THOUGHTS_TOKEN_COUNT]),
    ),
    (
        CountSlot::ToolUsePrompt,
        CountRead::Opt(&[FIELD_TOOL_USE_PROMPT_TOKEN_COUNT]),
    ),
    (
        CountSlot::InputAudio,
        CountRead::ListFirst {
            list: &["promptTokensDetails"],
            key: FIELD_MODALITY,
            value: GEMINI_AUDIO,
            count: FIELD_TOKEN_COUNT,
        },
    ),
    (
        CountSlot::OutputAudio,
        CountRead::ListFirst {
            list: &["candidatesTokensDetails"],
            key: FIELD_MODALITY,
            value: GEMINI_AUDIO,
            count: FIELD_TOKEN_COUNT,
        },
    ),
];

/// A Gemini response (or stream frame) → the IR usage: its `usageMetadata` through [`USAGE`], plus
/// what rides beside the counts — the identity cross-check against Google's own `totalTokenCount`
/// (`None` when they agree), `usageMetadata.trafficType` (INFORMATIONAL, ON_DEMAND vs PROVISIONED,
/// docs/design/1.6.0-QUESTIONS.md Q36) and the top-level `createTime` (a sibling of `usageMetadata`).
pub(super) fn read_gemini_usage(
    data: &serde_json::Value,
) -> Result<crate::codec::ir::IrUsage, IrError> {
    let u = data.get(FIELD_USAGE_METADATA);
    let mut usage = read_usage(COUNT_LABEL, u, USAGE)?;
    usage.detail.usage_identity_note = gemini_usage_identity_note(u);
    usage.detail.traffic_type = u
        .and_then(|u| u.get(FIELD_TRAFFIC_TYPE))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    usage.detail.create_time = read_gemini_create_time(data);
    Ok(usage)
}

/// [`read_gemini_usage`] for a fixture the test already knows carries readable counts. Test-only:
/// production goes through the refusing form, never through a read that could default a count.
#[cfg(test)]
pub(super) fn gemini_usage(data: &serde_json::Value) -> crate::codec::ir::IrUsage {
    read_gemini_usage(data).expect("test fixture carries readable usage counts")
}

// ── USAGE COUNTS (#42) ───────────────────────────────────────────────────────────────────────────

/// This dialect's label on a refused usage count.
pub(super) const COUNT_LABEL: &str = "gemini";
