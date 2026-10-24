// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPEN CLASSES: every count a far end reports beside its four token totals, by the meter class
//! it is ledgered under (owner LEDGER-100, docs/design/1.6.0-QUESTIONS.md, 2026-10-03: "every unit
//! a provider/far end reports is a ledger line under its meter class; its price comes from the
//! ratecard"; an unledgered reported unit is a defect, not a residual).
//!
//! The plane REPORTS units and never a price. Each class below is declared in the plane's tail
//! ([`crate::plane_door::OPEN_CLASSES`]) and in the linked declaration's billable classes, so the
//! kernel prices it from the operator's `rate_card.<model>.units.<class>` with no plane literal of
//! its own. The ratecard's absent-rate rule is unchanged: no card reads the class at 0 (#42); a
//! present card that does not configure a declared class is a boot refusal naming it (Q29/Q35); a
//! per-lane gap refuses at run time (#42).

use crate::codec::ir::rerank::SEARCH_UNITS_CLASS;

/// Cohere chat `usage.billed_units.classifications`: the classification units Cohere bills, a
/// count that is not a token.
pub const CLASSIFICATIONS_CLASS: &str = "classifications";

/// Anthropic `usage.server_tool_use.web_fetch_requests`: the server-side URL fetches a turn made.
/// Anthropic reports the count beside the tokens the fetched content already bills as; an
/// operator prices it (0 makes it free).
pub const WEB_FETCH_REQUESTS_CLASS: &str = "web_fetch_requests";

/// The tokens a provider's own stated total counts ABOVE the itemized buckets this dialect reads
/// (OpenAI `total_tokens`, Responses `total_tokens`, Gemini `totalTokenCount`, Bedrock
/// `totalTokens`): `reported_total - summed_total` when positive. A total BELOW its terms adds no
/// unit. The itemized buckets stay exactly as the provider sent them, so the four token classes
/// bill what they billed in 1.5.5 and this class carries only the remainder.
pub const UNITEMIZED_TOKENS_CLASS: &str = "unitemized_tokens";

/// The images a per-image provider returned (dall-e, Imagen, Titan, SDXL: one per `data` entry),
/// when the answer carries no token usage.
pub const IMAGES_CLASS: &str = "images";

/// The audio duration a transcription far end reported (whisper `usage.seconds`), in whole
/// MILLISECONDS. The exact decimal (`busbar_contract::Count`, microsecond scale) is floored to the
/// millisecond, integer only: a duration with three decimals or fewer (every provider's spelling)
/// is exact, and a finer one is never rounded up past what was reported.
pub const AUDIO_MS_CLASS: &str = "audio_ms";

/// Bedrock guardrail `invocationMetrics.usage.automatedReasoningPolicies`.
pub const GUARDRAIL_AUTOMATED_REASONING_POLICIES_CLASS: &str =
    "guardrail_automated_reasoning_policies";
/// Bedrock guardrail `invocationMetrics.usage.automatedReasoningPolicyUnits`.
pub const GUARDRAIL_AUTOMATED_REASONING_POLICY_UNITS_CLASS: &str =
    "guardrail_automated_reasoning_policy_units";
/// Bedrock guardrail `invocationMetrics.usage.contentPolicyImageUnits`.
pub const GUARDRAIL_CONTENT_POLICY_IMAGE_UNITS_CLASS: &str = "guardrail_content_policy_image_units";
/// Bedrock guardrail `invocationMetrics.usage.contentPolicyUnits`.
pub const GUARDRAIL_CONTENT_POLICY_UNITS_CLASS: &str = "guardrail_content_policy_units";
/// Bedrock guardrail `invocationMetrics.usage.contextualGroundingPolicyUnits`.
pub const GUARDRAIL_CONTEXTUAL_GROUNDING_POLICY_UNITS_CLASS: &str =
    "guardrail_contextual_grounding_policy_units";
/// Bedrock guardrail `invocationMetrics.usage.sensitiveInformationPolicyFreeUnits` (AWS prices
/// these at nothing; they are still reported units, so the operator's card says what they cost).
pub const GUARDRAIL_SENSITIVE_INFORMATION_POLICY_FREE_UNITS_CLASS: &str =
    "guardrail_sensitive_information_policy_free_units";
/// Bedrock guardrail `invocationMetrics.usage.sensitiveInformationPolicyUnits`.
pub const GUARDRAIL_SENSITIVE_INFORMATION_POLICY_UNITS_CLASS: &str =
    "guardrail_sensitive_information_policy_units";
/// Bedrock guardrail `invocationMetrics.usage.topicPolicyUnits`.
pub const GUARDRAIL_TOPIC_POLICY_UNITS_CLASS: &str = "guardrail_topic_policy_units";
/// Bedrock guardrail `invocationMetrics.usage.wordPolicyUnits`.
pub const GUARDRAIL_WORD_POLICY_UNITS_CLASS: &str = "guardrail_word_policy_units";

/// The family a count-shaped open class rolls up into.
const COUNT: &str = "count";

/// EVERY OPEN CLASS THIS PLANE DECLARES, each `(class, family)`, in the order the tail states them
/// after the four token classes. `search_units` keeps its place (and family) first.
pub const OPEN_CLASSES: &[(&str, &str)] = &[
    (SEARCH_UNITS_CLASS, "units"),
    (CLASSIFICATIONS_CLASS, COUNT),
    (WEB_FETCH_REQUESTS_CLASS, COUNT),
    // Family `count`, not `token`: a token-family class counts toward a `tokens:` cap
    // (`governance::is_token_class`), and the caps keep counting exactly the itemized tokens they
    // counted in 1.5.5. The remainder is billed, never capped.
    (UNITEMIZED_TOKENS_CLASS, COUNT),
    (IMAGES_CLASS, COUNT),
    (AUDIO_MS_CLASS, "duration"),
    (GUARDRAIL_AUTOMATED_REASONING_POLICIES_CLASS, COUNT),
    (GUARDRAIL_AUTOMATED_REASONING_POLICY_UNITS_CLASS, COUNT),
    (GUARDRAIL_CONTENT_POLICY_IMAGE_UNITS_CLASS, COUNT),
    (GUARDRAIL_CONTENT_POLICY_UNITS_CLASS, COUNT),
    (GUARDRAIL_CONTEXTUAL_GROUNDING_POLICY_UNITS_CLASS, COUNT),
    (
        GUARDRAIL_SENSITIVE_INFORMATION_POLICY_FREE_UNITS_CLASS,
        COUNT,
    ),
    (GUARDRAIL_SENSITIVE_INFORMATION_POLICY_UNITS_CLASS, COUNT),
    (GUARDRAIL_TOPIC_POLICY_UNITS_CLASS, COUNT),
    (GUARDRAIL_WORD_POLICY_UNITS_CLASS, COUNT),
];

/// The number of [`OPEN_CLASSES`], for the const tables that state them one by one.
pub const OPEN_CLASS_COUNT: usize = 15;
const _: () = assert!(OPEN_CLASSES.len() == OPEN_CLASS_COUNT);

/// Bedrock's guardrail usage counts (`GuardrailUsage`), each with the open class it is ledgered
/// under. AWS bills each policy's units at its own rate, so each is its own class; a count is
/// summed over every assessment on both sides (input and output), which AWS prices alike.
pub const GUARDRAIL_COUNT_CLASSES: &[(&str, &str)] = &[
    (
        "automatedReasoningPolicies",
        GUARDRAIL_AUTOMATED_REASONING_POLICIES_CLASS,
    ),
    (
        "automatedReasoningPolicyUnits",
        GUARDRAIL_AUTOMATED_REASONING_POLICY_UNITS_CLASS,
    ),
    (
        "contentPolicyImageUnits",
        GUARDRAIL_CONTENT_POLICY_IMAGE_UNITS_CLASS,
    ),
    ("contentPolicyUnits", GUARDRAIL_CONTENT_POLICY_UNITS_CLASS),
    (
        "contextualGroundingPolicyUnits",
        GUARDRAIL_CONTEXTUAL_GROUNDING_POLICY_UNITS_CLASS,
    ),
    (
        "sensitiveInformationPolicyFreeUnits",
        GUARDRAIL_SENSITIVE_INFORMATION_POLICY_FREE_UNITS_CLASS,
    ),
    (
        "sensitiveInformationPolicyUnits",
        GUARDRAIL_SENSITIVE_INFORMATION_POLICY_UNITS_CLASS,
    ),
    ("topicPolicyUnits", GUARDRAIL_TOPIC_POLICY_UNITS_CLASS),
    ("wordPolicyUnits", GUARDRAIL_WORD_POLICY_UNITS_CLASS),
];

/// Add `n` of `class` to a class map, skipping a zero (a zero count is no hit on the class).
pub fn add(map: &mut std::collections::BTreeMap<String, u64>, class: &str, n: u64) {
    if n != 0 {
        let slot = map.entry(class.to_string()).or_insert(0);
        *slot = slot.saturating_add(n);
    }
}

#[cfg(test)]
#[path = "tests/open_class_tests.rs"]
mod tests;
