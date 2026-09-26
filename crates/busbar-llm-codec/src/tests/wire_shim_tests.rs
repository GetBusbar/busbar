// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `tier_usage()`'s OWN dedicated suite (item 307) — until now the function every dialect's usage
//! funnels through before the ledger/metering write had no `#[cfg(test)] mod tests` of its own and
//! was exercised only incidentally, by two other suites' goldens (`ir::tests::tests` line 360,
//! `bedrock::tests::tests::bedrock_input_tier_excludes_cache_at_billing_boundary`), neither of which
//! ever built the one case that matters for money: a cache field that is `None` because the provider
//! never reported it, versus a cache field that is `None` because an upstream `read_count_u64` READ
//! REFUSED an unparseable value.
//!
//! Item 133 (`92227db57`, "a present-but-unreadable billed count REFUSES, never ledgers 0") already
//! moved the fix to the ROOT: every dialect reader (`billed`/`billed_opt` over
//! `usage_count::billed_count`) now refuses BEFORE a [`TokenUsage`] is ever constructed, so by the
//! time a value reaches `tier_usage()`, `None` can only mean "legitimately absent" — the refusal
//! never survives to become a collapsed `None` here. That invariant is what makes `tier_usage()`'s
//! `.unwrap_or(0)` safe, and it is exactly what this suite pins: the reported/absent split at
//! `tier_usage()` itself (this module's own contract), AND — end to end, through a real dialect
//! reader this crate owns — that an unreadable cache count REFUSES through item 133's path rather
//! than ever reaching `tier_usage()` as a bare, indistinguishable `None`.

use super::tier_usage;
use busbar_substrate_values::billing::TokenUsage;

fn unit(usage: &busbar_substrate_values::billing::Usage, k: &str) -> Option<u64> {
    usage.usage_units.get(k).copied()
}

/// A tier the dialect reader actually reported (including an honest zero, distinct from a
/// legitimately-absent tier — see `sparse_zero_and_absent_cache_tiers_are_both_omitted`) is priced.
#[test]
fn reported_tiers_are_priced() {
    let tu = TokenUsage {
        input: 100,
        output: 40,
        cache_read: Some(30),
        cache_creation: Some(20),
        ..Default::default()
    };
    let usage = tier_usage(&tu);
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_INPUT),
        Some(100)
    );
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_OUTPUT),
        Some(40)
    );
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_CACHE_READ),
        Some(30)
    );
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_CACHE_WRITE),
        Some(20)
    );
}

/// A cache tier the provider genuinely never reported (`None`, per `billed_opt`'s absent/null
/// contract) is OMITTED from the sparse map — not billed, not present as a zero entry either. This
/// is the legitimate-absence case `tier_usage()` must keep distinguishable from a refusal: a refusal
/// never reaches this function at all (see `unreadable_top_level_cache_count_refuses_before_reaching_tier_usage`
/// below), so every `None` this function ever sees is this case.
#[test]
fn absent_cache_tiers_are_omitted_not_billed() {
    let tu = TokenUsage {
        input: 100,
        output: 40,
        cache_read: None,
        cache_creation: None,
        ..Default::default()
    };
    let usage = tier_usage(&tu);
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_CACHE_READ),
        None
    );
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_CACHE_WRITE),
        None
    );
    // input/output are unconditional tiers (not `Option`), so a genuine zero on them is a real
    // reported zero (e.g. an embeddings response), not an absence — and is likewise omitted by the
    // no-zero-entry sparse contract.
    let tu_zero_output = TokenUsage {
        input: 5,
        output: 0,
        ..Default::default()
    };
    let usage = tier_usage(&tu_zero_output);
    assert_eq!(unit(&usage, busbar_contract::records::UNIT_OUTPUT), None);
    assert_eq!(unit(&usage, busbar_contract::records::UNIT_INPUT), Some(5));
}

/// An explicit reported zero (`Some(0)`) and a legitimately-absent tier (`None`) price IDENTICALLY —
/// both omitted — which is correct: neither should ever be billable money, and the map's sparse
/// contract (module doc, `wire_shim.rs`) makes no distinction between "reported zero" and
/// "not reported" once the value is a readable zero. The distinction this suite exists to police is
/// a DIFFERENT one: a refused, UNREADABLE value must never collapse into either of these — it must
/// never reach `tier_usage()` as a value at all.
#[test]
fn sparse_zero_and_absent_cache_tiers_are_both_omitted() {
    let reported_zero = TokenUsage {
        input: 5,
        output: 9,
        cache_read: Some(0),
        cache_creation: Some(0),
        ..Default::default()
    };
    let absent = TokenUsage {
        input: 5,
        output: 9,
        cache_read: None,
        cache_creation: None,
        ..Default::default()
    };
    assert_eq!(tier_usage(&reported_zero), tier_usage(&absent));
}

/// END TO END, through a real dialect reader this crate owns (not cohere/openai_responses): a
/// present-but-unparseable top-level `cache_read_input_tokens`/`cache_creation_input_tokens` REFUSES
/// the buffered response outright (item 133's path — `billed_opt` over `usage_count::billed_count`)
/// and never reaches `TokenUsage`, let alone `tier_usage()`. This is the proof that the `None`
/// `tier_usage()` sees can only ever mean "legitimately absent": the alternative cause never survives
/// to become a `TokenUsage` at all. Nothing in this crate's existing suites drove an unreadable
/// TOP-LEVEL cache count through a buffered response before this test (the item-133 refusal suite,
/// `anthropic/tests/unreadable_count_refusal_tests.rs`, covers `input_tokens`/`output_tokens` and the
/// nested 5m/1h cache-creation detail tiers, never the top-level `cache_read_input_tokens`/
/// `cache_creation_input_tokens` fields `tier_usage()` actually prices).
#[test]
fn unreadable_top_level_cache_count_refuses_before_reaching_tier_usage() {
    use crate::anthropic::AnthropicReader;
    use crate::proto_codec::ProtocolReader;

    let body = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 9,
            "cache_read_input_tokens": "1000",
        }
    });
    AnthropicReader.read_response(&body).expect_err(
        "a present, unreadable cache_read_input_tokens must refuse — never reach tier_usage() as a \
         collapsed None",
    );

    let body = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 9,
            "cache_creation_input_tokens": "200",
        }
    });
    AnthropicReader.read_response(&body).expect_err(
        "a present, unreadable cache_creation_input_tokens must refuse — never reach tier_usage() \
         as a collapsed None",
    );

    // Control: the SAME shape with a readable cache count reads fine and prices through tier_usage
    // as a real, present tier — proving the refusal above is about readability, not the field's mere
    // presence.
    let body = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 9,
            "cache_read_input_tokens": 1000,
        }
    });
    let ir = AnthropicReader
        .read_response(&body)
        .expect("a readable cache_read_input_tokens must read, not refuse");
    let tu = ir.usage.to_token_usage();
    let usage = tier_usage(&tu);
    assert_eq!(
        unit(&usage, busbar_contract::records::UNIT_CACHE_READ),
        Some(1000)
    );
}
