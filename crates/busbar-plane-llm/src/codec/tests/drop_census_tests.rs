// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DROP-NAMES CENSUS: how many (dialect, IR name) drops are named by the IR name because the
//! dialect's map file has no row for the member (design F3 "Drops"; never silent, driven to 0).

// ───────────────────────────── the census ─────────────────────────────

/// The IR members a seam gate or a writer drops by name, with the rows each is looked up by.
const NAMED: &[(&str, &[&str])] = &[
    ("n", &[]),
    (
        "reasoning",
        &["reasoning_effort", "reasoning", "thinking_budget"],
    ),
    ("cache_control", &[]),
    ("stop", &[]),
    ("tool_choice", &[]),
    ("parallel_tool_calls", &[]),
    ("response_format", &[]),
    ("tools", &[]),
    ("metadata", &[]),
    ("top_k", &[]),
    ("top_logprobs", &[]),
    ("output_modalities", &[]),
    ("logprobs", &[]),
    ("service_tier", &[]),
    ("temperature", &[]),
    ("top_p", &[]),
];

/// The (dialect, IR name) pairs whose drop is named by the IR name because the dialect's map file
/// has no row for it, measured 2026-10-02. A ratchet: it may only go down (add the row to the
/// dialect's map file), toward 0.
const UNRESOLVED_CEILING: usize = 41;

#[test]
fn the_drop_names_census_only_goes_down() {
    let mut unresolved = Vec::new();
    for dialect in [
        "anthropic",
        "bedrock",
        "cohere",
        "gemini",
        "openai",
        "responses",
    ] {
        for (name, rows) in NAMED {
            if crate::codec::drops::resolve(dialect, name, rows).is_none() {
                unresolved.push(format!("{dialect}:{name}"));
            }
        }
    }
    println!(
        "drop-names census: {} unresolved {unresolved:?}",
        unresolved.len()
    );
    assert!(
        unresolved.len() <= UNRESOLVED_CEILING,
        "a drop is named by its IR name for {} pairs (ceiling {UNRESOLVED_CEILING}): {unresolved:?}",
        unresolved.len()
    );
}
