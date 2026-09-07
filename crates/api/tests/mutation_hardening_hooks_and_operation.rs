// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: `crates/api/src/hooks.rs` and `crates/api/src/operation.rs`.
//!
//! Neither file has ANY `#[cfg(test)] mod tests` today (unlike every other module in this crate),
//! so `RoutingDecision::from_ranked`'s real logic (dedup, unknown-idx filtering, empty→Abstain
//! coercion) and every `OpShape`/`Operation` const-fn (`may_stream`, `as_str`, `shape`, `name`) were
//! completely unexercised. Integration test (crates/api/tests/, auto-discovered by Cargo,
//! public-surface only) — no `mod` line needs adding anywhere.

use busbar_api::operation::{OpShape, Operation};
use busbar_api::RoutingDecision;
use std::collections::HashSet;

// ── `RoutingDecision::from_ranked` ────────────────────────────────────────────────────────────────

#[test]
fn from_ranked_empty_input_is_abstain() {
    let valid: HashSet<usize> = [0, 1, 2].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked(Vec::<usize>::new(), &valid),
        RoutingDecision::Abstain
    );
}

#[test]
fn from_ranked_drops_unknown_idxs_not_in_valid() {
    let valid: HashSet<usize> = [0, 1].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked(vec![5, 0, 9, 1], &valid),
        RoutingDecision::Prefer(vec![0, 1])
    );
}

/// If EVERY raw idx is unknown, the result coerces to `Abstain` (not `Prefer(vec![])`) — a policy
/// that names only garbage must look exactly like a policy with no opinion.
#[test]
fn from_ranked_all_unknown_coerces_to_abstain() {
    let valid: HashSet<usize> = [0, 1].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked(vec![7, 8, 9], &valid),
        RoutingDecision::Abstain
    );
}

/// Dedup keeps FIRST-SEEN order, not last-seen and not sorted.
#[test]
fn from_ranked_dedups_preserving_first_seen_order() {
    let valid: HashSet<usize> = [0, 1, 2].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked(vec![2, 0, 2, 1, 0], &valid),
        RoutingDecision::Prefer(vec![2, 0, 1])
    );
}

#[test]
fn from_ranked_preserves_a_clean_subset_order() {
    let valid: HashSet<usize> = [0, 1, 2, 3].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked(vec![3, 1], &valid),
        RoutingDecision::Prefer(vec![3, 1])
    );
}

// ── `OpShape` ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn op_shape_may_stream_only_invoke() {
    for shape in OpShape::ALL {
        let expected = matches!(shape, OpShape::Invoke);
        assert_eq!(
            shape.may_stream(),
            expected,
            "{shape:?} may_stream mismatch"
        );
    }
}

#[test]
fn op_shape_as_str_is_stable_and_distinct() {
    let strs: Vec<&str> = OpShape::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        strs,
        vec!["invoke", "catalogue", "fetch", "task", "subscribe", "control"]
    );
    let unique: HashSet<&str> = strs.iter().copied().collect();
    assert_eq!(unique.len(), strs.len(), "every shape's word must be distinct");
}

#[test]
fn op_shape_all_has_exactly_six_entries() {
    assert_eq!(OpShape::ALL.len(), 6);
}

// ── `Operation` ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn operation_llm_verbs_are_all_invoke_shape_with_their_published_name() {
    let cases = [
        (Operation::CHAT, "chat"),
        (Operation::EMBEDDINGS, "embeddings"),
        (Operation::MODERATION, "moderation"),
        (Operation::IMAGE, "image"),
        (Operation::TRANSCRIPTION, "transcription"),
        (Operation::SPEECH, "speech"),
        (Operation::RERANK, "rerank"),
    ];
    for (op, name) in cases {
        assert_eq!(op.shape(), OpShape::Invoke, "{name} must be Invoke-shaped");
        assert_eq!(op.name(), name);
    }
}

#[test]
fn operation_protocol_surface_verbs_carry_the_shapes_own_word() {
    let cases = [
        (Operation::INVOKE, OpShape::Invoke, "invoke"),
        (Operation::CATALOGUE, OpShape::Catalogue, "catalogue"),
        (Operation::FETCH, OpShape::Fetch, "fetch"),
        (Operation::TASK, OpShape::Task, "task"),
        (Operation::SUBSCRIBE, OpShape::Subscribe, "subscribe"),
        (Operation::CONTROL, OpShape::Control, "control"),
    ];
    for (op, shape, name) in cases {
        assert_eq!(op.shape(), shape);
        assert_eq!(op.name(), name);
    }
}

#[test]
fn operation_all_lists_exactly_the_six_protocol_surface_verbs_in_order() {
    assert_eq!(
        Operation::ALL,
        &[
            Operation::INVOKE,
            Operation::CATALOGUE,
            Operation::FETCH,
            Operation::TASK,
            Operation::SUBSCRIBE,
            Operation::CONTROL,
        ]
    );
}

/// The LLM verbs are NOT in `Operation::ALL` (they arrive from protocol declarations instead — see
/// the module doc) — pinning the negative half of that design so a mutant that folded them back in
/// (or dropped a real entry without anyone noticing the length still matched some other case) fails.
#[test]
fn operation_all_excludes_the_llm_verbs() {
    assert!(!Operation::ALL.contains(&Operation::CHAT));
    assert!(!Operation::ALL.contains(&Operation::EMBEDDINGS));
    assert_eq!(Operation::ALL.len(), 6);
}
