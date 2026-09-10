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
use busbar_api::{
    ArgumentProjection, CallerIdentity, HookStatus, PolicyError, PolicyResult, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest,
};
use std::collections::HashSet;

/// A minimal, single-poll async executor: every default `RoutingPolicy` method under test here
/// returns immediately (no real I/O, no real await point), so a no-op waker that never actually
/// wakes anything is sufficient — this avoids pulling a runtime crate (tokio/futures) into this
/// crate's dependency tree just to drive three trivial default-method calls.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn no_op(_: *const ()) {}
    fn clone_raw(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_raw, no_op, no_op, no_op);
    let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
    let waker = unsafe { Waker::from_raw(raw_waker) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

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
        vec![
            "invoke",
            "catalogue",
            "fetch",
            "task",
            "subscribe",
            "control"
        ]
    );
    let unique: HashSet<&str> = strs.iter().copied().collect();
    assert_eq!(
        unique.len(),
        strs.len(),
        "every shape's word must be distinct"
    );
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

// ── `hooks.rs`'s redacting `Debug` impls ─────────────────────────────────────────────────────────

/// `ArgumentProjection`'s `Debug` must actually WRITE the shape summary (system char count, message
/// count) — a mutant that turned the whole `fmt` body into a no-op `Ok(())` would produce an EMPTY
/// debug string, which this catches, while still never emitting the operator-opted-in argument
/// payload itself.
///
/// The two labels it asserts are this projection's OWN members (`system`, `messages`) and stay; the
/// `RoutingRequest::system_chars` member that shared one of those words is gone, so this is now the
/// only `system_chars` in the hook contract and the pin is the only thing holding it.
#[test]
fn argument_projection_debug_writes_shape_not_empty_and_never_the_text() {
    let proj = ArgumentProjection {
        system: Some(std::borrow::Cow::Borrowed("you are a helpful assistant")),
        messages: vec![
            (
                std::borrow::Cow::Borrowed("user"),
                std::borrow::Cow::Borrowed("what is the capital of France"),
            ),
            (
                std::borrow::Cow::Borrowed("assistant"),
                std::borrow::Cow::Borrowed("Paris"),
            ),
        ],
    };
    let dbg = format!("{proj:?}");
    assert!(!dbg.is_empty(), "a no-op Debug body must be caught");
    assert!(dbg.contains("system_chars"), "{dbg}");
    assert!(dbg.contains("message_count"), "{dbg}");
    assert!(
        dbg.contains('2'),
        "message_count must reflect the real count: {dbg}"
    );
    assert!(
        !dbg.contains("capital of France") && !dbg.contains("Paris"),
        "the argument payload must never appear in Debug: {dbg}"
    );
}

/// `CallerIdentity`'s `Debug` shows the operator-facing key fields but redacts the end-user PII —
/// same "must not be a no-op" pin as `ArgumentProjection`, plus the redaction split.
#[test]
fn caller_identity_debug_writes_key_fields_and_redacts_user() {
    let id = CallerIdentity {
        key_id: Some("vk_1".to_string()),
        key_name: Some("prod-key".to_string()),
        user: Some("alice@example.com".to_string()),
    };
    let dbg = format!("{id:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("vk_1"), "{dbg}");
    assert!(dbg.contains("prod-key"), "{dbg}");
    assert!(!dbg.contains("alice@example.com"), "{dbg}");
    assert!(dbg.contains("redacted"), "{dbg}");
}

// ── `RoutingPolicy`'s defaulted `configure`/`describe`/`status` ─────────────────────────────────

struct MinimalPolicy;

#[async_trait::async_trait]
impl RoutingPolicy for MinimalPolicy {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[busbar_api::Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "minimal"
    }
}

#[test]
fn routing_policy_configure_default_is_a_loud_error() {
    let p = MinimalPolicy;
    let settings = serde_json::Map::new();
    let result: Result<(), PolicyError> =
        block_on(p.configure("hook-1", &settings, 1, std::time::Duration::from_millis(10)));
    assert!(
        result.is_err(),
        "a transport that cannot be configured must error, never silently accept"
    );
}

#[test]
fn routing_policy_describe_default_is_none() {
    let p = MinimalPolicy;
    let out = block_on(p.describe(std::time::Duration::from_millis(10)));
    assert_eq!(out, None);
}

#[test]
fn routing_policy_status_default_is_none() {
    let p = MinimalPolicy;
    let out: Option<HookStatus> = block_on(p.status(std::time::Duration::from_millis(10)));
    assert_eq!(out, None);
}
