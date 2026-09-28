//! # M4 acceptance suite (TODO M4 HOOK-PARITY, 1.6.0-TODO PHASE 4)
//!
//! The kernel's single named home for the v1.5.5 `kind: hook` test corpus, ported as BLACK-BOX
//! assertions against the CURRENT dispatch path (the real `test_env`/`resolve_one` harness above,
//! which resolves a `plugin:` ref through the same `busbar_plugin_loader::scan_and_validate` +
//! `resolve_gate_transport` seam a live request uses — not a hand-rolled `DlopenPolicy::new`).
//!
//! ## Reconciliation: 189 counted vs the signed brief's "178+4"
//!
//! A direct `#[test]`/`#[tokio::test]` count of the 8 v1.5.5 files named in
//! `inventory-hook.md` §5 gives **189** (50+43+27+13+5+16+16+19). The brief's own tally
//! ("178 hook tests plus 4 auth-cache tests") does not reconcile against any grouping of those 8
//! files' counts — no subset or combination sums to 178, and the brief's own worked arithmetic
//! ("19+43+27+16+5+5" = 115) is a third, still-different number. That mismatch is the brief's, not
//! resolved here.
//!
//! What DOES resolve, checked file-by-file against predev on this branch:
//!
//! - `crates/busbar/src/export/tests/webhook_tests.rs` (v1.5.5, 5 tests: `push_target_validates_
//!   and_carries_auth_header`, `deliver_logs_is_noop_when_unconfigured`, `delivery_failure_masks_
//!   userinfo`, `each_webhook_instance_gets_its_own_admission_gate`, `build_request_log_shape`) is
//!   **`kind: export`** (outbound webhook delivery), not `kind: hook` — it lived under `export/`
//!   in v1.5.5 too. The code it tests still exists, unchanged in kind, at
//!   `crates/busbar-kernel/src/export/{mod.rs,plugin.rs}`. The predev file at the inventory's
//!   "renamed" path (`crates/busbar-llm/src/tests/webhook_tests.rs`) is NOT a port of those 5 tests
//!   at all — it holds 11 unrelated tests (`a_tampered_body_is_refused_with_signature_mismatch`,
//!   `an_unsigned_request_is_refused_for_missing_headers`, …) verifying an INBOUND signed-webhook
//!   admission gate. Same file name, disjoint feature, disjoint kind. This is a misclassification
//!   in the inventory table, not a hook-kind gap: **excluded from this suite's scope.**
//! - True `kind: hook` v1.5.5 corpus: **189 − 5 = 184** tests.
//! - Of the 184: 89 already live natively in this crate (`tests.rs` 50→57, `scrape_tests.rs` 13→13,
//!   `wire_tests.rs` 19→19 on predev — additions are predev-only, nothing v1.5.5 removed); 70 live
//!   in `busbar-llm/src/engine/tests/{hook_seam_tests.rs,hook_opt_in_projection_tests.rs}` (plane
//!   projection/rewrite-gate coverage, verified all v1.5.5 names present there or renamed
//!   1:1 — e.g. `block_text_responses_reasoning_rejects_malformed_encrypted_content` →
//!   `responses_reasoning_reader_rejects_malformed_encrypted_content`); 16 live in
//!   `plugin-loader/src/tests/{hook_tests.rs,hook_transform_failure_tests.rs,
//!   hook_panic_status_tests.rs}` (split, +5 predev-only); 16 live in `hooks-ranking/src/tests/
//!   lib_tests.rs` + `hooks-ranking/tests/determinism.rs` (split, +5 predev-only). 89+70+16+16=191
//!   ≠ 184 only because the "+N predev-only" additions above are counted in the file totals but not
//!   in the 184 (they are net-new, tracked in inventory-hook.md §5's own predev-only list).
//!
//! ## What is physically consolidated HERE vs left at its existing (passing) location
//!
//! This file adds the ONE test from the plugin-loader-origin group whose PINNED 1.5.5 behaviour
//! (`MAX_INFLIGHT_HOOK_CALLS = 64` per loaded hook) had no equivalent anywhere in
//! this crate's own `tests.rs` dlopen coverage — the concurrency-cap/backpressure guarantee — ported
//! against the real `resolve_one` harness rather than a bare `DlopenPolicy`. Everything else in the
//! plugin-loader-origin 16 already has a same-behaviour sibling in `tests.rs` above, reached through
//! the identical harness, and is not duplicated:
//!
//! | v1.5.5 (`plugin-loader/src/hook.rs`) | this crate's already-passing equivalent |
//! |---|---|
//! | `dlopen_policy_drives_every_op` | `dlopen_decide_order_and_abstain` + `dlopen_transform_rewrite_and_reject` + `dlopen_status_and_schema_reads` |
//! | `dlopen_policy_abstains_and_drops_unknown_idx` | `dlopen_decide_order_and_abstain` |
//! | `dlopen_configure_acks_exact_version` | same name, `tests.rs:1751` |
//! | `dlopen_notify_never_errors` | `dlopen_notify_is_fire_and_forget` |
//! | `dlopen_configure_nack_is_err` | `dlopen_configure_nack_does_not_commit` |
//! | `dlopen_empty_management_reads_are_none` | `dlopen_empty_management_reads_are_fail_open_none` |
//! | `dlopen_slow_gate_hits_the_deadline` (ARCHITECT-named) | `dlopen_decide_deadline_cuts_off_a_slow_gate`, `tests.rs:2134` — **unignored, passing**: confirms the owner ruling (off-worker `spawn_blocking` + hard `timeout_ms`) holds on today's dispatch path |
//! | `dlopen_decide_reject_over_the_seam` | `dlopen_decide_reject_status_is_clamped` + `dlopen_decide_reject_from_opt_in_prompt` |
//! | `dlopen_transform_rewrites_over_the_seam` | `dlopen_transform_rewrite_and_reject` |
//! | `dlopen_a_hook_that_cannot_answer_is_an_err_not_an_abstain` | `dlopen_decide_raw_reply_is_fail_closed` |
//!
//! Genuinely not consolidated (no equivalent in `tests.rs`, but currently passing, unignored, at
//! their v1.5.5-inherited predev location `crates/plugin-loader/src/tests/`, which this crate does
//! not duplicate because they assert on the loader's OWN internal load/log plumbing rather than an
//! observable reply/timeout/metric the request path exposes): `load_refuses_kind_mismatch`,
//! `load_refuses_malformed_config`, `dlopen_plugin_panic_is_fail_closed_err`,
//! `a_plugin_log_reaches_the_host`, `the_log_ctx_is_interned_not_allocated_per_load`.
//!
//! The `busbar-llm`-origin 70 and `hooks-ranking`-origin 16 are similarly left at their existing,
//! passing predev locations: both exercise crate-private test scaffolding (`busbar_llm`'s
//! `WeightedLane`/prompt-projection fixtures; `hooks-ranking`'s native-policy signal tables) that
//! is not exported for cross-crate reuse, so relocating them here would mean rewriting rather than
//! porting them — out of scope for a byte-for-byte behaviour port.
//!
//! No test below is `#[ignore]`d: the one gap this file fills (the inflight cap) already passes
//! against today's dispatch path, and the two ARCHITECT-named timeout tests already pass, unignored,
//! in `tests.rs` above.

use std::time::Duration;

/// PINNED (inventory-hook.md §4): `MAX_INFLIGHT_HOOK_CALLS = 64` per loaded hook
/// (`crates/plugin-loader/src/hook.rs`, private const — mirrored here as a literal since it is not
/// exported across the crate boundary; the value is the pinned 1.5.5 constant, not a guess).
const MAX_INFLIGHT_HOOK_CALLS: usize = 64;

/// Ported from `crates/plugin-loader/src/tests/hook_tests.rs::hook_calls_are_capped_and_
/// saturation_fails_on_the_caller_deadline` (v1.5.5 `hook.rs` inline test), rebuilt against THIS
/// crate's `resolve_one`/`test_env` harness (the real `plugin:` resolution path) instead of a bare
/// `DlopenPolicy`.
///
/// One hook is saturated with `MAX_INFLIGHT_HOOK_CALLS` calls that never return inside the test's
/// budget (the fixture's `sleep_ms` knob). A further call must fail CLOSED on the caller's own
/// deadline — never wait out the wedge — and once the wedged calls drain, the freed slots let
/// service resume. The cap is backpressure, not a latch.
#[tokio::test]
async fn hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline() {
    let _dlopen_body = super::DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = super::test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let wedged = super::resolve_one(&env, serde_json::json!({"order": [0], "sleep_ms": 1_500}))
        .expect("resolve");

    let mut inflight = Vec::with_capacity(MAX_INFLIGHT_HOOK_CALLS);
    for _ in 0..MAX_INFLIGHT_HOOK_CALLS {
        let wedged = wedged.clone();
        inflight.push(tokio::spawn(async move {
            let _ = wedged
                .decide(
                    &super::dreq("x"),
                    &[super::dcand(0)],
                    &super::dctx(),
                    Duration::from_millis(50),
                )
                .await;
        }));
    }
    // Let every spawned call reach the plugin and take its slot.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let start = std::time::Instant::now();
    let saturated = wedged
        .decide(
            &super::dreq("y"),
            &[super::dcand(0)],
            &super::dctx(),
            Duration::from_millis(150),
        )
        .await;
    assert!(
        saturated.is_err(),
        "with every slot held, a further call must fail rather than wait for one"
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "the wait must be bounded by the caller's own deadline, not by the wedged plugin"
    );

    // The wedged calls returning frees the slots — the cap is backpressure, not a latch.
    for h in inflight {
        let _ = h.await;
    }
    let resumed = wedged
        .decide(
            &super::dreq("z"),
            &[super::dcand(0)],
            &super::dctx(),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        resumed.is_ok(),
        "a freed slot must let the next call through"
    );
}
