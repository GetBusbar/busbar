//! # M4 acceptance suite (TODO M4 HOOK-PARITY, 1.6.0-TODO PHASE 4)
//!
//! The kernel's single named home for the v1.5.5 `kind: hook` test corpus, ported as BLACK-BOX
//! assertions against the CURRENT resolution path (the `test_env`/`resolve_one` harness above,
//! which resolves a `plugin:` ref through the registry and the kernel's hook axis port — the same
//! `resolve_gate_transport` seam a live request uses — not a hand-rolled `HookPolicy::policy`).
//!
//! ## Moved out with the test-hook plugin (OWNER 2026-10-03, no test plugins)
//!
//! This file held ONE test: the inflight cap, ported from the loader's
//! `hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline`. The cap is the
//! dispatcher's (a hook's Statement `max_inflight`), and the plugin that wedged it here is deleted;
//! a double behind the kernel's port would only prove its own cap. It now lives where the cap does,
//! every assertion kept: `busbar-plugin-loader`'s
//! `hook_door_tests::the_inflight_cap_saturates_and_fails_on_the_caller_deadline_through_the_axis`,
//! over the loader's own hook fixture. The kernel's half of the same call path (the budget, the
//! error `on_error` decides) stays in `tests.rs` above.
//!
//! ## THE COUNT, ENUMERATED (ARCHITECT ruling M9, 2026-10-14)
//!
//! The suite's size is [`HOOK_PARITY_TESTS`], the length of [`CORPUS`]: every
//! `#[test]`/`#[tokio::test]` function of the seven v1.5.5 `kind: hook` files, by name, read off
//! the `v1.5.5` tag (`git show v1.5.5:<file>`, an attribute at the start of a line). It is **181**:
//! 69 of the v1.5.5 proxy tests (`proxy/tests/hook_seam_tests.rs` 42,
//! `hook_opt_in_projection_tests.rs` 27) and 112 of core (`hooks/tests/tests.rs` 50,
//! `scrape_tests.rs` 11, `hooks/wire.rs` 19, the loader's `hook.rs` 16, the in-tree hook's 16).
//!
//! The 184 below was `grep -c '#\[(tokio::)?test'` over the same files, which also counts three
//! COMMENTS that spell an attribute (`hook_seam_tests.rs:2133`, `scrape_tests.rs:236,246`): 43 and
//! 13 where the files hold 42 and 11 tests. Every other written size is held to this one by
//! `cargo xtask gate hook-parity-count`.
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
//!   "renamed" path (the retired engine crate's `src/tests/webhook_tests.rs`) is NOT a port of those 5 tests
//!   at all — it holds 11 unrelated tests (`a_tampered_body_is_refused_with_signature_mismatch`,
//!   `an_unsigned_request_is_refused_for_missing_headers`, …) verifying an INBOUND signed-webhook
//!   admission gate. Same file name, disjoint feature, disjoint kind. This is a misclassification
//!   in the inventory table, not a hook-kind gap: **excluded from this suite's scope.**
//! - True `kind: hook` v1.5.5 corpus by that attribute count: **189 − 5 = 184**; by name, **181**
//!   (the enumeration above: the attribute count read three comments as tests).
//! - Of the 184: 89 already live natively in this crate (`tests.rs` 50→57, `scrape_tests.rs` 13→13,
//!   `wire_tests.rs` 19→19 on predev — additions are predev-only, nothing v1.5.5 removed); 70 live
//!   in `the retired engine crate/src/engine/tests/{hook_seam_tests.rs,hook_opt_in_projection_tests.rs}` (plane
//!   projection/rewrite-gate coverage, verified all v1.5.5 names present there or renamed
//!   1:1 — e.g. `block_text_responses_reasoning_rejects_malformed_encrypted_content` →
//!   `responses_reasoning_reader_rejects_malformed_encrypted_content`); 16 live in
//!   the plugin loader's own hook, transform-failure and panic-status tests (split, +5
//!   predev-only); 16 live in the ranking hook's own unit and determinism suites (split, +5
//!   predev-only). 89+70+16+16=191
//!   ≠ 184 only because the "+N predev-only" additions above are counted in the file totals but not
//!   in the 184 (they are net-new, tracked in inventory-hook.md §5's own predev-only list).
//!
//! ## What is physically consolidated HERE vs left at its existing (passing) location
//!
//! The ONE test from the loader-origin group whose PINNED 1.5.5 behaviour (`MAX_INFLIGHT_HOOK_CALLS =
//! 64` per loaded hook) had no equivalent in `tests.rs` — the concurrency-cap/backpressure guarantee
//! — lives in the loader (see above). Everything else in the
//! loader-origin 16 already has a same-behaviour sibling in `tests.rs` above, reached through
//! the identical harness, and is not duplicated:
//!
//! | v1.5.5 (the loader's hook module) | this crate's already-passing equivalent |
//! |---|---|
//! | `dlopen_policy_drives_every_op` | `dlopen_decide_order_and_abstain` + `dlopen_transform_rewrite_and_reject` + `dlopen_status_and_schema_reads` |
//! | `dlopen_policy_abstains_and_drops_unknown_idx` | `dlopen_decide_order_and_abstain` |
//! | `dlopen_configure_acks_exact_version` | same name, in `tests.rs` |
//! | `dlopen_notify_never_errors` | `dlopen_notify_is_fire_and_forget` |
//! | `dlopen_configure_nack_is_err` | `dlopen_configure_nack_does_not_commit` |
//! | `dlopen_empty_management_reads_are_none` | `dlopen_empty_management_reads_are_fail_open_none` |
//! | `dlopen_slow_gate_hits_the_deadline` (ARCHITECT-named) | `dlopen_decide_deadline_cuts_off_a_slow_gate`, in `tests.rs` — **unignored, passing**: confirms the owner ruling (THE DESIGN §11.11 R1, l.298-301: every hook call runs on an off-worker lane and a crossing watchdog trips at the deadline) holds on today's dispatch path |
//! | `dlopen_decide_reject_over_the_seam` | `dlopen_decide_reject_status_is_clamped` + `dlopen_decide_reject_from_opt_in_prompt` |
//! | `dlopen_transform_rewrites_over_the_seam` | `dlopen_transform_rewrite_and_reject` |
//! | `dlopen_a_hook_that_cannot_answer_is_an_err_not_an_abstain` | `dlopen_decide_raw_reply_is_fail_closed` |
//!
//! Genuinely not consolidated (no equivalent in `tests.rs`, but currently passing, unignored, at
//! their v1.5.5-inherited predev location in the plugin loader's own tests, which this crate does
//! not duplicate because they assert on the loader's OWN internal load/log plumbing rather than an
//! observable reply/timeout/metric the request path exposes): `load_refuses_kind_mismatch`,
//! `load_refuses_malformed_config`, `dlopen_plugin_panic_is_fail_closed_err`,
//! `a_plugin_log_reaches_the_host`, `the_log_ctx_is_interned_not_allocated_per_load`.
//!
//! The the retired engine crate-origin 70 and ranking-hook-origin 16 are similarly left at their existing,
//! passing predev locations: both exercise crate-private test scaffolding (the retired engine crate's
//! `WeightedLane`/prompt-projection fixtures; the ranking hook's native-policy signal tables) that
//! is not exported for cross-crate reuse, so relocating them here would mean rewriting rather than
//! porting them — out of scope for a byte-for-byte behaviour port.
//!
//! The two ARCHITECT-named timeout tests pass, unignored, in `tests.rs` above (the kernel's half)
//! and in the loader's `a_slow_hook_is_cut_off_at_its_budget_through_the_axis` (the lane's half).

/// THE SUITE'S SIZE: the one number every writing of it is held to.
pub(crate) const HOOK_PARITY_TESTS: usize = 181;
/// Of them, of the v1.5.5 proxy tests' origin (`proxy` rows of [`CORPUS`]).
pub(crate) const PROXY_ORIGIN: usize = 69;
/// Of them, of core: the kernel's, the loader's and the in-tree hook's (`core` rows of [`CORPUS`]).
pub(crate) const CORE_ORIGIN: usize = 112;

/// THE v1.5.5 `kind: hook` CORPUS, by name: one `origin<TAB>v1.5.5 file<TAB>test fn` row per test,
/// kept as data beside the other v1.5.5 readings rather than in this crate's source: the rows spell
/// the v1.5.5 files and tests as they were, and a neutral crate's source names no instance (Law 0).
const CORPUS: &str = "../../testing/hook-parity/v1.5.5-hook-corpus.tsv";

/// [`CORPUS`]'s rows, `(origin, file, test fn)`, its `#` comment lines skipped.
fn v155_hook_corpus() -> Vec<(String, String, String)> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the v1.5.5 hook corpus must be readable at {path:?}: {e}"));
    raw.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut cols = l.split('\t');
            let mut next = || cols.next().unwrap_or_default().to_string();
            let row = (next(), next(), next());
            assert!(
                !row.2.is_empty() && cols.next().is_none(),
                "a corpus row is origin, file and test fn: {l:?}"
            );
            row
        })
        .collect()
}

/// THE COUNT IS THE ENUMERATION: the constant is the corpus's length, the split sums to it, and no
/// test is listed twice. RED on any written figure that is not what the corpus holds.
#[test]
fn the_hook_parity_count_is_the_enumerated_corpus() {
    let corpus = v155_hook_corpus();
    assert_eq!(corpus.len(), HOOK_PARITY_TESTS);
    assert!(
        corpus.iter().all(|(o, _, _)| o == "proxy" || o == "core"),
        "an origin is `proxy` or `core`"
    );
    let proxy = corpus.iter().filter(|(o, _, _)| o == "proxy").count();
    assert_eq!(proxy, PROXY_ORIGIN);
    assert_eq!(corpus.len() - proxy, CORE_ORIGIN);
    assert_eq!(PROXY_ORIGIN + CORE_ORIGIN, HOOK_PARITY_TESTS);
    let distinct: std::collections::BTreeSet<(&str, &str)> = corpus
        .iter()
        .map(|(_, file, name)| (file.as_str(), name.as_str()))
        .collect();
    assert_eq!(distinct.len(), corpus.len(), "a test is listed twice");
    let files: std::collections::BTreeSet<&str> =
        corpus.iter().map(|(_, file, _)| file.as_str()).collect();
    assert_eq!(
        files.len(),
        7,
        "the corpus is seven v1.5.5 files: {files:?}"
    );
}
