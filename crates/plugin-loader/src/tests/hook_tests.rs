// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/hook.rs`.

use super::*;
use busbar_api::{RoutingDecision, TransformOutcome};

/// Locate the test hook plugin cdylib in the build's target dir (mirrors the sqlite loader test).
/// Under CI (`cargo test --workspace` always builds it) a missing cdylib is a HARD failure, never
/// a silent skip — the only over-the-ABI coverage of the DlopenPolicy seam must not vanish.
///
/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a
/// ROOT build target, e.g. `cargo build --all-targets`) and the raw `<profile_dir>/deps/<name>`
/// compiler output (refreshed on every build that recompiles the lib). A SCOPED `cargo test -p
/// busbar-plugin-loader` does not uplift the cdylib to the top-level profile dir, only to
/// `target/deps`, so checking only `profile_dir` finds nothing even though the cdylib really
/// was built — and because this function only hard-panics when `CI` is set (not under a bare
/// local `cargo test`), every gated test here would quietly "pass" via its own early return
/// with zero real coverage locally. Mirrors this crate's
/// `store_fixture_plugin_path`/`secret_example_plugin_path`.
fn hook_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_hook_test_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the hook test plugin cdylib is not built under CI: `cargo test --workspace` must \
                 build busbar_hook_test_plugin (checked both the uplifted target dir and \
                 target/deps). Refusing to silently skip the only over-the-ABI coverage of the \
                 DlopenPolicy hook seam."
        );
    }
    candidate
}

/// Minimal engine-side projectors for the test: build a projection carrying `request.messages`,
/// and parse the reply with tiny fail-closed shims (the real engine wires `hooks::wire` here).
fn test_projectors() -> Arc<HookProjectors> {
    Arc::new(HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": {
                    "pool": req.pool,
                    "messages": req.prompt.as_ref().map(|p| {
                        p.messages.iter().map(|(r, t)| {
                            serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                        }).collect::<Vec<_>>()
                    }),
                },
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| {
            serde_json::json!({
                "request": {
                    "messages": req.prompt.as_ref().map(|p| {
                        p.messages.iter().map(|(r, t)| {
                            serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                        }).collect::<Vec<_>>()
                    }),
                }
            })
        }),
        normalize: Box::new(|v, cands| {
            if let Some(reject) = v.get("reject") {
                let status = reject
                    .get("status")
                    .and_then(|s| s.as_u64())
                    .map(|s| s as u16)
                    .unwrap_or(403);
                let message = reject
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(RoutingDecision::Reject { status, message });
            }
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return Ok(RoutingDecision::Abstain);
            };
            let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
            Ok(RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            ))
        }),
        transform_outcome: Box::new(|v| {
            if let Some(reject) = v.get("reject") {
                let status = reject
                    .get("status")
                    .and_then(|s| s.as_u64())
                    .map(|s| s as u16)
                    .unwrap_or(403);
                return TransformOutcome::Reject {
                    status,
                    message: reject
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string(),
                };
            }
            match v
                .get("rewrite")
                .and_then(|r| r.get("messages"))
                .and_then(|m| m.as_array())
            {
                Some(msgs) if !msgs.is_empty() => {
                    TransformOutcome::Rewrite(busbar_api::RewriteReply {
                        messages: msgs.clone(),
                        tools: Vec::new(),
                    })
                }
                _ => TransformOutcome::Abstain,
            }
        }),
        status: Box::new(|v| {
            v.get("status").map(|s| busbar_api::HookStatus {
                settings_version: None,
                settings: None,
                metrics: s.get("metrics").and_then(|m| m.as_array()).cloned(),
            })
        }),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

fn load(cfg: &str) -> Arc<dyn RoutingPolicy> {
    let path = hook_plugin_path().expect("hook cdylib built under --workspace");
    let bytes = std::fs::read(&path).expect("read hook cdylib");
    load_hook_from_bytes(
        &bytes,
        cfg,
        "test-hook",
        "hook",
        "test-hook",
        test_projectors(),
    )
    .expect("load hook plugin over the ABI")
}

fn req_with_prompt(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(busbar_api::PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
    }
}

fn cand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: Default::default(),
    }
}

fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// END-TO-END over the REAL hook cdylib: load it, then drive every op. `decide` echoes the
/// configured order; the opt-in prompt projection reaches the in-process gate and drives a
/// reject; `transform` rewrites (and rejects on the token); `configure` acks the exact version;
/// `describe` returns the schema; `status` reports the observed decide count. This is the exact
/// seam the engine sees: an `Arc<dyn RoutingPolicy>` indistinguishable from a compiled-in policy.
#[tokio::test]
async fn dlopen_policy_drives_every_op() {
    let Some(_) = hook_plugin_path() else {
        eprintln!("skip: hook test plugin cdylib not built (run under --workspace)");
        return;
    };
    let budget = Duration::from_secs(5);

    // decide: the configured order [1, 0] is echoed and normalized.
    let policy = load(r#"{"order": [1, 0], "reject_if_contains": "BLOCKME"}"#);
    let cands = [cand(0), cand(1)];
    let d = policy
        .decide(&req_with_prompt("hello"), &cands, &ctx(), budget)
        .await
        .expect("decide ok");
    assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));

    // decide: the opt-in prompt projection reaches the gate → reject (proves content arrives).
    let d = policy
        .decide(
            &req_with_prompt("please BLOCKME now"),
            &cands,
            &ctx(),
            budget,
        )
        .await
        .expect("decide ok");
    assert_eq!(
        d,
        RoutingDecision::Reject {
            status: 403,
            message: "blocked by test gate".to_string()
        }
    );

    // transform: rewrites the body; and rejects on the screen token.
    match policy.transform(&req_with_prompt("hello"), budget).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }
    match policy.transform(&req_with_prompt("BLOCKME"), budget).await {
        TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
        other => panic!("expected Reject, got {other:?}"),
    }

    // notify: fire-and-forget, never panics, never blocks.
    let projection = serde_json::to_vec(&serde_json::json!({"request": {"pool": "p"}})).unwrap();
    policy.notify(&projection, budget).await;

    // configure: the gate acks the exact version → Ok.
    policy
        .configure("test-hook", &serde_json::Map::new(), 7, budget)
        .await
        .expect("configure acks the pushed version");

    // describe: the schema envelope comes back.
    let schema = policy.describe(budget).await.expect("describe");
    assert_eq!(schema["type"], "object");

    // status: the observed decide count (we ran decide twice above).
    let status = policy.status(budget).await.expect("status");
    let metrics = status.metrics.expect("metrics");
    assert_eq!(metrics[0]["name"], "test_decides_total");
    assert!(metrics[0]["value"].as_f64().unwrap() >= 2.0);
}

/// An abstain config (no order) → the gate abstains, and an unresolvable order idx is dropped by
/// the engine's normalizer (fail-closed liberal parse over the ABI).
#[tokio::test]
async fn dlopen_policy_abstains_and_drops_unknown_idx() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load(r#"{"order": [9, 0]}"#);
    let cands = [cand(0)];
    let d = policy
        .decide(
            &req_with_prompt("x"),
            &cands,
            &ctx(),
            Duration::from_secs(5),
        )
        .await
        .expect("decide ok");
    // idx 9 is unknown (dropped), idx 0 survives.
    assert_eq!(d, RoutingDecision::Prefer(vec![0]));

    let policy = load("{}");
    let d = policy
        .decide(
            &req_with_prompt("x"),
            &cands,
            &ctx(),
            Duration::from_secs(5),
        )
        .await
        .expect("decide ok");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// A kind cross-check MISMATCH is a hard fail-closed load error naming both sides (loading the
/// hook cdylib as the wrong `manifest_kind`).
#[test]
fn load_refuses_kind_mismatch() {
    let Some(path) = hook_plugin_path() else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read hook cdylib");
    let err = match load_hook_from_bytes(&bytes, "{}", "test-hook", "store", "h", test_projectors())
    {
        Err(e) => e,
        Ok(_) => panic!("a hook cdylib loaded with manifest kind 'store' must be refused"),
    };
    assert!(err.contains("hook") && err.contains("store"), "got: {err}");
}

/// `configure` REQUIRES the plugin to ack the EXACT pushed version. The test-hook plugin acks by
/// default, so a matching-version push is `Ok`. (The wrong-version-ack rejection is exercised by
/// the ABI dispatch's version echo — a NACK echoes `version+1`, which this exact-match rejects.)
#[tokio::test]
async fn dlopen_configure_acks_exact_version() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load("{}");
    policy
        .configure("h", &serde_json::Map::new(), 5, Duration::from_secs(5))
        .await
        .expect("the plugin acks the exact pushed version");
}

/// `notify` (tap) is fire-and-forget over the dlopen seam: it never errors, even on a malformed
/// projection (swallowed) — the ported socket "notify is write-only" guarantee.
#[tokio::test]
async fn dlopen_notify_never_errors() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load("{}");
    let projection = serde_json::to_vec(&serde_json::json!({"request": {}})).unwrap();
    policy.notify(&projection, Duration::from_secs(5)).await;
    policy.notify(b"not json", Duration::from_secs(5)).await; // malformed → swallowed
}

/// A NACK'd `configure` is a wrong-version ack over the ABI → `configure` returns `Err` (the push
/// does not commit). The plugin's `nack_configure` echoes `version+1`, which the exact-match rejects.
#[tokio::test]
async fn dlopen_configure_nack_is_err() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load(r#"{"nack_configure": true}"#);
    assert!(
        policy
            .configure("h", &serde_json::Map::new(), 5, Duration::from_secs(5))
            .await
            .is_err(),
        "a NACK (wrong-version ack) must fail the configure push"
    );
}

/// `describe`/`status` are fail-open `None` when the plugin replies `{}` (unsupported): the reply
/// carries no `schema`/`status` member, so the engine surfaces nothing rather than erroring.
#[tokio::test]
async fn dlopen_empty_management_reads_are_none() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load(r#"{"empty_management": true}"#);
    assert!(policy.describe(Duration::from_secs(5)).await.is_none());
    assert!(policy.status(Duration::from_secs(5)).await.is_none());
}

/// A slow gate is cut off by the `budget` over the dlopen seam (spawn_blocking + timeout), promptly
/// → `Err`, never a hang. The blocking sleep never stalls the runtime.
#[tokio::test]
async fn dlopen_slow_gate_hits_the_deadline() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load(r#"{"order": [0], "sleep_ms": 2000}"#);
    let started = std::time::Instant::now();
    let r = policy
        .decide(
            &req_with_prompt("x"),
            &[cand(0)],
            &ctx(),
            Duration::from_millis(100),
        )
        .await;
    assert!(r.is_err(), "a slow gate must exceed the deadline");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the deadline must cut off promptly"
    );
}

/// A malformed plugin config is a fail-closed LOAD error (the ctor rejects it), never a live policy.
#[test]
fn load_refuses_malformed_config() {
    let Some(path) = hook_plugin_path() else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read hook cdylib");
    let err = match load_hook_from_bytes(
        &bytes,
        "{ this is not json",
        "test-hook",
        "hook",
        "h",
        test_projectors(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("a malformed config must fail the hook load"),
    };
    assert!(err.contains("open failed"), "got: {err}");
}

/// A `decide` REJECT rides the seam: the opt-in prompt projection reaches the gate and its
/// `{"reject":{...}}` surfaces as a `RoutingDecision::Reject` through the projector normalizer.
#[tokio::test]
async fn dlopen_decide_reject_over_the_seam() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load(r#"{"order": [0], "reject_if_contains": "BLOCKME"}"#);
    match policy
        .decide(
            &req_with_prompt("x BLOCKME y"),
            &[cand(0)],
            &ctx(),
            Duration::from_secs(5),
        )
        .await
        .expect("decide")
    {
        RoutingDecision::Reject { status, .. } => assert_eq!(status, 403),
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// `transform` over the dlopen seam maps the plugin's `{"rewrite":{...}}` reply to a `Rewrite`
/// outcome through the projector's `transform_outcome` — the rw-gate rewrite arm rides the ABI.
#[tokio::test]
async fn dlopen_transform_rewrites_over_the_seam() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load("{}");
    match policy
        .transform(&req_with_prompt("hi"), Duration::from_secs(5))
        .await
    {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }
}

/// A PANIC inside the plugin is caught at the boundary (SDK catch_unwind → PROTOCOL, plus the
/// engine's own catch_unwind) and surfaces as a fail-closed `Err` (→ on_error), never a crash.
#[tokio::test]
async fn dlopen_plugin_panic_is_fail_closed_err() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load(r#"{"panic_decide": true}"#);
    let r = policy
        .decide(
            &req_with_prompt("x"),
            &[cand(0)],
            &ctx(),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        r.is_err(),
        "a panicking gate must surface as a fail-closed Err"
    );
}
/// A hook that reports it COULD NOT ANSWER is a failure, not an abstain.
///
/// This is the distinction the ABI had no way to carry. `HookHandler::decide` returns a bare
/// value, so a gate whose remote dependency was down could only return `{}`, which the engine
/// reads as a successful "no opinion": the request proceeds and the operator's `on_error`
/// chain, whose terminal can be `reject`, never fires. A gate deliberately configured to fail
/// CLOSED failed OPEN, silently, and looked identical to one that genuinely had no view.
///
/// Asserts BOTH halves, because only the pair pins the behaviour: a failing gate is an `Err`
/// (so `on_error` resolves), and an abstaining gate is `Ok` (so a hook with no opinion still
/// lets the request through). Collapsing either into the other reintroduces the defect.
/// A plugin's diagnostics must reach the HOST rather than vanishing.
///
/// A cdylib statically links its own `tracing-core`, so its dispatcher is not this process's and
/// nothing joins them: every `tracing::warn!` inside a loaded plugin was silently discarded,
/// including auth-oidc's on a FAILED TOKEN SIGNATURE VERIFICATION. This drives the optional
/// `busbar_set_log_sink` symbol end to end over a REAL dlopen and asserts the record arrives,
/// attributed to the plugin that emitted it.
///
/// Asserted at the loader's tap rather than through a capturing `tracing` subscriber: interest
/// is cached per callsite and GLOBALLY, and this binary's sibling tests load plugins with no
/// subscriber, which caches the sink's callsite as uninteresting and makes a thread-local
/// subscriber miss the event. That is the harness, not the bridge — instrumenting the loader
/// showed the sink invoked correctly on every load — and the tap tests the property that
/// actually matters without depending on global tracing state.
#[test]
fn a_plugin_log_reaches_the_host() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let before = crate::hostlog::log_tap::RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();

    // A host subscriber has to be installed for this, and that is the POINT rather than test
    // scaffolding: the plugin is handed the host's level and filters on its own side, so with no
    // host subscriber the level is OFF and NOTHING should cross. Setting one to WARN is what
    // makes the plugin's `warn!` eligible while leaving its `debug!`/`trace!` filtered.
    struct Quiet;
    impl tracing::Subscriber for Quiet {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            *m.level() <= tracing::Level::WARN
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::WARN)
        }
        fn new_span(&self, _a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _s: &tracing::span::Id, _v: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _s: &tracing::span::Id, _f: &tracing::span::Id) {}
        fn event(&self, _e: &tracing::Event<'_>) {}
        fn enter(&self, _s: &tracing::span::Id) {}
        fn exit(&self, _s: &tracing::span::Id) {}
    }

    // The test plugin logs through the bridge from its CONSTRUCTOR, which is the case that
    // matters: installing the sink after `open` would drop exactly those lines.
    let _policy = tracing::subscriber::with_default(Quiet, || load("{}"));

    let records = crate::hostlog::log_tap::RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mine: Vec<_> = records
        .iter()
        .skip(before)
        .filter(|(_, _, text)| text.contains("host log bridge check"))
        .collect();
    assert!(
        !mine.is_empty(),
        "the plugin's own log record never crossed the ABI; records since this test began: {:?}",
        &records[before.min(records.len())..]
    );
    assert_eq!(
        mine[0].0, "test-hook",
        "the record must carry WHICH plugin emitted it"
    );
    assert_eq!(
        mine[0].1,
        busbar_plugin::cold::log_level::WARN,
        "the plugin's chosen level must survive the crossing"
    );

    // And the half that matters most in practice: a PLAIN `tracing::warn!` inside the plugin,
    // the shape every plugin library crate already uses, reaches the host too. Those call sites
    // are the ones that were being discarded — auth-ldap's ambiguous-match warning, auth-oidc's
    // failed-signature warning — and none of them would be rewritten by hand.
    let traced: Vec<_> = records
        .iter()
        .skip(before)
        .filter(|(_, _, text)| text.contains("test-hook tracing call"))
        .collect();
    assert!(
        !traced.is_empty(),
        "a plain tracing::warn! inside the plugin must reach the host: {:?}",
        &records[before.min(records.len())..]
    );
    assert!(
        traced[0].2.contains("probe=") && traced[0].2.contains("tracing-bridge"),
        "structured fields must survive, not just the message: {:?}",
        traced[0].2
    );
    assert_eq!(
        traced[0].1,
        busbar_plugin::cold::log_level::WARN,
        "the tracing level must map across"
    );

    // The plugin also emits at DEBUG and TRACE. Under this binary's default (no host subscriber
    // installed, so the host level is OFF/quiet) neither may cross: the plugin is told the
    // host's level and filters BEFORE building a record. Letting them through would make every
    // `trace!` in a plugin's whole dependency tree allocate and cross the FFI call on the
    // request path, only for the host to drop it.
    let noisy: Vec<_> = records
        .iter()
        .skip(before)
        .filter(|(_, lvl, _)| {
            *lvl == busbar_plugin::cold::log_level::DEBUG
                || *lvl == busbar_plugin::cold::log_level::TRACE
        })
        .collect();
    assert!(
        noisy.is_empty(),
        "debug/trace records crossed the boundary despite a quiet host: {noisy:?}"
    );
}

/// The sink's `ctx` must be interned per DISTINCT plugin name, not allocated per LOAD.
///
/// `wire_up_raw` runs per config reload, per `push_configure`, per `fetch_schema` and per
/// `fetch_status` — the last of which fires on every Prometheus scrape and every admin status
/// poll. A per-load allocation is therefore per-CALL and unbounded, driven by routine external
/// scraping: the exact leak `intern_name` exists to close, and the first version of the log
/// bridge reintroduced it. Loading the same plugin repeatedly must hand out ONE pointer.
#[test]
fn the_log_ctx_is_interned_not_allocated_per_load() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let before = crate::hostlog::log_tap::RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    for _ in 0..5 {
        let _ = load("{}");
    }
    let names: Vec<String> = crate::hostlog::log_tap::RECORDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .skip(before)
        .map(|(n, _, _)| n.clone())
        .collect();
    assert!(!names.is_empty(), "the loads should have produced records");
    assert!(
        names.iter().all(|n| n == "test-hook"),
        "every load must report the same interned name: {names:?}"
    );
}

#[tokio::test]
async fn dlopen_a_hook_that_cannot_answer_is_an_err_not_an_abstain() {
    let Some(_) = hook_plugin_path() else {
        return;
    };
    let failing = load(r#"{"fail_decide": "scoring service unreachable"}"#);
    let r = failing
        .decide(
            &req_with_prompt("x"),
            &[cand(0)],
            &ctx(),
            Duration::from_secs(5),
        )
        .await;
    let err = r.expect_err(
        "a gate that reports it could not answer must be an Err so the operator's on_error \
             chain resolves, not an Ok that lets the request proceed",
    );
    assert!(
        format!("{err:?}").contains("scoring service unreachable"),
        "the hook's own reason must reach the operator, got {err:?}"
    );

    // The other half: an ordinary abstain is still a SUCCESS, so a hook with no opinion does
    // not start rejecting traffic.
    let abstaining = load(r#"{"raw_decide_reply": {}}"#);
    assert!(
        abstaining
            .decide(
                &req_with_prompt("x"),
                &[cand(0)],
                &ctx(),
                Duration::from_secs(5),
            )
            .await
            .is_ok(),
        "an abstain must remain a successful no-opinion, not become a failure"
    );
}

/// A `spawn_blocking` task runs to completion, so a timed-out hook call abandons the future but
/// NOT the thread. Uncapped, a wedged plugin would leak one blocking thread per call until
/// Tokio's 512-thread pool is exhausted and every unrelated `spawn_blocking` in the process —
/// governance store I/O, admin transactions, the budget flusher — queued behind it forever.
///
/// The cap must therefore (a) sit far below the pool, and (b) make a saturated plugin fail on
/// the caller's own deadline rather than wait for a slot indefinitely.
/// `#[ignore]`: this test's SUBJECT is `HOOK_CALL_SLOTS` (`hook.rs`), a crate-global
/// `Semaphore::const_new(MAX_INFLIGHT_HOOK_CALLS)` acquired by every hook call
/// (`DlopenPolicy::call`). Draining all of it for the test's duration makes any
/// concurrently-running sibling hook test in this binary (the transform/status/decide tests,
/// `dlopen_plugin_panic_is_fail_closed_err`, …) take the caller-deadline timeout branch and fail
/// on a fail-closed `Err`/`None` it did not expect — for a reason unrelated to what it tests. The
/// pool being process-global is load-bearing production behaviour (it protects Tokio's shared
/// blocking pool across every loaded plugin), not something a test can inject around without
/// weakening that guarantee. Run explicitly and alone to reproduce:
/// `cargo test -p busbar-plugin-loader -- --ignored --test-threads=1 hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline`.
#[tokio::test]
#[ignore = "drains the global hook-call semaphore; run alone"]
async fn hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline() {
    // The cap must leave most of Tokio's 512-thread blocking pool to the rest of the process.
    const _: () = assert!(MAX_INFLIGHT_HOOK_CALLS < 256);

    let Some(_) = hook_plugin_path() else {
        return;
    };
    let policy = load("{}");

    // Occupy every slot, standing in for that many wedged plugin threads.
    let held = HOOK_CALL_SLOTS
        .acquire_many(MAX_INFLIGHT_HOOK_CALLS as u32)
        .await
        .expect("slots are open");

    let start = std::time::Instant::now();
    assert!(
        policy.status(Duration::from_millis(150)).await.is_none(),
        "with every slot held, a hook call must fail rather than wait for one"
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "the wait must be bounded by the caller's budget, not by the wedged plugin"
    );

    // Releasing the slots restores service — the cap is backpressure, not a latch.
    drop(held);
    assert!(
        policy.status(Duration::from_secs(5)).await.is_some(),
        "a freed slot must let the next call through"
    );
}
