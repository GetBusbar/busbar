// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOOK seam of the kind-neutral loader: [`DlopenPolicy`], a [`busbar_api::RoutingPolicy`] backed
//! by a dynamically-loaded plugin whose kind was bound to `hook` at load. It translates each async
//! trait method (`decide`/`transform`/`notify`/`configure`/`describe`/`status`) into a `busbar_call`
//! with the matching op envelope ([`busbar_plugin_abi::hook`]).
//!
//! ## Blocking call off the async runtime
//!
//! A hook GATE can be CPU-heavy (a compressor, a classifier), so the synchronous `busbar_call` runs on
//! [`tokio::task::spawn_blocking`], never on a runtime worker. The FFI call is additionally wrapped in
//! [`std::panic::catch_unwind`] on the ENGINE side (defense in depth — the SDK already catches inside
//! the plugin): a panic that somehow crosses becomes a PROTOCOL-style error the caller coerces to the
//! hook's `on_error`, never a torn-down runtime.
//!
//! ## The contract is the engine's, not the plugin's
//!
//! `DlopenPolicy` carries the REPLY back to the engine as an opaque [`serde_json::Value`]; the
//! fail-closed reply semantics (reject-precedence, status-clamp, restrict/rewrite parsing, metric
//! bounding) live in the engine's `hooks::wire`, which parses that value. This is what keeps the
//! retired socket/webhook seam and this dlopen seam provably identical.

use crate::{stage, wire_up_raw, RawPlugin};
use busbar_api::{
    Candidate, HookStatus, PolicyError, PolicyResult, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_plugin_abi::{
    hook::{ConfigureBody, HookReply, HookRequest},
    kind as abi_kind,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

/// A projection builder the engine installs so the loader can turn the borrowed request/candidate/
/// context projections into the owned JSON `payload` the ABI carries — WITHOUT the loader depending on
/// the engine's `hooks::wire`. The engine passes closures at resolution; the loader calls them per op.
/// Kept as boxed fns so `DlopenPolicy` stays `Send + Sync + 'static`.
pub struct HookProjectors {
    /// Build the `decide` projection JSON from (request, candidates, context).
    #[allow(clippy::type_complexity)]
    pub decide: Box<
        dyn for<'a> Fn(
                &RoutingRequest<'a>,
                &[Candidate<'a>],
                &RoutingContext<'a>,
            ) -> serde_json::Value
            + Send
            + Sync,
    >,
    /// Build the `transform` projection JSON from a request (no candidates).
    #[allow(clippy::type_complexity)]
    pub transform: Box<dyn for<'a> Fn(&RoutingRequest<'a>) -> serde_json::Value + Send + Sync>,
    /// Parse a `decide` reply Value into a decision (the engine's fail-closed normalizer).
    #[allow(clippy::type_complexity)]
    pub normalize:
        Box<dyn for<'a> Fn(serde_json::Value, &[Candidate<'a>]) -> RoutingDecision + Send + Sync>,
    /// Parse a `transform` reply Value into an outcome (reject > rewrite > abstain).
    pub transform_outcome: Box<dyn Fn(serde_json::Value) -> TransformOutcome + Send + Sync>,
    /// Parse a `status` reply Value into the engine's `HookStatus` (metrics validated/bounded).
    pub status: Box<dyn Fn(serde_json::Value) -> Option<HookStatus> + Send + Sync>,
    /// Extract the `schema` member of a `describe` reply envelope.
    pub describe_schema: Box<dyn Fn(serde_json::Value) -> Option<serde_json::Value> + Send + Sync>,
}

/// A `RoutingPolicy` loaded from a dynamic library over the kind-neutral ABI. Wraps a [`RawPlugin`]
/// whose kind was bound to `hook` at load; every trait method serializes an op envelope, ships it
/// across `busbar_call` on `spawn_blocking`, and hands the reply to the engine's parsers.
pub struct DlopenPolicy {
    raw: Arc<RawPlugin>,
    projectors: Arc<HookProjectors>,
    /// The hook's stable name (metrics / `x-busbar-route`). Leaked to `'static` (the C ABI can't
    /// return a `&'static str`) — a bounded one-per-plugin leak of a non-secret id.
    name: &'static str,
}

/// Concurrency cap on hook FFI calls occupying the shared blocking pool.
///
/// A `spawn_blocking` task, once scheduled, runs to completion: the deadline in [`call_bounded`]
/// abandons the FUTURE, never the thread. A plugin that deadlocks, spins, or blocks on an unbounded
/// syscall therefore holds its blocking thread for the life of the process, and a gate fires once
/// per request. Uncapped, sustained traffic against one wedged plugin leaks a thread per call until
/// Tokio's 512-thread default pool is gone — after which every unrelated `spawn_blocking` in the
/// process queues behind it forever: governance store I/O, admin config transactions, the
/// write-behind budget flusher, and the awaited shutdown flush. One bad plugin would take the admin
/// plane and durable persistence with it.
///
/// The cap keeps that isolated to the hook: calls beyond it wait, and since acquisition happens
/// under the caller's own budget a saturated plugin surfaces as its configured `on_error`
/// disposition rather than as a process-wide stall. Sized far below the pool so the rest of the
/// process always has threads, and above any plausible legitimate hook concurrency.
const MAX_INFLIGHT_HOOK_CALLS: usize = 64;

/// Borrowing from a `static` yields a `'static` permit, which is what lets the permit move INTO the
/// blocking closure — see [`DlopenPolicy::call`] for why that placement is the whole point.
static HOOK_CALL_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_INFLIGHT_HOOK_CALLS);

impl DlopenPolicy {
    /// The ONE blocking primitive: run `op` across `busbar_call` on a blocking thread, catching any
    /// panic that crosses the FFI boundary. Returns the [`HookReply`] or a `PolicyError` (coerced to
    /// the hook's `on_error` by the caller). Not bounded here — the caller wraps in a `timeout`.
    async fn call(&self, op: HookRequest) -> Result<HookReply, PolicyError> {
        let raw = self.raw.clone();
        // Acquire BEFORE spawning and release only when the blocking closure RETURNS, not when the
        // caller stops waiting. A timed-out call drops the future while the thread runs on, so a
        // permit tied to the future's lifetime would count patience rather than threads and cap
        // nothing. Acquisition sits under the caller's `timeout`, so a saturated plugin fails the
        // hook on its own deadline instead of queueing.
        let Ok(permit) = HOOK_CALL_SLOTS.acquire().await else {
            return Err("hook call slots closed".into());
        };
        let joined = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            // Defense-in-depth `catch_unwind`: since the `extern "C-unwind"` ABI landed, the ACTUAL FFI
            // boundary is guarded inside `transport_call` (via `ffi_guard`), which converts a plugin
            // panic into a `TransportError` — so the C-unwind path this method documents is now caught
            // there and never reaches here. This outer guard is retained as a belt-and-braces net for
            // any panic that could arise in the engine-side (de)serialization wrapper around that call
            // (`transport_call`'s encode/decode), which runs on this blocking thread OUTSIDE the FFI
            // guard; catching it here fails the hook CLOSED rather than aborting the blocking-pool worker.
            catch_unwind(AssertUnwindSafe(|| {
                raw.transport_call::<HookRequest, HookReply>(&op)
            }))
        })
        .await;
        match joined {
            Ok(Ok(Ok(reply))) => Ok(reply),
            Ok(Ok(Err(e))) => Err(e.into()),
            // A panic caught here is a protocol violation — fail-closed to on_error. (The FFI-boundary
            // unwind itself is already caught inside `transport_call`; see the comment above.)
            Ok(Err(_)) => Err("hook plugin panicked across the ABI boundary".into()),
            // The blocking task was cancelled/aborted (runtime shutdown) — treat as a hook failure.
            Err(e) => Err(format!("hook plugin call task failed: {e}").into()),
        }
    }

    /// Bounded variant: `call` under a hard wall-clock `budget`, mapping a timeout to a `PolicyError`.
    async fn call_bounded(
        &self,
        op: HookRequest,
        budget: Duration,
    ) -> Result<HookReply, PolicyError> {
        match tokio::time::timeout(budget, self.call(op)).await {
            Ok(r) => r,
            Err(_) => Err(format!("hook plugin deadline ({budget:?}) exceeded").into()),
        }
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for DlopenPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        let payload = (self.projectors.decide)(req, candidates, ctx);
        let reply = self
            .call_bounded(HookRequest::Decide { payload }, budget)
            .await?;
        match reply {
            HookReply::Reply(v) => Ok((self.projectors.normalize)(v, candidates)),
            // The hook SAID it could not answer. Distinct from an abstain (`Reply({})`), and that
            // distinction is the whole point: an abstain lets the request proceed, this resolves
            // the operator's `on_error` chain, whose terminal can be `reject`. Before the ABI
            // carried this variant a hook had no way to express it and answered "no opinion"
            // instead, so a gate configured to fail closed failed open, silently.
            HookReply::Failed { message } => {
                Err(format!("hook {} could not answer: {message}", self.name).into())
            }
            // A wrong reply variant is a protocol violation → on_error (never a silent route).
            other => Err(format!("hook plugin returned {other:?} for decide").into()),
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn transform(&self, req: &RoutingRequest<'_>, budget: Duration) -> TransformOutcome {
        let payload = (self.projectors.transform)(req);
        // FAIL-CLOSED on transport/protocol error → Abstain (proceed with the ORIGINAL body); a
        // parsed reply's reject IS honored by `transform_outcome`.
        match self
            .call_bounded(HookRequest::Transform { payload }, budget)
            .await
        {
            Ok(HookReply::Reply(v)) => (self.projectors.transform_outcome)(v),
            _ => TransformOutcome::Abstain,
        }
    }

    async fn configure(
        &self,
        hook_name: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
        settings_version: u64,
        budget: Duration,
    ) -> Result<(), PolicyError> {
        let op = HookRequest::Configure(ConfigureBody {
            hook: hook_name.to_string(),
            settings: settings.clone(),
            settings_version,
            busbar_version: env!("CARGO_PKG_VERSION").to_string(),
        });
        match self.call_bounded(op, budget).await? {
            HookReply::ConfigureAck {
                settings_version: acked,
            } if acked == settings_version => Ok(()),
            HookReply::ConfigureAck {
                settings_version: acked,
            } => Err(format!(
                "hook acked the wrong settings_version ({acked} != {settings_version})"
            )
            .into()),
            other => Err(format!("hook returned {other:?} for configure (expected an ack)").into()),
        }
    }

    async fn describe(&self, budget: Duration) -> Option<serde_json::Value> {
        match self.call_bounded(HookRequest::Describe, budget).await {
            Ok(HookReply::Reply(v)) => (self.projectors.describe_schema)(v),
            _ => None,
        }
    }

    async fn status(&self, budget: Duration) -> Option<HookStatus> {
        match self.call_bounded(HookRequest::Status, budget).await {
            Ok(HookReply::Reply(v)) => (self.projectors.status)(v),
            _ => None,
        }
    }

    async fn notify(&self, projection: &[u8], budget: Duration) {
        // The tap projection arrives pre-serialized (the engine's `hooks::wire::build` bytes). Wrap it
        // in a `Notify` op envelope. A malformed projection or any transport error is swallowed — a
        // tap can NEVER delay or fail the served request.
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(projection) else {
            return;
        };
        let _ = self
            .call_bounded(HookRequest::Notify { payload }, budget)
            .await;
    }
}

impl std::fmt::Debug for DlopenPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlopenPolicy")
            .field("name", &self.name)
            .field("path", &self.raw.path)
            .finish()
    }
}

/// Load a HOOK policy from EXACTLY the verified library `bytes` (TOCTOU-safe). Enforces the frozen
/// contract (transport version, kind == `hook` == the signed manifest — mismatch is a hard fail-closed
/// load error naming both), then `open`s it with `cfg_json` and wraps it as a [`DlopenPolicy`]. The
/// `projectors` are the engine-supplied closures that build the wire projection and parse the reply
/// through the engine's own fail-closed `hooks::wire` normalizers. `name` is the hook's registry name.
pub fn load_hook_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
    name: &str,
    projectors: Arc<HookProjectors>,
) -> Result<Arc<dyn RoutingPolicy>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::HOOK,
        manifest_kind,
        Some(staged),
    )?;
    // Intern the name to a `&'static str` reused across opens of the same plugin, rather than
    // leaking a fresh allocation on every open (this runs per reload/configure/status/schema scrape).
    let name: &'static str = crate::intern_name(name);
    Ok(Arc::new(DlopenPolicy {
        raw: Arc::new(raw),
        projectors,
        name,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_api::TransformOutcome;

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
                    return RoutingDecision::Reject { status, message };
                }
                let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                    return RoutingDecision::Abstain;
                };
                let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
                RoutingDecision::from_ranked(
                    order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                    &valid,
                )
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
        let projection =
            serde_json::to_vec(&serde_json::json!({"request": {"pool": "p"}})).unwrap();
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
        let err = match load_hook_from_bytes(
            &bytes,
            "{}",
            "test-hook",
            "store",
            "h",
            test_projectors(),
        ) {
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
        let before = crate::log_tap::RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();

        // The test plugin logs through the bridge from its CONSTRUCTOR, which is the case that
        // matters: installing the sink after `open` would drop exactly those lines.
        let _policy = load("{}");

        let records = crate::log_tap::RECORDS
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
            busbar_plugin_abi::log_level::WARN,
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
            busbar_plugin_abi::log_level::WARN,
            "the tracing level must map across"
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
}
