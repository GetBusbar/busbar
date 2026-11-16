// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

pub mod gate;
pub mod strategy;
pub mod taps;
pub mod text_cut;

pub use busbar_contract::hooks::{
    CallerIdentity, Candidate, PolicyError, PolicyResult, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest,
};

pub use busbar_contract::signal::{Signal, SignalBag, SignalValue};

pub fn requested_signals(hooks: &crate::config::hooks::HookRegistry) -> RequestedSignals {
    let mut mask = RequestedSignals::default();
    for hook in hooks.values() {
        for &s in &hook.signals {
            mask.insert(s);
        }
    }
    mask
}

pub fn any_content_hook(hooks: &crate::config::hooks::HookRegistry) -> bool {
    hooks.values().any(|h| h.prompt.sends_prompt())
}

// The hook environment and every hook resolver run once per boot or reload, and the admin
// configure, status and schema reads run per admin call: all off the request path.
#[cfg(any(test, feature = "test-support"))]
pub use crate::off_path::hooks::transport_publication_for_test;
#[cfg(test)]
use crate::off_path::hooks::*;
pub use crate::off_path::hooks::{
    default_hook_name, fetch_schema, fetch_status, push_configure, resolve_container_gates,
    resolve_container_rewrites, resolve_gate_hooks, resolve_policy, resolve_pool_gates,
    resolve_pool_ordering, resolve_pool_rewrites, resolve_rewrite_hooks, resolve_tap_hooks,
    settings_drift_keys, try_resolve_pool_ordering, HookEnv,
};

/// A hook's HTTP routes, dispatched per request to the opened hook calls.
pub(crate) struct HookHttp {
    pub(crate) calls: Arc<dyn busbar_contract::hook_calls::HookCalls>,
    pub(crate) budget: std::time::Duration,
}

impl crate::plugin_routes::PluginHttpDispatch for HookHttp {
    fn handle_http(
        &self,
        request: &busbar_contract::abi::mechanism::endpoint::EndpointRequest,
    ) -> busbar_contract::abi::mechanism::endpoint::EndpointResponse {
        hook_route_response(
            self.calls.name(),
            tokio::runtime::Handle::current()
                .block_on(self.calls.serve(request.clone(), self.budget)),
        )
    }
}

fn hook_route_response(
    name: &str,
    response: Result<busbar_contract::abi::mechanism::endpoint::EndpointResponse, String>,
) -> busbar_contract::abi::mechanism::endpoint::EndpointResponse {
    match response {
        Ok(response) => response,
        Err(why) => {
            tracing::warn!(hook=name,error=%why,"hook route failed");
            busbar_contract::abi::mechanism::endpoint::EndpointResponse {
                status: 502,
                headers: Vec::new(),
                body: Vec::new(),
            }
        }
    }
}

fn failed_rewrite(
    on_error: &crate::config::PolicyOnError,
    message: String,
) -> busbar_contract::hooks::TransformOutcome {
    if failed_call_refuses(on_error) {
        busbar_contract::hooks::TransformOutcome::Reject {
            status: REQUIRED_HOOK_UNAVAILABLE_STATUS,
            message: crate::cold::required_hook_unavailable(),
        }
    } else {
        busbar_contract::hooks::TransformOutcome::Failed { message }
    }
}

/// A rewrite hook carrying its declared on_error disposition, called per request.
pub(crate) struct RewriteOnError {
    pub(crate) inner: Arc<dyn RoutingPolicy>,
    pub(crate) on_error: crate::config::PolicyOnError,
    pub(crate) on_error_chain: Vec<FallbackHook>,
}

impl RewriteOnError {
    async fn rewrite(
        &self,
        req: &RoutingRequest<'_>,
        budget: std::time::Duration,
        reads: Option<&dyn busbar_contract::hooks::ReadRecorder>,
    ) -> busbar_contract::hooks::TransformOutcome {
        use busbar_contract::hooks::TransformOutcome;
        let message = match tokio::time::timeout(budget, self.inner.transform(req, budget)).await {
            Ok(TransformOutcome::Failed { message }) => message,
            Ok(other) => return other,
            Err(_) => "rewrite hook timed out".to_string(),
        };
        self.fallback(req, message, reads).await
    }

    async fn fallback(
        &self,
        req: &RoutingRequest<'_>,
        message: String,
        reads: Option<&dyn busbar_contract::hooks::ReadRecorder>,
    ) -> busbar_contract::hooks::TransformOutcome {
        use busbar_contract::hooks::TransformOutcome;
        for fallback in &self.on_error_chain {
            if fallback.send_prompt && req.prompt.is_none() {
                continue;
            }
            let mut original = req.clone();
            if !fallback.send_prompt {
                original.prompt = None;
            }
            if !fallback.send_user {
                original.identity = None;
            }
            if original.prompt.is_some() {
                let recorded = match reads {
                    Some(reads) => {
                        reads
                            .record(fallback.policy.name(), original.identity.is_some())
                            .await
                    }
                    None => false,
                };
                if !recorded {
                    return failed_rewrite(&crate::config::PolicyOnError::Reject, message);
                }
            }
            let context = RoutingContext {
                pool: req.pool,
                budget_remaining: None,
                budget: &[],
            };
            match tokio::time::timeout(
                fallback.timeout,
                fallback
                    .policy
                    .decide(&original, &[], &context, fallback.timeout),
            )
            .await
            {
                Ok(Ok(RoutingDecision::Reject { status, message })) => {
                    return TransformOutcome::Reject { status, message }
                }
                Ok(Ok(RoutingDecision::Abstain)) => return TransformOutcome::Failed { message },
                Ok(Ok(_)) => return failed_rewrite(&crate::config::PolicyOnError::Reject, message),
                Ok(Err(_)) | Err(_) => {}
            }
        }
        failed_rewrite(&self.on_error, message)
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for RewriteOnError {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: std::time::Duration,
    ) -> PolicyResult {
        self.inner.decide(req, candidates, ctx, budget).await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn name_arc(&self) -> std::sync::Arc<str> {
        self.inner.name_arc()
    }

    async fn transform(
        &self,
        req: &RoutingRequest<'_>,
        budget: std::time::Duration,
    ) -> busbar_contract::hooks::TransformOutcome {
        self.rewrite(req, budget, None).await
    }

    async fn transform_recording(
        &self,
        req: &RoutingRequest<'_>,
        budget: std::time::Duration,
        reads: &dyn busbar_contract::hooks::ReadRecorder,
    ) -> busbar_contract::hooks::TransformOutcome {
        self.rewrite(req, budget, Some(reads)).await
    }

    async fn fallback_rewrite_recording(
        &self,
        req: &RoutingRequest<'_>,
        reads: &dyn busbar_contract::hooks::ReadRecorder,
    ) -> Option<busbar_contract::hooks::TransformOutcome> {
        if self.on_error_chain.is_empty() {
            return None;
        }
        Some(
            self.fallback(req, "rewrite could not be applied".into(), Some(reads))
                .await,
        )
    }

    /// A rewrite the plane refuses to apply is this hook's failure: the same disposition, by the
    /// same rule, as a failed call.
    fn refuses_failed_rewrite(&self) -> bool {
        busbar_kernel::hooks::failed_call_refuses(&self.on_error)
    }

    async fn configure(
        &self,
        hook_name: &str,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
        settings_version: u64,
        budget: std::time::Duration,
    ) -> Result<(), PolicyError> {
        self.inner
            .configure(hook_name, settings, settings_version, budget)
            .await
    }

    async fn describe(
        &self,
        budget: std::time::Duration,
    ) -> Option<busbar_contract::hooks::HookSchema> {
        self.inner.describe(budget).await
    }

    async fn status(
        &self,
        budget: std::time::Duration,
    ) -> Option<busbar_contract::hooks::HookStatus> {
        self.inner.status(budget).await
    }

    async fn notify(
        &self,
        tap: Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        budget: std::time::Duration,
    ) {
        self.inner.notify(tap, budget).await;
    }
}

pub use busbar_kernel::config::plane_sections::attach_list;

pub const SECTION_SCOPE: &str = busbar_contract::section::RESERVED_SECTION_KEYS[0];

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/failed_policy_tests.rs"]
mod failed_policy_tests;

#[cfg(test)]
#[path = "tests/reads_request_tests.rs"]
mod reads_request_tests;

#[cfg(test)]
#[path = "tests/rewrite_fallback_tests.rs"]
mod rewrite_fallback_tests;

pub type TapEntry = (
    std::time::Duration,
    bool,
    Arc<dyn RoutingPolicy>,
    Vec<String>,
);

/// The per-generation, config-derived UNION of every hook's declared [`Signal`] set — a dense
/// bitmask ("which catalog entries does ANYTHING configured on this generation want"), consulted
/// with a single `AND`+compare BEFORE any compute fn runs ([`RequestedSignals::wants`]), never
/// call-then-discard.
///
/// Relocated here off `busbar_kernel::hooks::RequestedSignals` (App-retype WEDGE 2d) so the engine's
/// `EngineHost::requested_signals` seam returns a NEUTRAL type; core re-exports it (identity) and its
/// config-time builder (`busbar_kernel::hooks::requested_signals`, which takes core's `HookCfg`) stays
/// in core and drives [`insert`](RequestedSignals::insert).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestedSignals(u64);

impl RequestedSignals {
    #[inline]
    pub fn wants(self, s: Signal) -> bool {
        debug_assert!(
            s.bit() < 64,
            "Signal::bit() exceeded the u64 bitmask width; grow RequestedSignals to a bitset"
        );
        self.0 & (1u64 << s.bit()) != 0
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn insert(&mut self, s: Signal) {
        self.0 |= 1u64 << s.bit();
    }
}

/// The per-pool routing policy resolved ONCE at config load. `None` is the zero-cost default
/// (`route: weighted` / absent): no policy object, no projection, the inline SWRR hot path. Stored
/// on `App` keyed by pool name; the hot path is `if let Some(p) = app.pool_policies.get(pool) { … }`.
#[derive(Clone)]
pub enum ResolvedPolicy {
    /// A constructed policy object (a dlopen hook plugin / native non-weighted) plus its fallback config.
    /// The default SWRR / weighted path is represented as `None` by `resolve_policy` (it constructs no
    /// policy object), so there is no `Weighted` variant — a weighted pool simply has no resolved
    /// policy and takes the inline SWRR branch.
    Policy {
        policy: Arc<dyn RoutingPolicy>,
        /// The TERMINAL the on_error chain bottoms out on (weighted/reject/first) — applied when
        /// the policy fails and every chain link (below) also fails.
        on_error: crate::config::PolicyOnError,
        /// The resolved on_error FALLBACK CHAIN: hooks/strategies fired IN ORDER when the policy
        /// errors or times out; the first that answers decides. Empty (the common case — a
        /// terminal was named directly) costs nothing. Resolved once at config load; boot
        /// validation proves termination (cycles/unknowns/taps never reach here).
        on_error_chain: Vec<FallbackHook>,
        timeout: std::time::Duration,
        /// Derived from the hook's `prompt` grant (`ro`/`rw`) — build + send the prompt content
        /// projection (default false, i.e. `prompt: no`).
        send_prompt: bool,
        /// Derived from the hook's `user` grant (`ro`) — build + send the caller identity projection
        /// (default false, i.e. `user: no`).
        send_user: bool,
        /// Gate `on_empty` — behavior when a `restrict` reply leaves an EMPTY candidate intersection.
        /// Default `Reject` (fail-closed; the spec default for a compliance restrict); `Weighted`
        /// is the advisory escape (fall back to SWRR over the FULL pool). Inert for non-restricting
        /// policies (native/order-only), which never produce an empty intersection.
        on_empty: crate::config::PolicyOnError,
    },
}

impl ResolvedPolicy {
    /// Whether this policy may stop, change or route the unit on the request's content: true
    /// unless its policy is content-blind ([`RoutingPolicy::content_blind`], a built-in ranking
    /// strategy), it is sent no prompt and it has no fallback chain (any link of which may be a
    /// hook that reads the request).
    #[must_use]
    pub fn reads_request(&self) -> bool {
        let Self::Policy {
            policy,
            send_prompt,
            on_error_chain,
            ..
        } = self;
        !(policy.content_blind() && !*send_prompt && on_error_chain.is_empty())
    }
}

#[inline]
#[must_use]
pub fn failed_call_refuses(on_error: &crate::config::PolicyOnError) -> bool {
    match on_error {
        crate::config::PolicyOnError::Reject => true,
        crate::config::PolicyOnError::Weighted | crate::config::PolicyOnError::First => false,
    }
}

pub const REQUIRED_HOOK_UNAVAILABLE_STATUS: u16 = 503;

pub const REQUIRED_HOOK_UNAVAILABLE_MESSAGE: &str =
    "A required gate could not complete. Please retry shortly.";

/// One link in a gate's resolved `on_error` fallback chain: the fallback hook's transport plus
/// the per-hook config the firing site needs (its own deadline, ITS grants — a fallback never
/// sees a projection its own grants don't allow — and its own `on_empty`).
#[derive(Clone)]
pub struct FallbackHook {
    pub policy: Arc<dyn RoutingPolicy>,
    pub timeout: std::time::Duration,
    pub send_prompt: bool,
    pub send_user: bool,
    pub on_empty: crate::config::PolicyOnError,
}

#[cfg(test)]
#[path = "tests/hooks_tests.rs"]
mod call_input_tests;
