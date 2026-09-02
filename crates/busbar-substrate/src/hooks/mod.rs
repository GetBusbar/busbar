// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL hook value/wire layer — the plain-data hook types both the engine (busbar-core) and the
//! LLM model plane (busbar-llm) name, relocated here off `busbar_core::hooks::` so a plane reaches the
//! substrate ABI rather than back into core (the reverse-edge rule; see
//! docs/design/1.6.0-hooks-seam-notes.md).
//!
//! Only the PLAIN-DATA layer lives here: the per-pool resolved-policy carriers ([`ResolvedPolicy`],
//! [`FallbackHook`]) and the outbound hook-request wire projection ([`wire`]). Every field is composed
//! of already-neutral types — the [`RoutingPolicy`](busbar_api::RoutingPolicy) trait object
//! (busbar-api), [`PolicyOnError`](crate::config::PolicyOnError) (this crate), `Duration`, `bool`. No
//! trait object crosses the plugin C-ABI / `Any` boundary here: the model plane holds these in-process
//! and invokes `policy.decide(..)` directly on the api trait. The hook REPLY-side normalizers and the
//! settings-bag-carrying `StatusReply` stay in `busbar_core::hooks::wire` (inside the settings-leak-lint
//! scan root); core re-exports the request-side names from here so its own paths are unchanged.

pub mod wire;

use busbar_api::{RoutingPolicy, Signal};
use std::sync::Arc;

/// A resolved GLOBAL (all-pools) tap: `(per-hook deadline, prompt-grant, transport, caller-group
/// scope)`. The 4th element is the hook's `groups:` SELECTION scope (1.5.3) — the firing site fires
/// the tap only for a caller in that scope (empty = every caller).
///
/// Relocated here off `busbar_core::hooks::TapEntry` (App-retype WEDGE 2d): a purely-neutral tuple —
/// [`Duration`](std::time::Duration), `bool`, the [`RoutingPolicy`](busbar_api::RoutingPolicy) trait
/// object (busbar-api), `Vec<String>` — so the engine's tap-facet host seams
/// (`EngineHost::tap_hooks*`) can name it without reaching back into core. Core re-exports this alias
/// so `busbar_core::hooks::TapEntry` is unchanged (a transparent alias, identical by structure).
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
/// Relocated here off `busbar_core::hooks::RequestedSignals` (App-retype WEDGE 2d) so the engine's
/// `EngineHost::requested_signals` seam returns a NEUTRAL type; core re-exports it (identity) and its
/// config-time builder (`busbar_core::hooks::requested_signals`, which takes core's `HookCfg`) stays
/// in core and drives [`insert`](RequestedSignals::insert).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestedSignals(u64);

impl RequestedSignals {
    /// A single `u64` AND + compare — the same order of magnitude as the pre-existing
    /// `app.tap_hooks_response.is_empty()` early-out this design generalizes.
    #[inline]
    pub fn wants(self, s: Signal) -> bool {
        debug_assert!(
            s.bit() < 64,
            "Signal::bit() exceeded the u64 bitmask width; grow RequestedSignals to a bitset"
        );
        self.0 & (1u64 << s.bit()) != 0
    }

    /// True iff NOTHING is declared anywhere — the zero-cost default generation.
    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Set the bit for `s`. `pub` (rather than the former core-private visibility) only because the
    /// config-time builder that calls it — `busbar_core::hooks::requested_signals` — now lives across
    /// the crate boundary from the type; it is otherwise the same one-line bit-OR.
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
