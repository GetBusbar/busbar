// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAT — the one port through which the policy engine reaches a `kind: hook` PLUGIN.
//!
//! The engine decides WHICH hook runs, with WHICH grants, on WHICH terminal. It does not load
//! plugins: staging a tarball, verifying a signature, reading a manifest and `dlopen`ing a cdylib
//! are the plugin tooling's job, and a core crate that named that tooling would be carrying its
//! vocabulary — the coupling `kind-isolation` exists to refuse. So the engine states, in its OWN
//! words, the two things it needs from whatever seats a hook, and the composition side binds a
//! registry behind them:
//!
//! * [`HookSeat::declared_needs`] — what the plugin's signed manifest says it needs to SEE, on the
//!   same `no ⊂ ro ⊂ rw` ladder the operator's grant is written on ([`Need`]). The engine MEETS the
//!   two; both halves have to be nameable here or the intersection would be computed somewhere
//!   that cannot see one of them.
//! * [`HookSeat::open`] — the plugin behind a `plugin:` reference, opened with its resolved
//!   `settings:` bag as a [`RoutingPolicy`] — the same contract a native ranking policy and a
//!   dlopened hook are both reached through, so the engine calls every policy the same way.
//!
//! The reply/request PROJECTIONS a seated plugin is driven with are the engine's too
//! ([`Projectors`], built by [`crate::plugin::projectors`]): the projection is byte-for-byte the
//! engine's `wire::build`, and the reply is parsed by the engine's own fail-closed normalizers. The
//! adapter hands them to the loader; the loader never learns `wire`.
//!
//! The built-in ranking strategies are a plugin too, and whether they are compiled in is the
//! composition's decision, not the engine's: [`NativeResolver`] is the closure the composition
//! passes, `|name| None` when the plugin is compiled out (a `route: cheapest` is then a boot-time
//! config error at validation, exactly as before).

use crate::RoutingPolicy;
use std::sync::Arc;

/// One axis of a hook plugin's DECLARED intent — the same `no ⊂ ro ⊂ rw` ladder the operator grant
/// uses, so the engine compares "declared" against "granted" directly. `Rw` is meaningful on the
/// prompt axis only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Need {
    /// Declares no need for this content (the default).
    #[default]
    No,
    /// Asks to READ this content.
    Ro,
    /// Asks to read AND rewrite (prompt axis only).
    Rw,
}

impl Need {
    /// Whether the plugin declared it needs to READ this axis (`ro` or `rw`).
    pub fn wants_read(self) -> bool {
        !matches!(self, Need::No)
    }
    /// Whether the plugin declared it needs to REWRITE (prompt axis; `rw`).
    pub fn wants_rewrite(self) -> bool {
        matches!(self, Need::Rw)
    }
}

/// What a hook plugin's manifest declared it needs to see, per axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeclaredNeeds {
    /// Declared PROMPT need.
    pub prompt: Need,
    /// Declared caller-IDENTITY need (`ro` at most).
    pub user: Need,
}

impl DeclaredNeeds {
    /// Does the plugin declare ANY content need? Surfaced at resolution so an operator sees intent.
    pub fn declares_any(&self) -> bool {
        self.prompt != Need::No || self.user != Need::No
    }
}

/// THE PORT: what the engine asks of whatever seats a `kind: hook` plugin.
///
/// Both methods take the operator's `plugin:` REFERENCE (a name or alias, opaque to the engine).
/// A reference that resolves to nothing answers `None`/`Err`, and the engine degrades exactly as
/// it always did: an absent plugin is "gate absent", never a stranded request; an open failure on
/// a gate is a boot/reload refusal at `preopen_gate_hooks`.
pub trait HookSeat: Send + Sync {
    /// The declared needs of the plugin `plugin_ref` resolves to; `None` when it resolves to
    /// nothing. Reads the manifest only — no instance is opened.
    fn declared_needs(&self, plugin_ref: &str) -> Option<DeclaredNeeds>;

    /// Open the plugin `plugin_ref` resolves to as a policy transport for the hook named `name`,
    /// with `settings_json` — the hook's `settings:` map with every `SecretRef` already resolved —
    /// as its open configuration, driven through `projectors`.
    fn open(
        &self,
        plugin_ref: &str,
        settings_json: &str,
        name: &str,
        projectors: &Arc<Projectors>,
    ) -> Result<Arc<dyn RoutingPolicy>, String>;
}

/// The built-in ranking resolver the composition hands the engine: a strategy NAME to the policy
/// that implements it, or `None` when no built-in strategy has that name (or none is compiled in).
pub type NativeResolver = Arc<dyn Fn(&str) -> Option<Arc<dyn RoutingPolicy>> + Send + Sync>;

/// The projections a seated hook is driven with, typed on the contract and owned by the engine.
///
/// Each closure is a pure projection or parse: the request side builds the op payload from the
/// borrowed projection exactly as `wire::build` does, and the reply side runs the engine's own
/// fail-closed `wire` normalizers. Stateless, built once, shared behind an `Arc`.
pub struct Projectors {
    /// Build the `decide` projection from (request, candidates, context).
    #[allow(clippy::type_complexity)]
    pub decide: Box<
        dyn for<'a> Fn(
                &crate::RoutingRequest<'a>,
                &[crate::Candidate<'a>],
                &crate::RoutingContext<'a>,
            ) -> serde_json::Value
            + Send
            + Sync,
    >,
    /// Build the `transform` projection from a request (no candidates).
    #[allow(clippy::type_complexity)]
    pub transform:
        Box<dyn for<'a> Fn(&crate::RoutingRequest<'a>) -> serde_json::Value + Send + Sync>,
    /// Parse a `decide` reply into a decision. `Err` for a reply that does not PARSE — the same
    /// shape a transport failure takes, so the caller coerces it to the hook's `on_error` rather
    /// than silently abstaining; `Ok(Abstain)` for a reply that parses and carries no opinion.
    #[allow(clippy::type_complexity)]
    pub normalize: Box<
        dyn for<'a> Fn(serde_json::Value, &[crate::Candidate<'a>]) -> crate::PolicyResult
            + Send
            + Sync,
    >,
    /// Parse a `transform` reply into an outcome (reject > rewrite > abstain).
    pub transform_outcome:
        Box<dyn Fn(serde_json::Value) -> busbar_contract::TransformOutcome + Send + Sync>,
    /// Parse a `status` reply into the shared `HookStatus` (metrics validated/bounded downstream).
    pub status: Box<dyn Fn(serde_json::Value) -> Option<busbar_contract::HookStatus> + Send + Sync>,
    /// Extract the `schema` member of a `describe` reply envelope.
    pub describe_schema: Box<dyn Fn(serde_json::Value) -> Option<serde_json::Value> + Send + Sync>,
}

#[cfg(test)]
#[path = "tests/grant_axis_tests.rs"]
mod grant_axis_tests;
