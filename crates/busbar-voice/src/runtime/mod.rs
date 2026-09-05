// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE T2 VOICE SESSION RUNTIME — the live duplex engine (design `plane4-duplex-session.md` §8). Behind the
//! `runtime` cargo feature (OFF by default, HARD RULE 4): the default / prod build compiles the IR +
//! declarations only, so the workspace is unaffected regardless of this module's state.
//!
//! The runtime binds the neutral byte-duplex pump (`serve_messages`), the codec's
//! `DuplexReader`/`DuplexWriter` pair, the durable `SessionScope`, and the D2 metering lease into one
//! governed carrier — exposed to both topologies (`crate::topology`).

pub mod carrier;
pub mod metering;
pub mod scope;
pub mod session;
pub mod tools;

pub use carrier::Carrier;
pub use metering::{
    cap_nanos_from_buckets, principal_cap_nanos, HostLease, HostMeteringPort, LeaseCloseGuard,
    LeaseState, LocalLease, LocalMeteringPort, MeteringLease, MeteringPort,
};
pub use scope::{SessionHandle, VoiceSessionRow};
pub use session::{Outbound, SessionCore, UplinkForwarder, VoiceSession};
pub use tools::{EchoToolExecutor, ToolExecutor};

use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use std::sync::Arc;

/// THE PLANE'S PER-GENERATION RUNTIME OBJECT — the type-erased slot `PLANE_DECL.build_runtime` builds
/// (see `crate::PLANE_DECL`). It carries the process-wide dependencies a session is assembled from: the
/// durable-handle engine sessions bind into, the D2 metering PORT that opens a lease per session, the
/// server-side tool executor, and the pricing book. A session (either topology) is constructed FROM
/// this object; it holds no per-session state itself.
pub struct VoiceRuntime {
    /// The process-wide durable-handle engine every session's [`SessionHandle`] binds into.
    pub engine: Arc<DurableHandleEngine>,
    /// The D2 metering port — opens a reserve-then-settle lease at each session start. The lease also
    /// carries the turn PRICING leg (`price_usage`): the host prices each turn's usage_units against the
    /// deployment rate card, so the plane holds no price book of its own.
    pub metering: Arc<dyn MeteringPort>,
    /// The server-side tool executor (the tool moat) shared across sessions.
    pub tools: Arc<dyn ToolExecutor>,
    /// The plane's OPEN-PASS destination denial set — upstream models (destinations) a session
    /// `begin_session` refuses at the shared gauntlet gate BEFORE any lease/durable open (zero bytes,
    /// zero charge). Empty by default (no denial policy yet); the pre-admission hook a real model
    /// blocklist fills. Named by `session_gauntlet` through [`Self::destination_denied`].
    pub denied_destinations: std::collections::BTreeSet<String>,
    /// THE LOCKED SESSION DEFAULTS every session opens with, read from the operator's `streams.session:`
    /// (VAD/media/tool set). Seeded from [`crate::config::StreamsCfg`] at [`build_runtime`]; the pump
    /// re-applies it server-side so a client `session.update` is reconciled against it, never trusted
    /// blind.
    pub session_defaults: crate::ir::config::SessionConfig,
    /// The hard session wall-clock ceiling (`streams.session_max_secs:`) the pump enforces.
    pub session_max_secs: u32,
    /// The context-window ceiling (`streams.context_window_tokens:`).
    pub context_window_tokens: u32,
    /// The per-response output-token ceiling (`streams.max_output_tokens:`).
    pub max_output_tokens: u32,
    /// THE LIVE HOST — bound only by [`build_runtime_hosted`] once a mounted route hands the runtime a
    /// real `Arc<dyn EngineHost>`. `None` on the pre-host/dev-default runtime (no admin-audit trail to
    /// write to). Carried so a governed session mutation can land ONE admin-audit row through the SAME
    /// seam the host's other planes journal through (see [`VoiceRuntime::audit_session`]), without the
    /// D2 metering port (`Arc<dyn MeteringPort>`) needing to widen into the full host trait itself.
    pub host: Option<Arc<dyn busbar_substrate::plane_host::EngineHost>>,
}

impl VoiceRuntime {
    /// Assemble a runtime object from its dependencies (no destination denial policy).
    #[must_use]
    pub fn new(
        engine: Arc<DurableHandleEngine>,
        metering: Arc<dyn MeteringPort>,
        tools: Arc<dyn ToolExecutor>,
    ) -> Self {
        let defaults = crate::config::StreamsCfg::default();
        VoiceRuntime {
            engine,
            metering,
            tools,
            denied_destinations: std::collections::BTreeSet::new(),
            session_defaults: defaults.session,
            session_max_secs: defaults.session_max_secs,
            context_window_tokens: defaults.context_window_tokens,
            max_output_tokens: defaults.max_output_tokens,
            host: None,
        }
    }

    /// SEED the locked session config + the three session ceilings from the operator's `streams:`
    /// section. Called by [`build_runtime`] with the plane's own typed [`crate::config::StreamsCfg`]
    /// (an absent section falls back to `StreamsCfg::default()`), so the runtime a session is built
    /// FROM carries the operator's real posture rather than the dev defaults.
    #[must_use]
    pub fn with_streams(mut self, cfg: &crate::config::StreamsCfg) -> Self {
        self.session_defaults = cfg.session.clone();
        self.session_max_secs = cfg.session_max_secs;
        self.context_window_tokens = cfg.context_window_tokens;
        self.max_output_tokens = cfg.max_output_tokens;
        self
    }

    /// Builder: DENY the given upstream destinations (models) at the session open-pass gate. A session
    /// naming a denied destination is refused before any lease/durable open (zero bytes, zero charge).
    #[must_use]
    pub fn with_denied_destinations<I, S>(mut self, destinations: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.denied_destinations
            .extend(destinations.into_iter().map(Into::into));
        self
    }

    /// Whether the open-pass gate must REFUSE a session targeting `destination` (an upstream model on
    /// the plane's denial set).
    #[must_use]
    pub fn destination_denied(&self, destination: &str) -> bool {
        self.denied_destinations.contains(destination)
    }

    /// Bind a fresh [`SessionHandle`] for `(owner, id)` into this runtime's durable engine.
    #[must_use]
    pub fn bind_session(&self, owner: impl Into<String>, id: impl Into<String>) -> SessionHandle {
        SessionHandle::bind(Arc::clone(&self.engine), owner, id)
    }

    /// Open a D2 metering lease for a session over ALREADY-PRICED nanodollars (estimate + fee + cap).
    /// `None` mirrors a `cost_reserve` refusal (a refuse-all cap) — the session must not open.
    #[must_use]
    pub fn open_lease(
        &self,
        estimate_nanos: u64,
        fee_nanos: u64,
        cap_nanos: Option<u64>,
    ) -> Option<Box<dyn MeteringLease>> {
        self.metering.reserve(estimate_nanos, fee_nanos, cap_nanos)
    }

    /// Land ONE admin-audit row for a voice-plane mutation through the live host's `JournalHost` leg —
    /// a no-op on a runtime with no bound host (the pre-host/dev-default runtime, or an ungoverned
    /// deployment resolving no key has nothing to attribute the row to; callers pass a real principal
    /// only when one was resolved). `outcome` is a fixed vocabulary literal, matching every other
    /// plane's `audit_record` call shape.
    pub(crate) fn audit_session(
        &self,
        action: &str,
        resource: &str,
        outcome: &'static str,
        principal: &str,
    ) {
        if let Some(host) = &self.host {
            host.audit_record(action, resource, outcome, principal);
        }
    }
}

/// THE `PLANE_DECL.build_runtime` HOOK BODY — builds the plane's per-generation runtime object
/// (type-erased as `Arc<dyn Any + Send + Sync>`), the seam the composition root composes the voice
/// runtime slot through (see `crate::PLANE_DECL`). Wired behind the `runtime` feature; the default
/// (feature-off) build leaves the hook `None`.
///
/// WHAT IS WIRED, AND WHAT REMAINS A DEV DEFAULT. This entry reads the REAL `streams:` config (session
/// posture / ceilings, via `with_streams`) and binds the [`LocalMeteringPort`] — the faithful in-process
/// metering stand-in the runtime/topology tests and the conformance governance leg drive. It is the
/// PRE-HOST default only: every mounted route rebinds the money hop onto the live host lease through
/// [`build_runtime_hosted`] the moment a request hands it an engine host, so a served session prices
/// each turn against the deployment rate card (`MeteringHost::price_usage`) rather than the dev-default
/// zero. What is still a dev default is the durable engine (a fresh [`DurableHandleEngine`]) and the
/// tool executor ([`EchoToolExecutor`]): deriving the config-driven engine/tool set is a SEPARATE,
/// tracked slice. `prior` (carry-over) is ignored today; the signature is the real one so binding those
/// config-derived dependencies is a body change, not an ABI change.
pub fn build_runtime(
    section: &dyn std::any::Any,
    _prior: Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
) -> Arc<dyn std::any::Any + Send + Sync> {
    // READ THE REAL `streams:` CONFIG: core passes the plane's own typed section as `cfg.streams.as_any()`
    // (the `PlaneCfg::as_any` of `StreamsCfg`). An absent/other section downcasts to `None` and falls back
    // to the plane default, so a deployment with no `streams:` block still builds a runtime — with the
    // plane's own default posture, not an empty one.
    let streams = section
        .downcast_ref::<crate::config::StreamsCfg>()
        .cloned()
        .unwrap_or_default();
    // The PRE-HOST default binds [`LocalMeteringPort`] (HARD RULE 4): the runtime/topology tests and the
    // conformance governance leg drive the faithful in-process lease. A SERVED session never keeps it —
    // the mounted routes hold the live `Arc<dyn EngineHost>` and rebind the money hop through
    // [`build_runtime_hosted`], so the D2 hop PRICES each turn's usage against the deployment rate card
    // (`MeteringHost::price_usage`) rather than the dev-default zero. The frozen
    // `PlaneDecl::build_runtime` fn-pointer signature carries no host, so the hosted entry is a sibling
    // rather than a body branch.
    build_runtime_with_metering(Arc::new(LocalMeteringPort), &streams)
}

/// THE PRODUCTION composition entry — take a generation's runtime and rebind its D2 money hop onto the
/// REAL host metering lease. Called by every mounted route the moment the live host is in hand (the
/// route layer is where an `Arc<dyn EngineHost>` first exists — the per-generation slot is built
/// before any request), so a live voice session reserves / settles / exhausts against the caller's
/// real grant rather than the in-process [`LocalLease`] stand-in.
///
/// Everything but the metering port is SHARED with `base`, not rebuilt: the same durable-handle engine
/// (so a session opened on one request is the same durable working set another request sees), the same
/// tool executor, the same denial set, and the same operator session posture and ceilings.
#[must_use]
pub fn build_runtime_hosted(
    base: &VoiceRuntime,
    host: Arc<dyn busbar_substrate::plane_host::EngineHost>,
) -> VoiceRuntime {
    VoiceRuntime {
        engine: Arc::clone(&base.engine),
        metering: Arc::new(metering::HostMeteringPort::new(
            Arc::clone(&host) as Arc<dyn busbar_substrate::plane_host::MeteringHost>
        )),
        tools: Arc::clone(&base.tools),
        denied_destinations: base.denied_destinations.clone(),
        session_defaults: base.session_defaults.clone(),
        session_max_secs: base.session_max_secs,
        context_window_tokens: base.context_window_tokens,
        max_output_tokens: base.max_output_tokens,
        host: Some(host),
    }
}

/// The shared composition body: assemble the per-generation [`VoiceRuntime`] over the given metering
/// PORT (the one dependency the dev/prod paths differ on) plus the current dev defaults for the durable
/// engine and tool executor. Turn pricing rides the port's lease (`price_usage`), host-side.
fn build_runtime_with_metering(
    metering: Arc<dyn MeteringPort>,
    streams: &crate::config::StreamsCfg,
) -> Arc<dyn std::any::Any + Send + Sync> {
    Arc::new(
        VoiceRuntime::new(
            Arc::new(DurableHandleEngine::new()),
            metering,
            Arc::new(EchoToolExecutor),
        )
        .with_streams(streams),
    )
}

#[cfg(test)]
mod tests;

// THE VOICE D2 LEASE BILLING ORACLE — the voice money-path byte/scalar-pinned regression backstop, the
// sibling of the LLM-plane money oracles. A single end-to-end reserve → settle → exhaust → hard-close
// sequence with every nanodollar scalar pinned.
#[cfg(test)]
#[path = "voice_d2_billing_oracle.rs"]
mod voice_d2_billing_oracle;
