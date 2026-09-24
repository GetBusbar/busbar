// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE T2 VOICE SESSION RUNTIME — the live duplex engine (design `plane4-duplex-session.md` §8). Behind the
//! `runtime` cargo feature (OFF by default, HARD RULE 4): the default / prod build compiles the IR +
//! declarations only, so the workspace is unaffected regardless of this module's state.
//!
//! The runtime binds the neutral byte-duplex pump (`serve_messages`), the codec's
//! `DuplexReader`/`DuplexWriter` pair, the durable `SessionScope`, and the kernel session account
//! (per-class counts, ledgered and budget-checked kernel-side) into one governed carrier — exposed to
//! both topologies (`crate::topology`).

pub mod carrier;
pub mod metering;
pub mod scope;
pub mod session;
/// THE SERVER-SIDE TOOL EXECUTOR PORT, RE-EXPORTED FROM `busbar-plane-streaming`. `ToolExecutor` and
/// `EchoToolExecutor` moved to the plane crate for the same reason the governed-call port below did:
/// the port is what a tool call MEANS to this plane, and it names nothing this crate owns. Re-exported
/// as a MODULE, not just its items, so `crate::runtime::tools::EchoToolExecutor` — the spelling the
/// topology and governed-binding cells use — resolves exactly what it always did.
pub use busbar_plane_streaming::tools;

pub use carrier::Carrier;
// THE GOVERNED-CALL PORT, RE-EXPORTED FROM `busbar-plane-streaming`. `GovernedCalls` / `ReplyRefusal` /
// `GovernedSession` moved to the plane crate, beside the two declarations the composition root
// already pairs them with (`busbar_plane_streaming::plane::{FACT_TOOL_CORRELATION,
// TOOL_REPLY_DEADLINE_SECS}`) — the port and the key a wait is entered under are now one crate, so
// they cannot drift apart in silence. Re-exported HERE under the old name so every caller that
// spells `busbar_voice::runtime::GovernedCalls` resolves exactly what it always did. The split is a
// MOVE: no item changed shape crossing it.
pub use busbar_plane_streaming::governed::{GovernedCalls, GovernedSession, ReplyRefusal};
pub use metering::{BudgetRefused, SessionMetering, TurnMeter, TurnVerdict};
pub use scope::{SessionHandle, VoiceSessionRow};
pub use session::{
    serve_to_teardown, serve_with_sweep, Outbound, SessionCore, UplinkForwarder, VoiceSession,
};
pub use tools::{EchoToolExecutor, ToolExecutor};

use busbar_kernel::plane::handle_engine::DurableHandleEngine;
use std::sync::Arc;

/// THE PLANE'S PER-GENERATION RUNTIME OBJECT — the type-erased slot `PLANE_DECL.build_runtime` builds
/// (see `crate::PLANE_DECL`). It carries the process-wide dependencies a session is assembled from: the
/// durable-handle engine sessions bind into and the server-side tool executor. The plane holds no
/// pricing of its own: a session's metering is the kernel account its governed open binds. A session
/// (either topology) is constructed FROM this object; it holds no per-session state itself.
pub struct VoiceRuntime {
    /// The process-wide durable-handle engine every session's [`SessionHandle`] binds into.
    pub engine: Arc<DurableHandleEngine>,
    /// The server-side tool executor (the tool moat) shared across sessions.
    pub tools: Arc<dyn ToolExecutor>,
    /// The plane's OPEN-PASS destination denial set — upstream models (destinations) a session
    /// `begin_session` refuses at the shared gauntlet gate BEFORE any account/durable open (zero bytes,
    /// zero charge). Empty by default (no denial policy yet); the pre-admission hook a real model
    /// blocklist fills. Named by `session_gauntlet` through [`Self::destination_denied`].
    pub denied_destinations: std::collections::BTreeSet<String>,
    /// THE LOCKED SESSION DEFAULTS every session opens with, read from the operator's `streams.session:`
    /// (VAD/media/tool set). Seeded from [`crate::config::StreamsCfg`] at [`build_runtime`]; the pump
    /// re-applies it server-side so a client `session.update` is reconciled against it, never trusted
    /// blind.
    pub session_defaults: crate::ir::config::SessionConfig,
    /// The hard session wall-clock ceiling (`streams.session_max_secs:`), bound onto every session
    /// core at open and compared on the sweep tick beside the pump (`SessionCore::enforce_ceiling`).
    /// `None` — the default, and what an operator who writes nothing gets — is no ceiling (Q21a).
    pub session_max_secs: Option<std::num::NonZeroU32>,
    /// The context-window ceiling (`streams.context_window_tokens:`).
    pub context_window_tokens: u32,
    /// The per-response output-token ceiling (`streams.max_output_tokens:`).
    pub max_output_tokens: u32,
    /// THE LIVE HOST — bound only by [`build_runtime_hosted`] once a mounted route hands the runtime a
    /// real `Arc<dyn EngineHost>`. `None` on the pre-host/dev-default runtime (no admin-audit trail to
    /// write to). Carried so a governed session mutation can land ONE admin-audit row through the SAME
    /// seam the host's other planes journal through (see [`VoiceRuntime::audit_session`]).
    pub host: Option<Arc<dyn busbar_kernel::plane_host::EngineHost>>,
}

impl VoiceRuntime {
    /// Assemble a runtime object from its dependencies (no destination denial policy).
    #[must_use]
    pub fn new(engine: Arc<DurableHandleEngine>, tools: Arc<dyn ToolExecutor>) -> Self {
        let defaults = crate::config::StreamsCfg::default();
        VoiceRuntime {
            engine,
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
    /// naming a denied destination is refused before any account/durable open (zero bytes, zero charge).
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
/// posture / ceilings, via `with_streams`). A session's metering is not a runtime dependency at all:
/// it is the kernel account the governed open binds for the presenting key over the live host. What is
/// still a dev default is the durable engine (a fresh [`DurableHandleEngine`]) and the tool executor
/// ([`EchoToolExecutor`]): deriving the config-driven engine/tool set is a SEPARATE, tracked slice.
/// `prior` (carry-over) is ignored today; the signature is the real one so binding those
/// config-derived dependencies is a body change, not an ABI change.
pub fn build_runtime(
    section: &dyn std::any::Any,
    _prior: Option<&dyn busbar_kernel::plane_host::PlaneSlots>,
) -> Arc<dyn std::any::Any + Send + Sync> {
    // READ THE REAL `streams:` CONFIG: core passes the plane's own typed section as `cfg.streams.as_any()`
    // (the `PlaneCfg::as_any` of `StreamsCfg`). An absent/other section downcasts to `None` and falls back
    // to the plane default, so a deployment with no `streams:` block still builds a runtime — with the
    // plane's own default posture, not an empty one.
    let streams = section
        .downcast_ref::<crate::config::StreamsCfg>()
        .cloned()
        .unwrap_or_default();
    Arc::new(
        VoiceRuntime::new(
            Arc::new(DurableHandleEngine::new()),
            Arc::new(EchoToolExecutor),
        )
        .with_streams(&streams),
    )
}

/// THE PRODUCTION composition entry — take a generation's runtime and bind the live host onto it.
/// Called by every mounted route the moment the live host is in hand (the route layer is where an
/// `Arc<dyn EngineHost>` first exists — the per-generation slot is built before any request), so the
/// session's admin-audit row journals through the host.
///
/// Everything else is SHARED with `base`, not rebuilt: the same durable-handle engine (so a session
/// opened on one request is the same durable working set another request sees), the same tool
/// executor, the same denial set, and the same operator session posture and ceilings.
#[must_use]
pub fn build_runtime_hosted(
    base: &VoiceRuntime,
    host: Arc<dyn busbar_kernel::plane_host::EngineHost>,
) -> VoiceRuntime {
    VoiceRuntime {
        engine: Arc::clone(&base.engine),
        tools: Arc::clone(&base.tools),
        denied_destinations: base.denied_destinations.clone(),
        session_defaults: base.session_defaults.clone(),
        session_max_secs: base.session_max_secs,
        context_window_tokens: base.context_window_tokens,
        max_output_tokens: base.max_output_tokens,
        host: Some(host),
    }
}

#[cfg(test)]
mod tests;

// THE VOICE PLANE-UNIT BILLING ORACLE — the voice money-path regression backstop that replaces the D2
// lease oracle (Q21b): one fixed session script, every per-class count it ledgers and every verdict
// the kernel answers pinned.
#[cfg(test)]
#[path = "voice_plane_unit_oracle.rs"]
mod voice_plane_unit_oracle;
