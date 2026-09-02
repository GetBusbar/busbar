// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE T2 VOICE SESSION RUNTIME — the live duplex engine (design §8, the P2 build). Behind the
//! `runtime` cargo feature (OFF by default): the default / prod build compiles the skeleton IR +
//! declarations only, so the workspace is unaffected and voice stays dev-only until DoD.
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
    LeaseState, LocalLease, LocalMeteringPort, MeteringLease, MeteringPort, Pricing,
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
    /// The D2 metering port — opens a reserve-then-settle lease at each session start.
    pub metering: Arc<dyn MeteringPort>,
    /// The server-side tool executor (the tool moat) shared across sessions.
    pub tools: Arc<dyn ToolExecutor>,
    /// The per-token price book usage is priced with before it crosses the metering lease.
    pub pricing: Pricing,
}

impl VoiceRuntime {
    /// Assemble a runtime object from its dependencies.
    #[must_use]
    pub fn new(
        engine: Arc<DurableHandleEngine>,
        metering: Arc<dyn MeteringPort>,
        tools: Arc<dyn ToolExecutor>,
        pricing: Pricing,
    ) -> Self {
        VoiceRuntime {
            engine,
            metering,
            tools,
            pricing,
        }
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
}

/// THE `PLANE_DECL.build_runtime` HOOK BODY — builds the plane's per-generation runtime object
/// (type-erased as `Arc<dyn Any + Send + Sync>`), the seam the composition root composes the voice
/// runtime slot through (see `crate::PLANE_DECL`). Wired behind the `runtime` feature; the default
/// skeleton build leaves the hook `None`.
///
/// DEV DEFAULTS (reported). It builds from DEV defaults — a fresh durable engine, the [`LocalLease`]
/// metering port, the [`EchoToolExecutor`], and a zero price book — because deriving the real
/// dependencies from config needs the plane's config-section grammar (`PLANE_DECL.parse_section` /
/// `default_section`), which touches the frozen config snapshot and is a SEPARATE slice. The first
/// argument (the plane's own config section) and `prior` (carry-over) are therefore ignored today; the
/// signature is the real one so binding the config-derived dependencies is a body change, not an ABI
/// change. Voice is dev-only until DoD, so a dev-default runtime object is the honest interim.
pub fn build_runtime(
    _section: &dyn std::any::Any,
    _prior: Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
) -> Arc<dyn std::any::Any + Send + Sync> {
    Arc::new(VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
        Pricing {
            audio_in_nanos: 0,
            audio_out_nanos: 0,
            text_in_nanos: 0,
            text_out_nanos: 0,
            cached_nanos: 0,
        },
    ))
}

#[cfg(test)]
mod tests;
