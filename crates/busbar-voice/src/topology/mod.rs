// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO TOPOLOGIES the voice runtime exposes (design §5-6), behind the `runtime` feature.
//!
//! * [`webrtc`] — the BROWSER WebRTC sideband: busbar mints the ephemeral token and holds a persistent
//!   sideband control channel owning tools + instructions; the browser's MEDIA path is peer-to-peer, so
//!   busbar is mint/guard + control, NOT a media relay.
//! * [`telephony`] — a THIN WS PROXY: `g711_ulaw` end-to-end so 8 kHz passes straight through (no
//!   resample), with barge-in truncate driven from the codec's playback marks.
//!
//! Both are assembled from a [`crate::runtime::VoiceRuntime`] via [`begin_session`], which opens the D2
//! metering lease (fail-closed on a refused budget) and the durable [`SessionHandle`] before a frame
//! flows.

pub mod telephony;
pub mod webrtc;

#[cfg(test)]
mod tests;

use crate::ir::codec::{DuplexReader, DuplexWriter};
use crate::ir::config::SessionConfig;
use crate::runtime::carrier::Carrier;
use crate::runtime::scope::SessionHandle;
use crate::runtime::session::SessionCore;
use crate::runtime::VoiceRuntime;
use busbar_substrate::plane::handle_engine::HandleEngineError;
use std::sync::Arc;

/// THE ALREADY-PRICED SESSION BUDGET handed across the D2 lease at session start (§2.5): the coarse
/// over-`estimate` debited up front, the once-per-session flat `fee`, and the TRUE budget `cap`
/// exhaustion is judged against (`None` = uncapped, `Some(0)` = refuse-all). All nanodollars — the
/// plane priced them; core prices nothing.
#[derive(Debug, Clone, Copy)]
pub struct SessionBudget {
    /// The coarse over-estimate debited at reserve.
    pub estimate_nanos: u64,
    /// The once-per-session flat fee (`0` = none).
    pub fee_nanos: u64,
    /// The true budget ceiling (`None` = uncapped).
    pub cap_nanos: Option<u64>,
}

/// Why a session failed to start before any frame flowed.
#[derive(Debug)]
pub enum StartError {
    /// The D2 metering lease REFUSED the reserve (a refuse-all / zero budget) — fail closed, never open.
    BudgetRefused,
    /// The durable [`SessionHandle`] could not be opened (the engine rejected the genesis).
    Durable(HandleEngineError),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::BudgetRefused => write!(f, "voice session budget refused (fail closed)"),
            StartError::Durable(e) => write!(f, "voice session durable open failed: {e:?}"),
        }
    }
}

impl std::error::Error for StartError {}

/// BEGIN a governed session, common to both topologies: open the D2 metering lease (fail-closed on a
/// refused budget), open the durable [`SessionHandle`] at genesis, and assemble the [`SessionCore`]
/// with the plane's locked config, chosen `codec`, and `carrier`. The caller then serves the returned
/// core over the neutral pump.
#[allow(clippy::too_many_arguments)]
pub fn begin_session<C>(
    rt: &VoiceRuntime,
    codec: C,
    owner: impl Into<String>,
    call_id: impl Into<String>,
    locked_config: Option<SessionConfig>,
    carrier: Carrier,
    budget: SessionBudget,
    now: u64,
) -> Result<(Arc<SessionCore<C>>, SessionHandle), StartError>
where
    C: DuplexReader + DuplexWriter + Send + Sync + 'static,
{
    // The marquee guarantee starts HERE: no lease ⇒ no session (fail closed).
    let lease = rt
        .open_lease(budget.estimate_nanos, budget.fee_nanos, budget.cap_nanos)
        .ok_or(StartError::BudgetRefused)?;

    let handle = rt.bind_session(owner, call_id);
    handle.open(now).map_err(StartError::Durable)?;

    let core = Arc::new(SessionCore::new(
        codec,
        lease,
        Arc::clone(&rt.tools),
        rt.pricing,
        carrier,
        locked_config,
    ));
    Ok((core, handle))
}
