// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral BREAKER `Signal` constructors a plane's settle leg builds — the plane-side half of the
//! host `breaker_settle` seam. These are pure `#[repr(C)]` POD builders (they name only
//! [`busbar_plugin::hot`] + the neutral [`CanonicalSignal`](crate::breaker::CanonicalSignal)), so they
//! live here in the substrate rather than in `busbar-core`: a plane compiled apart from the host builds
//! the `Signal` it hands to [`EngineHost::breaker_settle`](super::EngineHost::breaker_settle) without
//! naming a core type.
//!
//! The host's own `classify` (in `busbar-core`) is the INVERSE of [`failure_signal`], so a settle folded
//! through the host reproduces the EXACT disposition the plane's own `record_signal` would.

use crate::breaker::{CanonicalSignal, StatusClass as BreakerClass};
use busbar_plugin::hot::{FaultClass, Signal, StatusClass};

/// The inverse of the host `classify`'s fine [`FaultClass`] → [`BreakerClass`] table: the plane's own
/// canonical class back to the ABI fine class the settle carries. Total — every [`BreakerClass`] maps
/// to exactly one [`FaultClass`], so a settle built here round-trips through the host `classify`.
// Built only by the MCP and A2A plane settle paths (via `failure_signal`), so it reads dead when both
// planes are compiled out; live with either on.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
fn fault_of(class: BreakerClass) -> FaultClass {
    match class {
        BreakerClass::RateLimit => FaultClass::RateLimit,
        BreakerClass::Overloaded => FaultClass::Overloaded,
        BreakerClass::ServerError => FaultClass::UpstreamError,
        BreakerClass::Timeout => FaultClass::Timeout,
        BreakerClass::Network => FaultClass::Network,
        BreakerClass::Auth => FaultClass::Auth,
        BreakerClass::Billing => FaultClass::Billing,
        BreakerClass::ClientError => FaultClass::ClientError,
        BreakerClass::ContextLength => FaultClass::ContextLength,
    }
}

/// Build the ABI [`Signal`] a host settle carries FROM the plane's own [`CanonicalSignal`] — the
/// INVERSE of the host `classify`, so a settle folded through the host scope reproduces the EXACT
/// disposition the plane's own `record_signal` would. A failure rides its fine [`FaultClass`], the
/// `Retry-After` floor (flagged in `fault_flags` bit 0 so a `0`-second header is distinct from "no
/// header"), and the borrowed provider error-code — the exact three inputs the host `classify` reads
/// back. The coarse `class` is the neutral failure carrier [`StatusClass::Fault`]; the FINE
/// `fault_class` is what the host reads.
///
/// The returned `Signal` BORROWS `cs.provider_signal`; it MUST NOT outlive `cs`.
// Built only by the MCP and A2A plane settle paths, so it reads dead when both planes are compiled
// out; live with either on.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[must_use]
pub fn failure_signal(cs: &CanonicalSignal) -> Signal {
    let (flags, secs) = match cs.retry_after {
        Some(s) => (0x01u8, s),
        None => (0, 0),
    };
    let (ptr, len) = match cs.provider_signal.as_deref() {
        Some(code) => (code.as_ptr(), code.len()),
        None => (core::ptr::null(), 0),
    };
    Signal {
        size: core::mem::size_of::<Signal>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        class: StatusClass::Fault,
        _reserved: 0,
        latency_nanos: 0,
        bytes: 0,
        fault_class: fault_of(cs.class),
        fault_flags: flags,
        _reserved2: 0,
        _reserved3: 0,
        retry_after_secs: secs,
        provider_signal_ptr: ptr,
        provider_signal_len: len,
    }
}

/// The ABI [`Signal`] a host settle carries for a SUCCESS — the host `classify` maps `Ok` straight to
/// `record_success`, closing the half-open probe exactly as the plane's own success record does.
// Built only by the MCP and A2A plane settle paths, so it reads dead when both planes are compiled
// out; live with either on.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[must_use]
pub fn success_signal() -> Signal {
    Signal {
        size: core::mem::size_of::<Signal>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        class: StatusClass::Ok,
        _reserved: 0,
        latency_nanos: 0,
        bytes: 0,
        fault_class: FaultClass::Unspecified,
        fault_flags: 0,
        _reserved2: 0,
        _reserved3: 0,
        retry_after_secs: 0,
        provider_signal_ptr: core::ptr::null(),
        provider_signal_len: 0,
    }
}

/// The ABI [`Signal`] a host settle carries for an outcome that is NOT an upstream health signal —
/// the host `classify` maps `Refused` to `RecordNothing`, so settling this RELEASES the half-open probe
/// without recording, exactly as dropping the raw `PlaneAdmission` did (the "record nothing"
/// disposition: a busbar-side refusal / a not-transmitted leg).
// Built only by the MCP plane leg (`mcp::tasks`/`mcp::reroute`) — the A2A relay never carries the
// "record nothing" outcome — so it reads dead whenever the MCP plane is compiled out.
#[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
#[must_use]
pub fn refused_signal() -> Signal {
    Signal {
        size: core::mem::size_of::<Signal>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        class: StatusClass::Refused,
        _reserved: 0,
        latency_nanos: 0,
        bytes: 0,
        fault_class: FaultClass::Unspecified,
        fault_flags: 0,
        _reserved2: 0,
        _reserved3: 0,
        retry_after_secs: 0,
        provider_signal_ptr: core::ptr::null(),
        provider_signal_len: 0,
    }
}
