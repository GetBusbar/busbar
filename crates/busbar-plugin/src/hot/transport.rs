// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`TransportDecl`] — the `#[repr(C)]` surface a TRANSPORT exports on the HOT lane, so a transport
//! is swappable exactly as a plane is: compiled in OR dropped in, over one contract (#3, OWNER-LOCKED:
//! transport is one of the seven kinds; #30: plane and transport are the two HOT kinds).
//!
//! # The shape it carries
//!
//! A linked transport is folded by the composition root as a row of three things: its registry KEY,
//! the layers it declares it COMPOSES OVER, and a `build(lower, settings)` that yields a built
//! transport. This decl carries exactly that row, as data and one slot, so a dropped-in transport and
//! a linked one reach the root as the same row:
//!
//! * [`TransportDecl::key`], the [`TransportDecl::composes_over_ptr`] list and
//!   [`TransportDecl::session`] are DECLARED DATA, borrowed from the image and read once at load;
//! * [`TransportDecl::build`] takes the built LOWER layer (a [`WireLower`]: the lower transport's own
//!   decl plus its built state, NULL = no lower layer) and the deployment's [`WireSettings`], and
//!   yields the built transport as an [`OpaqueHandle`] the host stores and never downcasts;
//! * `listen` / `accept` / `dial` / `read` / `write` / `close` move bytes over that built state and
//!   over opaque `u64` connection and listener handles the transport mints.
//!
//! # What the transport is handed, and what it is never handed (#40)
//!
//! Key material never crosses this surface. A transport whose session layer needs configuration is
//! handed a [`WireConfig`]: a kernel-built, kernel-owned OPAQUE handle — a slot, a role and an
//! opaque pointer. It has no byte range and no length, and nothing on this surface reads through it;
//! the transport can present it back to the host, and cannot disassemble it (#40(b)). A transport
//! that needs no configuration is handed NULL.
//!
//! # The call discipline
//!
//! Every slot is an `extern "C-unwind"` fn pointer; every result is a [`RawWireOutcome`] byte the
//! host decodes with a checked conversion (an out-of-range byte reads as [`WireOutcome::Fault`],
//! never as an invalid enum). Out-params are written only on `Ok`. A slot BLOCKS until its operation
//! completes — the transport owns its own I/O driver — so a host drives the byte-moving slots off its
//! request threads. The per-call cost of the crossing itself is the HOT-lane budget (#30, < 1 µs).

use super::decl::{DeclStr, OpaqueHandle};
use crate::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

/// The first airlock minor at which a [`TransportDecl`] states the whole linked row (minor 26: the
/// `session` fact joined it; the minor-24 decl never shipped). A transport's manifest `abi_version`
/// is an airlock minor in `[TRANSPORT_DECL_MINOR, ABI_MINOR]`.
pub const TRANSPORT_DECL_MINOR: u32 = 26;

/// What a transport slot answers. The discriminants `1..=10` are the transport kind's own failure
/// vocabulary, in the order the contract's transport error spells it, so the host maps one to the
/// other without a table of its own; `11` and `12` are the seam's own answers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireOutcome {
    /// Done; every out-param the slot names is written.
    Ok = 0,
    /// The far side refused the connection.
    Refused = 1,
    /// A deadline expired.
    Timeout = 2,
    /// The connection was reset mid-stream.
    Reset = 3,
    /// The connection (or listener) is closed or unknown.
    Closed = 4,
    /// The secure handshake failed.
    HandshakeFailed = 5,
    /// Configuration could not be resolved.
    KeyUnavailable = 6,
    /// The address was not admissible.
    AddressRefused = 7,
    /// The far side stopped reading and the buffer is full.
    Backpressure = 8,
    /// The bytes violated the transport's own framing.
    Framing = 9,
    /// A lower layer this transport does not compose over, or one it cannot adopt.
    HandoffMismatch = 10,
    /// This transport does not implement the operation.
    Unsupported = 11,
    /// An internal fault (a caught panic maps here); no out-param is written.
    Fault = 12,
}

impl TryFrom<u8> for WireOutcome {
    /// The offending out-of-range byte.
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, u8> {
        Ok(match v {
            0 => WireOutcome::Ok,
            1 => WireOutcome::Refused,
            2 => WireOutcome::Timeout,
            3 => WireOutcome::Reset,
            4 => WireOutcome::Closed,
            5 => WireOutcome::HandshakeFailed,
            6 => WireOutcome::KeyUnavailable,
            7 => WireOutcome::AddressRefused,
            8 => WireOutcome::Backpressure,
            9 => WireOutcome::Framing,
            10 => WireOutcome::HandoffMismatch,
            11 => WireOutcome::Unsupported,
            12 => WireOutcome::Fault,
            other => return Err(other),
        })
    }
}

/// The RAW byte a transport slot returns. A slot's answer is transport-written, so it crosses as a
/// byte and is decoded here, never transmuted into [`WireOutcome`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawWireOutcome(pub u8);

impl RawWireOutcome {
    /// The raw byte for an outcome (the encode direction, for a transport).
    #[inline]
    #[must_use]
    pub const fn of(outcome: WireOutcome) -> Self {
        RawWireOutcome(outcome as u8)
    }

    /// Decode, mapping any out-of-range byte to [`WireOutcome::Fault`].
    #[inline]
    #[must_use]
    pub fn outcome(self) -> WireOutcome {
        WireOutcome::try_from(self.0).unwrap_or(WireOutcome::Fault)
    }
}

/// The deployment's settings every transport is built from — the operator's limits a wire holds
/// itself to, resolved once by the host and handed to each `build`. Field for field the settings a
/// linked transport's `build` reads; the two flags are `0`/`1`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSettings {
    /// `size_of::<WireSettings>()` at construction (the sized-struct guard).
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// `1` = pin the egress client to HTTP/1.1.
    pub upstream_http1_only: u8,
    /// `1` = force cleartext HTTP/2 prior-knowledge.
    pub upstream_h2_prior_knowledge: u8,
    /// Per-host idle keep-alive socket budget.
    pub pool_max_idle_per_host: u64,
    /// Idle keep-alive lifetime, in seconds.
    pub pool_idle_timeout_secs: u64,
    /// The largest request body a transport accumulates, in bytes.
    pub request_body_max_bytes: u64,
    /// The largest response body a transport carries for one exchange, in bytes.
    pub response_body_max_bytes: u64,
    /// The ceiling on one egress exchange up to the response head, in seconds.
    pub request_timeout_secs: u64,
}

/// The OPAQUE, kernel-built configuration handle a transport is handed in place of key material
/// (#40(b)). A slot, the end of the connection it is for, and a kernel-owned pointer: no byte range,
/// no length, nothing a transport can read material out of.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireConfig {
    /// `size_of::<WireConfig>()` at construction.
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// `0` = the accepting end (`listen`/`accept`), `1` = the dialing end (`dial`).
    pub role: u8,
    /// Alignment padding.
    pub _reserved: u8,
    /// The node-local slot the configuration is registered under.
    pub slot: u64,
    /// The kernel-owned configuration. Opaque: the transport never dereferences it.
    pub handle: *const c_void,
}

/// The layer a transport is built OVER: that layer's own decl and its built state. Passed by pointer;
/// NULL = the transport opens its own socket and takes no lower layer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireLower {
    /// The lower transport's decl (its slots are how the upper layer drives it).
    pub decl: *const TransportDecl,
    /// The lower transport's built state, as its `build` produced it.
    pub state: *mut c_void,
}

// ── the slot signatures ─────────────────────────────────────────────────────────────────────────

/// Build the transport over `lower` (NULL = none) from `settings`, writing its state on `Ok`.
pub type WireBuildFn = extern "C-unwind" fn(
    lower: *const WireLower,
    settings: *const WireSettings,
    out_state: *mut MaybeUninit<OpaqueHandle>,
) -> RawWireOutcome;
/// Open a listener on the UTF-8 `bind` address; writes the listener handle and the bound address
/// (into `addr_buf`, `out_addr_len` bytes) on `Ok`.
pub type WireListenFn = extern "C-unwind" fn(
    state: *mut c_void,
    bind_ptr: *const u8,
    bind_len: usize,
    config: *const WireConfig,
    addr_buf: *mut u8,
    addr_cap: usize,
    out_addr_len: *mut usize,
    out_listener: *mut u64,
) -> RawWireOutcome;
/// Take the next connection off `listener`; writes the connection handle and the peer (into
/// `peer_buf`, `out_peer_len` bytes) on `Ok`.
pub type WireAcceptFn = extern "C-unwind" fn(
    state: *mut c_void,
    listener: u64,
    peer_buf: *mut u8,
    peer_cap: usize,
    out_peer_len: *mut usize,
    out_conn: *mut u64,
) -> RawWireOutcome;
/// Dial the UTF-8 `authority` (already admitted by the host); writes the connection handle on `Ok`.
pub type WireDialFn = extern "C-unwind" fn(
    state: *mut c_void,
    authority_ptr: *const u8,
    authority_len: usize,
    config: *const WireConfig,
    out_conn: *mut u64,
) -> RawWireOutcome;
/// Read the next bytes of `conn` into `buf`; sets `out_written`. `Ok` with `0` written is a clean end
/// of stream.
pub type WireReadFn = extern "C-unwind" fn(
    state: *mut c_void,
    conn: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawWireOutcome;
/// Write all `len` bytes to `conn` (`Ok` = every byte left).
pub type WireWriteFn = extern "C-unwind" fn(
    state: *mut c_void,
    conn: u64,
    buf: *const u8,
    len: usize,
) -> RawWireOutcome;
/// Close `conn` (idempotent: an unknown handle is already closed).
pub type WireCloseFn = extern "C-unwind" fn(state: *mut c_void, conn: u64) -> RawWireOutcome;

/// The `#[repr(C)]` surface a transport exports for the host to register and drive. Leads with the
/// FROZEN [`AbiPreamble`] and a sized/versioned header, then the declared row (key, composes-over),
/// then the slots. `None` slots are operations the transport does not provide.
///
/// # Safety / discipline
/// `key`, the composes-over list and every string it borrows MUST point at bytes that outlive the
/// decl (the image's own read-only data).
#[repr(C)]
pub struct TransportDecl {
    /// The FROZEN airlock header — the host `check_preamble`s it before reading anything else.
    pub abi: AbiPreamble,
    /// `size_of::<TransportDecl>()` at construction.
    pub size: u32,
    /// Decl schema version (the airlock minor the transport was built at).
    pub version: u32,
    /// The transport's registry key.
    pub key: DeclStr,
    /// Borrowed list of the keys of the layers this transport can be built over.
    pub composes_over_ptr: *const DeclStr,
    /// Number of entries in the composes-over list.
    pub composes_over_len: usize,
    /// Build the transport.
    pub build: Option<WireBuildFn>,
    /// Open a listener.
    pub listen: Option<WireListenFn>,
    /// Accept a connection.
    pub accept: Option<WireAcceptFn>,
    /// Dial an authority.
    pub dial: Option<WireDialFn>,
    /// Read bytes.
    pub read: Option<WireReadFn>,
    /// Write bytes.
    pub write: Option<WireWriteFn>,
    /// Close a connection.
    pub close: Option<WireCloseFn>,
    // ── appended at minor 26 ──
    /// `1` when this transport carries sessions, `0` when it does not — the linked row's `SESSION`.
    /// Any other value is refused at load.
    pub session: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

// SAFETY: the same lifetime contract as `PlaneDecl`'s: every raw pointer here (the key, the
// composes-over list and the strings it borrows) points INTO the transport image's own read-only
// data, mapped for the whole life of the loaded transport and never mutated or freed while a decl
// that references it exists; the slots are plain code addresses.
unsafe impl Send for TransportDecl {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for TransportDecl {}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
