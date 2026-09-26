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
//! * `listen` binds a listener and answers at once; `connect` begins a dial and answers at once; the
//!   POLL slots — `poll_accept`, `poll_read`, `poll_write`, `poll_flush`, `poll_close` — move bytes
//!   over that built state and over opaque `u64` connection and listener handles the transport mints.
//!
//! # What the transport is handed, and what it is never handed (#40)
//!
//! Key material never crosses this surface. A transport whose session layer needs configuration is
//! handed a [`WireConfig`]: a kernel-built, kernel-owned OPAQUE handle — a slot, a role and an
//! opaque pointer. It has no byte range and no length, and nothing on this surface reads through it;
//! the transport can present it back to the host, and cannot disassemble it (#40(b)). A transport
//! that needs no configuration is handed NULL.
//!
//! # The call discipline (minor 28: the POLL shape)
//!
//! Every slot is an `extern "C-unwind"` fn pointer; every result is a [`RawWireOutcome`] byte the
//! host decodes with a checked conversion (an out-of-range byte reads as [`WireOutcome::Fault`],
//! never as an invalid enum). Out-params are written only on `Ok`.
//!
//! NO SLOT BLOCKS. A poll slot answers at once, one of three ways: READY — [`WireOutcome::Ok`], with
//! its count (`Ready(n)`) in the out-param; [`WireOutcome::Pending`] — the operation cannot progress
//! yet; or an ERROR — any other outcome. The host drives the poll slots INLINE from its own reactor,
//! on its request threads, with no hop to another thread (#30: the crossing is the HOT-lane budget,
//! < 1 µs).
//!
//! READINESS is registered through the host's WAKER HANDLE, a [`WireWaker`] the host passes to
//! [`TransportDecl::init`] once: a `#[repr(C)]` table holding one function, `wake(token)`. Every poll
//! slot is handed a `token` — an opaque, host-minted `u64` naming the host task waiting on that
//! operation. A slot that answers `Pending` keeps the token and calls `wake(token)`, from any thread,
//! once the operation may progress; the host then polls again. Waking a token nobody waits on any
//! more is harmless, and [`NO_WAKER`] (`0`) names no task: a slot handed it never wakes it. The host
//! hands the transport no pointer into its own state (#40(c)): the waker handle is a vtable, and a
//! token is a number the host resolves in its own table.
//!
//! A transport synchronises its own built state: the host polls one connection's reading and its
//! writing from different tasks at once, and different connections from different threads.
//!
//! # Retired at minor 28: the blocking slots
//!
//! Minors 24–26 laid out `build`, `accept`, `dial`, `read`, `write` and `close` as BLOCKING slots, so
//! a host could drive them only by parking a thread per call — the crossing then cost a thread
//! handoff, over the HOT-lane budget. No shipped wire needs them, so minor 28 RETIRES them: the
//! fields keep their offsets (append-only), a minor-28 decl leaves every one of them `None`, and the
//! loader refuses a decl that fills one and every decl built before minor 28. [`TransportDecl::init`],
//! [`TransportDecl::connect`] and the five poll slots replace them.

use super::decl::{DeclStr, OpaqueHandle};
use crate::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

/// The first airlock minor whose [`TransportDecl`] the host admits: minor 28, the POLL-shaped slots
/// and the host's waker handle (the minor-24..27 decls carried BLOCKING slots, now retired; see the
/// module docs). A transport's manifest `abi_version` is an airlock minor in
/// `[TRANSPORT_DECL_MINOR, ABI_MINOR]`.
pub const TRANSPORT_DECL_MINOR: u32 = 28;

/// The token that names no waiting task: a poll slot handed it never calls `wake` for it (the host
/// uses it for a close nobody waits on).
pub const NO_WAKER: u64 = 0;

/// What a transport slot answers. The discriminants `1..=10` are the transport kind's own failure
/// vocabulary, in the order the contract's transport error spells it, so the host maps one to the
/// other without a table of its own; `11`, `12` and `13` are the seam's own answers.
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
    /// A POLL slot's "not yet" (minor 28): the operation cannot progress now; the transport keeps the
    /// call's token and wakes it through the host's [`WireWaker`] once it may. No out-param is
    /// written.
    Pending = 13,
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
            13 => WireOutcome::Pending,
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

/// THE HOST'S WAKER HANDLE (minor 28), passed to [`TransportDecl::init`] once and held by the built
/// transport for its life: how a poll slot that answered [`WireOutcome::Pending`] tells the host the
/// operation may progress. A `#[repr(C)]` vtable of one function and nothing else — no pointer into
/// host state (#40(c)); the `token` it is called with is a number the host minted and resolves in its
/// own table.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireWaker {
    /// `size_of::<WireWaker>()` at construction (the sized-struct guard).
    pub size: u32,
    /// Schema version (the airlock minor the host was built at).
    pub version: u32,
    /// Wake the host task `token` names. Callable from any thread, at any time, any number of times;
    /// never blocks and never unwinds. A token nobody waits on any more is ignored.
    pub wake: Option<WireWakeFn>,
}

/// `wake(token)` — see [`WireWaker::wake`].
pub type WireWakeFn = extern "C-unwind" fn(token: u64);

// ── the slot signatures ─────────────────────────────────────────────────────────────────────────

/// RETIRED at minor 28 (see [`WireInitFn`]). Build the transport over `lower` (NULL = none) from
/// `settings`, writing its state on `Ok`.
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
/// RETIRED at minor 28 (see [`WirePollAcceptFn`]). Take the next connection off `listener`, blocking;
/// writes the connection handle and the peer on `Ok`.
pub type WireAcceptFn = extern "C-unwind" fn(
    state: *mut c_void,
    listener: u64,
    peer_buf: *mut u8,
    peer_cap: usize,
    out_peer_len: *mut usize,
    out_conn: *mut u64,
) -> RawWireOutcome;
/// RETIRED at minor 28 (see [`WireConnectFn`]). Dial the UTF-8 `authority`, blocking; writes the
/// connection handle on `Ok`.
pub type WireDialFn = extern "C-unwind" fn(
    state: *mut c_void,
    authority_ptr: *const u8,
    authority_len: usize,
    config: *const WireConfig,
    out_conn: *mut u64,
) -> RawWireOutcome;
/// RETIRED at minor 28 (see [`WirePollReadFn`]). Read the next bytes of `conn` into `buf`, blocking.
pub type WireReadFn = extern "C-unwind" fn(
    state: *mut c_void,
    conn: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawWireOutcome;
/// RETIRED at minor 28 (see [`WirePollWriteFn`]). Write all `len` bytes to `conn`, blocking.
pub type WireWriteFn = extern "C-unwind" fn(
    state: *mut c_void,
    conn: u64,
    buf: *const u8,
    len: usize,
) -> RawWireOutcome;
/// RETIRED at minor 28 (see [`WirePollCloseFn`]). Close `conn`.
pub type WireCloseFn = extern "C-unwind" fn(state: *mut c_void, conn: u64) -> RawWireOutcome;

/// INIT (minor 28): build the transport over `lower` (NULL = none) from `settings`, handed the host's
/// `waker` handle (non-null, `'static` for the life of the built state), writing its state on `Ok`.
pub type WireInitFn = extern "C-unwind" fn(
    lower: *const WireLower,
    settings: *const WireSettings,
    waker: *const WireWaker,
    out_state: *mut MaybeUninit<OpaqueHandle>,
) -> RawWireOutcome;
/// CONNECT (minor 28): BEGIN dialing the UTF-8 `authority` (already admitted by the host) and answer
/// at once, writing the new connection's handle on `Ok`. The connection's opening completes under
/// its poll slots: `poll_flush` answers `Ok` once it is open (or the dial's refusal once it failed),
/// and `poll_read` / `poll_write` wait for the opening before they move a byte.
pub type WireConnectFn = extern "C-unwind" fn(
    state: *mut c_void,
    authority_ptr: *const u8,
    authority_len: usize,
    config: *const WireConfig,
    out_conn: *mut u64,
) -> RawWireOutcome;
/// POLL ACCEPT (minor 28): the next connection off `listener`, or `Pending` (waking `token` when one
/// arrives). On `Ok`, writes the connection handle and the peer (into `peer_buf`, `out_peer_len`
/// bytes).
pub type WirePollAcceptFn = extern "C-unwind" fn(
    state: *mut c_void,
    listener: u64,
    token: u64,
    peer_buf: *mut u8,
    peer_cap: usize,
    out_peer_len: *mut usize,
    out_conn: *mut u64,
) -> RawWireOutcome;
/// POLL READ (minor 28): the next bytes of `conn` into `buf` (`buf_cap > 0`), or `Pending` (waking
/// `token` when bytes arrive). On `Ok`, `out_read` is how many — `Ready(n)`; `Ok` with `0` is the
/// clean end of the stream.
pub type WirePollReadFn = extern "C-unwind" fn(
    state: *mut c_void,
    conn: u64,
    token: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_read: *mut usize,
) -> RawWireOutcome;
/// POLL WRITE (minor 28): take some of the `len` bytes for `conn`, or `Pending` (waking `token` when
/// it can take more). On `Ok`, `out_written` is how many it took — `Ready(n)`, `1..=len` for a
/// non-empty write; the host offers the rest on its next poll.
pub type WirePollWriteFn = extern "C-unwind" fn(
    state: *mut c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> RawWireOutcome;
/// POLL FLUSH (minor 28): `Ok` once every byte `conn` took is on the wire — and, for a connection
/// `connect` began, once it is open — or `Pending` (waking `token`).
pub type WirePollFlushFn =
    extern "C-unwind" fn(state: *mut c_void, conn: u64, token: u64) -> RawWireOutcome;
/// POLL CLOSE (minor 28): close `conn` and release its handle, answering `Ok` once it is closed, or
/// `Pending` (waking `token`). Idempotent: an unknown handle is already closed. Handed [`NO_WAKER`],
/// the transport closes the connection whether or not anyone polls again. A read or write parked on
/// the connection is woken, and sees it closed.
pub type WirePollCloseFn =
    extern "C-unwind" fn(state: *mut c_void, conn: u64, token: u64) -> RawWireOutcome;

/// The `#[repr(C)]` surface a transport exports for the host to register and drive. Leads with the
/// FROZEN [`AbiPreamble`] and a sized/versioned header, then the declared row (key, composes-over),
/// then the slots. `None` slots are operations the transport does not provide; the slots RETIRED at
/// minor 28 (`build`, `accept`, `dial`, `read`, `write`, `close`) are always `None`.
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
    /// RETIRED at minor 28 (always `None`): the blocking build, replaced by [`Self::init`].
    pub build: Option<WireBuildFn>,
    /// Open a listener (answers at once). The host may listen on one address once per acceptor —
    /// its per-core fan-out — so a wire that can share an address across listeners does.
    pub listen: Option<WireListenFn>,
    /// RETIRED at minor 28 (always `None`): replaced by [`Self::poll_accept`].
    pub accept: Option<WireAcceptFn>,
    /// RETIRED at minor 28 (always `None`): replaced by [`Self::connect`].
    pub dial: Option<WireDialFn>,
    /// RETIRED at minor 28 (always `None`): replaced by [`Self::poll_read`].
    pub read: Option<WireReadFn>,
    /// RETIRED at minor 28 (always `None`): replaced by [`Self::poll_write`].
    pub write: Option<WireWriteFn>,
    /// RETIRED at minor 28 (always `None`): replaced by [`Self::poll_close`].
    pub close: Option<WireCloseFn>,
    // ── appended at minor 26 ──
    /// `1` when this transport carries sessions, `0` when it does not — the linked row's `SESSION`.
    /// Any other value is refused at load.
    pub session: u32,
    /// Alignment padding.
    pub _reserved: u32,
    // ── appended at minor 28: the POLL shape ──
    /// Build the transport, handed the host's waker handle.
    pub init: Option<WireInitFn>,
    /// Begin a dial.
    pub connect: Option<WireConnectFn>,
    /// Poll a listener for its next connection.
    pub poll_accept: Option<WirePollAcceptFn>,
    /// Poll a connection's bytes in.
    pub poll_read: Option<WirePollReadFn>,
    /// Poll a connection's bytes out.
    pub poll_write: Option<WirePollWriteFn>,
    /// Poll a connection's bytes (and its opening) onto the wire.
    pub poll_flush: Option<WirePollFlushFn>,
    /// Poll a connection closed.
    pub poll_close: Option<WirePollCloseFn>,
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
