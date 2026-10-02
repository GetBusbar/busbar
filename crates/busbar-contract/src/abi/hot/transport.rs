// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`TransportDecl`] — the `#[repr(C)]` surface a TRANSPORT exports on the HOT lane (#3: a transport
//! is swappable, compiled in OR dropped in; #30: it rides the HOT lane).
//!
//! # A mechanical lowering, not a shape of its own (TRANSPORT-STACK, owner-approved 2026-09-27)
//!
//! A transport is a [`Carrier`](crate::transport::Carrier) or a [`Framer`](crate::transport::Framer)
//! (`crate::transport::stack`), and this decl is those two traits lowered to `#[repr(C)]`, ONE SLOT
//! PER METHOD, the slot named for the method: [`CarrierSlots`] for a carrier, [`FramerSlots`] for a
//! framer. Nothing here is shaped by any one wire; a byte stream is a carrier whose reads are its
//! frames. The witness `tests/transport_slot_coverage.rs` holds every trait method to exactly one
//! slot and goes RED on a method without one.
//!
//! * The ROW — every constant the transport declares (`crate::transport::TransportRow`) — is decl
//!   DATA, borrowed from the image and read once at load, so the host reads a dropped-in row exactly
//!   as it reads a linked one. The role is not stated: it is derived from `composes_over` (none = a
//!   carrier), and exactly the matching slot table is present.
//! * [`TransportDecl::init`] builds the transport from the deployment's [`WireSettings`], handed the
//!   host's waker handle ([`WireWaker`]).
//!
//! # The call discipline
//!
//! Every slot is an `extern "C-unwind"` fn pointer answering a [`RawWireOutcome`] byte the host
//! decodes with a checked conversion (an out-of-range byte reads as [`WireOutcome::Fault`]).
//! Out-params are written only on `Ok`.
//!
//! A CARRIER's slots are POLL-shaped: each answers at once — `Ok` (ready), [`WireOutcome::Pending`],
//! or an error. A slot that answers `Pending` keeps the call's `token` (an opaque number the host
//! minted for the waiting task) and calls the host's `wake(token)` once the operation may progress.
//! [`NO_WAKER`] names no task. The host polls inline from its reactor, on its own threads.
//!
//! A FRAMER is sans-IO: no socket, no waker, no clock. What a framer call produces — bytes owed to the
//! far side, frame pieces, the end of the connection's frames — is handed back through host-owned
//! callbacks ([`WireFramerOut`], [`WireBytesOut`]) during the call.
//!
//! # What never crosses (#40(b), #36)
//!
//! No slot hands a transport key or certificate material, and none takes it back: connection
//! security is core's own (#40(b)), and a framer is told only what the handshake
//! established, as facts ([`WireConnFacts`]).
//!
//! # The transport-decl major
//!
//! [`TRANSPORT_DECL_MAJOR`] is this decl's own generation, stated in [`TransportDecl::version`]. The
//! earlier decl (a byte-stream decl, airlock minors 24–30) is retired whole: its `version` field held
//! its airlock minor, never `2`, so the host refuses it by this one field.

use super::decl::{DeclStr, OpaqueHandle};
use crate::abi::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

use crate::grammar::SelectorForm;
use crate::transport::wire::{
    CloseReason, Encode, Framing, StatusAt, TransportError, Unit0Trigger, WireStatusClass,
};
use crate::transport::Side;

/// The transport decl's own generation (module docs): the value of [`TransportDecl::version`].
pub const TRANSPORT_DECL_MAJOR: u32 = 2;

/// The first airlock minor whose [`TransportDecl`] the host admits: the minor that introduced the
/// carrier/framer decl. A transport's manifest `abi_version` is an airlock minor in
/// `[TRANSPORT_DECL_MINOR, ABI_MINOR]`.
pub const TRANSPORT_DECL_MINOR: u32 = 31;

/// The token that names no waiting task: a poll slot handed it never wakes it.
pub const NO_WAKER: u64 = 0;

/// What a transport slot answers. `1..=10` are the transport kind's failure vocabulary in the order
/// [`TransportError`] spells it; `11`–`13` are the seam's own answers; `14`–`17` are an envelope
/// rendering's refusals in the order [`Encode`] spells them.
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
    /// The connection (or listener, or framing state) is closed or unknown.
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
    /// A stream this transport cannot take over.
    HandoffMismatch = 10,
    /// This transport does not implement the operation.
    Unsupported = 11,
    /// An internal fault (a caught panic maps here); no out-param is written.
    Fault = 12,
    /// A carrier slot's "not yet": it keeps the call's token and wakes it once it may progress.
    Pending = 13,
    /// The envelope cannot be expressed on this wire.
    Unrepresentable = 14,
    /// The rendering ran out of room.
    ScratchExhausted = 15,
    /// A secret placeholder did not appear exactly once where it was declared.
    SecretPlaceholder = 16,
    /// The rendering state is poisoned.
    Poisoned = 17,
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
            14 => WireOutcome::Unrepresentable,
            15 => WireOutcome::ScratchExhausted,
            16 => WireOutcome::SecretPlaceholder,
            17 => WireOutcome::Poisoned,
            other => return Err(other),
        })
    }
}

impl WireOutcome {
    /// A transport failure as its outcome.
    #[must_use]
    pub const fn of_error(e: TransportError) -> Self {
        match e {
            TransportError::Refused => WireOutcome::Refused,
            TransportError::Timeout => WireOutcome::Timeout,
            TransportError::Reset => WireOutcome::Reset,
            TransportError::Closed => WireOutcome::Closed,
            TransportError::HandshakeFailed => WireOutcome::HandshakeFailed,
            TransportError::KeyUnavailable => WireOutcome::KeyUnavailable,
            TransportError::AddressRefused => WireOutcome::AddressRefused,
            TransportError::Backpressure => WireOutcome::Backpressure,
            TransportError::Framing => WireOutcome::Framing,
            TransportError::HandoffMismatch => WireOutcome::HandoffMismatch,
        }
    }

    /// The transport failure an outcome reports. The seam's own answers (and a rendering refusal)
    /// read as a closed operation: the host cannot continue it.
    #[must_use]
    pub const fn error(self) -> TransportError {
        match self {
            WireOutcome::Refused => TransportError::Refused,
            WireOutcome::Timeout => TransportError::Timeout,
            WireOutcome::Reset => TransportError::Reset,
            WireOutcome::HandshakeFailed => TransportError::HandshakeFailed,
            WireOutcome::KeyUnavailable => TransportError::KeyUnavailable,
            WireOutcome::AddressRefused => TransportError::AddressRefused,
            WireOutcome::Backpressure => TransportError::Backpressure,
            WireOutcome::Framing => TransportError::Framing,
            WireOutcome::HandoffMismatch => TransportError::HandoffMismatch,
            _ => TransportError::Closed,
        }
    }

    /// An envelope rendering's refusal as its outcome.
    #[must_use]
    pub const fn of_encode(e: Encode) -> Self {
        match e {
            Encode::Unrepresentable => WireOutcome::Unrepresentable,
            Encode::ScratchExhausted => WireOutcome::ScratchExhausted,
            Encode::SecretPlaceholder => WireOutcome::SecretPlaceholder,
            Encode::Poisoned => WireOutcome::Poisoned,
        }
    }

    /// The rendering refusal an outcome reports; anything that is not one reads as poisoned (the
    /// rendering cannot be trusted).
    #[must_use]
    pub const fn encode_error(self) -> Encode {
        match self {
            WireOutcome::Unrepresentable => Encode::Unrepresentable,
            WireOutcome::ScratchExhausted => Encode::ScratchExhausted,
            WireOutcome::SecretPlaceholder => Encode::SecretPlaceholder,
            _ => Encode::Poisoned,
        }
    }
}

/// The RAW byte a transport slot returns, decoded by the host (never transmuted).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawWireOutcome(pub u8);

impl RawWireOutcome {
    /// The raw byte for an outcome.
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

// ── the closed vocabularies, as bytes ────────────────────────────────────────────────────────────

/// Every closed vocabulary a slot or the row carries crosses as a byte, `0` = absent where the
/// value is optional; these are the encodings, each with its inverse (an unknown byte is `None`).
pub mod code {
    use super::*;

    /// A close reason, `0..=7` in [`CloseReason`]'s order.
    #[must_use]
    pub const fn close_reason(r: CloseReason) -> u8 {
        match r {
            CloseReason::Normal => 0,
            CloseReason::PeerClosed => 1,
            CloseReason::Drain => 2,
            CloseReason::Poisoned => 3,
            CloseReason::Revoked => 4,
            CloseReason::Timeout => 5,
            CloseReason::TransportFailed => 6,
            CloseReason::CapacityExhausted => 7,
        }
    }

    /// The inverse of [`close_reason`].
    #[must_use]
    pub const fn close_reason_of(b: u8) -> Option<CloseReason> {
        Some(match b {
            0 => CloseReason::Normal,
            1 => CloseReason::PeerClosed,
            2 => CloseReason::Drain,
            3 => CloseReason::Poisoned,
            4 => CloseReason::Revoked,
            5 => CloseReason::Timeout,
            6 => CloseReason::TransportFailed,
            7 => CloseReason::CapacityExhausted,
            _ => return None,
        })
    }

    /// A status class, `1..=4`; `0` = none.
    #[must_use]
    pub const fn status_class(s: Option<WireStatusClass>) -> u8 {
        match s {
            None => 0,
            Some(WireStatusClass::Success) => 1,
            Some(WireStatusClass::CallerFault) => 2,
            Some(WireStatusClass::FarEndFault) => 3,
            Some(WireStatusClass::Other) => 4,
        }
    }

    /// The inverse of [`status_class`]; `Err` for an unknown byte.
    pub const fn status_class_of(b: u8) -> Result<Option<WireStatusClass>, u8> {
        Ok(match b {
            0 => None,
            1 => Some(WireStatusClass::Success),
            2 => Some(WireStatusClass::CallerFault),
            3 => Some(WireStatusClass::FarEndFault),
            4 => Some(WireStatusClass::Other),
            other => return Err(other),
        })
    }

    /// Which frame carries the status, `1..=2`; `0` = none.
    #[must_use]
    pub const fn status_at(s: Option<StatusAt>) -> u8 {
        match s {
            None => 0,
            Some(StatusAt::FirstFrame) => 1,
            Some(StatusAt::Terminal) => 2,
        }
    }

    /// The inverse of [`status_at`]; `Err` for an unknown byte.
    pub const fn status_at_of(b: u8) -> Result<Option<StatusAt>, u8> {
        Ok(match b {
            0 => None,
            1 => Some(StatusAt::FirstFrame),
            2 => Some(StatusAt::Terminal),
            other => return Err(other),
        })
    }

    /// How arrivals are delimited, `0..=1`.
    #[must_use]
    pub const fn framing(f: Framing) -> u8 {
        match f {
            Framing::Stream => 0,
            Framing::Datagram => 1,
        }
    }

    /// The inverse of [`framing`]; `Err` for an unknown byte.
    pub const fn framing_of(b: u8) -> Result<Framing, u8> {
        match b {
            0 => Ok(Framing::Stream),
            1 => Ok(Framing::Datagram),
            other => Err(other),
        }
    }

    /// What opens a session's first unit, `1..=6`; `0` = none.
    #[must_use]
    pub const fn unit0_trigger(t: Option<Unit0Trigger>) -> u8 {
        match t {
            None => 0,
            Some(Unit0Trigger::FirstBytes) => 1,
            Some(Unit0Trigger::FirstLine) => 2,
            Some(Unit0Trigger::FirstMessage) => 3,
            Some(Unit0Trigger::FirstDatagram) => 4,
            Some(Unit0Trigger::Upgrade) => 5,
            Some(Unit0Trigger::Handshake) => 6,
        }
    }

    /// The inverse of [`unit0_trigger`]; `Err` for an unknown byte.
    pub const fn unit0_trigger_of(b: u8) -> Result<Option<Unit0Trigger>, u8> {
        Ok(match b {
            0 => None,
            1 => Some(Unit0Trigger::FirstBytes),
            2 => Some(Unit0Trigger::FirstLine),
            3 => Some(Unit0Trigger::FirstMessage),
            4 => Some(Unit0Trigger::FirstDatagram),
            5 => Some(Unit0Trigger::Upgrade),
            6 => Some(Unit0Trigger::Handshake),
            other => return Err(other),
        })
    }

    /// Every selector form, in code order: a form's code is its index here plus one.
    pub const SELECTOR_FORMS: [SelectorForm; 13] = [
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::Sni,
        SelectorForm::ClientCertSubject,
        SelectorForm::PathPattern,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::PathSuffix,
        SelectorForm::PathContains,
        SelectorForm::StreamName,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];

    /// A selector form's code, `1..=13`.
    #[must_use]
    pub const fn selector_form(f: SelectorForm) -> u8 {
        let mut i = 0;
        while i < SELECTOR_FORMS.len() {
            if SELECTOR_FORMS[i] as u8 == f as u8 {
                return i as u8 + 1;
            }
            i += 1;
        }
        0
    }

    /// The inverse of [`selector_form`].
    #[must_use]
    pub const fn selector_form_of(b: u8) -> Option<SelectorForm> {
        match b {
            1..=13 => Some(SELECTOR_FORMS[b as usize - 1]),
            _ => None,
        }
    }

    /// Which end of a connection, `0..=1`.
    #[must_use]
    pub const fn side(s: Side) -> u8 {
        match s {
            Side::Accept => 0,
            Side::Dial => 1,
        }
    }

    /// The inverse of [`side`].
    #[must_use]
    pub const fn side_of(b: u8) -> Option<Side> {
        match b {
            0 => Some(Side::Accept),
            1 => Some(Side::Dial),
            _ => None,
        }
    }
}

// ── the shapes that cross ────────────────────────────────────────────────────────────────────────

/// The deployment's settings every transport is built from, field for field the settings a linked
/// transport's build reads; the two flags are `0`/`1`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSettings {
    /// `size_of::<WireSettings>()` at construction.
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

impl WireSettings {
    /// The settings a linked transport is built from, as they cross.
    #[must_use]
    pub fn of(s: &crate::transport::TransportSettings) -> Self {
        Self {
            size: core::mem::size_of::<WireSettings>() as u32,
            version: TRANSPORT_DECL_MAJOR as u16,
            upstream_http1_only: u8::from(s.upstream_http1_only),
            upstream_h2_prior_knowledge: u8::from(s.upstream_h2_prior_knowledge),
            pool_max_idle_per_host: s.pool_max_idle_per_host as u64,
            pool_idle_timeout_secs: s.pool_idle_timeout_secs,
            request_body_max_bytes: s.request_body_max_bytes as u64,
            response_body_max_bytes: s.response_body_max_bytes as u64,
            request_timeout_secs: s.request_timeout_secs,
        }
    }

    /// The settings as a linked transport reads them.
    #[must_use]
    pub fn settings(&self) -> crate::transport::TransportSettings {
        let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        crate::transport::TransportSettings {
            pool_max_idle_per_host: size(self.pool_max_idle_per_host),
            pool_idle_timeout_secs: self.pool_idle_timeout_secs,
            upstream_http1_only: self.upstream_http1_only == 1,
            upstream_h2_prior_knowledge: self.upstream_h2_prior_knowledge == 1,
            request_body_max_bytes: size(self.request_body_max_bytes),
            response_body_max_bytes: size(self.response_body_max_bytes),
            request_timeout_secs: self.request_timeout_secs,
        }
    }
}

/// THE HOST'S WAKER HANDLE, passed to [`TransportDecl::init`] once and held by the built transport
/// for its life: a `#[repr(C)]` table of one function, `wake(token)`, and no pointer into host state
/// (#40(c)).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireWaker {
    /// `size_of::<WireWaker>()` at construction.
    pub size: u32,
    /// Schema version (the airlock minor the host was built at).
    pub version: u32,
    /// Wake the host task `token` names. Any thread, any time; never blocks, never unwinds.
    pub wake: Option<WireWakeFn>,
}

/// `wake(token)` — see [`WireWaker::wake`].
pub type WireWakeFn = extern "C-unwind" fn(token: u64);

/// A borrowed list of strings (NULL `ptr` with `len` 0 = empty).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclStrList {
    /// The entries.
    pub ptr: *const DeclStr,
    /// How many.
    pub len: usize,
}

/// A borrowed list of bytes (NULL `ptr` with `len` 0 = empty).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclByteList {
    /// The bytes.
    pub ptr: *const u8,
    /// How many.
    pub len: usize,
}

// SAFETY: both lists borrow the image's own read-only data, mapped for its whole life (the
// `DeclStr` contract).
unsafe impl Send for DeclStrList {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DeclStrList {}
// SAFETY: as for `DeclStrList`.
unsafe impl Send for DeclByteList {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DeclByteList {}

/// One environment entry of a program destination.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireEnvPair {
    /// The variable's name.
    pub name: DeclStr,
    /// Its value.
    pub value: DeclStr,
}

/// A carrier's destination ([`crate::transport::Dest`]), borrowed for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireDest {
    /// `size_of::<WireDest>()` at construction.
    pub size: u32,
    /// `0` = an authority, `1` = a program.
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The authority (`kind` 0).
    pub authority: DeclStr,
    /// The program's absolute path (`kind` 1).
    pub program: DeclStr,
    /// Its arguments (`kind` 1).
    pub args: DeclStrList,
    /// Its whole environment (`kind` 1).
    pub env: *const WireEnvPair,
    /// How many environment entries.
    pub env_len: usize,
}

/// What connection security established ([`crate::transport::ConnFacts`]), borrowed for the call —
/// facts only; each string NULL when absent, and the certificate's three facts present together.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireConnFacts {
    /// `size_of::<WireConnFacts>()` at construction.
    pub size: u32,
    /// Schema version.
    pub version: u32,
    /// The server name offered.
    pub sni: DeclStr,
    /// The protocol agreed.
    pub alpn: DeclStr,
    /// The far end's certificate subject.
    pub cert_subject: DeclStr,
    /// The far end's certificate issuer.
    pub cert_issuer: DeclStr,
    /// The far end's certificate fingerprint (NULL = no certificate).
    pub cert_fingerprint: DeclStr,
    /// The claim the host resolved the connection to (appended at minor 33; NULL = the entry's
    /// first claim).
    pub claim: DeclStr,
}

/// One frame piece ([`crate::transport::Framed`]), borrowed for the callback.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireFramed {
    /// `size_of::<WireFramed>()` at construction.
    pub size: u32,
    /// `1` = this piece completes the frame.
    pub end_of_frame: u8,
    /// The status class ([`code::status_class`]; `0` = none).
    pub status_class: u8,
    /// [`FRAMED_HAS_STATUS_CODE`] | [`FRAMED_HAS_RETRY_AFTER`] | [`FRAMED_TEXT`].
    pub flags: u8,
    /// Alignment padding.
    pub _reserved: u8,
    /// The stream.
    pub stream: u64,
    /// The bytes.
    pub bytes: *const u8,
    /// How many.
    pub len: usize,
    /// The exact status number, in the declared numbering.
    pub status_code: u32,
    /// Alignment padding.
    pub _reserved2: u32,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: u64,
}

/// [`WireFramed::flags`]: the status number is present.
pub const FRAMED_HAS_STATUS_CODE: u8 = 1;
/// [`WireFramed::flags`]: the retry-after is present.
pub const FRAMED_HAS_RETRY_AFTER: u8 = 2;
/// [`WireFramed::flags`]: the bytes belong to a text message ([`crate::transport::Framed::text`]).
pub const FRAMED_TEXT: u8 = 4;

/// `send(ctx, bytes, len)`: bytes owed to the far side.
pub type WireSendFn = extern "C-unwind" fn(ctx: *mut c_void, bytes: *const u8, len: usize);
/// `frame(ctx, piece)`: one frame piece for the layer above.
pub type WireFrameFn = extern "C-unwind" fn(ctx: *mut c_void, piece: *const WireFramed);
/// `end(ctx)`: no frame follows on this connection.
pub type WireEndFn = extern "C-unwind" fn(ctx: *mut c_void);
/// `wake_at(ctx, has, monotonic_nanos)`: the instant to call `tick` at (`has` `0` = no deadline).
pub type WireWakeAtFn = extern "C-unwind" fn(ctx: *mut c_void, has: u8, monotonic_nanos: u64);

/// Where a framer puts what a call produced ([`crate::transport::FramerOut`]): host-owned
/// callbacks, valid for the call only. Never unwinds.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireFramerOut {
    /// The host's context, handed back to every callback.
    pub ctx: *mut c_void,
    /// Bytes for the far side.
    pub send: WireSendFn,
    /// A frame piece.
    pub frame: WireFrameFn,
    /// The end of the connection's frames.
    pub end: WireEndFn,
    // ── the host's clock (appended by the clock seam) ──
    /// The host's monotonic clock at this call, in nanoseconds.
    pub now_monotonic_nanos: u64,
    /// The host's wall time at this call, nanoseconds since the Unix epoch.
    pub now_unix_nanos: u64,
    /// The next instant to call `tick` at.
    pub wake_at: WireWakeAtFn,
}

/// Where a framer puts rendered bytes ([`crate::transport::BytesOut`]): a host-owned callback,
/// valid for the call only.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireBytesOut {
    /// The host's context, handed back to the callback.
    pub ctx: *mut c_void,
    /// The bytes, in order.
    pub put: WireSendFn,
}

/// One envelope field: a name and its value.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireField {
    /// The field name (UTF-8).
    pub name: DeclStr,
    /// Its value (any bytes).
    pub value: DeclStr,
}

// ── the carrier's slots: `crate::transport::Carrier`, one per method ─────────────────────────────

slot_table! {
/// A CARRIER's slots, one per [`Carrier`](crate::transport::Carrier) method, named for it.
pub struct CarrierSlots lowers Carrier {
    /// [`Carrier::listen`](crate::transport::Carrier::listen): writes the listener and the bound
    /// address (into `addr_buf`, `out_addr_len` bytes).
    listen: CarrierListenFn = fn(state: *mut c_void, bind: *const u8, bind_len: usize,
        addr_buf: *mut u8, addr_cap: usize, out_addr_len: *mut usize, out_listener: *mut u64);
    /// [`Carrier::poll_accept`](crate::transport::Carrier::poll_accept): writes the connection and the
    /// far end.
    poll_accept: CarrierPollAcceptFn = fn(state: *mut c_void, listener: u64, token: u64,
        peer_buf: *mut u8, peer_cap: usize, out_peer_len: *mut usize, out_conn: *mut u64);
    /// [`Carrier::dial`](crate::transport::Carrier::dial): writes the connection.
    dial: CarrierDialFn = fn(state: *mut c_void, dest: *const WireDest, out_conn: *mut u64);
    /// [`Carrier::poll_read`](crate::transport::Carrier::poll_read): writes how many (`0` = the end).
    poll_read: CarrierPollReadFn = fn(state: *mut c_void, conn: u64, token: u64, buf: *mut u8,
        buf_cap: usize, out_read: *mut usize);
    /// [`Carrier::poll_write`](crate::transport::Carrier::poll_write): writes how many it took.
    poll_write: CarrierPollWriteFn = fn(state: *mut c_void, conn: u64, token: u64, bytes: *const u8,
        len: usize, out_written: *mut usize);
    /// [`Carrier::poll_flush`](crate::transport::Carrier::poll_flush).
    poll_flush: CarrierPollFlushFn = fn(state: *mut c_void, conn: u64, token: u64);
    /// [`Carrier::poll_close`](crate::transport::Carrier::poll_close): `reason` is [`code::close_reason`].
    poll_close: CarrierPollCloseFn = fn(state: *mut c_void, conn: u64, token: u64, reason: u8);
    /// [`Carrier::arrival`](crate::transport::Carrier::arrival): writes the far end and the local port;
    /// [`WireOutcome::Closed`] for an unknown connection.
    arrival: CarrierArrivalFn = fn(state: *mut c_void, conn: u64, peer_buf: *mut u8,
        peer_cap: usize, out_peer_len: *mut usize, out_local_port: *mut u16);
}
}

// ── the framer's slots: `crate::transport::Framer`, one per method ───────────────────────────────

slot_table! {
/// A FRAMER's slots, one per [`Framer`](crate::transport::Framer) method, named for it.
pub struct FramerSlots lowers Framer {
    /// [`Framer::locate`](crate::transport::Framer::locate): writes the authority (into `auth_buf`),
    /// the server name (into `name_buf`; `usize::MAX` in `out_name_len` = none) and the secure flag.
    locate: FramerLocateFn = fn(state: *mut c_void, target: *const u8, target_len: usize,
        auth_buf: *mut u8, auth_cap: usize, out_auth_len: *mut usize, name_buf: *mut u8,
        name_cap: usize, out_name_len: *mut usize, out_secure: *mut u8);
    /// [`Framer::open`](crate::transport::Framer::open): `side` is [`code::side`]; writes the framing
    /// state.
    open: FramerOpenFn = fn(state: *mut c_void, side: u8, target: *const u8, target_len: usize,
        facts: *const WireConnFacts, out: *const WireFramerOut, out_state: *mut u64);
    /// [`Framer::ingest`](crate::transport::Framer::ingest): `end` is `0`/`1`.
    ingest: FramerIngestFn = fn(state: *mut c_void, framing: u64, bytes: *const u8, len: usize,
        end: u8, out: *const WireFramerOut);
    /// [`Framer::emit`](crate::transport::Framer::emit): `end_of_frame` is `0`/`1`.
    emit: FramerEmitFn = fn(state: *mut c_void, framing: u64, stream: u64, bytes: *const u8,
        len: usize, end_of_frame: u8, out: *const WireFramerOut);
    /// [`Framer::encode_envelope`](crate::transport::Framer::encode_envelope): a refusal answers one of
    /// the rendering outcomes (`14..=17`).
    encode_envelope: FramerEncodeEnvelopeFn = fn(state: *mut c_void, fields: *const WireField,
        fields_len: usize, body: *const u8, body_len: usize, out: *const WireBytesOut);
    /// [`Framer::refusal`](crate::transport::Framer::refusal): `has_stream` `0` = the whole connection.
    refusal: FramerRefusalFn = fn(state: *mut c_void, framing: u64, has_stream: u8, stream: u64,
        bytes: *const u8, len: usize, out: *const WireFramerOut);
    /// [`Framer::close`](crate::transport::Framer::close): `reason` is [`code::close_reason`].
    close: FramerCloseFn = fn(state: *mut c_void, framing: u64, reason: u8,
        out: *const WireFramerOut);
    /// [`Framer::detach`](crate::transport::Framer::detach): the unconsumed bytes go to `out`.
    detach: FramerDetachFn = fn(state: *mut c_void, framing: u64, out: *const WireBytesOut);
    /// [`Framer::adopt`](crate::transport::Framer::adopt): writes the new framing state.
    adopt: FramerAdoptFn = fn(state: *mut c_void, side: u8, facts: *const WireConnFacts,
        leftover: *const u8, leftover_len: usize, out: *const WireFramerOut, out_state: *mut u64);
    /// [`Framer::tick`](crate::transport::Framer::tick) (appended by the clock seam; a table ending before
    /// it keeps no deadline).
    tick: FramerTickFn = fn(state: *mut c_void, framing: u64, out: *const WireFramerOut);
}
}

/// INIT: build the transport from `settings`, handed the host's `waker` handle (non-null,
/// `'static`; a framer never calls it), writing its state on `Ok`.
pub type WireInitFn = extern "C-unwind" fn(
    settings: *const WireSettings,
    waker: *const WireWaker,
    out_state: *mut MaybeUninit<OpaqueHandle>,
) -> RawWireOutcome;

/// The `#[repr(C)]` surface a transport exports: the FROZEN [`AbiPreamble`], a sized header, the
/// ROW (every constant the transport declares), `init`, and exactly one role's slots — the carrier's
/// when `composes_over` is empty, the framer's otherwise.
///
/// # Safety / discipline
/// Every string, list and slot table it borrows MUST outlive the decl (the image's own read-only
/// data).
#[repr(C)]
pub struct TransportDecl {
    /// The FROZEN airlock header — checked before anything else is read.
    pub abi: AbiPreamble,
    /// `size_of::<TransportDecl>()` at construction.
    pub size: u32,
    /// [`TRANSPORT_DECL_MAJOR`].
    pub version: u32,
    // ── the row ──
    /// `KEY`.
    pub key: DeclStr,
    /// `COMPOSES_OVER`; the role follows from it.
    pub composes_over: DeclStrList,
    /// `SELECTOR_FORMS`, as [`code::selector_form`] bytes.
    pub selector_forms: DeclByteList,
    /// `EGRESS_SELECTOR_FORMS`, as [`code::selector_form`] bytes.
    pub egress_selector_forms: DeclByteList,
    /// `HANDOFF`'s `from` (NULL = no handoff).
    pub handoff_from: DeclStr,
    /// `HANDOFF`'s `to`.
    pub handoff_to: DeclStr,
    /// `HANDOFF`'s `binding_fact`.
    pub handoff_binding_fact: DeclStr,
    /// `UPGRADES_TO`.
    pub upgrades_to: DeclStrList,
    /// `HANDSHAKE_TRIGGER`'s `frame_kind` (NULL = no trigger).
    pub handshake_frame_kind: DeclStr,
    /// `TRANSPORT_FACTS`.
    pub transport_facts: DeclStrList,
    /// `STATUS_NAMESPACE` (NULL = none).
    pub status_namespace: DeclStr,
    /// `FRAMING` ([`code::framing`]).
    pub framing: u8,
    /// `SESSION` (`0`/`1`).
    pub session: u8,
    /// `SESSION_BOUND` (`0`/`1`).
    pub session_bound: u8,
    /// `DECODES_PAYLOAD` (`0`/`1`).
    pub decodes_payload: u8,
    /// `UNIT0_TRIGGER` ([`code::unit0_trigger`]).
    pub unit0_trigger: u8,
    /// `HANDSHAKE_TRIGGER`'s `max_steps`.
    pub handshake_max_steps: u8,
    /// `STATUS_CLASS` ([`code::status_at`]).
    pub status_at: u8,
    /// Alignment padding.
    pub _reserved: u8,
    // ── construction ──
    /// Build the transport.
    pub init: Option<WireInitFn>,
    // ── the role's slots ──
    /// The carrier's slots (non-null exactly when `composes_over` is empty).
    pub carrier: *const CarrierSlots,
    /// The framer's slots (non-null exactly when `composes_over` is not empty).
    pub framer: *const FramerSlots,
    // ── the claims (appended at minor 33) ──
    /// `CLAIMS`: every scheme the entry answers for, each with its per-scheme row
    /// ([`DeclClaim`]); the first is the entry's own. A decl that ends before this tail makes the
    /// one claim its row above describes.
    pub claims_ptr: *const DeclClaim,
    /// Number of entries in the claims list.
    pub claims_len: usize,
}

/// ONE CLAIM of a transport entry (`crate::transport::Claim`), borrowed in the list
/// [`TransportDecl::claims_ptr`] names: the scheme, and every per-scheme constant the root reads.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclClaim {
    /// The scheme (the row's key).
    pub key: DeclStr,
    /// Its selector forms, as [`code::selector_form`] bytes.
    pub selector_forms: DeclByteList,
    /// Its transport fact keys.
    pub transport_facts: DeclStrList,
    /// Its status numbering (NULL = none).
    pub status_namespace: DeclStr,
    /// It carries sessions (`0`/`1`).
    pub session: u8,
    /// A session on it caches its principal (`0`/`1`).
    pub session_bound: u8,
    /// What opens a session's first unit ([`code::unit0_trigger`]).
    pub unit0_trigger: u8,
    /// Which frame carries its status ([`code::status_at`]).
    pub status_at: u8,
    /// Alignment padding.
    pub _reserved: u32,
}

// SAFETY: a claim borrows the image's own read-only data, mapped for its whole life (the `DeclStr`
// contract).
unsafe impl Send for DeclClaim {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DeclClaim {}

// SAFETY: every raw pointer in the decl points INTO the transport image's own read-only data,
// mapped for the whole life of the loaded transport and never mutated or freed while a decl that
// references it exists; the slots are plain code addresses.
unsafe impl Send for TransportDecl {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for TransportDecl {}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
