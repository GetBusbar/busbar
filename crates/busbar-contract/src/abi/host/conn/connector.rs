// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST CONNECTOR, mechanism-shaped (`BUSBAR-1.6.0.md` THE DESIGN, the connections section):
//! the ONE connector every plugin of every kind reaches its connections through, whatever wire it
//! speaks over them. It lives in `abi/host/`, not `abi/transport/`: it is a HOST table any kind
//! calls (a store, an auth, a secret, an export or a plane plugin), while `abi/transport/` is the
//! table a transport PLUGIN implements for the connector to build connections from.
//!
//! A NEED. Every plugin states what it needs as `(transport, auth)` PER DIRECTION ([`Need`]); the
//! kernel instantiates it through the connector and never learns the plugin's name or kind.
//!
//! THE RULES THE TABLE CARRIES:
//!
//! * **The host dials.** The host owns the endpoint list, name resolution to many addresses, their
//!   order, the connect timeout and keepalive. After its handshake a plugin may reject the endpoint
//!   it landed on ([`service::REJECT_ENDPOINT`]); the connector closes it and tries the next.
//! * **Every connection is full-duplex.** A plugin may issue [`service::WRITE`] while a [`service::READ`] on
//!   the same stream is pending; each carries its own completion handle.
//! * **Mid-stream security upgrade is ONE generic service** ([`service::UPGRADE_SECURE`]), for any
//!   wire that negotiates connection security after connecting in the clear. Connection security
//!   stays core-only: the plugin sends and reads its own negotiation bytes, then asks the host to
//!   upgrade. After it, [`StreamFacts::peer_cert_hash`] exposes the far end's certificate hash (the
//!   channel-binding input).
//! * **Establishment is off the request workers.** Dial, security and the plugin's own
//!   authentication exchange run on the host's connector lane ([`service::ESTABLISH`], deadline
//!   class `Connection`); only an established stream's traffic is request-path.
//! * **One op, one connection.** A request op checks ONE connection out of the host's per-instance
//!   pool ([`service::CHECKOUT`]) and holds it across every PENDING until READY, FAILED or cancel,
//!   then checks it back in ([`service::CHECKIN`]). Pool policy (min/max, ping-on-reuse,
//!   reset-on-return, a local socket for a local endpoint, connect attributes) is HOST config; the
//!   reset itself is the plugin kind's own op. A write-behind op keeps its connection across reload.
//! * **Cancel may need a second stream** to the same endpoint ([`service::SIDE_STREAM`]).
//! * **Host services:** random bytes ([`service::RANDOM`]: nonces, key-exchange seeds) and the
//!   process identity (OS user, pid, program name; [`service::IDENTITY`]).
//! * **The far end's notices and warnings** travel as the metrics-and-diagnostics envelope's `Diag`s, severity `0`/`1`;
//!   there is no other channel.
//!
//! THE CALL SHAPE. Every service is a [`ServiceFn`]: `svc(ctx, in, out)`, `extern "C"`, answering
//! the mechanism's [`RawOutcome`]. `in` leads with a [`ServiceHead`] carrying the service's
//! [`CompletionHandle`]; a service that cannot finish answers PENDING, wakes the handle's ticket, and
//! on resume the plugin re-issues the SAME handle and receives the stored result — the host never
//! runs a service twice. A call with `handle.ticket` = `Ticket::NONE` may not pend.
//!
//! [`crate::abi::mechanism::ticket::HostTables::conns`] hands this table to every instance that
//! declared a need.

use std::os::raw::c_void;

use crate::abi::mechanism::call::{AbiStr, Blob, RawOutcome};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx};

/// [`Need::direction`]: the plugin is reached (it listens).
pub const DIRECTION_INBOUND: u32 = 1;
/// [`Need::direction`]: the plugin reaches out (it dials).
pub const DIRECTION_OUTBOUND: u32 = 2;

/// ONE NEED, declared once per direction: which transport claim carries it and which auth style
/// guards it. Opaque bytes to the kernel: the claiming transport validates `details`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Need {
    /// [`DIRECTION_INBOUND`] | [`DIRECTION_OUTBOUND`].
    pub direction: u32,
    /// The egress class the need's destinations are governed under; `0` = the connector's default.
    pub egress_class: u32,
    /// The transport claim (a scheme some transport entry claims).
    pub transport: AbiStr,
    /// The auth style (an open string resolved against the styles auth plugins declare); absent =
    /// none.
    pub auth: AbiStr,
    /// Where the target comes from (a config path the host reads); absent = the plugin names it.
    pub target_from: AbiStr,
    /// Where the trust anchors come from; absent = the host's default.
    pub trust_from: AbiStr,
    /// The need's details, validated only by the claiming transport.
    pub details: Blob,
}

/// The index of each connector service in [`ConnectorSlots`], in table order.
pub mod service {
    /// Establish a stream for a need on the connector lane.
    pub const ESTABLISH: u32 = 0;
    /// Reject the endpoint a stream landed on; the connector tries the next.
    pub const REJECT_ENDPOINT: u32 = 1;
    /// A second stream to the endpoint a stream landed on.
    pub const SIDE_STREAM: u32 = 2;
    /// Read.
    pub const READ: u32 = 3;
    /// Write.
    pub const WRITE: u32 = 4;
    /// Upgrade the stream to connection security, mid-stream.
    pub const UPGRADE_SECURE: u32 = 5;
    /// The stream's facts.
    pub const FACTS: u32 = 6;
    /// Check a pooled stream out for one op.
    pub const CHECKOUT: u32 = 7;
    /// Check it back in.
    pub const CHECKIN: u32 = 8;
    /// Close a stream.
    pub const CLOSE: u32 = 9;
    /// Random bytes.
    pub const RANDOM: u32 = 10;
    /// The process identity.
    pub const IDENTITY: u32 = 11;
}

/// How many services [`ConnectorSlots`] holds.
pub const SERVICES: u32 = 12;

/// A connector service: `svc(ctx, in, out)`. `extern "C"`: a panic escaping it aborts.
pub type ServiceFn =
    extern "C" fn(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome;

/// The head of every service `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServiceHead {
    /// `size_of` the whole `in`.
    pub size: u32,
    /// The [`service`] index.
    pub op: u32,
    /// The completion handle; on resume the plugin re-issues the same one.
    pub handle: CompletionHandle,
}

/// Every service's `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServiceOut {
    /// `size_of::<ServiceOut>()`.
    pub size: u32,
    /// The outcome, mirrored from the return value (the return value is authoritative).
    pub outcome: RawOutcome,
    /// Alignment padding.
    pub _reserved: [u8; 3],
    /// The stream a service produced ([`service::ESTABLISH`], [`service::REJECT_ENDPOINT`],
    /// [`service::SIDE_STREAM`], [`service::CHECKOUT`]); `0` otherwise.
    pub value: u64,
    /// Bytes moved ([`service::READ`]: `0` = the end; [`service::WRITE`]; [`service::RANDOM`]).
    pub len: u64,
    /// For FAILED/REFUSED: the reason; never secret material.
    pub error: AbiStr,
}

/// [`service::ESTABLISH`]'s `in`: dial the need's endpoints in the host's order, apply connection
/// security when the need asks for it, and answer the stream. The plugin's own authentication
/// exchange that follows runs on the same connector lane.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EstablishIn {
    /// The head.
    pub head: ServiceHead,
    /// The need, by its index in the plugin's declared needs.
    pub need: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The target; absent = the need's `target_from`.
    pub target: AbiStr,
}

/// The `in` of [`service::REJECT_ENDPOINT`], [`service::SIDE_STREAM`] and [`service::CLOSE`].
/// `REJECT_ENDPOINT` answers the stream on the next endpoint, or FAILED when none is left.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StreamIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
}

/// [`service::READ`]'s and [`service::WRITE`]'s `in`. The buffer is the plugin's and stays valid
/// until the service completes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
    /// The bytes to write, or the buffer to read into.
    pub buf: *mut u8,
    /// Their length, or the buffer's capacity.
    pub len: usize,
}

/// [`service::UPGRADE_SECURE`]'s `in`: the plugin has exchanged its own negotiation bytes; the host
/// now runs the security handshake on the stream.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UpgradeIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
    /// The name to offer the far end; absent = the endpoint's host name.
    pub offered_name: AbiStr,
    /// The trust anchors, by the need's `trust_from` reference; absent = the need's.
    pub trust: AbiStr,
}

/// [`service::FACTS`]'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FactsIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
    /// Where the host writes the facts; the strings stay valid until the stream closes.
    pub facts: *mut StreamFacts,
}

/// What a stream is, as facts: never key or certificate material.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StreamFacts {
    /// `size_of::<StreamFacts>()`.
    pub size: u32,
    /// `1` = connection security is established.
    pub secure: u32,
    /// The endpoint the stream landed on.
    pub endpoint: AbiStr,
    /// The protocol agreed in the security handshake; absent = none.
    pub agreed_protocol: AbiStr,
    /// The hash of the far end's certificate (the channel-binding input); absent = not secure.
    pub peer_cert_hash: AbiStr,
}

/// [`service::CHECKOUT`]'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckoutIn {
    /// The head.
    pub head: ServiceHead,
    /// The need whose pool to draw from.
    pub need: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`CheckinIn::disposition`]: return the stream to the pool as is.
pub const CHECKIN_REUSE: u32 = 0;
/// [`CheckinIn::disposition`]: return it after the plugin kind's reset op.
pub const CHECKIN_RESET: u32 = 1;
/// [`CheckinIn::disposition`]: close it; it is not fit for reuse.
pub const CHECKIN_DROP: u32 = 2;

/// [`service::CHECKIN`]'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckinIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
    /// `CHECKIN_*`.
    pub disposition: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// [`service::RANDOM`]'s `in`: fill the buffer. Never pends.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RandomIn {
    /// The head.
    pub head: ServiceHead,
    /// The buffer.
    pub buf: *mut u8,
    /// Its length.
    pub len: usize,
}

/// The process identity a plugin may present to a far end.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessIdentity {
    /// `size_of::<ProcessIdentity>()`.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The process id.
    pub pid: u64,
    /// The OS user.
    pub os_user: AbiStr,
    /// The program name.
    pub program: AbiStr,
}

/// [`service::IDENTITY`]'s `in`. Never pends; the strings are valid for the process's life.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentityIn {
    /// The head.
    pub head: ServiceHead,
    /// Where the host writes the identity.
    pub identity: *mut ProcessIdentity,
}

/// THE CONNECTOR TABLE: one [`ServiceFn`] per [`service`], in index order. A NULL slot is a
/// service this host does not offer, and a plugin that needs it refuses to open.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnectorSlots {
    /// `size_of::<ConnectorSlots>()`.
    pub size: u32,
    /// [`SERVICES`].
    pub slots: u32,
    /// [`service::ESTABLISH`], in [`EstablishIn`].
    pub establish: Option<ServiceFn>,
    /// [`service::REJECT_ENDPOINT`], in [`StreamIn`].
    pub reject_endpoint: Option<ServiceFn>,
    /// [`service::SIDE_STREAM`], in [`StreamIn`].
    pub side_stream: Option<ServiceFn>,
    /// [`service::READ`], in [`IoIn`].
    pub read: Option<ServiceFn>,
    /// [`service::WRITE`], in [`IoIn`].
    pub write: Option<ServiceFn>,
    /// [`service::UPGRADE_SECURE`], in [`UpgradeIn`].
    pub upgrade_secure: Option<ServiceFn>,
    /// [`service::FACTS`], in [`FactsIn`].
    pub facts: Option<ServiceFn>,
    /// [`service::CHECKOUT`], in [`CheckoutIn`].
    pub checkout: Option<ServiceFn>,
    /// [`service::CHECKIN`], in [`CheckinIn`].
    pub checkin: Option<ServiceFn>,
    /// [`service::CLOSE`], in [`StreamIn`].
    pub close: Option<ServiceFn>,
    /// [`service::RANDOM`], in [`RandomIn`].
    pub random: Option<ServiceFn>,
    /// [`service::IDENTITY`], in [`IdentityIn`].
    pub identity: Option<ServiceFn>,
}
