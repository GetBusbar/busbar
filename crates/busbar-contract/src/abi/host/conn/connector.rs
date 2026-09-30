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
//! THE CALL SHAPE, shared with the host services (`abi/host/service.rs`). Every service is a
//! [`ServiceFn`]: `svc(ctx, in, out)`, `extern "C"`, answering the mechanism's outcome. `in` leads
//! with a [`ServiceHead`] carrying the service's completion handle; a service that cannot finish answers PENDING, wakes the handle's ticket, and
//! on resume the plugin re-issues the SAME handle and receives the stored result — the host never
//! runs a service twice. A call with `handle.ticket` = `Ticket::NONE` may not pend.
//!
//! [`crate::abi::mechanism::ticket::HostTables::conns`] hands this table to every instance that
//! declared a need.

// THE SHARED CALL SHAPE. In a connector answer, `ServiceOut::value` is the stream a service produced
// (`ESTABLISH`, `REJECT_ENDPOINT`, `SIDE_STREAM`, `CHECKOUT`), `0` otherwise, and `ServiceOut::len`
// the bytes moved (`READ`: `0` = the end; `WRITE`; `RANDOM`).
pub use crate::abi::host::service::{ServiceFn, ServiceHead, ServiceOut};
use crate::abi::mechanism::call::{AbiStr, Blob};

/// [`Need::direction`]: the plugin is reached (it listens).
pub const DIRECTION_INBOUND: u32 = 1;
/// [`Need::direction`]: the plugin reaches out (it dials).
pub const DIRECTION_OUTBOUND: u32 = 2;

/// [`Need::egress_class`]: the connector's default class.
pub const EGRESS_DEFAULT: u32 = 0;
/// [`Need::egress_class`] `provider`: upstreams a plane reaches — the allow-list, and cloud
/// metadata hosts only when allowed.
pub const EGRESS_PROVIDER: u32 = 1;
/// [`Need::egress_class`] `operator-infrastructure`: databases, secret services, directories —
/// private, loopback and plaintext allowed; pinned; cloud metadata hosts refused.
pub const EGRESS_OPERATOR_INFRASTRUCTURE: u32 = 2;
/// [`Need::egress_class`] `open-web`: public destinations over a secure connection only.
pub const EGRESS_OPEN_WEB: u32 = 3;
/// [`Need::egress_class`] `loopback-allowed`: a secure connection, or plaintext to loopback; the
/// node's own ports refused.
pub const EGRESS_LOOPBACK_ALLOWED: u32 = 4;

/// ONE NEED, declared once per direction: which transport claim carries it and which auth style
/// guards it. Opaque bytes to the kernel: the claiming transport validates `details`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Need {
    /// [`DIRECTION_INBOUND`] | [`DIRECTION_OUTBOUND`].
    pub direction: u32,
    /// The egress class the need's destinations are governed under (`EGRESS_*`); `0` = the
    /// connector's default.
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
    /// The far end's RESPONSE head fields the plugin reads (lower-case names), for an outbound
    /// need: the kernel copies ONLY these into the answer's head it hands the plugin; no other
    /// response header ever crosses. Validated at boot: at most [`KEEP_RESPONSE_HEADERS_MAX`]
    /// names, each a lower-case token, none hop-by-hop or credential-bearing ([`NEVER_KEPT`]).
    pub keep_response_headers: *const AbiStr,
    /// How many.
    pub keep_response_headers_len: usize,
}

/// The most response head fields one need may keep.
pub const KEEP_RESPONSE_HEADERS_MAX: usize = 32;

/// The response head fields no need may keep: hop-by-hop fields (the connection's, not the
/// answer's) and fields that carry a credential or a session secret.
pub const NEVER_KEPT: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "authorization",
    "proxy-authorization",
    "proxy-authenticate",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-amz-security-token",
];

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
    /// Read the next piece of the far end's reply to what the plugin sent, with its descriptor.
    pub const READ_REPLY: u32 = 12;
    /// Write one piece of a request on a FRAMED stream, with its descriptor: the framer builds its
    /// own wire head from it. A stream that is not framed refuses it (use [`WRITE`]).
    pub const WRITE_REQUEST: u32 = 13;
}

/// How many services [`ConnectorSlots`] holds.
pub const SERVICES: u32 = 14;

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

/// [`ReplyPiece::kind`]: the terminal piece of a reply with no head — what became of what the
/// plugin sent (delivered or not), in [`ReplyPiece::code`] and [`ReplyPiece::reason`].
pub const REPLY_ACK: u32 = 1;
/// [`ReplyPiece::kind`]: the reply's head: its code, its reason and its fields.
pub const REPLY_HEAD: u32 = 2;
/// [`ReplyPiece::kind`]: body bytes of the reply.
pub const REPLY_BODY: u32 = 3;
/// [`ReplyPiece::kind`]: the terminal piece of a reply that had a head: nothing follows.
pub const REPLY_END: u32 = 4;

/// ONE PIECE OF A REPLY, as [`service::READ_REPLY`] describes it (OWNER ruling: a plugin that
/// sends data sees what became of it, over EVERY transport). Every request's reply ends with exactly
/// ONE terminal piece: [`REPLY_ACK`] (no head: the delivery result, a code and the peer's text), or
/// [`REPLY_END`] after a [`REPLY_HEAD`] and its [`REPLY_BODY`] pieces. A refusal by the egress class
/// is an ack failure carrying the class's text. The spans are ranges of the READ_REPLY buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplyPiece {
    /// `REPLY_*`; `0` = none (a transport that answered no piece breaks the rule).
    pub kind: u32,
    /// The transport's result code: the reply's status, or its own delivery/result code; `0` =
    /// none. On [`REPLY_HEAD`] and [`REPLY_ACK`].
    pub code: u32,
    /// The text the peer sent with the code, exactly as sent; empty when the transport has none.
    pub reason: crate::abi::transport::FrameSpan,
    /// The reply's metadata, ONE field block (`abi::transport::fields`); empty = none. On
    /// [`REPLY_HEAD`].
    pub fields: crate::abi::transport::FrameSpan,
}

/// [`service::READ_REPLY`]'s `in`. The buffer is the plugin's and stays valid until the service
/// completes: the host writes the piece's bytes into it (a head's reason and field block, or body
/// bytes) and its descriptor into `piece`; `ServiceOut::len` is the bytes written.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReplyIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
    /// The buffer the piece's bytes go into.
    pub buf: *mut u8,
    /// Its capacity.
    pub len: usize,
    /// Where the host writes the piece's descriptor.
    pub piece: *mut ReplyPiece,
}

/// [`RequestPiece::kind`]: the request's head — its method, target, fields and timeout.
pub const REQUEST_HEAD: u32 = 1;
/// [`RequestPiece::kind`]: body bytes of the request.
pub const REQUEST_BODY: u32 = 2;
/// [`RequestPiece::kind`]: the request is complete; nothing follows.
pub const REQUEST_END: u32 = 3;

/// ONE PIECE OF A REQUEST on a framed stream, as [`service::WRITE_REQUEST`] describes it: the mirror
/// of [`ReplyPiece`]. A request is one [`REQUEST_HEAD`], its [`REQUEST_BODY`] pieces and one
/// [`REQUEST_END`]. The spans are ranges of the WRITE_REQUEST buffer; the words are the approved
/// per-stream head slots (`method`, `target`), and the fields ONE field block
/// (`abi::transport::fields`, no pseudo-field).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestPiece {
    /// `REQUEST_*`.
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The method. On [`REQUEST_HEAD`].
    pub method: crate::abi::transport::FrameSpan,
    /// The target. On [`REQUEST_HEAD`].
    pub target: crate::abi::transport::FrameSpan,
    /// The request's fields, one field block; empty = none. On [`REQUEST_HEAD`].
    pub fields: crate::abi::transport::FrameSpan,
    /// How long the request may take, milliseconds; `0` = the op's deadline. The host clamps a
    /// larger value to the op's deadline class. On [`REQUEST_HEAD`].
    pub timeout_ms: u64,
}

/// [`service::WRITE_REQUEST`]'s `in`. The buffer and the descriptor are the plugin's and stay
/// valid until the service completes; `ServiceOut::len` is the bytes the host took (a body piece
/// may be taken in part).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RequestIn {
    /// The head.
    pub head: ServiceHead,
    /// The stream.
    pub stream: u64,
    /// The piece's bytes: a head's method, target and field block, or body bytes.
    pub buf: *const u8,
    /// Their length.
    pub len: usize,
    /// The piece's descriptor.
    pub piece: *const RequestPiece,
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
    /// [`service::READ_REPLY`], in [`ReplyIn`].
    pub read_reply: Option<ServiceFn>,
    /// [`service::WRITE_REQUEST`], in [`RequestIn`].
    pub write_request: Option<ServiceFn>,
}
