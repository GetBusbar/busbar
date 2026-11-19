// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport port (IF §11.3): the frozen trait the connector drives, implemented over the kind's proxy by
//! `adapters::transport::TransportAdapter`.

use busbar_plugin_abi::records::Records;

use crate::PortError;

/// One live transport session (a connection) and its output state.
pub struct TransportSession {
    pub s: crate::KindSession<busbar_ffi::kind::Transport>,
    /// The session's one validator of the output model: what the engine asked of each stream and
    /// what the session has written for it (rules L1 to L7 and L9).
    pub wire: busbar_plugin_abi::wire::Wire,
}

impl TransportSession {
    pub fn instance(&self) -> &std::sync::Arc<busbar_plugin_abi::host_side::driver::Instance> {
        self.s.instance()
    }
}

/// The byte-carrying pieces of one `emit`, in the contract's fixed order. `None`: the piece is not in
/// this call. `end` is `Some(&[])` when E_END is in the set (END's entry is empty).
#[derive(Clone, Copy, Default)]
pub struct EmitParts<'a> {
    pub head: Option<&'a [u8]>,
    pub body: Option<&'a [u8]>,
    pub trailers: Option<&'a [u8]>,
    pub end: Option<&'a [u8]>,
}

pub enum TransportOut<'o> {
    /// Write these bytes; they belong to `stream` (0 = the connection). `payload`: a body byte the
    /// engine gave for that stream, one for one; else control (heads, framing, trailers, settings).
    WirePart {
        stream: u64,
        payload: bool,
        bytes: &'o [u8],
    },
    /// Write bytes `offset..offset + len` of the engine's sealed value `slot` of `stream` here, in
    /// order with the parts around it. The transport never held the value.
    WireSealed {
        stream: u64,
        slot: u32,
        offset: u32,
        len: u32,
    },
    /// Nothing more will name `stream`. `how` = END_FLUSH, END_SHUTDOWN or END_FAILED; `arg` =
    /// END_NO_BODY or 0 on a successful end, an opaque protocol diagnostic on END_FAILED.
    WireEnd {
        stream: u64,
        how: u32,
        arg: u32,
    },
    /// `begin`'s statement of what the session is: whether it carries several streams at once and, if
    /// so, the bytes of inbound body the engine can be made to hold for one stream and for the
    /// connection. The engine never compares a protocol name to learn any of this.
    Session {
        multiplex: bool,
        stream_window: u32,
        conn_window: u32,
    },
    /// The answer of an `emit` that asked a dialled session to open a stream when it can carry no
    /// more now: nothing was taken; the engine uses another connection or waits.
    StreamBusy,
    /// The session will open no further stream; the streams it carries go on.
    NoNewStreams,
    Close {
        abort: bool,
    },
    WakeAt(u64),
    Upgrade {
        protocol: &'o str,
    },
    Leftover(&'o [u8]),
    StreamHead {
        stream: u64,
        end_stream: bool,
        head: Records<'o>,
    },
    StreamBody {
        stream: u64,
        flags: u32,
        bytes: &'o [u8],
    },
    StreamEnd(u64),
    /// `not_processed`: the far end guarantees it did not act on the stream, so the engine may send
    /// the request once more on another connection, recorded, never silently.
    StreamReset {
        stream: u64,
        code: u32,
        not_processed: bool,
    },
    StreamTrailers {
        stream: u64,
        pairs: Records<'o>,
    },
    StreamOpened(u64),
    StreamFull(u64),
    StreamWritable(u64),
    SendTo {
        path: u32,
        secured: bool,
        bytes: &'o [u8],
    },
    /// SECURE: run DTLS on `path` and accept only a far end whose certificate digest under `alg` (FP_*) is
    /// `peer_fingerprint` (§8.7); the connector enforces it before EV_KEYING.
    Secure {
        path: u32,
        role: u32,
        alg: u32,
        peer_fingerprint: &'o [u8],
    },
    Rendezvous(&'o str),
    /// Round 6 (§8.7): ICE credentials for this session; remote ones empty until known. The connector registers
    /// `local_ufrag` as this session's demux key on its media port and verifies checks with `local_pwd`.
    IceTerms {
        controlling: bool,
        local_ufrag: &'o str,
        local_pwd: &'o [u8],
        remote_ufrag: &'o str,
        remote_pwd: &'o [u8],
    },
    /// One far-end candidate line; the connector judges its address with the guard before any byte is sent.
    IceCandidate(&'o str),
    /// PATH_BIND (from = None) / PATH_REBIND (from = Some(old)).
    PathBind {
        path: u32,
        from: Option<u32>,
    },
}

/// local_fingerprint: ROLE_DATAGRAM only (the connector's host DTLS certificate, SDP form), else "".
pub struct ConnIn<'a> {
    pub role: u32,
    pub flags: u32,
    pub alpn: &'a str,
    pub sni: &'a str,
    pub peer: &'a str,
    pub local: &'a str,
    pub tls_peer_cert: &'a [u8],
    pub leftover: &'a [u8],
    pub head: &'a [u8],
    pub local_fingerprint: &'a str,
    pub mono_ns: u64,
}

pub trait TransportPort: Send + Sync + 'static {
    /// Round 9: the cached `offer` answer for `role` (ROLE_SERVER or ROLE_CLIENT; any other role, or a side the
    /// instance does not declare, is `&[]`). The connector's listener uses ROLE_SERVER for this instance's
    /// listeners, its dial uses ROLE_CLIENT for this instance's upstreams; never one list for both.
    fn alpn(&self, role: u32) -> &[Box<str>];
    /// Round 22: the cached ROLE_CLIENT `offer` PAIR* (empty for ROLE_SERVER and for a framer that states none).
    /// K8/C1 merge each line the upstream head lacks before auth `outbound` (§8.7 `offer`).
    fn defaults(&self, role: u32) -> &[(Box<str>, Box<str>)];
    fn protocols(&self) -> &[Box<str>];
    /// Validated initial stream-listener configuration slots from D_LISTENER_SLOT; never upgrade protocols.
    fn listener_slots(&self) -> &[Box<str>];
    fn facts(&self) -> u64;
    fn begin(
        &self,
        c: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError>;
    fn ingest(
        &self,
        s: &mut TransportSession,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
    /// piece = E_*; E_REFUSE (round 9) is how core ends a stream refused when no plane renders it (§8.7):
    /// arg = status | E_REFUSE_HEAD_SENT?, bytes = core text. K8/C1 call it wherever 1.5.5 called the framer's
    /// `refuse` (connector framed_stream.rs:199-209, 233-245). Round 16: E_CLOSE (stream 0, arg = CR_*) wherever
    /// 1.5.5 called the framer's `finish` (drain, revoke, timeout, capacity); the sink should then see only
    /// Write/SendTo and at most one Close. StreamFull is valid only from `emit` and only for this call's stream (or
    /// the stream it opened); StreamWritable only from ingest, timer, datagram and event (§8.7). The adapter only
    /// decodes; the connector's session task, which knows which call it made, checks these rules and treats a
    /// violation as FAULT BadRecords (quarantine + audit `plugin_fault`), so the check is charged to C1.
    /// The one output call. `pieces` = the contract's piece set (E_HEAD | E_BODY | E_TRAILERS | E_END in
    /// one call, or E_RESET, E_REFUSE, E_CLOSE, E_CONSUMED); `credit` = the bytes of credit given with
    /// E_CONSUMED, else 0; `parts` = one entry per byte-carrying piece in the set.
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        s: &mut TransportSession,
        stream: u64,
        pieces: u32,
        arg: u32,
        credit: u64,
        parts: EmitParts<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
    fn timer(
        &self,
        s: &mut TransportSession,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
    fn datagram(
        &self,
        s: &mut TransportSession,
        path: u32,
        secured: bool,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
    /// ev = EV_PATH (path, flags, addr), EV_KEYING (path, profile, material), EV_RENDEZVOUS (description text);
    /// the adapter encodes with transport::encode_path / encode_keying (§8.8).
    fn event(
        &self,
        s: &mut TransportSession,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
}

pub enum TransportEvent<'a> {
    Path {
        path: u32,
        flags: u32,
        addr: &'a str,
    },
    Keying {
        path: u32,
        profile: u32,
        material: &'a [u8],
    },
    Rendezvous(&'a str),
}
