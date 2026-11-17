// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind: the `Transport` trait and the `transport` module (IF §8, §10.4), one `kind!` block (W1-A4b).

crate::kind! {
    /// A transport is a framer. Core owns listeners, sockets (TCP and UDP), child stdio pipes, TLS, DTLS,
    /// ALPN/SNI, accept and dial. The transport turns bytes or datagrams into streams and streams into bytes.
    /// Upgrades name a protocol, never a plugin. Per-connection state is `Session` (shim slots, §6.5).
    pub trait Transport: kind = 7, abi = 1, session {
        views {
        /// role SERVER (accepted), CLIENT (core dialled upstream) or DATAGRAM (core bound a UDP port for
        /// this session; local = the bound address, peer empty). flags (DATAGRAM): CONN_ACCEPT = core will
        /// hand this session the far end's offer (EV_RENDEZVOUS) and wants the local answer; CONN_DIAL = this
        /// session dials: `begin` answers RENDEZVOUS (the local offer) and the far end's answer arrives later
        /// as EV_RENDEZVOUS. leftover = bytes adopted from an UPGRADE. local_fingerprint (ROLE_DATAGRAM only,
        /// else empty) = the fingerprint of the host DTLS certificate core's connector will present on every
        /// path of this session, in SDP `a=fingerprint` value form (`sha-256 AB:CD:…`); the transport writes it
        /// into its offer or answer and refuses `begin` (R_CONFIG) when it is empty. Core owns the certificate.
        /// Round 13: head (ROLE_SERVER with CONN_UPGRADED, or round 27 ROLE_DATAGRAM with CONN_DIAL; else
        /// empty) = nested records. CONN_UPGRADED: the upgrade request's H_METHOD, H_PATH, H_AUTHORITY, PAIR*,
        /// then H_STATUS(101) and the plane's RESPOND PAIR* (e.g. `sec-websocket-protocol`); the transport
        /// validates the handshake headers, writes the 101 response with them (its own `sec-websocket-accept`)
        /// as its `begin` answer, and serves stream 1. CONN_DIAL: the opening core resolved, PAIR* of `media`
        /// = <kind> (one per media line) then `channel` = <label> (one per data channel), in order; the
        /// transport offers exactly those lines, in that order, and refuses `begin` (R_CONFIG) when it is empty.
        pub struct ConnInfo<'a> {
            pub role: u32,
            pub flags: u32,
            pub alpn: crate::types::Str<'a>,
            pub sni: crate::types::Str<'a>,
            pub peer: crate::types::Str<'a>,
            pub local: crate::types::Str<'a>,
            pub tls_peer_cert: crate::types::Bytes<'a>,
            pub leftover: crate::types::Bytes<'a>,
            pub head: crate::types::Bytes<'a>,
            pub local_fingerprint: crate::types::Str<'a>,
            pub mono_ns: u64,
        }
        }
        pods {
        pub struct CloseRec {
            pub how: u32,
            pub _r: u32,
        }
        pub struct WakeAt {
            pub mono_ns: u64,
        }
        /// Tail = nested head records (H_METHOD/H_PATH/H_AUTHORITY/H_SCHEME or H_STATUS, PAIR*).
        pub struct StreamHead {
            pub stream: u64,
            pub flags: u32,
            pub _r: u32,
        }
        /// STREAM_BODY. Tail = body bytes. flags = 0 for a byte stream (HTTP bodies, gRPC frames); for a
        /// message stream (WebSocket, WebRTC data channel) MSG_TEXT or MSG_BINARY on every fragment of a
        /// message, plus MSG_FIN on its last fragment. Same bit values as plane MSG_* (core maps them 1:1).
        pub struct StreamBody {
            pub stream: u64,
            pub flags: u32,
            pub _r: u32,
        }
        pub struct StreamReset {
            pub stream: u64,
            pub code: u32,
            pub _r: u32,
        }
        /// Round 16, STREAM_FULL / STREAM_WRITABLE (per-stream outbound backpressure; today's
        /// YIELD_STREAM_FULL / PIECE_WRITABLE, busbar-contract abi/transport/mod.rs:73-81, 586-620).
        pub struct StreamFlow {
            pub stream: u64,
        }
        /// Ordered protocol output. Tail is nonempty serialized bytes; stream 0 is connection
        /// CONTROL only. The serializer supplies identity, never the call that drained its output.
        pub struct WirePart {
            pub stream: u64,
            pub class: u32,
            pub _r: u32,
        }
        /// A response's serialization fence. No tail. It is not a delivery receipt: the host joins
        /// actual carrier progress, checked flush/shutdown and producer/input retirement separately.
        pub struct WireEnd {
            pub stream: u64,
            pub requirement: u32,
            pub _r: u32,
        }
        /// Outbound response failure, distinct from inbound STREAM_RESET. Code is an opaque
        /// protocol diagnostic, never a host stop reason or billing disposition. No tail.
        pub struct ResponseAbort {
            pub stream: u64,
            pub code: u32,
            pub _r: u32,
        }
        /// Datagram out. Tail = payload. flags = DG_SECURED (core's DTLS layer for that path seals it).
        pub struct SendTo {
            pub path: u32,
            pub flags: u32,
        }
        /// Event EV_PATH. Tail = remote address text (`ip:port`). flags = PATH_*.
        pub struct PathRec {
            pub path: u32,
            pub flags: u32,
        }
        /// Event EV_KEYING. Tail = exported keying material (zeroized by core with the buffer, I11).
        pub struct KeyingRec {
            pub path: u32,
            pub profile: u32,
        }
        /// Answer SECURE: ask core to run DTLS on `path` (role = DTLS_CLIENT/DTLS_SERVER) and to accept only a
        /// far end whose certificate digest under `alg` (FP_*) equals the tail (digest_len bytes: the
        /// far end's SDP `a=fingerprint`, which the transport parsed from the rendezvous description). Core's
        /// connector compares after the handshake and before keying: a mismatch never yields EV_KEYING, ends the
        /// path with EV_PATH(PATH_REJECTED) and is audited `dtls_fingerprint_mismatch`. digest_len 0 = FAULT.
        pub struct SecureRec {
            pub path: u32,
            pub role: u32,
            pub alg: u32,
            pub digest_len: u32,
        }
        /// Answer ICE_TERMS (round 6): the session's ICE credentials, which core's connector uses to demux
        /// and authenticate connectivity checks itself. Tail = exactly four nested TEXT records, in order:
        /// local ufrag, local pwd, remote ufrag, remote pwd (remote ones empty until the far end's description
        /// is known; a later ICE_TERMS replaces the earlier one). flags = ICE_CONTROLLING?. The local ufrag is
        /// the demux key on a shared media port: core refuses (PATH_REJECTED on every check) a ufrag already
        /// live on that port, so concurrent accepted calls never collide.
        pub struct IceTermsRec {
            pub flags: u32,
            pub _r: u32,
        }
        /// Answer PATH_BIND / PATH_REBIND: ask core to make `path` the one path sealed (DG_SECURED) and sent
        /// to for this session (PATH_BIND: from = 0; PATH_REBIND: move the binding from `from` to `path`,
        /// e.g. after an ICE restart or a consent change). Core answers with EV_PATH(PATH_BOUND) on `path`,
        /// or EV_PATH(PATH_REJECTED) when the path is not verified or not admitted by egress.
        pub struct PathReqRec {
            pub path: u32,
            pub from: u32,
        }
        }
        tags {
            WRITE = 0x0100;
            CLOSE = 0x0101;
            WAKE_AT = 0x0102;
            /// UPGRADE (protocol text, e.g. "websocket") then LEFTOVER bytes; core hands the conn to that protocol's transport.
            /// Round 13: valid only as the answer to `emit(E_HEAD)` whose head is H_STATUS(101) on a ROUTE_UPGRADE
            /// stream (§12.27); the transport writes nothing for that head. Anywhere else: FAULT BadRecords.
            UPGRADE = 0x0103;
            LEFTOVER = 0x0104;
            STREAM_HEAD = 0x0105;
            STREAM_BODY = 0x0106;
            STREAM_END = 0x0107;
            STREAM_RESET = 0x0108;
            STREAM_TRAILERS = 0x0109;
            STREAM_OPENED = 0x010A;
            /// flow control: stop / restart reading the conn.
            PAUSE = 0x010B;
            RESUME = 0x010C;
            /// datagram answers: SEND_TO (SendTo + payload), SECURE (SecureRec), RENDEZVOUS (text: the local
            /// session description; core alone decides where it goes — to the plane session whose RENDEZVOUS or
            /// UP_NEW(CARRIER_RTC) intent created this session, §12.13. The transport never learns who that is).
            SEND_TO = 0x010D;
            SECURE = 0x010E;
            RENDEZVOUS = 0x010F;
            /// datagram answers, round 6: ICE_TERMS (IceTermsRec + 4 × TEXT); ICE_CANDIDATE (text: one remote
            /// candidate line, RFC 8839 `candidate:` attribute value, parsed by the transport from the far end's
            /// description; core judges each against egress before any byte goes to it); PATH_BIND / PATH_REBIND
            /// (PathReqRec).
            ICE_TERMS = 0x0110;
            ICE_CANDIDATE = 0x0111;
            PATH_BIND = 0x0112;
            PATH_REBIND = 0x0113;
            /// Round 9, answer of `offer`: one ALPN protocol id (text, 1..=255 bytes), most preferred first.
            /// Round 22: for ROLE_CLIENT the ALPN* may be followed by generic PAIR* (the framer's default lines).
            ALPN = 0x0114;
            /// Round 16, per-stream outbound backpressure (StreamFlow). STREAM_FULL: answer of `emit` only, for
            /// that emit's stream (the opened stream for an E_HEAD that answered STREAM_OPENED): the piece was taken
            /// whole and the framer's queue for the stream reached its high-water mark (an h2/gRPC stream's flow
            /// window is exhausted, a data channel's buffered amount is over its mark). Core then emits **nothing
            /// more on that stream** (no E_BODY, E_TRAILERS or E_END; E_RESET and E_REFUSE still go, and end it)
            /// and stops pulling whatever feeds it, leaving the conn's other streams flowing, until STREAM_WRITABLE
            /// for it or the stream ends; past `limits.stream_stall_ms` (§12.22, default 60,000) core ends it with
            /// `emit(E_RESET, RESET_STALLED)` and ends the feeding exchange as for a peer reset. STREAM_WRITABLE:
            /// answer of `ingest`, `timer`, `datagram` or `event` (the queue drained below the low-water mark: a
            /// WINDOW_UPDATE arrived, the buffered amount fell); for a stream not held, ignored. Either in any other
            /// answer, or STREAM_FULL for another stream, is FAULT BadRecords. A framer's queue is thereby bounded by
            /// its high-water mark plus one piece (core's piece size cap), and core holds at most the one piece in
            /// hand per held stream, so neither side buffers without bound. Byte-stream wires (HTTP/1.1, WebSocket)
            /// never need it: core owns the socket and stops calling `emit` while the socket is not writable.
            STREAM_FULL = 0x0115;
            STREAM_WRITABLE = 0x0116;
            /// R6b: an EV_PATH `event` argument is exactly one record of this tag, body = PathRec + remote address text.
            EVENT_PATH = 0x0117;
            /// R6b: an EV_KEYING `event` argument is exactly one record of this tag, body = KeyingRec + material.
            EVENT_KEYING = 0x0118;
            /// WirePart + nonempty bytes, with exact serializer-owned stream/class attribution.
            WIRE_PART = 0x0119;
            /// WireEnd: no later response bytes may name this stream; audited release precedes its ending.
            WIRE_END = 0x011A;
            /// ResponseAbort: a protocol producer failed the outbound response, even after its input ended.
            RESPONSE_ABORT = 0x011B;
            /// StreamFlow: no serializer source can produce future bytes for this response. Distinct
            /// from actual delivery; retain its binding until E_DELIVERY_SETTLED and input retirement.
            RESPONSE_QUIESCENT = 0x011C;
            /// describe: D_PROTOCOL (text protocol name for UPGRADE targets, e.g. "websocket", "grpc").
            /// Round 9: 0x0180 (round 8's D_ALPN) is retired; the ALPN offer is per instance and per side (`offer`).
            D_PROTOCOL = 0x0181;
            /// An existing core configuration slot this instance can serve as an initial stream listener.
            /// Repeatable text: at most 64 distinct, case-sensitive 1..=128-byte ASCII alphanumeric, `_` or
            /// `-` names. Requires FB_SERVER and forbids FB_DATAGRAM. Unknown slots remain inert; declaring a
            /// slot creates no listener or network permission. Core requires exactly one supplier per needed
            /// slot, uses that instance's server ALPN and retains the generation through every connection.
            /// D_PROTOCOL remains upgrade-only; neither ALPN nor image identity selects an initial supplier.
            D_LISTENER_SLOT = 0x0182;
        }
        consts {
            REQUIRED: u64 = 0b1;
            ROLE_SERVER: u32 = 1;
            ROLE_CLIENT: u32 = 2;
            ROLE_DATAGRAM: u32 = 3;
        /// Round 13: CONN_UPGRADED (ROLE_SERVER) = core adopted this conn from an UPGRADE; `head` is set.
            CONN_ACCEPT: u32 = 1;
            CONN_DIAL: u32 = 2;
            CONN_UPGRADED: u32 = 4;
            CLOSE_GRACEFUL: u32 = 1;
            CLOSE_ABORT: u32 = 2;
            SH_END_STREAM: u32 = 1;
        /// message flags of STREAM_BODY and of emit(E_BODY)'s arg.
            MSG_TEXT: u32 = 1;
            MSG_BINARY: u32 = 2;
            MSG_FIN: u32 = 4;
        /// emit pieces: HEAD (bytes = head records; round 22: on ROLE_CLIENT, ending in core-written
        /// H_BUDGET_NS? then H_BODY_LEN?, §3; arg = SH_END_STREAM?), BODY (arg = MSG_* flags, 0 for a
        /// byte stream), END, TRAILERS (bytes = PAIR*), RESET (arg = code), and (round 9, ABI-MIN-3 §4.6's
        /// REFUSE piece restored) REFUSE: core ends `stream` refused with no plane able to render it (plane
        /// FAULT or quarantine mid-stream, a core limit or deadline cut, the no-`render` fallback). arg =
        /// neutral status 400..=599 in bits 0..=15, plus E_REFUSE_HEAD_SENT when core already emitted E_HEAD on
        /// this stream; bytes = core-written UTF-8 text (never plugin text, I2). The transport maps it to its
        /// own wire, as today's framer `refuse` does: transport-grpc a trailers-only (or, head sent, trailers)
        /// `grpc-status` mapped from the status with `grpc-message` = text; transport-http a status response
        /// with the text body (head sent: a reset/abort of the stream). Round 13: transport-websocket is begun
        /// only after its 101 is written (§12.27), so every E_REFUSE it gets is post-handshake and it answers a
        /// close frame (4xx → 1008, 5xx → 1011, reason = text cut to 123 bytes); a refusal **before** the 101
        /// (route, auth, the plane's own refusal, no websocket transport) never reaches it: it is the HTTP
        /// transport's status response with body, byte-equal to 1.5.5's pre-101 refusal (transport-ws
        /// door/mod.rs:1297-1321). No E_END follows; the stream is over. A status outside 400..=599 is
        /// answered REFUSED R_INVALID.
        /// Round 16, E_CLOSE (stream 0; arg = CR_* reason, bytes empty; today's `finish` with FinishIn.reason,
        /// ABI-MIN-3 §4.6 "finish merges into emit"): core is closing the **connection** (or datagram session)
        /// by its own decision and asks the framer for its goodbye on the wire: transport-ws a close frame with
        /// the code its reason maps to (today's transport.rs:376-386: CR_DRAIN → 1012, CR_REVOKED → 1008,
        /// CR_TIMEOUT and CR_CAPACITY_EXHAUSTED → 1013, else 1000/1011 as today), transport-http/-grpc an h2
        /// GOAWAY (HTTP/1.1: nothing), transport-webrtc its final close datagrams (today's framing.rs:999-1007:
        /// `rtc.close()` then drain). Answer: WRITE* (or SEND_TO* for datagram sessions), then CLOSE? (absent =
        /// CLOSE_GRACEFUL); any other record is FAULT BadRecords. Core flushes the answer's bytes, bounded by the
        /// conn's write timeout (and, for CR_DRAIN, the shutdown grace), then closes the conn or path and drops
        /// the session; nothing else is called on it after E_CLOSE. Sent exactly once, only when core ends a
        /// live session itself (CR_NORMAL: core done with an idle client conn or an upstream conn it retires;
        /// CR_DRAIN: shutdown or a reconfigure retiring the listener; CR_REVOKED: the conn's credential or
        /// grant was revoked; CR_TIMEOUT: idle or deadline; CR_CAPACITY_EXHAUSTED: shed under core's limits;
        /// CR_POISONED: core refuses the conn for a protocol violation it detected); never after the transport
        /// answered CLOSE, after EOF/PATH_GONE (CR_PEER_CLOSED is never sent: the framer already saw it), after a
        /// socket failure (CR_TRANSPORT_FAILED is never sent: nothing can be written), or to a quarantined
        /// instance (its sessions are dropped with no call, §11.2).
            E_HEAD: u32 = 1;
            E_BODY: u32 = 2;
            E_END: u32 = 3;
            E_TRAILERS: u32 = 4;
            E_RESET: u32 = 5;
            E_REFUSE: u32 = 6;
            E_CLOSE: u32 = 7;
        /// Host-only reserved control; arg zero, bytes empty. May bypass a held normal feed to release
        /// an existing terminal serialization barrier after exact host audit authorization. It does
        /// not supply new response content, skip ordered bytes, or relax the E_END hold rule.
            E_RELEASE: u32 = 8;
        /// Host-only reserved control; arg zero, bytes empty. The host has already frozen delivery
        /// terminality after settling actual carrier writes. This acknowledgement creates no receipt.
            E_DELIVERY_SETTLED: u32 = 9;
            E_REFUSE_HEAD_SENT: u32 = 1 << 16;
        /// Round 16: E_CLOSE reasons (today's CLOSE_*, busbar-contract abi/transport/mod.rs:488-503, same
        /// numbers; CR_ because CLOSE_* names CloseRec.how here), and E_RESET's core code for a stall cut
        /// (outside every wire's code space; each framer maps it: h2/gRPC RST_STREAM(CANCEL) or, head not yet
        /// sent, gRPC `grpc-status` 8 RESOURCE_EXHAUSTED as stream.rs:17-21 does today; a data channel closed).
            CR_NORMAL: u32 = 0;
            CR_PEER_CLOSED: u32 = 1;
            CR_DRAIN: u32 = 2;
            CR_POISONED: u32 = 3;
            CR_REVOKED: u32 = 4;
            CR_TIMEOUT: u32 = 5;
            CR_TRANSPORT_FAILED: u32 = 6;
            CR_CAPACITY_EXHAUSTED: u32 = 7;
            RESET_STALLED: u32 = 0xFFFF_0001;
            FB_SERVER: u64 = 1;
            FB_CLIENT: u64 = 2;
            FB_DATAGRAM: u64 = 4;
        /// This framer supplies complete ordered output attribution and the reserved response lifecycle.
        /// Without it a host cannot activate a path promising actual response delivery evidence.
            FB_WIRE_PROVENANCE: u64 = 8;
            WIRE_CONTROL: u32 = 1;
            WIRE_PAYLOAD: u32 = 2;
            COMPLETE_FLUSH: u32 = 1;
            COMPLETE_SHUTDOWN: u32 = 2;
            DG_SECURED: u32 = 1;
            EV_PATH: u32 = 1;
            EV_KEYING: u32 = 2;
            EV_RENDEZVOUS: u32 = 3;
            PATH_NEW: u32 = 1;
            PATH_GONE: u32 = 2;
            PATH_BOUND: u32 = 4;
            PATH_VERIFIED: u32 = 8;
            DTLS_CLIENT: u32 = 1;
            DTLS_SERVER: u32 = 2;
        /// EV_PATH flag: core's DTLS on this path failed the SECURE fingerprint check; the path is closed.
            PATH_REJECTED: u32 = 16;
        /// SecureRec.alg: the SDP hash names core accepts (RFC 8122). sha-1 is refused (R_INVALID).
            FP_SHA256: u32 = 1;
            FP_SHA384: u32 = 2;
            FP_SHA512: u32 = 3;
        /// IceTermsRec.flags: this side is the ICE controlling agent.
            ICE_CONTROLLING: u32 = 1;
        /// EV_PATH flag (round 6): the remote candidate behind this path was refused by egress; no byte
        /// was or will be sent to it (audited `ice_candidate_denied`).
            PATH_DENIED: u32 = 32;
            M_BEGIN: u64 = 1 << 0;
            M_INGEST: u64 = 1 << 1;
            M_EMIT: u64 = 1 << 2;
            M_TIMER: u64 = 1 << 3;
            M_DATAGRAM: u64 = 1 << 4;
            M_EVENT: u64 = 1 << 5;
            M_OFFER: u64 = 1 << 6;
        }
        /// A new conn or datagram session. Answer (after the shim's TOKEN): WRITE* (preface), WAKE_AT?; with
        /// ROLE_DATAGRAM: ICE_TERMS (required: core cannot route a check to the session without its local
        /// ufrag), and with CONN_DIAL also RENDEZVOUS (the local offer, built from `conn.head`'s opening), SEND_TO*, SECURE?.
        sync open fn begin(&self, h: &Host, conn: &ConnInfo<'_>, out: &mut Out<'_>) -> Result<Session, Fail>;
        /// Bytes read from the conn (empty = EOF). Answer: STREAM_*, WRITE*, CLOSE?, WAKE_AT?, UPGRADE+LEFTOVER?, PAUSE/RESUME?,
        /// STREAM_WRITABLE* (round 16). PAUSE/RESUME stop and restart core's **reading** of the conn; they say nothing
        /// about a stream's outbound room, which is STREAM_FULL/STREAM_WRITABLE's.
        sync fn ingest(&self, h: &Host, s: &mut Session, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, s, bytes, out); Err(crate::fail::Fail::unsupported()) }
        /// Core sends a piece on `stream` (stream 0 + E_HEAD in ROLE_CLIENT opens a new stream: answer STREAM_OPENED).
        /// Round 22, ROLE_CLIENT E_HEAD: the head arrives complete and already signed (core merged this instance's
        /// `offer` default lines and ran auth `outbound` before the emit). The framer writes every field as handed,
        /// adds none of its default lines again and rewrites nothing; the only lines it may add are the two it
        /// derives from core's facts, which no outbound style signs (C-STYLE-VOCAB (r22)): from H_BUDGET_NS its
        /// wire's deadline line (transport-grpc `grpc-timeout: <msg::timeout_value(ns)>`, today's door.rs:278-296),
        /// and from H_BODY_LEN its length line (transport-http `content-length` on HTTP/1.1, today's
        /// `states_length = 1`); without H_BODY_LEN it frames the body its own way (chunked, DATA frames).
        /// Round 23, the one other exception, **protocol handshake lines**: a framer whose wire opens a stream
        /// with a handshake adds exactly that handshake's lines, and only these names: `upgrade`, `connection`,
        /// `sec-websocket-key`, `sec-websocket-version` (transport-ws ROLE_CLIENT, RFC 6455 §4.1: `upgrade:
        /// websocket`, `connection: Upgrade`, `sec-websocket-version: 13`, and a fresh `sec-websocket-key` per
        /// handshake, 16 bytes from its `MaskSource`, base64; today's `into_client_request`, transport.rs:1248-1253,
        /// :956-961), and it checks the peer's `sec-websocket-accept` (`Host::digest(Sha1)`; a mismatch is FAILED
        /// F_PROTOCOL). Core never sends these names in a ROLE_CLIENT E_HEAD: it drops them from the plane's head
        /// and from `offer` defaults before auth `outbound` (§13 head order), so they are outside every signed set
        /// (C-STYLE-VOCAB (r22)). A plane-stated `sec-websocket-protocol` is an ordinary line, written as handed.
        /// Answer: WRITE* (or SEND_TO* for datagram sessions), STREAM_OPENED?, WAKE_AT?, PAUSE/RESUME?, STREAM_FULL?
        /// (round 16, for this piece's stream). E_CLOSE (round 16): WRITE* or SEND_TO*, then CLOSE? only.
        sync fn emit(&self, h: &Host, s: &mut Session, stream: u64, piece: u32, arg: u32, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, s, stream, piece, arg, bytes, out); Err(crate::fail::Fail::unsupported()) }
        /// The WAKE_AT time passed. Answer: as ingest (datagram sessions: as datagram), STREAM_WRITABLE* included.
        sync fn timer(&self, h: &Host, s: &mut Session, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, s, out); Err(crate::fail::Fail::unsupported()) }
        /// One datagram on `path` (flags = DG_SECURED if core's DTLS layer opened it). Answer: SEND_TO*,
        /// SECURE?, PATH_BIND?/PATH_REBIND?, STREAM_* (media and data channels as streams; round 16: STREAM_WRITABLE*
        /// when a data channel's buffered amount falls below its low-water mark), WAKE_AT?, CLOSE?.
        sync fn datagram(&self, h: &Host, s: &mut Session, path: u32, flags: u32, bytes: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, s, path, flags, bytes, out); Err(crate::fail::Fail::unsupported()) }
        /// Core-side datagram events: EV_PATH (arg = one EVENT_PATH record, PathRec + addr: path added, gone, bound, verified, rejected
        /// or denied), EV_KEYING (arg = one EVENT_KEYING record, KeyingRec + material, after DTLS on a path), EV_RENDEZVOUS (arg = one generic TEXT record, the far
        /// end's session description text). Answer: as datagram, plus RENDEZVOUS, ICE_TERMS (with the remote
        /// credentials, after EV_RENDEZVOUS) and ICE_CANDIDATE* (the far end's candidates).
        sync fn event(&self, h: &Host, s: &mut Session, ev: u32, arg: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, s, ev, arg, out); Err(crate::fail::Fail::unsupported()) }
        /// Round 9. Cold, pure: the ALPN ids this instance offers on `role` (ROLE_SERVER: what core's listener
        /// advertises; ROLE_CLIENT: what core's TLS dial offers), from the instance's own settings (transport-http
        /// `offer_for(secure, prior_knowledge, http1_only)`: h2 only, http/1.1 only, or h2 + http/1.1). Called by the
        /// transport adapter right after INSTANCE, once per side the instance declares (FB_SERVER → ROLE_SERVER,
        /// FB_CLIENT → ROLE_CLIENT), before any `begin`; cached for the instance's life (a different offer is a
        /// reconfigure, so a new instance). Answer: ALPN* (zero = offer no ALPN on that side). Round 22 (the rest
        /// of today's `locate`, `LocateIn::defaults_buf`): for ROLE_CLIENT the ALPN* may be followed by PAIR*, at
        /// most 8, lowercase names = the framer's own default head lines for every request it carries, static per
        /// instance (transport-grpc `content-type: application/grpc`, `te: trailers`, door.rs:348-353;
        /// transport-http `accept: */*`, engine.rs:626-643, whose `host` line is core's own authority rule, §8.6
        /// `upstream`). Core adds each one the upstream head does not already carry (name compared ASCII
        /// case-insensitively) **before** auth `outbound`, so the auth signs the complete head (auth-sigv4 signs
        /// `content-type`). Any other role, PAIR on ROLE_SERVER, or any other tag, is FAULT BadRecords.
        sync fn offer(&self, h: &Host, role: u32, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, role, out); Err(crate::fail::Fail::unsupported()) }

        extras {
            /// The host side of the transport kind: a typed face over busbar-ffi's `Instance` (IF §10.4).
            /// `live` points into the plugin image and is valid because `inst` holds the image (I13).
            #[cfg(feature = "host")]
            pub struct Proxy {
                inst: std::sync::Arc<crate::host_side::driver::Instance>,
                live: std::sync::Arc<busbar_ffi::host::Instance<Marker>>,
            }

            #[cfg(feature = "host")]
            impl Proxy {
                /// Bind. Done by the loader only, after admit; None when `inst` is not a transport instance.
                pub fn bind(inst: std::sync::Arc<crate::host_side::driver::Instance>) -> Option<Self> {
                    let live = inst.live::<Marker>()?;
                    Some(Proxy { inst, live })
                }

                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
                }

                pub fn begin<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    conn: &ConnInfo<'_>,
                ) -> Result<
                    (Option<SessionHandle>, crate::host_side::answer::Answer<'o>),
                    crate::fail::CallError,
                > {
                    use crate::plugin::__rt::Arg;
                    let (session, answer) = crate::host_side::proxy::opener::<Marker>(
                        &self.inst,
                        crate::host_side::proxy::entry(M_BEGIN),
                        buf,
                        |lease| {
                            self.live.open_session1(|vt| &vt.begin, Arg::view(conn), lease)
                        },
                    )?;
                    Ok((
                        session.map(|session| SessionHandle {
                            inst: std::sync::Arc::clone(&self.inst),
                            session,
                        }),
                        answer,
                    ))
                }

                pub fn offer<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    role: u32,
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_OFFER), buf, |lease| {
                        self.live.call1(|vt| &vt.offer, Arg::u32(role), lease)
                    })
                }

            }

            /// One live transport session as the host holds it (IF §10.4): `Send`, not `Sync` and not `Clone`; every
            /// method takes `&mut self`, and its `Drop` is the only cancel (busbar-ffi's `Session`), so a cancel cannot
            /// race a method and two entries on one token need two `&mut` borrows, which the borrow checker refuses (I6).
            #[cfg(feature = "host")]
            pub struct SessionHandle {
                inst: std::sync::Arc<crate::host_side::driver::Instance>,
                session: busbar_ffi::host::Session<Marker>,
            }

            #[cfg(feature = "host")]
            impl SessionHandle {
                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
                }

                pub fn ingest<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    bytes: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    use crate::types::Bytes;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_INGEST), buf, |lease| {
                        self.session.call1(|vt| &vt.ingest, Arg::bytes(Bytes::new(bytes)), lease)
                    })
                }

                pub fn emit<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    stream: u64,
                    piece: u32,
                    arg: u32,
                    bytes: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    use crate::types::Bytes;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_EMIT), buf, |lease| {
                        self.session.call4(
                            |vt| &vt.emit,
                            (
                                Arg::u64(stream),
                                Arg::u32(piece),
                                Arg::u32(arg),
                                Arg::bytes(Bytes::new(bytes)),
                            ),
                            lease,
                        )
                    })
                }

                pub fn timer<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_TIMER), buf, |lease| {
                        self.session.call0(|vt| &vt.timer, lease)
                    })
                }

                pub fn datagram<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    path: u32,
                    flags: u32,
                    bytes: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    use crate::types::Bytes;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_DATAGRAM), buf, |lease| {
                        self.session.call3(
                            |vt| &vt.datagram,
                            (Arg::u32(path), Arg::u32(flags), Arg::bytes(Bytes::new(bytes))),
                            lease,
                        )
                    })
                }

                pub fn event<'o>(
                    &mut self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    ev: u32,
                    arg: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    use crate::types::Bytes;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_EVENT), buf, |lease| {
                        self.session.call2(
                            |vt| &vt.event,
                            (Arg::u32(ev), Arg::bytes(Bytes::new(arg))),
                            lease,
                        )
                    })
                }

            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::transport::{self as t, tag};
    use crate::records::{Pod, Records, Reply, Writer};
    use crate::types::{Bytes, KindCode, Str};

    /// Every transport tag, in table order.
    const TAGS: [u16; 31] = [
        tag::WRITE,
        tag::CLOSE,
        tag::WAKE_AT,
        tag::UPGRADE,
        tag::LEFTOVER,
        tag::STREAM_HEAD,
        tag::STREAM_BODY,
        tag::STREAM_END,
        tag::STREAM_RESET,
        tag::STREAM_TRAILERS,
        tag::STREAM_OPENED,
        tag::PAUSE,
        tag::RESUME,
        tag::SEND_TO,
        tag::SECURE,
        tag::RENDEZVOUS,
        tag::ICE_TERMS,
        tag::ICE_CANDIDATE,
        tag::PATH_BIND,
        tag::PATH_REBIND,
        tag::ALPN,
        tag::STREAM_FULL,
        tag::STREAM_WRITABLE,
        tag::EVENT_PATH,
        tag::EVENT_KEYING,
        tag::WIRE_PART,
        tag::WIRE_END,
        tag::RESPONSE_ABORT,
        tag::RESPONSE_QUIESCENT,
        tag::D_PROTOCOL,
        tag::D_LISTENER_SLOT,
    ];

    /// The call records are 0x0100..=0x011C in table order; describe items keep their allocated numbers, and
    /// round 8's D_ALPN (0x0180) stays retired.
    #[test]
    fn the_tags_keep_their_numbers_and_d_alpn_stays_retired() {
        assert!(TAGS[..29].iter().copied().eq(0x0100..=0x011C));
        assert_eq!(tag::D_PROTOCOL, 0x0181);
        assert_eq!(tag::D_LISTENER_SLOT, 0x0182);
        assert!(!TAGS.contains(&0x0180));
    }

    #[test]
    fn the_method_bits_follow_declaration_order() {
        let bits = [
            t::M_BEGIN,
            t::M_INGEST,
            t::M_EMIT,
            t::M_TIMER,
            t::M_DATAGRAM,
            t::M_EVENT,
            t::M_OFFER,
        ];
        assert_eq!(bits, [1, 2, 4, 8, 16, 32, 64]);
        assert_eq!(t::ALL, 0x7F);
        assert_eq!(t::KIND, KindCode::Transport);
        assert_eq!(t::ABI, crate::versions::TRANSPORT);
        assert_eq!(crate::versions::abi_of(t::KIND), t::ABI);
    }

    /// E_REFUSE's arg is a status in bits 0..=15 plus E_REFUSE_HEAD_SENT, so the flag never touches a status.
    #[test]
    fn the_refuse_flag_sits_above_the_status_bits() {
        assert_eq!(t::E_REFUSE_HEAD_SENT & 0xFFFF, 0);
        assert_eq!((599 | t::E_REFUSE_HEAD_SENT) & 0xFFFF, 599);
    }

    /// The view is its fields back to back (the size assert `kind!` writes, IF §7.6).
    #[test]
    fn conn_info_has_no_padding() {
        let strs = 5 * size_of::<Str<'_>>();
        let bytes = 3 * size_of::<Bytes<'_>>();
        assert_eq!(size_of::<t::ConnInfo<'_>>(), 2 * 4 + strs + bytes + 8);
    }

    fn round_trip<T: Pod>(v: T, size: usize) {
        assert_eq!(size_of::<T>(), size);
        let mut out = Reply::new();
        out.put_pod_tail(tag::SEND_TO, &v, b"tail")
            .expect("one record fits");
        let rec = Records::new(out.as_bytes())
            .next_rec()
            .expect("one record")
            .expect("well framed");
        let (back, tail) = rec.pod_tail::<T>().expect("the pod and its tail");
        assert_eq!(back.as_bytes(), v.as_bytes());
        assert_eq!(tail, b"tail");
    }

    #[test]
    fn every_pod_has_its_frozen_size_and_reads_back() {
        round_trip(
            t::CloseRec {
                how: t::CLOSE_ABORT,
                _r: 0,
            },
            8,
        );
        round_trip(t::WakeAt { mono_ns: u64::MAX }, 8);
        let head = t::StreamHead {
            stream: 1,
            flags: t::SH_END_STREAM,
            _r: 0,
        };
        round_trip(head, 16);
        let body = t::StreamBody {
            stream: 3,
            flags: t::MSG_TEXT | t::MSG_FIN,
            _r: 0,
        };
        round_trip(body, 16);
        let reset = t::StreamReset {
            stream: 5,
            code: t::RESET_STALLED,
            _r: 0,
        };
        round_trip(reset, 16);
        round_trip(t::StreamFlow { stream: 7 }, 8);
        round_trip(
            t::SendTo {
                path: 1,
                flags: t::DG_SECURED,
            },
            8,
        );
        let path = t::PathRec {
            path: 2,
            flags: t::PATH_NEW | t::PATH_VERIFIED,
        };
        round_trip(path, 8);
        round_trip(
            t::KeyingRec {
                path: 2,
                profile: 1,
            },
            8,
        );
        let secure = t::SecureRec {
            path: 2,
            role: t::DTLS_CLIENT,
            alg: t::FP_SHA256,
            digest_len: 32,
        };
        round_trip(secure, 16);
        let terms = t::IceTermsRec {
            flags: t::ICE_CONTROLLING,
            _r: 0,
        };
        round_trip(terms, 8);
        round_trip(t::PathReqRec { path: 3, from: 2 }, 8);
    }
}
