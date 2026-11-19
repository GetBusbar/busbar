// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport adapter: `TransportPort` over the transport kind's `Proxy` (IF §11.3, §8.7, §8.8).
//!
//! Every method is one sync proxy call on the thread's `sync_out`, decoded straight into `TransportOut` items
//! while the answer buffer is live (no copy). An answer is checked whole before the sink sees any item, so a
//! malformed answer reaches the sink with nothing: the adapter quarantines the instance and returns FAULT
//! (`BadRecords`, or `UnknownTag` for a tag outside the transport table). The adapter only decodes; the
//! per-call answer shapes (STREAM_FULL only from `emit`, E_CLOSE's WRITE*/SEND_TO* then CLOSE?) are the
//! connector session task's checks (§11.3), with one exception the IF gives the adapter: UPGRADE is taken only
//! as the whole answer to `emit(E_HEAD)` whose head is H_STATUS(101) (§8.7, §12.27 step 3).

use std::sync::atomic::AtomicBool;

use busbar_plugin_abi::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
use busbar_plugin_abi::fail::failed::F_LIMIT;
use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::pool::{sync_out, PooledOut};
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use busbar_plugin_abi::records::{tag as generic, Rec, RecErr, Records, Reply, U32Rec, Writer};
use busbar_plugin_abi::transport::{
    self as t, tag, ConnInfo, CLOSE_ABORT, CLOSE_GRACEFUL, DG_SECURED, EV_KEYING, EV_PATH,
    EV_RENDEZVOUS, E_HEAD, FB_CLIENT, FB_SERVER, ICE_CONTROLLING, MSG_BINARY, MSG_FIN, MSG_TEXT,
    ROLE_CLIENT, ROLE_SERVER, SH_END_STREAM,
};
use busbar_plugin_abi::types::{Bytes, Status, Str};
use busbar_plugin_abi::wire::{Breach, Wire};

/// The byte-carrying pieces of one `emit`, as the port hands them: the same four optional entries, in
/// the contract's order.
pub use crate::call::kinds::transport::Pieces as EmitParts;
use crate::call::kinds::transport::{OnSession as _, Pieces, Proxy};
use crate::call::Mono;
use crate::instance::ErrorBook;
use busbar_ports::codec::transport::{decode_offer, encode_keying, encode_path, Offer};
use busbar_ports::transport::{
    ConnIn, TransportEvent, TransportOut, TransportPort, TransportSession,
};
use busbar_ports::PluginCode;
use busbar_ports::PortError;

/// The clock reading of a session call. The transport port's session methods carry none today (only
/// `begin` does, in its connection record), so none is handed in; when the port gains the reading it
/// replaces this constant at each call below and nothing else changes.
const NOW: Mono = Mono::NONE;

/// The HTTP status of the one head an UPGRADE may answer (RFC 9110 §15.2.2).
const SWITCHING_PROTOCOLS: u32 = 101;

/// The port over one instance's proxy. `offer` ran once per declared side right after INSTANCE (`open`); its
/// answers are cached here for the instance's life (a different offer is a reconfigure, so a new instance).
pub struct TransportAdapter {
    proxy: Proxy,
    /// The image's error book (§11.2), for the ERROR number of a REFUSED or FAILED answer.
    errors: &'static ErrorBook,
    /// The undeclared-number WARN latch `ErrorBook::resolve` takes.
    warned: AtomicBool,
    max_out: usize,
    facts: u64,
    /// The image's D_PROTOCOL names (the UPGRADE targets it serves), from describe.
    protocols: Box<[Box<str>]>,
    listener_slots: Box<[Box<str>]>,
    offers: Offers,
}

impl TransportAdapter {
    /// Builds the port right after INSTANCE: one `offer` call for each side the instance declares (FB_SERVER →
    /// ROLE_SERVER, FB_CLIENT → ROLE_CLIENT), before any `begin` (§8.7 `offer`). A refused, failed or malformed
    /// offer fails the open; a datagram-only instance makes no call.
    pub fn open(
        proxy: Proxy,
        errors: &'static ErrorBook,
        protocols: Box<[Box<str>]>,
        listener_slots: Box<[Box<str>]>,
    ) -> Result<Self, PortError> {
        let (facts, max_out) = {
            let inst = proxy.instance();
            (inst.facts, inst.max_out)
        };
        let mut adapter = TransportAdapter {
            proxy,
            errors,
            warned: AtomicBool::new(false),
            max_out,
            facts,
            protocols,
            listener_slots,
            offers: Offers::default(),
        };
        for role in declared_roles(facts) {
            let offer = adapter.offer(role)?;
            adapter.offers.set(role, offer);
        }
        Ok(adapter)
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// One `offer(role)` call, decoded by A11's `decode_offer`.
    fn offer(&self, role: u32) -> Result<Offer, PortError> {
        sync_out(self.max_out, |out| {
            let a = self
                .proxy
                .offer(out, Mono::NONE, role)
                .map_err(PortError::Call)?;
            if !a.is_ok() {
                return Err(self.refusal(&a));
            }
            decode_offer(&a, role).map_err(|e| self.fault(Bad::Rec(e)))
        })
    }

    /// One session call: the proxy method `f` answers into the thread's `out`, then the answer is judged
    /// by the session's validator and decoded.
    fn call(
        &self,
        s: &mut TransportSession,
        call: Call<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
        f: impl for<'o> FnOnce(
            &mut TransportSession,
            &'o mut PooledOut,
        ) -> Result<Answer<'o>, CallError>,
    ) -> Result<(), PortError> {
        sync_out(self.max_out, |out| {
            let a = f(s, out).map_err(PortError::Call)?;
            self.answer(&a, call, &mut s.wire, sink)
        })
    }

    fn answer(
        &self,
        a: &Answer<'_>,
        call: Call<'_>,
        wire: &mut Wire,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        if !a.is_ok() {
            return Err(self.refusal(a));
        }
        decode(a.records(), call, wire, sink).map_err(|bad| self.fault(bad))
    }

    /// A REFUSED or FAILED answer as the port's error. Until W1-L2 lands the one shared builder (§11.3, no
    /// frozen signature yet), this is the transport's copy of it, with the same inputs.
    fn refusal(&self, a: &Answer<'_>) -> PortError {
        let error = self.errors.resolve(a.fail_error(), &self.warned);
        shown(
            a.status,
            a.fail(),
            a.fail_fact(FACT_RETRY_AFTER_S),
            a.fail_fact(FACT_BACKEND_STATUS),
            error,
            &self.proxy.instance().scrub,
        )
    }

    /// The plugin broke the answer grammar: quarantine the instance (the kernel audits `plugin_fault` from
    /// the error) and answer FAULT.
    fn fault(&self, bad: Bad) -> PortError {
        if let Bad::Wire(breach) = bad {
            let inst = self.proxy.instance();
            tracing::error!(
                plugin = %inst.identity,
                instance = %inst.name,
                rule = ?breach.rule,
                stream = breach.stream,
                "transport_fault: the session broke a rule of the output model; nothing of that answer is written"
            );
        }
        self.proxy.instance().quarantine();
        PortError::Call(CallError::Fault(bad.reason()))
    }
}

impl TransportPort for TransportAdapter {
    fn alpn(&self, role: u32) -> &[Box<str>] {
        self.offers.alpn(role)
    }

    fn defaults(&self, role: u32) -> &[(Box<str>, Box<str>)] {
        self.offers.defaults(role)
    }

    fn protocols(&self) -> &[Box<str>] {
        &self.protocols
    }

    fn listener_slots(&self) -> &[Box<str>] {
        &self.listener_slots
    }

    fn facts(&self) -> u64 {
        self.facts
    }

    fn begin(
        &self,
        c: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError> {
        let info = conn_info(c);
        sync_out(self.max_out, |out| {
            let (handle, a) = self.proxy.begin(out, &info).map_err(PortError::Call)?;
            if !a.is_ok() {
                return Err(self.refusal(&a));
            }
            let Some(mut handle) = handle else {
                return Err(self.fault(Bad::Token));
            };
            // On a bad answer the handle drops here, which cancels the session (§10.4).
            self.answer(&a, Call::Begin, &mut handle.wire, sink)?;
            Ok(handle)
        })
    }

    fn ingest(
        &self,
        s: &mut TransportSession,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.call(s, Call::Ingest, sink, |s, out| s.ingest(out, NOW, bytes))
    }

    /// Every piece, E_REFUSE and E_CLOSE included, goes to the framer as handed (§8.7); the answer's shape for
    /// E_CLOSE and STREAM_FULL's stream are the connector's checks.
    fn emit(
        &self,
        s: &mut TransportSession,
        stream: u64,
        pieces: u32,
        arg: u32,
        credit: u64,
        parts: EmitParts<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        // The pieces and the parts must say the same thing: one entry per byte-carrying piece.
        let carried = |bit: u32, part: Option<&[u8]>| (pieces & bit != 0) == part.is_some();
        if !(carried(E_HEAD, parts.head)
            && carried(t::E_BODY, parts.body)
            && carried(t::E_TRAILERS, parts.trailers)
            && carried(t::E_END, parts.end))
            || parts.end.is_some_and(|end| !end.is_empty())
            || (credit != 0 && pieces & t::E_CONSUMED == 0)
        {
            return Err(emit_misuse());
        }
        let head = parts.head.unwrap_or(&[]);
        // What the engine asks of this stream, told to the session's validator before the call: the
        // pieces, the body bytes given, and the length of each sealed value the head declares (the
        // transport is told a sealed value's name and length, never the value).
        sealed_lengths(head, |lengths| {
            let body = parts.body.map_or(0, |body| body.len() as u64);
            s.wire.asked(stream, pieces, body, lengths);
        })
        .map_err(|_| emit_misuse())?;
        let call = Call::Emit {
            piece: pieces,
            stream,
            head,
        };
        self.call(s, call, sink, |s, out| {
            let parts = Pieces {
                head: parts.head,
                body: parts.body,
                trailers: parts.trailers,
                end: parts.end,
            };
            s.emit(out, NOW, stream, pieces, arg, credit, parts)
        })
    }

    fn timer(
        &self,
        s: &mut TransportSession,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.call(s, Call::Other, sink, |s, out| s.timer(out, NOW))
    }

    fn datagram(
        &self,
        s: &mut TransportSession,
        path: u32,
        secured: bool,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        let flags = if secured { DG_SECURED } else { 0 };
        self.call(s, Call::Other, sink, |s, out| {
            s.datagram(out, NOW, path, flags, bytes)
        })
    }

    /// The argument is one record (R6b): EVENT_PATH and EVENT_KEYING through the §8.8 encoders, EV_RENDEZVOUS
    /// one generic TEXT. It is written into a `Reply`, which zeroes its bytes on growth and drop (I11: the
    /// keying material). `impl Writer for PooledOut` is on dev; moving this onto the thread's `args` buffer is a later
    /// optimisation, not a correctness gap.
    fn event(
        &self,
        s: &mut TransportSession,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        let (code, arg) = event_arg(&ev).map_err(|_| too_big())?;
        self.call(s, Call::Other, sink, |s, out| {
            s.event(out, NOW, code, arg.as_bytes())
        })
    }
}

/// The engine built an `emit` whose pieces and parts disagree, or a head it cannot read: the engine's
/// own fault, refused before any call (the plugin is not charged).
fn emit_misuse() -> PortError {
    PortError::Failed {
        code: busbar_plugin_abi::fail::failed::F_LIMIT,
        text: Box::from("the engine built an emit whose pieces and parts disagree"),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

/// The length of each sealed value a head declares, in slot order (the position of each H_SEALED_PAIR
/// or H_SEALED_QUERY record among the head's sealed records). Handed to `f` from this stack: a head
/// with more sealed values than fit inline spills to the heap, once, for that call.
fn sealed_lengths(head: &[u8], f: impl FnOnce(&[u32])) -> Result<(), RecErr> {
    use busbar_plugin_abi::vocab::head1::{tag as h, SealedPairRec};
    const INLINE: usize = 8;
    let mut inline = [0u32; INLINE];
    let mut spill: Vec<u32> = Vec::new();
    let mut n = 0usize;
    for rec in Records::new(head) {
        let rec = rec?;
        if !matches!(rec.tag, h::H_SEALED_PAIR | h::H_SEALED_QUERY) {
            continue;
        }
        let (sealed, _name) = rec.pod_tail::<SealedPairRec>()?;
        match inline.get_mut(n) {
            Some(slot) if spill.is_empty() => *slot = sealed.len,
            _ => {
                if spill.is_empty() {
                    spill.extend_from_slice(&inline);
                }
                spill.push(sealed.len);
            }
        }
        n += 1;
    }
    if spill.is_empty() {
        f(&inline[..n]);
    } else {
        f(&spill);
    }
    Ok(())
}

/// Core's own encode hit the record cap: a limit, not the plugin's fault.
fn too_big() -> PortError {
    PortError::Failed {
        code: F_LIMIT,
        text: Box::from("transport event argument over the record cap"),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

/// The EV_* code and its one-record argument.
fn event_arg(ev: &TransportEvent<'_>) -> Result<(u32, Reply), busbar_plugin_abi::records::Full> {
    /// Record head, the 8-byte pod and the padding to the next multiple of 8.
    const ROOM: usize = 8 + 8 + 7;
    match *ev {
        TransportEvent::Path { path, flags, addr } => {
            let mut w = Reply::with_capacity(ROOM + addr.len());
            encode_path(&mut w, path, flags, addr)?;
            Ok((EV_PATH, w))
        }
        TransportEvent::Keying {
            path,
            profile,
            material,
        } => {
            let mut w = Reply::with_capacity(ROOM + material.len());
            encode_keying(&mut w, path, profile, material)?;
            Ok((EV_KEYING, w))
        }
        TransportEvent::Rendezvous(description) => {
            let mut w = Reply::with_capacity(ROOM + description.len());
            w.put_text(generic::TEXT, description)?;
            Ok((EV_RENDEZVOUS, w))
        }
    }
}

/// The roles `offer` is asked for, from the instance's FB_* facts, in that order.
fn declared_roles(facts: u64) -> impl Iterator<Item = u32> {
    [(FB_SERVER, ROLE_SERVER), (FB_CLIENT, ROLE_CLIENT)]
        .into_iter()
        .filter(move |(bit, _)| facts & bit != 0)
        .map(|(_, role)| role)
}

/// The cached `offer` answers. A side the instance does not declare stays empty.
struct Offers {
    server: Offer,
    client: Offer,
}

impl Default for Offers {
    fn default() -> Self {
        let none = || Offer {
            alpn: Box::default(),
            defaults: Box::default(),
        };
        Offers {
            server: none(),
            client: none(),
        }
    }
}

impl Offers {
    fn set(&mut self, role: u32, offer: Offer) {
        match role {
            ROLE_SERVER => self.server = offer,
            ROLE_CLIENT => self.client = offer,
            _ => {}
        }
    }

    /// ROLE_SERVER: what core's listener advertises; ROLE_CLIENT: what its TLS dial offers; any other role `&[]`.
    fn alpn(&self, role: u32) -> &[Box<str>] {
        match role {
            ROLE_SERVER => &self.server.alpn,
            ROLE_CLIENT => &self.client.alpn,
            _ => &[],
        }
    }

    /// ROLE_CLIENT only (`decode_offer` refuses PAIR on ROLE_SERVER).
    fn defaults(&self, role: u32) -> &[(Box<str>, Box<str>)] {
        match role {
            ROLE_CLIENT => &self.client.defaults,
            _ => &[],
        }
    }
}

/// The port's borrowed connection as the kind's view. `head` is carried as handed: CONN_UPGRADED's upgrade
/// request + H_STATUS(101) + the plane's PAIR*, and (round 27) CONN_DIAL's resolved opening (§8.7).
fn conn_info<'a>(c: &ConnIn<'a>) -> ConnInfo<'a> {
    ConnInfo {
        role: c.role,
        flags: c.flags,
        alpn: Str::new(c.alpn),
        sni: Str::new(c.sni),
        peer: Str::new(c.peer),
        local: Str::new(c.local),
        tls_peer_cert: Bytes::new(c.tls_peer_cert),
        leftover: Bytes::new(c.leftover),
        head: Bytes::new(c.head),
        local_fingerprint: Str::new(c.local_fingerprint),
        mono_ns: c.mono_ns,
    }
}

/// A REFUSED or FAILED answer's parts as the port's error: the plugin text scrubbed, then cut (§12.16
/// `fail_text`), the FAILED-only facts, and the resolved ERROR code.
pub fn shown(
    status: Status,
    fail: Option<(u32, &str)>,
    retry_after_s: Option<u64>,
    backend_status: Option<u64>,
    error: Option<PluginCode>,
    scrub: &Scrub,
) -> PortError {
    let Some((code, text)) = fail else {
        return PortError::Call(CallError::Fault(FaultReason::MissingFail));
    };
    let text: Box<str> = Box::from(&*fail_text(scrub, text));
    match status {
        Status::REFUSED => PortError::Refused { code, text, error },
        Status::FAILED => PortError::Failed {
            code,
            text,
            retry_after_s,
            backend_status,
            error,
        },
        other => PortError::Call(CallError::Fault(FaultReason::BadStatus(other.0))),
    }
}

/// What the adapter called, as far as the answer grammar depends on it.
#[derive(Clone, Copy)]
pub enum Call<'a> {
    Begin,
    Ingest,
    /// `piece` = the piece set; `head` = the E_HEAD entry's records (empty without one).
    Emit {
        piece: u32,
        stream: u64,
        head: &'a [u8],
    },
    /// timer, datagram, event.
    Other,
}

impl Call<'_> {
    /// An `emit` whose pieces include E_HEAD on stream 0: the engine asks a dialled session to open a
    /// stream. Only that call may be answered STREAM_BUSY.
    fn opens_a_stream(self) -> bool {
        matches!(self, Call::Emit { piece, stream: 0, .. } if piece & E_HEAD != 0)
    }

    /// UPGRADE answers only `emit(E_HEAD)` whose head is H_STATUS(101) (§8.7 UPGRADE, round 13); whether the
    /// stream is a ROUTE_UPGRADE stream is core's to know (§12.27).
    fn upgrades(self) -> bool {
        match self {
            Call::Emit { piece, head, .. } => {
                piece & E_HEAD != 0 && head_status(head) == Some(SWITCHING_PROTOCOLS)
            }
            Call::Begin | Call::Ingest | Call::Other => false,
        }
    }
}

/// The H_STATUS of core-written head records, if any.
fn head_status(head: &[u8]) -> Option<u32> {
    Records::new(head)
        .map_while(Result::ok)
        .find(|rec| rec.tag == generic::H_STATUS)
        .and_then(|rec| rec.pod::<U32Rec>().ok())
        .map(|status| status.value)
}

/// Why an answer is not one: FAULT BadRecords, UnknownTag, or MissingToken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    Rec(RecErr),
    Tag(u16),
    Token,
    /// A breach of the output model, with the rule and the stream the record named.
    Wire(Breach),
}

impl From<RecErr> for Bad {
    fn from(e: RecErr) -> Self {
        Bad::Rec(e)
    }
}

impl Bad {
    pub fn reason(self) -> FaultReason {
        match self {
            Bad::Rec(e) => FaultReason::BadRecords(e),
            Bad::Tag(t) => FaultReason::UnknownTag(t),
            Bad::Token => FaultReason::MissingToken,
            // Every breach of the output model is FAULT BadRecords for the whole answer; the rule and
            // the stream go to the audit line (`TransportAdapter::fault`).
            Bad::Wire(_) => FaultReason::BadRecords(RecErr::Size),
        }
    }
}

/// A grammar breach (count, order, length, flag bit): `RecErr::Size`, as A11's `decode_offer`.
const GRAMMAR: Bad = Bad::Rec(RecErr::Size);

/// The whole answer is checked first, then handed to `sink`; a bad answer gives the sink nothing.
/// `wire` is the session's one validator of the output model (rules L1 to L7 and L9): every record of
/// the answer passes through it, in order, in the checking pass. A breach leaves `wire` mid-answer,
/// which is right: a breach ends the session.
pub fn decode(
    recs: Records<'_>,
    call: Call<'_>,
    wire: &mut Wire,
    sink: &mut dyn FnMut(TransportOut<'_>),
) -> Result<(), Bad> {
    // An answer with no records has nothing to check and nothing to deliver; only `begin` must speak
    // (its SESSION statement).
    if recs.rest().is_empty() && !matches!(call, Call::Begin) {
        return Ok(());
    }
    walk(recs, call, Some(wire), &mut |_: TransportOut<'_>| {})?;
    walk(recs, call, None, sink)
}

/// One pass over an OK answer's records (the leading TOKEN of `begin` is already gone, §10.2). A METRIC
/// record is passed over: `decode_metrics` reads it (§12.17). `wire` is Some in the checking pass.
fn walk(
    recs: Records<'_>,
    call: Call<'_>,
    mut wire: Option<&mut Wire>,
    sink: &mut dyn FnMut(TransportOut<'_>),
) -> Result<(), Bad> {
    let mut seen = false;
    let mut upgraded = false;
    let mut after_upgrade = false;
    // `begin` stated its SESSION; a STREAM_BUSY must be the answer's only record.
    let mut stated = false;
    let mut alone = false;
    for rec in recs {
        let rec = rec?;
        if rec.tag == generic::METRIC {
            continue;
        }
        if alone || (matches!(call, Call::Begin) && !stated && rec.tag != tag::SESSION) {
            return Err(GRAMMAR);
        }
        if let Some(wire) = wire.as_deref_mut() {
            wire.record(rec.tag, rec.body).map_err(Bad::Wire)?;
        }
        let leftover_ok = core::mem::replace(&mut after_upgrade, false);
        // After UPGRADE the answer holds at most its one LEFTOVER (§12.27 step 3: the framer writes nothing).
        if upgraded && !(leftover_ok && rec.tag == tag::LEFTOVER) {
            return Err(GRAMMAR);
        }
        let out = match rec.tag {
            // The one output model. The record was judged by the session's validator in the checking
            // pass (rules L1 to L7 and L9); here it is only read for the engine's writer.
            tag::WIRE_PART => {
                let (part, bytes) = rec.pod_tail::<t::WirePart>()?;
                TransportOut::WirePart {
                    stream: part.stream,
                    payload: part.class == t::WIRE_PAYLOAD,
                    bytes,
                }
            }
            tag::WIRE_SEALED => {
                let sealed = rec.pod::<t::WireSealed>()?;
                TransportOut::WireSealed {
                    stream: sealed.stream,
                    slot: sealed.slot,
                    offset: sealed.offset,
                    len: sealed.len,
                }
            }
            tag::WIRE_END => {
                let end = rec.pod::<t::WireEnd>()?;
                TransportOut::WireEnd {
                    stream: end.stream,
                    how: end.how,
                    arg: end.arg,
                }
            }
            // `begin`'s statement of what the session is: exactly one, first in the answer.
            tag::SESSION => {
                if !matches!(call, Call::Begin) || seen {
                    return Err(GRAMMAR);
                }
                let s = rec.pod::<t::SessionRec>()?;
                reserved(s._r)?;
                bits(s.flags, t::S_MULTIPLEX)?;
                let multiplex = s.flags & t::S_MULTIPLEX != 0;
                // The two windows are stated exactly when the session carries several streams.
                if multiplex == (s.stream_window == 0 || s.conn_window == 0)
                    && (multiplex || s.stream_window != 0 || s.conn_window != 0)
                {
                    return Err(GRAMMAR);
                }
                stated = true;
                TransportOut::Session {
                    multiplex,
                    stream_window: s.stream_window,
                    conn_window: s.conn_window,
                }
            }
            // The answer of an `emit` whose pieces include E_HEAD on stream 0 when the session can
            // carry no more streams now: alone in its answer, nothing was taken.
            tag::STREAM_BUSY => {
                empty(&rec)?;
                if seen || !call.opens_a_stream() {
                    return Err(GRAMMAR);
                }
                alone = true;
                TransportOut::StreamBusy
            }
            // The session will open no further stream; the streams it carries go on.
            tag::NO_NEW_STREAMS => {
                empty(&rec)?;
                TransportOut::NoNewStreams
            }
            tag::CLOSE => {
                let c = rec.pod::<t::CloseRec>()?;
                reserved(c._r)?;
                match c.how {
                    CLOSE_GRACEFUL => TransportOut::Close { abort: false },
                    CLOSE_ABORT => TransportOut::Close { abort: true },
                    _ => return Err(GRAMMAR),
                }
            }
            tag::WAKE_AT => TransportOut::WakeAt(rec.pod::<t::WakeAt>()?.mono_ns),
            tag::UPGRADE => {
                if seen || !call.upgrades() {
                    return Err(GRAMMAR);
                }
                upgraded = true;
                after_upgrade = true;
                TransportOut::Upgrade {
                    protocol: rec.text()?,
                }
            }
            tag::LEFTOVER => {
                if !leftover_ok {
                    return Err(GRAMMAR);
                }
                TransportOut::Leftover(rec.body)
            }
            tag::STREAM_HEAD => {
                let (h, tail) = rec.pod_tail::<t::StreamHead>()?;
                reserved(h._r)?;
                bits(h.flags, SH_END_STREAM)?;
                TransportOut::StreamHead {
                    stream: h.stream,
                    end_stream: h.flags & SH_END_STREAM != 0,
                    head: framed(tail)?,
                }
            }
            tag::STREAM_BODY => {
                let (b, tail) = rec.pod_tail::<t::StreamBody>()?;
                reserved(b._r)?;
                msg_flags(b.flags)?;
                TransportOut::StreamBody {
                    stream: b.stream,
                    flags: b.flags,
                    bytes: tail,
                }
            }
            tag::STREAM_END => TransportOut::StreamEnd(stream(&rec)?),
            tag::STREAM_RESET => {
                let r = rec.pod::<t::StreamReset>()?;
                reserved(r._r)?;
                TransportOut::StreamReset {
                    stream: r.stream,
                    code: r.code,
                }
            }
            tag::STREAM_TRAILERS => {
                let (f, tail) = rec.pod_tail::<t::StreamFlow>()?;
                TransportOut::StreamTrailers {
                    stream: f.stream,
                    pairs: pairs(tail)?,
                }
            }
            tag::STREAM_OPENED => TransportOut::StreamOpened(stream(&rec)?),
            tag::STREAM_FULL => TransportOut::StreamFull(stream(&rec)?),
            tag::STREAM_WRITABLE => TransportOut::StreamWritable(stream(&rec)?),
            tag::SEND_TO => {
                let (d, tail) = rec.pod_tail::<t::SendTo>()?;
                bits(d.flags, DG_SECURED)?;
                TransportOut::SendTo {
                    path: d.path,
                    secured: d.flags & DG_SECURED != 0,
                    bytes: tail,
                }
            }
            tag::SECURE => {
                let (sec, tail) = rec.pod_tail::<t::SecureRec>()?;
                // digest_len 0 is FAULT (§8.7 SecureRec); the tail is exactly the digest.
                if sec.digest_len == 0 || usize::try_from(sec.digest_len).ok() != Some(tail.len()) {
                    return Err(GRAMMAR);
                }
                TransportOut::Secure {
                    path: sec.path,
                    role: sec.role,
                    alg: sec.alg,
                    peer_fingerprint: tail,
                }
            }
            tag::RENDEZVOUS => TransportOut::Rendezvous(rec.text()?),
            tag::ICE_TERMS => ice_terms(&rec)?,
            tag::ICE_CANDIDATE => TransportOut::IceCandidate(rec.text()?),
            tag::PATH_BIND => {
                let p = rec.pod::<t::PathReqRec>()?;
                if p.from != 0 {
                    return Err(GRAMMAR);
                }
                TransportOut::PathBind {
                    path: p.path,
                    from: None,
                }
            }
            tag::PATH_REBIND => {
                let p = rec.pod::<t::PathReqRec>()?;
                TransportOut::PathBind {
                    path: p.path,
                    from: Some(p.from),
                }
            }
            other => return Err(Bad::Tag(other)),
        };
        seen = true;
        sink(out);
    }
    // `begin` answers with exactly one SESSION, first.
    if matches!(call, Call::Begin) && !stated {
        return Err(GRAMMAR);
    }
    Ok(())
}

/// A reserved pod field must be 0.
fn reserved(r: u32) -> Result<(), Bad> {
    if r == 0 {
        Ok(())
    } else {
        Err(Bad::Rec(RecErr::Reserved))
    }
}

/// `flags` sets no bit outside `allowed`.
fn bits(flags: u32, allowed: u32) -> Result<(), Bad> {
    if flags & !allowed == 0 {
        Ok(())
    } else {
        Err(GRAMMAR)
    }
}

/// STREAM_BODY flags (§8.7, C-MSG-FLAGS): 0 for a byte stream; else MSG_TEXT or MSG_BINARY (exactly one) on
/// every fragment of a message, plus MSG_FIN on its last.
fn msg_flags(flags: u32) -> Result<(), Bad> {
    bits(flags, MSG_TEXT | MSG_BINARY | MSG_FIN)?;
    match flags & (MSG_TEXT | MSG_BINARY) {
        0 if flags == 0 => Ok(()),
        MSG_TEXT | MSG_BINARY => Ok(()),
        _ => Err(GRAMMAR),
    }
}

/// A body that is exactly one stream id (StreamFlow).
fn stream(rec: &Rec<'_>) -> Result<u64, Bad> {
    Ok(rec.pod::<t::StreamFlow>()?.stream)
}

fn empty(rec: &Rec<'_>) -> Result<(), Bad> {
    if rec.body.is_empty() {
        Ok(())
    } else {
        Err(GRAMMAR)
    }
}

/// Nested records that frame (the head's tags are the kernel's to read).
fn framed(tail: &[u8]) -> Result<Records<'_>, Bad> {
    for rec in Records::new(tail) {
        rec?;
    }
    Ok(Records::new(tail))
}

/// Nested records that are all well-formed PAIRs (STREAM_TRAILERS).
fn pairs(tail: &[u8]) -> Result<Records<'_>, Bad> {
    for rec in Records::new(tail) {
        let rec = rec?;
        if rec.tag != generic::PAIR {
            return Err(GRAMMAR);
        }
        rec.pair()?;
    }
    Ok(Records::new(tail))
}

/// ICE_TERMS: IceTermsRec + exactly four nested TEXT (local ufrag, local pwd, remote ufrag, remote pwd).
fn ice_terms<'o>(rec: &Rec<'o>) -> Result<TransportOut<'o>, Bad> {
    let (r, tail) = rec.pod_tail::<t::IceTermsRec>()?;
    reserved(r._r)?;
    bits(r.flags, ICE_CONTROLLING)?;
    let mut texts = Records::new(tail);
    let local_ufrag = utf8(next_text(&mut texts)?)?;
    let local_pwd = next_text(&mut texts)?;
    let remote_ufrag = utf8(next_text(&mut texts)?)?;
    let remote_pwd = next_text(&mut texts)?;
    if texts.next().is_some() {
        return Err(GRAMMAR);
    }
    Ok(TransportOut::IceTerms {
        controlling: r.flags & ICE_CONTROLLING != 0,
        local_ufrag,
        local_pwd,
        remote_ufrag,
        remote_pwd,
    })
}

fn next_text<'o>(texts: &mut Records<'o>) -> Result<&'o [u8], Bad> {
    match texts.next() {
        Some(Ok(rec)) if rec.tag == generic::TEXT => Ok(rec.body),
        Some(Err(e)) => Err(Bad::Rec(e)),
        _ => Err(GRAMMAR),
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, Bad> {
    core::str::from_utf8(bytes).map_err(|_| Bad::Rec(RecErr::Utf8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::fail::refused::R_DENIED;
    use busbar_plugin_abi::host_side::scrub::FAIL_TEXT_SHOWN;
    use busbar_plugin_abi::records::Full;
    use busbar_plugin_abi::transport::{
        CloseRec, IceTermsRec, PathReqRec, SecureRec, SendTo, StreamBody, StreamFlow, StreamHead,
        StreamReset, WakeAt, E_BODY, FB_DATAGRAM, ROLE_DATAGRAM,
    };

    fn answer(f: impl FnOnce(&mut Reply) -> Result<(), Full>) -> Reply {
        let mut out = Reply::new();
        f(&mut out).expect("the test answer fits");
        out
    }

    fn text_records(texts: &[&str]) -> Reply {
        answer(|w| texts.iter().try_for_each(|s| w.put_text(generic::TEXT, s)))
    }

    /// One line per sink item, so a whole answer compares as one list.
    fn label(o: &TransportOut<'_>) -> String {
        match o {
            TransportOut::Write(b) => format!("write {}", String::from_utf8_lossy(b)),
            TransportOut::WirePart {
                stream,
                class,
                bytes,
            } => format!("wire {stream} {class:?} {}", String::from_utf8_lossy(bytes)),
            TransportOut::WireEnd {
                stream,
                requirement,
            } => format!("wire-end {stream} {requirement:?}"),
            TransportOut::ResponseAbort { stream, code } => format!("abort {stream} {code}"),
            TransportOut::ResponseQuiescent(stream) => format!("quiescent {stream}"),
            TransportOut::Close { abort } => format!("close abort={abort}"),
            TransportOut::WakeAt(ns) => format!("wake {ns}"),
            TransportOut::Upgrade { protocol } => format!("upgrade {protocol}"),
            TransportOut::Leftover(b) => format!("leftover {}", String::from_utf8_lossy(b)),
            TransportOut::StreamHead {
                stream,
                end_stream,
                head,
            } => format!("head {stream} end={end_stream} recs={}", head.count()),
            TransportOut::StreamBody {
                stream,
                flags,
                bytes,
            } => format!(
                "body {stream} flags={flags} {}",
                String::from_utf8_lossy(bytes)
            ),
            TransportOut::StreamEnd(s) => format!("end {s}"),
            TransportOut::StreamReset { stream, code } => format!("reset {stream} {code}"),
            TransportOut::StreamTrailers { stream, pairs } => {
                format!("trailers {stream} pairs={}", pairs.count())
            }
            TransportOut::StreamOpened(s) => format!("opened {s}"),
            TransportOut::Pause => "pause".into(),
            TransportOut::Resume => "resume".into(),
            TransportOut::StreamFull(s) => format!("full {s}"),
            TransportOut::StreamWritable(s) => format!("writable {s}"),
            TransportOut::SendTo {
                path,
                secured,
                bytes,
            } => format!(
                "send {path} secured={secured} {}",
                String::from_utf8_lossy(bytes)
            ),
            TransportOut::Secure {
                path,
                role,
                alg,
                peer_fingerprint,
            } => format!("secure {path} {role} {alg} len={}", peer_fingerprint.len()),
            TransportOut::Rendezvous(d) => format!("rendezvous {d}"),
            TransportOut::IceTerms {
                controlling,
                local_ufrag,
                local_pwd,
                remote_ufrag,
                remote_pwd,
            } => format!(
                "ice controlling={controlling} {local_ufrag} {} {remote_ufrag} {}",
                String::from_utf8_lossy(local_pwd),
                String::from_utf8_lossy(remote_pwd)
            ),
            TransportOut::IceCandidate(c) => format!("candidate {c}"),
            TransportOut::PathBind { path, from } => format!("bind {path} from={from:?}"),
        }
    }

    fn run(out: &Reply, call: Call<'_>) -> Result<Vec<String>, Bad> {
        let mut seen = Vec::new();
        decode(
            Records::new(out.as_bytes()),
            call,
            &mut |o: TransportOut<'_>| seen.push(label(&o)),
        )?;
        Ok(seen)
    }

    fn provenance_record(stream: u64, value: u32, reserved: u32, tail: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(stream.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.extend_from_slice(&reserved.to_le_bytes());
        bytes.extend_from_slice(tail);
        bytes
    }

    #[test]
    fn attributed_output_reaches_sink_in_protocol_order() {
        let out = answer(|w| {
            w.put(0x0119, &provenance_record(0, 1, 0, b"control"))?;
            w.put(0x0119, &provenance_record(7, 2, 0, b"payload"))?;
            w.put(0x011a, &provenance_record(7, 2, 0, b""))?;
            w.put(0x011b, &provenance_record(9, 8, 0, b""))?;
            w.put(0x011c, &7u64.to_le_bytes())
        });
        assert_eq!(
            run(&out, Call::Ingest).expect("valid protocol attribution"),
            [
                "wire 0 Control control",
                "wire 7 Payload payload",
                "wire-end 7 Shutdown",
                "abort 9 8",
                "quiescent 7"
            ]
        );
    }

    #[test]
    fn malformed_provenance_rejects_the_whole_answer_before_any_callback() {
        for (tag, bad) in [
            (0x0119, provenance_record(0, 2, 0, b"body")),
            (0x0119, provenance_record(1, 3, 0, b"body")),
            (0x0119, provenance_record(1, 2, 0, b"")),
            (0x0119, provenance_record(1, 2, 1, b"body")),
            (0x011a, provenance_record(0, 1, 0, b"")),
            (0x011a, provenance_record(1, 3, 0, b"")),
            (0x011a, provenance_record(1, 1, 1, b"")),
            (0x011a, provenance_record(1, 1, 0, b"tail")),
            (0x011b, provenance_record(0, 1, 0, b"")),
            (0x011b, provenance_record(1, 1, 1, b"")),
            (0x011c, Vec::from(0u64.to_le_bytes())),
        ] {
            let out = answer(|w| {
                w.put(tag::WRITE, b"must not escape")?;
                w.put(tag, &bad)
            });
            let mut calls = 0;
            let error = decode(Records::new(out.as_bytes()), Call::Ingest, &mut |_| {
                calls += 1
            })
            .expect_err("invalid attribution");
            assert!(matches!(error, Bad::Rec(_)), "record grammar: {error:?}");
            assert_eq!(calls, 0, "no valid prefix may escape");
        }
    }

    fn head_with_status(status: u32) -> Reply {
        answer(|w| {
            w.put_pod(
                generic::H_STATUS,
                &U32Rec {
                    value: status,
                    _r: 0,
                },
            )?;
            w.put_pair(generic::PAIR, "sec-websocket-protocol", b"chat")
        })
    }

    /// The byte-stream records, the round-16 STREAM_FULL/STREAM_WRITABLE arms and a METRIC (passed over)
    /// reach the sink in answer order with their fields.
    #[test]
    fn every_answer_record_reaches_the_sink_in_order() {
        let head = head_with_status(200);
        let trailers = answer(|w| w.put_pair(generic::PAIR, "grpc-status", b"0"));
        let out = answer(|w| {
            w.put(tag::WRITE, b"preface")?;
            w.put_pod(tag::WAKE_AT, &WakeAt { mono_ns: 99 })?;
            w.put_metric(1, 0, 1.0, &[])?;
            let sh = StreamHead {
                stream: 3,
                flags: SH_END_STREAM,
                _r: 0,
            };
            w.put_pod_tail(tag::STREAM_HEAD, &sh, head.as_bytes())?;
            let sb = StreamBody {
                stream: 3,
                flags: 0,
                _r: 0,
            };
            w.put_pod_tail(tag::STREAM_BODY, &sb, b"bytes")?;
            w.put_pod_tail(
                tag::STREAM_TRAILERS,
                &StreamFlow { stream: 3 },
                trailers.as_bytes(),
            )?;
            w.put_pod(tag::STREAM_END, &StreamFlow { stream: 3 })?;
            w.put_pod(
                tag::STREAM_RESET,
                &StreamReset {
                    stream: 5,
                    code: 8,
                    _r: 0,
                },
            )?;
            w.put_pod(tag::STREAM_OPENED, &StreamFlow { stream: 7 })?;
            w.put(tag::PAUSE, b"")?;
            w.put(tag::RESUME, b"")?;
            w.put_pod(tag::STREAM_FULL, &StreamFlow { stream: 7 })?;
            w.put_pod(tag::STREAM_WRITABLE, &StreamFlow { stream: 9 })?;
            w.put_pod(
                tag::CLOSE,
                &CloseRec {
                    how: CLOSE_ABORT,
                    _r: 0,
                },
            )
        });
        let want = [
            "write preface",
            "wake 99",
            "head 3 end=true recs=2",
            "body 3 flags=0 bytes",
            "trailers 3 pairs=1",
            "end 3",
            "reset 5 8",
            "opened 7",
            "pause",
            "resume",
            "full 7",
            "writable 9",
            "close abort=true",
        ];
        assert_eq!(run(&out, Call::Ingest).expect("a good answer"), want);
    }

    /// C-MSG-FLAGS (adapter arm): MSG_TEXT/MSG_BINARY and MSG_FIN cross a fragmented message unchanged; FIN
    /// alone, TEXT with BINARY, or an unknown bit is FAULT BadRecords.
    #[test]
    fn message_flags_cross_a_fragmented_message() {
        let body = |flags: u32, text: &'static [u8]| {
            move |w: &mut Reply| {
                w.put_pod_tail(
                    tag::STREAM_BODY,
                    &StreamBody {
                        stream: 1,
                        flags,
                        _r: 0,
                    },
                    text,
                )
            }
        };
        let out = answer(|w| {
            body(MSG_TEXT, b"he")(w)?;
            body(MSG_TEXT, b"ll")(w)?;
            body(MSG_TEXT | MSG_FIN, b"o")(w)?;
            body(MSG_BINARY | MSG_FIN, b"z")(w)
        });
        assert_eq!(
            run(
                &out,
                Call::Emit {
                    piece: E_BODY,
                    head: b""
                }
            )
            .expect("a message"),
            [
                "body 1 flags=1 he",
                "body 1 flags=1 ll",
                "body 1 flags=5 o",
                "body 1 flags=6 z"
            ]
        );
        for flags in [MSG_FIN, MSG_TEXT | MSG_BINARY, MSG_TEXT | 8] {
            let out = answer(|w| body(flags, b"x")(w));
            assert_eq!(run(&out, Call::Ingest), Err(GRAMMAR), "flags {flags}");
        }
    }

    /// L9 (round 13): UPGRADE + LEFTOVER is taken only as the whole answer to `emit(E_HEAD)` whose head is
    /// H_STATUS(101); from `ingest`, after a 200 head, after a WRITE, or with anything after it, FAULT.
    #[test]
    fn upgrade_is_taken_only_as_the_answer_to_a_101_head() {
        let switching = head_with_status(101);
        let ok = head_with_status(200);
        let upgrade = answer(|w| {
            w.put_text(tag::UPGRADE, "websocket")?;
            w.put(tag::LEFTOVER, b"first")
        });
        let on_101 = Call::Emit {
            piece: E_HEAD,
            head: switching.as_bytes(),
        };
        assert_eq!(
            run(&upgrade, on_101).expect("the commit answer"),
            ["upgrade websocket", "leftover first"]
        );
        let elsewhere = [
            Call::Ingest,
            Call::Begin,
            Call::Emit {
                piece: E_HEAD,
                head: ok.as_bytes(),
            },
            Call::Emit {
                piece: E_BODY,
                head: switching.as_bytes(),
            },
        ];
        for call in elsewhere {
            assert_eq!(run(&upgrade, call), Err(GRAMMAR));
        }
        let written = answer(|w| {
            w.put(tag::WRITE, b"HTTP/1.1 101")?;
            w.put_text(tag::UPGRADE, "websocket")
        });
        let trailing = answer(|w| {
            w.put_text(tag::UPGRADE, "websocket")?;
            w.put(tag::LEFTOVER, b"a")?;
            w.put(tag::LEFTOVER, b"b")
        });
        let stray = answer(|w| w.put(tag::LEFTOVER, b"a"));
        for bad in [&written, &trailing, &stray] {
            assert_eq!(run(bad, on_101), Err(GRAMMAR));
        }
    }

    /// The whole answer is checked before the sink sees an item: a good WRITE before a bad CLOSE gives the
    /// sink nothing, so core never writes a half-answer.
    #[test]
    fn a_bad_answer_gives_the_sink_nothing() {
        let out = answer(|w| {
            w.put(tag::WRITE, b"preface")?;
            w.put_pod(tag::CLOSE, &CloseRec { how: 9, _r: 0 })
        });
        let mut items = 0;
        let got = decode(
            Records::new(out.as_bytes()),
            Call::Ingest,
            &mut |_: TransportOut<'_>| items += 1,
        );
        assert_eq!((got, items), (Err(GRAMMAR), 0));
    }

    /// The datagram answers decode with their §8.7 rules: SECURE's tail is exactly its non-zero digest, ICE_TERMS
    /// is exactly four TEXT, PATH_BIND has from = 0, SEND_TO knows only DG_SECURED.
    #[test]
    fn datagram_answers_decode_with_their_rules() {
        let terms = text_records(&["lu", "lp", "ru", ""]);
        let out = answer(|w| {
            w.put_pod_tail(
                tag::SEND_TO,
                &SendTo {
                    path: 2,
                    flags: DG_SECURED,
                },
                b"srtp",
            )?;
            let sec = SecureRec {
                path: 2,
                role: 1,
                alg: 1,
                digest_len: 32,
            };
            w.put_pod_tail(tag::SECURE, &sec, &[0xAB; 32])?;
            let ice = IceTermsRec {
                flags: ICE_CONTROLLING,
                _r: 0,
            };
            w.put_pod_tail(tag::ICE_TERMS, &ice, terms.as_bytes())?;
            w.put_text(
                tag::ICE_CANDIDATE,
                "candidate:1 1 udp 1 192.0.2.1 4000 typ host",
            )?;
            w.put_text(tag::RENDEZVOUS, "v=0")?;
            w.put_pod(tag::PATH_BIND, &PathReqRec { path: 2, from: 0 })?;
            w.put_pod(tag::PATH_REBIND, &PathReqRec { path: 4, from: 2 })
        });
        assert_eq!(
            run(&out, Call::Other).expect("a good answer"),
            [
                "send 2 secured=true srtp",
                "secure 2 1 1 len=32",
                "ice controlling=true lu lp ru ",
                "candidate candidate:1 1 udp 1 192.0.2.1 4000 typ host",
                "rendezvous v=0",
                "bind 2 from=None",
                "bind 4 from=Some(2)",
            ]
        );
        let three = text_records(&["lu", "lp", "ru"]);
        let five = text_records(&["lu", "lp", "ru", "rp", "x"]);
        let bad: [Reply; 6] = [
            answer(|w| {
                let sec = SecureRec {
                    path: 2,
                    role: 1,
                    alg: 1,
                    digest_len: 0,
                };
                w.put_pod_tail(tag::SECURE, &sec, b"")
            }),
            answer(|w| {
                let sec = SecureRec {
                    path: 2,
                    role: 1,
                    alg: 1,
                    digest_len: 32,
                };
                w.put_pod_tail(tag::SECURE, &sec, &[0xAB; 31])
            }),
            answer(|w| {
                let ice = IceTermsRec { flags: 0, _r: 0 };
                w.put_pod_tail(tag::ICE_TERMS, &ice, three.as_bytes())
            }),
            answer(|w| {
                let ice = IceTermsRec { flags: 0, _r: 0 };
                w.put_pod_tail(tag::ICE_TERMS, &ice, five.as_bytes())
            }),
            answer(|w| w.put_pod(tag::PATH_BIND, &PathReqRec { path: 2, from: 1 })),
            answer(|w| w.put_pod_tail(tag::SEND_TO, &SendTo { path: 2, flags: 2 }, b"x")),
        ];
        for (i, out) in bad.iter().enumerate() {
            assert_eq!(run(out, Call::Other), Err(GRAMMAR), "case {i}");
        }
    }

    /// A tag outside the transport answer table (here the `offer` tag ALPN) is FAULT UnknownTag, not
    /// BadRecords; a reserved field that is not 0 is BadRecords(Reserved).
    #[test]
    fn a_foreign_tag_is_unknown_and_a_reserved_field_is_checked() {
        let alpn = answer(|w| w.put_text(tag::ALPN, "h2"));
        assert_eq!(run(&alpn, Call::Ingest), Err(Bad::Tag(tag::ALPN)));
        assert_eq!(
            Bad::Tag(tag::ALPN).reason(),
            FaultReason::UnknownTag(tag::ALPN)
        );
        let close = answer(|w| {
            w.put_pod(
                tag::CLOSE,
                &CloseRec {
                    how: CLOSE_GRACEFUL,
                    _r: 1,
                },
            )
        });
        assert_eq!(run(&close, Call::Ingest), Err(Bad::Rec(RecErr::Reserved)));
    }

    /// C-SCRUB-CUT (transport adapter arm): the port error's text is scrubbed first and cut after, so a secret
    /// at bytes 500..540 leaves no 4-byte run and the text is at most 512 bytes; FAILED keeps its facts and
    /// REFUSED drops them.
    #[test]
    fn the_port_error_text_is_scrubbed_then_cut() {
        const SECRET: &str = "cut-secret-0123456789ABCDEFGHIJKLMNOPQRS";
        let scrub = Scrub::new();
        scrub.register(1, &[SECRET.as_bytes()]);
        let raw = format!("{}{SECRET}{}", "a".repeat(500), "b".repeat(2000));
        let fail = Some((7, raw.as_str()));
        let leaks = |text: &str| {
            SECRET
                .as_bytes()
                .windows(4)
                .any(|run| text.as_bytes().windows(4).any(|have| have == run))
        };
        match shown(Status::FAILED, fail, Some(30), Some(503), None, &scrub) {
            PortError::Failed {
                code,
                text,
                retry_after_s,
                backend_status,
                error,
            } => {
                assert_eq!(
                    (code, retry_after_s, backend_status, error),
                    (7, Some(30), Some(503), None)
                );
                assert!(text.len() <= FAIL_TEXT_SHOWN && !leaks(&text), "{text}");
            }
            other => panic!("FAILED is Failed: {other:?}"),
        }
        match shown(
            Status::REFUSED,
            Some((R_DENIED, raw.as_str())),
            Some(30),
            None,
            None,
            &scrub,
        ) {
            PortError::Refused { code, text, .. } => {
                assert_eq!(code, R_DENIED);
                assert!(text.len() <= FAIL_TEXT_SHOWN && !leaks(&text), "{text}");
            }
            other => panic!("REFUSED is Refused: {other:?}"),
        }
        assert_eq!(
            shown(Status::REFUSED, None, None, None, None, &scrub),
            PortError::Call(CallError::Fault(FaultReason::MissingFail))
        );
    }

    /// C-ALPN (adapter arm): `offer` is asked once per declared side, server first; the cache answers each
    /// side its own list, `defaults` only for ROLE_CLIENT, and nothing for any other role.
    #[test]
    fn alpn_is_cached_per_declared_side() {
        assert!(declared_roles(FB_SERVER | FB_CLIENT | FB_DATAGRAM).eq([ROLE_SERVER, ROLE_CLIENT]));
        assert!(declared_roles(FB_CLIENT).eq([ROLE_CLIENT]));
        assert_eq!(declared_roles(FB_DATAGRAM).count(), 0);
        let mut offers = Offers::default();
        offers.set(
            ROLE_SERVER,
            Offer {
                alpn: Box::new([Box::from("h2"), Box::from("http/1.1")]),
                defaults: Box::default(),
            },
        );
        offers.set(
            ROLE_CLIENT,
            Offer {
                alpn: Box::new([Box::from("http/1.1")]),
                defaults: Box::new([(Box::from("accept"), Box::from("*/*"))]),
            },
        );
        let list = |ids: &[Box<str>]| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
        assert_eq!(list(offers.alpn(ROLE_SERVER)), ["h2", "http/1.1"]);
        assert_eq!(list(offers.alpn(ROLE_CLIENT)), ["http/1.1"]);
        assert!(offers.alpn(ROLE_DATAGRAM).is_empty());
        assert_eq!(offers.defaults(ROLE_CLIENT).len(), 1);
        assert!(offers.defaults(ROLE_SERVER).is_empty());
        assert!(Offers::default().alpn(ROLE_SERVER).is_empty());
    }

    /// L9: every `ConnIn` field reaches the kind's view, `head` (CONN_UPGRADED, CONN_DIAL) included; distinct
    /// lengths catch a dropped or swapped field.
    #[test]
    fn conn_info_carries_every_field() {
        let c = ConnIn {
            role: ROLE_SERVER,
            flags: 4,
            alpn: "h",
            sni: "sn",
            peer: "pee",
            local: "loca",
            tls_peer_cert: b"certs",
            leftover: b"leftov",
            head: b"head-re",
            local_fingerprint: "sha-256 ",
            mono_ns: 11,
        };
        let i = conn_info(&c);
        assert_eq!((i.role, i.flags, i.mono_ns), (ROLE_SERVER, 4, 11));
        assert_eq!(
            [i.alpn.len(), i.sni.len(), i.peer.len(), i.local.len()],
            [1, 2, 3, 4]
        );
        assert_eq!(
            [
                i.tls_peer_cert.len(),
                i.leftover.len(),
                i.head.len(),
                i.local_fingerprint.len()
            ],
            [5, 6, 7, 8]
        );
    }

    /// R6b: EV_PATH and EV_KEYING arguments are one record from the §8.8 encoders; EV_RENDEZVOUS one TEXT.
    #[test]
    fn an_event_argument_is_one_record() {
        let one = |ev: TransportEvent<'_>| {
            let (code, w) = event_arg(&ev).expect("fits");
            let mut recs = Records::new(w.as_bytes());
            let rec = recs.next().expect("one record").expect("framed");
            assert!(recs.next().is_none());
            (code, rec.tag, rec.body.len())
        };
        assert_eq!(
            one(TransportEvent::Path {
                path: 1,
                flags: 8,
                addr: "192.0.2.1:4000"
            }),
            (EV_PATH, tag::EVENT_PATH, 8 + 14)
        );
        assert_eq!(
            one(TransportEvent::Keying {
                path: 1,
                profile: 1,
                material: &[7; 60]
            }),
            (EV_KEYING, tag::EVENT_KEYING, 8 + 60)
        );
        assert_eq!(
            one(TransportEvent::Rendezvous("v=0")),
            (EV_RENDEZVOUS, generic::TEXT, 3)
        );
    }
}
