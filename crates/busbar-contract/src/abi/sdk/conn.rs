// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN'S CONNECTIONS, THROUGH THE HOST CONNECTOR (THE DESIGN, the connections section: one connector for every kind;
//! the plugin ABI: every call is Ready or Pending(wake), never a blocking thread). [`Host`] is the instance's
//! host tables as `open` handed them (`OpenIn.host`, kept by the generic lifecycle,
//! `abi::sdk::life::Held::host`); [`Connector`] makes the connector's services for ONE op on ONE
//! ticket, each answering [`Poll::Ready`] or [`Poll::Pending`]. The one-shot request/reply every
//! driver needs is `abi::sdk::exchange`, built on it.
//!
//! THE REPLAY RULE (the mechanism's completion handles, `abi::mechanism::ticket`). An op that
//! answers PENDING is re-invoked, on the same ticket, when its wake fires; its body runs again from
//! the top. Each service a [`Connector`] makes carries the handle `(ticket, n)`, `n` counting the
//! services this entry made. So a body that makes its services in the same order on every entry
//! re-issues each completed one with its own handle, and the host answers its stored result
//! without running it twice. Memory a pending service writes into (a read buffer) must outlive the
//! entry: `abi::sdk::exchange` keeps its buffers parked on the ticket (`Instance::park`).

use std::task::Poll;

use crate::abi::host::conn::connector::{
    service, ConnectorSlots, EstablishIn, FactsIn, IoIn, ReplyIn, ReplyPiece, RequestIn,
    RequestPiece, StreamFacts, StreamIn, UpgradeIn,
};
use crate::abi::host::service::{
    op, ClockNowIn, ClockReading, DiskAppendIn, DiskWritten, HostSlots, NeedAdmitIn, ServiceFn,
    ServiceHead, ServiceOut,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_OCTETS};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket, WakeFn};

/// Why a connector service answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnFailure {
    /// The instance was handed no connector (it declared no need, or its host offers none).
    Unarmed,
    /// The call cannot pend: the op runs on no ticket.
    NoTicket,
    /// The host answered FAILED (the far end, the need or the endpoint said no), with its text
    /// (empty = none), verbatim: a driver may prefix it with its own words.
    Failed(String),
    /// The host refused the call (the egress class, an undeclared need), with its text, verbatim.
    Refused(String),
    /// The host faulted.
    Fault,
}

impl std::fmt::Display for ConnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unarmed => "the instance was handed no connector",
            Self::NoTicket => "the call runs on no ticket and cannot pend",
            Self::Failed(t) if !t.is_empty() => t.as_str(),
            Self::Refused(t) if !t.is_empty() => t.as_str(),
            Self::Failed(_) => "the connector failed the call",
            Self::Refused(_) => "the connector refused the call",
            Self::Fault => "the connector faulted",
        })
    }
}

impl std::error::Error for ConnFailure {}

/// A connector service's answer.
pub type Answer<T> = Poll<Result<T, ConnFailure>>;

/// A STREAM'S FACTS, owned, as [`Connector::facts`] read them off the host connector: never key or
/// certificate material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    /// Connection security is established on the stream.
    pub secure: bool,
    /// The protocol the security handshake agreed; `None` = none.
    pub agreed_protocol: Option<String>,
    /// The far end's key, the pin of its leaf certificate's SubjectPublicKeyInfo
    /// (`transport::trust::key_pin`'s spelling); `None` = the stream carried no certificate.
    pub peer_key_pin: Option<String>,
    /// Busbar presented its client identity in the handshake.
    pub client_identity: bool,
}

/// Why a `disk.append` ([`Connector::disk_append`]) did not land its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskFailure {
    /// The step that failed when the host answered FAILED (`DISK_OPEN_FAILED` /
    /// `DISK_APPEND_FAILED`); `0` for any other answer.
    pub step: u64,
    /// What the rotation the host ran before the failed append did (`rotated`, `faults`); all zero
    /// when the host wrote no result.
    pub rotation: DiskWritten,
    /// The answer, with the host's text.
    pub why: ConnFailure,
}

/// A `disk.append`'s answer.
pub type DiskAnswer = Poll<Result<DiskWritten, DiskFailure>>;

/// THE INSTANCE'S HOST TABLES, as `open` handed them: the context every host call is made with,
/// the wake, the connector table and the host services table.
#[derive(Debug, Clone, Copy)]
pub struct Host {
    ctx: HostCtx,
    wake: Option<WakeFn>,
    conns: *const ConnectorSlots,
    services: *const HostSlots,
}

// SAFETY: the context is an opaque handle and the table plain code addresses, both valid for the
// instance's life (the mechanism's host-table rule); every call goes through the host's own
// synchronisation.
unsafe impl Send for Host {}
// SAFETY: as `Send`.
unsafe impl Sync for Host {}

impl Host {
    /// The tables `tables` names: what `open` was handed (`OpenIn::host`), for a kind whose SDK
    /// wrapper is not yet in this crate (the auth kind's outbound mint reaches its need through it).
    #[must_use]
    pub const fn of(tables: &HostTables) -> Self {
        Self {
            ctx: tables.ctx,
            wake: tables.wake,
            conns: tables.conns,
            services: tables.services,
        }
    }

    /// WAKE `ticket` (the host's `wake`, `abi::mechanism::ticket`): from any thread, never blocks,
    /// never fails; the host re-invokes the op that answered PENDING on it with `FLAG_RESUME`. A
    /// wake for a stale ticket is dropped; tables with no wake make it a no-op.
    pub fn wake(&self, ticket: Ticket) {
        if let Some(wake) = self.wake {
            wake(self.ctx, ticket);
        }
    }

    /// The host services table these tables carry (`abi::host::service`), as the SDK's typed
    /// wrappers; `None` when the host offers none.
    #[must_use]
    pub fn services(&self) -> Option<crate::abi::sdk::services::Services> {
        crate::abi::sdk::services::Services::of(&HostTables {
            size: std::mem::size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: self.ctx,
            wake: self.wake,
            conns: self.conns,
            services: self.services,
        })
    }

    /// The connector for ONE entry of the op running on `ticket`.
    #[must_use]
    pub fn connector(&self, ticket: Ticket) -> Connector<'_> {
        self.connector_from(ticket, 0)
    }

    /// The connector for one entry of the op running on `ticket`, its handles counting on from
    /// `issued` (what [`Connector::issued`] answered when the op parked): an op that runs several
    /// requests one after another parks `(which request, issued)` and resumes the pending one
    /// without replaying the completed ones.
    #[must_use]
    pub fn connector_from(&self, ticket: Ticket, issued: u32) -> Connector<'_> {
        Connector {
            host: self,
            ticket,
            issued,
            budget_ms: None,
            cause: std::cell::Cell::new(0),
        }
    }

    /// Whether the host lent the instance a connector table: a host that declared none of its needs
    /// (no connection table bound) dials nothing for it.
    #[must_use]
    pub fn lends_connector(&self) -> bool {
        !self.conns.is_null()
    }

    fn slots(&self) -> Option<&ConnectorSlots> {
        // SAFETY: NULL, or the host's connector table, valid for the instance's life.
        unsafe { self.conns.as_ref() }
    }
}

/// The connector for one entry of one op: each service it makes carries the next completion
/// handle on its ticket (the replay rule, above).
#[derive(Debug)]
pub struct Connector<'h> {
    host: &'h Host,
    ticket: Ticket,
    issued: u32,
    budget_ms: Option<u64>,
    /// The `CAUSE_*` stage the host named on the last service that failed (`CAUSE_NONE` = none).
    cause: std::cell::Cell<u64>,
}

/// A service `in`: every one leads with a [`ServiceHead`].
trait ServiceIn {
    fn head(&mut self) -> &mut ServiceHead;
}
macro_rules! service_in {
    ($($t:ty),*) => {$(impl ServiceIn for $t {
        fn head(&mut self) -> &mut ServiceHead { &mut self.head }
    })*};
}
service_in!(
    EstablishIn,
    FactsIn,
    StreamIn,
    IoIn,
    UpgradeIn,
    ReplyIn,
    RequestIn,
    ClockNowIn,
    NeedAdmitIn,
    DiskAppendIn
);

const fn blank_head() -> ServiceHead {
    ServiceHead {
        size: 0,
        op: 0,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

const fn absent() -> AbiStr {
    AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    }
}

/// The host's error text, copied (it is the host's until the next service on the ticket).
fn host_text(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the host's text, `len` bytes, live until its next service on this ticket.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

fn text(s: Option<&str>) -> AbiStr {
    s.map_or(absent(), |s| AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    })
}

impl Connector<'_> {
    /// How many services this entry has made so far, counting from where it started.
    #[must_use]
    pub const fn issued(&self) -> u32 {
        self.issued
    }

    /// Where the last service this connector made that failed was failed, as the host named it:
    /// a `CAUSE_*` stage (`CAUSE_NONE` = the host named none). The failure's text is the
    /// [`ConnFailure`]'s, the underlying error's own words when a stage is named.
    #[must_use]
    pub fn cause(&self) -> u64 {
        self.cause.get()
    }

    /// Bound every request this connector sends to `ms` milliseconds: what is left of the op's
    /// deadline, as the op knows it. A request asking for longer is clamped to it.
    #[must_use]
    pub const fn within(mut self, ms: u64) -> Self {
        self.budget_ms = Some(ms);
        self
    }

    /// The bound [`Connector::within`] set; `None` = the op's deadline, as the host enforces it.
    #[must_use]
    pub const fn budget_ms(&self) -> Option<u64> {
        self.budget_ms
    }

    /// Make service `op` through `pick`'s slot with `input`: its `out` when READY.
    fn call<I: ServiceIn>(
        &mut self,
        op: u32,
        pick: impl FnOnce(&ConnectorSlots) -> Option<ServiceFn>,
        input: I,
    ) -> Answer<ServiceOut> {
        let f = self.host.slots().and_then(pick);
        self.make(op, f, input)
    }

    /// Make one service through `f` with `input`, under the next handle on the ticket: the
    /// connector's services and the host's share one count, so one op may make both.
    fn make<I: ServiceIn>(
        &mut self,
        op: u32,
        f: Option<ServiceFn>,
        input: I,
    ) -> Answer<ServiceOut> {
        let Some(f) = f else {
            return Poll::Ready(Err(ConnFailure::Unarmed));
        };
        // A service on no ticket may not pend: `close` never does, so it is made on none (an
        // instance closing its kept connections as it goes).
        if self.ticket.is_none() && op != service::CLOSE {
            return Poll::Ready(Err(ConnFailure::NoTicket));
        }
        let seq = self.issued;
        self.issued += 1;
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        };
        self.cross(op, f, input, handle)
    }

    /// Cross into service `op` through `f` with `input`, under `handle`.
    fn cross<I: ServiceIn>(
        &self,
        op: u32,
        f: ServiceFn,
        input: I,
        handle: CompletionHandle,
    ) -> Answer<ServiceOut> {
        let (answered, out) = self.cross_out(op, f, input, handle);
        match answered {
            Outcome::Ready => Poll::Ready(Ok(out)),
            Outcome::Pending => Poll::Pending,
            Outcome::Failed => {
                self.cause.set(out.value);
                Poll::Ready(Err(ConnFailure::Failed(host_text(out.error))))
            }
            Outcome::Refused => {
                self.cause.set(out.value);
                Poll::Ready(Err(ConnFailure::Refused(host_text(out.error))))
            }
            Outcome::Fault => Poll::Ready(Err(ConnFailure::Fault)),
        }
    }

    /// Cross into service `op` through `f` with `input`, under `handle`: the outcome the host
    /// returned and the `out` it wrote, whatever the outcome.
    fn cross_out<I: ServiceIn>(
        &self,
        op: u32,
        f: ServiceFn,
        mut input: I,
        handle: CompletionHandle,
    ) -> (Outcome, ServiceOut) {
        *input.head() = ServiceHead {
            size: std::mem::size_of::<I>() as u32,
            op,
            handle,
        };
        let mut out = ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(Outcome::Fault),
            _reserved: [0; 3],
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: absent(),
        };
        let answered = f(self.host.ctx, std::ptr::from_ref(&input).cast(), &mut out).outcome();
        (answered, out)
    }

    /// Establish a stream for the declared need `need` (its index), to `target` (`None` = the
    /// need's `target_from`), its dial landing only on an address of `within` (the set a
    /// `dest.judge` answered, `Judged::within`; `""` = no pin beyond the host's judgement): the
    /// stream. A dial the host's judgement pins outside `within` is refused before any byte leaves.
    pub fn establish(&mut self, need: u32, target: Option<&str>, within: &str) -> Answer<u64> {
        self.establish_timed(need, target, within, 0)
    }

    /// [`Connector::establish`], its dial bounded by `timeout_ms` (`0` = the need's own timeout,
    /// else the host's default): an operator-set connect timeout.
    pub fn establish_timed(
        &mut self,
        need: u32,
        target: Option<&str>,
        within: &str,
        timeout_ms: u32,
    ) -> Answer<u64> {
        self.establish_as(need, target, within, timeout_ms, None)
    }

    /// [`Connector::establish_timed`] for the REGISTRATION `member` (its name in the plugin's
    /// declaring section): what the host sealed for that registration alone (its private reach)
    /// applies to this stream; `None` = the stream names none.
    pub fn establish_as(
        &mut self,
        need: u32,
        target: Option<&str>,
        within: &str,
        timeout_ms: u32,
        member: Option<&str>,
    ) -> Answer<u64> {
        let input = EstablishIn {
            head: blank_head(),
            need,
            timeout_ms,
            target: text(target),
            within: text(Some(within)),
            member: text(member),
        };
        self.call(service::ESTABLISH, |s| s.establish, input)
            .map(|r| r.map(|o| o.value))
    }

    /// Write `bytes` to `stream`: how many the host took. The host reads `bytes` during this call
    /// only (`IoIn`); after a PENDING answer the RESUME lends them again.
    pub fn write(&mut self, stream: u64, bytes: &[u8]) -> Answer<usize> {
        let input = IoIn {
            head: blank_head(),
            stream,
            buf: bytes.as_ptr().cast_mut(),
            len: bytes.len(),
        };
        self.call(service::WRITE, |s| s.write, input)
            .map(|r| r.map(|o| o.len as usize))
    }

    /// Read from `stream` into `buf`: how many bytes; `0` = the end. The host writes `buf` during
    /// this call only (`IoIn`); after a PENDING answer the RESUME lends it again.
    pub fn read(&mut self, stream: u64, buf: &mut [u8]) -> Answer<usize> {
        let input = IoIn {
            head: blank_head(),
            stream,
            buf: buf.as_mut_ptr(),
            len: buf.len(),
        };
        self.call(service::READ, |s| s.read, input)
            .map(|r| r.map(|o| (o.len as usize).min(buf.len())))
    }

    /// Upgrade `stream` to connection security, offering `name` (`None` = the endpoint's) and
    /// trusting `trust` (`None` = the need's anchors).
    pub fn upgrade_secure(
        &mut self,
        stream: u64,
        name: Option<&str>,
        trust: Option<&str>,
    ) -> Answer<()> {
        self.upgrade_secure_flagged(stream, name, trust, 0)
    }

    /// [`Connector::upgrade_secure`] with `UPGRADE_*` `flags`
    /// ([`UPGRADE_VERIFY_OFF`](crate::abi::host::conn::connector::UPGRADE_VERIFY_OFF): the
    /// operator's opt-in to an unverified handshake, honoured for an operator-infrastructure need
    /// only).
    pub fn upgrade_secure_flagged(
        &mut self,
        stream: u64,
        name: Option<&str>,
        trust: Option<&str>,
        flags: u32,
    ) -> Answer<()> {
        let input = UpgradeIn {
            head: blank_head(),
            stream,
            offered_name: text(name),
            trust: text(trust),
            flags,
            _reserved: 0,
        };
        self.call(service::UPGRADE_SECURE, |s| s.upgrade_secure, input)
            .map(|r| r.map(|_| ()))
    }

    /// WHAT `stream`'s CONNECTION SECURITY ESTABLISHED, as the host connector observed it
    /// (`service::FACTS`): whether it is secured, the protocol agreed, the far end's key pin and
    /// whether busbar presented its client identity (the transport pin, ARCHITECT 2026-10-03) — readable
    /// on a stream whose connection the connector refused for its trust anchors too, until it is
    /// closed. `None`: a re-issued handle the host answered from its store without writing the
    /// facts again (the replay rule) — they were read on the entry that first answered it.
    pub fn facts(&mut self, stream: u64) -> Answer<Option<Observed>> {
        // `size` stays 0 unless the host wrote the facts on this call.
        let mut slot = StreamFacts {
            size: 0,
            secure: 0,
            endpoint: absent(),
            agreed_protocol: absent(),
            peer_cert_hash: absent(),
            peer_key_pin: absent(),
            client_identity: 0,
            _reserved: 0,
        };
        let input = FactsIn {
            head: blank_head(),
            stream,
            facts: std::ptr::from_mut(&mut slot),
        };
        self.call(service::FACTS, |s| s.facts, input).map(|r| {
            r.map(|_| {
                (slot.size != 0).then(|| {
                    let owned = |t: AbiStr| Some(host_text(t)).filter(|t| !t.is_empty());
                    Observed {
                        secure: slot.secure == 1,
                        agreed_protocol: owned(slot.agreed_protocol),
                        peer_key_pin: owned(slot.peer_key_pin),
                        client_identity: slot.client_identity == 1,
                    }
                })
            })
        })
    }

    /// Close `stream`.
    pub fn close(&mut self, stream: u64) -> Answer<()> {
        let input = StreamIn {
            head: blank_head(),
            stream,
        };
        self.call(service::CLOSE, |s| s.close, input)
            .map(|r| r.map(|_| ()))
    }
}

impl Connector<'_> {
    /// The host's clock (`clock.now`: wall and monotonic, the kernel's one clock). Never pends.
    pub fn clock_now(&mut self) -> Answer<ClockReading> {
        let mut reading = ClockReading {
            size: std::mem::size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: 0,
            mono_ns: 0,
        };
        let input = ClockNowIn {
            head: blank_head(),
            reading: std::ptr::from_mut(&mut reading),
        };
        match self.cross_now(op::CLOCK_NOW, |s| s.clock_now, input) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(reading)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // It never pends: a host that says so broke the service's rule.
            Poll::Pending => Poll::Ready(Err(ConnFailure::Fault)),
        }
    }

    /// THE HOST'S VERDICT on the declared need `need` (its index in the Statement's needs), as it
    /// admitted it when it bound this instance (target, egress class, trust anchors): `Ok` when
    /// admitted, or `ConnFailure::Refused` with the host's text. Never pends. It only lets `open`
    /// answer its own words — a need that failed admission is refused at every establish whether
    /// or not the plugin asked (FAIL-CLOSED, the connector's).
    pub fn admit(&mut self, need: u32) -> Result<(), ConnFailure> {
        let input = NeedAdmitIn {
            head: blank_head(),
            need,
            _reserved: 0,
        };
        match self.cross_now(op::NEED_ADMIT, |s| s.need_admit, input) {
            Poll::Ready(r) => r.map(|_| ()),
            // It never pends: a host that says so broke the service's rule.
            Poll::Pending => Err(ConnFailure::Fault),
        }
    }

    /// APPEND `bytes` to the local file the host maps this instance's destination `dest_key` to
    /// (`disk.append`, the host's bounded disk lane, THE DESIGN): the host owns the path
    /// and rotates the file by its own rules before the append when it is due. It may pend: a body
    /// re-issues it with the same `bytes` on resume (the replay rule) and reads the stored answer.
    /// READY with what the host wrote: the whole of `bytes` landed, and whether the file was rotated
    /// first. A FAILED answer names its step and still reports the rotation that ran before it.
    pub fn disk_append(&mut self, dest_key: &str, bytes: &[u8]) -> DiskAnswer {
        let blank = DiskWritten {
            size: 0,
            rotated: 0,
            faults: 0,
            _reserved: [0; 2],
            written: 0,
        };
        let fail = |step, rotation, why| {
            Poll::Ready(Err(DiskFailure {
                step,
                rotation,
                why,
            }))
        };
        // SAFETY: NULL, or the host's services table, valid for the instance's life.
        let Some(f) = unsafe { self.host.services.as_ref() }.and_then(|s| s.disk_append) else {
            return fail(0, blank, ConnFailure::Unarmed);
        };
        if self.ticket.is_none() {
            return fail(0, blank, ConnFailure::NoTicket);
        }
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq: self.issued,
            _reserved: 0,
        };
        self.issued += 1;
        let mut result = blank;
        let input = DiskAppendIn {
            head: blank_head(),
            dest_key: AbiStr {
                ptr: dest_key.as_ptr(),
                len: dest_key.len(),
            },
            bytes: Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            },
            result: std::ptr::from_mut(&mut result),
        };
        let (answered, out) = self.cross_out(op::DISK_APPEND, f, input, handle);
        let rotation = if result.size as usize == std::mem::size_of::<DiskWritten>() {
            result
        } else {
            blank
        };
        match answered {
            Outcome::Ready => Poll::Ready(Ok(result)),
            Outcome::Pending => Poll::Pending,
            Outcome::Failed => fail(
                out.value,
                rotation,
                ConnFailure::Failed(host_text(out.error)),
            ),
            Outcome::Refused => fail(0, rotation, ConnFailure::Refused(host_text(out.error))),
            Outcome::Fault => fail(0, blank, ConnFailure::Fault),
        }
    }

    /// Make a host service that NEVER pends through `pick`'s slot, on NO ticket: the host keeps no
    /// stored result for it, so every entry of the op asks afresh, and it draws no handle from the
    /// op's count (the replay rule is untouched).
    fn cross_now<I: ServiceIn>(
        &self,
        op: u32,
        pick: impl FnOnce(&HostSlots) -> Option<ServiceFn>,
        input: I,
    ) -> Answer<ServiceOut> {
        // SAFETY: NULL, or the host's services table, valid for the instance's life.
        let Some(f) = unsafe { self.host.services.as_ref() }.and_then(pick) else {
            return Poll::Ready(Err(ConnFailure::Unarmed));
        };
        let none = CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        };
        self.cross(op, f, input, none)
    }

    /// Write one request piece on a framed `stream`: `piece` describes it, `bytes` holds what its
    /// spans name (a head's method, target and field block) or the body bytes. How many bytes the
    /// host took. Both must stay where they are until the write completes (keep them parked). A
    /// stream that is not framed refuses it.
    pub fn write_request(
        &mut self,
        stream: u64,
        piece: &RequestPiece,
        bytes: &[u8],
    ) -> Answer<usize> {
        let input = RequestIn {
            head: blank_head(),
            stream,
            buf: bytes.as_ptr(),
            len: bytes.len(),
            piece: std::ptr::from_ref(piece),
        };
        self.call(service::WRITE_REQUEST, |s| s.write_request, input)
            .map(|r| r.map(|o| o.len as usize))
    }
}

/// One reply piece as [`Connector::read_reply`] reads it: its descriptor, its bytes in the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replied {
    /// The descriptor.
    pub piece: ReplyPiece,
    /// How many bytes the host wrote into the buffer.
    pub len: usize,
}

impl Connector<'_> {
    /// Read the next piece of the reply on `stream` into `buf`, with its descriptor. `buf` (and
    /// the descriptor the SDK keeps beside it in `slot`) must stay where they are until the read
    /// completes (on a PENDING answer, keep them parked).
    pub fn read_reply(
        &mut self,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Answer<Replied> {
        let input = ReplyIn {
            head: blank_head(),
            stream,
            buf: buf.as_mut_ptr(),
            len: buf.len(),
            piece: std::ptr::from_mut(slot),
        };
        let cap = buf.len();
        self.call(service::READ_REPLY, |s| s.read_reply, input)
            .map(|r| {
                r.map(|o| Replied {
                    piece: *slot,
                    len: (o.len as usize).min(cap),
                })
            })
    }
}

/// NOT BEFORE `until_mono_ns` (the host's monotonic clock): a backoff with no plugin timer. READY
/// once the host's clock has reached it; else PENDING with the op's `wake_at_ns` set to it, so the
/// host resumes the op then without a wake (its timer never fires early) — and a resume that comes
/// sooner (a latched or spurious wake) answers PENDING again with the same instant. The op computes
/// `until_mono_ns` ONCE (`clock_now().mono_ns + delay`) and parks it on its ticket.
pub fn not_before<T: crate::abi::sdk::door::AbiOut>(
    c: &mut Connector<'_>,
    out: &mut crate::abi::sdk::out::Out<'_, T>,
    until_mono_ns: u64,
) -> Answer<()> {
    let now = match c.clock_now() {
        Poll::Ready(Ok(r)) => r.mono_ns,
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Pending => return Poll::Pending,
    };
    if now >= until_mono_ns {
        return Poll::Ready(Ok(()));
    }
    out.wake_at(until_mono_ns);
    Poll::Pending
}

#[cfg(test)]
#[path = "tests/conn_tests.rs"]
mod tests;
