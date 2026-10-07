// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE, lowered: [`crate::conn::Conns`] as a `#[repr(C)]` table of
//! `extern "C-unwind"` slots, ONE SLOT PER METHOD, named for it ([`ConnSlots`]). The witness
//! `tests/conn_slot_coverage.rs` holds the list to the trait.
//!
//! Two halves, one file, because they are one contract:
//!
//! * **HOST side** — [`host_slots`], the table a host hands every plugin instance, each slot running
//!   the host's own [`Conns`] for the instance its [`ConnCtx`] names. A plugin never states who it
//!   is: the host reads the caller off the context it minted for that instance, so a [`ConnId`] the
//!   caller does not own, a closed one and a need the caller never declared are refused here exactly
//!   as a linked caller is refused.
//! * **PLUGIN side** — [`HostConns`], a plugin's view of the table it was handed: the same six
//!   operations, without the caller.
//!
//! Every slot catches its own panics and answers [`ConnOutcome::Fault`]. What a slot hands back that
//! borrows the host — a piece's status numbering, a connection's facts — stays valid until that
//! connection is closed.

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};

use crate::abi::hot::decl::DeclStr;
use crate::abi::hot::transport::{code, WireConnFacts, WireField};
use crate::conn::{
    ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc, Piece, PieceKind, Ticket,
};
use crate::ids::StreamId;
use crate::transport::wire::CertFacts;
use crate::transport::ConnFacts;

pub mod connector;

/// The outcome byte every connection slot answers ([`ConnOutcome`]); an unknown byte reads as
/// [`ConnOutcome::Fault`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawConnOutcome(pub u8);

/// What a connection slot answered.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnOutcome {
    /// Answered.
    Ok = 0,
    /// [`ConnError::Pending`].
    Pending = 1,
    /// [`ConnError::Timeout`].
    Timeout = 2,
    /// [`ConnError::Closed`].
    Closed = 3,
    /// [`ConnError::NotOwner`].
    NotOwner = 4,
    /// [`ConnError::UndeclaredNeed`].
    UndeclaredNeed = 5,
    /// [`ConnError::Refused`].
    Refused = 6,
    /// [`ConnError::Fault`].
    Fault = 7,
    /// [`ConnError::Unarmed`].
    Unarmed = 8,
}

impl RawConnOutcome {
    /// The outcome of a result.
    #[must_use]
    pub const fn of(r: Result<(), ConnError>) -> Self {
        Self(match r {
            Ok(()) => ConnOutcome::Ok,
            Err(ConnError::Pending) => ConnOutcome::Pending,
            Err(ConnError::Timeout) => ConnOutcome::Timeout,
            Err(ConnError::Closed) => ConnOutcome::Closed,
            Err(ConnError::NotOwner) => ConnOutcome::NotOwner,
            Err(ConnError::UndeclaredNeed) => ConnOutcome::UndeclaredNeed,
            Err(ConnError::Refused) => ConnOutcome::Refused,
            Err(ConnError::Fault) => ConnOutcome::Fault,
            Err(ConnError::Unarmed) => ConnOutcome::Unarmed,
        } as u8)
    }

    /// The result the byte states.
    ///
    /// # Errors
    ///
    /// The refusal the byte names; an unknown byte is [`ConnError::Fault`].
    pub const fn result(self) -> Result<(), ConnError> {
        match self.0 {
            0 => Ok(()),
            1 => Err(ConnError::Pending),
            2 => Err(ConnError::Timeout),
            3 => Err(ConnError::Closed),
            4 => Err(ConnError::NotOwner),
            5 => Err(ConnError::UndeclaredNeed),
            6 => Err(ConnError::Refused),
            8 => Err(ConnError::Unarmed),
            _ => Err(ConnError::Fault),
        }
    }
}

/// The host's context for ONE plugin instance: opaque to the plugin, handed back on every call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnCtx {
    /// The host's per-instance state; never dereferenced by a plugin.
    pub ptr: *mut c_void,
}

/// [`OpenDesc`], borrowed for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireOpenDesc {
    /// `size_of::<WireOpenDesc>()` at construction.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The target (UTF-8).
    pub target: DeclStr,
    /// The head fields.
    pub fields: *const WireField,
    /// How many.
    pub fields_len: usize,
    /// The body.
    pub body: *const u8,
    /// Its length.
    pub body_len: usize,
    /// Milliseconds the open may take; `0` = the host's default.
    pub timeout_ms: u64,
    /// [`OpenDesc::method`], appended: a descriptor whose `size` ends before it states none.
    pub method: DeclStr,
    /// [`OpenDesc::head_target`], appended: a descriptor whose `size` ends before it states none.
    pub head_target: DeclStr,
}

/// A [`WireOpenDesc`] as a descriptor without the appended head words states it: read from a
/// plugin whose `size` ends at [`OPEN_DESC_HEADLESS`], never past it.
#[repr(C)]
#[derive(Clone, Copy)]
struct Headless {
    size: u32,
    _reserved: u32,
    target: DeclStr,
    fields: *const WireField,
    fields_len: usize,
    body: *const u8,
    body_len: usize,
    timeout_ms: u64,
}

impl Headless {
    const fn into_wire(self) -> WireOpenDesc {
        WireOpenDesc {
            size: self.size,
            _reserved: self._reserved,
            target: self.target,
            fields: self.fields,
            fields_len: self.fields_len,
            body: self.body,
            body_len: self.body_len,
            timeout_ms: self.timeout_ms,
            method: DeclStr::NONE,
            head_target: DeclStr::NONE,
        }
    }
}

const _: () = assert!(core::mem::size_of::<Headless>() == OPEN_DESC_HEADLESS);

/// How much of a [`WireOpenDesc`] a sized descriptor must state: everything before the appended
/// head words ([`WireOpenDesc::method`], [`WireOpenDesc::head_target`]), which a shorter one
/// states as none.
pub const OPEN_DESC_HEADLESS: usize = core::mem::offset_of!(WireOpenDesc, method);

/// [`Piece`], written by the host into the caller's slot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WirePiece {
    /// `size_of::<WirePiece>()` at construction.
    pub size: u32,
    /// [`PieceKind`]: `0` body, `1` fields, `2` hook reply, `3` completion.
    pub kind: u8,
    /// `1` = the piece ends its frame.
    pub end: u8,
    /// The status class (`code::status_class`; `0` = none).
    pub status_class: u8,
    /// [`PIECE_HAS_CODE`] | [`PIECE_HAS_RETRY_AFTER`].
    pub flags: u8,
    /// The stream.
    pub stream: u64,
    /// How many bytes of the caller's buffer it filled.
    pub len: usize,
    /// The exact status number.
    pub code: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The status numbering (NULL = none); valid until the connection closes.
    pub ns: DeclStr,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: u64,
    /// [`Piece::reason`]: a range of the caller's buffer (`len == 0` = none).
    pub reason: crate::abi::transport::FrameSpan,
}

/// [`WirePiece::flags`]: the status number is present.
pub const PIECE_HAS_CODE: u8 = 1;
/// [`WirePiece::flags`]: the retry-after is present.
pub const PIECE_HAS_RETRY_AFTER: u8 = 2;

/// The `write` slot's `end` byte: the bytes are a text message ([`Conns::write`]'s `text`).
pub const WRITE_TEXT: u8 = 2;

slot_table! {
/// THE CONNECTION TABLE: one slot per [`Conns`] method, named for it.
pub struct ConnSlots lowers Conns -> RawConnOutcome {
    /// [`Conns::open`]: writes the connection.
    open: ConnOpenFn = fn(ctx: ConnCtx, need: u32, desc: *const WireOpenDesc, out_conn: *mut u64);
    /// [`Conns::write`]: writes how many were taken. `end` is `0`/`1`, with [`WRITE_TEXT`] set for a
    /// text message.
    write: ConnWriteFn = fn(ctx: ConnCtx, conn: u64, bytes: *const u8, len: usize, end: u8,
        out_written: *mut usize);
    /// [`Conns::read`]: the piece's bytes into `buf`, the piece into `out_piece`; with nothing
    /// ready, pending with interest registered under `ticket`.
    read: ConnReadFn = fn(ctx: ConnCtx, conn: u64, ticket: u64, buf: *mut u8, cap: usize,
        out_piece: *mut WirePiece);
    /// [`Conns::wait`]: writes the position of a ready connection in the set; with none ready,
    /// pending with interest registered under `ticket`.
    wait: ConnWaitFn = fn(ctx: ConnCtx, set: *const u64, set_len: usize, ticket: u64,
        out_ready: *mut usize);
    /// [`Conns::facts`]: the facts, borrowed until the connection closes.
    facts: ConnFactsFn = fn(ctx: ConnCtx, conn: u64, out_facts: *mut WireConnFacts);
    /// [`Conns::close`].
    close: ConnCloseFn = fn(ctx: ConnCtx, conn: u64);
}
}

// ── HOST SIDE ────────────────────────────────────────────────────────────────────────────────────

/// What a host keeps for one plugin instance, behind the [`ConnCtx`] it hands that instance: its
/// connection table, the instance it serves, and what a slot handed back that borrows the host.
///
/// The state lives on the heap and the [`ConnCtx`] points at it, never at the `ConnHost` itself, so
/// moving a `ConnHost` after minting its context (returning it from a helper, pushing it into a
/// vector) leaves every context valid.
pub struct ConnHost {
    state: Box<HostState>,
}

/// The heap-stable state behind a [`ConnHost`]: what its [`ConnCtx`] points at.
struct HostState {
    conns: Arc<dyn Conns>,
    instance: InstanceId,
    held: Mutex<HashMap<ConnId, Held>>,
}

/// What the host holds for a connection so the plugin's borrows stay valid until it closes.
#[derive(Default)]
struct Held {
    facts: Option<ConnFacts>,
    ns: Option<String>,
}

impl std::fmt::Debug for ConnHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnHost")
            .field("instance", &self.state.instance)
            .finish_non_exhaustive()
    }
}

impl ConnHost {
    /// The host's state for `instance` over `conns`.
    #[must_use]
    pub fn new(conns: Arc<dyn Conns>, instance: InstanceId) -> Self {
        Self {
            state: Box::new(HostState {
                conns,
                instance,
                held: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The context the host hands `self`'s instance: a pointer to the heap-stable state, valid
    /// wherever `self` moves. `self` must outlive every call made with it.
    #[must_use]
    pub fn ctx(&self) -> ConnCtx {
        ConnCtx {
            ptr: (&*self.state as *const HostState).cast_mut().cast(),
        }
    }
}

impl HostState {
    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<ConnId, Held>> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The table a host hands every plugin instance.
#[must_use]
pub const fn host_slots() -> ConnSlots {
    ConnSlots {
        size: core::mem::size_of::<ConnSlots>() as u32,
        _reserved: 0,
        open: Some(host_open),
        write: Some(host_write),
        read: Some(host_read),
        wait: Some(host_wait),
        facts: Some(host_facts),
        close: Some(host_close),
    }
}

/// Run a host slot body over the instance's state, answering the fault byte for a panic or a null
/// context.
fn hosted(ctx: ConnCtx, body: impl FnOnce(&HostState) -> Result<(), ConnError>) -> RawConnOutcome {
    RawConnOutcome::of(
        crate::abi::sdk::boundary::caught(|| {
            // SAFETY: a non-null context is the `HostState` of the `ConnHost` the host minted it from
            // (`ConnHost::ctx`),
            // alive for the call.
            let host = unsafe { ctx.ptr.cast::<HostState>().as_ref() }.ok_or(ConnError::Fault)?;
            body(host)
        })
        .unwrap_or(Err(ConnError::Fault)),
    )
}

/// A borrowed byte range (NULL only when empty).
///
/// # Safety
/// `ptr`, when non-null, must address `len` readable bytes for the call.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], ConnError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ConnError::Fault);
    }
    // SAFETY: per this fn's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// A borrowed [`DeclStr`] as text (`None` for NULL).
///
/// # Safety
/// A non-null range must address `len` readable bytes for the call.
unsafe fn text<'a>(d: DeclStr) -> Result<Option<&'a str>, ConnError> {
    if d.ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: per this fn's contract.
    std::str::from_utf8(unsafe { bytes(d.ptr, d.len) }?)
        .map(Some)
        .map_err(|_| ConnError::Fault)
}

/// Write one out-param.
///
/// # Safety
/// `out`, when non-null, must address a writable `T`.
unsafe fn set<T>(out: *mut T, v: T) -> Result<(), ConnError> {
    if out.is_null() {
        return Err(ConnError::Fault);
    }
    // SAFETY: per this fn's contract.
    unsafe { out.write(v) };
    Ok(())
}

/// A range the host holds, borrowed.
fn range(s: &str) -> DeclStr {
    DeclStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

extern "C-unwind" fn host_open(
    ctx: ConnCtx,
    need: u32,
    desc: *const WireOpenDesc,
    out_conn: *mut u64,
) -> RawConnOutcome {
    hosted(ctx, |host| {
        if desc.is_null() {
            return Err(ConnError::Fault);
        }
        // SAFETY: the plugin's live sized descriptor and its ranges, for the call; read only as far
        // as it attests.
        unsafe {
            let size = core::ptr::read_unaligned(core::ptr::addr_of!((*desc).size)) as usize;
            if size < OPEN_DESC_HEADLESS {
                return Err(ConnError::Fault);
            }
            // The head words are read only where the descriptor's size states them.
            let d = if size >= core::mem::size_of::<WireOpenDesc>() {
                core::ptr::read_unaligned(desc)
            } else {
                core::ptr::read_unaligned(desc.cast::<Headless>()).into_wire()
            };
            if d.fields.is_null() && d.fields_len != 0 {
                return Err(ConnError::Fault);
            }
            let fields = (0..d.fields_len)
                .map(|i| {
                    let f = core::ptr::read_unaligned(d.fields.add(i));
                    let name = text(f.name)?.ok_or(ConnError::Fault)?;
                    Ok((name, bytes(f.value.ptr, f.value.len)?))
                })
                .collect::<Result<Vec<_>, ConnError>>()?;
            let conn = host.conns.open(
                host.instance,
                NeedId(need),
                &OpenDesc {
                    target: text(d.target)?.unwrap_or(""),
                    fields: &fields,
                    body: bytes(d.body, d.body_len)?,
                    timeout_ms: d.timeout_ms,
                    method: bytes(d.method.ptr, d.method.len)?,
                    head_target: bytes(d.head_target.ptr, d.head_target.len)?,
                    // A pin is stated through the connector's ESTABLISH (`EstablishIn::within`).
                    within: &[],
                    // So is a registration (`EstablishIn::member`).
                    member: "",
                },
            )?;
            set(out_conn, conn.0)
        }
    })
}

extern "C-unwind" fn host_write(
    ctx: ConnCtx,
    conn: u64,
    buf: *const u8,
    len: usize,
    end: u8,
    out_written: *mut usize,
) -> RawConnOutcome {
    hosted(ctx, |host| {
        // SAFETY: the plugin's live range and out-slot, for the call.
        unsafe {
            let n = host.conns.write(
                host.instance,
                ConnId(conn),
                bytes(buf, len)?,
                end & 1 == 1,
                end & WRITE_TEXT != 0,
            )?;
            set(out_written, n)
        }
    })
}

extern "C-unwind" fn host_read(
    ctx: ConnCtx,
    conn: u64,
    ticket: u64,
    buf: *mut u8,
    cap: usize,
    out_piece: *mut WirePiece,
) -> RawConnOutcome {
    hosted(ctx, |host| {
        if out_piece.is_null() || (buf.is_null() && cap != 0) {
            return Err(ConnError::Fault);
        }
        // SAFETY: the plugin's live writable range and out-slot, for the call.
        let into: &mut [u8] = if cap == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(buf, cap) }
        };
        let piece = host.conns.read(host.instance, ConnId(conn), ticket, into)?;
        if piece.len > cap
            || piece
                .reason
                .as_ref()
                .is_some_and(|r| r.start > r.end || r.end > cap)
        {
            return Err(ConnError::Fault);
        }
        // The numbering is held until the connection closes, so the plugin's borrow outlives the
        // call.
        let ns = {
            let mut held = host.held();
            let entry = held.entry(ConnId(conn)).or_default();
            entry.ns = piece.status_namespace.clone();
            entry.ns.as_deref().map_or(DeclStr::NONE, range)
        };
        let mut flags = 0;
        if piece.status_code.is_some() {
            flags |= PIECE_HAS_CODE;
        }
        if piece.retry_after_secs.is_some() {
            flags |= PIECE_HAS_RETRY_AFTER;
        }
        // SAFETY: the plugin's out-slot, checked non-null above.
        unsafe {
            set(
                out_piece,
                WirePiece {
                    size: core::mem::size_of::<WirePiece>() as u32,
                    kind: piece_kind(piece.kind),
                    end: u8::from(piece.end),
                    status_class: code::status_class(piece.status),
                    flags,
                    stream: piece.stream.0,
                    len: piece.len,
                    code: piece.status_code.unwrap_or(0),
                    _reserved: 0,
                    ns,
                    retry_after_secs: piece.retry_after_secs.unwrap_or(0),
                    reason: piece.reason.as_ref().map_or_else(Default::default, |r| {
                        crate::abi::transport::FrameSpan {
                            offset: r.start as u64,
                            len: (r.end - r.start) as u64,
                        }
                    }),
                },
            )
        }
    })
}

extern "C-unwind" fn host_wait(
    ctx: ConnCtx,
    set_ptr: *const u64,
    set_len: usize,
    ticket: u64,
    out_ready: *mut usize,
) -> RawConnOutcome {
    hosted(ctx, |host| {
        if set_ptr.is_null() && set_len != 0 {
            return Err(ConnError::Fault);
        }
        // SAFETY: the plugin's live `set_len` ids, for the call.
        let ids: Vec<ConnId> = (0..set_len)
            .map(|i| ConnId(unsafe { core::ptr::read_unaligned(set_ptr.add(i)) }))
            .collect();
        let ready = host.conns.wait(host.instance, &ids, ticket)?;
        // SAFETY: the plugin's out-slot.
        unsafe { set(out_ready, ready) }
    })
}

extern "C-unwind" fn host_facts(
    ctx: ConnCtx,
    conn: u64,
    out_facts: *mut WireConnFacts,
) -> RawConnOutcome {
    hosted(ctx, |host| {
        let facts = host.conns.facts(host.instance, ConnId(conn))?;
        let mut held = host.held();
        let entry = held.entry(ConnId(conn)).or_default();
        let f = entry.facts.insert(facts);
        let opt = |s: Option<&String>| s.map_or(DeclStr::NONE, |s| range(s));
        let cert = f.peer_cert.as_ref();
        // SAFETY: the plugin's out-slot; every range borrows what the host holds until close.
        unsafe {
            set(
                out_facts,
                WireConnFacts {
                    size: core::mem::size_of::<WireConnFacts>() as u32,
                    version: 0,
                    sni: opt(f.sni.as_ref()),
                    alpn: opt(f.alpn.as_ref()),
                    cert_subject: opt(cert.map(|c| &c.subject)),
                    cert_issuer: opt(cert.map(|c| &c.issuer)),
                    cert_fingerprint: opt(cert.map(|c| &c.fingerprint)),
                    claim: opt(f.claim.as_ref()),
                },
            )
        }
    })
}

extern "C-unwind" fn host_close(ctx: ConnCtx, conn: u64) -> RawConnOutcome {
    hosted(ctx, |host| {
        host.conns.close(host.instance, ConnId(conn))?;
        host.held().remove(&ConnId(conn));
        Ok(())
    })
}

const fn piece_kind(k: PieceKind) -> u8 {
    match k {
        PieceKind::Body => 0,
        PieceKind::Fields => 1,
        PieceKind::HookReply => 2,
        PieceKind::Completion => 3,
    }
}

const fn piece_kind_of(b: u8) -> Option<PieceKind> {
    Some(match b {
        0 => PieceKind::Body,
        1 => PieceKind::Fields,
        2 => PieceKind::HookReply,
        3 => PieceKind::Completion,
        _ => return None,
    })
}

// ── PLUGIN SIDE ──────────────────────────────────────────────────────────────────────────────────

/// A plugin's view of the connection table it was handed: the six operations, without the caller —
/// the host knows who is calling from `ctx`.
#[derive(Debug, Clone, Copy)]
pub struct HostConns {
    slots: ConnSlots,
    ctx: ConnCtx,
}

// SAFETY: the table is plain code addresses and the context an opaque handle the host guarantees
// for the plugin's life; every call goes through the host's own synchronisation.
unsafe impl Send for HostConns {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for HostConns {}

impl HostConns {
    /// The table `slots` over the context `ctx` the host handed this instance.
    ///
    /// # Safety
    /// `slots` must be the host's table and `ctx` the context it minted for this instance, both live
    /// for every call made through the value.
    #[must_use]
    pub const unsafe fn new(slots: ConnSlots, ctx: ConnCtx) -> Self {
        Self { slots, ctx }
    }

    /// [`Conns::open`], for this instance.
    ///
    /// # Errors
    ///
    /// As [`Conns::open`].
    pub fn open(&self, need: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        let f = self.slots.open.ok_or(ConnError::Fault)?;
        let fields: Vec<WireField> = desc
            .fields
            .iter()
            .map(|(name, value)| WireField {
                name: range(name),
                value: DeclStr {
                    ptr: value.as_ptr(),
                    len: value.len(),
                },
            })
            .collect();
        let wire = WireOpenDesc {
            size: core::mem::size_of::<WireOpenDesc>() as u32,
            _reserved: 0,
            target: range(desc.target),
            fields: fields.as_ptr(),
            fields_len: fields.len(),
            body: desc.body.as_ptr(),
            body_len: desc.body.len(),
            timeout_ms: desc.timeout_ms,
            method: DeclStr {
                ptr: desc.method.as_ptr(),
                len: desc.method.len(),
            },
            head_target: DeclStr {
                ptr: desc.head_target.as_ptr(),
                len: desc.head_target.len(),
            },
        };
        let mut conn = 0_u64;
        f(self.ctx, need.0, &wire, &mut conn).result()?;
        Ok(ConnId(conn))
    }

    /// [`Conns::write`], for this instance.
    ///
    /// # Errors
    ///
    /// As [`Conns::write`].
    pub fn write(
        &self,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let f = self.slots.write.ok_or(ConnError::Fault)?;
        let mut n = 0_usize;
        f(
            self.ctx,
            conn.0,
            bytes.as_ptr(),
            bytes.len(),
            u8::from(end) | if text { WRITE_TEXT } else { 0 },
            &mut n,
        )
        .result()?;
        Ok(n)
    }

    /// [`Conns::read`], for this instance.
    ///
    /// # Errors
    ///
    /// As [`Conns::read`].
    pub fn read(&self, conn: ConnId, ticket: Ticket, buf: &mut [u8]) -> Result<Piece, ConnError> {
        let f = self.slots.read.ok_or(ConnError::Fault)?;
        let mut p = core::mem::MaybeUninit::<WirePiece>::zeroed();
        f(
            self.ctx,
            conn.0,
            ticket,
            buf.as_mut_ptr(),
            buf.len(),
            p.as_mut_ptr(),
        )
        .result()?;
        // SAFETY: an `Ok` answer wrote the piece; every field is valid zeroed besides.
        let p = unsafe { p.assume_init() };
        if p.len > buf.len() {
            return Err(ConnError::Fault);
        }
        // SAFETY: the host's numbering, borrowed until the connection closes; copied out now.
        let ns = unsafe { text(p.ns) }?.map(str::to_string);
        Ok(Piece {
            kind: piece_kind_of(p.kind).ok_or(ConnError::Fault)?,
            stream: StreamId(p.stream),
            len: p.len,
            end: p.end == 1,
            status: code::status_class_of(p.status_class).map_err(|_| ConnError::Fault)?,
            status_code: (p.flags & PIECE_HAS_CODE != 0).then_some(p.code),
            status_namespace: ns,
            retry_after_secs: (p.flags & PIECE_HAS_RETRY_AFTER != 0).then_some(p.retry_after_secs),
            reason: match p.reason.len {
                0 => None,
                n => {
                    let at = usize::try_from(p.reason.offset).map_err(|_| ConnError::Fault)?;
                    let end = at
                        .checked_add(usize::try_from(n).map_err(|_| ConnError::Fault)?)
                        .filter(|e| *e <= buf.len())
                        .ok_or(ConnError::Fault)?;
                    Some(at..end)
                }
            },
        })
    }

    /// [`Conns::wait`], for this instance.
    ///
    /// # Errors
    ///
    /// As [`Conns::wait`].
    pub fn wait(&self, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        let f = self.slots.wait.ok_or(ConnError::Fault)?;
        let ids: Vec<u64> = set.iter().map(|c| c.0).collect();
        let mut ready = 0_usize;
        f(self.ctx, ids.as_ptr(), ids.len(), ticket, &mut ready).result()?;
        Ok(ready)
    }

    /// [`Conns::facts`], for this instance.
    ///
    /// # Errors
    ///
    /// As [`Conns::facts`].
    pub fn facts(&self, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let f = self.slots.facts.ok_or(ConnError::Fault)?;
        let mut w = core::mem::MaybeUninit::<WireConnFacts>::zeroed();
        f(self.ctx, conn.0, w.as_mut_ptr()).result()?;
        // SAFETY: an `Ok` answer wrote the facts; every range borrows the host until close, and is
        // copied out now.
        unsafe {
            let w = w.assume_init();
            let owned = |d: DeclStr| text(d).map(|t| t.map(str::to_string));
            let peer_cert = match owned(w.cert_fingerprint)? {
                Some(fingerprint) => Some(CertFacts {
                    subject: owned(w.cert_subject)?.unwrap_or_default(),
                    issuer: owned(w.cert_issuer)?.unwrap_or_default(),
                    fingerprint,
                }),
                None => None,
            };
            Ok(ConnFacts {
                sni: owned(w.sni)?,
                alpn: owned(w.alpn)?,
                peer_cert,
                claim: owned(w.claim)?,
                // The far end's key pin and whether busbar presented its client identity reach a
                // plugin on the host connector's FACTS service (`connector::StreamFacts`), not here.
                ..ConnFacts::default()
            })
        }
    }

    /// [`Conns::close`], for this instance.
    ///
    /// # Errors
    ///
    /// As [`Conns::close`].
    pub fn close(&self, conn: ConnId) -> Result<(), ConnError> {
        let f = self.slots.close.ok_or(ConnError::Fault)?;
        f(self.ctx, conn.0).result()
    }
}

#[cfg(test)]
#[path = "../../tests/conn_lowering_tests.rs"]
mod tests;
