// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR, DRIVEN OVER ITS OWN ABI as the kernel's plane driver drives it: `open`, `refresh`,
//! `arrive`, `on_piece`, `refusal` and `cancel`, each a frame of plain C data crossing the door's
//! table. The decisions door calls no host service, so the host tables it is opened with are empty.

#![allow(dead_code)]

use std::os::raw::c_void;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, Outcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, OpenIn, OpenOut, OpsHead, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProviderFacts, RecordWrite,
    RefusalIn, RefusalOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END,
    FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, REFUSAL_ARRIVE, REFUSAL_KERNEL,
};
use busbar_plane_decisions::plane_door::door;

pub fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

fn str_of(s: &[u8]) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn read(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the door's memory, valid until the instance's next call.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

fn head<T>(op: u32, ticket: Ticket) -> InHead {
    InHead {
        size: std::mem::size_of::<T>() as u32,
        op,
        ticket,
        ..z()
    }
}

fn out_head<T>() -> OutHead {
    OutHead {
        size: std::mem::size_of::<T>() as u32,
        ..z()
    }
}

fn ops() -> &'static Ops {
    // SAFETY: the door is a `'static` table whose ops are the plane kind's.
    unsafe { &*(*door()).ops.cast::<Ops>() }
}

fn lifecycle() -> &'static OpsHead {
    &ops().head
}

struct Tables(HostTables);
// SAFETY: the tables name no function and no memory.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx::NONE,
    wake: None,
    conns: std::ptr::null(),
    io: std::ptr::null(),
    services: std::ptr::null(),
});

/// The claims a snapshot publishes, `(verb, target)`.
fn claims_of(snapshot: *const PlaneSnapshot) -> Vec<(String, String)> {
    if snapshot.is_null() {
        return Vec::new();
    }
    // SAFETY: the door's snapshot, valid until its generation retires.
    let s = unsafe { &*snapshot };
    if s.claims.is_null() {
        return Vec::new();
    }
    // SAFETY: as above, `claims_len` claims.
    unsafe { std::slice::from_raw_parts(s.claims, s.claims_len) }
        .iter()
        .map(|c| (read(c.verb), read(c.target)))
        .collect()
}

/// The ticket a unit's pieces are pushed on: one per unit.
pub fn ticket_of(unit: u64) -> Ticket {
    Ticket {
        slot: u32::try_from(unit).expect("a small unit"),
        generation: 1,
    }
}

/// One opened instance of the door.
pub struct Door {
    instance: *mut c_void,
    /// The first generation's claims.
    pub claims: Vec<(String, String)>,
}

/// Open the door over `settings` (the `decisions:` section, as written).
pub fn open(settings: &str) -> Door {
    open_with(settings, &[])
}

/// Open the door over `settings`, the host stating each referenced provider's `(name, protocol)`.
pub fn open_with(settings: &str, providers: &[(&str, &str)]) -> Door {
    let facts: Vec<ProviderFacts> = providers
        .iter()
        .map(|(name, protocol)| ProviderFacts {
            name: str_of(name.as_bytes()),
            protocol: str_of(protocol.as_bytes()),
            error_map: Blob::ABSENT,
        })
        .collect();
    let mut err = [0_u8; 1024];
    let mut i: PlaneOpenIn = z();
    i.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: &TABLES.0,
        settings: octets(settings.as_bytes()),
        generation: 1,
        err_buf: err.as_mut_ptr(),
        err_cap: err.len(),
        ..z()
    };
    (i.providers, i.providers_len) = (facts.as_ptr(), facts.len());
    let mut o: PlaneOpenOut = z();
    o.open = OpenOut {
        head: out_head::<PlaneOpenOut>(),
        ..z()
    };
    let f = lifecycle().open.expect("the door opens");
    let ret = f(
        std::ptr::null_mut(),
        std::ptr::from_ref(&i).cast(),
        std::ptr::from_mut(&mut o).cast(),
    );
    assert_eq!(
        ret.outcome(),
        Outcome::Ready,
        "the door opens over {settings}"
    );
    Door {
        instance: o.open.instance,
        claims: claims_of(o.snapshot),
    }
}

/// `validate` of the dealt blob `{decisions: <settings>}`: the outcome and its words.
pub fn validate(settings: &str) -> (Outcome, String) {
    let dealt = format!("{{\"decisions\":{settings}}}");
    let mut err = [0_u8; 1024];
    let mut i: ValidateIn = z();
    i.head = head::<ValidateIn>(life::VALIDATE, Ticket::NONE);
    i.settings = octets(dealt.as_bytes());
    (i.err_buf, i.err_cap) = (err.as_mut_ptr(), err.len());
    let mut o: OutHead = out_head::<OutHead>();
    let f = lifecycle().validate.expect("validate");
    let ret = f(
        std::ptr::null_mut(),
        std::ptr::from_ref(&i).cast(),
        std::ptr::from_mut(&mut o).cast(),
    );
    (ret.outcome(), read(o.error))
}

/// What `arrive` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrived {
    pub outcome: Outcome,
    /// The plane's own refusal code, `0` unless refused.
    pub refusal: u32,
    /// The status a refusal wears.
    pub status: u32,
    /// The refusal's words (`head.error`).
    pub text: String,
    /// The route class and the entry it names.
    pub route: u8,
    pub entry: String,
}

/// What one `on_piece` answered, re-called while it said `more`.
#[derive(Debug, Clone, Default)]
pub struct Answered {
    pub outcome: Option<Outcome>,
    /// The bytes emitted, over every re-call.
    pub bytes: Vec<u8>,
    /// The bytes were bound for the far end.
    pub far: bool,
    /// The answer said done.
    pub done: bool,
    /// The reply status.
    pub status: u32,
    /// The request line of an ATTEMPT, `"<verb> <target>"`.
    pub request: String,
    /// The head fields written, `(name, value)`.
    pub fields: Vec<(String, String)>,
    /// The units written, `(class, source, amount)`.
    pub units: Vec<(u32, u32, u64)>,
    /// Short-answer needs, when the answer was short.
    pub short: bool,
}

/// One piece as the kernel pushes it.
#[derive(Debug, Clone, Copy)]
pub struct Given<'a> {
    pub from: u32,
    pub flags: u32,
    pub status: u32,
    pub attempt: u32,
    pub bytes: &'a [u8],
    /// The dialect `arrive` answered, carried on every piece.
    pub dialect: u32,
}

impl<'a> Given<'a> {
    /// The ATTEMPT piece of attempt `n`.
    pub const fn attempt(n: u32) -> Self {
        Self {
            from: FROM_KERNEL,
            flags: 0,
            status: 0,
            attempt: n,
            bytes: b"",
            dialect: 0,
        }
    }

    /// The caller's whole body.
    pub const fn caller(bytes: &'a [u8]) -> Self {
        Self {
            from: FROM_CALLER,
            flags: PIECE_LAST,
            status: 0,
            attempt: 0,
            bytes,
            dialect: 0,
        }
    }

    /// The far end's whole answer, its status on it.
    pub const fn whole(status: u32, bytes: &'a [u8]) -> Self {
        Self {
            from: FROM_FAR_END,
            flags: PIECE_HAS_STATUS | PIECE_LAST,
            status,
            attempt: 0,
            bytes,
            dialect: 0,
        }
    }

    /// One piece of the far end's answer: the first carries `status`, the last says so.
    pub const fn far(first: Option<u32>, last: bool, bytes: &'a [u8]) -> Self {
        let mut flags = 0;
        let mut status = 0;
        if let Some(s) = first {
            flags |= PIECE_HAS_STATUS;
            status = s;
        }
        if last {
            flags |= PIECE_LAST;
        }
        Self {
            from: FROM_FAR_END,
            flags,
            status,
            attempt: 0,
            bytes,
            dialect: 0,
        }
    }
}

/// The host buffers one `on_piece` is lent, reused across calls so a measured call allocates only
/// what the door does.
pub struct Bufs {
    reply: Vec<u8>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
    records: Vec<RecordWrite>,
    units: Vec<UnitCount>,
}

impl Bufs {
    pub fn new(reply_cap: usize) -> Self {
        Self {
            reply: vec![0; reply_cap],
            fields: vec![z(); 16],
            arena: vec![0; 1 << 14],
            records: vec![z(); 4],
            units: vec![z(); 8],
        }
    }
}

impl Door {
    /// `refresh` onto `generation` over `settings`: the new generation's claims.
    pub fn refresh(&self, settings: &str, generation: u64) -> Vec<(String, String)> {
        let mut i: RefreshIn = z();
        i.head = head::<RefreshIn>(life::REFRESH, Ticket::NONE);
        i.generation = generation;
        i.settings = octets(settings.as_bytes());
        let mut o: PlaneRefreshOut = z();
        o.head = out_head::<PlaneRefreshOut>();
        let f = lifecycle().refresh.expect("refresh");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        assert_eq!(ret.outcome(), Outcome::Ready, "the door refreshes");
        claims_of(o.snapshot)
    }

    /// `arrive` of `unit` on `POST /v1/systemone` with `body`.
    pub fn arrive(&self, unit: u64, body: &[u8]) -> Arrived {
        self.arrive_on(unit, "POST", "/v1/systemone", body, &[])
    }

    /// `arrive` of `unit` on `verb target` with `body` and the caller's `fields`.
    pub fn arrive_on(
        &self,
        unit: u64,
        verb: &str,
        target: &str,
        body: &[u8],
        fields: &[(&str, &str)],
    ) -> Arrived {
        let fields: Vec<Field> = fields
            .iter()
            .map(|(n, v)| Field {
                name: str_of(n.as_bytes()),
                value: str_of(v.as_bytes()),
            })
            .collect();
        let mut i: ArriveIn = z();
        i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        i.unit = unit;
        i.target = str_of(target.as_bytes());
        i.method = str_of(verb.as_bytes());
        i.body = octets(body);
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        let mut units = [z::<UnitCount>(); 4];
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: ArriveOut = z();
        o.head = out_head::<ArriveOut>();
        let f = ops().arrive.expect("arrive");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        Arrived {
            outcome: ret.outcome(),
            refusal: o.refusal,
            status: o.refusal_status,
            text: read(o.head.error),
            route: o.route,
            entry: read(o.pool),
        }
    }

    /// One piece of `unit` on its ticket, re-called while the door says `more`.
    pub fn piece(&self, unit: u64, given: Given<'_>, bufs: &mut Bufs) -> Answered {
        let ticket = ticket_of(unit);
        let mut got = Answered::default();
        let mut first = true;
        for _ in 0..1024 {
            let mut i: OnPieceIn = z();
            i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket);
            i.unit = unit;
            i.from = given.from;
            i.dialect = given.dialect;
            if first {
                i.flags = given.flags;
                i.bytes = octets(given.bytes);
                i.status_code = given.status;
                i.attempt_no = given.attempt;
            } else {
                i.bytes = octets(b"");
            }
            (i.reply_buf, i.reply_cap) = (bufs.reply.as_mut_ptr(), bufs.reply.len());
            (i.fields_buf, i.fields_cap) = (bufs.fields.as_mut_ptr(), bufs.fields.len());
            (i.arena_buf, i.arena_cap) = (bufs.arena.as_mut_ptr(), bufs.arena.len());
            (i.records_buf, i.records_cap) = (bufs.records.as_mut_ptr(), bufs.records.len());
            (i.units_buf, i.units_cap) = (bufs.units.as_mut_ptr(), bufs.units.len());
            let mut o: OnPieceOut = z();
            o.head = out_head::<OnPieceOut>();
            let f = ops().on_piece.expect("on_piece");
            let ret = f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            );
            first = false;
            got.outcome = Some(ret.outcome());
            got.short |= o.units_needed != 0 || o.fields_needed != 0 || o.arena_needed != 0;
            if o.reply_status != 0 {
                got.status = o.reply_status;
            }
            let arena = &bufs.arena;
            let at = |s: Span| {
                let from = s.offset as usize;
                String::from_utf8_lossy(&arena[from..from + s.len as usize]).into_owned()
            };
            if ret.outcome() == Outcome::Ready {
                got.fields.extend(
                    bufs.fields[..o.fields_written as usize]
                        .iter()
                        .map(|f| (at(f.name), at(f.value))),
                );
                got.units.extend(
                    bufs.units[..o.units_written as usize]
                        .iter()
                        .map(|u| (u.class, u.source, u.amount)),
                );
                if o.verb.len != 0 {
                    got.request = format!("{} {}", at(o.verb), at(o.target));
                }
            }
            got.far |= o.flags & EMIT_TO_FAR_END != 0;
            got.done |= o.flags & EMIT_DONE != 0;
            got.bytes
                .extend_from_slice(&bufs.reply[..usize::try_from(o.emitted).unwrap()]);
            if ret.outcome() != Outcome::Ready || o.more == 0 {
                break;
            }
        }
        got
    }

    /// One crossing of `unit`'s piece that keeps nothing of the answer (so it allocates nothing
    /// of its own): the bytes emitted. The answer must fit and be READY.
    pub fn piece_bytes(&self, unit: u64, given: Given<'_>, bufs: &mut Bufs) -> usize {
        let mut i: OnPieceIn = z();
        i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket_of(unit));
        i.unit = unit;
        i.from = given.from;
        i.dialect = given.dialect;
        i.flags = given.flags;
        i.bytes = octets(given.bytes);
        i.status_code = given.status;
        i.attempt_no = given.attempt;
        (i.reply_buf, i.reply_cap) = (bufs.reply.as_mut_ptr(), bufs.reply.len());
        (i.fields_buf, i.fields_cap) = (bufs.fields.as_mut_ptr(), bufs.fields.len());
        (i.arena_buf, i.arena_cap) = (bufs.arena.as_mut_ptr(), bufs.arena.len());
        (i.records_buf, i.records_cap) = (bufs.records.as_mut_ptr(), bufs.records.len());
        (i.units_buf, i.units_cap) = (bufs.units.as_mut_ptr(), bufs.units.len());
        let mut o: OnPieceOut = z();
        o.head = out_head::<OnPieceOut>();
        let f = ops().on_piece.expect("on_piece");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        assert!(ret.outcome() == Outcome::Ready && o.more == 0);
        usize::try_from(o.emitted).unwrap()
    }

    /// `refusal` of `unit` (`0`: none arrived) at `status` with the kernel's `text`; `arrived`
    /// says the refusal is the plane's own arrival's. Answers the outcome and the rendered body.
    pub fn refusal(&self, unit: u64, status: u32, text: &str, arrived: bool) -> (Outcome, Vec<u8>) {
        let (mut reply, mut arena) = (vec![0_u8; 4096], vec![0_u8; 1024]);
        let mut fields = [z::<OutField>(); 4];
        let mut i: RefusalIn = z();
        i.head = head::<RefusalIn>(slot::REFUSAL, Ticket::NONE);
        i.cause = if arrived {
            REFUSAL_ARRIVE
        } else {
            REFUSAL_KERNEL
        };
        i.status = status;
        i.text = str_of(text.as_bytes());
        i.unit = unit;
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let mut o: RefusalOut = z();
        o.head = out_head::<RefusalOut>();
        let f = ops().refusal.expect("refusal");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        let n = usize::try_from(o.reply_written).unwrap().min(reply.len());
        (ret.outcome(), reply[..n].to_vec())
    }

    /// `cancel` of the op on `ticket`: the outcome and the disposition.
    pub fn cancel(&self, ticket: Ticket) -> (Outcome, u32) {
        let mut records = [z::<RecordWrite>(); 4];
        let mut arena = [0_u8; 256];
        let mut i: PlaneCancelIn = z();
        i.cancel = CancelIn {
            head: head::<PlaneCancelIn>(life::CANCEL, ticket),
            ticket,
        };
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let mut o: PlaneCancelOut = z();
        o.cancel = CancelOut {
            head: out_head::<PlaneCancelOut>(),
            ..z()
        };
        let f = lifecycle().cancel.expect("cancel");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        (ret.outcome(), o.cancel.disposition)
    }
}
