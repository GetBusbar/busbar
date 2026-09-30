// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND: `abi/plane/`. Every answer is judged by its kind's own check:
//!
//! * `arrive` by `check_arrive`, its units over the host's `units_buf`/`units_cap`;
//! * `on_piece` by `check_on_piece`, its units, records and fields over the host's buffers, every
//!   cap from `OnPieceIn`;
//! * `refusal` by `check_refusal` and `serve` by `check_serve`, their fields over the host's
//!   `fields_buf`/`fields_cap`, every cap from the op's `in`;
//! * `project` by `check_project`, its view's signals over the host's `signals_buf`/`signals_cap`
//!   and its strings and body over the host's `arena_buf`/`arena_cap`, from `ProjectIn`;
//! * `open` and `refresh` by `check_snapshot` on the generation snapshot a READY answer carries,
//!   against the generation the `in` names;
//! * `cancel` by `check_cancel` on its disposition (answered on READY only);
//! * `drive` by `check_drive`, its ready sessions over the host's `sessions_cap` from
//!   `PlaneDriveIn`.
//!
//! Every outcome is judged; each check decides what an outcome carries. A snapshot is read only
//! from a READY `open`/`refresh`: on another outcome the plugin publishes none.
//!
//! `hydrate` and `start` answer a bare `OutHead`: no per-answer rule beyond the mechanism's. The
//! snapshot's claims and admin routes (`check_claims`, `check_admin_routes`) and the Statement tail
//! are generation and load data, judged where the kernel adopts them, not per answer.
//!
//! THE TAIL'S INDICES. A unit's billable class, a record's kind, `arrive`'s op class and dialect
//! index lists of the plane's Statement tail ([`PlaneTail`]). The tail is read once at bind: it
//! must be a whole `PlaneTail` that passes `check_tail`, or the load is refused. Its list lengths
//! are the instance's context ([`Bounds`]), and every answer's indices are judged against them at
//! the crossing: an index past its list is FAULT.
//!
//! SHORT ANSWERS: `arrive`, `on_piece`, `refusal`, `serve`, `project` and `drive` have the short
//! path; a FAILED answer of one of them with any `*_needed` non-zero is short.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::{fault, reported, Fault, Rule};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut, OpenIn, RefreshIn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::check::{
    check_arrive, check_cancel, check_drive, check_on_piece, check_pin_mechanisms, check_project,
    check_refusal, check_serve, check_snapshot, check_tail, check_trust_keys, Bounds, Caps,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, PinMechanism, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, TrustKey,
};

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};

/// The plane kind.
#[derive(Debug, Clone, Copy)]
pub struct Plane;

// SAFETY: `#[repr(C)]` in `abi/plane/`, each leading with its head (`PlaneOpenIn` with an
// `OpenIn`, `PlaneOpenOut` with an `OpenOut`, each of which leads with its head); their pointers
// are host buffers, host-borrowed inputs, or the plugin's generation snapshot, valid until
// `retire` of its generation.
unsafe impl InFrame for PlaneOpenIn {}
unsafe impl InFrame for PlaneDriveIn {}
unsafe impl InFrame for ArriveIn {}
unsafe impl InFrame for OnPieceIn {}
unsafe impl InFrame for RefusalIn {}
unsafe impl InFrame for ServeIn {}
unsafe impl InFrame for ProjectIn {}
unsafe impl OutFrame for PlaneOpenOut {}
unsafe impl OutFrame for PlaneRefreshOut {}
unsafe impl OutFrame for PlaneDriveOut {}
unsafe impl OutFrame for ArriveOut {}
unsafe impl OutFrame for OnPieceOut {}
unsafe impl OutFrame for RefusalOut {}
unsafe impl OutFrame for ServeOut {}
unsafe impl OutFrame for ProjectOut {}

/// The instance's tail bounds; an answer judged without them is FAULT (a plane instance always
/// binds with its tail).
fn bounds<'a>(a: &Answer<'a>) -> Result<&'a Bounds, Fault> {
    a.context::<Bounds>()
        .ok_or(fault(Rule::Missing, "plane.tail"))
}

/// The plane's tail, read from the Statement: a whole `PlaneTail` that passes `check_tail`.
fn tail_bounds(st: &Statement) -> Result<Bounds, String> {
    let p = st.kind_tail;
    if p.is_null() {
        return Err("a plane states no kind tail".into());
    }
    // SAFETY: a non-NULL kind tail is `'static` plugin data leading with a `KindTailHead`, whose
    // size the loader checked covers the head; the whole tail is read only once its size covers
    // this host's `PlaneTail`.
    let size = unsafe { (*p).size };
    if (size as usize) < std::mem::size_of::<PlaneTail>() {
        return Err(format!(
            "the plane tail is {size} bytes, smaller than this host's"
        ));
    }
    // SAFETY: as above.
    let tail = unsafe { p.cast::<PlaneTail>().read_unaligned() };
    check_tail(&tail).map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    check_tail_trust_keys(&tail)
        .map_err(|f| format!("the plane tail breaks {:?} at {}", f.rule, f.field))?;
    Ok(Bounds::of(&tail))
}

/// The tail's kernel-owned trust keys, judged PER ELEMENT: each key by `check_trust_keys`, each
/// pin's mechanisms by `check_pin_mechanisms`. `check_tail` proved only that no list is counted over
/// a NULL pointer; the elements are read here, once, at bind.
fn check_tail_trust_keys(tail: &PlaneTail) -> Result<(), Fault> {
    let keys: &[TrustKey] = if tail.trust_keys_len == 0 {
        &[]
    } else {
        // SAFETY: `check_tail` refused a NULL `trust_keys` counted non-zero; the tail is `'static`
        // plugin data whose list is `trust_keys_len` `TrustKey`s.
        unsafe { std::slice::from_raw_parts(tail.trust_keys, tail.trust_keys_len) }
    };
    check_trust_keys(keys)?;
    for key in keys {
        let mechanisms: &[PinMechanism] = if key.mechanisms_len == 0 {
            &[]
        } else {
            // SAFETY: `check_trust_keys` refused a NULL `mechanisms` counted non-zero; the list is
            // `'static` plugin data of `mechanisms_len` `PinMechanism`s.
            unsafe { std::slice::from_raw_parts(key.mechanisms, key.mechanisms_len) }
        };
        check_pin_mechanisms(mechanisms)?;
    }
    Ok(())
}

impl Kind for Plane {
    const CODE: KindCode = KindCode::Plane;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(tail_bounds(st)?)))
    }
    type Ops = plane::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::ARRIVE => "arrive",
            slot::ON_PIECE => "on_piece",
            slot::REFUSAL => "refusal",
            slot::SERVE => "serve",
            slot::HYDRATE => "hydrate",
            slot::START => "start",
            slot::PROJECT => "project",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::ARRIVE => arrive(a),
            slot::ON_PIECE => on_piece(a),
            slot::REFUSAL => {
                let i = a.input::<RefusalIn>()?;
                let o = a.out::<RefusalOut>()?;
                // SAFETY: `fields_buf` is the host's own buffer of `fields_cap` `OutField`s,
                // named by this op's `in`.
                let fields = unsafe {
                    reported(
                        i.fields_buf.cast_const(),
                        u64::from(o.fields_written),
                        i.fields_cap as u64,
                        "refusal.fields",
                    )
                }?;
                let caps = Caps {
                    reply: i.reply_cap as u64,
                    fields: i.fields_cap as u64,
                    arena: i.arena_cap as u64,
                    ..Caps::default()
                };
                check_refusal(a.outcome, o, fields, &caps)
            }
            slot::SERVE => {
                let i = a.input::<ServeIn>()?;
                let o = a.out::<ServeOut>()?;
                // SAFETY: as `refusal`: the host's `fields_buf` of `fields_cap` elements.
                let fields = unsafe {
                    reported(
                        i.fields_buf.cast_const(),
                        u64::from(o.fields_written),
                        i.fields_cap as u64,
                        "serve.fields",
                    )
                }?;
                let caps = Caps {
                    reply: i.reply_cap as u64,
                    fields: i.fields_cap as u64,
                    arena: i.arena_cap as u64,
                    ..Caps::default()
                };
                check_serve(a.outcome, o, fields, &caps)
            }
            slot::PROJECT => project(a),
            life::OPEN if a.outcome == Outcome::Ready => {
                let generation = a.input::<OpenIn>()?.generation;
                snapshot(
                    a.out::<PlaneOpenOut>()?.snapshot,
                    generation,
                    "open.snapshot",
                )
            }
            life::REFRESH if a.outcome == Outcome::Ready => {
                let generation = a.input::<RefreshIn>()?.generation;
                snapshot(
                    a.out::<PlaneRefreshOut>()?.snapshot,
                    generation,
                    "refresh.snapshot",
                )
            }
            life::CANCEL => check_cancel(a.outcome, a.out::<CancelOut>()?.disposition),
            life::DRIVE => {
                let cap = a.input::<PlaneDriveIn>()?.sessions_cap as u64;
                check_drive(a.outcome, a.out::<PlaneDriveOut>()?, cap)
            }
            // `hydrate`, `start` (a bare `OutHead`) and the other lifecycle answers: no
            // per-answer rule beyond the mechanism's.
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::ARRIVE => a.out::<ArriveOut>().is_ok_and(|o| o.units_needed != 0),
            slot::ON_PIECE => a.out::<OnPieceOut>().is_ok_and(|o| {
                o.units_needed != 0
                    || o.records_needed != 0
                    || o.fields_needed != 0
                    || o.arena_needed != 0
            }),
            slot::REFUSAL => a
                .out::<RefusalOut>()
                .is_ok_and(|o| o.reply_needed != 0 || o.fields_needed != 0 || o.arena_needed != 0),
            slot::SERVE => a
                .out::<ServeOut>()
                .is_ok_and(|o| o.reply_needed != 0 || o.fields_needed != 0 || o.arena_needed != 0),
            slot::PROJECT => a
                .out::<ProjectOut>()
                .is_ok_and(|o| o.signals_needed != 0 || o.arena_needed != 0),
            life::DRIVE => a
                .out::<PlaneDriveOut>()
                .is_ok_and(|o| o.sessions_needed != 0),
            _ => false,
        }
    }
}

/// `arrive`: the expected units over the host's `units_buf`, `units_cap` from `ArriveIn`.
fn arrive(a: &Answer) -> Result<(), Fault> {
    let i = a.input::<ArriveIn>()?;
    let o = a.out::<ArriveOut>()?;
    let cap = i.units_cap as u64;
    // SAFETY: `units_buf` is the host's own buffer of `units_cap` `UnitCount`s, named by this op's
    // `in`.
    let units = unsafe {
        reported(
            i.units_buf.cast_const(),
            u64::from(o.units_written),
            cap,
            "arrive.units",
        )
    }?;
    check_arrive(a.outcome, o, units, cap, bounds(a)?)
}

/// `on_piece`: units, records and fields over the host's buffers, every cap from `OnPieceIn`.
fn on_piece(a: &Answer) -> Result<(), Fault> {
    let i = a.input::<OnPieceIn>()?;
    let o = a.out::<OnPieceOut>()?;
    let caps = Caps {
        reply: i.reply_cap as u64,
        units: i.units_cap as u64,
        records: i.records_cap as u64,
        fields: i.fields_cap as u64,
        arena: i.arena_cap as u64,
    };
    // SAFETY: `units_buf`, `records_buf` and `fields_buf` are the host's own buffers of
    // `units_cap`, `records_cap` and `fields_cap` elements, named by this op's `in`.
    let (units, records, fields) = unsafe {
        (
            reported(
                i.units_buf.cast_const(),
                u64::from(o.units_written),
                caps.units,
                "on_piece.units",
            )?,
            reported(
                i.records_buf.cast_const(),
                u64::from(o.records_written),
                caps.records,
                "on_piece.records",
            )?,
            reported(
                i.fields_buf.cast_const(),
                u64::from(o.fields_written),
                caps.fields,
                "on_piece.fields",
            )?,
        )
    };
    check_on_piece(a.outcome, o, (units, records, fields), &caps, bounds(a)?)
}

/// `project`: the view's signals over the host's `signals_buf`, its strings and body over the
/// host's arena, every cap from `ProjectIn`.
fn project(a: &Answer) -> Result<(), Fault> {
    let i = a.input::<ProjectIn>()?;
    let o = a.out::<ProjectOut>()?;
    let cap = i.signals_cap as u64;
    // SAFETY: `signals_buf` is the host's own buffer of `signals_cap` `SignalEntry`s, named by
    // this op's `in`.
    let signals = unsafe {
        reported(
            i.signals_buf.cast_const(),
            o.view.signals_len as u64,
            cap,
            "project.signals",
        )
    }?;
    check_project(
        a.outcome,
        o,
        signals,
        cap,
        (i.arena_buf.cast_const(), i.arena_cap as u64),
    )
}

/// A READY `open`'s or `refresh`'s generation snapshot: present, of this host's size, then
/// `check_snapshot` against the generation the `in` names. The size is read before the whole
/// struct, so a smaller foreign snapshot is never read past its end.
fn snapshot(s: *const PlaneSnapshot, generation: u64, field: &'static str) -> Result<(), Fault> {
    if s.is_null() {
        return Err(fault(Rule::Missing, field));
    }
    // SAFETY: a non-NULL snapshot is the plugin's generation data, valid until `retire` of its
    // generation; its leading `size` is read alone first.
    let size = unsafe { s.cast::<u32>().read_unaligned() };
    if size as usize != std::mem::size_of::<PlaneSnapshot>() {
        return Err(fault(Rule::Foreign, "snapshot.size"));
    }
    // SAFETY: as above; the snapshot states this host's full size.
    let snap = unsafe { s.read_unaligned() };
    check_snapshot(&snap, generation)
}
