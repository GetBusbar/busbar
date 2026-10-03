// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: plane`, BOTH WAYS, OVER THE SHIPPED DOOR** (TODO ABI-b4 for the plane kind; M6/contract:
//! exact crossing counts, run under the release profile).
//!
//! [`plane_conformance_tests`](super::plane_conformance_tests) runs a TEST plane. This file runs a
//! SHIPPED one: the decisions plane's own door, `busbar_plane_decisions::plane_door::door`, LINKED
//! (the door a busbar build holds) and DROPPED IN (the `decisions_door_dropped` example, the plane's
//! own `export_door!` source built as a `cdylib`), each through the one dispatcher, ONE script of the
//! plane kind's whole table: `validate` (refused, then ready), `open`, `hydrate`, `start`, `arrive`
//! (claimed, unclaimed), the request path (`on_piece` for the attempt, the caller's body, the far
//! end's answer whole and 16 bytes at a time, an empty body), `refusal`, `serve`, `project`, `drive`,
//! `release`, `tick`, `cancel`, `refresh`, `retire` and `close`.
//!
//! Compared: the TRANSCRIPTS (line for line, and against the transcript the plane's answers to the
//! driver require), and the CROSSINGS: the dispatcher counts every crossing it made
//! (`Plugin::inner.crossings`), and after EVERY step on BOTH legs the count must equal the number of
//! steps taken, ending at [`CROSSINGS`], the number the script's own arithmetic gives. "Greater than
//! zero" would pass a leg that swallowed or duplicated an op.
//!
//! RED ARMS, KEPT: a count one off, a leg one crossing short and a dropped leg are each seen
//! ([`a_miscount_is_seen`]); a door that stops metering answers differently
//! ([`a_door_that_stops_counting_the_far_ends_units_answers_differently`]).

use std::mem::zeroed;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END,
    FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_GATE, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
use busbar_contract::abi::sdk::door::kind_op;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_plane_decisions::plane_door;
use std::sync::atomic::Ordering;

use super::door_both_ways::{self as both, line, release};
use crate::dispatch::kinds::plane::Plane;
use crate::dispatch::{
    in_head, load_linked, out_head, DispatchConfig, Dispatcher, Frame, LinkedRow, Plugin,
};

/// THE CROSSINGS THE SCRIPT MAKES, counted by hand from [`script`], one per line of the transcript:
///
/// | step | ops |
/// |---|---|
/// | `validate` x2, `open`, `hydrate`, `start` | 5 |
/// | `arrive` x2 | 2 |
/// | unit 7: attempt, body, far end's answer | 3 |
/// | unit 9: attempt, answer through a 16-byte buffer, `more` x3 | 5 |
/// | unit 10: an empty body | 1 |
/// | `refusal`, `serve`, `project`, `drive`, `release`, `tick`, `cancel` | 7 |
/// | `refresh`, `retire`, `close` | 3 |
const CROSSINGS: u64 = 26;

/// One leg's run: the transcript, the plugin it ran against.
struct Steps<'a> {
    p: &'a Plugin<Plane>,
    lines: Vec<String>,
}

impl Steps<'_> {
    /// One step's line. THE PER-OP COUNT: this step crossed exactly once, so the dispatcher's count
    /// is the number of steps taken, here, at every op.
    fn push(&mut self, line: String) {
        self.lines.push(line);
        assert_eq!(
            crossings(self.p),
            self.lines.len() as u64,
            "the dispatcher's crossings after `{}`",
            self.lines.last().expect("a line was just pushed")
        );
    }
}

/// The crossings the dispatcher counted on `p`.
fn crossings(p: &Plugin<Plane>) -> u64 {
    p.inner.crossings.load(Ordering::Relaxed)
}

fn octets(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn text(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn at(buf: &[u8], s: Span) -> String {
    String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
}

/// One model configured: `systemone` is claimed.
const ONE_MODEL: &[u8] = br#"{"models":{"jev":{"provider":"typesafe"}}}"#;
/// Two models: nothing is claimed.
const TWO_MODELS: &[u8] =
    br#"{"models":{"a":{"provider":"typesafe"},"b":{"provider":"typesafe"}}}"#;
/// What the caller sends.
const REQUEST: &[u8] = br#"{"state":{"session":"s"},"context":{}}"#;
/// What the far end answers: a decision billing 42 units.
const ANSWER: &[u8] = br#"{"request_id":"req_1","usage":{"units":42},"answers":{}}"#;
/// The far end's kept response field.
const HEAD: &[Field] = &[Field {
    name: AbiStr {
        ptr: b"content-type".as_ptr(),
        len: 12,
    },
    value: AbiStr {
        ptr: b"application/json".as_ptr(),
        len: 16,
    },
}];

/// The host's buffers for one `on_piece`.
struct Piece {
    reply: Vec<u8>,
    units: [UnitCount; 2],
    fields: [OutField; 2],
    arena: [u8; 128],
}

impl Piece {
    fn new(reply_cap: usize) -> Box<Self> {
        Box::new(Self {
            reply: vec![0; reply_cap],
            units: [z(); 2],
            fields: [z(); 2],
            arena: [0; 128],
        })
    }

    /// One piece of `unit`, answered: the outcome, and what it wrote, as text.
    fn call(
        &mut self,
        p: &Plugin<Plane>,
        unit: u64,
        from: u32,
        flags: u32,
        bytes: &'static [u8],
        attempt_no: u32,
    ) -> String {
        let mut i: OnPieceIn = z();
        i.head = in_head();
        (i.unit, i.from, i.flags, i.bytes) = (unit, from, flags, octets(bytes));
        (i.attempt_no, i.member) = (attempt_no, text(b"jev"));
        if flags & PIECE_HAS_STATUS != 0 {
            i.status_code = 200;
            (i.head_fields, i.head_fields_len) = (HEAD.as_ptr(), HEAD.len());
        }
        (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
        (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), self.units.len());
        (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
        (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
        let mut o: OnPieceOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        let c = p.call(slot::ON_PIECE, &mut f);
        let o = f.out;
        let fields: Vec<String> = self.fields[..o.fields_written as usize]
            .iter()
            .map(|f| format!("{}={}", at(&self.arena, f.name), at(&self.arena, f.value)))
            .collect();
        let units: Vec<String> = self.units[..o.units_written as usize]
            .iter()
            .map(|u| format!("{}:{}:{}", u.class, u.amount, u.source == UNITS_REPORTED))
            .collect();
        format!(
            "{:?} emitted={} more={} to_far_end={} done={} status={} verb={} target={} \
             fields={fields:?} units={units:?}",
            c.outcome,
            String::from_utf8_lossy(&self.reply[..o.emitted as usize]),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
        )
    }
}

fn arrive(p: &Plugin<Plane>, unit: u64, method: &'static [u8], target: &'static [u8]) -> String {
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    (a.input.unit, a.input.method, a.input.target) = (unit, text(method), text(target));
    a.input.body = octets(REQUEST);
    let c = p.call(slot::ARRIVE, &mut a);
    format!(
        "arrive {:?} op_class={} principal_required={} dialect={} refusal={} status={}",
        c.outcome,
        a.out.op_class,
        a.out.principal_need == PRINCIPAL_REQUIRED,
        a.out.dialect,
        a.out.refusal,
        a.out.refusal_status
    )
}

/// THE SCRIPT: every plane op, each answer read back.
fn script(p: &Plugin<Plane>) -> Steps<'_> {
    let mut t = Steps {
        p,
        lines: Vec::new(),
    };

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: octets(br#"{"modles":{}}"#),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    t.push(format!(
        "validate typo {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));
    v.input.settings = octets(ONE_MODEL);
    t.push(format!(
        "validate {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));

    let mut i: PlaneOpenIn = z();
    i.open.head = in_head();
    (i.open.generation, i.open.settings) = (1, octets(ONE_MODEL));
    let mut o: PlaneOpenOut = z();
    o.open.head = out_head();
    let (c, snapshot) = p.open(&mut Frame::new(i, o));
    t.push(format!("open {:?} {snapshot:?}", c.outcome));

    for s in [slot::HYDRATE, slot::START] {
        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        t.push(format!("{s} {:?}", p.call(s, &mut g).outcome));
    }

    t.push(arrive(p, 7, b"POST", b"/v1/systemone"));
    t.push(arrive(p, 8, b"GET", b"/v1/models"));

    // One unit: the ATTEMPT, the caller's body, the far end's whole answer.
    let mut piece = Piece::new(256);
    t.push(format!(
        "attempt {}",
        piece.call(p, 7, FROM_KERNEL, 0, b"", 1)
    ));
    t.push(format!(
        "body {}",
        piece.call(p, 7, FROM_CALLER, PIECE_LAST, REQUEST, 0)
    ));
    let whole = PIECE_HAS_STATUS | PIECE_LAST;
    t.push(format!(
        "far_end {}",
        piece.call(p, 7, FROM_FAR_END, whole, ANSWER, 0)
    ));

    // Another, whose answer is written 16 bytes at a time.
    let mut narrow = Piece::new(16);
    t.push(format!(
        "attempt {}",
        narrow.call(p, 9, FROM_KERNEL, 0, b"", 1)
    ));
    t.push(format!(
        "far_end narrow {}",
        narrow.call(p, 9, FROM_FAR_END, whole, ANSWER, 0)
    ));
    for _ in 0..3 {
        t.push(format!(
            "more {}",
            narrow.call(p, 9, FROM_FAR_END, 0, b"", 0)
        ));
    }

    // A caller body that ended empty.
    t.push(format!(
        "empty {}",
        piece.call(p, 10, FROM_CALLER, PIECE_LAST, b"", 0)
    ));

    let (mut reply, mut fields, mut buf) = ([0_u8; 128], [z::<OutField>(); 1], [0_u8; 64]);
    let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
    (r.input.head, r.out.head) = (in_head(), out_head());
    (r.input.cause, r.input.status, r.input.text) = (REFUSAL_GATE, 403, text(b"denied"));
    (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (r.input.arena_buf, r.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
    let c = p.call(slot::REFUSAL, &mut r);
    t.push(format!(
        "refusal {:?} {} {}={} status={}",
        c.outcome,
        String::from_utf8_lossy(&reply[..r.out.reply_written as usize]),
        at(&buf, fields[0].name),
        at(&buf, fields[0].value),
        r.out.status
    ));

    let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
    (s.input.head, s.out.head) = (in_head(), out_head());
    t.push(format!("serve {:?}", p.call(slot::SERVE, &mut s).outcome));
    let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
    (j.input.head, j.out.head) = (in_head(), out_head());
    t.push(format!(
        "project {:?}",
        p.call(slot::PROJECT, &mut j).outcome
    ));

    let mut sessions = [0_u64; 2];
    let mut d: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
    (d.input.drive.head, d.out.head) = (in_head(), out_head());
    (d.input.sessions_buf, d.input.sessions_cap) = (sessions.as_mut_ptr(), sessions.len());
    let c = p.call(life::DRIVE, &mut d);
    t.push(format!(
        "drive {:?} sessions={}",
        c.outcome, d.out.sessions_written
    ));
    t.push(line("release", &release(p, 0)));

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1_000,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 7,
        },
    );
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));
    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    (x.input.head, x.out.head) = (in_head(), out_head());
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!("cancel {:?} {}", c.outcome, x.out.disposition));

    let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
    (f.input.head, f.out.head) = (in_head(), out_head());
    (f.input.generation, f.input.settings) = (2, octets(TWO_MODELS));
    let (c, snapshot) = p.refresh(&mut f);
    t.push(format!("refresh {:?} {snapshot:?}", c.outcome));

    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!("retire {:?}", p.call(life::RETIRE, &mut g).outcome));
    let mut e = Frame::new(in_head(), out_head());
    t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
    t
}

/// The transcript the plane's answers to the driver require, linked or dropped.
const EXPECTED: &[&str] = &[
    "validate typo Refused",
    "validate Ready",
    "open Ready Some(OwnedSnapshot { generation: 1, claims: [OwnedClaim { verb: \"POST\", \
     target: \"/v1/systemone\", carrier: \"http\", flags: 2 }], \
     admin_routes: [], openapi: None, audience: None, resource_metadata: None })",
    "13 Ready",
    "14 Ready",
    "arrive Ready op_class=0 principal_required=true dialect=0 refusal=0 status=0",
    "arrive Refused op_class=0 principal_required=false dialect=0 refusal=1 status=404",
    "attempt Ready emitted= more=0 to_far_end=true done=false status=0 verb=POST \
     target=/v1/systemone fields=[\"content-type=application/json\"] units=[]",
    "body Ready emitted={\"state\":{\"session\":\"s\"},\"context\":{}} more=0 to_far_end=true \
     done=false status=0 verb= target= fields=[] units=[]",
    "far_end Ready emitted={\"request_id\":\"req_1\",\"usage\":{\"units\":42},\"answers\":{}} \
     more=0 to_far_end=false done=true status=200 verb= target= \
     fields=[\"content-type=application/json\"] units=[\"0:42:true\"]",
    "attempt Ready emitted= more=0 to_far_end=true done=false status=0 verb=POST \
     target=/v1/systemone fields=[\"content-type=application/json\"] units=[]",
    "far_end narrow Ready emitted={\"request_id\":\"r more=1 to_far_end=false done=false \
     status=200 verb= target= fields=[\"content-type=application/json\"] units=[\"0:42:true\"]",
    "more Ready emitted=eq_1\",\"usage\":{\" more=1 to_far_end=false done=false status=0 verb= \
     target= fields=[] units=[]",
    "more Ready emitted=units\":42},\"answ more=1 to_far_end=false done=false status=0 verb= \
     target= fields=[] units=[]",
    "more Ready emitted=ers\":{}} more=0 to_far_end=false done=true status=0 verb= target= \
     fields=[] units=[]",
    "empty Refused emitted= more=0 to_far_end=false done=false status=0 verb= target= \
     fields=[] units=[]",
    "refusal Ready {\"error\":{\"code\":\"unsupported_operation\",\"message\":\"denied\"}} \
     content-type=application/json status=0",
    "serve Refused",
    "project Refused",
    "drive Ready sessions=0",
    "release: Ready lease=0 error=\"\"",
    "tick Ready next=0",
    "cancel Ready 3",
    "refresh Ready Some(OwnedSnapshot { generation: 2, claims: [], admin_routes: [], \
     openapi: None, audience: None, resource_metadata: None })",
    "retire Ready",
    "close Ready",
];

/// THE COUNT RULE over a whole leg: the transcript's lines, the dispatcher's crossings and the
/// literal the script's arithmetic gives are one number.
fn exact(who: &str, r: &Steps<'_>, expected: u64) -> Result<(), String> {
    for (what, n) in [
        ("the dispatcher's crossings", crossings(r.p)),
        ("the transcript's lines", r.lines.len() as u64),
    ] {
        if n != expected {
            return Err(format!(
                "{who}: {what} are {n}, expected exactly {expected}"
            ));
        }
    }
    Ok(())
}

#[test]
fn the_shipped_door_linked_and_dropped_in_answers_every_op_the_same_with_exact_crossings() {
    let linked = both::linked::<Plane>(plane_door::door);
    // Never a skip: the dropped leg is the other half of the proof.
    let dropped = both::dropped::<Plane>(plane_door::door, "decisions_door_dropped")
        .expect("the decisions_door_dropped example cdylib is built: a both-ways proof");

    let a = script(&linked.plugin);
    let b = script(&dropped.plugin);
    assert_eq!(a.lines, EXPECTED, "the linked shipped door");
    both::same(&a.lines, &b.lines);
    exact("linked", &a, CROSSINGS).unwrap();
    exact("dropped in", &b, CROSSINGS).unwrap();
}

/// THE RED ARM, KEPT: the count rule is not vacuous. A count one off, or a leg that dropped a
/// crossing, is refused with the number it saw.
#[test]
fn a_miscount_is_seen() {
    let linked = both::linked::<Plane>(plane_door::door);
    let r = script(&linked.plugin);
    assert_eq!(crossings(&r.p), CROSSINGS);
    assert!(exact("linked", &r, CROSSINGS).is_ok());
    assert!(exact("linked", &r, CROSSINGS + 1).is_err());
    assert!(exact("linked", &r, CROSSINGS - 1).is_err());
    let mut short = Steps {
        p: r.p,
        lines: r.lines.clone(),
    };
    short.lines.pop();
    assert!(
        exact("short", &short, CROSSINGS).is_err(),
        "a transcript one line short is seen"
    );
}

/// A call capture for the hand-built table entry below: one slot per thread, as `plugin_door!`
/// expands for a plugin's own image.
struct TestCapture;
impl CaptureHome for TestCapture {
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
        thread_local! {
            static SLOT: std::cell::RefCell<CaptureSlot> =
                std::cell::RefCell::new(CaptureSlot::new());
        }
        SLOT.with(|s| f(&mut s.borrow_mut()))
    }
}

/// An `on_piece` that relays every piece's bytes to the caller and reports no count.
struct Uncounted;
impl SafeSlot for Uncounted {
    type In = OnPieceIn;
    type Out = OnPieceOut;
    type State = ();
    fn call(
        _: Instance<'_, ()>,
        input: Lent<'_, OnPieceIn>,
        mut out: Out<'_, OnPieceOut>,
    ) -> Outcome {
        let bytes = input.field(|i| &i.bytes).bytes();
        let n = input.reply_buf().stream(bytes);
        out.set(|o| &o.emitted, n as u64);
        if input.from == FROM_FAR_END && input.flags & PIECE_LAST != 0 {
            out.set(|o| &o.flags, EMIT_DONE);
        }
        Outcome::Ready
    }
}

/// The decisions door with `on_piece` swapped for [`Uncounted`].
extern "C" fn uncounted_door() -> *const Door {
    // SAFETY: the macro's `'static` door and its plane table.
    let (d, mut ops) = unsafe {
        let d = &*plane_door::door();
        (d, *d.ops.cast::<plane::Ops>())
    };
    ops.on_piece = kind_op::<plane::Ops, Safe<Uncounted>, TestCapture, { slot::ON_PIECE }>();
    let ops: &'static plane::Ops = Box::leak(Box::new(ops));
    Box::leak(Box::new(Door {
        ops: std::ptr::from_ref(ops).cast(),
        ..*d
    }))
}

#[test]
fn a_door_that_stops_counting_the_far_ends_units_answers_differently() {
    let d = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(uncounted_door).expect("the door states its Statement");
    let door = load_linked::<Plane>(&row, both::bind(&d)).expect("the door loads");
    let red = script(&door);
    let far_end = red
        .lines
        .iter()
        .find(|l| l.starts_with("far_end "))
        .expect("the red door answers the far end");
    assert!(far_end.contains("units=[]"), "{far_end}");
    assert_ne!(red.lines, EXPECTED);
}
