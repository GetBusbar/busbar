// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR, BOTH WAYS (`BUSBAR-1.6.0.md` Part 2 #2, THE DESIGN, the section on one table for compiled-in and dropped-in): the linked door
//! (`plane_door::door`) and this crate's dropped-in image (the `llm_door` example, the same door
//! behind `export_door!`), each admitted through the one loader, run ONE script through every plane
//! op, each answer read back. The two transcripts must be identical, and carry what the plane's
//! answers to the driver require (Part 3, the plane seam's driver section).
//!
//! RED ARM, kept: the same door with `on_piece` swapped for one that relays the far end's answer
//! and reports no count. Its transcript differs at the far end's answer, so a door that stopped
//! counting cannot pass for this one.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS,
    PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_KERNEL, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
use busbar_contract::abi::sdk::door::kind_op;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_plane_llm::plane_door;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        // These rows never dial: the door's needs are not declared, bound as a probe.
        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    }
}

fn octets(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

const fn text(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

const fn field(name: &'static [u8], value: &'static [u8]) -> Field {
    Field {
        name: text(name),
        value: text(value),
    }
}

fn at(buf: &[u8], s: Span) -> String {
    String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
}

/// One anthropic far end, one model, one pool.
const SETTINGS: &[u8] = br#"{
    "providers": { "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" } },
    "models": { "claude": { "provider": "ant" } },
    "pools": { "p": { "members": ["claude"] } }
}"#;
/// The same far end under a second pool.
const SETTINGS_2: &[u8] = br#"{
    "providers": { "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" } },
    "models": { "claude": { "provider": "ant" } },
    "pools": { "q": { "members": ["claude"] } }
}"#;
/// What the caller sends.
const CHAT: &[u8] =
    br#"{"model":"claude","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;
/// The caller's head.
const CALLER: &[Field] = &[
    field(b"content-type", b"application/json"),
    field(b"anthropic-version", b"2023-06-01"),
];
/// What the far end answers: 7 tokens in, 3 out.
const ANSWER: &[u8] = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
/// The far end's kept response field.
const HEAD: &[Field] = &[field(b"content-type", b"application/json")];

/// The host's buffers for one `on_piece`.
struct Piece {
    reply: Vec<u8>,
    units: [UnitCount; 8],
    fields: [OutField; 16],
    arena: [u8; 1024],
}

impl Piece {
    fn new(reply_cap: usize) -> Box<Self> {
        Box::new(Self {
            reply: vec![0; reply_cap],
            units: [z(); 8],
            fields: [z(); 16],
            arena: [0; 1024],
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
        (i.attempt_no, i.member, i.pool) = (attempt_no, text(b"claude"), text(b"p"));
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
            "{:?} emitted={} more={} to_far_end={} done={} status={} verdict={} verb={} target={} \
             fields={fields:?} units={units:?}",
            c.outcome,
            String::from_utf8_lossy(&self.reply[..o.emitted as usize]),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            o.verdict,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
        )
    }
}

fn arrive(p: &Plugin<Plane>, unit: u64, target: &'static [u8], body: &'static [u8]) -> String {
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    (a.input.unit, a.input.method, a.input.target) = (unit, text(b"POST"), text(target));
    (a.input.fields, a.input.fields_len) = (CALLER.as_ptr(), CALLER.len());
    a.input.body = octets(body);
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

fn refusal(p: &Plugin<Plane>, unit: u64, plane_code: u32, target: &'static [u8]) -> String {
    let (mut reply, mut fields, mut buf) = ([0_u8; 512], [z::<OutField>(); 4], [0_u8; 256]);
    let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
    (r.input.head, r.out.head) = (in_head(), out_head());
    (r.input.cause, r.input.status, r.input.text) = (REFUSAL_KERNEL, 404, text(b"not found"));
    (r.input.unit, r.input.plane_code, r.input.target) = (unit, plane_code, text(target));
    (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (r.input.arena_buf, r.input.arena_cap) = (buf.as_mut_ptr(), buf.len());
    let c = p.call(slot::REFUSAL, &mut r);
    let named: Vec<String> = fields[..r.out.fields_written as usize]
        .iter()
        .map(|f| format!("{}={}", at(&buf, f.name), at(&buf, f.value)))
        .collect();
    format!(
        "refusal {:?} {} {named:?}",
        c.outcome,
        String::from_utf8_lossy(&reply[..r.out.reply_written as usize]),
    )
}

/// THE SCRIPT: every plane op, each answer read back.
fn script(p: &Plugin<Plane>) -> Vec<String> {
    let mut t = Vec::new();

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: octets(br#"{"providers":7}"#),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    t.push(format!(
        "validate broken {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));
    v.input.settings = octets(SETTINGS);
    t.push(format!(
        "validate {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));

    let mut i: PlaneOpenIn = z();
    i.open.head = in_head();
    (i.open.generation, i.open.settings) = (1, octets(SETTINGS));
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

    t.push(arrive(p, 7, b"/v1/messages", CHAT));
    t.push(arrive(p, 8, b"/nowhere", b"{}"));

    // One unit: the ATTEMPT, the caller's body, the far end's whole answer.
    let mut piece = Piece::new(1024);
    t.push(format!(
        "attempt {}",
        piece.call(p, 7, FROM_KERNEL, 0, b"", 1)
    ));
    t.push(format!(
        "body {}",
        piece.call(p, 7, FROM_CALLER, PIECE_LAST, CHAT, 0)
    ));
    let whole = PIECE_HAS_STATUS | PIECE_LAST;
    t.push(format!(
        "far_end {}",
        piece.call(p, 7, FROM_FAR_END, whole, ANSWER, 0)
    ));

    // Another, whose answer is written 48 bytes at a time.
    t.push(arrive(p, 9, b"/v1/messages", CHAT));
    let mut narrow = Piece::new(48);
    t.push(format!(
        "attempt {}",
        narrow.call(p, 9, FROM_KERNEL, 0, b"", 1)
    ));
    t.push(format!(
        "body {}",
        piece.call(p, 9, FROM_CALLER, PIECE_LAST, CHAT, 0)
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

    // The declined arrival, in its own envelope; a refusal before any arrival, by its target.
    t.push(refusal(p, 8, 1, b"/nowhere"));
    t.push(refusal(p, 0, 0, b"/v1/messages"));

    let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
    (s.input.head, s.out.head) = (in_head(), out_head());
    t.push(format!("serve {:?}", p.call(slot::SERVE, &mut s).outcome));
    let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
    (j.input.head, j.out.head) = (in_head(), out_head());
    t.push(format!(
        "project {:?}",
        p.call(slot::PROJECT, &mut j).outcome
    ));

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
    let mut x: Frame<
        busbar_contract::abi::plane::PlaneCancelIn,
        busbar_contract::abi::plane::PlaneCancelOut,
    > = Frame::new(z(), z());
    (x.input.cancel.head, x.out.cancel.head) = (in_head(), out_head());
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} {}",
        c.outcome, x.out.cancel.disposition
    ));

    let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
    (f.input.head, f.out.head) = (in_head(), out_head());
    (f.input.generation, f.input.settings) = (2, octets(SETTINGS_2));
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

/// The line of `t` that starts with `prefix`.
fn line<'a>(t: &'a [String], prefix: &str) -> &'a str {
    t.iter()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` line in {t:#?}"))
}

/// What the plane's answers to the driver require of the transcript, linked or dropped.
fn assert_the_planes_answers(t: &[String]) {
    let all = t.join("\n");
    assert_eq!(t[0], "validate broken Refused", "{all}");
    assert_eq!(t[1], "validate Ready", "{all}");
    // ARCHITECT Q-FL1: the plane states its paths as claims, and 1.5.5's fallback is a prefix claim
    // on `/` for every verb.
    assert!(
        t[2].starts_with("open Ready Some(")
            && t[2].contains(r#"verb: "POST", target: "/v1/messages", carrier: "http""#)
            && ["GET", "POST", "PUT", "PATCH", "DELETE"].iter().all(|v| {
                t[2].contains(&format!(r#"verb: "{v}", target: "/", carrier: "http""#))
            }),
        "the plane's paths are claims and the fallback is a prefix claim on / per verb: {all}"
    );
    assert_eq!(
        t[5], "arrive Ready op_class=0 principal_required=true dialect=0 refusal=0 status=0",
        "an anthropic chat: {all}"
    );
    assert_eq!(
        t[6], "arrive Refused op_class=0 principal_required=false dialect=0 refusal=1 status=404",
        "an unclaimed path, refused as 1.5.5 refused it: {all}"
    );
    let attempt = line(t, "attempt ");
    assert!(
        attempt.contains("to_far_end=true")
            && attempt.contains("verb=POST target=/v1/messages")
            && attempt.contains("anthropic-version=2023-06-01"),
        "the attempt's request carries the same-dialect caller's own field: {all}"
    );
    let body = line(t, "body ");
    assert!(
        body.starts_with(&format!(
            "body Ready emitted={} more=0 to_far_end=true done=false",
            String::from_utf8_lossy(CHAT)
        )),
        "a pristine same-dialect body goes out as sent: {all}"
    );
    let far = line(t, "far_end Ready");
    assert!(
        far.starts_with(&format!(
            "far_end Ready emitted={} more=0 to_far_end=false done=true status=200 verdict=1",
            String::from_utf8_lossy(ANSWER)
        )),
        "a same-dialect answer is the far end's bytes: {all}"
    );
    assert!(
        far.contains(r#"units=["0:7:true", "1:3:true", "2:0:true", "3:0:true", "19:1:true"]"#),
        "the far end's counts, in the tail's class order, then the per-request fee unit a success \
         reply incurs, last after the 15 open classes (owner #77, money-B1; LEDGER-100): {all}"
    );
    let narrow = line(t, "far_end narrow ");
    assert!(
        narrow.contains("more=1") && narrow.contains("done=false") && narrow.contains("status=200"),
        "{all}"
    );
    let mores: Vec<&String> = t.iter().filter(|l| l.starts_with("more ")).collect();
    assert!(mores[..2].iter().all(|l| l.contains("more=1")), "{all}");
    assert!(
        mores[2].contains("more=0") && mores[2].contains("done=true"),
        "the last chunk completes the reply: {all}"
    );
    let drained: String = std::iter::once(narrow)
        .chain(mores.iter().map(|l| l.as_str()))
        .map(|l| {
            let from = l.find("emitted=").expect("emitted") + "emitted=".len();
            let to = l.find(" more=").expect("more");
            l[from..to].to_string()
        })
        .collect();
    assert_eq!(
        drained.as_bytes(),
        ANSWER,
        "the narrow reply drains whole: {all}"
    );
    let declined = &t[t.len() - 9];
    assert!(
        declined.starts_with("refusal Ready {")
            && declined.contains("content-type=application/json"),
        "{all}"
    );
    assert!(t[t.len() - 8].starts_with("refusal Ready {"), "{all}");
    assert_eq!(t[t.len() - 7], "serve Refused", "{all}");
    assert_eq!(t[t.len() - 6], "project Refused", "{all}");
    assert_eq!(t[t.len() - 5], "tick Ready next=0", "{all}");
    assert_eq!(t[t.len() - 4], "cancel Ready 3", "{all}");
    assert!(
        t[t.len() - 3].starts_with("refresh Ready Some(")
            && t[t.len() - 3].contains("generation: 2"),
        "{all}"
    );
    assert_eq!(t[t.len() - 2], "retire Ready", "{all}");
    assert_eq!(t[t.len() - 1], "close Ready", "{all}");
}

fn linked(d: &Dispatcher) -> Plugin<Plane> {
    let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
    load_linked(&row, bind(d)).expect("the linked door loads")
}

/// This crate's dropped-in image, the `llm_door` example `cargo test` builds. A missing artifact
/// is a failure, never a skip: this test IS the dropped-in door's proof.
fn dropped(d: &Dispatcher) -> Plugin<Plane> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let examples = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>")
        .join("examples");
    let file = busbar_plugin_loader::plugin_library_filename("llm_door");
    let path = [examples.join(&file), examples.join("deps").join(&file)]
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("the llm_door example ({file}) is not built"));
    let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
    load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
}

#[test]
fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked = script(&linked(&d));
    assert_the_planes_answers(&linked);
    assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
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

/// The llm door with `on_piece` swapped for [`Uncounted`].
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
fn red_a_door_that_stops_counting_the_far_ends_units_answers_differently() {
    let d = Dispatcher::new(DispatchConfig::default());
    let honest = script(&linked(&d));
    let row = LinkedRow::of(uncounted_door).expect("the door states its Statement");
    let red = script(&load_linked::<Plane>(&row, bind(&d)).expect("the door loads"));
    let far_end = |t: &[String]| t.iter().find(|l| l.starts_with("far_end ")).cloned();
    let red_line = far_end(&red).expect("the red door answers the far end");
    assert!(red_line.contains("units=[]"), "{red_line}");
    assert_ne!(Some(red_line), far_end(&honest));
    assert_ne!(red, honest);
}
