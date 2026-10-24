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

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS,
    PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_KERNEL, TAP_FAULT_BAD_JSON, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
use busbar_contract::abi::sdk::door::kind_op;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_plane_llm::plane_door;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of_macro, Bind, DispatchConfig,
    Dispatcher, Frame, LinkedRow, NoSink, Plugin,
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
    Blob::of(b)
}

const fn text(b: &'static [u8]) -> AbiStr {
    AbiStr::of_bytes(b)
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
/// An openai caller's head: no `anthropic-version`, whose header claim outranks the
/// `/v1/chat/completions` path claim in 1.5.5's detection order (`codec/anthropic/mod.rs`).
const OPENAI_CALLER: &[Field] = &[field(b"content-type", b"application/json")];
/// What the far end answers: 7 tokens in, 3 out.
const ANSWER: &[u8] = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
/// The far end's kept response field.
const HEAD: &[Field] = &[field(b"content-type", b"application/json")];

/// The host's buffers for one `on_piece`.
struct Piece {
    /// The status code a piece flagged `PIECE_HAS_STATUS` carries (the far end's answer head).
    status: u32,
    reply: Vec<u8>,
    units: [UnitCount; 8],
    fields: [OutField; 16],
    arena: [u8; 1024],
}

impl Piece {
    fn new(reply_cap: usize) -> Box<Self> {
        Box::new(Self {
            status: 200,
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
            i.status_code = self.status;
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
             fields={fields:?} units={units:?} tap_fault={}",
            c.outcome,
            String::from_utf8_lossy(&self.reply[..o.emitted as usize]),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            o.verdict,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
            o.tap_fault,
        )
    }
}

fn arrive(p: &Plugin<Plane>, unit: u64, target: &'static [u8], body: &'static [u8]) -> String {
    arrive_with(p, unit, target, CALLER, body)
}

/// [`arrive`], the caller's head `fields`.
fn arrive_with(
    p: &Plugin<Plane>,
    unit: u64,
    target: &'static [u8],
    fields: &'static [Field],
    body: &'static [u8],
) -> String {
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    (a.input.unit, a.input.method, a.input.target) = (unit, text(b"POST"), text(target));
    (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
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
    let row =
        LinkedRow::of_macro(plane_door::MACRO_DOOR).expect("the linked door states its Statement");
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
    let stated =
        rendering_of_macro(plane_door::MACRO_DOOR).expect("the door renders its Statement");
    load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
}

#[test]
fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
    let d = Dispatcher::new(DispatchConfig::default());
    let linked = script(&linked(&d));
    assert_the_planes_answers(&linked);
    assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
}

/// A same-dialect 2xx body the usage tap cannot read: not JSON, and longer than one narrow window.
const UNREADABLE: &[u8] = b"{not json: the far end answered 200 with a body no reader can meter";

/// THE USAGE-TAP FAULT RIDES THE DOOR'S ANSWER AS DATA, ONCE (row 155): a same-dialect 2xx body the
/// tap cannot read is relayed as it came, and the answer that carries its units carries the fault
/// beside them, on ONE window of the answer however many the reply takes, so the kernel, which
/// counts each answer's fault, counts it exactly once. Linked and dropped in alike: the codec
/// reaches no host to report it.
#[test]
fn a_usage_tap_fault_rides_one_window_of_the_doors_answer() {
    let d = Dispatcher::new(DispatchConfig::default());
    for p in [linked(&d), dropped(&d)] {
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SETTINGS));
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        assert_eq!(p.open(&mut Frame::new(i, o)).0.outcome, Outcome::Ready);
        assert!(arrive(&p, 11, b"/v1/messages", CHAT).starts_with("arrive Ready"));
        let mut wide = Piece::new(1024);
        assert!(wide
            .call(&p, 11, FROM_KERNEL, 0, b"", 1)
            .contains("to_far_end=true"));
        assert!(wide
            .call(&p, 11, FROM_CALLER, PIECE_LAST, CHAT, 0)
            .contains(" more=0 "));
        let mut narrow = Piece::new(16);
        let whole = PIECE_HAS_STATUS | PIECE_LAST;
        let mut windows = vec![narrow.call(&p, 11, FROM_FAR_END, whole, UNREADABLE, 0)];
        while windows.last().is_some_and(|w| w.contains(" more=1 ")) {
            windows.push(narrow.call(&p, 11, FROM_FAR_END, 0, b"", 0));
        }
        let all = windows.join("\n");
        assert!(
            windows.len() > 1,
            "the answer takes more than one window: {all}"
        );
        let carried: Vec<&String> = windows
            .iter()
            .filter(|w| !w.ends_with(" tap_fault=0"))
            .collect();
        assert_eq!(carried.len(), 1, "one window carries the fault: {all}");
        assert!(
            carried[0].ends_with(&format!(" tap_fault={TAP_FAULT_BAD_JSON}")),
            "the fault is the tap's own reason: {all}"
        );
    }
}

/// The same far end, model and pool, with a translation cap below [`ANSWER`]'s length: the
/// `limits.request_body_max_bytes` the kernel hands a plane in its settings.
const SETTINGS_CAPPED: &[u8] = br#"{
    "providers": { "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" } },
    "models": { "claude": { "provider": "ant" } },
    "pools": { "p": { "members": ["claude"] } },
    "limits": { "request_body_max_bytes": 64 }
}"#;

/// One openai caller's unit against the anthropic far end, its whole answer [`ANSWER`]: the far
/// end's answer line.
fn translated(p: &Plugin<Plane>, unit: u64) -> String {
    assert!(
        arrive_with(p, unit, b"/v1/chat/completions", OPENAI_CALLER, CHAT)
            .starts_with("arrive Ready")
    );
    let mut wide = Piece::new(1024);
    assert!(wide
        .call(p, unit, FROM_KERNEL, 0, b"", 1)
        .contains("to_far_end=true"));
    wide.call(p, unit, FROM_CALLER, PIECE_LAST, CHAT, 0);
    wide.call(
        p,
        unit,
        FROM_FAR_END,
        PIECE_HAS_STATUS | PIECE_LAST,
        ANSWER,
        0,
    )
}

/// THE TRANSLATE CAP IS THE SETTINGS' (row 155): the cap the door's codec enforces is the one the
/// kernel handed in the settings the plane was opened and refreshed with. Opened with none, the
/// whole answer of another dialect translates (200); refreshed onto settings whose
/// `limits.request_body_max_bytes` is below the answer's length, the same answer is refused with
/// the over-cap 500's own bytes. Linked and dropped in alike: no host reader is consulted.
#[test]
fn the_translate_cap_the_settings_carry_is_the_one_the_door_enforces() {
    // The openai over-cap refusal mints nothing, so the host it is rendered with gives nothing.
    struct NoHost;
    impl busbar_contract::codec::CodecHost for NoHost {
        fn fill_entropy(&self, _out: &mut [u8]) -> bool {
            false
        }
        fn wall_clock_now(&self) -> Option<u64> {
            None
        }
    }
    let refused = busbar_plane_llm::exchange::reply::whole::over_cap(&NoHost, "openai").answer;
    let d = Dispatcher::new(DispatchConfig::default());
    for p in [linked(&d), dropped(&d)] {
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SETTINGS));
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        assert_eq!(p.open(&mut Frame::new(i, o)).0.outcome, Outcome::Ready);
        let open = translated(&p, 21);
        assert!(
            open.contains(" status=200 ") && open.contains("chat.completion"),
            "opened with the default cap, the answer translates: {open}"
        );

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        (f.input.generation, f.input.settings) = (2, octets(SETTINGS_CAPPED));
        assert_eq!(p.refresh(&mut f).0.outcome, Outcome::Ready);
        let capped = translated(&p, 22);
        assert!(
            capped.contains(&format!(" status={} ", refused.status))
                && capped.contains(&format!(
                    "emitted={} more=",
                    String::from_utf8_lossy(&refused.body)
                )),
            "refreshed onto a 64-byte cap, the same answer is the over-cap refusal: {capped}"
        );
    }
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
        let bytes = input.bytes().bytes();
        let n = input.reply_buf().stream(bytes);
        out.set(|o| &o.emitted, n as u64);
        if input.from() == FROM_FAR_END && input.flags() & PIECE_LAST != 0 {
            out.set(|o| &o.flags, EMIT_DONE);
        }
        Outcome::Ready
    }
}

/// The llm door with `on_piece` swapped for [`Uncounted`].
extern "C" fn uncounted_door() -> *const Door {
    let d = plane_door::door();
    // SAFETY: the macro's `'static` door states a plane table.
    let mut ops = unsafe { *d.ops().cast::<plane::Ops>() };
    ops.on_piece = kind_op::<plane::Ops, Safe<Uncounted>, TestCapture, { slot::ON_PIECE }>();
    let ops: &'static plane::Ops = Box::leak(Box::new(ops));
    let mut parts = d.parts();
    parts.ops = std::ptr::from_ref(ops).cast();
    // SAFETY: the llm door's own `'static` Statement, over a leaked plane table whose every slot
    // honours the call convention (one swapped for the SDK's own `kind_op`).
    Box::leak(Box::new(unsafe { Door::__from_parts(parts) }))
}

#[test]
fn red_a_door_that_stops_counting_the_far_ends_units_answers_differently() {
    let d = Dispatcher::new(DispatchConfig::default());
    let honest = script(&linked(&d));
    // SAFETY: `uncounted_door` answers the `'static` door it laid out (leaked) over the llm door's.
    let door = unsafe { busbar_plugin_loader::dispatch::LoadedDoor::from_raw(uncounted_door) };
    let row = LinkedRow::of_loaded(door).expect("the door states its Statement");
    let red = script(&load_linked::<Plane>(&row, bind(&d)).expect("the door loads"));
    let far_end = |t: &[String]| t.iter().find(|l| l.starts_with("far_end ")).cloned();
    let red_line = far_end(&red).expect("the red door answers the far end");
    assert!(red_line.contains("units=[]"), "{red_line}");
    assert_ne!(Some(red_line), far_end(&honest));
    assert_ne!(red, honest);
}

/// THE PROVIDER KEYS THROUGH THE ONE LOADER (row 155 B1c, ARCHITECT ruling "Option A"): the
/// descriptor the door states (`meta::PROVIDER_KEYS`) is what its Statement rendering carries under
/// the contract's one extensions key, and what the loader hands on in the plane's registration.
/// Held here because this is the one file of the crate that may name the loader; the descriptor's
/// own shape is `tests/provider_keys.rs`'s.
mod provider_keys_through_the_loader {
    use busbar_contract::abi::mechanism::{extensions, rendering};
    use busbar_contract::provider_keys::{decode, EXT_PROVIDER_KEYS};
    use busbar_plane_llm::meta::PROVIDER_KEYS;
    use busbar_plane_llm::plane_door;
    use busbar_plugin_loader::dispatch::kinds::plane::{linked_probe_macro, registration};
    use busbar_plugin_loader::dispatch::rendering_of_macro;

    /// The door's signed Statement rendering carries the descriptor under the one extensions key, as
    /// octets, byte for byte the declared text.
    #[test]
    fn the_door_states_its_provider_keys_in_its_statement_extensions() {
        let stated =
            rendering_of_macro(plane_door::MACRO_DOOR).expect("the door renders its Statement");
        let read = rendering::read(&stated).expect("the rendering reads back");
        assert_eq!(
            read.extensions.fmt,
            busbar_contract::abi::mechanism::call::BLOB_OCTETS
        );
        assert_eq!(
            extensions::get(&read.extensions.bytes, EXT_PROVIDER_KEYS),
            Some(PROVIDER_KEYS.as_bytes())
        );
    }

    /// The one loader reads the descriptor off the bound door into the plane's registration, decoded
    /// and equal to the declared one.
    #[test]
    fn the_loader_hands_the_provider_keys_on_in_the_registration() {
        let reg = registration(linked_probe_macro(
            plane_door::MACRO_DOOR,
            "provider-keys-probe",
        ))
        .expect("the linked door binds");
        assert_eq!(
            reg.provider_keys,
            Some(
                decode(PROVIDER_KEYS.as_bytes())
                    .expect("the plane's provider keys are a neutral descriptor")
            )
        );
    }
}

/// THE DOOR'S UNITS ACROSS ATTEMPTS, driven through the one loader like the witness above. They live
/// in this file because it is the one file a plugin's tests may drive its door through the loader
/// from (kind isolation's both-ways witness rule).
///
/// THE DOOR'S UNITS ACROSS ATTEMPTS AND CUTS. A RETRY VERDICT, AS THE DOOR SERVES IT (row-159 audit plane-llm L1#1; status row 155): a far-end
/// error the plane judges retryable (here a context-length 400, the error map's class) keeps the
/// unit for the kernel's next ATTEMPT, so the failover reaches the next member, as 1.5.5 served the
/// second member after the first failed (v1.5.5 `crates/busbar/src/ingress/tests/tests.rs`
/// `test_real_failover_serves_second_member_after_first_5xx`, and the context-length exclusion of
/// `proxy`'s failover walk). An answer the kernel states it will not fail over (`PIECE_FINAL`) ends
/// the unit whatever its verdict, so the door keeps nothing behind it: a later piece of that unit is
/// a FAULT, the unit is gone.
mod door_units {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome};
    use busbar_contract::abi::plane::{
        slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
        UnitCount, EMIT_DONE, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_CUT, PIECE_FINAL,
        PIECE_HAS_STATUS, PIECE_LAST, VERDICT_HARD, VERDICT_OK, VERDICT_RETRY,
    };
    use busbar_plane_llm::plane_door;
    use busbar_plugin_loader::dispatch::kinds::plane::Plane;
    use busbar_plugin_loader::dispatch::{
        in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
        Plugin,
    };

    fn z<T>() -> T {
        // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
        unsafe { zeroed() }
    }

    fn octets(b: &'static [u8]) -> Blob {
        Blob::of(b)
    }

    const fn text(b: &'static [u8]) -> AbiStr {
        AbiStr::of_bytes(b)
    }

    const fn field(name: &'static [u8], value: &'static [u8]) -> Field {
        Field {
            name: text(name),
            value: text(value),
        }
    }

    /// Two anthropic far ends in one pool; the error map reads `invalid_request_error` as context length.
    const SETTINGS: &[u8] = br#"{
        "providers": {
            "ant-a": { "protocol": "anthropic", "base_url": "https://a.example",
                       "error_map": { "invalid_request_error": "context_length" } },
            "ant-b": { "protocol": "anthropic", "base_url": "https://b.example" }
        },
        "models": { "small": { "provider": "ant-a" }, "large": { "provider": "ant-b" } },
        "pools": { "p": { "members": ["small", "large"] } }
    }"#;
    const CHAT: &[u8] =
        br#"{"model":"p","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;
    const CALLER: &[Field] = &[
        field(b"content-type", b"application/json"),
        field(b"anthropic-version", b"2023-06-01"),
    ];
    const TOO_LONG: &[u8] =
        br#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"}}"#;
    const ANSWER: &[u8] = br#"{"id":"msg_1","type":"message","role":"assistant","model":"large","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
    const HEAD: &[Field] = &[field(b"content-type", b"application/json")];
    const SSE_HEAD: &[Field] = &[field(b"content-type", b"text/event-stream")];
    /// A streamed chat on the pool.
    const STREAM_CHAT: &[u8] =
        br#"{"model":"p","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    /// The far end's stream before its connection dropped: its start (7 tokens in, 1 out so far) and
    /// one content delta.
    const STREAM_START: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"large\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":7,\"output_tokens\":1}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hel\"}}\n\n";

    fn door() -> (Dispatcher, Plugin<Plane>) {
        let d = Dispatcher::new(DispatchConfig::default());
        let row = LinkedRow::of_macro(plane_door::MACRO_DOOR)
            .expect("the linked door states its Statement");
        let p = load_linked(
            &row,
            Bind {
                instance: Arc::from("the-instance"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
            },
        )
        .expect("the linked door loads");
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SETTINGS));
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (opened, _) = p.open(&mut Frame::new(i, o));
        assert_eq!(opened.outcome, Outcome::Ready, "the door opens");
        for s in [slot::HYDRATE, slot::START] {
            let mut g = Frame::new(
                busbar_contract::abi::mechanism::lifecycle::GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            assert_eq!(p.call(s, &mut g).outcome, Outcome::Ready);
        }
        (d, p)
    }

    fn arrive(p: &Plugin<Plane>, unit: u64) {
        arrive_with(p, unit, CHAT);
    }

    fn arrive_with(p: &Plugin<Plane>, unit: u64, body: &'static [u8]) {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        (a.input.unit, a.input.method, a.input.target) =
            (unit, text(b"POST"), text(b"/v1/messages"));
        (a.input.fields, a.input.fields_len) = (CALLER.as_ptr(), CALLER.len());
        a.input.body = octets(body);
        assert_eq!(p.call(slot::ARRIVE, &mut a).outcome, Outcome::Ready);
    }

    /// One piece's answer: its outcome, verdict and whether it closed the reply.
    #[derive(Debug, PartialEq, Eq)]
    struct Answer {
        outcome: Outcome,
        verdict: u32,
        done: bool,
        emitted: String,
        /// The counts the answer reported: `(class, amount)`.
        units: Vec<(u32, u64)>,
    }

    #[allow(clippy::too_many_arguments)]
    fn piece(
        p: &Plugin<Plane>,
        unit: u64,
        from: u32,
        flags: u32,
        status: u32,
        bytes: &'static [u8],
        member: &'static [u8],
        attempt_no: u32,
    ) -> Answer {
        piece_into(
            p, unit, from, flags, status, bytes, member, attempt_no, 4096,
        )
    }

    /// [`piece`], its answer written into a reply buffer of `cap` bytes.
    #[allow(clippy::too_many_arguments)]
    fn piece_into(
        p: &Plugin<Plane>,
        unit: u64,
        from: u32,
        flags: u32,
        status: u32,
        bytes: &'static [u8],
        member: &'static [u8],
        attempt_no: u32,
        cap: usize,
    ) -> Answer {
        let (mut reply, mut units, mut fields, mut arena) = (
            vec![0_u8; cap],
            [z::<UnitCount>(); 8],
            [z::<OutField>(); 16],
            [0_u8; 1024],
        );
        let mut i: OnPieceIn = z();
        i.head = in_head();
        (i.unit, i.from, i.flags, i.bytes) = (unit, from, flags, octets(bytes));
        (i.attempt_no, i.member, i.pool) = (attempt_no, text(member), text(b"p"));
        if flags & PIECE_HAS_STATUS != 0 {
            i.status_code = status;
            let head = if bytes.starts_with(b"event:") {
                SSE_HEAD
            } else {
                HEAD
            };
            (i.head_fields, i.head_fields_len) = (head.as_ptr(), head.len());
        }
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let mut o: OnPieceOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        let called = p.call(slot::ON_PIECE, &mut f);
        Answer {
            outcome: called.outcome,
            verdict: f.out.verdict,
            done: f.out.flags & EMIT_DONE != 0,
            emitted: String::from_utf8_lossy(&reply[..f.out.emitted as usize]).into_owned(),
            units: units[..f.out.units_written as usize]
                .iter()
                .map(|u| (u.class, u.amount))
                .collect(),
        }
    }

    /// One attempt of `unit` on `member`: its ATTEMPT piece and the caller's body.
    fn attempt(p: &Plugin<Plane>, unit: u64, member: &'static [u8], attempt_no: u32) {
        attempt_with(p, unit, member, attempt_no, CHAT);
    }

    fn attempt_with(
        p: &Plugin<Plane>,
        unit: u64,
        member: &'static [u8],
        attempt_no: u32,
        body: &'static [u8],
    ) {
        let a = piece(p, unit, FROM_KERNEL, 0, 0, b"", member, attempt_no);
        assert_eq!(
            a.outcome,
            Outcome::Ready,
            "the ATTEMPT on {member:?}: {a:?}"
        );
        let b = piece(p, unit, FROM_CALLER, PIECE_LAST, 0, body, member, 0);
        assert_eq!(b.outcome, Outcome::Ready, "the body on {member:?}: {b:?}");
    }

    /// RED: the door forgot the unit on its retry verdict, so the second ATTEMPT was a FAULT and the
    /// failover never reached `large`.
    #[test]
    fn a_retry_verdict_keeps_the_unit_and_the_failover_reaches_the_next_member() {
        let (_d, p) = door();
        arrive(&p, 7);
        attempt(&p, 7, b"small", 1);
        let failed = piece(
            &p,
            7,
            FROM_FAR_END,
            PIECE_HAS_STATUS | PIECE_LAST,
            400,
            TOO_LONG,
            b"small",
            0,
        );
        assert_eq!(failed.outcome, Outcome::Ready, "{failed:?}");
        assert_eq!(
            failed.verdict, VERDICT_RETRY,
            "context length is retried: {failed:?}"
        );
        attempt(&p, 7, b"large", 2);
        let served = piece(
            &p,
            7,
            FROM_FAR_END,
            PIECE_HAS_STATUS | PIECE_LAST,
            200,
            ANSWER,
            b"large",
            0,
        );
        assert_eq!(served.outcome, Outcome::Ready, "{served:?}");
        assert_eq!(served.verdict, VERDICT_OK);
        assert!(
            served.done && served.emitted.contains("hello"),
            "{served:?}"
        );
        // The unit ended with its answer: nothing of it is left behind.
        let after = piece(&p, 7, FROM_KERNEL, 0, 0, b"", b"small", 3);
        assert_eq!(
            after.outcome,
            Outcome::Fault,
            "the ended unit is gone: {after:?}"
        );
    }

    /// RED: a door that keeps every retried unit leaves one behind when the kernel will not fail the
    /// answer over (a relayed answer): the unit's later piece is answered instead of faulted.
    #[test]
    fn a_final_answer_ends_the_unit_whatever_its_verdict() {
        let (_d, p) = door();
        arrive(&p, 9);
        attempt(&p, 9, b"small", 1);
        let last = piece(
            &p,
            9,
            FROM_FAR_END,
            PIECE_HAS_STATUS | PIECE_LAST | PIECE_FINAL,
            400,
            TOO_LONG,
            b"small",
            0,
        );
        assert_eq!(last.outcome, Outcome::Ready, "{last:?}");
        assert_eq!(last.verdict, VERDICT_RETRY);
        assert!(last.done, "the final answer closes the reply: {last:?}");
        let after = piece(&p, 9, FROM_KERNEL, 0, 0, b"", b"large", 2);
        assert_eq!(
            after.outcome,
            Outcome::Fault,
            "nothing left behind: {after:?}"
        );
    }

    /// A piece whose flags the contract refuses (`PIECE_FINAL` without a status) is a FAULT.
    #[test]
    fn a_final_mark_off_the_status_piece_is_a_fault() {
        let (_d, p) = door();
        arrive(&p, 11);
        attempt(&p, 11, b"small", 1);
        let bad = piece(
            &p,
            11,
            FROM_FAR_END,
            PIECE_LAST | PIECE_FINAL,
            0,
            ANSWER,
            b"small",
            0,
        );
        assert_eq!(bad.outcome, Outcome::Fault, "{bad:?}");
    }

    /// A STREAM CUT AFTER ITS FIRST BYTE (`PIECE_CUT`; row-159 plane-llm L1#2), `$`: the caller's answer
    /// ends in its in-band error, never its clean terminator, and the unit reports the units its
    /// stream stated up to the cut (7 in, 1 out): the owner's #62, a cut bills what streamed (1.5.5
    /// billed no tokens; register entry "#62 an upstream cut after the first byte bills what
    /// streamed"). Nothing of the unit is left behind. RED: a cut fed to the reply as a clean end
    /// writes `message_stop` and no `event: error`.
    #[test]
    fn a_cut_stream_ends_in_the_callers_error_and_bills_what_streamed() {
        let (_d, p) = door();
        arrive_with(&p, 21, STREAM_CHAT);
        attempt_with(&p, 21, b"large", 1, STREAM_CHAT);
        let head = piece(
            &p,
            21,
            FROM_FAR_END,
            PIECE_HAS_STATUS,
            200,
            STREAM_START,
            b"large",
            0,
        );
        assert_eq!(head.outcome, Outcome::Ready, "{head:?}");
        assert!(
            head.emitted.contains("hel"),
            "the first byte reached the caller: {head:?}"
        );
        let cut = piece(
            &p,
            21,
            FROM_FAR_END,
            PIECE_LAST | PIECE_CUT,
            0,
            b"",
            b"large",
            0,
        );
        assert_eq!(cut.outcome, Outcome::Ready, "{cut:?}");
        assert!(cut.done, "the cut closes the reply: {cut:?}");
        assert_eq!(cut.verdict, VERDICT_HARD, "{cut:?}");
        assert!(
            cut.emitted.starts_with("event: error\n"),
            "1.5.5's in-band error: {cut:?}"
        );
        assert!(
            !cut.emitted.contains("message_stop"),
            "never a clean end: {cut:?}"
        );
        assert!(
            cut.units.contains(&(0, 7)) && cut.units.contains(&(1, 1)),
            "the units streamed to the cut, 7 in and 1 out: {cut:?}"
        );
        let after = piece(&p, 21, FROM_KERNEL, 0, 0, b"", b"large", 2);
        assert_eq!(
            after.outcome,
            Outcome::Fault,
            "nothing left behind: {after:?}"
        );
    }

    /// THE SAME STREAM, COMPLETE (the control): its last piece unmarked ends on the caller's clean
    /// terminator. A cut piece and a clean one are told apart only by `PIECE_CUT`.
    #[test]
    fn a_stream_that_completes_ends_cleanly() {
        let (_d, p) = door();
        arrive_with(&p, 23, STREAM_CHAT);
        attempt_with(&p, 23, b"large", 1, STREAM_CHAT);
        let head = piece(
            &p,
            23,
            FROM_FAR_END,
            PIECE_HAS_STATUS,
            200,
            STREAM_START,
            b"large",
            0,
        );
        assert_eq!(head.outcome, Outcome::Ready, "{head:?}");
        let end = piece(
            &p,
            23,
            FROM_FAR_END,
            PIECE_LAST,
            0,
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            b"large",
            0,
        );
        assert!(end.done && !end.emitted.contains("event: error"), "{end:?}");
    }

    /// A SAME-DIALECT WHOLE ANSWER CUT MID-BODY streams what arrived and bills no tokens. Under
    /// ARCHITECT ruling (a) (the base cut path supersedes #891's) and as v1.5.5 relayed it (a
    /// same-protocol non-stream body passes through verbatim as it arrives, v1.5.5
    /// `proxy/response_body.rs:216-262`), the far end's bytes reach the caller under its 200 as
    /// they come; the cut ends the body with nothing appended, and the far end reported no usage
    /// in the bytes in hand, so nothing bills (OWNER RULING Q31). A cut before the first byte
    /// never reaches the plane as a cut piece at all (the kernel's walk takes it as no answer and
    /// fails over, `far_end::no_answer`). RED: the arrived bytes held back, a body appended at the
    /// cut, or a token billed.
    #[test]
    fn a_same_dialect_answer_cut_mid_body_streams_what_arrived_and_bills_no_tokens() {
        let (_d, p) = door();
        arrive(&p, 25);
        attempt(&p, 25, b"large", 1);
        let head = piece(
            &p,
            25,
            FROM_FAR_END,
            PIECE_HAS_STATUS,
            200,
            b"{\"id\":",
            b"large",
            0,
        );
        assert_eq!(head.outcome, Outcome::Ready, "{head:?}");
        assert_eq!(
            head.emitted, "{\"id\":",
            "a same-dialect answer streams as it arrives: {head:?}"
        );
        let cut = piece(
            &p,
            25,
            FROM_FAR_END,
            PIECE_LAST | PIECE_CUT,
            0,
            b"",
            b"large",
            0,
        );
        assert_eq!(cut.outcome, Outcome::Ready, "{cut:?}");
        assert!(cut.done, "{cut:?}");
        assert!(
            cut.emitted.is_empty(),
            "the cut appends nothing to what arrived: {cut:?}"
        );
        assert!(cut.units.iter().all(|(_, n)| *n == 0), "no tokens: {cut:?}");
    }

    /// The cancel disposition the door answers for the unit on the (one) ticket these tests cross on.
    fn cancel(p: &Plugin<Plane>) -> u32 {
        let mut x: Frame<
            busbar_contract::abi::plane::PlaneCancelIn,
            busbar_contract::abi::plane::PlaneCancelOut,
        > = Frame::new(z(), z());
        (x.input.cancel.head, x.out.cancel.head) = (in_head(), out_head());
        assert_eq!(
            p.call(
                busbar_contract::abi::mechanism::lifecycle::slot::CANCEL,
                &mut x
            )
            .outcome,
            Outcome::Ready
        );
        x.out.cancel.disposition
    }

    /// A CALLER THAT LEAVES WHILE THE LAST WINDOW OF A COMPLETED STREAM IS BEING WRITTEN (row-159
    /// plane-llm L1#5), `$`: the answer was a usable success, fully reported, so its cancel is PARTIAL and
    /// the units the stream stated bill, as a caller that left mid-relay does and as 1.5.5's drop arm
    /// billed the reader's usage (v1.5.5 `proxy/response_body.rs` `FirstByteBody::drop`). RED: the door
    /// read the finished reply as nothing usable and answered ABORTED, billing 0 tokens for a fully
    /// reported completion.
    #[test]
    fn a_caller_that_leaves_during_the_last_window_bills_what_the_stream_stated() {
        let (_d, p) = door();
        arrive_with(&p, 31, STREAM_CHAT);
        attempt_with(&p, 31, b"large", 1, STREAM_CHAT);
        let head = piece(
            &p,
            31,
            FROM_FAR_END,
            PIECE_HAS_STATUS,
            200,
            STREAM_START,
            b"large",
            0,
        );
        assert_eq!(head.outcome, Outcome::Ready, "{head:?}");
        // The far end's last piece, its answer written 16 bytes at a time: the first window only.
        let last = piece_into(
            &p,
            31,
            FROM_FAR_END,
            PIECE_LAST,
            0,
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            b"large",
            0,
            16,
        );
        assert_eq!(last.outcome, Outcome::Ready, "{last:?}");
        assert!(!last.done, "more of the last window is owed: {last:?}");
        assert_eq!(
            cancel(&p),
            busbar_contract::abi::plane::CANCEL_OK_PARTIAL,
            "the stated units of a fully reported stream bill"
        );
    }

    /// THE CONTROL: a caller that leaves before the first byte of the answer reached it bills nothing.
    #[test]
    fn a_caller_that_leaves_before_the_first_byte_bills_nothing() {
        let (_d, p) = door();
        arrive_with(&p, 33, STREAM_CHAT);
        attempt_with(&p, 33, b"large", 1, STREAM_CHAT);
        assert_eq!(cancel(&p), busbar_contract::abi::plane::CANCEL_ABORTED);
    }
}

/// The door brought up on [`SETTINGS`]: settings checked, opened, hydrated and started, as the
/// script brings it up.
fn opened(dispatcher: &Dispatcher) -> Plugin<Plane> {
    let door = linked(dispatcher);
    let mut validate = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: octets(SETTINGS),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    assert_eq!(
        door.call(life::VALIDATE, &mut validate).outcome,
        Outcome::Ready
    );
    let mut open_in: PlaneOpenIn = z();
    open_in.open.head = in_head();
    (open_in.open.generation, open_in.open.settings) = (1, octets(SETTINGS));
    let mut open_out: PlaneOpenOut = z();
    open_out.open.head = out_head();
    let (called, _) = door.open(&mut Frame::new(open_in, open_out));
    assert_eq!(called.outcome, Outcome::Ready, "the door opens");
    for lifecycle in [slot::HYDRATE, slot::START] {
        let mut generation = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        door.call(lifecycle, &mut generation);
    }
    door
}

/// A probe arrival for `unit`: the claim is the probe claim, no caller body.
fn arrive_probe(door: &Plugin<Plane>, unit: u64) -> String {
    let mut arrival: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (arrival.input.head, arrival.out.head) = (in_head(), out_head());
    (arrival.input.unit, arrival.input.claim) = (unit, plane::CLAIM_PROBE);
    (arrival.input.method, arrival.input.target) = (text(b"POST"), text(b"/v1/messages"));
    let called = door.call(slot::ARRIVE, &mut arrival);
    format!(
        "arrive {:?} principal_required={}",
        called.outcome,
        arrival.out.principal_need == PRINCIPAL_REQUIRED
    )
}

/// The far end's error answers the fee cases feed.
const UPSTREAM_FAILED: &[u8] =
    br#"{"type":"error","error":{"type":"api_error","message":"upstream failed"}}"#;
const NOT_FOUND: &[u8] =
    br#"{"type":"error","error":{"type":"not_found_error","message":"no such model"}}"#;

/// The per-request fee unit as a transcript line spells it: the fee class, one, reported.
fn fee_line() -> String {
    format!("\"{}:1:true\"", plane_door::FEE_CLASS_INDEX)
}

/// One whole caller unit on a fresh door: arrive, attempt, the caller's body, then the far end's
/// whole answer under `status`. Answers the attempt, body and far-end lines.
fn one_unit(status: u32, answer: &'static [u8]) -> (String, String, String) {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let door = opened(&dispatcher);
    assert!(arrive(&door, 7, b"/v1/messages", CHAT).starts_with("arrive Ready"));
    let mut piece = Piece::new(1024);
    let attempt = piece.call(&door, 7, FROM_KERNEL, 0, b"", 1);
    let body = piece.call(&door, 7, FROM_CALLER, PIECE_LAST, CHAT, 0);
    piece.status = status;
    let far = piece.call(
        &door,
        7,
        FROM_FAR_END,
        PIECE_HAS_STATUS | PIECE_LAST,
        answer,
        0,
    );
    (attempt, body, far)
}

/// THE FEE IS DECIDED BY THE LEG AND THE CLIENT-FACING STATUS (row 719).
///
/// Legacy: the retiring engine crate's `src/unit/tests/meter.rs::the_fee_is_decided_by_the_leg_and_the_client_facing_status`
/// (coverage map row 719, REHOME). 1.5.5 behaviour pinned: one flat fee per delivered request that
/// routed to a far end — a 2xx answer from the far end carries the fee unit; a far-end 502 and a
/// post-admission 404 carry none; a leg that is not the caller's answer (the attempt and the body
/// the door sends TO the far end, the kernel-verb side of a unit) carries none; and a breaker probe
/// is no billable request, so its 2xx carries none either. `fee_unit()` in `plane_door.rs` is the
/// one decider (2xx only, not a probe, not a far-end-bound leg).
///
/// RED: a door that bills the fee on any status (a 502 or a 404 carries the fee unit), on the
/// far-end-bound legs, or on a probe's 2xx; or one that stops billing a delivered 2xx.
#[test]
fn the_fee_is_decided_by_the_leg_and_the_client_facing_status() {
    let fee = fee_line();

    let (attempt, body, delivered) = one_unit(200, ANSWER);
    assert!(
        delivered.contains("status=200") && delivered.contains(&fee),
        "a 2xx delivered from the far end carries the one fee unit: {delivered}"
    );
    assert_eq!(
        delivered.matches(&fee).count(),
        1,
        "exactly one fee unit: {delivered}"
    );
    for (leg, line) in [("attempt", &attempt), ("body", &body)] {
        assert!(
            line.contains("to_far_end=true") && line.contains(" units=[] "),
            "the {leg} leg goes TO the far end, so it is no delivered request and carries no \
             fee: {line}"
        );
    }

    for (status, answer, why) in [
        (502, UPSTREAM_FAILED, "a failed transfer posts no fee"),
        (404, NOT_FOUND, "a post-admission 404 is unbilled"),
    ] {
        let (_, _, far) = one_unit(status, answer);
        assert!(
            far.starts_with("Ready ") && !far.contains("status=200"),
            "{why}: the far end's {status} is answered, never as a success: {far}"
        );
        assert!(!far.contains(&fee), "{why}: no fee unit: {far}");
    }

    // A breaker probe: one member, no caller. Its 2xx is the far end's own, and no billable request.
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let door = opened(&dispatcher);
    assert_eq!(
        arrive_probe(&door, 11),
        "arrive Ready principal_required=false",
        "a probe claim needs no principal"
    );
    let mut piece = Piece::new(1024);
    let probe_attempt = piece.call(&door, 11, FROM_KERNEL, 0, b"", 1);
    assert!(
        probe_attempt.contains("to_far_end=true") && probe_attempt.contains(" units=[] "),
        "the probe's request goes to the far end and carries no fee: {probe_attempt}"
    );
    let probe_far = piece.call(
        &door,
        11,
        FROM_FAR_END,
        PIECE_HAS_STATUS | PIECE_LAST,
        ANSWER,
        0,
    );
    assert!(
        probe_far.contains("status=200") && !probe_far.contains(&fee),
        "a probe's 2xx is no billable request: {probe_far}"
    );
}

// THE PUBLISHED CONFORMANCE SUITE, run over this plane (TODO ABI-b4; OWNER 2026-10-03: plugins
// test themselves against busbar's published suite): the linked door and the `llm_door` cdylib,
// driven by busbar-plugin-loader's plane script over `conformance.json`, every step at its pinned
// crossing count, the two folds equal. Its sessions are the far ends' own answers, one per dialect
// that reports a class (Anthropic server tools, an OpenAI stated total, Cohere billed units, three
// Bedrock guardrail traces, an OpenAI per-image answer, a whisper duration), each wanting its
// counts exactly, so every billable class the tail declares is reported by a case (TODO L-R22).
busbar_plugin_loader::conformance_suite! {
    door: busbar_plane_llm::plane_door::MACRO_DOOR,
    cdylib: "llm_door",
    inputs: include_str!("conformance.json"),
}
