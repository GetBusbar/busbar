// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RETRY VERDICT, AS THE DOOR SERVES IT (row-159 audit plane-llm L1#1; status row 155): a far-end
//! error the plane judges retryable (here a context-length 400, the error map's class) keeps the
//! unit for the kernel's next ATTEMPT, so the failover reaches the next member, as 1.5.5 served the
//! second member after the first failed (v1.5.5 `crates/busbar/src/ingress/tests/tests.rs`
//! `test_real_failover_serves_second_member_after_first_5xx`, and the context-length exclusion of
//! `proxy`'s failover walk). An answer the kernel states it will not fail over (`PIECE_FINAL`) ends
//! the unit whatever its verdict, so the door keeps nothing behind it: a later piece of that unit is
//! a FAULT, the unit is gone.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::slot as life;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    UnitCount, EMIT_DONE, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_FINAL, PIECE_HAS_STATUS,
    PIECE_LAST, VERDICT_OK, VERDICT_RETRY,
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
const CHAT: &[u8] = br#"{"model":"p","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;
const CALLER: &[Field] = &[
    field(b"content-type", b"application/json"),
    field(b"anthropic-version", b"2023-06-01"),
];
const TOO_LONG: &[u8] =
    br#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"}}"#;
const ANSWER: &[u8] = br#"{"id":"msg_1","type":"message","role":"assistant","model":"large","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
const HEAD: &[Field] = &[field(b"content-type", b"application/json")];

fn door() -> (Dispatcher, Plugin<Plane>) {
    let d = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
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
    for s in [life::HYDRATE, life::START] {
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
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    (a.input.unit, a.input.method, a.input.target) = (unit, text(b"POST"), text(b"/v1/messages"));
    (a.input.fields, a.input.fields_len) = (CALLER.as_ptr(), CALLER.len());
    a.input.body = octets(CHAT);
    assert_eq!(p.call(slot::ARRIVE, &mut a).outcome, Outcome::Ready);
}

/// One piece's answer: its outcome, verdict and whether it closed the reply.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    outcome: Outcome,
    verdict: u32,
    done: bool,
    emitted: String,
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
    let (mut reply, mut units, mut fields, mut arena) = (
        vec![0_u8; 4096],
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
        (i.head_fields, i.head_fields_len) = (HEAD.as_ptr(), HEAD.len());
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
    }
}

/// One attempt of `unit` on `member`: its ATTEMPT piece and the caller's body.
fn attempt(p: &Plugin<Plane>, unit: u64, member: &'static [u8], attempt_no: u32) {
    let a = piece(p, unit, FROM_KERNEL, 0, 0, b"", member, attempt_no);
    assert_eq!(
        a.outcome,
        Outcome::Ready,
        "the ATTEMPT on {member:?}: {a:?}"
    );
    let b = piece(p, unit, FROM_CALLER, PIECE_LAST, 0, CHAT, member, 0);
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
