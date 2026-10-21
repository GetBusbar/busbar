// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin test support against a REAL door: a transport built by `plugin_door!` over the
//! generic lifecycle, with two claims, two claim rows, their facts and one declared answer. Its
//! Statement is read back through [`DoorView`] and its `open`/`close` slots are called over
//! [`zeroed`] `in`s and `out`s, all without `unsafe`, as a plugin's own tests do.

use core::mem::size_of;
use core::ptr;

use super::*;
use crate::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use crate::abi::mechanism::door::KindTailHead;
use crate::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use crate::abi::sdk::door::{abi_str, statement};
use crate::abi::sdk::life::{Life, Refreshed, Refusal};
use crate::abi::transport::{
    Claim, FramePiece, FramerSink, IngestIn, TransportTail, FRAMING_STREAM, ROLE_FRAMER,
    UNIT0_UPGRADE,
};

const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

const CLAIM_NAMES: &[AbiStr] = &[abi_str("probe"), abi_str("probes")];
const FORMS: &[u8] = &[1, 2];
const FACTS: &[AbiStr] = &[abi_str("probe.fact-a"), abi_str("probe.fact-b")];
const ANSWERS: &[AbiStr] = &[abi_str("probe.answer")];

const ROW: Claim = Claim {
    selector_forms: AbiStr {
        ptr: FORMS.as_ptr(),
        len: FORMS.len(),
    },
    egress_selector_forms: NONE,
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: abi_str("probe-status"),
    session: 1,
    session_bound: 0,
    unit0_trigger: UNIT0_UPGRADE,
    status_at: 0,
    _reserved: 0,
};

/// The second claim's row differs: no sessions, and only its first fact.
const ROWS: &[Claim] = &[
    ROW,
    Claim {
        session: 0,
        facts_len: 1,
        ..ROW
    },
];

const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 3,
    composes_over: ptr::null(),
    composes_over_len: 0,
    claim_rows: ROWS.as_ptr(),
    claim_rows_len: ROWS.len(),
    upgrades_to: ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: ptr::null(),
    status_rows_len: 0,
    settings: ptr::null(),
    settings_len: 0,
    fault_rows: ptr::null(),
    fault_rows_len: 0,
    frame_piece_size: size_of::<FramePiece>() as u32,
    _reserved: 0,
};

const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    answers: ANSWERS.as_ptr(),
    answers_len: ANSWERS.len(),
    ..statement("probe-transport", "0.0.1", 4)
};

/// The probe's instance state: nothing.
struct Probe;

impl Life for Probe {
    const CANCEL: u32 = 0;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Probe)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

mod plugin {
    crate::plugin_door! {
        ops: crate::abi::transport::Ops,
        statement: super::STATEMENT,
        lifecycle: life(super::Probe),
    }
}

fn view() -> DoorView {
    DoorView::of(plugin::door)
}

/// A head for slot `op` over a `T` `in`, every other byte zero.
fn in_head<T>(op: u32) -> InHead {
    let mut h: InHead = zeroed();
    h.size = size_of::<T>() as u32;
    h.op = op;
    h
}

/// A head for a `T` `out`, every other byte zero.
fn out_head<T>() -> OutHead {
    let mut h: OutHead = zeroed();
    h.size = size_of::<T>() as u32;
    h
}

#[test]
fn a_zeroed_struct_is_every_field_zero() {
    let piece: FramePiece = zeroed();
    assert_eq!(
        (
            piece.stream,
            piece.offset,
            piece.len,
            piece.code,
            piece.flags
        ),
        (0, 0, 0, 0, 0)
    );
    let sink = FramerSink::default();
    assert!(sink.wire.is_null() && sink.frame.is_null() && sink.pieces.is_null());
    assert_eq!((sink.wire_cap, sink.frame_cap, sink.pieces_cap), (0, 0, 0));
    let pieces: Vec<FramePiece> = vec![zeroed(); 4];
    assert!(pieces.iter().all(|p| p.len == 0 && p.declared_len == 0));
    let array: [FramePiece; 4] = zeroed();
    assert!(array.iter().all(|p| p.stream == 0));
    let ingest = IngestIn::default();
    assert!(ingest.bytes.is_null());
    assert_eq!((ingest.head.size, ingest.head.op, ingest.len), (0, 0, 0));
    let slots = crate::abi::host::service::HostSlots::default();
    assert!(slots.clock_now.is_none() && slots.session_emit.is_none());
}

#[test]
fn a_real_doors_slots_run_over_zeroed_ins_and_outs() {
    let table = view().ops::<crate::abi::transport::Ops>();
    let open = table.head.open.expect("the door states open");
    let close = table.head.close.expect("the door states close");

    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    let mut out: OpenOut = zeroed();
    out.head = out_head::<OpenOut>();
    let answered = open(
        ptr::null_mut(),
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut out).cast(),
    )
    .outcome();
    assert_eq!(answered, Outcome::Ready);
    assert!(!out.instance.is_null(), "open answered an instance");

    let input = in_head::<InHead>(slot::CLOSE);
    let mut done = out_head::<OutHead>();
    let answered = close(
        out.instance,
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut done).cast(),
    )
    .outcome();
    assert_eq!(answered, Outcome::Ready);
}

#[test]
fn the_statement_reads_back_its_name_claims_and_declared_answers() {
    let v = view();
    assert_eq!(v.kind(), Some(KindCode::Transport));
    assert_eq!(v.name(), "probe-transport");
    assert_eq!(v.claims(), ["probe", "probes"]);
    assert_eq!(v.declares(), ["probe.answer"]);
    assert_eq!(v.statement().max_inflight, 4);
}

#[test]
fn the_kind_tail_and_each_claim_row_with_its_facts_read_back() {
    let v = view();
    let tail = v.kind_tail::<TransportTail>();
    assert_eq!((tail.role, tail.framing), (ROLE_FRAMER, FRAMING_STREAM));
    assert_eq!(tail.handshake_max_steps, 3);
    let rows = v.claim_rows();
    assert_eq!(rows.len(), v.claims().len(), "one row per claim");
    assert_eq!(rows[0].selector_forms, FORMS);
    assert!(rows[0].egress_selector_forms.is_empty());
    assert_eq!(rows[0].facts, ["probe.fact-a", "probe.fact-b"]);
    assert_eq!(rows[0].status_namespace, "probe-status");
    assert_eq!((rows[0].session, rows[0].unit0_trigger), (1, UNIT0_UPGRADE));
    assert_eq!(rows[1].facts, ["probe.fact-a"]);
    assert_eq!(rows[1].session, 0);
}

#[test]
#[should_panic(expected = "the door is not of the kind whose tail was asked for")]
fn another_kinds_tail_is_refused() {
    let _ = view().kind_tail::<crate::abi::plane::PlaneTail>();
}

#[test]
#[should_panic(expected = "the door is not of the kind whose table was asked for")]
fn another_kinds_table_is_refused() {
    let _ = view().ops::<crate::abi::secret::Ops>();
}
