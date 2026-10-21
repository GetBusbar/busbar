// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin test support against a REAL door: a transport built by `plugin_door!` over the
//! generic lifecycle, with two claims, two claim rows, their facts and one declared answer. Its
//! Statement is read back through [`DoorView`] and its `open`/`close` slots are called over
//! [`zeroed`] `in`s and `out`s, all without `unsafe`, as a plugin's own tests do. Beside it: a plane
//! door whose tail's texts and lists read back, the reason a failed `open` wrote into the buffer the
//! test lent, and fake host services called as a plugin's SDK calls them.

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

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        if let Some(why) = settings.strip_prefix(b"boom:") {
            // An owned text: an instance-less failure writes it into the host's lent buffer.
            return Err(Refusal::failed(format!(
                "probe open failed:{}",
                String::from_utf8_lossy(why)
            )));
        }
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

// ── a plane's tail ───────────────────────────────────────────────────────────────────────────────

const DIALECTS: &[AbiStr] = &[abi_str("probe-dialect")];
const FEE_UNITS: &[AbiStr] = &[abi_str("per_call")];
const BILLABLE: &[crate::abi::plane::BillableClass] = &[
    crate::abi::plane::BillableClass {
        class: abi_str("tokens_in"),
        family: abi_str("token"),
    },
    crate::abi::plane::BillableClass {
        class: abi_str("per_call"),
        family: abi_str("count"),
    },
];

const PLANE_TAIL: crate::abi::plane::PlaneTail = crate::abi::plane::PlaneTail {
    head: KindTailHead {
        size: size_of::<crate::abi::plane::PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: 0,
    dispatch_shape: 0,
    answer_layout: 0,
    scope: abi_str("probe-scope"),
    label: NONE,
    subject_noun: NONE,
    admin_noun: NONE,
    audit_kind: abi_str("probe_audit"),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    dialect_auth: ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: ptr::null(),
    scope_kinds_len: 0,
    op_classes: ptr::null(),
    op_classes_len: 0,
    billable_classes: BILLABLE.as_ptr(),
    billable_classes_len: BILLABLE.len(),
    route_cost: ptr::null(),
    route_cost_len: 0,
    fee_units: FEE_UNITS.as_ptr(),
    fee_units_len: FEE_UNITS.len(),
    record_kinds: ptr::null(),
    record_kinds_len: 0,
    egress_targets: ptr::null(),
    egress_targets_len: 0,
    record_chains: ptr::null(),
    record_chains_len: 0,
    trust_keys: ptr::null(),
    trust_keys_len: 0,
    refusal_statuses: ptr::null(),
    refusal_statuses_len: 0,
    caller_credential_refusal: NONE,
    admin_routes: ptr::null(),
    admin_routes_len: 0,
    admin_openapi: crate::abi::mechanism::call::Blob::ABSENT,
    stream_ceiling_secs: 0,
    metric_lanes: ptr::null(),
    metric_lanes_len: 0,
};

/// A plane door, laid out as `plugin_door!` lays one (its Statement stamped, every slot absent):
/// only its Statement is read.
const PLANE_STATEMENT: &Statement =
    &crate::abi::sdk::door::stamp::<crate::abi::plane::Ops>(Statement {
        kind_tail: (&PLANE_TAIL as *const crate::abi::plane::PlaneTail).cast::<KindTailHead>(),
        ..statement("probe-plane", "0.0.1", 1)
    });
const PLANE_OPS: &crate::abi::plane::Ops =
    &crate::abi::sdk::door::absent_table::<crate::abi::plane::Ops>();
const PLANE_DOOR: &crate::abi::mechanism::door::Door =
    &crate::abi::sdk::door::door::<crate::abi::plane::Ops>(PLANE_STATEMENT, PLANE_OPS, None);

extern "C" fn plane_door() -> *const crate::abi::mechanism::door::Door {
    PLANE_DOOR
}

#[test]
fn a_plane_tails_texts_words_and_rows_read_back() {
    let v = DoorView::of(plane_door);
    assert_eq!(v.kind(), Some(KindCode::Plane));
    assert_eq!(v.plane_text(PlaneText::Scope), "probe-scope");
    assert_eq!(v.plane_text(PlaneText::AuditKind), "probe_audit");
    assert_eq!(
        v.plane_text(PlaneText::Label),
        "",
        "an absent text reads empty"
    );
    assert_eq!(v.plane_words(PlaneWords::FeeUnits), ["per_call"]);
    assert_eq!(v.plane_words(PlaneWords::Dialects), ["probe-dialect"]);
    assert!(v.plane_words(PlaneWords::MetricLanes).is_empty());
    assert_eq!(v.plane_word_list(PlaneWords::FeeUnits).len(), 1);
    assert_eq!(
        v.billable_classes(),
        [
            BillableClassRow {
                class: "tokens_in",
                family: "token"
            },
            BillableClassRow {
                class: "per_call",
                family: "count"
            },
        ]
    );
    assert_eq!(v.plane_rows::<crate::abi::plane::BillableClass>().len(), 2);
    assert!(v.plane_rows::<crate::abi::plane::OpClass>().is_empty());
}

#[test]
#[should_panic(expected = "the door is not of the kind whose tail was asked for")]
fn a_plane_read_of_a_transport_door_is_refused() {
    let _ = view().plane_words(PlaneWords::FeeUnits);
}

// ── what a plugin wrote into a lent buffer ─────────────────────────────────────────────────────

#[test]
fn a_failed_opens_reason_reads_back_from_the_lent_buffer() {
    let table = view().ops::<crate::abi::transport::Ops>();
    let open = table.head.open.expect("the door states open");
    let settings = b"boom: x";
    let mut reason = [0_u8; 64];
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    input.settings = crate::abi::mechanism::call::Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..crate::abi::mechanism::call::Blob::ABSENT
    };
    input.err_buf = reason.as_mut_ptr();
    input.err_cap = reason.len();
    let mut out: OpenOut = zeroed();
    out.head = out_head::<OpenOut>();
    let answered = open(
        ptr::null_mut(),
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut out).cast(),
    )
    .outcome();
    assert_eq!(answered, Outcome::Failed);
    assert_eq!(
        written_text(&reason, out.err_len, "open.err_len"),
        "probe open failed: x"
    );
    assert_eq!(
        written(&reason, out.err_len, "open.err_len"),
        b"probe open failed: x"
    );
}

#[test]
#[should_panic(expected = "open.err_len: the plugin states it wrote 9 bytes into a buffer of 4")]
fn a_length_past_the_lent_capacity_is_refused() {
    let _ = written(&[0_u8; 4], 9_usize, "open.err_len");
}

#[test]
#[should_panic(expected = "reason: not UTF-8")]
fn written_text_that_is_not_utf8_is_refused() {
    let _ = written_text(&[0xff, 0xfe], 2_u64, "reason");
}

// ── fake host services ──────────────────────────────────────────────────────────────────────────

use super::fake::{FakeHost, FakeService, ServiceCall};
use crate::abi::host::service::{
    self as svc, ClockNowIn, ClockReading, ItemSpan, RecordsGetIn, ServiceBufs, ServiceHead,
    ServiceOut,
};
use crate::abi::mechanism::call::Span;
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};

/// A clock at a fixed instant.
struct Clock;
impl FakeService for Clock {
    type In = ClockNowIn;
    fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
        call.put(
            |i| &i.reading,
            ClockReading {
                size: size_of::<ClockReading>() as u32,
                _reserved: 0,
                wall_ns: 7,
                mono_ns: 9,
            },
        );
        Outcome::Ready
    }
}

/// A record store holding one record, `probe` = `value-of-probe`, of kind `kind`.
struct Records;
impl FakeService for Records {
    type In = RecordsGetIn;
    fn serve(call: &mut ServiceCall<RecordsGetIn>) -> Outcome {
        assert_eq!(call.text(|i| &i.kind), "kind");
        if call.bytes(|i| &i.key) != b"probe" {
            call.set_value(svc::ABSENT);
            return Outcome::Ready;
        }
        let record = b"value-of-probe";
        let span = ItemSpan {
            key: Span {
                offset: crate::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
            value: Span {
                offset: 0,
                len: record.len() as u32,
            },
        };
        if !call.fill(|i| &i.into, record, &[span]) {
            return Outcome::Ready;
        }
        call.set_value(svc::FOUND);
        Outcome::Ready
    }
}

/// A double whose selector names memory outside its call's `in`.
struct Stray;
impl FakeService for Stray {
    type In = RecordsGetIn;
    fn serve(call: &mut ServiceCall<RecordsGetIn>) -> Outcome {
        let _ = call.bytes(|_| &NONE);
        Outcome::Ready
    }
}

fn service_head<T>(op: u32) -> ServiceHead {
    ServiceHead {
        size: size_of::<T>() as u32,
        op,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

fn get(
    host: &FakeHost,
    key: &[u8],
    buf: &mut [u8],
    spans: &mut [ItemSpan],
) -> (RecordsGetIn, ServiceOut) {
    let input = RecordsGetIn {
        head: service_head::<RecordsGetIn>(svc::op::RECORDS_GET),
        kind: abi_str("kind"),
        key: AbiStr {
            ptr: key.as_ptr(),
            len: key.len(),
        },
        into: ServiceBufs {
            buf: buf.as_mut_ptr(),
            cap: buf.len(),
            spans: spans.as_mut_ptr(),
            spans_cap: spans.len(),
        },
    };
    let mut out: ServiceOut = zeroed();
    let f = host.services().records_get.expect("records.get is served");
    let raw = f(
        HostCtx::NONE,
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(raw, out.outcome, "the return value is mirrored");
    (input, out)
}

#[test]
fn a_fake_service_answers_as_the_host_does() {
    let host = FakeHost::new()
        .serve(fake::host::CLOCK_NOW, Clock)
        .serve(fake::host::RECORDS_GET, Records);
    assert!(
        host.services().records_list.is_none(),
        "an unserved slot is absent"
    );
    assert!(!host.tables().is_null());

    // clock.now writes the reading the plugin lent, as the host's own check admits.
    let mut reading: ClockReading = zeroed();
    let input = ClockNowIn {
        head: service_head::<ClockNowIn>(svc::op::CLOCK_NOW),
        reading: ptr::from_mut(&mut reading),
    };
    let mut out: ServiceOut = zeroed();
    let clock = host.services().clock_now.expect("clock.now is served");
    let raw = clock(
        HostCtx::NONE,
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(raw.outcome(), Outcome::Ready);
    assert!(svc::check_clock_now(&input, raw, &out).is_ok());
    assert_eq!((reading.wall_ns, reading.mono_ns), (7, 9));

    // records.get reads the key the plugin lent and fills the buffers it lent.
    let mut buf = [0_u8; 32];
    let mut spans: [ItemSpan; 2] = zeroed();
    let (input, out) = get(&host, b"probe", &mut buf, &mut spans);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);
    assert_eq!((out.value, out.len, out.items), (svc::FOUND, 14, 1));
    assert!(svc::check_records_get(&input, out.outcome, &out).is_ok());
    assert_eq!(&buf[..14], b"value-of-probe");
    assert_eq!(spans[0].value.len, 14);

    // A result the lent capacity does not hold writes nothing and states its size.
    let mut small = [0_u8; 4];
    let (_, out) = get(&host, b"probe", &mut small, &mut spans);
    assert_eq!((out.len, out.needed_bytes, out.needed_items), (0, 14, 1));
    assert_eq!(small, [0; 4]);
}

#[test]
fn a_fake_refuses_an_in_of_another_op_a_short_in_and_a_stray_selector_with_fault() {
    let host = FakeHost::new().serve(fake::host::RECORDS_GET, Records);
    let mut buf = [0_u8; 32];
    let mut spans: [ItemSpan; 1] = zeroed();
    let mut input = RecordsGetIn {
        head: service_head::<RecordsGetIn>(svc::op::RECORDS_LIST),
        kind: abi_str("kind"),
        key: abi_str("probe"),
        into: ServiceBufs {
            buf: buf.as_mut_ptr(),
            cap: buf.len(),
            spans: spans.as_mut_ptr(),
            spans_cap: spans.len(),
        },
    };
    let call = |host: &FakeHost, input: &RecordsGetIn| {
        let mut out: ServiceOut = zeroed();
        let f = host.services().records_get.expect("served");
        f(
            HostCtx::NONE,
            ptr::from_ref(input).cast(),
            ptr::from_mut(&mut out).cast(),
        )
        .outcome()
    };
    // An `in` whose head names another op: the double never runs.
    assert_eq!(call(&host, &input), Outcome::Fault);
    assert_eq!(buf, [0; 32], "nothing was written");
    // An `in` whose head states fewer bytes than the slot's `in`: the same.
    input.head = service_head::<ClockNowIn>(svc::op::RECORDS_GET);
    assert_eq!(call(&host, &input), Outcome::Fault);
    // A double whose selector names memory outside its call's `in`: FAULT, nothing read.
    input.head = service_head::<RecordsGetIn>(svc::op::RECORDS_GET);
    let stray = FakeHost::new().serve(fake::host::RECORDS_GET, Stray);
    assert_eq!(call(&stray, &input), Outcome::Fault);
    // The well-formed call still answers.
    assert_eq!(call(&host, &input), Outcome::Ready);
}
