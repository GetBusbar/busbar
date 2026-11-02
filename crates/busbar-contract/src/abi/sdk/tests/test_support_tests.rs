// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ordinary SDK tests over exported descriptors, caller-owned ABI frames and concrete callbacks.

use super::zeroed;
use crate::abi::host::service::{
    self as svc, ClockNowIn, ClockReading, HostSlots, ItemSpan, RecordsGetIn, ServiceOut,
};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, RawOutcome};
use crate::abi::mechanism::door::{KindTailHead, Statement};
use crate::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};
use crate::abi::mechanism::KindCode;
use crate::abi::sdk::door::{abi_str, statement};
use crate::abi::sdk::life::{Life, Refreshed, Refusal};
use crate::abi::transport::{
    Claim, FramePiece, FramerSink, IngestIn, TransportTail, FRAMING_STREAM, ROLE_FRAMER,
    UNIT0_UPGRADE,
};
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr;

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

mod allowed_needs {
    use crate::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND};
    use crate::abi::sdk::door::abi_str;

    const NEEDS: &[Need] = &[Need {
        direction: DIRECTION_OUTBOUND,
        transport: abi_str("https"),
        ..Need::EMPTY
    }
    .with_keep_response_headers(&[abi_str("retry-after")])];
    crate::plugin_door! {
        ops: crate::abi::transport::Ops,
        statement: super::STATEMENT.with_needs(NEEDS),
        lifecycle: life(super::Probe),
    }
}

mod forbidden_needs {
    use crate::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND};
    use crate::abi::sdk::door::abi_str;

    const NEEDS: &[Need] = &[Need {
        direction: DIRECTION_OUTBOUND,
        transport: abi_str("https"),
        ..Need::EMPTY
    }
    .with_keep_response_headers(&[abi_str("authorization")])];
    crate::plugin_door! {
        ops: crate::abi::transport::Ops,
        statement: super::STATEMENT.with_needs(NEEDS),
        lifecycle: life(super::Probe),
    }
}

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
    record_retentions: ptr::null(),
    record_retentions_len: 0,
    ..crate::abi::plane::PlaneTail::ZERO
};

/// A plane door, laid out as `plugin_door!` lays one (its Statement stamped, every slot absent):
const PLANE_STATEMENT: &Statement =
    &crate::abi::sdk::door::stamp::<crate::abi::plane::Ops>(Statement {
        kind_tail: (&PLANE_TAIL as *const crate::abi::plane::PlaneTail).cast::<KindTailHead>(),
        ..statement("probe-plane", "0.0.1", 1)
    });
const PLANE_OPS: &crate::abi::plane::Ops =
    &crate::abi::sdk::door::absent_table::<crate::abi::plane::Ops>();
// SAFETY: this file's `'static` Statement and tail, and an all-absent table.
const PLANE_DOOR: &crate::abi::mechanism::door::Door = &unsafe {
    crate::abi::sdk::door::door::<crate::abi::plane::Ops>(PLANE_STATEMENT, PLANE_OPS, None)
};

fn transport_ops() -> &'static crate::abi::transport::Ops {
    let door = (plugin::MACRO_DOOR.door_fn())();
    assert_eq!(door.kind(), KindCode::Transport as u32);
    // SAFETY: this exact macro exports a static transport table.
    unsafe { &*door.ops().cast::<crate::abi::transport::Ops>() }
}

fn in_head<T>(op: u32) -> InHead {
    let mut head: InHead = zeroed();
    head.size = size_of::<T>() as u32;
    head.op = op;
    head
}

fn out_head<T>() -> OutHead {
    let mut head: OutHead = zeroed();
    head.size = size_of::<T>() as u32;
    head
}

unsafe extern "C" fn clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: Services::clock_now supplies these exact exclusive output and input frames,
    // including a live, exclusively lent ClockReading.
    let (input, out) = unsafe { (&*input.cast::<ClockNowIn>(), &mut *out) };
    assert_eq!(input.head.op, svc::op::CLOCK_NOW);
    assert_eq!(input.head.size as usize, size_of::<ClockNowIn>());
    // SAFETY: the SDK clock call owns this reading until the callback returns.
    unsafe {
        input.reading.write(ClockReading {
            size: size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: 7,
            mono_ns: 9,
        })
    };
    out.outcome = RawOutcome::of(Outcome::Ready);
    out.outcome
}

unsafe extern "C" fn records(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: Services::records_get supplies a complete RecordsGetIn and exclusive ServiceOut.
    let (input, out) = unsafe { (&*input.cast::<RecordsGetIn>(), &mut *out) };
    assert_eq!(input.head.op, svc::op::RECORDS_GET);
    // SAFETY: these exact strings are borrowed from the SDK call for this callback's duration.
    let (kind, key) = unsafe {
        (
            std::slice::from_raw_parts(input.kind.ptr, input.kind.len),
            std::slice::from_raw_parts(input.key.ptr, input.key.len),
        )
    };
    assert_eq!(kind, b"kind");
    if key != b"probe" {
        out.value = svc::ABSENT;
        out.outcome = RawOutcome::of(Outcome::Ready);
        return out.outcome;
    }
    let record = b"value-of-probe";
    if input.into.cap < record.len() || input.into.spans_cap < 1 {
        out.needed_bytes = record.len() as u64;
        out.needed_items = 1;
        out.outcome = RawOutcome::of(Outcome::Failed);
        return out.outcome;
    }
    // SAFETY: the capacity checks cover both live SDK-owned output buffers. They do not
    // overlap this static record, and the callback writes exactly one item.
    unsafe {
        ptr::copy_nonoverlapping(record.as_ptr(), input.into.buf, record.len());
        input.into.spans.write(ItemSpan {
            key: crate::abi::mechanism::call::Span {
                offset: crate::abi::mechanism::check::SPAN_ABSENT,
                len: 0,
            },
            value: crate::abi::mechanism::call::Span {
                offset: 0,
                len: record.len() as u32,
            },
        });
    }
    out.value = svc::FOUND;
    out.len = record.len() as u64;
    out.items = 1;
    out.outcome = RawOutcome::of(Outcome::Ready);
    out.outcome
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
fn needs_validation_reads_the_exported_descriptor_and_nested_headers() {
    for (door, forbidden) in [
        ((allowed_needs::MACRO_DOOR.door_fn())(), false),
        ((plugin::MACRO_DOOR.door_fn())(), false),
        ((forbidden_needs::MACRO_DOOR.door_fn())(), true),
    ] {
        // SAFETY: each macro exports its static Statement and its static Need list.
        let statement = unsafe { &*door.statement() };
        let needs = if statement.needs_len == 0 {
            &[][..]
        } else {
            // SAFETY: the exact exported Need array remains static and has this declared length.
            unsafe { std::slice::from_raw_parts(statement.needs, statement.needs_len) }
        };
        // SAFETY: the exact macro-exported Need rows and all their nested headers are static.
        let result = unsafe { crate::abi::mechanism::check::check_needs(needs) };
        if forbidden {
            let fault = result.expect_err("authorization retention is forbidden");
            assert_eq!(fault.rule, crate::abi::mechanism::check::Rule::Foreign);
            assert_eq!(fault.field, "need.keep_response_headers");
        } else {
            assert_eq!(result, Ok(()));
        }
    }
}

#[test]
fn real_door_slots_open_and_close_over_complete_caller_owned_frames() {
    let table = transport_ops();
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    let mut output: OpenOut = zeroed();
    output.head = out_head::<OpenOut>();
    // SAFETY: OPEN receives its full live input/output frames and no instance. No nested loan.
    let outcome = unsafe {
        table.head.open.unwrap()(
            ptr::null_mut(),
            ptr::from_ref(&input).cast(),
            ptr::from_mut(&mut output).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Ready);
    assert!(!output.instance.is_null());
    let close = in_head::<InHead>(slot::CLOSE);
    let mut closed = out_head::<OutHead>();
    // SAFETY: the same door uniquely closes the instance it just opened; both frames remain live.
    let outcome = unsafe {
        table.head.close.unwrap()(
            output.instance,
            ptr::from_ref(&close).cast(),
            ptr::from_mut(&mut closed).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Ready);
}

#[test]
fn exported_statement_retains_name_claims_answers_and_capacity() {
    let door = (plugin::MACRO_DOOR.door_fn())();
    assert_eq!(door.kind(), KindCode::Transport as u32);
    // SAFETY: this exact plugin exports this static Statement and its static string arrays.
    let s = unsafe { &*door.statement() };
    assert_eq!(s.max_inflight, 4);
    assert_eq!((s.claims_len, s.answers_len), (2, 1));
    // SAFETY: all pointers below are the immutable static arrays and strings declared above.
    unsafe {
        assert_eq!(
            std::slice::from_raw_parts(s.name.ptr, s.name.len),
            b"probe-transport"
        );
        for (name, expected) in std::slice::from_raw_parts(s.claims, s.claims_len)
            .iter()
            .zip([b"probe".as_slice(), b"probes"])
        {
            assert_eq!(std::slice::from_raw_parts(name.ptr, name.len), expected);
        }
        let answer = &*s.answers;
        assert_eq!(
            std::slice::from_raw_parts(answer.ptr, answer.len),
            b"probe.answer"
        );
    }
}

#[test]
fn transport_tail_retains_each_claims_forms_facts_and_session() {
    let door = (plugin::MACRO_DOOR.door_fn())();
    // SAFETY: this transport macro's static Statement names exactly TAIL and ROWS.
    unsafe {
        let s = &*door.statement();
        let tail = &*s.kind_tail.cast::<TransportTail>();
        assert_eq!(
            (tail.role, tail.framing, tail.handshake_max_steps),
            (ROLE_FRAMER, FRAMING_STREAM, 3)
        );
        let rows = std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len);
        assert_eq!(rows.len(), s.claims_len);
        assert_eq!(
            std::slice::from_raw_parts(rows[0].selector_forms.ptr, rows[0].selector_forms.len),
            FORMS
        );
        assert_eq!(rows[0].egress_selector_forms.len, 0);
        assert_eq!((rows[0].facts_len, rows[1].facts_len), (2, 1));
        for (fact, expected) in std::slice::from_raw_parts(rows[0].facts, rows[0].facts_len)
            .iter()
            .zip([b"probe.fact-a".as_slice(), b"probe.fact-b"])
        {
            assert_eq!(std::slice::from_raw_parts(fact.ptr, fact.len), expected);
        }
        let fact = &*rows[1].facts;
        assert_eq!(
            std::slice::from_raw_parts(fact.ptr, fact.len),
            b"probe.fact-a"
        );
        assert_eq!(
            std::slice::from_raw_parts(rows[0].status_namespace.ptr, rows[0].status_namespace.len),
            b"probe-status"
        );
        assert_eq!(
            (rows[0].session, rows[0].unit0_trigger, rows[1].session),
            (1, UNIT0_UPGRADE, 0)
        );
    }
}

#[test]
fn plane_descriptor_retains_text_lists_and_billable_rows() {
    assert_eq!(PLANE_DOOR.kind(), KindCode::Plane as u32);
    // SAFETY: PLANE_DOOR names the static PLANE_STATEMENT, PLANE_TAIL and their static arrays.
    unsafe {
        let tail = &*(*PLANE_DOOR.statement())
            .kind_tail
            .cast::<crate::abi::plane::PlaneTail>();
        assert_eq!(
            std::slice::from_raw_parts(tail.scope.ptr, tail.scope.len),
            b"probe-scope"
        );
        assert_eq!(
            std::slice::from_raw_parts(tail.audit_kind.ptr, tail.audit_kind.len),
            b"probe_audit"
        );
        assert!(tail.label.ptr.is_null());
        assert_eq!(tail.label.len, 0);
        assert_eq!(
            (
                tail.fee_units_len,
                tail.dialects_len,
                tail.metric_lanes_len,
                tail.op_classes_len
            ),
            (1, 1, 0, 0)
        );
        let fee = &*tail.fee_units;
        let dialect = &*tail.dialects;
        assert_eq!(std::slice::from_raw_parts(fee.ptr, fee.len), b"per_call");
        assert_eq!(
            std::slice::from_raw_parts(dialect.ptr, dialect.len),
            b"probe-dialect"
        );
        let rows = std::slice::from_raw_parts(tail.billable_classes, tail.billable_classes_len);
        assert_eq!(rows.len(), 2);
        for (row, (class, family)) in rows.iter().zip([
            (b"tokens_in".as_slice(), b"token".as_slice()),
            (b"per_call", b"count"),
        ]) {
            assert_eq!(
                std::slice::from_raw_parts(row.class.ptr, row.class.len),
                class
            );
            assert_eq!(
                std::slice::from_raw_parts(row.family.ptr, row.family.len),
                family
            );
        }
    }
}

#[test]
fn failed_open_writes_its_reason_into_the_caller_owned_buffer() {
    let settings = b"boom: x";
    let mut reason = [0_u8; 64];
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        ..Blob::ABSENT
    };
    input.err_buf = reason.as_mut_ptr();
    input.err_cap = reason.len();
    let mut output: OpenOut = zeroed();
    output.head = out_head::<OpenOut>();
    // SAFETY: the full OPEN frames and exclusive reason buffer remain live for this call.
    let outcome = unsafe {
        transport_ops().head.open.unwrap()(
            ptr::null_mut(),
            ptr::from_ref(&input).cast(),
            ptr::from_mut(&mut output).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Failed);
    assert!(output.instance.is_null());
    assert!(output.err_len <= reason.len());
    assert_eq!(&reason[..output.err_len], b"probe open failed: x");
    assert_eq!(
        std::str::from_utf8(&reason[..output.err_len]),
        Ok("probe open failed: x")
    );
}

#[test]
fn concrete_host_callbacks_answer_sdk_clock_records_and_short_buffer_calls() {
    use crate::abi::sdk::services::{ServiceError, Services};
    use core::task::Poll;
    let mut slots = HostSlots::default();
    slots.size = size_of::<HostSlots>() as u32;
    slots.slots = svc::SERVICES;
    slots.clock_now = Some(clock);
    slots.records_get = Some(records);
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: ptr::null(),
        services: &slots,
        io: ptr::null(),
    };
    // SAFETY: the complete tables remain live here; both callbacks are static and use no context.
    let services = Services::of(unsafe { crate::abi::sdk::Lent::new(&tables) }).unwrap();
    let handle = CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    };
    let reading = services.clock_now(handle).unwrap();
    assert_eq!((reading.wall_ns, reading.mono_ns), (7, 9));
    let mut buf = [0_u8; 32];
    assert!(matches!(
        services.records_get(handle, "kind", b"probe", &mut buf),
        Poll::Ready(Ok(Some(b"value-of-probe")))
    ));
    assert!(matches!(
        services.records_get(handle, "kind", b"absent", &mut buf),
        Poll::Ready(Ok(None))
    ));
    let mut small = [0_u8; 4];
    assert!(matches!(
        services.records_get(handle, "kind", b"probe", &mut small),
        Poll::Ready(Err(ServiceError::Short {
            bytes: 14,
            items: 1
        }))
    ));
    assert_eq!(small, [0; 4]);
    let mut spans: [ItemSpan; 1] = zeroed();
    assert!(matches!(
        services.records_list(handle, "kind", b"", None, 0, (&mut buf, &mut spans)),
        Poll::Ready(Err(ServiceError::Unserved))
    ));
}

#[test]
fn direct_login_validator_refuses_a_null_form_with_a_nonzero_count() {
    let mut output: crate::abi::auth::BeginLoginOut = zeroed();
    output.shape = crate::abi::auth::BEGIN_FORM;
    output.form_len = 2;
    let fault = crate::abi::auth::check_begin_login(Outcome::Ready, &output).unwrap_err();
    assert_eq!(
        fault.rule,
        crate::abi::mechanism::check::Rule::NullWithCount
    );
}

#[test]
fn hosted_open_closes_over_the_same_live_concrete_tables() {
    let mut slots = HostSlots::default();
    slots.size = size_of::<HostSlots>() as u32;
    slots.slots = svc::SERVICES;
    slots.clock_now = Some(clock);
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: ptr::null(),
        services: &slots,
        io: ptr::null(),
    };
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    input.host = &tables;
    let mut output: OpenOut = zeroed();
    output.head = out_head::<OpenOut>();
    let table = transport_ops();
    // SAFETY: both complete frames and all nested tables remain live through CLOSE below.
    let outcome = unsafe {
        table.head.open.unwrap()(
            ptr::null_mut(),
            ptr::from_ref(&input).cast(),
            ptr::from_mut(&mut output).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Ready);
    assert!(!output.instance.is_null());
    let input = in_head::<InHead>(slot::CLOSE);
    let mut closed = out_head::<OutHead>();
    // SAFETY: this is the same door's unique instance, with its original host still live.
    let outcome = unsafe {
        table.head.close.unwrap()(
            output.instance,
            ptr::from_ref(&input).cast(),
            ptr::from_mut(&mut closed).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Ready);
}

#[test]
fn lifecycle_slot_indices_are_the_exported_tables_actual_offsets() {
    use crate::abi::sdk::door::slot_at;
    assert_eq!(
        slot_at(
            offset_of!(crate::abi::transport::Ops, head)
                + offset_of!(crate::abi::mechanism::lifecycle::OpsHead, open)
        ),
        slot::OPEN
    );
    assert_eq!(
        slot_at(
            offset_of!(crate::abi::transport::Ops, head)
                + offset_of!(crate::abi::mechanism::lifecycle::OpsHead, close)
        ),
        slot::CLOSE
    );
    let door = (plugin::MACRO_DOOR.door_fn())();
    // SAFETY: the macro exports exactly this static table with these lifecycle slots.
    let head = unsafe { &*door.ops() };
    assert_eq!(
        head.open.unwrap() as usize,
        transport_ops().head.open.unwrap() as usize
    );
    assert_eq!(
        head.close.unwrap() as usize,
        transport_ops().head.close.unwrap() as usize
    );
}

#[test]
fn sdk_slot_types_match_the_kinds_declared_input_and_output_frames() {
    use crate::abi::sdk::door::{slot_count, KindSlot, Lifecycle};
    use crate::abi::{auth, export, hook, plane, secret, store, transport};
    use std::any::TypeId;
    for count in [
        slot_count::<store::Ops>(),
        slot_count::<secret::Ops>(),
        slot_count::<auth::Ops>(),
        slot_count::<hook::Ops>(),
        slot_count::<export::Ops>(),
        slot_count::<plane::Ops>(),
        slot_count::<transport::Ops>(),
    ] {
        assert!(count > slot::CLOSE);
    }
    assert_eq!(
        TypeId::of::<<Lifecycle as KindSlot<{ slot::OPEN }>>::In>(),
        TypeId::of::<OpenIn>()
    );
    assert_eq!(
        TypeId::of::<<Lifecycle as KindSlot<{ slot::CLOSE }>>::In>(),
        TypeId::of::<InHead>()
    );
    assert_eq!(
        TypeId::of::<<plane::PlaneLifecycle as KindSlot<{ slot::OPEN }>>::In>(),
        TypeId::of::<plane::PlaneOpenIn>()
    );
    assert_eq!(
        TypeId::of::<<transport::Ops as KindSlot<{ transport::slot::LISTEN }>>::In>(),
        TypeId::of::<transport::ListenIn>()
    );
    assert_eq!(
        TypeId::of::<<plane::Ops as KindSlot<{ plane::slot::ARRIVE }>>::In>(),
        TypeId::of::<plane::ArriveIn>()
    );
    assert_eq!(
        TypeId::of::<<auth::Ops as KindSlot<{ auth::slot::VERIFY }>>::In>(),
        TypeId::of::<auth::VerifyIn>()
    );
    assert_eq!(
        TypeId::of::<<secret::Ops as KindSlot<{ secret::slot::RESOLVE }>>::In>(),
        TypeId::of::<secret::ResolveIn>()
    );
    assert_eq!(
        TypeId::of::<<hook::Ops as KindSlot<{ hook::slot::NOTIFY }>>::In>(),
        TypeId::of::<hook::NotifyIn>()
    );
    assert_eq!(
        TypeId::of::<<export::Ops as KindSlot<{ export::slot::SCRAPE }>>::In>(),
        TypeId::of::<export::ScrapeIn>()
    );
    assert_eq!(
        TypeId::of::<<store::Ops as KindSlot<{ store::slot::GET_KEY }>>::In>(),
        TypeId::of::<store::IdIn>()
    );
    assert_eq!(
        TypeId::of::<<Lifecycle as KindSlot<{ slot::OPEN }>>::Out>(),
        TypeId::of::<OpenOut>()
    );
}

#[test]
fn sdk_host_handles_copy_the_concrete_tables_before_the_allocations_drop() {
    use crate::abi::sdk::conn::Host;
    use crate::abi::sdk::services::Services;
    let (host, services) = {
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let mut io: crate::abi::host::io::IoSlots = zeroed();
        io.size = size_of::<crate::abi::host::io::IoSlots>() as u32;
        io.slots = crate::abi::host::io::SLOTS;
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: &io,
        };
        // SAFETY: all advertised table prefixes are live through these copying constructors.
        // Their sole callback is static, needs no context and remains callable afterward.
        let lent = unsafe { crate::abi::sdk::Lent::new(&tables) };
        (Host::of(lent), Services::of(lent).unwrap())
    };
    let handle = CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    };
    assert_eq!(services.clock_now(handle).unwrap().mono_ns, 9);
    assert_eq!(
        host.services().unwrap().clock_now(handle).unwrap().wall_ns,
        7
    );
    assert!(
        matches!(host.connector(Ticket::NONE).clock_now(), core::task::Poll::Ready(Ok(r)) if r.mono_ns == 9)
    );
    assert!(host.io(Ticket::NONE).armed());
}

mod pending_open_custody {
    use super::*;
    use crate::abi::mechanism::call::{BLOB_OCTETS, FLAG_RESUME};
    use crate::abi::mechanism::lifecycle::{CancelIn, CancelOut};
    use crate::abi::sdk::conn::Host;
    use crate::abi::sdk::life::Opening;
    use std::any::Any;
    use std::cell::RefCell;
    const TICKET: Ticket = Ticket {
        slot: 19,
        generation: 1,
    };
    const SECRET_REFS: &[AbiStr] = &[abi_str("fixture-secret")];

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Counts {
        opens: usize,
        steps: usize,
        resumes: usize,
        cancels: usize,
        closes: usize,
        drops: usize,
        parked_drops: usize,
    }

    thread_local! {
        static COUNTS: RefCell<Counts> = RefCell::new(Counts::default());
    }

    fn counts() -> Counts {
        COUNTS.with(|state| *state.borrow())
    }

    fn reset() {
        COUNTS.with(|state| *state.borrow_mut() = Counts::default());
    }

    struct Parked;

    impl Drop for Parked {
        fn drop(&mut self) {
            COUNTS.with(|state| state.borrow_mut().parked_drops += 1);
        }
    }

    struct PendingLife {
        fail: bool,
    }

    impl Drop for PendingLife {
        fn drop(&mut self) {
            COUNTS.with(|state| state.borrow_mut().drops += 1);
        }
    }

    fn check_host(host: Option<&Host>) {
        let host = host.expect("the original host loan remains installed");
        let reading = host
            .services()
            .expect("the concrete host has services")
            .clock_now(CompletionHandle {
                ticket: TICKET,
                seq: 0,
                _reserved: 0,
            })
            .expect("the original host remains callable");
        assert_eq!((reading.wall_ns, reading.mono_ns), (7, 9));
    }

    impl Life for PendingLife {
        const CANCEL: u32 = 17;

        fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
            assert_eq!(secrets, [b"nested-secret".as_slice()]);
            assert_eq!(generation, 41);
            COUNTS.with(|state| state.borrow_mut().opens += 1);
            Ok(Self {
                fail: settings == br#"{"fail":true}"#,
            })
        }

        fn opening(
            &self,
            host: Option<&Host>,
            ticket: Ticket,
            parked: Option<Box<dyn Any + Send + Sync>>,
        ) -> Opening {
            assert_eq!(ticket, TICKET, "every resume keeps the original ticket");
            check_host(host);
            COUNTS.with(|state| state.borrow_mut().steps += 1);
            let Some(parked) = parked else {
                return Opening::Pending {
                    wake_at_ns: 0,
                    parked: Box::new(Parked),
                };
            };
            match parked.downcast::<Parked>() {
                Ok(parked) => drop(parked),
                Err(_) => panic!("resume must recover its original parked continuation"),
            }
            COUNTS.with(|state| state.borrow_mut().resumes += 1);
            if self.fail {
                Opening::Failed(Refusal::failed("scripted pending OPEN failure"))
            } else {
                Opening::Ready
            }
        }

        fn cancel(&self, ticket: Ticket) -> u32 {
            assert_eq!(ticket, TICKET);
            COUNTS.with(|state| state.borrow_mut().cancels += 1);
            Self::CANCEL
        }

        fn close(&self, host: Option<&Host>) {
            check_host(host);
            COUNTS.with(|state| state.borrow_mut().closes += 1);
        }
    }

    mod first {
        crate::plugin_door! {
            ops: crate::abi::secret::Ops,
            statement: crate::abi::sdk::door::statement("pending-open-first", "0", 1)
                .with_secret_refs(super::SECRET_REFS),
            lifecycle: life(super::PendingLife),
        }
    }

    mod other {
        crate::plugin_door! {
            ops: crate::abi::secret::Ops,
            statement: crate::abi::sdk::door::statement("pending-open-other", "0", 1)
                .with_secret_refs(super::SECRET_REFS),
            lifecycle: life(super::PendingLife),
        }
    }

    #[test]
    fn pending_open_resumes_once_over_its_original_host_and_nested_secret() {
        reset();
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: ptr::null(),
        };
        let secret = String::from("nested-secret");
        let secrets = [Blob {
            ptr: secret.as_ptr(),
            len: secret.len(),
            fmt: BLOB_OCTETS,
            ..Blob::ABSENT
        }];
        let settings = br#"{"fail":false}"#;
        let mut reason = [0_u8; 64];
        let mut input: OpenIn = zeroed();
        input.head = in_head::<OpenIn>(slot::OPEN);
        input.head.ticket = TICKET;
        input.host = &tables;
        input.settings = Blob::json(settings);
        input.secrets = secrets.as_ptr();
        input.secrets_len = secrets.len();
        input.generation = 41;
        input.err_buf = reason.as_mut_ptr();
        input.err_cap = reason.len();
        let door = (first::MACRO_DOOR.door_fn())();
        // SAFETY: this exact macro exports a static secret Ops table.
        let table = unsafe { &*door.ops().cast::<crate::abi::secret::Ops>() };
        let mut output: OpenOut = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: OPEN has no instance; its complete frames, host tables, settings, secret array,
        // nested secret bytes and exclusive reason buffer stay live through every operation below.
        let outcome = unsafe {
            table.head.open.unwrap()(
                ptr::null_mut(),
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Pending);
        assert!(!output.instance.is_null());
        let instance = output.instance;
        assert_eq!(counts().opens, 1);
        input.head.flags = FLAG_RESUME;
        output = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: the same door resumes its live pending instance on the original ticket and
        // original complete frames and nested loans; output is exclusive for this call.
        let outcome = unsafe {
            table.head.open.unwrap()(
                instance,
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(output.instance, instance);
        let close = in_head::<InHead>(slot::CLOSE);
        let mut closed = out_head::<OutHead>();
        // SAFETY: this same door uniquely closes its live instance while the original host is live.
        let outcome = unsafe {
            table.head.close.unwrap()(
                instance,
                ptr::from_ref(&close).cast(),
                ptr::from_mut(&mut closed).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(
            counts(),
            Counts {
                opens: 1,
                steps: 2,
                resumes: 1,
                closes: 1,
                drops: 1,
                parked_drops: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn failed_pending_open_retires_its_partial_instance_without_close() {
        reset();
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: ptr::null(),
        };
        let secret = String::from("nested-secret");
        let secrets = [Blob {
            ptr: secret.as_ptr(),
            len: secret.len(),
            fmt: BLOB_OCTETS,
            ..Blob::ABSENT
        }];
        let settings = br#"{"fail":true}"#;
        let mut reason = [0_u8; 64];
        let mut input: OpenIn = zeroed();
        input.head = in_head::<OpenIn>(slot::OPEN);
        input.head.ticket = TICKET;
        input.host = &tables;
        input.settings = Blob::json(settings);
        input.secrets = secrets.as_ptr();
        input.secrets_len = secrets.len();
        input.generation = 41;
        input.err_buf = reason.as_mut_ptr();
        input.err_cap = reason.len();
        let door = (first::MACRO_DOOR.door_fn())();
        // SAFETY: this exact macro exports a static secret Ops table.
        let table = unsafe { &*door.ops().cast::<crate::abi::secret::Ops>() };
        let mut output: OpenOut = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: OPEN has no instance; its complete frames, host tables, settings, secret array,
        // nested secret bytes and exclusive reason buffer stay live through every operation below.
        let outcome = unsafe {
            table.head.open.unwrap()(
                ptr::null_mut(),
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Pending);
        assert!(!output.instance.is_null());
        let instance = output.instance;
        input.head.flags = FLAG_RESUME;
        output = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: the same door resumes its live pending instance on the original ticket and
        // original complete frames and nested loans; output is exclusive for this call.
        let outcome = unsafe {
            table.head.open.unwrap()(
                instance,
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Failed);
        assert!(output.instance.is_null());
        assert!(output.err_len <= reason.len());
        assert_eq!(&reason[..output.err_len], b"scripted pending OPEN failure");
        assert_eq!(
            counts(),
            Counts {
                opens: 1,
                steps: 2,
                resumes: 1,
                drops: 1,
                parked_drops: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn cancelling_then_closing_pending_open_keeps_disposition_and_drops_once() {
        reset();
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: ptr::null(),
        };
        let secret = String::from("nested-secret");
        let secrets = [Blob {
            ptr: secret.as_ptr(),
            len: secret.len(),
            fmt: BLOB_OCTETS,
            ..Blob::ABSENT
        }];
        let settings = br#"{"fail":false}"#;
        let mut reason = [0_u8; 64];
        let mut input: OpenIn = zeroed();
        input.head = in_head::<OpenIn>(slot::OPEN);
        input.head.ticket = TICKET;
        input.host = &tables;
        input.settings = Blob::json(settings);
        input.secrets = secrets.as_ptr();
        input.secrets_len = secrets.len();
        input.generation = 41;
        input.err_buf = reason.as_mut_ptr();
        input.err_cap = reason.len();
        let door = (first::MACRO_DOOR.door_fn())();
        // SAFETY: this exact macro exports a static secret Ops table.
        let table = unsafe { &*door.ops().cast::<crate::abi::secret::Ops>() };
        let mut output: OpenOut = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: OPEN has no instance; its complete frames, host tables, settings, secret array,
        // nested secret bytes and exclusive reason buffer stay live through every operation below.
        let outcome = unsafe {
            table.head.open.unwrap()(
                ptr::null_mut(),
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Pending);
        assert!(!output.instance.is_null());
        let instance = output.instance;
        let cancel = CancelIn {
            head: in_head::<CancelIn>(slot::CANCEL),
            ticket: TICKET,
        };
        let mut cancelled: CancelOut = zeroed();
        cancelled.head = out_head::<CancelOut>();
        // SAFETY: the same door's live instance receives its exact CANCEL frame and original ticket.
        let outcome = unsafe {
            table.head.cancel.unwrap()(
                instance,
                ptr::from_ref(&cancel).cast(),
                ptr::from_mut(&mut cancelled).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(cancelled.disposition, PendingLife::CANCEL);
        let close = in_head::<InHead>(slot::CLOSE);
        let mut closed = out_head::<OutHead>();
        // SAFETY: this same door uniquely closes its live instance while the original host is live.
        let outcome = unsafe {
            table.head.close.unwrap()(
                instance,
                ptr::from_ref(&close).cast(),
                ptr::from_mut(&mut closed).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(
            counts(),
            Counts {
                opens: 1,
                steps: 1,
                cancels: 1,
                closes: 1,
                drops: 1,
                parked_drops: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn closing_unfinished_open_retires_while_its_original_host_is_live() {
        reset();
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: ptr::null(),
        };
        let secret = String::from("nested-secret");
        let secrets = [Blob {
            ptr: secret.as_ptr(),
            len: secret.len(),
            fmt: BLOB_OCTETS,
            ..Blob::ABSENT
        }];
        let settings = br#"{"fail":false}"#;
        let mut reason = [0_u8; 64];
        let mut input: OpenIn = zeroed();
        input.head = in_head::<OpenIn>(slot::OPEN);
        input.head.ticket = TICKET;
        input.host = &tables;
        input.settings = Blob::json(settings);
        input.secrets = secrets.as_ptr();
        input.secrets_len = secrets.len();
        input.generation = 41;
        input.err_buf = reason.as_mut_ptr();
        input.err_cap = reason.len();
        let door = (first::MACRO_DOOR.door_fn())();
        // SAFETY: this exact macro exports a static secret Ops table.
        let table = unsafe { &*door.ops().cast::<crate::abi::secret::Ops>() };
        let mut output: OpenOut = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: OPEN has no instance; its complete frames, host tables, settings, secret array,
        // nested secret bytes and exclusive reason buffer stay live through every operation below.
        let outcome = unsafe {
            table.head.open.unwrap()(
                ptr::null_mut(),
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Pending);
        assert!(!output.instance.is_null());
        let instance = output.instance;
        let close = in_head::<InHead>(slot::CLOSE);
        let mut closed = out_head::<OutHead>();
        // SAFETY: this same door uniquely closes its live instance while the original host is live.
        let outcome = unsafe {
            table.head.close.unwrap()(
                instance,
                ptr::from_ref(&close).cast(),
                ptr::from_mut(&mut closed).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(
            counts(),
            Counts {
                opens: 1,
                steps: 1,
                closes: 1,
                drops: 1,
                parked_drops: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn resume_on_another_ticket_does_not_enter_the_pending_continuation() {
        reset();
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: ptr::null(),
        };
        let secret = String::from("nested-secret");
        let secrets = [Blob {
            ptr: secret.as_ptr(),
            len: secret.len(),
            fmt: BLOB_OCTETS,
            ..Blob::ABSENT
        }];
        let settings = br#"{"fail":false}"#;
        let mut reason = [0_u8; 64];
        let mut input: OpenIn = zeroed();
        input.head = in_head::<OpenIn>(slot::OPEN);
        input.head.ticket = TICKET;
        input.host = &tables;
        input.settings = Blob::json(settings);
        input.secrets = secrets.as_ptr();
        input.secrets_len = secrets.len();
        input.generation = 41;
        input.err_buf = reason.as_mut_ptr();
        input.err_cap = reason.len();
        let door = (first::MACRO_DOOR.door_fn())();
        // SAFETY: this exact macro exports a static secret Ops table.
        let table = unsafe { &*door.ops().cast::<crate::abi::secret::Ops>() };
        let mut output: OpenOut = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: OPEN has no instance; its complete frames, host tables, settings, secret array,
        // nested secret bytes and exclusive reason buffer stay live through every operation below.
        let outcome = unsafe {
            table.head.open.unwrap()(
                ptr::null_mut(),
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Pending);
        assert!(!output.instance.is_null());
        let instance = output.instance;
        assert!(!ptr::eq(door, (other::MACRO_DOOR.door_fn())()));
        input.head.ticket.generation += 1;
        input.head.flags = FLAG_RESUME;
        output = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: the same door receives its live instance and complete frames with all original
        // nested loans. The deliberately changed ticket is rejected before entering its continuation.
        let outcome = unsafe {
            table.head.open.unwrap()(
                instance,
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Fault);
        assert!(output.instance.is_null());
        assert_eq!(
            counts(),
            Counts {
                opens: 1,
                steps: 1,
                drops: 1,
                parked_drops: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn cancelled_pending_open_cannot_resume_and_retires_once() {
        reset();
        let mut slots = HostSlots::default();
        slots.size = size_of::<HostSlots>() as u32;
        slots.slots = svc::SERVICES;
        slots.clock_now = Some(clock);
        let tables = HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns: ptr::null(),
            services: &slots,
            io: ptr::null(),
        };
        let secret = String::from("nested-secret");
        let secrets = [Blob {
            ptr: secret.as_ptr(),
            len: secret.len(),
            fmt: BLOB_OCTETS,
            ..Blob::ABSENT
        }];
        let settings = br#"{"fail":false}"#;
        let mut reason = [0_u8; 64];
        let mut input: OpenIn = zeroed();
        input.head = in_head::<OpenIn>(slot::OPEN);
        input.head.ticket = TICKET;
        input.host = &tables;
        input.settings = Blob::json(settings);
        input.secrets = secrets.as_ptr();
        input.secrets_len = secrets.len();
        input.generation = 41;
        input.err_buf = reason.as_mut_ptr();
        input.err_cap = reason.len();
        let door = (first::MACRO_DOOR.door_fn())();
        // SAFETY: this exact macro exports a static secret Ops table.
        let table = unsafe { &*door.ops().cast::<crate::abi::secret::Ops>() };
        let mut output: OpenOut = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: OPEN has no instance; its complete frames, host tables, settings, secret array,
        // nested secret bytes and exclusive reason buffer stay live through every operation below.
        let outcome = unsafe {
            table.head.open.unwrap()(
                ptr::null_mut(),
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Pending);
        assert!(!output.instance.is_null());
        let instance = output.instance;
        let cancel = CancelIn {
            head: in_head::<CancelIn>(slot::CANCEL),
            ticket: TICKET,
        };
        let mut cancelled: CancelOut = zeroed();
        cancelled.head = out_head::<CancelOut>();
        // SAFETY: the same door's live instance receives its exact CANCEL frame and original ticket.
        let outcome = unsafe {
            table.head.cancel.unwrap()(
                instance,
                ptr::from_ref(&cancel).cast(),
                ptr::from_mut(&mut cancelled).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(cancelled.disposition, PendingLife::CANCEL);
        input.head.flags = FLAG_RESUME;
        output = zeroed();
        output.head = out_head::<OpenOut>();
        // SAFETY: the same door resumes its live pending instance on the original ticket and
        // original complete frames and nested loans; output is exclusive for this call.
        let outcome = unsafe {
            table.head.open.unwrap()(
                instance,
                ptr::from_ref(&input).cast(),
                ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        assert_eq!(outcome, Outcome::Fault);
        assert!(output.instance.is_null());
        assert_eq!(
            counts(),
            Counts {
                opens: 1,
                steps: 1,
                cancels: 1,
                drops: 1,
                parked_drops: 1,
                ..Counts::default()
            }
        );
    }
}
