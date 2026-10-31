// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin test support against a REAL door: a transport built by `plugin_door!` over the
//! generic lifecycle, with two claims, two claim rows, their facts and one declared answer. Its
//! Statement is read back through [`DoorView`] and its `open`/`close` slots are called over
//! [`zeroed`] `in`s and `out`s, all without `unsafe`, as a plugin's own tests do. Beside it: a plane
//! door whose tail's texts and lists read back, the reason a failed `open` wrote into the buffer the
//! test lent, and fake host services called as a plugin's SDK calls them.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;

use super::*;
use crate::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use crate::abi::mechanism::door::{KindTailHead, Statement};
use crate::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use crate::abi::mechanism::KindCode;
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
    DoorView::of(plugin::MACRO_DOOR)
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
    let opened = call(open, ptr::null_mut(), &input, zeroed::<OpenOut>());
    assert_eq!(opened.outcome, Outcome::Ready);
    assert!(!opened.out.instance.is_null(), "open answered an instance");

    let closed = call(
        close,
        opened.out.instance,
        &in_head::<InHead>(slot::CLOSE),
        out_head::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
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
    record_retentions: ptr::null(),
    record_retentions_len: 0,
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
// SAFETY: this file's `'static` Statement and tail, and an all-absent table.
const PLANE_DOOR: &crate::abi::mechanism::door::Door = &unsafe {
    crate::abi::sdk::door::door::<crate::abi::plane::Ops>(PLANE_STATEMENT, PLANE_OPS, None)
};

extern "C" fn plane_door() -> &'static crate::abi::mechanism::door::Door {
    PLANE_DOOR
}

#[test]
fn a_plane_tails_texts_words_and_rows_read_back() {
    // The contract states no plane door macro, so this door is laid out as `plugin_door!` lays one
    // and handed in through the macro's own plumbing: only this crate's test names it.
    // SAFETY: `plane_door` answers `PLANE_DOOR`, a `'static` `Door` laid out by the SDK's own
    // `door`, `stamp` and `absent_table` const fns, over this file's `'static` Statement and tail.
    let door = unsafe { crate::abi::sdk::door::MacroDoor::__from_door_macro(plane_door) };
    let v = DoorView::of(door);
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
    let got = call(open, ptr::null_mut(), &input, zeroed::<OpenOut>());
    assert_eq!(got.outcome, Outcome::Failed);
    assert_eq!(got.error.as_deref(), Some("probe open failed: x"));
    assert_eq!(
        written_text(&reason, got.out.err_len, "open.err_len"),
        "probe open failed: x"
    );
    assert_eq!(
        written(&reason, got.out.err_len, "open.err_len"),
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
            // Short: the full size is stated, and a short answer is FAILED.
            return Outcome::Failed;
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

#[test]
fn a_fake_service_answers_the_sdks_own_calls_as_the_host_does() {
    use crate::abi::sdk::services::{ServiceError, Services};
    use core::task::Poll;
    let host = FakeHost::new()
        .serve(fake::host::CLOCK_NOW, Clock)
        .serve(fake::host::RECORDS_GET, Records);
    // The SDK's own wrapper, over the tables an `open` would be lent: it stamps every head and
    // judges every answer by the host's checks.
    let services = Services::of(host.tables_for_tests()).expect("the host offers services");
    let handle = CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    };

    // clock.now writes the reading the plugin lent.
    let reading = services.clock_now(handle).expect("clock.now answers");
    assert_eq!((reading.wall_ns, reading.mono_ns), (7, 9));

    // records.get reads the key the plugin lent and fills the buffers it lent.
    let mut buf = [0_u8; 32];
    match services.records_get(handle, "kind", b"probe", &mut buf) {
        Poll::Ready(Ok(Some(v))) => assert_eq!(v, b"value-of-probe"),
        other => panic!("records.get answered {other:?}"),
    }
    match services.records_get(handle, "kind", b"absent", &mut buf) {
        Poll::Ready(Ok(None)) => {}
        other => panic!("records.get of an absent key answered {other:?}"),
    }

    // A result the lent capacity does not hold writes nothing and states its size.
    let mut small = [0_u8; 4];
    match services.records_get(handle, "kind", b"probe", &mut small) {
        Poll::Ready(Err(ServiceError::Short { bytes, items })) => {
            assert_eq!((bytes, items), (14, 1));
        }
        other => panic!("a short records.get answered {other:?}"),
    }
    assert_eq!(small, [0; 4]);

    // An unserved slot is absent.
    let mut spans: [ItemSpan; 1] = zeroed();
    assert!(matches!(
        services.records_list(handle, "kind", b"", None, 0, (&mut buf, &mut spans)),
        Poll::Ready(Err(ServiceError::Unserved))
    ));
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
        let f = host.slots_for_tests().0.records_get.expect("served");
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

// ── a reply copied before release ───────────────────────────────────────────────────────────────

use super::reply::{call, Reply};
use crate::abi::auth::{BeginLoginOut, LoginField, BEGIN_FORM};
use crate::abi::export::{CheckOut, ServeOut};
use crate::abi::mechanism::call::{Blob, RawOutcome};
use crate::abi::mechanism::check::HARD_MAX_BYTES;
use crate::abi::plane::{PlaneRefreshOut, PlaneSnapshot};
use crate::abi::secret::ResolveOut;

/// A stand-in slot: it answers the `O` its instance points at, whole, as a plugin writes its
/// answer (pointers into memory the plugin keeps until release).
extern "C" fn answer<O: Reply>(
    instance: *mut c_void,
    _: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    // SAFETY: the test's own template `O`, and the caller's `out` of that type.
    let mut written = unsafe { *instance.cast::<O>() };
    // SAFETY: as above.
    unsafe { out.cast::<O>().write(written) };
    written.head().outcome
}

/// `answer::<O>` called over `template`.
fn answered<O: Reply>(template: &mut O) -> super::reply::Called<O> {
    call(
        answer::<O>,
        ptr::from_mut(template).cast(),
        &in_head::<InHead>(0),
        *template,
    )
}

fn bytes_of(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        ..Blob::ABSENT
    }
}

fn str_of(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn ready_head(lease: u64) -> OutHead {
    let mut h: OutHead = zeroed();
    h.outcome = RawOutcome::of(Outcome::Ready);
    h.lease = lease;
    h
}

fn resolved(secret: Blob) -> ResolveOut {
    let mut out: ResolveOut = zeroed();
    // No lease: a resolved value is written into the host's buffer (the credential chip, row 6: host-owned secret bytes).
    out.head = ready_head(0);
    out.secret = secret;
    out
}

#[test]
fn a_secret_is_copied_into_wiped_memory_before_the_buffer_is_wiped() {
    let mut material = b"s3cret".to_vec();
    let mut t = resolved(bytes_of(&material));
    let got = answered(&mut t);
    material.fill(0); // the host wipes its buffer once its consumer is done
    assert_eq!(got.outcome, Outcome::Ready);
    assert_eq!(got.owned.material(), b"s3cret");
    assert_eq!(got.out.head.lease, 0, "the scalars stay: no lease");
    assert!(
        got.out.secret.ptr.is_null(),
        "no pointer into the host buffer survives"
    );
    assert!(
        !format!("{:?}", got.owned).contains("s3cret"),
        "never printed"
    );
}

#[test]
#[should_panic(expected = "resolve.secret: NullWithCount")]
fn a_forged_secret_with_no_pointer_is_refused() {
    let mut t = resolved(Blob {
        ptr: ptr::null(),
        len: 5,
        ..Blob::ABSENT
    });
    let _ = answered(&mut t);
}

#[test]
#[should_panic(expected = "resolve.secret.len: OverMax")]
fn a_secret_past_the_declared_bound_is_refused() {
    let mut t = resolved(Blob {
        ptr: ptr::NonNull::<u8>::dangling().as_ptr(),
        len: HARD_MAX_BYTES as usize + 1,
        ..Blob::ABSENT
    });
    let _ = answered(&mut t);
}

fn served(headers: &[AbiStr], body: &[u8]) -> ServeOut {
    let mut out: ServeOut = zeroed();
    out.head = ready_head(3);
    out.status_code = 200;
    out.headers_out = headers.as_ptr();
    out.headers_out_len = headers.len();
    out.body = bytes_of(body);
    out
}

#[test]
fn a_served_reply_is_copied_before_release() {
    let mut name = String::from("content-type");
    let value = String::from("text/plain");
    let mut body = b"metrics 1".to_vec();
    let headers = [str_of(&name), str_of(&value)];
    let mut t = served(&headers, &body);
    let got = answered(&mut t);
    name.clear();
    body.fill(b'x');
    assert_eq!(got.owned.headers, ["content-type", "text/plain"]);
    assert_eq!(got.owned.body, b"metrics 1");
    assert_eq!(got.out.status_code, 200);
    assert!(got.out.headers_out.is_null() && got.out.body.ptr.is_null());
}

#[test]
#[should_panic(expected = "serve.headers_out: misaligned")]
fn a_forged_misaligned_header_list_is_refused() {
    let mut t = served(&[], b"");
    t.headers_out = ptr::without_provenance(1);
    t.headers_out_len = 2;
    let _ = answered(&mut t);
}

#[test]
#[should_panic(expected = "serve.headers_out_len: OverMax")]
fn a_header_list_past_the_declared_bound_is_refused() {
    let mut t = served(&[], b"");
    t.headers_out = ptr::NonNull::<AbiStr>::dangling().as_ptr();
    t.headers_out_len = 129;
    let _ = answered(&mut t);
}

#[test]
fn check_findings_are_copied_before_release() {
    let mut findings = b"[\"ok\"]".to_vec();
    let mut t: CheckOut = zeroed();
    t.head = ready_head(4);
    t.findings = bytes_of(&findings);
    let got = answered(&mut t);
    findings.fill(0);
    assert_eq!(got.owned, b"[\"ok\"]");
}

#[test]
#[should_panic(expected = "check.findings.len: OverMax")]
fn findings_past_the_declared_bound_are_refused() {
    let mut t: CheckOut = zeroed();
    t.head = ready_head(4);
    t.findings = Blob {
        ptr: ptr::NonNull::<u8>::dangling().as_ptr(),
        len: HARD_MAX_BYTES as usize + 1,
        ..Blob::ABSENT
    };
    let _ = answered(&mut t);
}

fn login(form: *const LoginField, form_len: usize) -> BeginLoginOut {
    let mut out: BeginLoginOut = zeroed();
    out.head = ready_head(0);
    out.shape = BEGIN_FORM;
    out.form = form;
    out.form_len = form_len;
    out
}

#[test]
fn a_login_forms_texts_are_copied_before_release() {
    let mut label = String::from("Your user name");
    let form = [LoginField {
        name: abi_str("user"),
        label: str_of(&label),
        kind: 1,
        required: 1,
    }];
    let mut t = login(form.as_ptr(), form.len());
    let got = answered(&mut t);
    label.clear();
    assert_eq!(got.owned.authorize_url, "");
    assert_eq!(got.owned.form.len(), 1);
    assert_eq!(got.owned.form[0].name, "user");
    assert_eq!(got.owned.form[0].label, "Your user name");
    assert!(got.out.form.is_null());
}

#[test]
#[should_panic(expected = "NullWithCount")]
fn a_forged_login_form_with_no_pointer_is_refused() {
    let mut t = login(ptr::null(), 2);
    let _ = answered(&mut t);
}

#[test]
#[should_panic(expected = "begin_login.form: a count of 1025, over the bound of 1024")]
fn a_login_form_past_the_declared_bound_is_refused() {
    let mut t = login(ptr::NonNull::<LoginField>::dangling().as_ptr(), 1025);
    let _ = answered(&mut t);
}

/// A snapshot a plane published, over `claims`.
fn snapshot_of(claims: &[crate::abi::plane::Claim]) -> PlaneSnapshot {
    PlaneSnapshot {
        size: size_of::<PlaneSnapshot>() as u32,
        _reserved: 0,
        generation: 2,
        claims: claims.as_ptr(),
        claims_len: claims.len(),
        admin_routes: ptr::null(),
        admin_routes_len: 0,
        openapi: Blob::ABSENT,
        audience: abi_str("probe-audience"),
        resource_metadata: NONE,
        resource_facts: Blob::ABSENT,
        listed: ptr::null(),
        listed_len: 0,
        arrival_spans: ptr::null(),
        arrival_spans_len: 0,
    }
}

fn refreshed(snapshot: *const PlaneSnapshot) -> PlaneRefreshOut {
    let mut out: PlaneRefreshOut = zeroed();
    out.head = ready_head(0);
    out.snapshot = snapshot;
    out
}

#[test]
fn a_published_snapshot_is_copied_before_its_generation_retires() {
    let mut target = String::from("/probe");
    let claims = [crate::abi::plane::Claim {
        verb: abi_str("POST"),
        target: str_of(&target),
        carrier: NONE,
        flags: 0,
        refusal_dialect: 0,
        _pad: 0,
    }];
    let mut snapshot = snapshot_of(&claims);
    let mut t = refreshed(ptr::from_ref(&snapshot));
    let got = answered(&mut t);
    target.clear(); // the next generation replaces what the old one named
    snapshot.generation = 3;
    let copy = got.owned.expect("a snapshot was published");
    assert_eq!(
        (copy.generation, snapshot.generation),
        (2, 3),
        "the copy keeps the generation the plugin has since replaced"
    );
    assert_eq!(copy.audience, "probe-audience");
    assert_eq!(copy.claims.len(), 1);
    assert_eq!(
        (copy.claims[0].verb.as_str(), copy.claims[0].target.as_str()),
        ("POST", "/probe")
    );
    assert!(got.out.snapshot.is_null());
}

#[test]
#[should_panic(expected = "snapshot: misaligned")]
fn a_forged_misaligned_snapshot_is_refused() {
    let mut t = refreshed(ptr::without_provenance(1));
    let _ = answered(&mut t);
}

#[test]
#[should_panic(expected = "snapshot.claims: OverMax")]
fn a_snapshot_past_the_declared_bound_is_refused() {
    let mut snapshot = snapshot_of(&[]);
    snapshot.claims = ptr::NonNull::<crate::abi::plane::Claim>::dangling().as_ptr();
    snapshot.claims_len = 1025;
    let mut t = refreshed(ptr::from_ref(&snapshot));
    let _ = answered(&mut t);
}

fn failed_with(error: AbiStr) -> OutHead {
    let mut h: OutHead = zeroed();
    h.outcome = RawOutcome::of(Outcome::Failed);
    h.error = error;
    h
}

#[test]
fn a_failures_text_is_copied_before_release() {
    let mut why = String::from("the probe failed");
    let mut t = failed_with(str_of(&why));
    let got = answered(&mut t);
    why.clear();
    assert_eq!(got.outcome, Outcome::Failed);
    assert_eq!(got.error.as_deref(), Some("the probe failed"));
    assert!(got.out.error.ptr.is_null());
}

#[test]
#[should_panic(expected = "head.error: NULL with a count of 3")]
fn a_forged_failure_text_with_no_pointer_is_refused() {
    let mut t = failed_with(AbiStr {
        ptr: ptr::null(),
        len: 3,
    });
    let _ = answered(&mut t);
}

#[test]
#[should_panic(expected = "head.error: 16777217 bytes, over the bound of 16777216")]
fn a_failure_text_past_the_declared_bound_is_refused() {
    let mut t = failed_with(AbiStr {
        ptr: ptr::NonNull::<u8>::dangling().as_ptr(),
        len: HARD_MAX_BYTES as usize + 1,
    });
    let _ = answered(&mut t);
}

// ── the sizes a slot reads, and the regions a double may touch ──────────────────────────────────

/// A stand-in slot that writes down the head sizes it was handed, and touches nothing past them.
extern "C" fn heads_seen(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    // SAFETY: the test's own `[u32; 2]`, and `call`'s `in`/`out`, each leading with its head.
    let (seen, i, o) = unsafe {
        (
            &mut *instance.cast::<[u32; 2]>(),
            &*input.cast::<InHead>(),
            &mut *out.cast::<OutHead>(),
        )
    };
    *seen = [i.size, o.size];
    o.outcome = RawOutcome::of(Outcome::Ready);
    o.outcome
}

#[test]
fn the_heads_a_slot_reads_state_the_structs_call_passed() {
    let mut seen = [0_u32; 2];
    // Heads that claim the larger `open` structs, over a bare `InHead` and `OutHead`.
    let lying_in = in_head::<OpenIn>(slot::OPEN);
    let lying_out = out_head::<OpenOut>();
    let got = call(
        heads_seen,
        ptr::from_mut(&mut seen).cast(),
        &lying_in,
        lying_out,
    );
    assert_eq!(got.outcome, Outcome::Ready);
    assert_eq!(
        seen,
        [size_of::<InHead>() as u32, size_of::<OutHead>() as u32],
        "a slot is never told it may read or write past what was passed"
    );
}

#[test]
#[should_panic(expected = "the door is not of the kind whose tail was asked for")]
fn plane_rows_of_a_transport_door_are_refused() {
    let _ = view().plane_rows::<crate::abi::plane::BillableClass>();
}

use crate::abi::host::conn::connector::{self as conn_abi, IoIn};
use crate::abi::host::io::{self as io_abi, ReadIn as IoReadIn};

/// A connector double that answers bytes into the `IoIn` buffer, on whichever op it serves.
struct Answers;
impl FakeService for Answers {
    type In = IoIn;
    fn serve(call: &mut ServiceCall<IoIn>) -> Outcome {
        if call.fill_lent(|i| &i.buf, b"pong") {
            Outcome::Ready
        } else {
            Outcome::Failed
        }
    }
}

/// An I/O double that reads back the buffer `io.read` lends for the host to WRITE.
struct ReadsItsOwnOutput;
impl FakeService for ReadsItsOwnOutput {
    type In = IoReadIn;
    fn serve(call: &mut ServiceCall<IoReadIn>) -> Outcome {
        let _ = call.lent(|i| &i.buf);
        Outcome::Ready
    }
}

/// A records double that writes one byte through a pointer nested in a `ServiceBufs`.
struct PutsIntoBufs;
impl FakeService for PutsIntoBufs {
    type In = RecordsGetIn;
    fn serve(call: &mut ServiceCall<RecordsGetIn>) -> Outcome {
        call.put(|i| &i.into.buf, 0_u8);
        Outcome::Ready
    }
}

fn io_in(op: u32, buf: &mut [u8]) -> IoIn {
    IoIn {
        head: service_head::<IoIn>(op),
        stream: 1,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    }
}

fn served_by(f: crate::abi::host::service::ServiceFn, input: *const c_void) -> Outcome {
    let mut out: ServiceOut = zeroed();
    f(HostCtx::NONE, input, ptr::from_mut(&mut out).cast()).outcome()
}

#[test]
fn a_double_writes_only_the_regions_its_op_lends_for_writing() {
    let host = FakeHost::new()
        .serve(fake::conn::READ, Answers)
        .serve(fake::conn::WRITE, Answers);
    // `read` lends its buffer for the host to write: the double fills it.
    let mut buf = [0_u8; 8];
    let input = io_in(conn_abi::service::READ, &mut buf);
    let read = host.slots_for_tests().2.read.expect("served");
    assert_eq!(
        served_by(read, ptr::from_ref(&input).cast()),
        Outcome::Ready
    );
    assert_eq!(&buf[..4], b"pong");
    // `write` lends the same field for the host to READ: writing it is refused, nothing written.
    let mut sent = [7_u8; 8];
    let input = io_in(conn_abi::service::WRITE, &mut sent);
    let write = host.slots_for_tests().2.write.expect("served");
    assert_eq!(
        served_by(write, ptr::from_ref(&input).cast()),
        Outcome::Fault
    );
    assert_eq!(sent, [7; 8]);
}

#[test]
fn a_double_reading_a_write_region_or_writing_through_no_region_answers_fault() {
    let host = FakeHost::new()
        .serve(fake::io::READ, ReadsItsOwnOutput)
        .serve(fake::host::RECORDS_GET, PutsIntoBufs);
    let mut buf = [0_u8; 8];
    let input = IoReadIn {
        head: service_head::<IoReadIn>(io_abi::op::READ),
        handle: 1,
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
    };
    let read = host.slots_for_tests().1.read.expect("served");
    assert_eq!(
        served_by(read, ptr::from_ref(&input).cast()),
        Outcome::Fault
    );

    let mut bytes = [9_u8; 4];
    let mut spans: [ItemSpan; 1] = zeroed();
    let input = RecordsGetIn {
        head: service_head::<RecordsGetIn>(svc::op::RECORDS_GET),
        kind: abi_str("kind"),
        key: abi_str("probe"),
        into: ServiceBufs {
            buf: bytes.as_mut_ptr(),
            cap: bytes.len(),
            spans: spans.as_mut_ptr(),
            spans_cap: spans.len(),
        },
    };
    let get = host.slots_for_tests().0.records_get.expect("served");
    assert_eq!(served_by(get, ptr::from_ref(&input).cast()), Outcome::Fault);
    assert_eq!(bytes, [9; 4], "nothing was written");
}

// ── no table and no `ServiceFn` reaches safe code ───────────────────────────────────────────────

/// Every `pub fn` of `src` (outside a `#[cfg(test)]` item) whose signature names a host table or a
/// raw service function: each one is a way for safe code to reach a `ServiceFn`.
fn table_leaks(src: &str) -> Vec<String> {
    const TABLE_TYPES: [&str; 5] = [
        "ServiceFn",
        "HostSlots",
        "IoSlots",
        "ConnectorSlots",
        "HostTables",
    ];
    let lines: Vec<&str> = src.lines().map(str::trim).collect();
    let mut out = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        if !line.starts_with("pub fn ") {
            continue;
        }
        let gated = lines[..n]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
            .any(|l| *l == "#[cfg(test)]");
        if gated {
            continue;
        }
        let signature: String = lines[n..]
            .iter()
            .take_while(|l| !l.ends_with('{'))
            .chain(lines[n..].iter().find(|l| l.ends_with('{')))
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        // The `Lent` of the tables (status row 194), named by its exact path, hands safe code no
        // way to call into the host: every entry of the tables is a raw pointer (a table's) or the
        // wake the test itself installed, so calling any service still needs `unsafe`. #1471
        // seals it (no `Deref`, no `get`); only `Services::of`, `Wake::of` and `Host::of` read
        // it. Nothing else is exempt: another `Lent`, a `Lent` named another way, or a
        // `&HostTables` beside it is still a leak.
        let unsealed =
            signature.replace("-> busbar_contract::abi::sdk::Lent<'_, HostTables>", "->");
        if TABLE_TYPES.iter().any(|t| unsealed.contains(t)) {
            out.push(format!("line {}: {signature}", n + 1));
        }
    }
    out
}

#[test]
fn the_fake_host_hands_safe_code_no_table_and_no_service_fn() {
    let found = table_leaks(include_str!(
        "../../../../../busbar-test-kit/src/test_support/fake.rs"
    ));
    assert!(found.is_empty(), "{found:?}");
    // RED: the accessors this module once had are each found.
    for planted in [
        "pub fn services(&self) -> &HostSlots {",
        "pub fn tables(&self) -> *const HostTables {",
        "pub fn lend<R>(&self, f: impl FnOnce(&HostTables) -> R) -> R {",
        "pub fn raw(\n    &self,\n) -> Option<ServiceFn> {",
    ] {
        assert_eq!(table_leaks(planted).len(), 1, "{planted}");
    }
    // A crate-private accessor behind `#[cfg(test)]` is not safe code's to call.
    assert!(table_leaks("#[cfg(test)]\npub fn slots(&self) -> &HostSlots {").is_empty());
    // GREEN: the lend of the tables, at its exact path, is no leak.
    assert!(
        table_leaks("pub fn lent(&self) -> busbar_contract::abi::sdk::Lent<'_, HostTables> {")
            .is_empty()
    );
    // RED: a bare reference beside it, a `Lent` named another way, and a `&HostTables` read out
    // of a `Lent` in any accessor shape are each still found.
    for planted in [
        "pub fn lent(&self) -> (crate::abi::sdk::Lent<'_, HostTables>, &HostTables) {",
        "pub fn lent(&self) -> Lent<'_, HostTables> {",
        "pub fn tables(&self) -> &HostTables {",
        "pub fn tables_of<'a>(lent: crate::abi::sdk::Lent<'a, HostTables>) -> &'a HostTables {",
        "pub fn tables(&self) -> Option<&HostTables> {",
    ] {
        assert_eq!(table_leaks(planted).len(), 1, "{planted}");
    }
    // RED (this tree, where the `Lent` still has its `Deref`): a safe accessor that hands out a
    // service function read out of the lent tables is still found, in any shape it is returned.
    for planted in [
        "pub fn clock(&self) -> Option<ServiceFn> {",
        "pub fn service(&self, at: usize) -> crate::abi::host::service::ServiceFn {",
        "pub fn services_of(\n    lent: crate::abi::sdk::Lent<'_, HostTables>,\n) -> &HostSlots {",
    ] {
        assert_eq!(table_leaks(planted).len(), 1, "{planted}");
    }
}

#[test]
fn a_door_opens_over_the_tables_a_fake_host_lent_while_the_host_lives() {
    let table = view().ops::<crate::abi::transport::Ops>();
    let open = table.head.open.expect("the door states open");
    let host = FakeHost::new().serve(fake::host::CLOCK_NOW, Clock);
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    // The lent `in` lives only in this block: it borrows the host, and its borrow ends here.
    let opened = {
        let lent = host.lend_to(input);
        super::reply::call_hosted(open, ptr::null_mut(), &lent, zeroed::<OpenOut>())
    };
    // Nothing the host lent is left, so the host may go.
    drop(host);
    assert_eq!(opened.outcome, Outcome::Ready);
    assert!(!opened.out.instance.is_null());
}

// ── the slot handles #1471 keeps under these names (status rows 159 and 194, expand) ─────────────

#[test]
fn a_door_views_slot_is_its_tables_slot_at_its_index() {
    let v = view();
    let table = v.ops::<crate::abi::transport::Ops>();
    let open = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .expect("the door states open");
    let close = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.close)
        .expect("the door states close");
    assert_eq!((open.index(), close.index()), (slot::OPEN, slot::CLOSE));
    let (raw, door, _) = open.parts();
    assert_eq!(raw as usize, table.head.open.unwrap() as usize);
    assert!(ptr::eq(door, v.door()));
}

#[test]
#[should_panic(expected = "DoorView::op: the picked reference is not a slot of the door's table")]
fn red_a_door_views_slot_is_never_a_reference_outside_its_table() {
    static ELSEWHERE: Option<crate::abi::mechanism::call::Op> = None;
    let _ = view().op::<crate::abi::transport::Ops>(|_| &ELSEWHERE);
}

#[test]
fn call_in_opens_and_close_in_closes_as_call_does_over_the_raw_slot() {
    let v = view();
    let open = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .unwrap();
    let close = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.close)
        .unwrap();

    // The old path: the raw slot, a zeroed `in`.
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    let by_raw = call(open.parts().0, ptr::null_mut(), &input, zeroed::<OpenOut>());

    // The new path: the door's slot and a `TestIn`; the instance comes back sealed.
    let built = super::test_in::TestIn::<OpenIn>::new().set(|i| &i.head.op, slot::OPEN);
    let mut by_view = super::reply::call_in(open, None, &built, zeroed::<OpenOut>());
    assert_eq!(by_view.outcome, by_raw.outcome);
    assert_eq!(by_view.error, by_raw.error);
    let instance = by_view
        .take_instance()
        .expect("open answered READY with an instance");
    assert!(
        by_view.take_instance().is_none(),
        "the instance is taken once"
    );

    let closed = super::reply::close_in(
        close,
        instance,
        &super::test_in::TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE),
        out_head::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
    // The raw path's instance is closed the raw way.
    let _ = call(
        close.parts().0,
        by_raw.out.instance,
        &in_head::<InHead>(slot::CLOSE),
        out_head::<OutHead>(),
    );
}

#[test]
#[should_panic(expected = "reply::call_in: `validate` and `open` run on no instance")]
fn red_call_in_refuses_an_instance_for_open() {
    let v = view();
    let open = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .unwrap();
    let built = super::test_in::TestIn::<OpenIn>::new().set(|i| &i.head.op, slot::OPEN);
    let mut opened = super::reply::call_in(open, None, &built, zeroed::<OpenOut>());
    let instance = opened.take_instance().unwrap();
    let _ = super::reply::call_in(open, Some(&instance), &built, zeroed::<OpenOut>());
}

#[test]
#[should_panic(expected = "reply::close_in: the op is not its door's close")]
fn red_close_in_enters_close_alone() {
    let v = view();
    let open = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .unwrap();
    let built = super::test_in::TestIn::<OpenIn>::new().set(|i| &i.head.op, slot::OPEN);
    let mut opened = super::reply::call_in(open, None, &built, zeroed::<OpenOut>());
    let instance = opened.take_instance().unwrap();
    let _ = super::reply::close_in(open, instance, &built, zeroed::<OpenOut>());
}

#[test]
fn call_hosted_in_opens_over_the_fake_hosts_tables_as_call_hosted_does() {
    let open = view()
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .unwrap();
    let host = FakeHost::new().serve(fake::host::CLOCK_NOW, Clock);
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    let by_raw = {
        let lent = host.lend_to(input);
        super::reply::call_hosted(open.parts().0, ptr::null_mut(), &lent, zeroed::<OpenOut>())
    };
    let mut by_view = {
        let lent =
            host.lend_in(super::test_in::TestIn::<OpenIn>::new().set(|i| &i.head.op, slot::OPEN));
        assert!(!lent.input.host.is_null(), "the host's tables are lent");
        super::reply::call_hosted_in(open, None, &lent, zeroed::<OpenOut>())
    };
    assert_eq!(by_view.outcome, by_raw.outcome);
    let instance = by_view
        .take_instance()
        .expect("open answered READY with an instance");
    // The instance is closed before the host goes, as #1471 holds it to.
    let close = view()
        .op::<crate::abi::transport::Ops>(|t| &t.head.close)
        .unwrap();
    let closed = super::reply::close_in(
        close,
        instance,
        &super::test_in::TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE),
        out_head::<OutHead>(),
    );
    assert_eq!(closed.outcome, Outcome::Ready);
    drop(host);
}

// ── a `TestIn` names only what its builders lent (status row 194) ──────────────────────────────

#[test]
#[should_panic(expected = "is the length of the pointer at byte")]
fn red_a_test_in_does_not_set_a_length_its_builder_set_with_its_pointer() {
    let mut err = [0_u8; 1];
    let _ = super::test_in::TestIn::<OpenIn>::new()
        .buffer(|i| &i.err_buf, |i| &i.err_cap, &mut err)
        .set(|i| &i.err_cap, 4096_usize);
}

#[test]
#[should_panic(expected = "is the length of the pointer at byte")]
fn red_a_test_in_does_not_state_a_length_for_a_list_it_never_lent() {
    let _ = super::test_in::TestIn::<OpenIn>::new().set(|i| &i.secrets_len, 1_usize << 20);
}

#[test]
#[should_panic(expected = "are not one of the in's pointer and length pairs")]
fn red_a_test_in_does_not_pair_a_list_with_another_lists_length() {
    let secrets = [crate::abi::mechanism::call::Blob::ABSENT];
    let _ = super::test_in::TestIn::<OpenIn>::new().list(|i| &i.secrets, |i| &i.err_cap, &secrets);
}

#[test]
#[should_panic(expected = "is not slot 1's own `in`")]
fn red_call_in_does_not_enter_a_slot_over_another_slots_in() {
    let open = view()
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .unwrap();
    let wrong = super::test_in::TestIn::<crate::abi::transport::ReadIn>::new();
    let _ = super::reply::call_in(open, None, &wrong, zeroed::<OpenOut>());
}

#[test]
fn a_door_views_slot_knows_its_own_in() {
    let v = view();
    let open = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.open)
        .unwrap();
    let close = v
        .op::<crate::abi::transport::Ops>(|t| &t.head.close)
        .unwrap();
    // GREEN, the REDs' twins: each slot over its own `in` passes the check.
    open.check_in::<OpenIn>();
    close.check_in::<InHead>();
}

/// Every slot `T`'s table lays out (its lifecycle's and its own) maps to an `in` type.
fn every_slot_maps<T: crate::abi::sdk::door::KindOps>() {
    let count = crate::abi::sdk::door::slot_count::<T>();
    assert!(count > slot::CLOSE, "{}", core::any::type_name::<T>());
    for index in 0..count {
        assert!(
            super::kit::slot_in_type::<T>(index).is_some(),
            "{}: slot {index} maps to no `in`",
            core::any::type_name::<T>()
        );
    }
}

#[test]
fn the_slot_table_maps_every_slot_of_every_kind_to_its_own_in() {
    every_slot_maps::<crate::abi::store::Ops>();
    every_slot_maps::<crate::abi::secret::Ops>();
    every_slot_maps::<crate::abi::auth::Ops>();
    every_slot_maps::<crate::abi::hook::Ops>();
    every_slot_maps::<crate::abi::export::Ops>();
    every_slot_maps::<crate::abi::plane::Ops>();
    every_slot_maps::<crate::abi::transport::Ops>();
    // Spot checks against the kinds' own `KindSlot` rows, one per table.
    use crate::abi::sdk::door::KindSlot;
    fn in_of<T: KindSlot<N>, const N: u32>() -> Option<core::any::TypeId> {
        Some(core::any::TypeId::of::<T::In>())
    }
    use crate::abi::{auth, export, hook, plane, secret, store, transport};
    assert_eq!(
        super::kit::slot_in_type::<transport::Ops>(slot::OPEN),
        in_of::<crate::abi::sdk::door::Lifecycle, { slot::OPEN }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<plane::Ops>(slot::OPEN),
        in_of::<plane::PlaneLifecycle, { slot::OPEN }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<transport::Ops>(transport::slot::LISTEN),
        in_of::<transport::Ops, { transport::slot::LISTEN }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<plane::Ops>(plane::slot::ARRIVE),
        in_of::<plane::Ops, { plane::slot::ARRIVE }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<auth::Ops>(auth::slot::VERIFY),
        in_of::<auth::Ops, { auth::slot::VERIFY }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<secret::Ops>(secret::slot::RESOLVE),
        in_of::<secret::Ops, { secret::slot::RESOLVE }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<hook::Ops>(hook::slot::NOTIFY),
        in_of::<hook::Ops, { hook::slot::NOTIFY }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<export::Ops>(export::slot::SCRAPE),
        in_of::<export::Ops, { export::slot::SCRAPE }>()
    );
    assert_eq!(
        super::kit::slot_in_type::<store::Ops>(store::slot::GET_KEY),
        in_of::<store::Ops, { store::slot::GET_KEY }>()
    );
}
