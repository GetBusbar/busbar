// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `auth_outbound_door!` over a safe test plugin, driven through its real table: open, a binding
//! and its `ready` fact, `fields` READY with a field and with none, THE SHORT-BUFFER ANSWER and its
//! one re-call, the inbound ops it does not serve, a pending `fields` and its redrive, and the
//! combined verify-and-outbound door. Each `fields` answer is judged by the kind's own validator
//! (`check_fields`).

use std::collections::HashMap;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::task::Poll;

use crate::abi::auth::{
    check_fields, slot, AuthPoints, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, NamedValue,
    OpenOutboundIn, OpenOutboundOut, Ops, OutboundReadyIn, OutboundReadyOut, RequestFacts,
    VerifyIn, CAP_INBOUND, CAP_OUTBOUND, MODE_OWN, POINT_HEAD, VERDICT_IDENTITY,
};
use crate::abi::mechanism::call::{
    AbiStr, Blob, Envelope, InHead, Op as RawOp, OutHead, Outcome, RawOutcome, Span, BLOB_ABSENT,
    BLOB_JSON, BLOB_OCTETS, BLOB_SECRET, FLAG_RESUME,
};
use crate::abi::mechanism::call::{Diag, SEVERITY_INFO, SEVERITY_WARN};
use crate::abi::mechanism::door::{Door, DoorFn};
use crate::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use crate::abi::mechanism::lifecycle::{CancelIn, CancelOut, DriveIn, TickIn, TickOut};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::sdk::auth_door::{with_tail, Answer, Verdict, VerifiedIdentity, VerifyView};
use crate::abi::sdk::conn::Host as SdkHost;
use crate::abi::sdk::door::{abi_str, statement};

use super::*;

/// The index of the one diagnostic id the test doors declare.
const NOTED: u32 = 0;
/// The diagnostic ids the test doors declare (`'static`: the Statement points at them).
const DIAG_IDS: &[AbiStr] = &[abi_str("auth.test-noted")];

/// `statement` with the test doors' diagnostic ids.
const fn noted(
    st: crate::abi::mechanism::door::Statement,
) -> crate::abi::mechanism::door::Statement {
    crate::abi::mechanism::door::Statement {
        diag_ids: DIAG_IDS.as_ptr(),
        diag_ids_len: DIAG_IDS.len(),
        ..st
    }
}

/// The binding settings that ask for the 20-field answer.
const HUGE: &[u8] = br#"{"huge":true}"#;

/// One binding: its credential and whether it asks for the 20-field answer.
struct Binding {
    credential: Option<Vec<u8>>,
    huge: bool,
}

/// Serves style `bearer-test`: `fields` stages `authorization: Bearer <credential>`, or twenty
/// fields when the binding's settings say `huge`, or none when the binding has no credential. The
/// credential `facts` stages one field naming what the view read; `slow` pends once, then answers.
#[derive(Default)]
struct Echo {
    bindings: Mutex<HashMap<u64, Binding>>,
    next: AtomicU64,
    pended: AtomicBool,
}

impl OutboundPlugin for Echo {
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Echo::default())
    }

    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        _: Option<&SdkHost>,
        diags: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        if style != "bearer-test" {
            diags.push(NOTED, SEVERITY_WARN, format!("style {style} is not served"));
            let refusal = OpenRefusal::new("style: not served");
            return Err(refusal.and("credential: unused"));
        }
        if credential == Some(b"note") {
            diags.push(NOTED, SEVERITY_INFO, "credential noted at open");
        }
        let handle = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let binding = Binding {
            credential: credential.map(<[u8]>::to_vec),
            huge: settings == Some(HUGE),
        };
        self.bindings.lock().unwrap().insert(handle, binding);
        Ok(handle)
    }

    fn fields(
        &self,
        r: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        let bindings = self.bindings.lock().unwrap();
        let Some(b) = bindings.get(&r.handle()) else {
            return Poll::Ready(FieldsAnswer::Refused);
        };
        let Some(credential) = b.credential.as_deref() else {
            return Poll::Ready(FieldsAnswer::Ready);
        };
        match credential {
            b"slow" if !self.pended.swap(true, Ordering::SeqCst) => return Poll::Pending,
            b"note" => {
                out.diag(NOTED, SEVERITY_WARN, "credential noted on the request");
                return Poll::Ready(FieldsAnswer::Ready);
            }
            b"facts" => {
                let facts = format!(
                    "{} {} {} {:?} {} {:?} {} {} {:?} {}",
                    String::from_utf8_lossy(r.method()),
                    String::from_utf8_lossy(r.authority()),
                    String::from_utf8_lossy(r.path()),
                    r.query().map(String::from_utf8_lossy),
                    r.timestamp(),
                    r.point(),
                    r.conn(),
                    r.unit(),
                    r.mode(),
                    r.headers().count(),
                );
                out.push(b"x-facts", facts.as_bytes(), 0);
            }
            _ if b.huge => {
                for i in 0..20 {
                    out.push(format!("x-huge-{i:02}").as_bytes(), credential, 0);
                }
            }
            _ => {
                let mut value = b"Bearer ".to_vec();
                value.extend_from_slice(credential);
                out.push(b"authorization", &value, 0);
            }
        }
        Poll::Ready(FieldsAnswer::Ready)
    }

    fn outbound_ready(&self, handle: u64) -> bool {
        self.bindings.lock().unwrap().contains_key(&handle)
    }
}

const STYLES: &[crate::abi::auth::StyleDecl] = &[style("bearer-test", 0, AuthPoints::HEAD)];
const TAIL: &AuthTail = &outbound_tail(0, STYLES);

mod plugin {
    use super::*;
    crate::auth_outbound_door!(Echo, with_tail(noted(statement("echo", "1.0.0", 8)), TAIL));
}

fn ops() -> &'static Ops {
    ops_of(plugin::door)
}

fn ops_of(door: DoorFn) -> &'static Ops {
    // The macro's door and table are `'static` consts.
    let d: &Door = door();
    // SAFETY: as above; the door's ops are an auth table.
    unsafe { &*d.ops.cast::<Ops>() }
}

fn absent() -> Blob {
    Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    }
}

fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

fn head<T>(op: u32) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx::NONE,
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: absent(),
    }
}

fn out_head(size: usize) -> OutHead {
    OutHead {
        size: size as u32,
        outcome: RawOutcome::of(Outcome::Fault),
        _reserved: [0; 3],
        wake_at_ns: 0,
        lease: 0,
        error: AbiStr {
            ptr: ptr::null(),
            len: 0,
        },
        envelope: Envelope {
            metrics: ptr::null(),
            metrics_len: 0,
            diags: ptr::null(),
            diags_len: 0,
        },
        extensions: absent(),
    }
}

fn cross<I, O>(op: Option<RawOp>, instance: *mut std::ffi::c_void, i: &I, o: &mut O) -> Outcome {
    op.expect("every slot is filled")(instance, ptr::from_ref(i).cast(), ptr::from_mut(o).cast())
        .outcome()
}

fn opened(t: &Ops) -> *mut std::ffi::c_void {
    let input = OpenIn {
        head: head::<OpenIn>(life::OPEN),
        host: ptr::null(),
        settings: blob(b"{}", BLOB_JSON, 0),
        secrets: ptr::null(),
        secrets_len: 0,
        generation: 1,
        err_buf: ptr::null_mut(),
        err_cap: 0,
    };
    let mut out = OpenOut {
        head: out_head(size_of::<OpenOut>()),
        instance: ptr::null_mut(),
        err_len: 0,
    };
    let o = cross(t.head.open, ptr::null_mut(), &input, &mut out);
    assert_eq!(o, Outcome::Ready);
    assert!(!out.instance.is_null());
    out.instance
}

fn open_outbound(
    t: &Ops,
    instance: *mut std::ffi::c_void,
    style: &str,
    credential: Option<&[u8]>,
    settings: &[u8],
) -> (Outcome, OpenOutboundOut) {
    let input = OpenOutboundIn {
        head: head::<OpenOutboundIn>(slot::OPEN_OUTBOUND),
        style: abi_str_of(style),
        credential: credential.map_or_else(absent, |c| blob(c, BLOB_OCTETS, BLOB_SECRET)),
        settings: blob(settings, BLOB_JSON, 0),
    };
    let mut out = OpenOutboundOut {
        head: out_head(size_of::<OpenOutboundOut>()),
        handle: 0,
    };
    let o = cross(t.open_outbound, instance, &input, &mut out);
    (o, out)
}

fn abi_str_of(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn ready(t: &Ops, instance: *mut std::ffi::c_void, handle: u64) -> (Outcome, u32) {
    let input = OutboundReadyIn {
        head: head::<OutboundReadyIn>(slot::OUTBOUND_READY),
        handle,
    };
    let mut out = OutboundReadyOut {
        head: out_head(size_of::<OutboundReadyOut>()),
        ready: 0,
        _reserved: 0,
    };
    let o = cross(t.outbound_ready, instance, &input, &mut out);
    (o, out.ready)
}

const FILL: u8 = 0xAA;
const NO_FIELD: FieldSpan = FieldSpan {
    name: Span {
        offset: 0xAAAA_AAAA,
        len: 0xAAAA_AAAA,
    },
    value: Span {
        offset: 0xAAAA_AAAA,
        len: 0xAAAA_AAAA,
    },
    flags: 0xAAAA_AAAA,
    _reserved: 0xAAAA_AAAA,
};

/// The host's `fields` buffers, filled with a pattern a write would change.
struct Host {
    buf: Vec<u8>,
    fields: Vec<FieldSpan>,
}

impl Host {
    fn new(bytes: usize, fields: usize) -> Self {
        Host {
            buf: vec![FILL; bytes],
            fields: vec![NO_FIELD; fields],
        }
    }

    /// The fields a READY answer reports, as the host reads them.
    fn reported(&self, o: Outcome, out: &FieldsOut) -> &[FieldSpan] {
        let n = if o == Outcome::Ready {
            out.fields_len as usize
        } else {
            0
        };
        &self.fields[..n.min(self.fields.len())]
    }

    fn text(&self, s: Span) -> &[u8] {
        &self.buf[s.offset as usize..(s.offset + s.len) as usize]
    }

    /// Whether no byte and no field was written (a written field's flags are a vocabulary value).
    fn untouched(&self) -> bool {
        let bytes = self.buf.iter().all(|b| *b == FILL);
        let fields = self.fields.iter().all(|f| f.flags == NO_FIELD.flags);
        bytes && fields
    }
}

fn fields_in(handle: u64, host: &mut Host, headers: &[NamedValue]) -> FieldsIn {
    FieldsIn {
        head: head::<FieldsIn>(slot::FIELDS),
        handle,
        mode: MODE_OWN,
        point: POINT_HEAD,
        request: RequestFacts {
            method: abi_str("GET"),
            authority: abi_str("up.example:443"),
            canonical_path: abi_str("/v1/x"),
            query: abi_str("a=1"),
            timestamp: 1_700_000_000,
        },
        caller_credential: absent(),
        field_buf: host.buf.as_mut_ptr(),
        field_buf_cap: host.buf.len(),
        fields: host.fields.as_mut_ptr(),
        fields_cap: host.fields.len() as u32,
        _reserved: 0,
        headers: if headers.is_empty() {
            ptr::null()
        } else {
            headers.as_ptr()
        },
        headers_len: headers.len(),
        conn: 7,
        unit: 9,
        body: absent(),
    }
}

fn fields_out() -> FieldsOut {
    FieldsOut {
        head: out_head(size_of::<FieldsOut>()),
        fields_len: 0,
        needed_fields: 0,
        needed_bytes: 0,
    }
}

fn fields_with(t: &Ops, inst: *mut std::ffi::c_void, input: &FieldsIn) -> (Outcome, FieldsOut) {
    let mut out = fields_out();
    let o = cross(t.fields, inst, input, &mut out);
    (o, out)
}

fn fields(
    t: &Ops,
    instance: *mut std::ffi::c_void,
    handle: u64,
    host: &mut Host,
) -> (Outcome, FieldsOut, FieldsIn) {
    let input = fields_in(handle, host, &[]);
    let (o, out) = fields_with(t, instance, &input);
    (o, out, input)
}

/// The kind's own check over a `fields` answer, with the host's buffers.
fn check(o: Outcome, out: &FieldsOut, input: &FieldsIn, host: &Host) {
    check_fields(
        o,
        out,
        input.field_buf_cap,
        input.fields_cap,
        host.reported(o, out),
    )
    .expect("the kind's check accepts the answer");
}

/// (a) A binding answers its handle, and its `ready` fact is 1; a style it does not serve is
/// FAILED with the plugin's lines, and an unknown handle is not ready.
#[test]
fn a_binding_answers_a_handle_and_is_ready() {
    let t = ops();
    let inst = opened(t);
    let (o, out) = open_outbound(t, inst, "bearer-test", Some(b"k"), b"{}");
    assert_eq!(o, Outcome::Ready);
    assert_ne!(out.handle, 0);
    assert_eq!(ready(t, inst, out.handle), (Outcome::Ready, 1));
    assert_eq!(ready(t, inst, out.handle + 100), (Outcome::Ready, 0));

    let (o, out) = open_outbound(t, inst, "other", Some(b"k"), b"{}");
    assert_eq!(o, Outcome::Failed);
    // SAFETY: the text the instance keeps for its answer, `len` bytes.
    let text = unsafe { std::slice::from_raw_parts(out.head.error.ptr, out.head.error.len) };
    assert_eq!(text, b"style: not served\ncredential: unused");
}

/// (b) `fields` answers READY with one field, written into the host's buffers, and the kind's
/// check accepts it.
#[test]
fn fields_answers_ready_with_one_field() {
    let t = ops();
    let inst = opened(t);
    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"k"), b"{}");
    let mut host = Host::new(64, 16);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 1));
    assert_eq!((out.needed_fields, out.needed_bytes), (0, 0));
    check(o, &out, &input, &host);
    let f = host.fields[0];
    assert_eq!(host.text(f.name), b"authorization");
    assert_eq!(host.text(f.value), b"Bearer k");
    assert_eq!(f.flags, 0);
}

/// (c) RED, THE SHORT-BUFFER RULE: twenty fields into a sixteen-field array is the short answer
/// (FAILED, `needed_fields` 20, `needed_bytes` the full size) and not one byte of the host's
/// buffers changes; the re-call with room for thirty-two answers READY with all twenty. The kind's
/// check accepts both.
#[test]
fn red_fields_that_do_not_fit_are_the_short_answer_and_write_nothing() {
    let t = ops();
    let inst = opened(t);
    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"k"), HUGE);
    let mut host = Host::new(4096, 16);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!(o, Outcome::Failed);
    // Twenty names `x-huge-NN` (9 bytes) and twenty values `k` (1 byte).
    assert_eq!((out.needed_fields, out.needed_bytes), (20, 200));
    assert_eq!(out.fields_len, 0);
    check(o, &out, &input, &host);
    assert!(host.untouched(), "a short answer writes nothing");

    let mut host = Host::new(4096, 32);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 20));
    assert_eq!((out.needed_fields, out.needed_bytes), (0, 0));
    check(o, &out, &input, &host);
    for (i, f) in host.fields[..20].iter().enumerate() {
        assert_eq!(host.text(f.name), format!("x-huge-{i:02}").as_bytes());
        assert_eq!(host.text(f.value), b"k");
    }
    assert!(
        host.buf[200..].iter().all(|b| *b == FILL),
        "nothing past the answer"
    );

    // Bytes short, fields fitting: still the short answer, both at their full sizes.
    let mut host = Host::new(64, 32);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!(
        (o, out.needed_fields, out.needed_bytes),
        (Outcome::Failed, 20, 200)
    );
    check(o, &out, &input, &host);
    assert!(host.untouched(), "a short answer writes nothing");
}

/// (d) A binding with no credential answers READY with zero fields: no auth header.
#[test]
fn ready_with_zero_fields_is_no_header() {
    let t = ops();
    let inst = opened(t);
    let (o, bound) = open_outbound(t, inst, "bearer-test", None, b"{}");
    assert_eq!(o, Outcome::Ready);
    let mut host = Host::new(64, 16);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 0));
    check(o, &out, &input, &host);
    assert!(host.untouched());
    // An unknown handle is the plugin's REFUSED.
    let (o, out, input) = fields(t, inst, bound.handle + 100, &mut host);
    assert_eq!(o, Outcome::Refused);
    check(o, &out, &input, &host);
}

/// (e) The inbound ops of an outbound-only door answer REFUSED, and its tail states outbound only.
#[test]
fn verify_on_an_outbound_only_door_is_refused() {
    let t = ops();
    let inst = opened(t);
    // SAFETY: plain C data; all-zero is valid.
    let mut input: VerifyIn = unsafe { std::mem::zeroed() };
    input.head = head::<VerifyIn>(slot::VERIFY);
    input.credential = absent();
    // SAFETY: as above.
    let mut out: IdentifyOut = unsafe { std::mem::zeroed() };
    out.head = out_head(size_of::<IdentifyOut>());
    assert_eq!(cross(t.verify, inst, &input, &mut out), Outcome::Refused);
    assert!(t.begin_login.is_some() && t.complete_login.is_some());

    // SAFETY: the door's `'static` Statement and tail.
    let st = unsafe { &*plugin::door().statement };
    // SAFETY: as above.
    let tail = unsafe { &*st.kind_tail.cast::<AuthTail>() };
    assert_eq!((tail.caps, tail.inbound_points), (CAP_OUTBOUND, 0));
    assert_eq!(tail.styles_len, 1);
    // SAFETY: the tail's `'static` styles.
    let decl = unsafe { &*tail.styles };
    // SAFETY: a `'static` str's pointer and length.
    let name = unsafe { std::slice::from_raw_parts(decl.name.ptr, decl.name.len) };
    assert_eq!((name, decl.points), (&b"bearer-test"[..], POINT_HEAD));
}

/// (f) A `fields` that pends answers PENDING on its ticket, writing nothing, and the host's
/// redrive (`FLAG_RESUME` on the same ticket) answers READY. A ticket-less `fields` cannot pend:
/// it is REFUSED there, and the host submits it on a ticket.
#[test]
fn a_pending_fields_answers_pending_and_the_redrive_answers_ready() {
    let t = ops();
    // On the spot: REFUSED, not PENDING (the plugin pends once per instance; this was it).
    let inst = opened(t);
    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"slow"), b"{}");
    let mut host = Host::new(64, 16);
    let input = fields_in(bound.handle, &mut host, &[]);
    let (o, out) = fields_with(t, inst, &input);
    assert_eq!(o, Outcome::Refused);
    check(o, &out, &input, &host);
    assert!(host.untouched());

    // On a ticket, on a fresh instance: PENDING, then the redrive answers.
    let inst = opened(t);
    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"slow"), b"{}");
    let mut host = Host::new(64, 16);
    let mut input = fields_in(bound.handle, &mut host, &[]);
    input.head.ticket = Ticket {
        slot: 5,
        generation: 1,
    };
    let (o, out) = fields_with(t, inst, &input);
    assert_eq!(o, Outcome::Pending);
    assert_eq!(
        (out.fields_len, out.needed_fields, out.needed_bytes),
        (0, 0, 0)
    );
    check(o, &out, &input, &host);
    assert!(host.untouched(), "PENDING writes nothing");

    input.head.flags = FLAG_RESUME;
    let (o, out) = fields_with(t, inst, &input);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 1));
    check(o, &out, &input, &host);
    assert_eq!(host.text(host.fields[0].value), b"Bearer slow");
}

/// The view reads every fact the host lent: the method, authority, path, query, timestamp, point,
/// connection, unit, mode and the header envelope.
#[test]
fn the_view_reads_the_requests_facts() {
    let t = ops();
    let inst = opened(t);
    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"facts"), b"{}");
    let mut host = Host::new(256, 16);
    let headers = [NamedValue {
        name: abi_str("host"),
        value: blob(b"up.example", BLOB_OCTETS, 0),
    }];
    let input = fields_in(bound.handle, &mut host, &headers);
    let (o, out) = fields_with(t, inst, &input);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 1));
    check(o, &out, &input, &host);
    assert_eq!(
        String::from_utf8_lossy(host.text(host.fields[0].value)),
        "GET up.example:443 /v1/x Some(\"a=1\") 1700000000 Some(Head) 7 9 Own 1"
    );
}

/// Stages a field with a flag outside the vocabulary.
struct Stray;

impl OutboundPlugin for Stray {
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Stray)
    }
    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: Option<&SdkHost>,
        _: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        Ok(1)
    }
    fn fields(
        &self,
        _: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        out.push(b"authorization", b"x", 8);
        Poll::Ready(FieldsAnswer::Ready)
    }
    fn outbound_ready(&self, _: u64) -> bool {
        true
    }
}

mod stray {
    use super::*;
    crate::auth_outbound_door!(Stray, with_tail(statement("stray", "1.0.0", 8), TAIL));
}

/// A flag outside `FIELD_SENSITIVE | FIELD_QUERY` is the plugin's bug: the call is FAULT, and
/// nothing reaches the host's buffers.
#[test]
fn a_stray_field_flag_is_fault() {
    let t = ops_of(stray::door);
    let inst = opened(t);
    let mut host = Host::new(64, 16);
    let (o, _, _) = fields(t, inst, 1, &mut host);
    assert_eq!(o, Outcome::Fault);
    assert!(host.untouched());
}

/// Verifies `good` inbound and presents `authorization: SIG` outbound, from one instance.
struct Sig;

impl VerifyPlugin for Sig {
    fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Sig)
    }
    fn verify(&self, r: &VerifyView<'_>) -> Answer {
        let verdict = match r.credential() {
            Some(b"good") => Verdict::Identity(VerifiedIdentity {
                subject: "alice".into(),
                ..VerifiedIdentity::default()
            }),
            _ => Verdict::Pass,
        };
        verdict.into()
    }
}

impl OutboundPlugin for Sig {
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Sig)
    }
    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: Option<&SdkHost>,
        _: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        Ok(1)
    }
    fn fields(
        &self,
        _: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        out.push(b"authorization", b"SIG", crate::abi::auth::FIELD_SENSITIVE);
        Poll::Ready(FieldsAnswer::Ready)
    }
    fn outbound_ready(&self, _: u64) -> bool {
        true
    }
}

const BOTH: &AuthTail = &with_inbound(outbound_tail(0, STYLES), AuthPoints::HEAD);

mod both {
    use super::*;
    crate::auth_door!(verify_and_outbound: Sig, with_tail(statement("sig", "1.0.0", 8), BOTH));
}

/// THE COMBINED DOOR (`auth_door!(verify_and_outbound: ..)`): one instance verifies inbound and
/// presents outbound, and its tail states both capabilities.
#[test]
fn a_verify_and_outbound_door_serves_both_families() {
    let t = ops_of(both::door);
    let inst = opened(t);

    let (o, bound) = open_outbound(t, inst, "bearer-test", Some(b"k"), b"{}");
    assert_eq!(o, Outcome::Ready);
    let mut host = Host::new(64, 16);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 1));
    check(o, &out, &input, &host);
    assert_eq!(host.text(host.fields[0].value), b"SIG");

    let mut buf = vec![0_u8; 64];
    let mut groups = vec![Span { offset: 0, len: 0 }; 4];
    // SAFETY: plain C data; all-zero is valid.
    let mut input: VerifyIn = unsafe { std::mem::zeroed() };
    input.head = head::<VerifyIn>(slot::VERIFY);
    input.credential = blob(b"good", BLOB_OCTETS, BLOB_SECRET);
    input.point = POINT_HEAD;
    input.peer = absent();
    input.body = absent();
    input.out_buf = crate::abi::auth::IdentityBuf {
        buf: buf.as_mut_ptr(),
        buf_cap: buf.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    // SAFETY: as above.
    let mut out: IdentifyOut = unsafe { std::mem::zeroed() };
    out.head = out_head(size_of::<IdentifyOut>());
    assert_eq!(cross(t.verify, inst, &input, &mut out), Outcome::Ready);
    assert_eq!(out.verdict, VERDICT_IDENTITY);

    // SAFETY: the door's `'static` Statement and tail.
    let st = unsafe { &*both::door().statement };
    // SAFETY: as above.
    let tail = unsafe { &*st.kind_tail.cast::<AuthTail>() };
    assert_eq!(tail.caps, CAP_OUTBOUND | CAP_INBOUND);
    assert_eq!(tail.inbound_points, POINT_HEAD);
}

/// The declared diagnostics a reply's envelope carries, as the host reads them: `(id, severity,
/// text)`.
fn reported(head: &OutHead) -> Vec<(u32, u8, String)> {
    let e = &head.envelope;
    if e.diags_len == 0 {
        return Vec::new();
    }
    // SAFETY: the reply's envelope names `diags_len` diagnostics, kept by the instance that
    // answered until the host has copied the reply (`abi::sdk::out::Kept`).
    let diags: &[Diag] = unsafe { std::slice::from_raw_parts(e.diags, e.diags_len) };
    diags
        .iter()
        .map(|d| {
            // SAFETY: as above; each text is the instance's own, `len` bytes.
            let text = unsafe { std::slice::from_raw_parts(d.text.ptr, d.text.len) };
            (
                d.id_idx,
                d.severity,
                String::from_utf8_lossy(text).into_owned(),
            )
        })
        .collect()
}

/// RED, THE DECLARED DIAGNOSTICS: what `open_outbound` notes rides its reply's envelope, READY or
/// FAILED, under the Statement's id index and the plugin's severity, word for word; a binding
/// that notes nothing reports nothing. RED with the kit dropping the staged diagnostics (the
/// envelope stays empty, and the host logs no line).
#[test]
fn red_open_outbound_reports_its_diagnostics_ready_or_failed() {
    let t = ops();
    let inst = opened(t);
    let (o, out) = open_outbound(t, inst, "bearer-test", Some(b"note"), b"{}");
    assert_eq!(o, Outcome::Ready);
    assert_eq!(
        reported(&out.head),
        vec![(NOTED, SEVERITY_INFO, "credential noted at open".to_string())]
    );

    let (o, out) = open_outbound(t, inst, "other", Some(b"k"), b"{}");
    assert_eq!(o, Outcome::Failed);
    assert_eq!(
        reported(&out.head),
        vec![(
            NOTED,
            SEVERITY_WARN,
            "style other is not served".to_string()
        )]
    );

    let (o, out) = open_outbound(t, inst, "bearer-test", Some(b"k"), b"{}");
    assert_eq!(o, Outcome::Ready);
    assert!(reported(&out.head).is_empty());
}

/// RED, THE DECLARED DIAGNOSTICS ON THE REQUEST: what `fields` notes rides that request's reply,
/// with its answer. RED with the kit dropping the writer's diagnostics.
#[test]
fn red_fields_reports_its_diagnostics_with_its_answer() {
    let t = ops();
    let inst = opened(t);
    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"note"), b"{}");
    let mut host = Host::new(64, 16);
    let (o, out, input) = fields(t, inst, bound.handle, &mut host);
    assert_eq!((o, out.fields_len), (Outcome::Ready, 0));
    check(o, &out, &input, &host);
    assert_eq!(
        reported(&out.head),
        vec![(
            NOTED,
            SEVERITY_WARN,
            "credential noted on the request".to_string()
        )]
    );

    let (_, bound) = open_outbound(t, inst, "bearer-test", Some(b"k"), b"{}");
    let (o, out, _) = fields(t, inst, bound.handle, &mut Host::new(64, 16));
    assert_eq!((o, out.fields_len), (Outcome::Ready, 1));
    assert!(reported(&out.head).is_empty());
}

/// Mints on its driver ticket: `tick` notes the ticket it ran on and whether it was handed host
/// tables, and wants the next tick 1000 ns on; `drive` notes its driver ticket and waits,
/// re-driven at 42 at the latest; `cancel` keeps the work of [`WAITING`] going
/// (`CANCEL_CONTINUES`) and abandons any other.
struct Minter;

/// The call ticket [`Minter`] has a mint running for.
const WAITING: Ticket = Ticket {
    slot: 9,
    generation: 2,
};

impl OutboundPlugin for Minter {
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Minter)
    }
    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: Option<&SdkHost>,
        _: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        Ok(1)
    }
    fn fields(
        &self,
        _: &FieldsView<'_>,
        _: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        Poll::Ready(FieldsAnswer::Ready)
    }
    fn outbound_ready(&self, _: u64) -> bool {
        true
    }
    fn tick(&self, now_ns: u64, host: Option<&SdkHost>, driver: Ticket, diags: &mut Diags) -> u64 {
        diags.push(
            NOTED,
            SEVERITY_INFO,
            format!(
                "minted on {}/{} host={}",
                driver.slot,
                driver.generation,
                host.is_some()
            ),
        );
        now_ns + 1_000
    }
    fn drive(&self, _: Option<&SdkHost>, driver: Ticket, diags: &mut Diags) -> Driven {
        diags.push(
            NOTED,
            SEVERITY_WARN,
            format!("waiting on {}/{}", driver.slot, driver.generation),
        );
        Driven::Pending { wake_at_ns: 42 }
    }
    fn cancel(&self, ticket: Ticket) -> u32 {
        if ticket == WAITING {
            crate::abi::auth::CANCEL_CONTINUES
        } else {
            crate::abi::auth::CANCEL_ABANDONED
        }
    }
}

mod minter {
    use super::*;
    crate::auth_outbound_door!(
        Minter,
        with_tail(noted(statement("minter", "1.0.0", 8)), TAIL)
    );
}

const DRIVER: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

fn tick(t: &Ops, inst: *mut std::ffi::c_void, ticket: Ticket, now_ns: u64) -> (Outcome, TickOut) {
    let mut input = TickIn {
        head: head::<TickIn>(life::TICK),
        now_ns,
    };
    input.head.ticket = ticket;
    let mut out = TickOut {
        head: out_head(size_of::<TickOut>()),
        next_tick_ns: 0,
    };
    let o = cross(t.head.tick, inst, &input, &mut out);
    (o, out)
}

fn drive(t: &Ops, inst: *mut std::ffi::c_void, ticket: Ticket) -> (Outcome, OutHead) {
    let mut input = DriveIn {
        head: head::<DriveIn>(life::DRIVE),
        driver: ticket,
    };
    input.head.ticket = ticket;
    let mut out = out_head(size_of::<OutHead>());
    let o = cross(t.head.drive, inst, &input, &mut out);
    (o, out)
}

fn cancel(t: &Ops, inst: *mut std::ffi::c_void, ticket: Ticket) -> (Outcome, u32) {
    let input = CancelIn {
        head: head::<CancelIn>(life::CANCEL),
        ticket,
    };
    let mut out = CancelOut {
        head: out_head(size_of::<CancelOut>()),
        disposition: 0,
        _reserved: 0,
    };
    let o = cross(t.head.cancel, inst, &input, &mut out);
    (o, out.disposition)
}

/// THE DRIVER TICKET: `tick` runs the plugin on the instance's driver ticket with the host tables
/// `open` handed it (none here), its notes and next tick in the reply; `drive` on that ticket
/// answers PENDING with the plugin's latest re-drive, and a ticket-less `drive` (which cannot pend)
/// READY; `cancel` answers the plugin's own disposition for the cancelled ticket.
#[test]
fn a_minting_plugin_runs_on_its_driver_ticket() {
    let t = ops_of(minter::door);
    let inst = opened(t);

    let (o, out) = tick(t, inst, DRIVER, 5_000);
    assert_eq!((o, out.next_tick_ns), (Outcome::Ready, 6_000));
    // `open` was handed no host tables, so none reach `tick`.
    assert_eq!(
        reported(&out.head),
        vec![(NOTED, SEVERITY_INFO, "minted on 3/1 host=false".to_string())]
    );

    let (o, out) = drive(t, inst, DRIVER);
    assert_eq!((o, out.wake_at_ns), (Outcome::Pending, 42));
    assert_eq!(
        reported(&out),
        vec![(NOTED, SEVERITY_WARN, "waiting on 3/1".to_string())]
    );
    let (o, _) = drive(t, inst, Ticket::NONE);
    assert_eq!(o, Outcome::Ready, "a ticket-less drive cannot pend");

    assert_eq!(
        cancel(t, inst, WAITING),
        (Outcome::Ready, crate::abi::auth::CANCEL_CONTINUES)
    );
    assert_eq!(
        cancel(t, inst, DRIVER),
        (Outcome::Ready, crate::abi::auth::CANCEL_ABANDONED)
    );
}

/// A plugin that holds no driver ticket keeps the kit's defaults: `tick` wants none, `drive` is
/// REFUSED, `cancel` is `CANCEL_ABANDONED`.
#[test]
fn a_plugin_without_a_driver_ticket_keeps_the_defaults() {
    let t = ops();
    let inst = opened(t);
    let (o, out) = tick(t, inst, DRIVER, 5_000);
    assert_eq!((o, out.next_tick_ns), (Outcome::Ready, 0));
    assert!(reported(&out.head).is_empty());
    assert_eq!(drive(t, inst, DRIVER).0, Outcome::Refused);
    assert_eq!(
        cancel(t, inst, DRIVER),
        (Outcome::Ready, crate::abi::auth::CANCEL_ABANDONED)
    );
}

/// Judges its settings (`{"bad":true}` is refused, in its own words) and answers each binding's
/// handle as the generation it was opened at.
struct Generational(AtomicU64);

/// The settings [`Generational`] refuses.
const BAD: &[u8] = br#"{"bad":true}"#;

impl OutboundPlugin for Generational {
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        if settings == BAD {
            return Err(Refusal::refused("settings: bad"));
        }
        Ok(())
    }
    fn open(settings: &[u8], _: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        Self::validate(settings)?;
        Ok(Generational(AtomicU64::new(generation)))
    }
    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: Option<&SdkHost>,
        _: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        Ok(self.0.load(Ordering::SeqCst))
    }
    fn fields(
        &self,
        _: &FieldsView<'_>,
        _: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        Poll::Ready(FieldsAnswer::Ready)
    }
    fn outbound_ready(&self, _: u64) -> bool {
        true
    }
    fn refresh(&self, settings: &[u8], _: &[&[u8]], generation: u64) -> Result<(), Refusal> {
        Self::validate(settings)?;
        self.0.store(generation, Ordering::SeqCst);
        Ok(())
    }
}

mod generational {
    use super::*;
    crate::auth_outbound_door!(Generational, with_tail(statement("gen", "1.0.0", 8), TAIL));
}

/// The text a REFUSED or FAILED answer names.
fn error_text(head: &OutHead) -> String {
    if head.error.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the answer's error text, `len` bytes, kept by the instance or the program.
    let text = unsafe { std::slice::from_raw_parts(head.error.ptr, head.error.len) };
    String::from_utf8_lossy(text).into_owned()
}

/// A HANDLE IS GENERATION DATA: `open` and `refresh` hand the plugin the generation, so the
/// handles a binding opens after a reload belong to the new one; `validate` and `refresh` refuse
/// settings that are not the plugin's with the plugin's own outcome and words, and a refused
/// reload changes nothing.
#[test]
fn open_and_refresh_hand_the_plugin_its_generation_and_its_refusals() {
    let t = ops_of(generational::door);

    let mut buf = vec![0_u8; 64];
    let input = crate::abi::mechanism::lifecycle::ValidateIn {
        head: head::<crate::abi::mechanism::lifecycle::ValidateIn>(life::VALIDATE),
        settings: blob(BAD, BLOB_JSON, 0),
        err_buf: buf.as_mut_ptr(),
        err_cap: buf.len(),
    };
    let mut out = out_head(size_of::<OutHead>());
    assert_eq!(
        cross(t.head.validate, ptr::null_mut(), &input, &mut out),
        Outcome::Refused
    );
    assert_eq!(error_text(&out), "settings: bad");

    let inst = opened(t);
    assert_eq!(
        open_outbound(t, inst, "bearer-test", None, b"{}").1.handle,
        1
    );

    let refresh = |settings: &[u8], generation: u64| {
        let input = crate::abi::mechanism::lifecycle::RefreshIn {
            head: head::<crate::abi::mechanism::lifecycle::RefreshIn>(life::REFRESH),
            generation,
            settings: blob(settings, BLOB_JSON, 0),
            secrets: ptr::null(),
            secrets_len: 0,
        };
        let mut out = out_head(size_of::<OutHead>());
        let o = cross(t.head.refresh, inst, &input, &mut out);
        (o, error_text(&out))
    };
    assert_eq!(refresh(b"{}", 2), (Outcome::Ready, String::new()));
    assert_eq!(
        open_outbound(t, inst, "bearer-test", None, b"{}").1.handle,
        2
    );
    assert_eq!(
        refresh(BAD, 3),
        (Outcome::Refused, "settings: bad".to_string())
    );
    assert_eq!(
        open_outbound(t, inst, "bearer-test", None, b"{}").1.handle,
        2,
        "a refused reload changes nothing"
    );
}

/// What a plugin staged reads back in order, for its own tests.
#[test]
fn staged_diagnostics_read_back_in_order() {
    let mut d = Diags::default();
    assert!(d.is_empty());
    d.push(0, SEVERITY_WARN, "one");
    d.push(2, SEVERITY_INFO, String::from("two"));
    assert_eq!(d.len(), 2);
    assert_eq!(
        d.iter().collect::<Vec<_>>(),
        vec![(0, SEVERITY_WARN, "one"), (2, SEVERITY_INFO, "two")]
    );
}

/// RED (open160 A9, "every refusal says why"): an outbound door's REFUSED answers named no text,
/// so the host's log of the refusal could not say what was refused. An op the door does not serve,
/// a style that is not UTF-8 and a `fields` on a handle the plugin does not hold each answer
/// REFUSED saying why.
#[test]
fn red_every_outbound_refusal_says_why() {
    let t = ops();
    let inst = opened(t);

    // SAFETY: plain C data; all-zero is valid.
    let mut input: VerifyIn = unsafe { std::mem::zeroed() };
    input.head = head::<VerifyIn>(slot::VERIFY);
    input.credential = absent();
    // SAFETY: as above.
    let mut out: IdentifyOut = unsafe { std::mem::zeroed() };
    out.head = out_head(size_of::<IdentifyOut>());
    assert_eq!(cross(t.verify, inst, &input, &mut out), Outcome::Refused);
    assert!(
        !error_text(&out.head).is_empty(),
        "an op the door does not serve was refused saying nothing"
    );

    let not_utf8 = [0xff_u8, 0xfe];
    let input = OpenOutboundIn {
        head: head::<OpenOutboundIn>(slot::OPEN_OUTBOUND),
        style: AbiStr {
            ptr: not_utf8.as_ptr(),
            len: not_utf8.len(),
        },
        credential: absent(),
        settings: blob(b"{}", BLOB_JSON, 0),
    };
    let mut out = OpenOutboundOut {
        head: out_head(size_of::<OpenOutboundOut>()),
        handle: 0,
    };
    assert_eq!(
        cross(t.open_outbound, inst, &input, &mut out),
        Outcome::Refused
    );
    assert!(
        !error_text(&out.head).is_empty(),
        "a style that is not UTF-8 was refused saying nothing"
    );

    let mut host = Host::new(256, 4);
    let (o, out, _) = fields(t, inst, 999, &mut host);
    assert_eq!(o, Outcome::Refused);
    assert!(
        !error_text(&out.head).is_empty(),
        "a handle the plugin does not hold was refused saying nothing"
    );
}
