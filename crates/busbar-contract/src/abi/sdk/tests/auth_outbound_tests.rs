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
use crate::abi::mechanism::door::{Door, DoorFn};
use crate::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::sdk::auth_door::{with_tail, Answer, Verdict, VerifiedIdentity, VerifyView};
use crate::abi::sdk::door::{abi_str, statement};

use super::*;

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
    fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Echo::default())
    }

    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
    ) -> Result<u64, OpenRefusal> {
        if style != "bearer-test" {
            let refusal = OpenRefusal::new("style: not served");
            return Err(refusal.and("credential: unused"));
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
    crate::auth_outbound_door!(Echo, with_tail(statement("echo", "1.0.0", 8), TAIL));
}

fn ops() -> &'static Ops {
    ops_of(plugin::door)
}

fn ops_of(door: DoorFn) -> &'static Ops {
    // SAFETY: the macro's door and table are `'static` consts.
    let d: &Door = unsafe { &*door() };
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
        host: HostCtx {
            ptr: ptr::null_mut(),
        },
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
    let st = unsafe { &*(*plugin::door()).statement };
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
    fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Stray)
    }
    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
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
    fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Sig)
    }
    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
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
    let st = unsafe { &*(*both::door()).statement };
    // SAFETY: as above.
    let tail = unsafe { &*st.kind_tail.cast::<AuthTail>() };
    assert_eq!(tail.caps, CAP_OUTBOUND | CAP_INBOUND);
    assert_eq!(tail.inbound_points, POINT_HEAD);
}
