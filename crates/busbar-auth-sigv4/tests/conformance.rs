// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLUGIN TESTS ITSELF, BOTH WAYS** (BUSBAR-1.6.0.md THE DESIGN, §2; §11.4). See
//! `busbar-auth-header/tests/conformance.rs` for the shared harness shape; this is `sigv4`'s own
//! script.
//!
//! ## The RED arms stay in the file
//!
//! * [`red_a_sensitive_field_flag_is_not_the_1_5_5_bytes`]: the shape TODO item 583 asks for
//!   loads and passes the kind's checks, yet its transcript diverges from the pinned one (Q4: the
//!   1.5.5 bytes win).
//! * [`red_a_writer_that_ignores_the_host_capacity_faults`]: a `fields` that writes past the host's
//!   field capacity is FAULT at the loader, never a truncated header.

use std::ffi::c_void;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{
    self, slot, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, RequestFacts, VerifyIn, FIELD_SENSITIVE, MODE_OWN,
    MODE_PASSTHROUGH, POINT_HEAD_BODY,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Op, Outcome, RawOutcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &'static str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &'static str, fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

fn json(b: &'static str) -> Blob {
    blob(b, BLOB_JSON, 0)
}

fn secret(b: &'static str) -> Blob {
    blob(b, BLOB_OCTETS, BLOB_SECRET)
}

#[derive(Default)]
struct Folds(Mutex<Vec<String>>);

impl EnvelopeSink for Folds {
    fn metric(&self, m: Metric<'_>) {
        self.0.lock().unwrap().push(format!("metric {}", m.family));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!(
            "diag {} sev={} {}",
            d.id,
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn bind(folds: &Arc<Folds>, dispatcher: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("conformance"),
        max_inflight_cap: 64,
        sink: folds.clone(),
        dispatcher: dispatcher.adopter(),
        conns: None,
    }
}

/// The compiled-in row `door` states: its Statement rendering and the door.
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("the door states its Statement")
}

fn linked(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(busbar_auth_sigv4::door), bind(folds, d))
        .expect("the linked door loads")
}

fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Option<Plugin<Auth>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let name = format!(
        "{}busbar_auth_sigv4{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = [profile.join(&name), profile.join("deps").join(&name)]
        .into_iter()
        .find(|p| p.exists());
    assert!(
        path.is_some() || std::env::var_os("CI").is_none(),
        "the busbar-auth-sigv4 cdylib is not built under CI; a both-ways proof must not skip"
    );
    let stated = rendering_of(busbar_auth_sigv4::door).expect("the door renders its Statement");
    path.map(|p| load_dropped::<Auth>(&p, &stated, bind(folds, d)).expect("the dropped door loads"))
}

fn err(e: &Option<Vec<u8>>) -> String {
    e.as_deref()
        .map(|e| String::from_utf8_lossy(e).replace('\n', " | "))
        .unwrap_or_default()
}

struct Buffers {
    buf: Vec<u8>,
    spans: Vec<FieldSpan>,
}

impl Buffers {
    fn new(bytes: usize, fields: usize) -> Self {
        Self {
            buf: vec![0; bytes],
            spans: vec![z(); fields],
        }
    }

    fn read(&self, n: u32) -> String {
        (0..n as usize)
            .map(|i| {
                let f = self.spans[i];
                let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                    String::from_utf8_lossy(
                        &self.buf[sp.offset as usize..sp.offset as usize + sp.len as usize],
                    )
                    .into_owned()
                };
                format!("{}: {} [flags={}]", at(f.name), at(f.value), f.flags)
            })
            .collect::<Vec<_>>()
            .join(" ; ")
    }
}

fn facts() -> RequestFacts {
    RequestFacts {
        method: s("POST"),
        authority: s("runtime.signer.example"),
        canonical_path: s("/model/m/converse"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 1_440_938_160,
    }
}

fn fields(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, cap: (usize, usize)) -> String {
    fields_over(p, handle, mode, caller, cap, None)
}

/// One `fields` call at `HeadBody`, lending `body` (none lent = the empty body).
fn fields_over(
    p: &Plugin<Auth>,
    handle: u64,
    mode: u32,
    caller: Blob,
    cap: (usize, usize),
    body: Option<&'static str>,
) -> String {
    let mut b = Buffers::new(cap.0, cap.1);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = mode;
    f.input.request = facts();
    f.input.point = POINT_HEAD_BODY;
    f.input.body = body.map_or(z(), |b| blob(b, BLOB_OCTETS, 0));
    f.input.caller_credential = caller;
    (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
    (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
    let c = p.call(slot::FIELDS, &mut f);
    let mut line = format!("fields {:?} {}", c.outcome, err(&c.error));
    let mut outcome = c.outcome;
    if let Some(token) = c.recall {
        line.push_str(&format!(
            " short(needed_fields={} needed_bytes={})",
            f.out.needed_fields, f.out.needed_bytes
        ));
        b = Buffers::new(f.out.needed_bytes as usize, f.out.needed_fields as usize);
        (f.input.field_buf, f.input.field_buf_cap) = (b.buf.as_mut_ptr(), b.buf.len());
        (f.input.fields, f.input.fields_cap) = (b.spans.as_mut_ptr(), b.spans.len() as u32);
        f.out = z();
        f.out.head = out_head();
        let c = p.recall(token, slot::FIELDS, &mut f);
        line.push_str(&format!(" -> recall {:?}", c.outcome));
        outcome = c.outcome;
    }
    if outcome == Outcome::Ready {
        line.push_str(&format!(" {}", b.read(f.out.fields_len)));
    }
    line
}

fn open_outbound(
    p: &Plugin<Auth>,
    style: &'static str,
    credential: Option<&'static str>,
    settings: &'static str,
) -> (String, u64) {
    let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.style = s(style);
    f.input.credential = credential.map_or(z(), secret);
    f.input.settings = json(settings);
    let c = p.call(slot::OPEN_OUTBOUND, &mut f);
    (
        format!("open_outbound {style} {:?} {}", c.outcome, err(&c.error)),
        f.out.handle,
    )
}

fn ready(p: &Plugin<Auth>, handle: u64) -> String {
    let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    let c = p.call(slot::OUTBOUND_READY, &mut f);
    format!("ready {:?} {}", c.outcome, f.out.ready)
}

const SIGV4_SETTINGS: &str =
    r#"{"service":"svc","region":"us-east-1","content_type":"application/json"}"#;

fn script(p: &Plugin<Auth>) -> Vec<String> {
    let mut t = Vec::new();

    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json("[1]"),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let c = p.call(life::VALIDATE, &mut v);
    t.push(format!("validate [1] {:?} {}", c.outcome, err(&c.error)));
    v.input.settings = json("{}");
    t.push(format!(
        "validate {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));

    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    t.push(format!("open {:?}", p.call(life::OPEN, &mut o).outcome));

    let (l, sigv4) = open_outbound(p, "sigv4", Some("AKIDEXAMPLE:SECRET:TOKEN"), SIGV4_SETTINGS);
    t.push(l);
    let (l, keyless) = open_outbound(p, "sigv4", None, SIGV4_SETTINGS);
    t.push(l);
    t.push(open_outbound(p, "bearer", Some("k"), "{}").0);
    t.push(open_outbound(p, "kerberos", Some("k"), "{}").0);

    t.push(fields(p, sigv4, MODE_OWN, z(), (1024, 4)));
    t.push(fields(p, sigv4, MODE_OWN, z(), (8, 0)));
    t.push(fields(
        p,
        keyless,
        MODE_PASSTHROUGH,
        secret("AKIDCALLER:CALLERSECRET"),
        (1024, 4),
    ));
    t.push(fields(p, keyless, MODE_OWN, z(), (1024, 4)));
    t.push(fields(p, 999, MODE_OWN, z(), (1024, 4)));
    // The body the host lends at `HeadBody` is what the payload hash covers.
    t.push(fields_over(p, sigv4, MODE_OWN, z(), (1024, 4), Some("{}")));

    for h in [sigv4, keyless] {
        t.push(ready(p, h));
    }

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 1_000,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = p.call(life::TICK, &mut k);
    t.push(format!(
        "tick {:?} next>1000={}",
        c.outcome,
        k.out.next_tick_ns > 1_000
    ));

    let mut vf: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    vf.input.head = in_head();
    vf.out.head = out_head();
    t.push(format!(
        "verify {:?}",
        p.call(slot::VERIFY, &mut vf).outcome
    ));

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    x.input.head = in_head();
    x.out.head = out_head();
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!("cancel {:?}", c.outcome));

    let mut r: Frame<RefreshIn, _> = Frame::new(z(), out_head());
    r.input.head = in_head();
    r.input.generation = 2;
    t.push(format!(
        "refresh {:?}",
        p.call(life::REFRESH, &mut r).outcome
    ));
    let (l, sigv4_2) = open_outbound(p, "sigv4", Some("AKIDEXAMPLE:SECRET:TOKEN"), SIGV4_SETTINGS);
    t.push(l);
    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!(
        "retire 1 {:?}",
        p.call(life::RETIRE, &mut g).outcome
    ));
    t.push(format!(
        "after retire {}",
        fields(p, sigv4, MODE_OWN, z(), (1024, 4))
    ));
    let after_retire_gen2 = fields(p, sigv4_2, MODE_OWN, z(), (1024, 4));
    t.push(format!(
        "gen 2 fields ready with a signature: {}",
        after_retire_gen2.starts_with("fields Ready  authorization: AWS4-HMAC-SHA256")
    ));

    let mut e = Frame::new(in_head(), out_head());
    t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
    t
}

const EXPECTED: &[&str] = &[
    "validate [1] Refused busbar-auth-sigv4 settings must be a JSON object",
    "validate Ready",
    "open Ready",
    "open_outbound sigv4 Ready ",
    "open_outbound sigv4 Ready ",
    "open_outbound bearer Failed settings: outbound auth style `bearer` is not served by this \
     plugin",
    "open_outbound kerberos Failed settings: outbound auth style `kerberos` is not served by this \
     plugin",
    "fields Ready  authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/\
     svc/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;\
     x-amz-security-token, Signature=SIGNATURE [flags=0] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
     [flags=0] ; x-amz-security-token: TOKEN [flags=0]",
    "fields Failed  short(needed_fields=4 needed_bytes=385) -> recall Ready authorization: \
     AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/svc/aws4_request, \
     SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
     Signature=SIGNATURE [flags=0] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
     [flags=0] ; x-amz-security-token: TOKEN [flags=0]",
    "fields Ready  authorization: AWS4-HMAC-SHA256 Credential=AKIDCALLER/20150830/us-east-1/svc/\
     aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
     Signature=SIGNATURE [flags=0] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
     [flags=0]",
    "fields Ready  ",
    "fields Refused ",
    "fields Ready  authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/\
     svc/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;\
     x-amz-security-token, Signature=SIGNATURE [flags=0] ; x-amz-date: 20150830T123600Z [flags=0] ; \
     x-amz-content-sha256: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a \
     [flags=0] ; x-amz-security-token: TOKEN [flags=0]",
    "ready Ready 1",
    "ready Ready 1",
    "tick Ready next>1000=true",
    "verify Refused",
    "cancel Ready",
    "refresh Ready",
    "open_outbound sigv4 Ready ",
    "retire 1 Ready",
    "after retire fields Refused ",
    "gen 2 fields ready with a signature: true",
    "close Ready",
];

const EXPECTED_FOLDS: &[&str] = &[];

/// The SigV4 signature depends on nothing but its inputs; it is replaced by a marker so the
/// transcript reads, and pinned separately by `signing_tests` and the AWS vectors.
fn mask_signature(t: Vec<String>) -> Vec<String> {
    t.into_iter()
        .map(|l| match l.find("Signature=") {
            Some(i) => {
                let end = l[i..].find(' ').map_or(l.len(), |e| i + e);
                format!("{}Signature=SIGNATURE{}", &l[..i], &l[end..])
            }
            None => l,
        })
        .collect()
}

fn run(p: &Plugin<Auth>, folds: &Folds) -> (Vec<String>, Vec<String>) {
    let t = script(p);
    (t, std::mem::take(&mut *folds.0.lock().unwrap()))
}

#[test]
fn compiled_in_and_dropped_in_answer_every_op_identically() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let (linked_t, linked_f) = run(&linked(&folds, &d), &folds);
    assert_eq!(
        mask_signature(linked_t.clone()),
        EXPECTED,
        "the linked door"
    );
    assert_eq!(linked_f, EXPECTED_FOLDS, "the linked door's folds");
    let folds = Arc::new(Folds::default());
    if let Some(p) = dropped(&folds, &d) {
        let (dropped_t, dropped_f) = run(&p, &folds);
        assert_eq!(dropped_t, linked_t, "the dropped door, signature included");
        assert_eq!(dropped_f, linked_f, "the dropped door's folds");
        println!(
            "PROOF auth-sigv4: linked and dropped answered {} ops and {} folds identically",
            linked_t.len(),
            linked_f.len()
        );
    }
}

// ── RED ARMS ────────────────────────────────────────────────────────────────────────────────────

fn door_with_fields(op: Op) -> &'static Door {
    // SAFETY: the plugin's `'static` door and its auth table.
    let (d, ops) = unsafe {
        let d = &*busbar_auth_sigv4::door();
        (d, *d.ops.cast::<auth::Ops>())
    };
    let mut ops = ops;
    ops.fields = Some(op);
    let ops: &'static auth::Ops = Box::leak(Box::new(ops));
    Box::leak(Box::new(Door {
        ops: std::ptr::from_ref(ops).cast(),
        ..*d
    }))
}

fn real_fields() -> Op {
    // SAFETY: the plugin's `'static` door and its auth table.
    unsafe {
        (*(*busbar_auth_sigv4::door()).ops.cast::<auth::Ops>())
            .fields
            .unwrap()
    }
}

extern "C" fn sensitive_fields(inst: *mut c_void, i: *const c_void, o: *mut c_void) -> RawOutcome {
    let r = real_fields()(inst, i, o);
    // SAFETY: the host's live `FieldsIn`/`FieldsOut` for this call.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &*o.cast::<FieldsOut>());
        if r.outcome() == Outcome::Ready {
            for k in 0..o.fields_len as usize {
                (*i.fields.add(k)).flags = FIELD_SENSITIVE;
            }
        }
    }
    r
}

extern "C" fn sensitive_door() -> *const Door {
    door_with_fields(sensitive_fields)
}

#[test]
fn red_a_sensitive_field_flag_is_not_the_1_5_5_bytes() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let red = load_linked::<Auth>(&row(sensitive_door), bind(&folds, &d)).expect("the door loads");
    let t = mask_signature(script(&red));
    assert_ne!(
        t, EXPECTED,
        "a sensitive flag must not pass as the 1.5.5 bytes"
    );
    assert!(
        t.iter().any(|l| l.contains("[flags=1]")),
        "the kind's check admits the flag; only the pinned transcript refuses it"
    );
}

extern "C" fn overrunning_fields(_: *mut c_void, i: *const c_void, o: *mut c_void) -> RawOutcome {
    // SAFETY: the host's live `FieldsOut` for this call; nothing is written past its `out`.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &mut *o.cast::<FieldsOut>());
        o.fields_len = i.fields_cap + 1;
        o.head.outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn overrunning_door() -> *const Door {
    door_with_fields(overrunning_fields)
}

#[test]
fn red_a_writer_that_ignores_the_host_capacity_faults() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let red =
        load_linked::<Auth>(&row(overrunning_door), bind(&folds, &d)).expect("the door loads");
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    assert_eq!(red.call(life::OPEN, &mut o).outcome, Outcome::Ready);
    let (_, h) = open_outbound(&red, "sigv4", Some("AKIDEXAMPLE:SECRET"), SIGV4_SETTINGS);
    assert!(fields(&red, h, MODE_OWN, z(), (1024, 4)).starts_with("fields Fault"));
}
