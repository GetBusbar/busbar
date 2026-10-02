// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLUGIN TESTS ITSELF, BOTH WAYS** (BUSBAR-1.6.0.md THE DESIGN, §2: *"Its `tests/conformance.rs` links it,
//! loads its own cdylib through the real loader, compares the two, and keeps RED arms"*; BUSBAR-1.6.0.md §11.4:
//! compiled in or dropped in, the same table).
//!
//! ONE crate, reached two ways through the loader's ONE path, exactly as `busbar-auth-sigv4` and
//! `busbar-auth-oauth` are:
//!
//! * LINKED — this crate's `door` (the `DoorFn` a compiled-in row holds), through
//!   [`load_linked`];
//! * DROPPED — this crate's own `cdylib` (built with `--features dropped-in`, its one exported
//!   `busbar_plugin_door`), through [`load_dropped`].
//!
//! ONE script drives every auth op both ways through the loader's auth kind, each answer judged by
//! the kind's own `check_*`, and the two are compared on BOTH folds.
//!
//! ## The RED arms stay in the file
//!
//! * [`red_a_sensitive_field_flag_is_not_the_1_5_5_bytes`]: the same plugin with its `fields` slot
//!   rewritten to mark every field `FIELD_SENSITIVE` — the shape TODO item 583 asks for — loads and
//!   passes the kind's checks, yet its transcript diverges from the pinned one. The pinned
//!   transcript is what holds the ARCHITECT's Q4 ruling (the 1.5.5 bytes win: no flag).
//! * [`red_a_writer_that_ignores_the_host_capacity_faults`]: a `fields` that writes past the
//!   host's field capacity is FAULT at the loader, never a truncated header.

use std::ffi::c_void;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{
    self, slot, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, RequestFacts, VerifyIn, FIELD_SENSITIVE, MODE_OWN,
    MODE_PASSTHROUGH,
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

/// THE ENVELOPE FOLD: every diagnostic the host was handed, as `(id, severity, text)`.
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
    load_linked::<Auth>(&row(busbar_auth_header::door), bind(folds, d))
        .expect("the linked door loads")
}

/// This crate's own cdylib, beside the test executable's `deps/`. Under CI a missing artifact is a
/// failure, never a skip.
fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Option<Plugin<Auth>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let name = format!(
        "{}busbar_auth_header{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = [profile.join(&name), profile.join("deps").join(&name)]
        .into_iter()
        .find(|p| p.exists());
    assert!(
        path.is_some() || std::env::var_os("CI").is_none(),
        "the busbar-auth-header cdylib is not built under CI; a both-ways proof must not skip"
    );
    let stated = rendering_of(busbar_auth_header::door).expect("the door renders its Statement");
    path.map(|p| load_dropped::<Auth>(&p, &stated, bind(folds, d)).expect("the dropped door loads"))
}

fn err(e: &Option<Vec<u8>>) -> String {
    e.as_deref()
        .map(|e| String::from_utf8_lossy(e).replace('\n', " | "))
        .unwrap_or_default()
}

/// The host's buffers one `fields` call writes into.
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

    /// What the answer wrote: `name: value` per field, and the flags.
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

/// One `fields` call over `bytes`/`fields` of host capacity; a SHORT answer earns its ONE re-call
/// with the capacity it named.
fn fields(p: &Plugin<Auth>, handle: u64, mode: u32, caller: Blob, cap: (usize, usize)) -> String {
    let mut b = Buffers::new(cap.0, cap.1);
    let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.handle = handle;
    f.input.mode = mode;
    f.input.request = facts();
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
    // The loader's judgement, never the plugin's own `out`: a FAULT answer is never read.
    if outcome == Outcome::Ready {
        line.push_str(&format!(" {}", b.read(f.out.fields_len)));
    }
    line
}

/// `open_outbound`, answering `(line, handle)`.
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

/// THE SCRIPT: every auth op, each answer read back.
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

    let (l, bearer) = open_outbound(p, "bearer", Some("sk-test-123"), "{}");
    t.push(l);
    let (l, api_key) = open_outbound(p, "api-key", Some("azure-key"), "{}");
    t.push(l);
    let (l, goog) = open_outbound(p, "x-goog-api-key", Some("goog-key"), "{}");
    t.push(l);
    let (l, bad_bytes) = open_outbound(p, "bearer", Some("sk\r\ninjected"), "{}");
    t.push(l);
    let (l, keyless) = open_outbound(p, "x-goog-api-key", None, "{}");
    t.push(l);
    t.push(open_outbound(p, "sigv4", Some("k"), "{}").0);
    t.push(open_outbound(p, "kerberos", Some("k"), "{}").0);

    t.push(fields(p, bearer, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, bearer, MODE_OWN, z(), (8, 0)));
    t.push(fields(p, api_key, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, goog, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, bad_bytes, MODE_OWN, z(), (256, 4)));
    t.push(fields(
        p,
        keyless,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));
    t.push(fields(
        p,
        bearer,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));
    t.push(fields(p, keyless, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, 999, MODE_OWN, z(), (256, 4)));
    // THE QUERY STYLE: the credential as a query parameter the framer appends, flagged
    // FIELD_QUERY (2), under the dialect's parameter name.
    let (l, query) = open_outbound(p, "query-key", Some("gem-key"), "{}");
    t.push(l);
    let (l, named) = open_outbound(p, "query-key", Some("gem-key"), r#"{"param":"api_key"}"#);
    t.push(l);
    t.push(fields(p, query, MODE_OWN, z(), (256, 4)));
    t.push(fields(p, named, MODE_OWN, z(), (256, 4)));
    t.push(fields(
        p,
        query,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));

    for h in [bearer, api_key, goog, keyless] {
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
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

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
    let (l, bearer2) = open_outbound(p, "bearer", Some("sk-test-123"), "{}");
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
        fields(p, bearer, MODE_OWN, z(), (256, 4))
    ));
    t.push(format!(
        "gen 2 {}",
        fields(p, bearer2, MODE_OWN, z(), (256, 4))
    ));

    let mut e = Frame::new(in_head(), out_head());
    t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
    t
}

/// The transcript every build must answer: the 1.5.5 header bytes, no sensitive flag, the
/// `credential:` / `settings:` refusal lines, the short-buffer re-call, the caller-mode
/// presentation (ARCHITECT ruling 2026-09-29), the expired handle.
const EXPECTED: &[&str] = &[
    "validate [1] Refused busbar-auth-header settings must be a JSON object",
    "validate Ready",
    "open Ready",
    "open_outbound bearer Ready ",
    "open_outbound api-key Ready ",
    "open_outbound x-goog-api-key Ready ",
    "open_outbound bearer Ready ",
    "open_outbound x-goog-api-key Ready ",
    "open_outbound sigv4 Failed settings: outbound auth style `sigv4` is not served by this plugin",
    "open_outbound kerberos Failed settings: outbound auth style `kerberos` is not served by this \
     plugin",
    "fields Ready  authorization: Bearer sk-test-123 [flags=0]",
    "fields Failed  short(needed_fields=1 needed_bytes=31) -> recall Ready authorization: Bearer \
     sk-test-123 [flags=0]",
    "fields Ready  api-key: azure-key [flags=0]",
    "fields Ready  x-goog-api-key: goog-key [flags=0]",
    "fields Ready  ",
    "fields Ready  x-goog-api-key: caller-tok [flags=0]",
    "fields Ready  authorization: Bearer caller-tok [flags=0]",
    "fields Ready  ",
    "fields Refused ",
    "open_outbound query-key Ready ",
    "open_outbound query-key Ready ",
    "fields Ready  key: gem-key [flags=2]",
    "fields Ready  api_key: gem-key [flags=2]",
    "fields Ready  key: caller-tok [flags=2]",
    "ready Ready 1",
    "ready Ready 1",
    "ready Ready 1",
    "ready Ready 1",
    "tick Ready next=0",
    "verify Refused",
    "cancel Ready",
    "refresh Ready",
    "open_outbound bearer Ready ",
    "retire 1 Ready",
    "after retire fields Refused ",
    "gen 2 fields Ready  authorization: Bearer sk-test-123 [flags=0]",
    "close Ready",
];

/// The folds every build must hand the host: the un-encodable bearer's line at open.
const EXPECTED_FOLDS: &[&str] = &[
    "diag 1 sev=0 authorization credential contains invalid header bytes (ASCII control \
     character); omitting auth header — upstream will reject with 401",
];

fn run(p: &Plugin<Auth>, folds: &Folds) -> (Vec<String>, Vec<String>) {
    let t = script(p);
    (t, std::mem::take(&mut *folds.0.lock().unwrap()))
}

#[test]
fn compiled_in_and_dropped_in_answer_every_op_identically() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let (linked_t, linked_f) = run(&linked(&folds, &d), &folds);
    assert_eq!(linked_t, EXPECTED, "the linked door");
    assert_eq!(linked_f, EXPECTED_FOLDS, "the linked door's folds");
    let folds = Arc::new(Folds::default());
    if let Some(p) = dropped(&folds, &d) {
        let (dropped_t, dropped_f) = run(&p, &folds);
        assert_eq!(dropped_t, linked_t, "the dropped door");
        assert_eq!(dropped_f, linked_f, "the dropped door's folds");
        println!(
            "PROOF auth-header: linked and dropped answered {} ops and {} folds identically",
            linked_t.len(),
            linked_f.len()
        );
    }
}

// ── RED ARMS ────────────────────────────────────────────────────────────────────────────────────

/// The door with `fields` replaced by `op`.
fn door_with_fields(op: Op) -> &'static Door {
    // SAFETY: the plugin's `'static` door and its auth table.
    let (d, ops) = unsafe {
        let d = &*busbar_auth_header::door();
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
        (*(*busbar_auth_header::door()).ops.cast::<auth::Ops>())
            .fields
            .unwrap()
    }
}

/// The real `fields`, then every written field marked `FIELD_SENSITIVE`.
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
    let t = script(&red);
    assert_ne!(
        t, EXPECTED,
        "a sensitive flag must not pass as the 1.5.5 bytes"
    );
    assert!(
        t.iter().any(|l| l.contains("[flags=1]")),
        "the kind's check admits the flag; only the pinned transcript refuses it"
    );
}

/// A `fields` that ignores the host's capacity and reports more fields than it was given room for.
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
    let (_, h) = open_outbound(&red, "bearer", Some("sk"), "{}");
    assert!(fields(&red, h, MODE_OWN, z(), (256, 4)).starts_with("fields Fault"));
}

/// THE h2 BEARER BYTES (BUSBAR-1.6.0.md THE DESIGN, §6's proof): DOOR-TRANSPORT's `h2_parity` harness proves the
/// framer door puts `authorization: Bearer sk-ant-test-0123456789` on the wire byte-identical to
/// 1.5.5's reqwest, HPACK block included. That header is exactly what this plugin writes for that
/// key, through the loader, both builds: the same name, the same value, and no sensitive flag (a
/// flagged field would be sent never-indexed, other bytes — ARCHITECT ruling Q4).
#[test]
fn the_bearer_field_is_the_h2_parity_harness_input() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let mut builds = vec![linked(&folds, &d)];
    builds.extend(dropped(&folds, &d));
    for p in &builds {
        let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
        o.input.head = in_head();
        o.out.head = out_head();
        assert_eq!(p.call(life::OPEN, &mut o).outcome, Outcome::Ready);
        let (_, h) = open_outbound(p, "bearer", Some("sk-ant-test-0123456789"), "{}");
        assert_eq!(
            fields(p, h, MODE_OWN, z(), (256, 4)),
            "fields Ready  authorization: Bearer sk-ant-test-0123456789 [flags=0]"
        );
    }
}
