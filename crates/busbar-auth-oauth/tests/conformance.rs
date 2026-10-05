// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLUGIN TESTS ITSELF, BOTH WAYS** (BUSBAR-1.6.0.md THE DESIGN, §2; §11.4). See
//! `busbar-auth-header/tests/conformance.rs` for the shared harness shape; this is
//! `jwt-bearer`/`oauth-client-credentials`'s own script. The doors are bound with no connection
//! table here, so the plugin's own needs are not granted and nothing mints: the script proves
//! refusal shape, the not-ready answer and cache bookkeeping; `instance_tests.rs` proves the mint
//! over a scripted need and the `mint_door` module below over the one loader and a connection table.
//!
//! ## The RED arms stay in the file
//!
//! * [`red_a_sensitive_field_flag_is_not_the_1_5_5_bytes`]
//! * [`red_a_writer_that_ignores_the_host_capacity_faults`]

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
    load_linked::<Auth>(&row(busbar_auth_oauth::door), bind(folds, d))
        .expect("the linked door loads")
}

fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Option<Plugin<Auth>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let name = format!(
        "{}busbar_auth_oauth{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = [profile.join(&name), profile.join("deps").join(&name)]
        .into_iter()
        .find(|p| p.exists());
    assert!(
        path.is_some() || std::env::var_os("CI").is_none(),
        "the busbar-auth-oauth cdylib is not built under CI; a both-ways proof must not skip"
    );
    let stated = rendering_of(busbar_auth_oauth::door).expect("the door renders its Statement");
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

const OAUTH: &str = r#"{"token_url":"https://idp.example/token","scope":"s"}"#;

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

    let (l, oauth) = open_outbound(p, "oauth-client-credentials", Some("id:secret"), OAUTH);
    t.push(l);
    t.push(
        open_outbound(
            p,
            "oauth-client-credentials",
            Some("unused"),
            r#"{"scope":"s"}"#,
        )
        .0,
    );
    t.push(open_outbound(p, "jwt-bearer", None, "{}").0);
    t.push(open_outbound(p, "bearer", Some("k"), "{}").0);
    t.push(open_outbound(p, "kerberos", Some("k"), "{}").0);

    // No connection table is handed: nothing mints, so `fields` is not ready (ticket-less:
    // REFUSED, never an empty answer).
    t.push(fields(p, oauth, MODE_OWN, z(), (256, 4)));
    t.push(fields(
        p,
        oauth,
        MODE_PASSTHROUGH,
        secret("caller-tok"),
        (256, 4),
    ));
    t.push(fields(p, 999, MODE_OWN, z(), (256, 4)));

    t.push(ready(p, oauth));

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
    t.push(format!(
        "cancel {:?} continues={}",
        c.outcome,
        x.out.disposition == busbar_contract::abi::auth::CANCEL_CONTINUES
    ));

    let mut r: Frame<RefreshIn, _> = Frame::new(z(), out_head());
    r.input.head = in_head();
    r.input.generation = 2;
    t.push(format!(
        "refresh {:?}",
        p.call(life::REFRESH, &mut r).outcome
    ));
    let (l, oauth2) = open_outbound(p, "oauth-client-credentials", Some("id:secret"), OAUTH);
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
        fields(p, oauth, MODE_OWN, z(), (256, 4))
    ));
    t.push(format!(
        "gen 2 {}",
        fields(p, oauth2, MODE_OWN, z(), (256, 4))
    ));

    let mut e = Frame::new(in_head(), out_head());
    t.push(format!("close {:?}", p.call(life::CLOSE, &mut e).outcome));
    t
}

const EXPECTED: &[&str] = &[
    "validate [1] Refused busbar-auth-oauth settings must be a JSON object",
    "validate Ready",
    "open Ready",
    "open_outbound oauth-client-credentials Ready ",
    "open_outbound oauth-client-credentials Failed settings: uses auth: oauth-client-credentials \
     but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to) | \
     credential: oauth-client-credentials key must be `client_id:client_secret`",
    "open_outbound jwt-bearer Failed settings: uses auth: jwt-bearer but declares `api_key: none`; \
     that grant signs its assertion WITH the credential (the service-account JSON or key file), so \
     there is nothing to declare keyless",
    "open_outbound bearer Failed settings: outbound auth style `bearer` is not served by this \
     plugin",
    "open_outbound kerberos Failed settings: outbound auth style `kerberos` is not served by this \
     plugin",
    "fields Refused ",
    "fields Refused ",
    "fields Refused ",
    "ready Ready 0",
    "tick Ready next=30000001000",
    "verify Refused",
    "cancel Ready continues=true",
    "refresh Ready",
    "open_outbound oauth-client-credentials Ready ",
    "retire 1 Ready",
    "after retire fields Refused ",
    "gen 2 fields Refused ",
    "close Ready",
];

const EXPECTED_FOLDS: &[&str] = &[
    "diag 2 sev=1 OAuth token mint failed; will retry error=token endpoint request failed: no \
     connection was granted for the token endpoint",
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
            "PROOF auth-oauth: linked and dropped answered {} ops and {} folds identically",
            linked_t.len(),
            linked_f.len()
        );
    }
}

// ── RED ARMS ────────────────────────────────────────────────────────────────────────────────────

fn door_with_fields(op: Op) -> &'static Door {
    // SAFETY: the plugin's `'static` door and its auth table.
    let (d, ops) = unsafe {
        let d = &*busbar_auth_oauth::door();
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
        (*(*busbar_auth_oauth::door()).ops.cast::<auth::Ops>())
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
    let t = script(&red);
    assert_eq!(
        t, EXPECTED,
        "no mint lands without a connection table (the step 20-21 seam), so this build's \
         transcript is unchanged — the RED case that DOES diverge is covered end to end by \
         busbar-auth-header, whose styles mint nothing and so always answer fields synchronously"
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
    let (_, h) = open_outbound(&red, "oauth-client-credentials", Some("id:secret"), OAUTH);
    assert!(fields(&red, h, MODE_OWN, z(), (256, 4)).starts_with("fields Fault"));
}

// THE MINT THROUGH THE PLUGIN'S OWN NEED, OVER THE ONE LOADER (THE DESIGN §5, §6.5, §11; TODO
// row 22). Folded here from the former `tests/mint_door.rs` so the plugin's loader usage
// stays in its ONE conformance witness file (THE DESIGN §2 / §11.4; the witness grant covers
// exactly this file). The scripted connection-table double mints, then refreshes, the bearer.
mod mint_door {
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED,
    };
    use busbar_contract::abi::mechanism::rendering::ReadNeed;
    use busbar_contract::auth_calls::{Fields, FieldsRequest, OutboundAuth};
    use busbar_contract::conn::{
        ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
        PieceKind,
    };
    use busbar_contract::ids::StreamId;
    use busbar_contract::transport::ConnFacts;
    use busbar_plugin_loader::dispatch::auth_outbound::OutboundInstance;
    use busbar_plugin_loader::dispatch::kinds::auth::Auth;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };

    const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
    const SCOPE: &str = "https://cognitiveservices.azure.com/.default";
    const CREDENTIAL: &str = "oracle-client-0001:oracle:secret:with:colons";

    /// What one open carried: the need, the target, the method, the head target, the fields, the body.
    type Opened = (u32, String, String, String, Vec<(String, String)>, String);

    /// Each open's reply, piece by piece, with its bytes.
    type Replies = HashMap<ConnId, VecDeque<(Piece, Vec<u8>)>>;

    /// A connection table whose needs are framed: each open is recorded and answered by the token
    /// endpoint's next reply (`expires_in` 2, then 3600), one piece per read.
    #[derive(Default)]
    struct TokenEndpoint {
        slab: ConnSlab<()>,
        declared: Mutex<Vec<(u32, ReadNeed, Option<String>)>>,
        opened: Mutex<Vec<Opened>>,
        replies: Mutex<Replies>,
    }

    fn piece(kind: PieceKind, len: usize, status: Option<u32>) -> Piece {
        Piece {
            kind,
            stream: StreamId(0),
            len,
            end: kind != PieceKind::Fields,
            status: None,
            status_code: status,
            status_namespace: None,
            retry_after_secs: None,
            reason: None,
        }
    }

    impl DeclaredConns for TokenEndpoint {
        fn declare(
            &self,
            owner: InstanceId,
            need: NeedId,
            spec: &ReadNeed,
            target: Option<&str>,
            _trust: Option<&str>,
        ) -> Result<(), ConnError> {
            self.declared
                .lock()
                .unwrap()
                .push((need.0, spec.clone(), target.map(str::to_owned)));
            // A `target_from` that resolved to nothing is refused, as the connector refuses it.
            if !spec.target_from.is_empty() && target.is_none() {
                return Err(ConnError::Refused);
            }
            self.slab.declare(owner, need);
            Ok(())
        }
        fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
            self.slab.check_need(owner, need).ok().map(Ok)
        }
        fn framed(&self, _: InstanceId, _: NeedId) -> bool {
            true
        }
        fn serves_scheme(&self, scheme: &str) -> bool {
            scheme == "http"
        }
    }

    impl Conns for TokenEndpoint {
        fn open(
            &self,
            caller: InstanceId,
            need: NeedId,
            desc: &OpenDesc<'_>,
        ) -> Result<ConnId, ConnError> {
            self.slab.check_need(caller, need)?;
            let mut opened = self.opened.lock().unwrap();
            opened.push((
                need.0,
                desc.target.to_owned(),
                String::from_utf8_lossy(desc.method).into_owned(),
                String::from_utf8_lossy(desc.head_target).into_owned(),
                desc.fields
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), String::from_utf8_lossy(v).into_owned()))
                    .collect(),
                String::from_utf8_lossy(desc.body).into_owned(),
            ));
            let n = opened.len();
            let body = format!(
                r#"{{"access_token":"oracle-minted-{n}","expires_in":{},"token_type":"Bearer"}}"#,
                if n == 1 { 2 } else { 3600 }
            );
            let id = self.slab.insert(caller, need, ())?;
            self.replies.lock().unwrap().insert(
                id,
                VecDeque::from([
                    (piece(PieceKind::Fields, 0, Some(200)), Vec::new()),
                    (piece(PieceKind::Body, body.len(), None), body.into_bytes()),
                    (piece(PieceKind::Completion, 0, None), Vec::new()),
                ]),
            );
            Ok(id)
        }
        fn write(
            &self,
            _: InstanceId,
            _: ConnId,
            b: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            Ok(b.len())
        }
        fn read(
            &self,
            c: InstanceId,
            id: ConnId,
            _: u64,
            buf: &mut [u8],
        ) -> Result<Piece, ConnError> {
            self.slab.get(c, id)?;
            let (p, bytes) = self
                .replies
                .lock()
                .unwrap()
                .get_mut(&id)
                .and_then(VecDeque::pop_front)
                .ok_or(ConnError::Closed)?;
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(p)
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
            Err(ConnError::Pending)
        }
        fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
            Err(ConnError::Closed)
        }
        fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
            self.replies.lock().unwrap().remove(&id);
            self.slab.remove(c, id).map(|_| ())
        }
    }

    /// The authorization one `fields` answer presents, if any.
    fn presented(answer: &Fields) -> Option<String> {
        match answer {
            Fields::Ready(fields) => fields.iter().find_map(|f| {
                (f.name == b"authorization")
                    .then(|| String::from_utf8_lossy(f.value.expose_secret()).into_owned())
            }),
            _ => None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_presents_its_minted_bearer_then_the_refreshed_one() {
        let table = Arc::new(TokenEndpoint::default());
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let row = LinkedRow::of(busbar_auth_oauth::door).expect("the door states its Statement");
        let plugin = load_linked::<Auth>(
            &row,
            Bind {
                instance: Arc::from("busbar-auth-oauth"),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: Some(Arc::clone(&table) as Arc<dyn DeclaredConns>),
            },
        )
        .expect("the linked door binds on the connection table");
        assert!(
            plugin.targets_from_settings(),
            "its needs take their target from the binding's settings"
        );

        // THE INSTANCE, OPENED OVER THE BINDING'S SETTINGS: its token_url need is declared pinned to
        // the binding's endpoint, `loopback-allowed` (https or loopback plaintext, as 1.5.5
        // validated a mint endpoint), over the http transport.
        let settings = serde_json::json!({ "token_url": TOKEN_URL, "scope": SCOPE });
        let instance = Arc::new(
            OutboundInstance::open_with(
                plugin,
                Arc::clone(&dispatcher),
                0,
                &serde_json::to_vec(&settings).expect("json"),
            )
            .expect("the instance opens"),
        );
        {
            let declared = table.declared.lock().unwrap();
            let token_url = declared
                .iter()
                .find(|(need, _, _)| *need == 0)
                .expect("the token_url need is declared");
            assert_eq!(token_url.1.direction, DIRECTION_OUTBOUND);
            assert_eq!(token_url.1.egress_class, EGRESS_LOOPBACK_ALLOWED);
            assert_eq!(token_url.1.transport, "http");
            assert_eq!(token_url.1.target_from, "settings.token_url");
            assert_eq!(token_url.2.as_deref(), Some(TOKEN_URL), "pinned to it");
        }
        let handle = instance
            .open_outbound("oauth-client-credentials", CREDENTIAL.as_bytes(), &settings)
            .expect("the binding opens");

        // BEFORE THE FIRST MINT: not ready. On the spot the call is refused (the host submits it on a
        // ticket); nothing is presented empty.
        let request = FieldsRequest::default();
        assert!(
            instance.fields_now(handle, &request).is_none(),
            "nothing minted yet: no answer on the spot"
        );

        // THE TICK SCHEDULE: the first mint lands, and the waiting call presents it.
        tokio::spawn(Arc::clone(&instance).ticks());
        let first = tokio::time::timeout(
            Duration::from_secs(10),
            instance.fields(handle, FieldsRequest::default(), 0),
        )
        .await
        .expect("the first mint lands");
        assert_eq!(
            presented(&first).as_deref(),
            Some("Bearer oracle-minted-1"),
            "the first upstream request carries the first token: {first:?}"
        );
        assert_eq!(
            presented(
                &instance
                    .fields_now(handle, &request)
                    .expect("ready on the spot")
            )
            .as_deref(),
            Some("Bearer oracle-minted-1"),
            "the cached bearer answers in place, one call"
        );

        // THE REFRESH AHEAD OF EXPIRY: `expires_in: 2` re-mints after one second (1.5.5's
        // `next_refresh_secs`), and the next request carries the refreshed token.
        let refreshed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(answer) = instance.fields_now(handle, &request) {
                    if presented(&answer).as_deref() == Some("Bearer oracle-minted-2") {
                        return answer;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the refresh lands");
        assert_eq!(
            presented(&refreshed).as_deref(),
            Some("Bearer oracle-minted-2")
        );

        // THE TOKEN REQUESTS, as 1.5.5 POSTed them: the mint, then the refresh, byte for byte.
        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
        let form = "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
                oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com\
                %2F.default";
        for sent in opened.iter() {
            assert_eq!(
                sent,
                &(
                    0,
                    TOKEN_URL.to_string(),
                    "POST".to_string(),
                    "/tenant/oauth2/v2.0/token".to_string(),
                    vec![(
                        "content-type".to_string(),
                        "application/x-www-form-urlencoded".to_string()
                    )],
                    form.to_string(),
                )
            );
        }
    }
}
