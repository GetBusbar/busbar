// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE AUTH KIND'S CONFORMANCE SUITE** (TODO ABI-b4: one suite per kind, running the SHIPPED
//! compiled-in build and the dropped-in build through the same table; DECISIONS #2, THE DESIGN
//! §11.4). The auth kind is ONE kind with TWO operations (DECISIONS #3): inbound VERIFY and the
//! outbound per-request auth fields, SIGN. No plugin serves both, so each operation is proven over
//! the real plugin that serves it, each reached by its row of `[package.metadata.busbar.both-ways]`
//! (`auth-verify`, `auth-sign`) and never by its name:
//!
//! * LINKED — the row's `door`, the one a compiled-in row holds (the composition root's `auths` axis
//!   links the verify row's door), registered through [`PluginRegistry::link`];
//! * DROPPED IN — the plugin's own `cdylib` (verify) or the same `door` behind the one exported
//!   symbol (sign, the `auth_sign_door` example), signed first-party into `plugins/` and found by
//!   the scan.
//!
//! Each registry's row is loaded the way the auth axis loads it (`AuthRows`: the linked door through
//! [`load_linked`], the dropped one through [`load_dropped_bytes`] against its signed Statement), on
//! a real dispatcher, and opened by the kernel's one opener ([`AuthInstance::open`]). VERIFY then
//! runs the token cases through the kernel's identity calls ([`AuthCalls`]: on the spot and
//! submitted) and the cache refresh; SIGN binds each style through the kernel's egress calls
//! ([`OutboundAuth`]) and asks for the fields of every binding, in both credential modes, on the
//! spot and submitted.
//!
//! ## What is compared
//!
//! Per operation, a [`Fold`] of each door: the TRANSCRIPT (every answer as the kernel reads it), the
//! ENVELOPE (every metric, diagnostic and drop the host was handed) and the EXACT CROSSINGS each
//! step made (`== n`, never `> 0`: M6/contract). The two folds must be equal ([`compared`]), the
//! crossings must be the counts the kind's calls make, and each transcript must reach every answer
//! it names, so the equality is not vacuous. The suite is profile-free: the proof job runs it under
//! the release profile (`--cargo-profile release`), the shipped build's.
//!
//! ## The RED arms stay in the file
//!
//! * [`a_divergent_verify_door_fails_the_comparison`]: the verify row's door with its `verify`
//!   answering PASS where the plugin answers REJECT — an answer the kind's checks admit — linked
//!   beside the real dropped-in plugin. [`compared`] refuses it.
//! * [`a_divergent_sign_door_fails_the_comparison`]: the sign row's door with its `fields` marking
//!   every field sensitive (other bytes on the wire), the same way.
//! * [`a_third_party_signature_is_a_different_row`]: the same image signed by a third party is a
//!   different registry row, so the row equality is not vacuous either.

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use busbar_contract::abi::auth::{
    self as abi, AuthPoint, FieldsIn, FieldsOut, IdentifyOut, FIELD_SENSITIVE, VERDICT_PASS,
    VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::auth_calls::{
    AuthCalls, Fields, FieldsRequest, OutboundAuth, Verified, VerifyAnswer, VerifyRequest,
};
use busbar_contract::redacted::{sha256_hex, Redacted};

use super::both_ways::{
    cdylib, door_fixture, dropped, dropped_third_party, example_cdylib, row, statement,
};
use crate::auth_axis::AuthRows;
use crate::auth_door::{split_secrets, AuthInstance, AuthSink};
use crate::dispatch::auth_outbound::OutboundInstance;
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{
    load_dropped_bytes, load_linked, now_ns, Bind, Budgets, Diagnostic, DispatchConfig, Dispatcher,
    Dropped, EnvelopeSink, LinkedRow, Metric, Plugin,
};
use crate::{LinkedPlugin, PluginRegistry};

// ── THE TWO PROOFS ──────────────────────────────────────────────────────────────────────────────

/// One operation's proof: the both-ways row it reads, the name and alias both doors state, and
/// where its dropped-in image is built.
struct Proof {
    row: &'static str,
    name: &'static str,
    alias: &'static str,
    image: fn(&str) -> Option<PathBuf>,
}

/// VERIFY: the row's plugin ships its own `cdylib` (built under `deps/`, hashed).
const VERIFY: Proof = Proof {
    row: "auth-verify",
    name: "auth-fixture",
    alias: "the-auth",
    image: own_cdylib,
};

/// SIGN: the row's door behind the one exported symbol, the `auth_sign_door` example.
const SIGN: Proof = Proof {
    row: "auth-sign",
    name: "auth-sign-fixture",
    alias: "the-signer",
    image: sign_example,
};

fn own_cdylib(crate_snake: &str) -> Option<PathBuf> {
    cdylib(crate_snake)
}

fn sign_example(_: &str) -> Option<PathBuf> {
    example_cdylib("auth_sign_door")
}

/// The manifest both doors state, carrying the Statement rendering `door` states (a dropped-in
/// plugin's signed manifest carries its rendering: the design's One Statement).
fn stated(p: &Proof, door: DoorFn) -> crate::sign::Manifest {
    let rendering = LinkedRow::of(door)
        .expect("the door states itself")
        .statement;
    crate::sign::Manifest {
        statement: Some(hex::encode(rendering)),
        ..statement("auth", p.name, p.alias, abi::ABI_VERSION)
    }
}

/// The proof's two registries: `door` LINKED, and the row's image DROPPED IN (signed first-party, or
/// by a third party). `None` when the image is not built in this scoped, non-CI run (the image
/// lookups hard-fail under CI).
fn registries(p: &Proof, door: DoorFn, third_party: bool) -> Option<[PluginRegistry; 2]> {
    let (crate_snake, _) = door_fixture(p.row);
    let lib = std::fs::read((p.image)(crate_snake)?).expect("read the dropped-in image");
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(stated(p, door), door)])
        .expect("the linked door admits the plugin");
    let manifest = stated(p, door_fixture(p.row).1);
    let dropped = if third_party {
        let manifest = crate::sign::Manifest {
            publisher: "a-third-party".into(),
            ..manifest
        };
        dropped_third_party(crate_snake, manifest, &lib)
    } else {
        dropped(crate_snake, manifest, &lib)
    };
    Some([linked, dropped])
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }))
}

// ── THE FOLDS ───────────────────────────────────────────────────────────────────────────────────

/// THE ENVELOPE FOLD: every entry the host was handed, recorded, then passed on to the auth
/// instance's own sink (its refresh count is read there).
struct Envelope {
    seen: Mutex<Vec<String>>,
    to: Arc<dyn EnvelopeSink>,
}

impl Envelope {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn push(&self, line: String) {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(line);
    }
}

impl EnvelopeSink for Envelope {
    fn metric(&self, m: Metric<'_>) {
        let labels: Vec<_> = m
            .labels
            .iter()
            .map(|l| String::from_utf8_lossy(l))
            .collect();
        self.push(format!(
            "metric family={} kind={} value={} labels={labels:?}",
            m.family, m.kind, m.value
        ));
        self.to.metric(m);
    }

    fn diag(&self, d: Diagnostic<'_>) {
        self.push(format!(
            "diag {} {} sev={} {}",
            d.id,
            String::from_utf8_lossy(d.name),
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
        self.to.diag(d);
    }

    fn dropped(&self, why: Dropped) {
        self.push(format!("dropped {why:?}"));
        self.to.dropped(why);
    }
}

/// What one door did over one operation's script.
#[derive(Debug, Default)]
struct Fold {
    /// Every answer, as the kernel reads it.
    transcript: Vec<String>,
    /// The crossings each transcript line made, in order.
    crossings: Vec<u64>,
    /// The envelope the host was handed over the whole script.
    envelope: Vec<String>,
}

impl Fold {
    fn step(&mut self, what: String, crossed: u64) {
        self.transcript.push(what);
        self.crossings.push(crossed);
    }

    fn has(&self, needle: &str) -> bool {
        self.transcript.iter().any(|l| l.contains(needle))
    }
}

/// THE COMPARISON both arms run: `None` when the two folds are one plugin's, else the first
/// difference.
fn compared(linked: &Fold, dropped: &Fold) -> Option<String> {
    let lines = linked.transcript.iter().zip(&dropped.transcript);
    if let Some((i, (a, b))) = lines.enumerate().find(|(_, (a, b))| a != b) {
        return Some(format!(
            "transcript line {i}:\n linked:     {a}\n dropped in: {b}"
        ));
    }
    if linked.transcript.len() != dropped.transcript.len() {
        return Some("the two doors ran different scripts".into());
    }
    if linked.crossings != dropped.crossings {
        return Some(format!(
            "crossings: linked {:?}, dropped in {:?}",
            linked.crossings, dropped.crossings
        ));
    }
    (linked.envelope != dropped.envelope).then(|| {
        format!(
            "envelope: linked {:?}, dropped in {:?}",
            linked.envelope, dropped.envelope
        )
    })
}

/// Crossings `p` actually made.
fn crossings(p: &Plugin<Auth>) -> u64 {
    p.inner.crossings.load(Ordering::SeqCst)
}

/// One proof's row loaded from `registry` the way the auth axis loads it, bound to a fresh
/// dispatcher with the recording envelope, and opened over `settings` by the kernel's one opener.
struct Opened {
    plugin: Plugin<Auth>,
    instance: AuthInstance,
    dispatcher: Arc<Dispatcher>,
    envelope: Arc<Envelope>,
}

/// `(the opened instance, the crossings opening it made)`.
fn open(registry: &PluginRegistry, p: &Proof, settings: &serde_json::Value) -> (Opened, u64) {
    let dispatcher = dispatcher();
    let sink = AuthSink::new(p.name);
    let envelope = Arc::new(Envelope {
        seen: Mutex::new(Vec::new()),
        to: sink.bind(),
    });
    let bind = Bind {
        instance: Arc::from(p.alias),
        max_inflight_cap: 64,
        sink: envelope.clone(),
        dispatcher: dispatcher.adopter(),
        conns: None,
    };
    let row = registry.resolve(p.name).expect("the registry has the row");
    let plugin = match row.door() {
        Some(door) => LinkedRow::of(door).and_then(|r| load_linked::<Auth>(&r, bind)),
        None => {
            let stated = row
                .manifest
                .stated_rendering()
                .expect("the signed Statement reads")
                .expect("a dropped-in auth plugin states its Statement");
            load_dropped_bytes::<Auth>(&row.lib_bytes, p.name, &stated, bind)
        }
    }
    .expect("the row's door loads");
    let before = crossings(&plugin);
    let (settings, secrets) = split_secrets(&plugin, settings);
    let text = settings.to_string();
    let instance = AuthInstance::open(
        plugin.clone(),
        sink,
        dispatcher.clone(),
        p.alias,
        text.as_bytes(),
        secrets,
    )
    .expect("the instance opens");
    let opened = crossings(&plugin) - before;
    (
        Opened {
            plugin,
            instance,
            dispatcher,
            envelope,
        },
        opened,
    )
}

// ── VERIFY ──────────────────────────────────────────────────────────────────────────────────────

/// The operator's token. The plugin is configured with its SHA-256 digest, never the token.
const TOKEN: &str = "the-operator-token";

/// The token cases, as the two field lines a request presents them on — the Bearer on the
/// `authorization` line, the other on the second credential line: the accepted token on either,
/// a wrong opaque token, a token in another scheme's grammar (a JWS compact serialization), none.
/// The line names are the plugin's own, read here as the request's data.
const CASES: [(Option<&str>, Option<&str>); 6] = [
    (Some(TOKEN), None),
    (None, Some(TOKEN)),
    (Some("not-the-token"), None),
    (None, Some("not-the-token")),
    (Some("aaa.bbb.ccc"), None),
    (None, None),
];

/// The two credential lines the cases are presented on.
const LINES: (&str, &str) = ("authorization", "x-admin-token");

/// One case at the `Head` point.
fn verify_request(bearer: Option<&str>, other: Option<&str>) -> VerifyRequest {
    let line = |name: &str, value: String| (name.to_string(), Redacted::new(value.into_bytes()));
    let lines = bearer
        .map(|b| line(LINES.0, format!("Bearer {b}")))
        .into_iter()
        .chain(other.map(|h| line(LINES.1, h.to_string())))
        .collect();
    VerifyRequest {
        point: AuthPoint::Head,
        lines,
        method: "GET".into(),
        authority: "node.example".into(),
        path: "/admin/v1/keys".into(),
        ..VerifyRequest::default()
    }
}

/// An answer as the transcript spells it: the verdict, the decision, the lines to strip.
fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    format!("{verdict} {:?} [{}]", a.decision, strips.join(", "))
}

/// THE VERIFY SCRIPT: open over the token's `digest`, every case on the spot and submitted, then
/// the cache refresh.
async fn verify_fold(registry: &PluginRegistry, digest: &str) -> Fold {
    let (o, opened) = open(registry, &VERIFY, &serde_json::json!(digest));
    let mut f = Fold::default();
    let i = &o.instance;
    f.step(
        format!("open name={} facts={}", i.name(), i.facts()),
        opened,
    );
    for (bearer, other) in CASES {
        let at = crossings(&o.plugin);
        let now = i
            .verify_now(&verify_request(bearer, other))
            .map_or_else(|| "not on the spot".to_string(), |a| spelled(&a));
        f.step(
            format!("verify_now {bearer:?} {other:?} -> {now}"),
            crossings(&o.plugin) - at,
        );
        let at = crossings(&o.plugin);
        let submitted = Box::into_pin(i.verify(verify_request(bearer, other))).await;
        f.step(
            format!("verify {bearer:?} {other:?} -> {}", spelled(&submitted)),
            crossings(&o.plugin) - at,
        );
    }
    let at = crossings(&o.plugin);
    let refreshed = i.refresh();
    f.step(format!("refresh {refreshed:?}"), crossings(&o.plugin) - at);
    f.envelope = o.envelope.take();
    f
}

/// The crossings the verify script makes: `validate` + `open`, then ONE per verify (no short
/// answer at the host's starting buffers), on the spot and submitted, then ONE `refresh`.
fn verify_crossings() -> Vec<u64> {
    std::iter::once(2)
        .chain(CASES.iter().flat_map(|_| [1, 1]))
        .chain(std::iter::once(1))
        .collect()
}

/// The verify fold reaches every verdict, so the equality it is compared under covers them all.
fn assert_every_verdict(f: &Fold) {
    assert!(
        f.has("Identity") && f.has("Reject") && f.has("Pass"),
        "the token cases must identify, reject and pass: {:#?}",
        f.transcript
    );
    assert!(
        !f.has("not on the spot") && !f.has("Failed") && !f.has("Overloaded"),
        "every case is answered, on the spot and submitted: {:#?}",
        f.transcript
    );
}

/// **VERIFY, BOTH WAYS.** The linked door and the dropped-in door register one row, answer every
/// token case alike on the spot and submitted, hand the host the same envelope, and cross the
/// plugin exactly as often; the kernel's auth axis finds the operator credential by its Statement
/// through either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_verify_operation_is_one_plugin_linked_and_dropped_in() {
    let Some([linked, dropped]) = registries(&VERIFY, door_fixture(VERIFY.row).1, false) else {
        eprintln!("skip: the verify row's cdylib is not built");
        return;
    };
    let rows = [row(&linked, VERIFY.name), row(&dropped, VERIFY.name)];
    assert!(!rows[0].starts_with("no row"), "{}", rows[0]);
    assert_eq!(rows[0], rows[1], "the two doors must register one row");
    let digest = sha256_hex(TOKEN.as_bytes());
    let l = verify_fold(&linked, &digest).await;
    let d = verify_fold(&dropped, &digest).await;
    assert_every_verdict(&l);
    assert_eq!(l.crossings, verify_crossings(), "{:#?}", l.transcript);
    if let Some(diff) = compared(&l, &d) {
        panic!("the two doors must verify as one plugin: {diff}");
    }
    for registry in [linked, dropped] {
        assert_eq!(
            AuthRows::new(Arc::new(registry), dispatcher()).operator(),
            Some((VERIFY.alias.to_string(), "admin".to_string())),
            "the axis finds the operator credential's row by its Statement"
        );
    }
    println!(
        "PROOF auth verify: linked and dropped in answered {} steps, {} crossings and {} envelope \
         entries identically",
        l.transcript.len(),
        l.crossings.iter().sum::<u64>(),
        l.envelope.len()
    );
}

// ── SIGN ────────────────────────────────────────────────────────────────────────────────────────

/// The bindings the sign script opens: `(style, credential, settings)` — the header styles with a
/// credential, one whose bytes cannot be a field value, a passthrough-only binding, the query style
/// under its default and its named parameter, and a style the plugin does not serve.
const STYLES: [(&str, &str, &str); 8] = [
    ("bearer", "sk-test-123", "{}"),
    ("api-key", "azure-key", "{}"),
    ("x-goog-api-key", "goog-key", "{}"),
    ("bearer", "sk\r\ninjected", "{}"),
    ("x-goog-api-key", "", "{}"),
    ("query-key", "gem-key", "{}"),
    ("query-key", "gem-key", r#"{"param":"api_key"}"#),
    ("kerberos", "k", "{}"),
];

/// A handle no binding answered.
const UNKNOWN: u64 = 999;

/// The request one `fields` call is made for: the operator's own credential, or the caller's.
fn sign_request(caller: Option<&str>) -> FieldsRequest {
    FieldsRequest {
        method: b"POST".to_vec(),
        authority: "runtime.signer.example".into(),
        path: b"/model/m/converse".to_vec(),
        timestamp: 1_440_938_160,
        caller_credential: caller.map(|c| Redacted::new(c.as_bytes().to_vec())),
        ..FieldsRequest::default()
    }
}

/// The fields as the transcript spells them: name, value and flag, in order.
fn spelled_fields(f: &Fields) -> String {
    match f {
        Fields::Ready(fields) => {
            let each: Vec<String> = fields
                .iter()
                .map(|a| {
                    format!(
                        "{}: {} sensitive={}",
                        String::from_utf8_lossy(&a.name),
                        String::from_utf8_lossy(a.value.expose_secret()),
                        a.sensitive
                    )
                })
                .collect();
            format!("Ready[{}]", each.join(" ; "))
        }
        other => format!("{other:?}"),
    }
}

/// THE SIGN SCRIPT: open, bind every style, then every binding's fields (and an unknown
/// handle's), in the operator's mode and the caller's, on the spot and submitted.
async fn sign_fold(registry: &PluginRegistry) -> Fold {
    let (o, opened) = open(registry, &SIGN, &serde_json::json!({}));
    let mut f = Fold::default();
    f.step(
        format!(
            "open name={} facts={}",
            o.instance.name(),
            o.instance.facts()
        ),
        opened,
    );
    let out = OutboundInstance::new(o.plugin.clone(), o.dispatcher.clone(), 0);
    let mut bound = Vec::new();
    for (n, (style, credential, settings)) in STYLES.into_iter().enumerate() {
        let settings: serde_json::Value = serde_json::from_str(settings).expect("JSON settings");
        let at = crossings(&o.plugin);
        let answered = out.open_outbound(style, credential.as_bytes(), &settings);
        let crossed = crossings(&o.plugin) - at;
        let spelled = match answered {
            Ok(handle) => {
                bound.push((format!("#{n} {style}"), handle));
                "Ok".to_string()
            }
            Err(e) => format!("Err({e})"),
        };
        f.step(format!("open_outbound #{n} {style} -> {spelled}"), crossed);
    }
    bound.push(("unknown".into(), UNKNOWN));
    for (binding, handle) in bound {
        for caller in [None, Some("caller-tok")] {
            let at = crossings(&o.plugin);
            let now = out
                .fields_now(handle, &sign_request(caller))
                .map_or_else(|| "not on the spot".to_string(), |a| spelled_fields(&a));
            f.step(
                format!("fields_now {binding} caller={caller:?} -> {now}"),
                crossings(&o.plugin) - at,
            );
            let at = crossings(&o.plugin);
            let deadline = now_ns() + Duration::from_secs(5).as_nanos() as u64;
            let submitted = Box::into_pin(out.fields(handle, sign_request(caller), deadline)).await;
            f.step(
                format!(
                    "fields {binding} caller={caller:?} -> {}",
                    spelled_fields(&submitted)
                ),
                crossings(&o.plugin) - at,
            );
        }
    }
    f.envelope = o.envelope.take();
    f
}

/// The crossings the sign script makes: `validate` + `open`, ONE per `open_outbound` (a refused
/// style crosses too), then ONE per `fields` (no short answer at the host's starting buffers), on
/// the spot and submitted, for every binding and the unknown handle, in both modes.
fn sign_crossings() -> Vec<u64> {
    // Every style but the unserved one is a binding, and the unknown handle is one more.
    let bindings = STYLES.len();
    std::iter::once(2)
        .chain(STYLES.iter().map(|_| 1))
        .chain(std::iter::repeat_n(1, bindings * 2 * 2))
        .collect()
}

/// The sign fold reaches every answer: a header field, a query field, the caller's credential
/// presented, an empty answer, a refusal, an unserved style, and the envelope's open-time line.
fn assert_every_answer(f: &Fold) {
    for needle in [
        "authorization: Bearer sk-test-123 sensitive=false",
        "key: gem-key sensitive=false",
        "api_key: gem-key",
        "Bearer caller-tok",
        "Ready[]",
        "-> Refused",
        "-> Err(",
    ] {
        assert!(
            f.has(needle),
            "the sign script never reached {needle:?}: {f:#?}"
        );
    }
    assert!(
        f.envelope.iter().any(|e| e.starts_with("diag")),
        "the un-encodable credential's diagnostic reaches the envelope: {:?}",
        f.envelope
    );
}

/// **SIGN, BOTH WAYS.** The linked door and the dropped-in door register one row, bind every style
/// and answer every binding's fields alike, hand the host the same envelope, and cross the plugin
/// exactly as often.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sign_operation_is_one_plugin_linked_and_dropped_in() {
    let Some([linked, dropped]) = registries(&SIGN, door_fixture(SIGN.row).1, false) else {
        eprintln!("skip: the sign row's example cdylib is not built");
        return;
    };
    let rows = [row(&linked, SIGN.name), row(&dropped, SIGN.name)];
    assert!(!rows[0].starts_with("no row"), "{}", rows[0]);
    assert_eq!(rows[0], rows[1], "the two doors must register one row");
    let l = sign_fold(&linked).await;
    let d = sign_fold(&dropped).await;
    assert_every_answer(&l);
    assert_eq!(l.crossings, sign_crossings(), "{:#?}", l.transcript);
    if let Some(diff) = compared(&l, &d) {
        panic!("the two doors must sign as one plugin: {diff}");
    }
    println!(
        "PROOF auth sign: linked and dropped in answered {} steps, {} crossings and {} envelope \
         entries identically",
        l.transcript.len(),
        l.crossings.iter().sum::<u64>(),
        l.envelope.len()
    );
}

// ── RED ARMS ────────────────────────────────────────────────────────────────────────────────────

/// The `row` fixture's door and its auth table.
fn real(row: &str) -> (&'static Door, abi::Ops) {
    let door = door_fixture(row).1;
    // SAFETY: a door function answers its `'static` door, whose `ops` is its kind's table; the
    // green arm loads the same door through the loader's validation.
    unsafe {
        let d = &*door();
        (d, *d.ops.cast::<abi::Ops>())
    }
}

/// `door` with `ops` as its table, leaked for the process: the address of a `'static` door.
fn leaked(door: &Door, ops: abi::Ops) -> usize {
    let ops: &'static abi::Ops = Box::leak(Box::new(ops));
    let door: &'static Door = Box::leak(Box::new(Door {
        ops: std::ptr::from_ref(ops).cast(),
        ..*door
    }));
    std::ptr::from_ref(door) as usize
}

/// The plugin's own `verify`, then a REJECT answered as PASS — a verdict the kind's checks admit.
extern "C" fn passing_verify(inst: *mut c_void, i: *const c_void, o: *mut c_void) -> RawOutcome {
    let verify = real(VERIFY.row)
        .1
        .verify
        .expect("the verify row serves verify");
    let r = verify(inst, i, o);
    // SAFETY: the host's live `IdentifyOut` for this call.
    let out = unsafe { &mut *o.cast::<IdentifyOut>() };
    if r.outcome() == Outcome::Ready && out.verdict == VERDICT_REJECT {
        out.verdict = VERDICT_PASS;
    }
    r
}

extern "C" fn divergent_verify_door() -> *const Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    *DOOR.get_or_init(|| {
        let (door, mut ops) = real(VERIFY.row);
        ops.verify = Some(passing_verify);
        leaked(door, ops)
    }) as *const Door
}

/// The plugin's own `fields`, then every field it wrote marked sensitive — other bytes on the wire.
extern "C" fn sensitive_fields(inst: *mut c_void, i: *const c_void, o: *mut c_void) -> RawOutcome {
    let fields = real(SIGN.row).1.fields.expect("the sign row serves fields");
    let r = fields(inst, i, o);
    // SAFETY: the host's live `FieldsIn`/`FieldsOut` for this call; a READY answer wrote
    // `fields_len` spans into the host's array of `fields_cap`.
    unsafe {
        let (i, o) = (&*i.cast::<FieldsIn>(), &*o.cast::<FieldsOut>());
        if r.outcome() == Outcome::Ready {
            for k in 0..o.fields_len.min(i.fields_cap) as usize {
                (*i.fields.add(k)).flags |= FIELD_SENSITIVE;
            }
        }
    }
    r
}

extern "C" fn divergent_sign_door() -> *const Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    *DOOR.get_or_init(|| {
        let (door, mut ops) = real(SIGN.row);
        ops.fields = Some(sensitive_fields);
        leaked(door, ops)
    }) as *const Door
}

/// **THE RED ARM OF THE VERIFY COMPARISON.** The divergent door, linked, loads and opens, and every
/// answer it gives passes the kind's checks — yet beside the real dropped-in plugin the comparison
/// fails, at the first case the plugin rejects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_divergent_verify_door_fails_the_comparison() {
    let Some([red, real]) = registries(&VERIFY, divergent_verify_door, false) else {
        eprintln!("skip: the verify row's cdylib is not built");
        return;
    };
    let digest = sha256_hex(TOKEN.as_bytes());
    let red = verify_fold(&red, &digest).await;
    let real = verify_fold(&real, &digest).await;
    assert_every_verdict(&real);
    assert!(
        !red.has("Reject") && !red.has("Failed"),
        "the divergent door answers every case, never REJECT: {:#?}",
        red.transcript
    );
    let diff = compared(&red, &real).expect(
        "a door answering PASS where the plugin answers REJECT must fail the comparison — this \
         difference is what `the_verify_operation_is_one_plugin_linked_and_dropped_in` refuses",
    );
    assert!(diff.contains("not-the-token"), "{diff}");
}

/// **THE RED ARM OF THE SIGN COMPARISON.** The divergent door, linked, binds and answers every
/// field the kind's checks admit — yet beside the real dropped-in plugin the comparison fails, at
/// the first field it marked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_divergent_sign_door_fails_the_comparison() {
    let Some([red, real]) = registries(&SIGN, divergent_sign_door, false) else {
        eprintln!("skip: the sign row's example cdylib is not built");
        return;
    };
    let red = sign_fold(&red).await;
    let real = sign_fold(&real).await;
    assert_every_answer(&real);
    assert!(
        red.has("sensitive=true") && !red.has("-> Failed"),
        "the divergent door's fields are admitted, marked: {:#?}",
        red.transcript
    );
    let diff = compared(&red, &real).expect(
        "a door marking its fields sensitive must fail the comparison — this difference is what \
         `the_sign_operation_is_one_plugin_linked_and_dropped_in` refuses",
    );
    assert!(diff.contains("sensitive=true"), "{diff}");
}

/// **THE RED ARM OF THE ROW COMPARISON.** The same image signed by a third party is a different
/// row from the linked first-party one, for either operation's plugin.
#[test]
fn a_third_party_signature_is_a_different_row() {
    for p in [&VERIFY, &SIGN] {
        let Some([linked, dropped]) = registries(p, door_fixture(p.row).1, true) else {
            eprintln!("skip: the {} row's image is not built", p.row);
            continue;
        };
        let dropped_row = row(&dropped, p.name);
        assert!(!dropped_row.starts_with("no row"), "{dropped_row}");
        assert_ne!(
            row(&linked, p.name),
            dropped_row,
            "a third-party row must not compare equal to the first-party one"
        );
    }
}
