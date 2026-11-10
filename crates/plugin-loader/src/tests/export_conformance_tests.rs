// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::abi::export::{ExportStream, Ops, CHECK_PHASE_INSTANCES, CHECK_PHASE_LIMITS};
use busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB;
use busbar_contract::abi::mechanism::call::{DIAG_LOG, DIAG_LOG_DROPPED};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::OpsHead;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::export_calls::{Delivered, ExportCalls};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

use super::*;
use crate::dispatch::kinds::export::Export;
use crate::dispatch::{
    load_dropped_bytes, load_linked, rendering_of, Bind, Diagnostic, DispatchConfig, Dispatcher,
    Dropped, EnvelopeSink, LinkedRow, Metric, Plugin,
};
use crate::export_axis::ExportRows;
use crate::export_door::ExportInstance;
use crate::sign::{Declares, Manifest};

#[path = "export_refresh_tests.rs"]
mod refresh_tests;

const WITNESS_DOOR: DoorFn = crate::neutral_export::door;
fn witness_cdylib() -> PathBuf {
    crate::neutral_export::cdylib()
}
fn witness_declares() -> Declares {
    Declares::from_declares_json(br#"{"diagnostics":[{"code":9901,"slug":"witness-crossing-refused","title":"Witness refusal","severity":"actionable","summary":"Synthetic crossing refusal","action":"Inspect the witness","since":"1.6.0"}]}"#).unwrap()
}
fn manifest(name: &str, declares: Declares) -> Manifest {
    let mut m = crate::both_ways::statement(
        "export",
        name,
        name,
        busbar_contract::abi::export::ABI_VERSION,
    );
    m.declares = declares;
    m
}
fn stating(mut m: Manifest, door: DoorFn) -> Manifest {
    m.statement = Some(hex::encode(
        rendering_of(door).expect("the witness renders"),
    ));
    m
}
fn cdylib_bytes(path: PathBuf) -> Vec<u8> {
    assert!(
        path.is_absolute() && path.is_file(),
        "the independent SDK image must exist"
    );
    std::fs::read(path).expect("read the SDK witness image")
}

fn both(m: Manifest, door: DoorFn, path: PathBuf) -> [PluginRegistry; 2] {
    let lib = cdylib_bytes(path);
    let m = stating(m, door);
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(m.clone(), door)])
        .expect("the SDK descriptor admits the sink");
    let release = crate::sign::SigningKey::from_bytes(&[11; 32]);
    let signer = if m.publisher == crate::sign::FIRST_PARTY_PUBLISHER {
        release.clone()
    } else {
        crate::sign::SigningKey::from_bytes(&[22; 32])
    };
    let publisher = (m.publisher.clone(), signer.verifying_key());
    let package = crate::sign::sign(&signer, m, &lib);
    let dir = scratch(&format!("package-{}", package.name));
    std::fs::write(
        dir.join("exporter.tar.gz"),
        crate::tarball::package(&package, "exporter", &lib).expect("package SDK image"),
    )
    .expect("write the SDK witness package");
    let policy = crate::sign::TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        first_party_keys: vec![crate::sign::FirstPartyKey::unnamed(release.verifying_key())],
        publishers: std::iter::once(publisher)
            .filter(|(_, key)| *key != release.verifying_key())
            .collect(),
        binary_version: package.version.clone(),
        ..Default::default()
    };
    let dropped =
        crate::scan_and_validate(&dir, &policy).expect("the signed witness package admits");
    std::fs::remove_dir_all(dir).expect("remove the staged package");
    [linked, dropped]
}

fn entry_text(id: u32, severity: u8, text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    match id {
        DIAG_LOG => format!("log {severity} {text}"),
        DIAG_LOG_DROPPED => format!("logs-dropped {text}"),
        id => format!("diag {id} {severity} {text}"),
    }
}

fn metric_text(family: u32, kind: u8, value: f64) -> String {
    format!("metric {family} {kind} {value}")
}

/// THE HOST'S ENVELOPE SINK, recorded: every entry the host ingested from one instance, in order.
#[derive(Default)]
struct Tape(Mutex<Vec<String>>);

impl Tape {
    fn push(&self, line: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }

    fn seen(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn count(&self, needle: &str) -> usize {
        self.seen().iter().filter(|l| l.contains(needle)).count()
    }
}

impl EnvelopeSink for Tape {
    fn metric(&self, m: Metric<'_>) {
        self.push(metric_text(m.family, m.kind, m.value));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.push(entry_text(d.id, d.severity, d.text));
    }
    fn dropped(&self, why: Dropped) {
        self.push(format!("dropped {why:?}"));
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        crate::dispatch::services::clock_for_tests(),
        busbar_contract::services::test_caller_binding(),
    ))
}

const REFUSED_TARGET: &str = "refused.example";

const UNREACHABLE_TARGET: &str = "unreachable.example";

const STALL_TARGET: &str = "stall.example";

type Verdict = (Result<(), ConnError>, String);
type OnForget = Arc<dyn Fn(InstanceId) + Send + Sync>;
type OnDeclare = Arc<dyn Fn(&str) + Send + Sync>;
type OnOpen = Arc<dyn Fn(&str) + Send + Sync>;

/// THE HOST'S CONNECTION TABLE, as this binary stands it: every need declared on it is recorded
/// (its egress class, its scheme, the target its `target_from` resolved to), a need whose target is
/// on [`REFUSED_TARGET`] is refused (the host's policy, before anything is sent), and every framed
/// request opened on it — the WHOLE request, head words, fields and body, as the host hands it to
/// the framer — is recorded and answered `204` with no body. A need whose `target_from` resolved to
/// nothing is refused, as the table's contract and the host's connector refuse it. A target on
/// [`UNREACHABLE_TARGET`] fails at the open. A reply from [`STALL_TARGET`] pends — interest kept
/// under the reading ticket, which the table wakes through the dispatcher's connection waker once
/// [`Far::release`]d — so a stalled request holds no thread. Ownership is the shared [`ConnSlab`].
#[derive(Default)]
struct Far {
    /// Explicit transport-double capability, never inferred from a URL.
    peer_cert: Option<busbar_contract::transport::CertFacts>,
    prepared: Mutex<HashMap<ConnId, (NeedId, String, bool)>>,
    slab: ConnSlab<()>,
    verdicts: Mutex<HashMap<(InstanceId, NeedId), Verdict>>,
    declared: Mutex<Vec<serde_json::Value>>,
    carried: Mutex<Vec<serde_json::Value>>,
    read: Mutex<HashMap<ConnId, u8>>,
    /// The connections whose reply is held, and the caller and ticket each read registered interest
    /// under.
    stalled: Mutex<HashMap<ConnId, (InstanceId, u64)>>,
    released: std::sync::atomic::AtomicBool,
    waker: OnceLock<busbar_contract::conn::ConnWake>,
    forgotten: Mutex<Vec<InstanceId>>,
    on_forget: Mutex<Option<OnForget>>,
    on_declare: Mutex<Option<OnDeclare>>,
    on_open: Mutex<Option<OnOpen>>,
    owners: Mutex<Vec<(InstanceId, String)>>,
}

impl Far {
    /// A modeled established peer for credential-lifetime tests, not a TLS handshake.
    fn with_modeled_secure_transport() -> Self {
        Self {
            peer_cert: Some(busbar_contract::transport::CertFacts {
                subject: "export conformance peer".into(),
                issuer: "export conformance fixture".into(),
                fingerprint: "fixture-peer-certificate".into(),
            }),
            ..Self::default()
        }
    }

    fn target(&self, caller: InstanceId, need: NeedId, desc: &OpenDesc<'_>) -> String {
        let declared = self
            .verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(caller, need))
            .map(|(_, t)| t.clone())
            .unwrap_or_default();
        if desc.target.is_empty() {
            declared
        } else {
            desc.target.to_string()
        }
    }

    fn carry(&self, caller: InstanceId, id: ConnId, target: &str, desc: &OpenDesc<'_>) {
        if target.contains(STALL_TARGET) && !self.released.load(std::sync::atomic::Ordering::SeqCst)
        {
            self.stalled
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, (caller, 0));
        }
        let fields: Vec<(String, String)> = desc
            .fields
            .iter()
            .map(|(n, v)| ((*n).to_string(), String::from_utf8_lossy(v).into_owned()))
            .collect();
        self.carried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(serde_json::json!({
                "target": target,
                "method": String::from_utf8_lossy(desc.method),
                "head_target": String::from_utf8_lossy(desc.head_target),
                "fields": fields,
                // Text as text; any other body (opaque non-text bytes) as hex.
                "body": std::str::from_utf8(&desc.body)
                    .map_or_else(|_| hex::encode(&desc.body), str::to_owned),
            }));
    }

    fn carried(&self) -> Vec<serde_json::Value> {
        self.carried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    fn declarations(&self) -> Vec<serde_json::Value> {
        self.declared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn stalled(&self) -> usize {
        self.stalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let held: Vec<(InstanceId, u64)> = self
            .stalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, t)| t)
            .collect();
        if let Some(wake) = self.waker.get() {
            held.into_iter().for_each(|(owner, t)| wake(owner, t));
        }
    }
}

impl DeclaredConns for Far {
    fn prepare_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        _: u64,
    ) -> Result<ConnId, ConnError> {
        if !desc.fields.is_empty() || !desc.body.is_empty() {
            return Err(ConnError::Refused);
        }
        let target = self.target(caller, need, desc);
        if target.contains(UNREACHABLE_TARGET) {
            return Err(ConnError::Timeout);
        }
        let conn = self.slab.insert(caller, need, ())?;
        self.prepared
            .lock()
            .unwrap()
            .insert(conn, (need, target, false));
        Ok(conn)
    }

    fn commit_request(
        &self,
        caller: InstanceId,
        conn: ConnId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), ConnError> {
        self.slab.get(caller, conn)?;
        let target = {
            let mut all = self.prepared.lock().unwrap();
            let (need, target, committed) = all.get_mut(&conn).ok_or(ConnError::Closed)?;
            if *committed || self.target(caller, *need, desc) != *target {
                return Err(ConnError::Refused);
            }
            if require_secure && self.peer_cert.is_none() {
                return Err(ConnError::AuthRefused);
            }
            *committed = true;
            target.clone()
        };
        let callback = self.on_open.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(&target);
        }
        self.carry(caller, conn, &target, desc);
        Ok(())
    }

    fn forget(&self, owner: InstanceId) {
        self.forgotten.lock().unwrap().push(owner);
        for conn in self.slab.forget(owner) {
            self.prepared.lock().unwrap().remove(&conn);
            self.stalled.lock().unwrap().remove(&conn);
            self.read.lock().unwrap().remove(&conn);
        }
        self.verdicts
            .lock()
            .unwrap()
            .retain(|(o, _), _| *o != owner);
        let callback = self.on_forget.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(owner);
        }
    }
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(serde_json::json!({
                "egress_class": spec.egress_class,
                "transport": spec.transport,
                "target_from": spec.target_from,
                "target": target,
            }));

        let unresolved = !spec.target_from.is_empty() && target.is_none();
        let target = target.unwrap_or_default().to_string();
        self.owners.lock().unwrap().push((owner, target.clone()));
        let callback = self.on_declare.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(&target);
        }
        let verdict = if unresolved || target.contains(REFUSED_TARGET) {
            Err(ConnError::Refused)
        } else {
            self.slab.declare(owner, need);
            Ok(())
        };
        self.verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((owner, need), (verdict, target));
        verdict
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(owner, need))
            .map(|(v, _)| *v)
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        DeclaredConns::declared(self, owner, need).is_some()
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == busbar_contract::http::uri::Scheme::HTTP.as_str()
    }
}

impl Conns for Far {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let target = self.target(caller, need, desc);
        let callback = self.on_open.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(&target);
        }
        if target.contains(UNREACHABLE_TARGET) {
            return Err(ConnError::Timeout);
        }
        let id = self.slab.insert(caller, need, ())?;
        self.carry(caller, id, &target, desc);
        Ok(id)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: u64,
        _: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.slab.get(caller, conn)?;
        if self
            .prepared
            .lock()
            .unwrap()
            .get(&conn)
            .is_some_and(|(_, _, committed)| !committed)
        {
            return Err(ConnError::Refused);
        }
        {
            let mut stalled = self.stalled.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(waiting) = stalled.get_mut(&conn) {
                *waiting = (caller, ticket);
                return Err(ConnError::Pending);
            }
        }
        let mut read = self.read.lock().unwrap_or_else(PoisonError::into_inner);
        let n = read.entry(conn).or_default();
        *n += 1;
        let (kind, status_code) = match *n {
            1 => (PieceKind::Fields, Some(204)),
            2 => (PieceKind::Completion, None),
            _ => return Err(ConnError::Closed),
        };
        Ok(Piece {
            kind,
            stream: StreamId(0),
            len: 0,
            end: true,
            status: status_code.map(|_| busbar_contract::transport::wire::WireStatusClass::Success),
            status_code,
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Ok(0)
    }
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        if !self.prepared.lock().unwrap().contains_key(&conn) {
            return Err(ConnError::Closed);
        }
        Ok(ConnFacts {
            peer_cert: self.peer_cert.clone(),
            ..ConnFacts::default()
        })
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.slab.get(caller, conn)?;
        self.prepared.lock().unwrap().remove(&conn);
        self.stalled.lock().unwrap().remove(&conn);
        self.read.lock().unwrap().remove(&conn);
        self.slab.remove(caller, conn).map(|_| ())
    }
}

struct OlderDoor(Door, Ops);
// SAFETY: built once from the linked door's `'static` data and never written after; every pointer
// names that data or the box itself.
unsafe impl Send for OlderDoor {}
// SAFETY: as above.
unsafe impl Sync for OlderDoor {}

fn older(cell: &'static OnceLock<Box<OlderDoor>>, strip: fn(&mut Ops)) -> *const Door {
    &cell
        .get_or_init(|| {
            let door = *WITNESS_DOOR();
            // SAFETY: the linked door's table is the export kind's, `'static`.
            let mut ops = unsafe { *door.ops().cast::<Ops>() };
            strip(&mut ops);
            let mut older = Box::new(OlderDoor(door, ops));
            let parts = DoorParts {
                ops: std::ptr::from_ref(&older.1).cast::<OpsHead>(),
                ..older.0.parts()
            };
            // SAFETY: the linked door's own `'static` Statement over the boxed table, built once
            // and held for the process.
            older.0 = unsafe { Door::__from_parts(parts) };
            older
        })
        .0
}

static NO_VALIDATE: OnceLock<Box<OlderDoor>> = OnceLock::new();
static NO_CHECK: OnceLock<Box<OlderDoor>> = OnceLock::new();

extern "C" fn door_without_validate() -> *const Door {
    older(&NO_VALIDATE, |ops| ops.head.validate = None)
}

extern "C" fn door_without_check() -> *const Door {
    older(&NO_CHECK, |ops| ops.check = None)
}

fn refused_at_load(door: busbar_contract::abi::sdk::door::RawDoorFn) -> String {
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    match LinkedRow::of_raw(door)
        .and_then(|row| load_linked::<Export>(&row, bind("older", tape, &d)))
    {
        Ok(_) => panic!("a door that predates an op was bound"),
        Err(e) => e.to_string(),
    }
}

fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn deliver(sink: &dyn ExportCalls, line: &serde_json::Value) {
    let queued = sink.deliver(
        ExportStream::Logs as u8,
        line.to_string().into_bytes(),
        Box::new(()),
    );
    assert!(matches!(queued, Delivered::Queued), "{queued:?}");
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-11-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn bind(label: &str, sink: Arc<Tape>, d: &Dispatcher) -> Bind {
    Bind {
        instance: {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{label}-{}",
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
            .into()
        },
        max_inflight_cap: 64,
        sink,
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::Probe,
    }
}

#[test]
fn the_witness_streams_are_read_from_its_statement() {
    let bytes = cdylib_bytes(witness_cdylib());
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let stated = rendering_of(WITNESS_DOOR).expect("the door renders its Statement");
    let plugin = load_dropped_bytes::<Export>(
        &bytes,
        "#11-dropped-in",
        &stated,
        bind("#11-dropped-in", tape.clone(), &d),
    )
    .expect("the dropped-in door loads");
    assert_eq!(
        plugin
            .context::<crate::dispatch::kinds::export::ExportFacts>()
            .map(|f| f.streams.clone()),
        Some(crate::neutral_export::STREAMS.to_vec())
    );
    drop(plugin);
}

#[test]
fn a_sink_validates_its_settings_the_same_through_either_door() {
    let name = "s2-sink";
    let doors = both(
        manifest(name, witness_declares()),
        WITNESS_DOOR,
        witness_cdylib(),
    );
    let refused = serde_json::json!({ "value": 7 });
    let accepted = serde_json::json!({ "value": "opaque witness value" });
    let [linked, dropped] = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher()).with_disk(crate::dispatch::test_disk_authority());
        let transcript = serde_json::json!({
            "accepted": rows.probe(name, "tail", &crate::dispatch::test_settings(&accepted)),
            "refused": rows.probe(name, "tail", &crate::dispatch::test_settings(&refused)),
            "not_export": rows.probe("no-such-module", "tail", &crate::dispatch::test_settings(&refused)),
        })
        .to_string();
        ({ let row = registry.resolve(name).expect("the SDK witness row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() }, transcript)
    });
    let line = "export.tail.settings: witness refused";
    let streams = crate::neutral_export::STREAMS;
    assert_eq!(
        linked.1,
        serde_json::json!({
            "accepted": [streams, [], null],
            "refused": [streams, [line], null],
            "not_export": null,
        })
        .to_string()
    );
    assert_eq!(linked, dropped, "both doors validate the same");

    assert_eq!(
        refused_at_load(door_without_validate),
        format!(
            "ops slot {} is NULL",
            busbar_contract::abi::mechanism::lifecycle::slot::VALIDATE
        )
    );
}

#[test]
fn a_declared_diagnostic_is_stated_and_raised_the_same_through_either_door() {
    let decl = witness_declares();
    assert!(decl.diagnostics.iter().any(|d| d.code == 9901), "{decl:?}");
    let name = "s3-fixture";
    let doors = both(manifest(name, decl.clone()), WITNESS_DOOR, witness_cdylib());
    let cfg = serde_json::json!({ "target": format!("https://{UNREACHABLE_TARGET}/in") });
    let [linked, dropped] = doors.map(|registry| {
        let tape = Arc::new(Tape::default());
        let far = Arc::new(Far::default());
        let rows = ExportRows::new(&registry, dispatcher()).with_disk(crate::dispatch::test_disk_authority())
            .with_envelope(tape.clone())
            .with_conns(crate::dispatch::test_admissions(far.clone()));
        let first_party = rows.first_party(name);
        let sink = rows.open(name, "export.s3", &crate::export_axis::test_opening(&cfg)).expect("opens");
        deliver(sink.as_ref(), &serde_json::json!({ "n": 1 }));
        until("the transport-error diagnostic", || {
            tape.count("BUSBAR-9901") == 1
        });
        drop(sink);
        let transcript = serde_json::json!({
            "first_party": first_party,
            "raised": tape.seen(),
            "carried": far.carried(),
        })
        .to_string();
        ({ let row = registry.resolve(name).expect("the SDK witness row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() }, transcript)
    });
    assert!(
        linked.0.contains("witness-crossing-refused"),
        "{}",
        linked.0
    );
    assert!(
        linked.1.contains(r#""first_party":true"#)
            && linked.1.contains("BUSBAR-9901")
            && linked.1.contains(r#""carried":[]"#),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors state and raise the same");

    let mut third = stating(manifest("s3-third-party", decl.clone()), WITNESS_DOOR);
    third.publisher = "acme".into();
    let [_, registry] = both(third, WITNESS_DOOR, witness_cdylib());
    let row = registry.resolve("s3-third-party").expect("admitted");
    assert_eq!(row.manifest.declares.diagnostics, decl.diagnostics);
    assert!(!row.first_party());
}

#[test]
fn a_sinks_outbound_request_is_carried_by_the_host_the_same_through_either_door() {
    let name = "s5-fixture";
    let m = manifest(name, witness_declares());
    let run = |registry: &PluginRegistry, url: &str, refused: bool| {
        let tape = Arc::new(Tape::default());
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(registry, dispatcher())
            .with_disk(crate::dispatch::test_disk_authority())
            .with_envelope(tape.clone())
            .with_conns(crate::dispatch::test_admissions(far.clone()))
            .open(
                name,
                "export.s5",
                &crate::export_axis::test_opening(&serde_json::json!({ "target": url })),
            )
            .expect("opens");
        for n in 1..=2 {
            deliver(sink.as_ref(), &serde_json::json!({ "n": n }));
        }
        if refused {
            until("the disabled line", || tape.count("BUSBAR-9901") == 2);
        } else {
            until("both requests carried", || far.carried().len() == 2);
        }
        drop(sink);
        serde_json::json!({
            "declared": far.declarations(),
            "carried": far.carried(),
            "folds": tape.seen(),
        })
        .to_string()
    };
    let doors = both(m.clone(), WITNESS_DOOR, witness_cdylib());
    let [linked, dropped] = doors.map(|registry| {
        (
            { let row = registry.resolve(name).expect("the SDK witness row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() },
            run(&registry, "https://collector.example/v1", false),
        )
    });
    assert!(
        linked
            .1
            .contains(&format!(r#""egress_class":{EGRESS_OPEN_WEB}"#))
            && linked.1.contains(r#""transport":"http""#)
            && linked.1.contains(r#""method":"POST""#)
            && linked.1.contains(r#""head_target":"/v1""#)
            && linked.1.contains(r#""body":"{\"n\":2}""#)
            && linked.1.contains(r#""folds":[]"#),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors are carried the same");

    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(m, WITNESS_DOOR),
            WITNESS_DOOR,
        )])
        .expect("the linked door admits the sink");
    let refused = run(&registry, &format!("https://{REFUSED_TARGET}/v1"), true);
    assert!(refused.contains(r#""carried":[]"#), "{refused}");
    assert!(refused.contains("BUSBAR-9901"), "{refused}");
}

#[test]
fn a_sink_starts_and_checks_the_same_through_either_door() {
    let files = both(
        manifest("k9c-sink", witness_declares()),
        WITNESS_DOOR,
        witness_cdylib(),
    );
    let hooks = both(
        manifest("k9c-hook", witness_declares()),
        WITNESS_DOOR,
        witness_cdylib(),
    );
    let file_settings = serde_json::json!({ "value": "opaque" });
    let file_settings = crate::dispatch::test_settings(&file_settings);
    let file_instances = [("tail".to_string(), &file_settings)];
    let hook_settings = serde_json::json!({
        "target": "https://collector.example/in",
        "max_inflight_deliveries": 0,
        "case": "check",
    });
    let hook_settings = crate::dispatch::test_settings(&hook_settings);
    let hook_instances = [("audit".to_string(), &hook_settings)];
    let transcripts: Vec<String> = files
        .iter()
        .zip(hooks.iter())
        .map(|(file, hook)| {
            let f = ExportRows::new(file, dispatcher())
                .with_disk(crate::dispatch::test_disk_authority());
            let h = ExportRows::new(hook, dispatcher())
                .with_disk(crate::dispatch::test_disk_authority())
                .with_conns(crate::dispatch::test_admissions(Arc::new(Far::default())));
            format!(
                "{:?} {:?} {:?} {:?} {:?}",
                f.check("k9c-sink", CHECK_PHASE_INSTANCES, &file_instances),
                f.check("k9c-sink", CHECK_PHASE_LIMITS, &file_instances),
                h.check("k9c-hook", CHECK_PHASE_LIMITS, &hook_instances),
                h.check("k9c-hook", CHECK_PHASE_INSTANCES, &hook_instances),
                f.check("no-such-module", CHECK_PHASE_LIMITS, &file_instances),
            )
        })
        .collect();
    let t = &transcripts[0];
    assert!(
        t.starts_with("Some([]) Some([]) Some([\"export.audit: witness check phase"),
        "{t}"
    );
    assert!(
        t.contains("witness check phase 1") && t.ends_with(" None"),
        "{t}"
    );
    assert_eq!(transcripts[0], transcripts[1], "both doors check the same");

    assert_eq!(
        refused_at_load(door_without_check),
        format!(
            "ops slot {} is NULL",
            busbar_contract::abi::export::slot::CHECK
        )
    );
}

#[test]
fn a_declared_need_is_bound_the_same_through_either_door() {
    use crate::EgressPolicy;

    let collector = Declares {
        egress: EgressPolicy::Collector,
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&collector).expect("encode"),
        serde_json::json!({"egress": "collector"})
    );
    assert!(!collector.is_empty() && Declares::default().is_empty());
    assert_eq!(
        serde_json::to_value(Declares::default()).expect("encode"),
        serde_json::json!({})
    );

    let name = "k9e2-hook";
    let doors = both(
        manifest(name, witness_declares()),
        WITNESS_DOOR,
        witness_cdylib(),
    );
    let [linked, dropped] = doors.map(|registry| {
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_disk(crate::dispatch::test_disk_authority())
            .with_conns(crate::dispatch::test_admissions(far.clone()))
            .open(
                name,
                "export.k9e2",
                &crate::export_axis::test_opening(
                    &serde_json::json!({ "target": "https://collector.example/in" }),
                ),
            )
            .expect("opens");
        drop(sink);
        let needs: Vec<serde_json::Value> = far
            .declarations()
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "egress_class": d["egress_class"],
                    "transport": d["transport"],
                    "target": d["target"],
                })
            })
            .collect();
        serde_json::to_string(&needs).expect("encode")
    });
    assert_eq!(
        linked,
        serde_json::json!([{
            "egress_class": EGRESS_OPEN_WEB,
            "transport": "http",
            "target": "https://collector.example/in",
        }])
        .to_string(),
        "the need is declared under the open web, framed by `http`, pinned to the `url` setting"
    );
    assert_eq!(linked, dropped, "both doors declare the same need");
}

struct Released(Arc<Far>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn a_sinks_deliveries_in_flight_reach_its_admission_bound_past_the_blocking_pool() {
    const BOUND: usize = 600;
    let name = "k9c-bound";
    let doors = both(
        manifest(name, witness_declares()),
        WITNESS_DOOR,
        witness_cdylib(),
    );
    let settings = serde_json::json!({
        "target": format!("https://{STALL_TARGET}/in"),
        "max_inflight_deliveries": BOUND,
        "delivery_timeout_secs": 600,
    });
    let [linked, dropped] = doors.map(|registry| {
        let d = dispatcher();
        assert_eq!(
            d.workers(),
            1,
            "one worker: far fewer threads than deliveries"
        );
        let far = Arc::new(Far::default());
        assert!(far.waker.set(d.conn_waker()).is_ok());
        let sink = ExportRows::new(&registry, d)
            .with_disk(crate::dispatch::test_disk_authority())
            .with_conns(crate::dispatch::test_admissions(far.clone()))
            .open(
                name,
                "export.k9c",
                &crate::export_axis::test_opening(&settings),
            )
            .expect("opens");

        let _answer = Released(far.clone());
        for n in 0..=BOUND {
            deliver(sink.as_ref(), &serde_json::json!({ "n": n }));
        }
        until("every admitted delivery in flight", || {
            far.stalled() == BOUND
        });

        std::thread::sleep(Duration::from_millis(300));
        let in_flight = far.stalled();
        let carried_while_held = far.carried().len();
        far.release();
        until("every line carried", || far.carried().len() == BOUND + 1);
        drop(sink);
        let mut ns: Vec<u64> = far
            .carried()
            .iter()
            .map(|r| {
                serde_json::from_str::<serde_json::Value>(r["body"].as_str().expect("a body"))
                    .expect("a JSON line")["n"]
                    .as_u64()
                    .expect("n")
            })
            .collect();
        ns.sort_unstable();
        (in_flight, carried_while_held, ns)
    });
    assert_eq!(
        linked.0, BOUND,
        "every admitted delivery is in flight at once"
    );
    assert_eq!(
        linked.1, BOUND,
        "the delivery past the bound waits; it is not carried while the bound is full"
    );
    assert_eq!(
        linked.2,
        (0..=BOUND as u64).collect::<Vec<_>>(),
        "nothing is lost: the line past the bound is carried once a delivery answers"
    );
    assert_eq!(linked, dropped, "both doors are bounded the same");
}

#[test]
fn dropping_an_instance_whose_delivery_never_wakes_returns() {
    let name = "bn2-stuck";
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(manifest(name, witness_declares()), WITNESS_DOOR),
            WITNESS_DOOR,
        )])
        .expect("the linked door admits the sink");

    let far = Arc::new(Far::default());
    let sink = ExportRows::new(&registry, dispatcher())
        .with_disk(crate::dispatch::test_disk_authority())
        .with_conns(crate::dispatch::test_admissions(far.clone()))
        .open(
            name,
            "export.bn2",
            &crate::export_axis::test_opening(&serde_json::json!({
                "target": format!("https://{STALL_TARGET}/in"),
                "delivery_timeout_secs": 600,
            })),
        )
        .expect("opens");
    deliver(sink.as_ref(), &serde_json::json!({ "n": 0 }));
    until("the delivery in flight", || far.stalled() == 1);
    let (dropped, returned) = std::sync::mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(sink);
        let _ = dropped.send(());
    });
    let returned = returned.recv_timeout(Duration::from_secs(5));
    if returned.is_err() {
        std::mem::forget(dropper);
    }
    assert!(
        returned.is_ok(),
        "dropping the instance returns within a bounded time while its delivery never wakes"
    );
}

#[test]
fn a_declared_target_is_bound_for_first_and_third_party_publishers() {
    let collector: DoorFn = WITNESS_DOOR;
    let settings = serde_json::json!({ "target": "http://127.0.0.1:4318/v1/traces" });
    let doors = both(
        manifest("k9e2-witness", Declares::default()),
        collector,
        witness_cdylib(),
    );
    let opened = doors.map(|registry| {
        assert!(registry
            .resolve("k9e2-witness")
            .is_some_and(|r| r.first_party()));
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_disk(crate::dispatch::test_disk_authority())
            .with_conns(crate::dispatch::test_admissions(far.clone()))
            .open(
                "k9e2-witness",
                "export.trace",
                &crate::export_axis::test_opening(&settings),
            )
            .expect("a first-party collector opens");
        drop(sink);
        serde_json::to_string(&far.declarations()).expect("encode")
    });
    assert!(
        opened[0].contains(&format!(
            r#""egress_class":{}"#,
            busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB
        )),
        "{}",
        opened[0]
    );
    assert_eq!(opened[0], opened[1], "both doors declare the same need");

    let mut third = stating(
        manifest("k9e2-third-witness", Declares::default()),
        collector,
    );
    third.publisher = "acme".into();
    let [_, registry] = both(third, WITNESS_DOOR, witness_cdylib());
    let row = registry.resolve("k9e2-third-witness").expect("admitted");
    assert!(!row.first_party());
    ExportRows::new(&registry, dispatcher())
        .with_disk(crate::dispatch::test_disk_authority())
        .with_conns(crate::dispatch::test_admissions(Arc::new(Far::default())))
        .open(
            "k9e2-third-witness",
            "export.trace",
            &crate::export_axis::test_opening(&settings),
        )
        .expect("an operator-trusted collector opens");

    let mut third = stating(
        manifest("k9e2-third-hook", witness_declares()),
        WITNESS_DOOR,
    );
    third.publisher = "acme".into();
    let [_, registry] = both(third, WITNESS_DOOR, witness_cdylib());
    let row = registry.resolve("k9e2-third-hook").expect("admitted");
    assert!(!row.first_party());
}

#[test]
fn an_opened_sinks_envelope_reaches_the_host_observability() {
    use crate::dispatch::EnvelopeSink as _;
    let guard = crate::observe::testing::exclusive();
    let stated = rendering_of(WITNESS_DOOR).expect("renders");

    let sink = crate::observe::EnvelopeObserver::of(
        crate::observe::testing::observing(),
        "export-sink",
        busbar_contract::abi::mechanism::kind::EXPORT,
        &stated,
    );

    let counted = crate::observe::EnvelopeObserver::with_families(
        crate::observe::testing::observing(),
        "export-sink",
        busbar_contract::abi::mechanism::kind::EXPORT,
        vec![busbar_contract::abi::mechanism::rendering::ReadFamily {
            name: "witness_crossings_total".into(),
            help: String::new(),
            unit: String::new(),
            label_keys: vec!["path".into()],
            kind: busbar_contract::abi::mechanism::door::FAMILY_COUNTER,
        }],
    );
    counted.metric(Metric {
        family: 0,
        kind: busbar_contract::abi::mechanism::call::METRIC_ADD,
        value: 1.0,
        labels: &[b"opaque-label"],
    });

    counted.metric(Metric {
        family: 7,
        kind: busbar_contract::abi::mechanism::call::METRIC_ADD,
        value: 1.0,
        labels: &[],
    });
    let folds = crate::observe::testing::folds();
    assert_eq!(folds.len(), 1, "{folds:?}");
    assert_eq!(
        folds[0].2,
        vec![serde_json::json!({
            "name": "witness_crossings_total",
            "type": "counter",
            "value": 1.0,
            "labels": { "path": "opaque-label" },
        })]
    );
    crate::observe::testing::clear(&guard);
    sink.diag(Diagnostic {
        id: 0,
        name: b"BUSBAR-9901",
        severity: 1,
        text: b"witness crossing refused",
    });
    sink.diag(Diagnostic {
        id: DIAG_LOG,
        name: b"",
        severity: 0,
        text: b"sink: a log record",
    });
    let folds = crate::observe::testing::folds();
    assert_eq!(
        folds.len(),
        1,
        "one observation; the log record is not one: {folds:?}"
    );
    let (plugin, kind, metrics, diagnostics) = &folds[0];
    assert_eq!((plugin.as_str(), kind.as_str()), ("export-sink", "export"));
    assert!(metrics.is_empty());
    assert_eq!(diagnostics[0]["code"], "BUSBAR-9901");
    assert_eq!(diagnostics[0]["level"], "warn");

    crate::observe::testing::clear(&guard);
    let dir = scratch("envelope");
    let logs = crate::dispatch::PluginLogConfig::from_words(
        Some(&dir.display().to_string()),
        None,
        &std::collections::BTreeMap::new(),
        None,
        None,
    )
    .expect("a plugins.logs block");

    let log_sink = Arc::new(
        logs.sink(
            "export.tail",
            busbar_contract::abi::mechanism::KindCode::Export,
            Arc::new(crate::dispatch::NoSink),
        )
        .expect("a log sink"),
    );
    let behind = crate::observe::EnvelopeObserver::before(
        crate::observe::testing::observing(),
        log_sink.clone(),
        "export-sink",
        busbar_contract::abi::mechanism::kind::EXPORT,
        Vec::new(),
    );
    behind.diag(Diagnostic {
        id: 0,
        name: b"BUSBAR-9901",
        severity: 1,
        text: b"witness crossing refused",
    });
    let folds = crate::observe::testing::folds();
    log_sink.flush();
    let logged: String = std::fs::read_dir(&dir)
        .expect("the log dir")
        .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        logged.contains("BUSBAR-9901: witness crossing refused"),
        "the plugin log has the line: {logged:?}"
    );
    assert_eq!(folds.len(), 1, "{folds:?}");
    assert_eq!(folds[0].3[0]["code"], "BUSBAR-9901");
}

#[test]
fn opaque_trace_bytes_cross_the_same_through_either_door() {
    let collector: DoorFn = WITNESS_DOOR;
    let name = "s7-witness";
    let doors = both(
        manifest(name, Declares::default()),
        collector,
        witness_cdylib(),
    );
    let span = serde_json::json!({"opaque":"trace-crossing-witness"});
    let [linked, dropped] = doors.map(|registry| {
        let tape = Arc::new(Tape::default());
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_disk(crate::dispatch::test_disk_authority())
            .with_envelope(tape.clone())
            .with_conns(crate::dispatch::test_admissions(far.clone()))
            .open(
                name,
                "export.trace",
                &crate::export_axis::test_opening(
                    &serde_json::json!({ "target": "http://127.0.0.1:4318/v1/traces" }),
                ),
            )
            .expect("a first-party collector opens");
        let queued = sink.deliver(
            ExportStream::Traces as u8,
            span.to_string().into_bytes(),
            Box::new(()),
        );
        assert!(matches!(queued, Delivered::Queued), "{queued:?}");
        until("the span carried", || far.carried().len() == 1);
        drop(sink);
        serde_json::json!({ "carried": far.carried(), "folds": tape.seen() }).to_string()
    });
    assert!(
        linked.contains(r#""method":"POST""#)
            && linked.contains(r#""head_target":"/v1/traces""#)
            && linked.contains("trace-crossing-witness"),
        "{linked}"
    );
    assert_eq!(linked, dropped, "both doors carry the same request");
}

#[test]
fn modeled_secure_transport_commits_only_its_prepared_connection_once() {
    let caller = InstanceId(9001);
    let other = InstanceId(9002);
    let need = NeedId(0);
    let target = "https://fixture.example/in";
    let preparing = OpenDesc {
        target,
        ..OpenDesc::default()
    };
    let fields = [("authorization", b"fixture-credential".as_slice())];
    let sending = OpenDesc {
        target,
        fields: &fields,
        ..OpenDesc::default()
    };
    for secure in [false, true] {
        let far = if secure {
            Far::with_modeled_secure_transport()
        } else {
            Far::default()
        };
        far.slab.declare(caller, need);
        let conn = far.prepare_request(caller, need, &preparing, 0).unwrap();
        assert!(
            far.carried().is_empty(),
            "preparation carries no credentials"
        );
        assert_eq!(far.facts(caller, conn).unwrap().peer_cert.is_some(), secure);
        assert!(far.facts(other, conn).is_err());
        assert!(far.commit_request(other, conn, &sending, true).is_err());
        assert!(far.carried().is_empty());
        if secure {
            let changed = OpenDesc {
                target: "https://other.example/in",
                ..sending.clone()
            };
            assert!(far.commit_request(caller, conn, &changed, true).is_err());
            assert!(far.carried().is_empty());
            far.commit_request(caller, conn, &sending, true).unwrap();
            assert_eq!(far.carried().len(), 1);
            assert!(
                far.slab.get(caller, conn).is_ok(),
                "commit keeps the prepared connection"
            );
            assert!(far.commit_request(caller, conn, &sending, true).is_err());
            assert_eq!(far.carried().len(), 1);
        } else {
            assert_eq!(
                far.commit_request(caller, conn, &sending, true),
                Err(ConnError::AuthRefused)
            );
            assert!(
                far.carried().is_empty(),
                "HTTPS alone grants no fixture security"
            );
        }
        Conns::close(&far, caller, conn).unwrap();
        assert!(far.facts(caller, conn).is_err());
    }
}
