// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::abi::export::{ExportStream, Ops, CHECK_PHASE_INSTANCES, CHECK_PHASE_LIMITS};
use busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB;
use busbar_contract::abi::host::service::{
    DISK_APPEND_FAILED, DISK_OPEN_FAILED, DISK_RENAME_FAILED, DISK_RETENTION_FAILED,
    DISK_SHIFT_FAILED,
};
use busbar_contract::abi::mechanism::call::{
    Diag, MetricEntry, OutHead, RawOutcome, DIAG_LOG, DIAG_LOG_DROPPED,
};
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
use busbar_contract::services::{DiskDest, DiskReport, DiskRotate, Later, Ran};
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

const FILE_DOOR: DoorFn = file_door;
const WEBHOOK_DOOR: DoorFn = webhook_door;
const TRACE_DOOR: DoorFn = trace_door;

fn file_cdylib() -> &'static str {
    "BUSBAR_TEST_EXPORT_FILE_CDYLIB"
}
fn webhook_cdylib() -> &'static str {
    "BUSBAR_TEST_EXPORT_WEBHOOK_CDYLIB"
}
fn trace_cdylib() -> &'static str {
    "BUSBAR_TEST_EXPORT_OTLP_CDYLIB"
}

fn required_file(variable: &str) -> PathBuf {
    let path = std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{variable} must name the fresh actual product input"));
    assert!(
        path.is_absolute() && path.is_file(),
        "{variable} must be an absolute file: {}",
        path.display()
    );
    path
}

fn actual_door(
    variable: &str,
    image: &'static OnceLock<(
        libloading::Library,
        busbar_contract::abi::sdk::door::RawDoorFn,
    )>,
) -> &'static Door {
    let image = image.get_or_init(|| {
        let library = crate::dlopen_on_worker(required_file(variable).as_os_str())
            .expect("the actual exporter image loads on the plugin thread");
        // SAFETY: the required actual product image exports the typed mechanism symbol;
        // image retains its library throughout every test crossing.
        let entry = unsafe {
            *library
                .get::<busbar_contract::abi::sdk::door::RawDoorFn>(DOOR_SYMBOL)
                .expect("the actual exporter door")
        };
        (library, entry)
    });
    let door = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<Export>(door).expect("the actual exporter validates");
    // SAFETY: the validated immutable descriptor belongs to the process-held image.
    unsafe { &*door }
}

extern "C" fn file_door() -> &'static Door {
    static IMAGE: OnceLock<(
        libloading::Library,
        busbar_contract::abi::sdk::door::RawDoorFn,
    )> = OnceLock::new();
    actual_door(file_cdylib(), &IMAGE)
}
extern "C" fn webhook_door() -> &'static Door {
    static IMAGE: OnceLock<(
        libloading::Library,
        busbar_contract::abi::sdk::door::RawDoorFn,
    )> = OnceLock::new();
    actual_door(webhook_cdylib(), &IMAGE)
}
extern "C" fn trace_door() -> &'static Door {
    static IMAGE: OnceLock<(
        libloading::Library,
        busbar_contract::abi::sdk::door::RawDoorFn,
    )> = OnceLock::new();
    actual_door(trace_cdylib(), &IMAGE)
}

const FILE_CARRIES: &[u8] = &[ExportStream::Logs as u8, ExportStream::Events as u8];

fn file_declaration() -> Declares {
    Declares::from_declares_json(
        &std::fs::read(required_file("BUSBAR_TEST_EXPORT_FILE_DECLARES"))
            .expect("read the actual file declaration"),
    )
    .expect("the actual file sink's declaration parses")
}

fn file_declares() -> Declares {
    Declares {
        metrics: Vec::new(),
        ..file_declaration()
    }
}

fn renaming(mut declared: Declares) -> Declares {
    declared.keep.insert("path".to_string(), 2);
    declared
}

fn webhook_declares() -> Declares {
    let declared = Declares::from_declares_json(
        &std::fs::read(required_file("BUSBAR_TEST_EXPORT_WEBHOOK_DECLARES"))
            .expect("read the actual webhook declaration"),
    )
    .expect("the actual webhook sink's declaration parses");
    Declares {
        metrics: Vec::new(),
        ..declared
    }
}

fn manifest(name: &str, declares: Declares) -> Manifest {
    let mut m: Manifest = serde_json::from_slice(
        &std::fs::read(required_file("BUSBAR_TEST_EXPORT_FILE_MANIFEST"))
            .expect("read the actual file manifest"),
    )
    .expect("the actual file manifest parses");
    m.name = name.into();
    m.alias = name.into();
    m.declares = declares;
    m
}

fn stating(m: Manifest, door: DoorFn) -> Manifest {
    let variable = if std::ptr::fn_addr_eq(door, FILE_DOOR) {
        "BUSBAR_TEST_EXPORT_FILE_MANIFEST"
    } else if std::ptr::fn_addr_eq(door, WEBHOOK_DOOR) {
        "BUSBAR_TEST_EXPORT_WEBHOOK_MANIFEST"
    } else if std::ptr::fn_addr_eq(door, TRACE_DOOR) {
        "BUSBAR_TEST_EXPORT_OTLP_MANIFEST"
    } else {
        panic!("only an actual exporter supplies a package manifest")
    };
    let mut stated: Manifest = serde_json::from_slice(
        &std::fs::read(required_file(variable)).expect("read the actual exporter manifest"),
    )
    .expect("the actual exporter manifest parses");
    stated.name = m.name;
    stated.alias = m.alias;
    stated.publisher = m.publisher;
    stated.declares = m.declares;
    stated.statement = Some(hex::encode(
        rendering_of(door).expect("the actual door renders its Statement"),
    ));
    stated
}

fn cdylib_bytes(variable: &str) -> Vec<u8> {
    std::fs::read(required_file(variable)).expect("read the actual exporter image")
}

fn both(m: Manifest, door: DoorFn, variable: &str) -> [PluginRegistry; 2] {
    let lib = cdylib_bytes(variable);
    let m = stating(m, door);
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(m.clone(), door)])
        .expect("the actual descriptor admits the sink");
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
        crate::tarball::package(&package, "exporter", &lib).expect("package actual image"),
    )
    .expect("write the actual exporter package");
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
        crate::scan_and_validate(&dir, &policy).expect("the actual signed exporter package admits");
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

struct DiskHost;

impl DiskHost {
    fn append(dest: &DiskDest, bytes: &[u8]) -> DiskReport {
        use std::io::Write as _;
        let due = dest
            .rotate_at
            .is_some_and(|limit| std::fs::metadata(&dest.path).is_ok_and(|m| m.len() >= limit));
        let truncate = due && dest.rotate == DiskRotate::Truncate;
        let (renamed, failed) = match dest.rotate {
            DiskRotate::Rename { keep } if due => {
                crate::host::rotate(std::path::Path::new(&dest.path), keep)
            }
            _ => (false, Vec::new()),
        };
        let faults = failed.iter().fold(0u8, |f, step| {
            f | match *step {
                "retention" => DISK_RETENTION_FAILED,
                "shift" => DISK_SHIFT_FAILED,
                _ => DISK_RENAME_FAILED,
            }
        });
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(!truncate)
            .truncate(truncate)
            .open(&dest.path);
        let rotated = renamed;
        let report = |step, error: String| DiskReport {
            step,
            rotated,
            faults,
            error: Box::leak(error.into_boxed_str()),
        };
        match opened {
            Ok(mut file) => match file.write_all(bytes) {
                Ok(()) => report(0, String::new()),
                Err(e) => report(DISK_APPEND_FAILED, e.to_string()),
            },
            Err(e) => report(DISK_OPEN_FAILED, e.to_string()),
        }
    }
}

impl crate::services_double::ServicesDouble for DiskHost {
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        later(Self::append(dest, &bytes).stored());
        Ran::Later
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(crate::services_double::Double(DiskHost)),
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
    fn forget(&self, owner: InstanceId) {
        self.forgotten.lock().unwrap().push(owner);
        for conn in self.slab.forget(owner) {
            let _ = Conns::close(self, owner, conn);
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
        transport == "http"
    }
}

impl Conns for Far {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let declared = self
            .verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(caller, need))
            .map(|(_, t)| t.clone())
            .unwrap_or_default();
        let target = if desc.target.is_empty() {
            declared
        } else {
            desc.target.to_string()
        };
        let callback = self.on_open.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback(&target);
        }
        if target.contains(UNREACHABLE_TARGET) {
            return Err(ConnError::Timeout);
        }
        let id = self.slab.insert(caller, need, ())?;
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
                // Text as text; any other body (the collector's protobuf) as hex.
                "body": std::str::from_utf8(&desc.body)
                    .map_or_else(|_| hex::encode(&desc.body), str::to_owned),
            }));
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
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
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
            let door = *FILE_DOOR();
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

fn line(n: u32, pad: usize) -> serde_json::Value {
    serde_json::json!({ "n": n, "pad": "x".repeat(pad) })
}

fn big_line(n: u32) -> serde_json::Value {
    line(n, 1_100_000)
}

fn ns_of(text: &str) -> Option<Vec<u64>> {
    if !text.is_empty() && !text.ends_with('\n') {
        return None;
    }
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).ok()?["n"].as_u64())
        .collect()
}

fn ns(path: &Path) -> Option<Vec<u64>> {
    ns_of(&std::fs::read_to_string(path).ok()?)
}

fn ns_settled(path: &Path) -> Option<Vec<u64>> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(ns_of(&text).unwrap_or_else(|| {
        panic!(
            "{} holds {} bytes that are not whole JSON lines with an `n`",
            path.display(),
            text.len()
        )
    }))
}

fn archive(path: &Path, n: u32) -> PathBuf {
    PathBuf::from(format!("{}.{n}", path.display()))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-11-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn file_settings(path: &Path) -> serde_json::Value {
    serde_json::json!({ "path": path.display().to_string(), "rotate_mb": 1 })
}

fn script(sink: &dyn ExportCalls, path: &Path) {
    for n in 1..=3 {
        deliver(sink, &big_line(n));
    }
    until("the three lines on disk", || {
        ns(path) == Some(vec![3])
            && ns(&archive(path, 1)) == Some(vec![2])
            && ns(&archive(path, 2)) == Some(vec![1])
    });
}

fn opened(
    plugin: Plugin<Export>,
    d: Arc<Dispatcher>,
    settings: &serde_json::Value,
) -> ExportInstance {
    plugin.grant_destinations(&renaming(file_declares()));
    ExportInstance::open(plugin, d, settings.to_string().as_bytes()).expect("the sink opens")
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

fn run_compiled_in(path: &Path) -> Vec<String> {
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let row = LinkedRow::of(FILE_DOOR).expect("the door states its Statement");
    let plugin =
        load_linked::<Export>(&row, bind("#11-compiled-in", tape.clone(), &d)).expect("loads");
    let sink = opened(plugin, d, &file_settings(path));
    script(&sink, path);

    drop(sink);
    tape.seen()
}

fn run_dropped_in(path: &Path) -> Vec<String> {
    let bytes = cdylib_bytes(file_cdylib());
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let stated = rendering_of(FILE_DOOR).expect("the door renders its Statement");
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
        Some(FILE_CARRIES.to_vec())
    );
    let sink = opened(plugin, d, &file_settings(path));
    script(&sink, path);
    drop(sink);
    tape.seen()
}

fn rotated_record(path: &Path) -> String {
    format!(
        "log 0 {target}: request-log file rotated by rename path={p} archive={p}.1",
        target = "busbar_export_file",
        p = path.display()
    )
}

#[test]
fn compiled_in_and_dropped_in_report_identical_observations() {
    let dir = scratch("equivalence");
    let path = dir.join("requests.jsonl");
    let compiled = run_compiled_in(&path);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let dropped = run_dropped_in(&path);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        compiled, dropped,
        "compiled-in and dropped-in builds of ONE crate must hand the host identical \
         observations — this is design decision #11's real test"
    );

    assert!(
        !compiled.is_empty(),
        "neither build reported anything; the equivalence would be vacuous"
    );
}

#[test]
fn the_reported_observations_are_the_ones_the_sink_produced() {
    let dir = scratch("produced");
    let path = dir.join("requests.jsonl");
    let observed = run_compiled_in(&path);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        observed,
        vec![rotated_record(&path), rotated_record(&path)],
        "observed: {observed:?}"
    );
}

#[test]
fn a_destination_declared_keep_zero_is_truncated_in_place_with_no_archive() {
    let dir = scratch("keep0");
    let path = dir.join("requests.jsonl");
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let row = LinkedRow::of(FILE_DOOR).expect("the door states its Statement");
    let plugin = load_linked::<Export>(&row, bind("keep0", tape.clone(), &d)).expect("loads");
    let mut declares = file_declares();
    declares.keep.insert("path".to_string(), 0);
    plugin.grant_destinations(&declares);
    let sink = ExportInstance::open(plugin, d, file_settings(&path).to_string().as_bytes())
        .expect("the sink opens");
    for n in 1..=3 {
        deliver(&sink, &big_line(n));
    }
    until("the third line alone in the live file", || {
        ns(&path) == Some(vec![3])
    });
    drop(sink);
    assert!(!archive(&path, 1).exists(), "keep 0 writes no archive");
    let files = std::fs::read_dir(&dir).expect("scratch dir").count();
    assert_eq!(files, 1, "the live file and nothing else");
    assert!(
        tape.seen().is_empty(),
        "a truncation in place is no rotation: {:?}",
        tape.seen()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_linked_and_a_dropped_in_export_sink_register_one_row_and_fold_the_same() {
    let name = "export-fixture";
    let doors = both(
        manifest(name, renaming(file_declares())),
        FILE_DOOR,
        file_cdylib(),
    );
    let dir = scratch("k5");
    let path = dir.join("requests.jsonl");
    let [linked, dropped] = doors.map(|registry| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_envelope(tape.clone())
            .open(name, "export.tail", &file_settings(&path))
            .expect("the export sink opens through its alias");
        let streams = sink.streams().to_vec();
        let routes = sink.routes().len();

        for n in [1, 2] {
            deliver(sink.as_ref(), &big_line(n));
        }
        until("both lines on disk", || {
            ns(&path) == Some(vec![2]) && ns(&archive(&path, 1)) == Some(vec![1])
        });
        drop(sink);
        let transcript = serde_json::json!({
            "streams": streams,
            "routes": routes,
            "folds": tape.seen(),
        })
        .to_string();
        ({ let row = registry.resolve(name).expect("the actual exporter row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() }, transcript)
    });
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("request-log file rotated by rename"),
        "the linked sink reported the rotation its deliveries caused: {}",
        linked.1
    );
    assert_eq!(
        linked, dropped,
        "the two doors must register one row and fold the same"
    );
}

static PRE_ENVELOPE_PLUGIN_LOCAL: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct RealOps(Ops);
// SAFETY: the table is the dlopened image's `'static` data (its pointers name its code), never
// written; the library stays loaded for the life of the process (the RED arm leaks it).
unsafe impl Send for RealOps {}
// SAFETY: as above.
unsafe impl Sync for RealOps {}
static PRE_ENVELOPE_REAL: OnceLock<RealOps> = OnceLock::new();

struct ShimDoor(Door, Ops);
// SAFETY: built once from the image's `'static` door and never written after; every pointer names
// the image's `'static` data or [`PRE_ENVELOPE_DOORS`] itself.
unsafe impl Send for ShimDoor {}
// SAFETY: as above.
unsafe impl Sync for ShimDoor {}
static PRE_ENVELOPE_DOORS: OnceLock<Box<ShimDoor>> = OnceLock::new();

/// Move the reply's #85 envelope out of the `out` the host reads into the plugin's own store —
/// where a dropped-in `cdylib`'s statically-linked facade sent what it observed before the
/// envelope: the reply the host reads carries none of it.
///
/// # Safety
/// `out` leads with an [`OutHead`] the op just wrote, its envelope arrays valid for this call.
unsafe fn keep_plugin_local(out: *mut c_void) {
    if out.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let head = unsafe { &mut *out.cast::<OutHead>() };
    let env = &mut head.envelope;
    let mut local = PRE_ENVELOPE_PLUGIN_LOCAL
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if !env.metrics.is_null() {
        // SAFETY: the plugin's array of `metrics_len` entries, valid until its next op.
        let metrics: &[MetricEntry] =
            unsafe { std::slice::from_raw_parts(env.metrics, env.metrics_len) };
        local.extend(
            metrics
                .iter()
                .map(|m| metric_text(m.family_idx, m.kind, m.value)),
        );
    }
    if !env.diags.is_null() {
        // SAFETY: as above.
        let diags: &[Diag] = unsafe { std::slice::from_raw_parts(env.diags, env.diags_len) };
        local.extend(diags.iter().map(|d| {
            let text = if d.text.ptr.is_null() {
                &[][..]
            } else {
                // SAFETY: the plugin's text, valid until its next op.
                unsafe { std::slice::from_raw_parts(d.text.ptr, d.text.len) }
            };
            entry_text(d.id_idx, d.severity, text)
        }));
    }
    env.metrics = std::ptr::null();
    env.metrics_len = 0;
    env.diags = std::ptr::null();
    env.diags_len = 0;
}

/// One forwarding op per slot of the export table: the real image's op, then its envelope kept
/// plugin-local.
macro_rules! pre_envelope_ops {
    ($($name:ident => $($field:ident).+;)*) => {
        $(
            extern "C" fn $name(i: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
                let real = PRE_ENVELOPE_REAL.get().expect("the RED arm sets the table first");
                let op = real.0.$($field).+.expect("a forwarding op wraps a present op");
                // SAFETY: the shim forwards the original instance and unchanged ABI frame to
                // the real op for this same slot; its checked loans remain live for the call.
                let answered = unsafe { op(i, input, out) };
                // SAFETY: every op's `out` leads with its `OutHead`, written by the op just now.
                unsafe { keep_plugin_local(out) };
                answered
            }
        )*
        /// The real table with every present op replaced by its forwarding op.
        fn pre_envelope_ops(real: &Ops) -> Ops {
            let mut ops = *real;
            $(
                if real.$($field).+.is_some() {
                    ops.$($field).+ = Some($name);
                }
            )*
            ops
        }
    };
}

pre_envelope_ops! {
    pre_validate => head.validate;
    pre_open => head.open;
    pre_refresh => head.refresh;
    pre_retire => head.retire;
    pre_tick => head.tick;
    pre_drive => head.drive;
    pre_cancel => head.cancel;
    pre_release => head.release;
    pre_close => head.close;
    pre_deliver => deliver;
    pre_scrape => scrape;
    pre_status => status;
    pre_check => check;
    pre_serve => serve;
}

extern "C" fn pre_envelope_door() -> *const Door {
    &PRE_ENVELOPE_DOORS
        .get()
        .expect("the RED arm builds the door first")
        .0
}

#[test]
fn the_pre_envelope_path_loses_a_dropped_in_plugins_counters() {
    let dir = scratch("pre-envelope");
    let path = dir.join("requests.jsonl");

    let compiled_in = run_compiled_in(&path);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let bytes = cdylib_bytes(file_cdylib());
    let (lib, staged) = crate::stage::load_library_from_bytes(&bytes, "#11-pre-envelope")
        .expect("stage the file sink cdylib");
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; the library is leaked below, so
    // the pointer stays valid for the life of the process.
    let real_door: busbar_contract::abi::sdk::door::RawDoorFn = unsafe {
        *lib.get::<busbar_contract::abi::sdk::door::RawDoorFn>(DOOR_SYMBOL)
            .expect("the image's door")
    };
    std::mem::forget(lib);
    std::mem::forget(staged);
    // SAFETY: the image's door answers its `'static` Door; its ops table is the export kind's.
    let door = unsafe { *real_door() };
    // SAFETY: as above: the export kind's table, `'static` in the image.
    let real_ops = unsafe { *door.ops().cast::<Ops>() };
    let _ = PRE_ENVELOPE_REAL.set(RealOps(real_ops));
    let shim = PRE_ENVELOPE_DOORS.get_or_init(|| {
        let mut shim = Box::new(ShimDoor(door, pre_envelope_ops(&real_ops)));
        let parts = DoorParts {
            ops: std::ptr::from_ref(&shim.1).cast::<OpsHead>(),
            ..shim.0.parts()
        };
        // SAFETY: the image's own `'static` Statement over the boxed shim table, built once and
        // held for the process.
        shim.0 = unsafe { Door::__from_parts(parts) };
        shim
    });
    assert_eq!(
        shim.0.statement(),
        door.statement(),
        "the image's own Statement"
    );
    PRE_ENVELOPE_PLUGIN_LOCAL
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let row = LinkedRow::of_raw(pre_envelope_door).expect("the image's Statement renders");
    assert_eq!(
        row.statement,
        rendering_of(FILE_DOOR).expect("renders"),
        "the pre-envelope door states the real sink's Statement"
    );
    let plugin = load_linked::<Export>(&row, bind("#11-pre-envelope", tape.clone(), &d))
        .expect("the pre-envelope door loads");
    let sink = opened(plugin, d, &file_settings(&path));

    script(&sink, &path);
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
    let dropped_in_pre_envelope = tape.seen();
    let plugin_local = std::mem::take(
        &mut *PRE_ENVELOPE_PLUGIN_LOCAL
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
    );

    assert_eq!(
        compiled_in.len(),
        2,
        "the compiled-in build must report both rotations: {compiled_in:?}"
    );

    assert_eq!(
        plugin_local, compiled_in,
        "the pre-envelope build must have observed what the compiled-in one reported, or the \
         divergence below is a broken fixture rather than the defect"
    );

    assert!(
        dropped_in_pre_envelope.is_empty(),
        "the defect: a dropped-in plugin's observations land where nothing reads — the host \
         ingested {dropped_in_pre_envelope:?}"
    );
    assert_ne!(
        compiled_in, dropped_in_pre_envelope,
        "compiled-in ≡ dropped-in was ASSERTED and false for anything a plugin observes — this \
         inequality is what #85's envelope exists to remove, and \
         `compiled_in_and_dropped_in_report_identical_observations` is what proves it did"
    );
}

/// **OWED, and named so it is not forgotten.** The assertions above compare what the host was
/// HANDED. The one #85's acceptance clause names compares what the host RENDERS:
///
/// ```ignore
/// // wherever a metrics recorder legitimately exists (the engine, not the loader):
/// install_recorder();
/// run_compiled_in();
/// let a = busbar_kernel_testkit::test_support::export_axis::render();
/// reset_recorder();
/// run_dropped_in();
/// let b = busbar_kernel_testkit::test_support::export_axis::render();
/// assert_eq!(a, b);   // byte-identical exposition
/// ```
///
/// It is not written here because this crate has no recorder and must not acquire one, and it is
/// not written in the kernel because the kernel may not name a concrete plugin instance — not even
/// under `tests/` (DECISIONS #2). Its home is the composition root, which is the one place entitled
/// to name both. Recorded here rather than in a document because a test file is the thing the next
/// person editing this seam actually reads.
#[test]
fn the_rendered_exposition_equivalence_is_owed_at_the_composition_root() {}

const S1_HOST_SERIES: &str = "busbar_s1_host_owned_total";

#[test]
fn a_first_party_series_is_granted_through_either_door_and_to_nobody_else() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;

    let d = dispatcher();
    d.observing()
        .install_host_series(|name| name == S1_HOST_SERIES);
    let declared = file_declaration();
    let series: Vec<(String, String)> = declared
        .metrics
        .iter()
        .map(|s| (s.name.clone(), s.kind.clone()))
        .collect();

    assert!(
        series
            .iter()
            .any(|(n, _)| n == "busbar_file_logs_dropped_total"),
        "{series:?}"
    );
    let name = "s1-fixture";
    let doors = both(
        manifest(name, renaming(declared.clone())),
        FILE_DOOR,
        file_cdylib(),
    );
    let dir = scratch("s1");
    let path = dir.join("requests.jsonl");
    let [linked, dropped] = doors.map(|registry| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(&registry, Arc::clone(&d))
            .with_envelope(tape.clone())
            .open(name, "export.tail", &file_settings(&path))
            .expect("a first-party declaration opens");
        for n in [1, 2] {
            deliver(sink.as_ref(), &big_line(n));
        }
        until("both lines on disk", || ns(&path) == Some(vec![2]));

        let granted: Vec<bool> = series
            .iter()
            .map(|(s, k)| crate::observe::first_party_series(name, s, k))
            .collect();
        drop(sink);
        assert!(
            series
                .iter()
                .all(|(s, k)| !crate::observe::first_party_series(name, s, k)),
            "the grant goes with the instance"
        );
        let transcript =
            serde_json::json!({ "granted": granted, "folds": tape.seen() }).to_string();
        ({ let row = registry.resolve(name).expect("the actual exporter row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() }, transcript)
    });
    let every_granted = format!(
        r#""granted":{}"#,
        serde_json::json!(vec![true; series.len()])
    );
    assert!(
        linked.1.contains(&every_granted)
            && linked.1.contains("request-log file rotated by rename"),
        "the linked door grants every declared series and the sink reports: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors grant and fold the same");

    let mut third = stating(manifest("s1-third-party", declared.clone()), FILE_DOOR);
    third.publisher = "acme".into();
    let [_, registry] = both(third, FILE_DOOR, file_cdylib());
    let sink = ExportRows::new(&registry, Arc::clone(&d))
        .open("s1-third-party", "export.tail", &file_settings(&path))
        .expect("a third party opens; its declaration is simply not granted");
    drop(sink);
    for (s, k) in &series {
        assert!(!crate::observe::first_party_series("s1-third-party", s, k));
    }

    let mut collides = declared;
    collides.metrics = vec![SeriesDecl::new(S1_HOST_SERIES, "counter")];
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(manifest("s1-collides", collides), FILE_DOOR),
            FILE_DOOR,
        )])
        .expect("the linked door admits the sink");
    let Err(refused) = ExportRows::new(&registry, Arc::clone(&d)).open(
        "s1-collides",
        "export.tail",
        &file_settings(&path),
    ) else {
        panic!("a claim on a host series is refused");
    };
    assert!(
        refused.contains(S1_HOST_SERIES) && refused.contains("the host itself emits"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_sink_validates_its_settings_the_same_through_either_door() {
    let name = "s2-sink";
    let doors = both(manifest(name, file_declares()), FILE_DOOR, file_cdylib());
    let refused = serde_json::json!({ "path": 7 });
    let accepted = serde_json::json!({ "path": "/var/log/busbar/requests.jsonl", "rotate_mb": 64 });
    let [linked, dropped] = doors.map(|registry| {
        let rows = ExportRows::new(&registry, dispatcher());
        let transcript = serde_json::json!({
            "accepted": rows.probe(name, "tail", &accepted),
            "refused": rows.probe(name, "tail", &refused),
            "not_export": rows.probe("no-such-module", "tail", &refused),
        })
        .to_string();
        ({ let row = registry.resolve(name).expect("the actual exporter row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() }, transcript)
    });
    let line = "export.tail.settings: invalid type: integer `7`, expected a string";
    let streams = [ExportStream::Logs as u8, ExportStream::Events as u8];
    assert_eq!(
        linked.1,
        serde_json::json!({
            "accepted": [streams, []],
            "refused": [streams, [line]],
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
    let decl = webhook_declares();
    assert!(decl.diagnostics.iter().any(|d| d.code == 7072), "{decl:?}");
    let name = "s3-fixture";
    let doors = both(manifest(name, decl.clone()), WEBHOOK_DOOR, webhook_cdylib());
    let cfg = serde_json::json!({ "url": format!("https://{UNREACHABLE_TARGET}/in") });
    let [linked, dropped] = doors.map(|registry| {
        let tape = Arc::new(Tape::default());
        let far = Arc::new(Far::default());
        let rows = ExportRows::new(&registry, dispatcher())
            .with_envelope(tape.clone())
            .with_conns(far.clone());
        let first_party = rows.first_party(name);
        let sink = rows.open(name, "export.s3", &cfg).expect("opens");
        deliver(sink.as_ref(), &serde_json::json!({ "n": 1 }));
        until("the transport-error diagnostic", || {
            tape.count("BUSBAR-7072") == 1
        });
        drop(sink);
        let transcript = serde_json::json!({
            "first_party": first_party,
            "raised": tape.seen(),
            "carried": far.carried(),
        })
        .to_string();
        ({ let row = registry.resolve(name).expect("the actual exporter row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() }, transcript)
    });
    assert!(
        linked.0.contains("webhook-delivery-transport-error"),
        "{}",
        linked.0
    );
    assert!(
        linked.1.contains(r#""first_party":true"#)
            && linked.1.contains("BUSBAR-7072")
            && linked.1.contains(r#""carried":[]"#),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors state and raise the same");

    let mut third = stating(manifest("s3-third-party", decl.clone()), WEBHOOK_DOOR);
    third.publisher = "acme".into();
    let [_, registry] = both(third, WEBHOOK_DOOR, webhook_cdylib());
    let row = registry.resolve("s3-third-party").expect("admitted");
    assert_eq!(row.manifest.declares.diagnostics, decl.diagnostics);
    assert!(!row.first_party());
}

#[test]
fn a_sink_writes_its_declared_destination_through_the_host_the_same_through_either_door() {
    let declaring = |name: &str, declared: bool| {
        let mut d = file_declares();
        if !declared {
            d.destinations.clear();
        }
        manifest(name, d)
    };
    let dir = scratch("s4");
    let path = dir.join("requests.jsonl");

    let run = |registry: &PluginRegistry, name: &str, landed: &dyn Fn(&Tape) -> bool| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(registry, dispatcher())
            .with_envelope(tape.clone())
            .open(name, "export.tail", &file_settings(&path))
            .expect("opens");
        for n in 1..=4 {
            deliver(sink.as_ref(), &line(n, 600_000));
        }
        until("the four deliveries answered", || landed(&tape));
        drop(sink);
        serde_json::json!({
            "live": ns_settled(&path),
            "archive": ns_settled(&archive(&path, 1)),
            "folds": tape.seen(),
        })
        .to_string()
    };
    let doors = both(declaring("s4-fixture", true), FILE_DOOR, file_cdylib());
    let [linked, dropped] = doors.map(|registry| {
        let on_disk = |_: &Tape| ns(&path) == Some(vec![3, 4]) && !archive(&path, 1).exists();
        (
            { let row = registry.resolve("s4-fixture").expect("the actual exporter row resolves");
 serde_json::json!({"manifest": Manifest { sha256: String::new(), signature: String::new(), ..row.manifest.clone() },
 "alias_resolves_to": registry.resolve(&row.manifest.alias).map(|alias| alias.manifest.name.clone()) }).to_string() },
            run(&registry, "s4-fixture", &on_disk),
        )
    });

    assert!(linked.1.contains(r#""archive":null"#), "{}", linked.1);
    assert!(linked.1.contains(r#""live":[3,4]"#), "{}", linked.1);
    assert!(
        !linked.1.contains("request-log file rotated"),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors write and rotate the same");

    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(declaring("s4-undeclared", false), FILE_DOOR),
            FILE_DOOR,
        )])
        .expect("the linked door admits the sink");
    let refused = run(&registry, "s4-undeclared", &|tape| {
        tape.count("BUSBAR-7074") == 4
    });
    let _ = std::fs::remove_dir_all(&dir);
    assert!(refused.contains(r#""live":null"#), "{refused}");
    assert_eq!(
        refused.matches("BUSBAR-7074").count(),
        4,
        "one refusal line per delivery: {refused}"
    );
    assert!(
        refused.contains(crate::dispatch::services::NO_DESTINATION),
        "the host's refusal, in its words: {refused}"
    );
}

#[test]
fn a_sinks_outbound_request_is_carried_by_the_host_the_same_through_either_door() {
    let name = "s5-fixture";
    let m = manifest(name, webhook_declares());
    let run = |registry: &PluginRegistry, url: &str, refused: bool| {
        let tape = Arc::new(Tape::default());
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(registry, dispatcher())
            .with_envelope(tape.clone())
            .with_conns(far.clone())
            .open(name, "export.s5", &serde_json::json!({ "url": url }))
            .expect("opens");
        for n in 1..=2 {
            deliver(sink.as_ref(), &serde_json::json!({ "n": n }));
        }
        if refused {
            until("the disabled line", || tape.count("BUSBAR-7070") == 1);
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
    let doors = both(m.clone(), WEBHOOK_DOOR, webhook_cdylib());
    let [linked, dropped] = doors.map(|registry| {
        (
            { let row = registry.resolve(name).expect("the actual exporter row resolves");
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
            stating(m, WEBHOOK_DOOR),
            WEBHOOK_DOOR,
        )])
        .expect("the linked door admits the sink");
    let refused = run(&registry, &format!("https://{REFUSED_TARGET}/v1"), true);
    assert!(refused.contains(r#""carried":[]"#), "{refused}");
    assert!(refused.contains("BUSBAR-7070"), "{refused}");
}

#[test]
fn a_sink_starts_and_checks_the_same_through_either_door() {
    let files = both(
        manifest("k9c-sink", file_declares()),
        FILE_DOOR,
        file_cdylib(),
    );
    let hooks = both(
        manifest("k9c-hook", webhook_declares()),
        WEBHOOK_DOOR,
        webhook_cdylib(),
    );
    let file_settings = serde_json::json!({ "path": "/tmp/x" });
    let file_instances = [("tail".to_string(), &file_settings)];
    let hook_settings = serde_json::json!({
        "url": "https://collector.example/in",
        "max_inflight_deliveries": 0,
        "delivery_timeout_secs": 0,
    });
    let hook_instances = [("audit".to_string(), &hook_settings)];
    let transcripts: Vec<String> = files
        .iter()
        .zip(hooks.iter())
        .map(|(file, hook)| {
            let f = ExportRows::new(file, dispatcher());
            let h = ExportRows::new(hook, dispatcher()).with_conns(Arc::new(Far::default()));
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
    assert!(t.starts_with("Some([]) Some([]) Some([\"export.request-log-webhook.settings.max_inflight_deliveries must be >= 1"), "{t}");
    assert!(
        t.contains("sets settings.delivery_timeout_secs: 0, which would abort every delivery")
            && t.ends_with(" None"),
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
fn a_declared_egress_policy_is_granted_to_a_first_party_sink_only() {
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
        manifest(name, webhook_declares()),
        WEBHOOK_DOOR,
        webhook_cdylib(),
    );
    let [linked, dropped] = doors.map(|registry| {
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_conns(far.clone())
            .open(
                name,
                "export.k9e2",
                &serde_json::json!({ "url": "https://collector.example/in" }),
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
        manifest(name, webhook_declares()),
        WEBHOOK_DOOR,
        webhook_cdylib(),
    );
    let settings = serde_json::json!({
        "url": format!("https://{STALL_TARGET}/in"),
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
            .with_conns(far.clone())
            .open(name, "export.k9c", &settings)
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
            stating(manifest(name, webhook_declares()), WEBHOOK_DOOR),
            WEBHOOK_DOOR,
        )])
        .expect("the linked door admits the sink");

    let far = Arc::new(Far::default());
    let sink = ExportRows::new(&registry, dispatcher())
        .with_conns(far.clone())
        .open(
            name,
            "export.bn2",
            &serde_json::json!({
                "url": format!("https://{STALL_TARGET}/in"),
                "delivery_timeout_secs": 600,
            }),
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
fn a_loopback_collector_the_operator_trusted_loads_first_party_or_not() {
    let collector: DoorFn = TRACE_DOOR;
    let settings = serde_json::json!({ "url": "http://127.0.0.1:4318/v1/traces" });
    let doors = both(
        manifest("k9e2-otlp", Declares::default()),
        collector,
        trace_cdylib(),
    );
    let opened = doors.map(|registry| {
        assert!(registry
            .resolve("k9e2-otlp")
            .is_some_and(|r| r.first_party()));
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_conns(far.clone())
            .open("k9e2-otlp", "export.trace", &settings)
            .expect("a first-party collector opens");
        drop(sink);
        serde_json::to_string(&far.declarations()).expect("encode")
    });
    assert!(
        opened[0].contains(&format!(
            r#""egress_class":{}"#,
            busbar_contract::abi::host::conn::connector::EGRESS_LOOPBACK_ALLOWED
        )),
        "{}",
        opened[0]
    );
    assert_eq!(opened[0], opened[1], "both doors declare the same need");

    let mut third = stating(manifest("k9e2-third-otlp", Declares::default()), collector);
    third.publisher = "acme".into();
    let [_, registry] = both(third, TRACE_DOOR, trace_cdylib());
    let row = registry.resolve("k9e2-third-otlp").expect("admitted");
    assert!(!row.first_party());
    ExportRows::new(&registry, dispatcher())
        .with_conns(Arc::new(Far::default()))
        .open("k9e2-third-otlp", "export.trace", &settings)
        .expect("an operator-trusted collector opens");

    let mut third = stating(
        manifest("k9e2-third-hook", webhook_declares()),
        WEBHOOK_DOOR,
    );
    third.publisher = "acme".into();
    let [_, registry] = both(third, WEBHOOK_DOOR, webhook_cdylib());
    let row = registry.resolve("k9e2-third-hook").expect("admitted");
    assert!(!row.first_party());
}

#[test]
fn an_opened_sinks_envelope_reaches_the_host_observability() {
    use crate::dispatch::EnvelopeSink as _;
    let guard = crate::observe::testing::exclusive();
    let stated = rendering_of(FILE_DOOR).expect("renders");

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
            name: "busbar_file_logs_rotated_total".into(),
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
        labels: &[b"/var/log/busbar/requests.jsonl"],
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
            "name": "busbar_file_logs_rotated_total",
            "type": "counter",
            "value": 1.0,
            "labels": { "path": "/var/log/busbar/requests.jsonl" },
        })]
    );
    crate::observe::testing::clear(&guard);
    sink.diag(Diagnostic {
        id: 0,
        name: b"BUSBAR-7074",
        severity: 1,
        text: b"request-log file open failed; this log was dropped",
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
    assert_eq!(diagnostics[0]["code"], "BUSBAR-7074");
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
        name: b"BUSBAR-7074",
        severity: 1,
        text: b"request-log file open failed; this log was dropped",
    });
    let folds = crate::observe::testing::folds();
    log_sink.flush();
    let logged: String = std::fs::read_dir(&dir)
        .expect("the log dir")
        .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        logged.contains("BUSBAR-7074: request-log file open failed"),
        "the plugin log has the line: {logged:?}"
    );
    assert_eq!(folds.len(), 1, "{folds:?}");
    assert_eq!(folds[0].3[0]["code"], "BUSBAR-7074");
}

#[test]
fn a_closed_span_reaches_a_collector_the_same_through_either_door() {
    let collector: DoorFn = TRACE_DOOR;
    let name = "s7-otlp";
    let doors = both(
        manifest(name, Declares::default()),
        collector,
        trace_cdylib(),
    );
    let span = serde_json::json!({
        "trace_id": "4bf92f3577b34da6",
        "span_id": "00f067aa0ba902b7",
        "name": "busbar.request",
        "start": 1_700_000_000_000_000_u64,
        "duration_us": 1500,
    });
    let [linked, dropped] = doors.map(|registry| {
        let tape = Arc::new(Tape::default());
        let far = Arc::new(Far::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_envelope(tape.clone())
            .with_conns(far.clone())
            .open(
                name,
                "export.trace",
                &serde_json::json!({ "url": "http://127.0.0.1:4318/v1/traces" }),
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
    let trace_id = "4bf92f3577b34da6";
    assert!(
        linked.contains(r#""method":"POST""#)
            && linked.contains(r#""head_target":"/v1/traces""#)
            && linked.contains("application/x-protobuf")
            && linked.contains(trace_id)
            && linked.contains(&hex::encode("busbar.request")),
        "{linked}"
    );
    assert_eq!(linked, dropped, "both doors carry the same request");
}

#[test]
fn the_operators_keep_beside_a_destination_outranks_the_manifest() {
    let dir = scratch("keep-setting");
    let path = dir.join("requests.jsonl");
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(manifest("keep-fixture", file_declares()), FILE_DOOR),
            FILE_DOOR,
        )])
        .expect("the linked door admits the sink");
    let mut settings = file_settings(&path);
    settings["keep"] = serde_json::json!(2);
    let sink = ExportRows::new(&registry, dispatcher())
        .open("keep-fixture", "export.tail", &settings)
        .expect("opens");
    for n in 1..=4 {
        deliver(sink.as_ref(), &line(n, 600_000));
    }
    until("the four lines landed", || ns(&path) == Some(vec![3, 4]));
    drop(sink);
    assert_eq!(
        ns_settled(&archive(&path, 1)),
        Some(vec![1, 2]),
        "the rotated lines are kept in the first archive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn accepted_event_payload_crosses_linked_and_dropped_fixture_doors_unchanged() {
    use busbar_contract::abi::export::ExportField as F;

    const FIXTURE_NAME: &str = "accepted-events-carrier";
    const INSTANCE_LABEL: &str = "export.accepted-events";
    const ACTION: &str = "fixture.mutate";
    const RESOURCE: &str = "fixture:accepted";
    const ACTOR: &str = "fixture-admin";
    const FIRST_SEQUENCE: u64 = 1;
    const FIXTURE_UNIX_SECONDS: u64 = 1_700_000_000;
    const ONE_RECORD: usize = 1;
    const FIRST_RECORD: usize = 0;

    let doors = both(
        manifest(FIXTURE_NAME, renaming(file_declares())),
        FILE_DOOR,
        file_cdylib(),
    );
    let dir = scratch(FIXTURE_NAME);
    let path = dir.join("accepted-events.jsonl");
    let fields = [
        (F::Seq, serde_json::Value::from(FIRST_SEQUENCE)),
        (F::Ts, serde_json::Value::from(FIXTURE_UNIX_SECONDS)),
        (F::PrevHash, serde_json::Value::from("")),
        (F::Kind, serde_json::Value::from(ACTION)),
        (F::Actor, serde_json::Value::from(ACTOR)),
        (F::Resource, serde_json::Value::from(RESOURCE)),
        (
            F::Outcome,
            serde_json::Value::from(busbar_contract::vocab::OUTCOME_APPLIED),
        ),
    ];
    let expected = serde_json::Value::Object(
        fields
            .into_iter()
            .map(|(field, value)| (field.as_token().into(), value))
            .collect(),
    );
    let [linked, dropped] = doors.map(|registry| {
        let _ = std::fs::remove_file(&path);
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_envelope(tape)
            .open(FIXTURE_NAME, INSTANCE_LABEL, &file_settings(&path))
            .expect("the neutral carrier opens through either memory ABI door");
        assert!(sink.streams().contains(&(ExportStream::Events as u8)));
        assert!(matches!(
            sink.deliver(
                ExportStream::Events as u8,
                serde_json::to_vec(&expected).unwrap(),
                Box::new(()),
            ),
            Delivered::Queued
        ));
        until("the accepted event reaches the host disk lane", || {
            std::fs::read_to_string(&path).is_ok_and(|text| text.ends_with('\n'))
        });
        drop(sink);
        let text = std::fs::read_to_string(&path).unwrap();
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), ONE_RECORD);
        assert_eq!(records[FIRST_RECORD], expected);
        records
    });
    assert_eq!(linked, dropped);
    std::fs::remove_dir_all(dir).unwrap();
}
