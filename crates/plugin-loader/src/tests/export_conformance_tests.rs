// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE #11 TEST.** One crate, built BOTH ways, must be observationally identical.
//!
//! DECISIONS #11 says every plugin is compiled-in OR dropped-in over the same contract and one
//! loading path, and that the distinction is a BUILD property and nothing more. For everything a
//! plugin OBSERVES that claim was once FALSE:
//!
//! > a COMPILED-IN plugin can reach the process-global `metrics` recorder, while the same crate
//! > built as a dropped-in `cdylib` gets its own and silently loses the counters.
//!
//! A `cdylib` statically links its own copy of every facade it uses. Its recorder (and its
//! `tracing` dispatcher) is not the host's, nothing joins them, and everything a dropped-in sink
//! observed went where nobody ever reads. The same source, built the other way, linked the host's
//! and worked. Two builds, two different observable behaviours, and no test anywhere said so —
//! which is precisely why #85's envelope exists: under it, reaching a recorder is not representable
//! from either build, so both REPORT and the host ingests.
//!
//! ## The subjects (owner FIXTURES: "real plugins are the proofs"; NO-TEST-PLUGINS)
//!
//! The REAL request-log sinks on the export kind's MEMORY ABI, each LINKED by its logic crate's
//! `door` and DROPPED IN as its `-plugin` crate's `cdylib` (signed first-party, its Statement
//! rendering in its manifest), at the revs the composition root links:
//!
//! * the request-log FILE sink — a host-written destination: every append and rotation is the
//!   HOST's act (`disk.append`), the sink never opens a path;
//! * the request-log WEBHOOK sink — a host-carried outbound request: its POST rides the host's
//!   connection table (the need its Statement declares), the sink never dials.
//!
//! The host services and the connection table are the host's side of the boundary, so this binary
//! supplies them as the composition root does: [`DiskHost`] serves `disk.append` by the kernel's
//! lane rules (append, rotating by rename first when due, `crate::host::rotate`), and [`Far`] is
//! the connection table the webhook's need is declared on, recording what it is asked to carry.
//!
//! ## What this test compares, and why that is the right thing
//!
//! It runs the SAME sequence of operations against the SAME door reached two ways, and compares
//! what the HOST was handed on the #85 envelope — every metric, diagnostic and log record its sink
//! ([`Tape`]) ingested, byte for byte — plus what the host did for the sink (the files on disk, the
//! requests carried).
//!
//! ## Red-before-green, PERMANENTLY
//!
//! [`the_pre_envelope_path_loses_a_dropped_in_plugins_counters`] is the RED arm, and it stays in the
//! file. It replays what the old arrangement did over the production seam — the REAL file-sink
//! cdylib, dlopened by the loader's staging, its replies' envelopes kept in a store of its own
//! instead of crossing to the host — and shows the two builds diverging. A test that only ever
//! passes cannot tell you what it is protecting you from.
//!
//! ## What the cold lane's suite had that the memory ABI does not
//!
//! Ported from the cold-lane suite (`predev-all/b9`), each arm on the door registries. One of its
//! claims has no door form, and says why here rather than vanish: the cold `start` op (live,
//! admission, words) — the export table has no `start`; a sink's in-flight bound is the one its
//! settings state (`max_inflight_deliveries`), within its Statement's declared `max_inflight`, read
//! at bind ([`a_sinks_deliveries_in_flight_reach_its_admission_bound_past_the_blocking_pool`] holds
//! the bound).

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
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::lifecycle::OpsHead;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::export_calls::{Delivered, ExportCalls};
use busbar_contract::ids::StreamId;
use busbar_contract::services::{
    Caller, DiskDest, DiskReport, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
};
use busbar_contract::transport::ConnFacts;

use super::*;
use crate::both_ways;
use crate::dispatch::kinds::export::Export;
use crate::dispatch::{
    load_dropped_bytes, load_linked, rendering_of, Bind, Diagnostic, DispatchConfig, Dispatcher,
    Dropped, EnvelopeSink, LinkedRow, Metric, Plugin,
};
use crate::export_axis::ExportRows;
use crate::export_door::ExportInstance;
use crate::sign::{Declares, Manifest};

// ── the subjects ─────────────────────────────────────────────────────────────────────────────────

/// The request-log FILE sink's door, LINKED (its logic crate's `door`).
const FILE_DOOR: DoorFn = busbar_export_file::door;
/// The FILE sink's `-plugin` crate, whose `cdylib` exports the same door: the DROPPED-IN build.
const FILE_CDYLIB: &str = "busbar_export_file_plugin";
/// The request-log WEBHOOK sink's door, LINKED.
const WEBHOOK_DOOR: DoorFn = busbar_export_webhook::door;
/// The WEBHOOK sink's `-plugin` crate's `cdylib`: the DROPPED-IN build.
const WEBHOOK_CDYLIB: &str = "busbar_export_webhook_plugin";

/// What the FILE sink carries: the request-log line.
const FILE_CARRIES: [u8; 1] = [ExportStream::Logs as u8];

/// The FILE sink's own manifest declaration (its `declares.json`): its series, its codes and its
/// one destination, `path`.
fn file_declaration() -> Declares {
    serde_json::from_str(busbar_export_file::DECLARES).expect("the file sink's declaration parses")
}

/// [`file_declaration`] without its series. A first-party series is granted to ONE plugin per
/// process (the grant is the host's namespace), so only the S1 arm, whose subject the grant is,
/// states them; every other arm registers its row under a name of its own.
fn file_declares() -> Declares {
    Declares {
        metrics: Vec::new(),
        ..file_declaration()
    }
}

/// The WEBHOOK sink's own manifest declaration, without its series (as [`file_declares`]).
fn webhook_declares() -> Declares {
    let declared: Declares = serde_json::from_str(busbar_export_webhook::DECLARES)
        .expect("the webhook sink's declaration parses");
    Declares {
        metrics: Vec::new(),
        ..declared
    }
}

/// A first-party export manifest named `name` (its alias too), at this host's export ABI, stating
/// `declares`.
fn manifest(name: &str, declares: Declares) -> Manifest {
    let mut m = both_ways::statement(
        "export",
        name,
        name,
        busbar_contract::abi::export::ABI_VERSION,
    );
    m.declares = declares;
    m
}

/// `m` stating `door`'s Statement rendering, as the pack tool signs it into a dropped plugin's
/// manifest and as the linked row states it.
fn stating(mut m: Manifest, door: DoorFn) -> Manifest {
    m.statement = Some(hex::encode(
        rendering_of(door).expect("the door renders its Statement"),
    ));
    m
}

/// The bytes of `crate_snake`'s built `cdylib`; `None` in a scoped, non-CI run that did not build
/// it (`both_ways::cdylib` refuses to skip under CI).
fn cdylib_bytes(crate_snake: &str) -> Option<Vec<u8>> {
    Some(std::fs::read(both_ways::cdylib(crate_snake)?).expect("read the cdylib"))
}

/// THE TWO DOORS through registration: `m` with `door` registered LINKED (through
/// [`PluginRegistry::link`]) and `crate_snake`'s `cdylib` signed first-party into `plugins/` and
/// scanned (the DROPPED-IN door) — both stating the door's Statement.
fn both(m: Manifest, door: DoorFn, crate_snake: &str) -> Option<[PluginRegistry; 2]> {
    let lib = cdylib_bytes(crate_snake)?;
    let m = stating(m, door);
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(m.clone(), door)])
        .expect("the linked door admits the sink");
    let dropped = both_ways::dropped(crate_snake, m, &lib);
    Some([linked, dropped])
}

// ── the host's side: its envelope sink, its disk lane, its connection table ──────────────────────

/// One envelope entry, as text: what the host ingested. A log record and a declared diagnostic
/// are told apart, a metric names its family by index.
fn entry_text(id: u32, severity: u8, text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    match id {
        DIAG_LOG => format!("log {severity} {text}"),
        DIAG_LOG_DROPPED => format!("logs-dropped {text}"),
        id => format!("diag {id} {severity} {text}"),
    }
}

/// A metric, as text.
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

    /// How many entries carry `needle`.
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

/// The host-service refusal of every service but `disk.append`: this binary's host serves the
/// disk lane only.
const NO_SERVICE: &str = "this test host serves disk.append only";

/// THE HOST'S DISK LANE, as this binary serves it: `disk.append` appends to the file the loader
/// bound for the caller's destination key, rotating by rename first when the file already holds
/// `rotate_at` bytes and keeping `keep` archives ([`crate::host::rotate`]), then opening it for
/// append (created if absent) and writing the bytes whole — the same rules the kernel's lane follows.
struct DiskHost;

impl DiskHost {
    fn append(dest: &DiskDest, bytes: &[u8]) -> DiskReport {
        use std::io::Write as _;
        let due = dest
            .rotate_at
            .is_some_and(|limit| std::fs::metadata(&dest.path).is_ok_and(|m| m.len() >= limit));
        let (rotated, failed) = if due {
            crate::host::rotate(&dest.path, dest.keep)
        } else {
            (false, Vec::new())
        };
        let faults = failed.iter().fold(0u8, |f, step| {
            f | match *step {
                "retention" => DISK_RETENTION_FAILED,
                "shift" => DISK_SHIFT_FAILED,
                _ => DISK_RENAME_FAILED,
            }
        });
        let report = |step, error: String| DiskReport {
            step,
            rotated,
            faults,
            error: Box::leak(error.into_boxed_str()),
        };
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&dest.path)
        {
            Ok(mut file) => match file.write_all(bytes) {
                Ok(()) => report(0, String::new()),
                Err(e) => report(DISK_APPEND_FAILED, e.to_string()),
            },
            Err(e) => report(DISK_OPEN_FAILED, e.to_string()),
        }
    }
}

impl HostServices for DiskHost {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: 0,
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(NO_SERVICE))
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused(NO_SERVICE))
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(Stored::refused(NO_SERVICE))
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(Stored::refused(NO_SERVICE))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(NO_SERVICE)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::refused(NO_SERVICE))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(NO_SERVICE)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::refused(NO_SERVICE)
    }
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        Stored::refused(NO_SERVICE)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::refused(NO_SERVICE)
    }
    fn records_secret(&self, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::refused(NO_SERVICE))
    }
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        later(Self::append(dest, &bytes).stored());
        Ran::Later
    }

    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        Ran::Now(Stored::refused("no nested units here"))
    }

    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused("no work book here"))
    }

    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused("no work book here"))
    }

    fn work_settle(&self, _: &Caller, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused("no work book here"))
    }

    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        Ran::Now(Stored::refused("no work book here"))
    }

    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused("no verify cache here"))
    }

    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        Stored::refused("no verify cache here")
    }

    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused("no hook stage here"))
    }

    fn hook_call(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: busbar_contract::services::HookAsk,
        _: Later,
    ) -> Ran {
        Ran::Now(Stored::refused("no hook stage here"))
    }

    fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
        busbar_contract::services::Snapshot::Refused(NO_SERVICE)
    }
}

/// A dispatcher whose host services are [`DiskHost`]'s.
fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(DiskHost),
    ))
}

/// A target the host's egress policy refuses: its need's declaration is refused, so its admission
/// is.
const REFUSED_TARGET: &str = "refused.example";
/// A target the host admits and cannot reach: its connection fails at the open.
const UNREACHABLE_TARGET: &str = "unreachable.example";
/// A target whose far end holds every request until released: its reply pends, no thread waiting.
const STALL_TARGET: &str = "stall.example";

/// What the table answered one declaration, and the target it is pinned to.
type Verdict = (Result<(), ConnError>, String);

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
    /// The connections whose reply is held, and the ticket each read registered interest under.
    stalled: Mutex<HashMap<ConnId, u64>>,
    released: std::sync::atomic::AtomicBool,
    waker: OnceLock<Arc<dyn Fn(u64) + Send + Sync>>,
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
    /// How many requests the far end holds right now.
    fn stalled(&self) -> usize {
        self.stalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
    /// Let every held request answer, waking each ticket that waits on one.
    fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let held: Vec<u64> = self
            .stalled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, t)| t)
            .collect();
        if let Some(wake) = self.waker.get() {
            held.into_iter().for_each(|t| wake(t));
        }
    }
}

impl DeclaredConns for Far {
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
        // The table's contract (`DeclaredConns::declare`, spec PB-100): a need whose `target_from`
        // resolved to nothing is refused, as the host's connector refuses it.
        let unresolved = !spec.target_from.is_empty() && target.is_none();
        let target = target.unwrap_or_default().to_string();
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
        if target.contains(UNREACHABLE_TARGET) {
            return Err(ConnError::Timeout);
        }
        let id = self.slab.insert(caller, need, ())?;
        if target.contains(STALL_TARGET) && !self.released.load(std::sync::atomic::Ordering::SeqCst)
        {
            self.stalled
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, 0);
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
                "body": std::str::from_utf8(desc.body)
                    .map_or_else(|_| hex::encode(desc.body), str::to_owned),
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
                *waiting = ticket;
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
            reason: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Ok(0)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.slab.remove(caller, conn).map(|_| ())
    }
}

// ── a door that predates an op ───────────────────────────────────────────────────────────────────

/// The FILE sink's own door with one slot of its ops table NULL: what a table built before that op
/// existed hands the host. The memory ABI's table is the host's for the kind's ABI version, every
/// slot present (`dispatch::load`), so such a door is never bound.
struct OlderDoor(Door, Ops);
// SAFETY: built once from the linked door's `'static` data and never written after; every pointer
// names that data or the box itself.
unsafe impl Send for OlderDoor {}
// SAFETY: as above.
unsafe impl Sync for OlderDoor {}

/// [`FILE_DOOR`]'s door, its table passed through `strip`, built once into `cell`.
fn older(cell: &'static OnceLock<Box<OlderDoor>>, strip: fn(&mut Ops)) -> *const Door {
    &cell
        .get_or_init(|| {
            // SAFETY: the linked door answers its `'static` Door; its table is the export kind's.
            let door = unsafe { *FILE_DOOR() };
            // SAFETY: as above.
            let mut ops = unsafe { *door.ops.cast::<Ops>() };
            strip(&mut ops);
            let mut older = Box::new(OlderDoor(door, ops));
            older.0.ops = std::ptr::from_ref(&older.1).cast::<OpsHead>();
            older
        })
        .0
}

static NO_VALIDATE: OnceLock<Box<OlderDoor>> = OnceLock::new();
static NO_CHECK: OnceLock<Box<OlderDoor>> = OnceLock::new();

/// The FILE sink's door from before `validate`.
extern "C" fn door_without_validate() -> *const Door {
    older(&NO_VALIDATE, |ops| ops.head.validate = None)
}

/// The FILE sink's door from before `check`.
extern "C" fn door_without_check() -> *const Door {
    older(&NO_CHECK, |ops| ops.check = None)
}

/// Why the one load refuses `door`.
fn refused_at_load(door: DoorFn) -> String {
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    match LinkedRow::of(door).and_then(|row| load_linked::<Export>(&row, bind("older", tape, &d))) {
        Ok(_) => panic!("a door that predates an op was bound"),
        Err(e) => e.to_string(),
    }
}

// ── driving one instance ─────────────────────────────────────────────────────────────────────────

/// Wait (at most a minute) until `done` holds.
fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Hand `line` to `sink` on the request-log stream; it is queued.
fn deliver(sink: &dyn ExportCalls, line: &serde_json::Value) {
    let queued = sink.deliver(
        ExportStream::Logs as u8,
        line.to_string().into_bytes(),
        Box::new(()),
    );
    assert!(matches!(queued, Delivered::Queued), "{queued:?}");
}

/// A line of `pad` bytes of padding, numbered `n`.
fn line(n: u32, pad: usize) -> serde_json::Value {
    serde_json::json!({ "n": n, "pad": "x".repeat(pad) })
}

/// A line too large to share a 1 MiB file with another: a delivery of it to a file that already
/// holds one has the host rotate first (`rotate_mb: 1`).
fn big_line(n: u32) -> serde_json::Value {
    line(n, 1_100_000)
}

/// `path`'s JSON lines as their `n` fields — what one door left on disk, independent of the pad.
fn ns(path: &Path) -> Option<Vec<u64>> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(
        text.lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).expect("a JSON line")["n"]
                    .as_u64()
                    .expect("n")
            })
            .collect(),
    )
}

/// `path`'s `n`-th archive.
fn archive(path: &Path, n: u32) -> PathBuf {
    PathBuf::from(format!("{}.{n}", path.display()))
}

/// A fresh scratch directory for `tag`.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-11-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The FILE sink's settings: `path`, rotated at 1 MiB.
fn file_settings(path: &Path) -> serde_json::Value {
    serde_json::json!({ "path": path.display().to_string(), "rotate_mb": 1 })
}

/// The operations the observation arms run, in order: three lines too large to share the file, so
/// the second and the third each have the host rotate first — two rotations the sink observes and
/// reports, then the host's files: `[3]` live, `[2]` in `.1`, `[1]` in `.2`.
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

/// THE DOOR, BOUND: `door` (the linked row's or the dlopened image's) under `sink`, on `dispatcher`,
/// granted the FILE sink's declared destination, then OPENED over `settings` — the instance the
/// opener makes ([`ExportRows::open`]'s memory arm).
fn opened(
    plugin: Plugin<Export>,
    d: Arc<Dispatcher>,
    settings: &serde_json::Value,
) -> ExportInstance {
    plugin.grant_destinations(&file_declares().destinations);
    ExportInstance::open(plugin, d, settings.to_string().as_bytes()).expect("the sink opens")
}

/// The bind a door is loaded under: this test's envelope sink, `dispatcher`, no connections.
fn bind(label: &str, sink: Arc<Tape>, d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from(label),
        max_inflight_cap: 64,
        sink,
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// Run [`script`] against the COMPILED-IN build: the FILE sink's door this crate LINKS, loaded
/// through the one load, its envelope ingested by the host. What the host was handed.
fn run_compiled_in(path: &Path) -> Vec<String> {
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let row = LinkedRow::of(FILE_DOOR).expect("the door states its Statement");
    let plugin =
        load_linked::<Export>(&row, bind("#11-compiled-in", tape.clone(), &d)).expect("loads");
    let sink = opened(plugin, d, &file_settings(path));
    script(&sink, path);
    // Dropping the instance waits for the batch in flight to answer: its envelope is in.
    drop(sink);
    tape.seen()
}

/// Run the same script against the DROPPED-IN build: the `cdylib` on disk, staged and `dlopen`ed by
/// the loader against the Statement the linked door renders. `None` when the `cdylib` is not built
/// (a scoped `cargo test -p` of an unrelated crate); under CI that is a hard failure.
fn run_dropped_in(path: &Path) -> Option<Vec<String>> {
    let bytes = cdylib_bytes(FILE_CDYLIB)?;
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
    Some(tape.seen())
}

/// The rotation record the FILE sink reports for a rotation of `path`.
fn rotated_record(path: &Path) -> String {
    format!(
        "log 0 busbar_export_file: request-log file rotated by rename path={p} archive={p}.1",
        p = path.display()
    )
}

/// **THE EQUIVALENCE.** The same crate, built both ways, hands the host byte-identical observations.
///
/// Before the envelope this could not pass: the dropped-in arm would have handed the host NOTHING
/// (what it observed went into its own copy of the facade) while the compiled-in arm reported both
/// rotations. The RED arm below reproduces exactly that divergence, so the difference between the
/// two arrangements is visible in one file.
#[test]
fn compiled_in_and_dropped_in_report_identical_observations() {
    let dir = scratch("equivalence");
    let path = dir.join("requests.jsonl");
    let compiled = run_compiled_in(&path);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let Some(dropped) = run_dropped_in(&path) else {
        // Not built under this scoped run. `both_ways::cdylib` already hard-fails under CI, so
        // this arm cannot quietly disappear where it matters.
        return;
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        compiled, dropped,
        "compiled-in and dropped-in builds of ONE crate must hand the host identical \
         observations — this is design decision #11's real test"
    );
    // And they must both have SAID something: an equivalence between two empty sequences is the
    // vacuous pass this test exists to avoid.
    assert!(
        !compiled.is_empty(),
        "neither build reported anything; the equivalence would be vacuous"
    );
}

/// The observations are the ones the sink actually produced — one record per rotation the host
/// reported, on the reply of the delivery that caused it — so the equivalence above is over real
/// content rather than over two identical nothings.
///
/// TWO records, not three: the first delivery finds no file to rotate, so it observes nothing; the
/// second and the third each have the host rotate first, and the sink reports each rotation once
/// (the FILE sink at its pin reports a rotation as its `info` record, the line 1.5.5 logged; it
/// emits no metric). Nothing is dropped.
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

/// **THE AXIS, BOTH WAYS** (DECISIONS #2 rule (1), item 141). The FILE sink registered through the
/// LINKED door (its `door`, through [`PluginRegistry::link`]) and the DROPPED-IN door (its `cdylib`,
/// signed into `plugins/`) resolves to the byte-identical registry row, and the sink each door's
/// opener ([`ExportRows::open`]) opens — the one load over either image — answers the same streams
/// and routes, writes the same files and hands the host byte-identical observations for the same
/// deliveries. This is the equivalence above taken through the real registration and open a node
/// runs.
///
/// RED by taking `export` out of the linked door's kinds: `link` refuses the row and the linked
/// arm never opens.
#[test]
fn a_linked_and_a_dropped_in_export_sink_register_one_row_and_fold_the_same() {
    let name = "export-fixture";
    let Some(doors) = both(manifest(name, file_declares()), FILE_DOOR, FILE_CDYLIB) else {
        eprintln!("skip: the file sink's cdylib is not built");
        return;
    };
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
        // Two lines too large to share the file: the second has the host rotate first.
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
        (both_ways::row(&registry, name), transcript)
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

// ── THE RED ARM: the pre-envelope path ───────────────────────────────────────────────────────────

/// What the pre-envelope build's plugin-side store received: every entry the sink OBSERVED and the
/// pre-envelope wire had no field to carry. Process-global only because an op is a bare fn pointer
/// with no closure; the RED arm is its only writer.
static PRE_ENVELOPE_PLUGIN_LOCAL: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The real dropped-in image's ops table, which the pre-envelope door's ops forward to.
struct RealOps(Ops);
// SAFETY: the table is the dlopened image's `'static` data (its pointers name its code), never
// written; the library stays loaded for the life of the process (the RED arm leaks it).
unsafe impl Send for RealOps {}
// SAFETY: as above.
unsafe impl Sync for RealOps {}
static PRE_ENVELOPE_REAL: OnceLock<RealOps> = OnceLock::new();

/// The pre-envelope door: the real image's door, its ops table replaced by [`PRE_ENVELOPE_OPS`].
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
                let answered = op(i, input, out);
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

/// The pre-envelope door function.
extern "C" fn pre_envelope_door() -> *const Door {
    &PRE_ENVELOPE_DOORS
        .get()
        .expect("the RED arm builds the door first")
        .0
}

/// **THE RED ARM — what the old arrangement did, kept as the witness.**
///
/// Before #85 a dropped-in sink had no wire for what it observed: its reply was the kind's answer
/// BARE, and what it observed went into the facade its own object statically linked — a store
/// nobody reads. The compiled-in build of the same source linked the host's, so the two builds
/// diverged and nothing errored.
///
/// This arm REPLAYS that arrangement over the production seam rather than modelling it: the REAL
/// FILE-sink `cdylib` is staged and `dlopen`ed by the loader (`stage::load_library_from_bytes`), its
/// door bound through the one load, and every op of its table answers exactly what the real op
/// answered — with the reply's envelope moved into a store of the plugin's own
/// ([`PRE_ENVELOPE_PLUGIN_LOCAL`]) before the host reads it. The compiled-in arm is the real one,
/// and the host's envelope sink is the real ingestion's.
///
/// So it is RED-capable in every direction the claim has: if the real sink stops observing, if the
/// host starts inventing entries, or if the two builds stop diverging, one of the assertions below
/// fails.
///
/// The envelope makes this unrepresentable. A plugin has no symbol to call: it REPORTS, on a wire
/// that goes to exactly one place, and the host is what ingests.
#[test]
fn the_pre_envelope_path_loses_a_dropped_in_plugins_counters() {
    let dir = scratch("pre-envelope");
    let path = dir.join("requests.jsonl");

    // Compiled-in, as the equivalence test runs it: the host ingests what the plugin reported.
    let compiled_in = run_compiled_in(&path);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");

    // Dropped-in, pre-envelope: the real cdylib staged by the real loader, its envelopes kept
    // plugin-local.
    let Some(bytes) = cdylib_bytes(FILE_CDYLIB) else {
        // Not built under this scoped run; `both_ways::cdylib` hard-fails under CI.
        return;
    };
    let (lib, staged) = crate::stage::load_library_from_bytes(&bytes, "#11-pre-envelope")
        .expect("stage the file sink cdylib");
    // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; the library is leaked below, so the
    // pointer stays valid for the life of the process.
    let real_door: DoorFn = unsafe { *lib.get::<DoorFn>(DOOR_SYMBOL).expect("the image's door") };
    std::mem::forget(lib);
    std::mem::forget(staged);
    // SAFETY: the image's door answers its `'static` Door; its ops table is the export kind's.
    let door = unsafe { *real_door() };
    // SAFETY: as above: the export kind's table, `'static` in the image.
    let real_ops = unsafe { *door.ops.cast::<Ops>() };
    let _ = PRE_ENVELOPE_REAL.set(RealOps(real_ops));
    let shim = PRE_ENVELOPE_DOORS.get_or_init(|| {
        let mut shim = Box::new(ShimDoor(door, pre_envelope_ops(&real_ops)));
        shim.0.ops = std::ptr::from_ref(&shim.1).cast::<OpsHead>();
        shim
    });
    assert_eq!(
        shim.0.statement, door.statement,
        "the image's own Statement"
    );
    PRE_ENVELOPE_PLUGIN_LOCAL
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let tape = Arc::new(Tape::default());
    let d = dispatcher();
    let row = LinkedRow::of(pre_envelope_door).expect("the image's Statement renders");
    assert_eq!(
        row.statement,
        rendering_of(FILE_DOOR).expect("renders"),
        "the pre-envelope door states the real sink's Statement"
    );
    let plugin = load_linked::<Export>(&row, bind("#11-pre-envelope", tape.clone(), &d))
        .expect("the pre-envelope door loads");
    let sink = opened(plugin, d, &file_settings(&path));
    // The sink still DOES its work — the host appends and rotates for it, exactly as before.
    script(&sink, &path);
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
    let dropped_in_pre_envelope = tape.seen();
    let plugin_local = std::mem::take(
        &mut *PRE_ENVELOPE_PLUGIN_LOCAL
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
    );

    // The compiled-in build's observations reached the host.
    assert_eq!(
        compiled_in.len(),
        2,
        "the compiled-in build must report both rotations: {compiled_in:?}"
    );
    // The pre-envelope build OBSERVED exactly the same thing — the records existed...
    assert_eq!(
        plugin_local, compiled_in,
        "the pre-envelope build must have observed what the compiled-in one reported, or the \
         divergence below is a broken fixture rather than the defect"
    );
    // ...and the host received none of it.
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
/// let a = busbar_kernel::snapshot::render();
/// reset_recorder();
/// run_dropped_in();
/// let b = busbar_kernel::snapshot::render();
/// assert_eq!(a, b);   // byte-identical exposition
/// ```
///
/// It is not written here because this crate has no recorder and must not acquire one, and it is
/// not written in the kernel because the kernel may not name a concrete plugin instance — not even
/// under `tests/` (DECISIONS #2). Its home is the composition root, which is the one place entitled
/// to name both. Recorded here rather than in a document because a test file is the thing the next
/// person editing this seam actually reads.
#[test]
fn the_rendered_exposition_equivalence_is_owed_at_the_composition_root() {
    // Nothing to assert; this test is a landmark. It fails only if deleted, which is the point.
}

/// A series the host itself emits, for the collision arm — installed once as this test binary's
/// host catalog (the composition root installs the real one).
const S1_HOST_SERIES: &str = "busbar_s1_host_owned_total";

/// **K9a S1 — THE FIRST-PARTY METRIC NAMESPACE, BOTH WAYS.** The FILE sink, its manifest declaring
/// the reserved series it reports under (its own `declares.json`), registered through the LINKED
/// door and the DROPPED-IN door (signed by the release key): each open GRANTS every declared series,
/// so the host renders them as declared (the kernel's `observe` tests render the grant), and the
/// two doors register one row and fold the same. RED ARMS, in the same test so the grant cannot pass
/// vacuously: the same crate dropped in by a THIRD party (allowlisted, trusted, not first-party) is
/// granted nothing whatever it declares, and a first-party claim on a series the host emits refuses
/// the open naming it.
#[test]
fn a_first_party_series_is_granted_through_either_door_and_to_nobody_else() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    crate::observe::install_host_series(|name| name == S1_HOST_SERIES);
    let declared = file_declaration();
    let series: Vec<(String, String)> = declared
        .metrics
        .iter()
        .map(|s| (s.name.clone(), s.kind.clone()))
        .collect();
    assert!(
        series
            .iter()
            .any(|(n, _)| n == "busbar_file_logs_rotated_total"),
        "{series:?}"
    );
    let name = "s1-fixture";
    let Some(doors) = both(manifest(name, declared.clone()), FILE_DOOR, FILE_CDYLIB) else {
        eprintln!("skip: the file sink's cdylib is not built");
        return;
    };
    let dir = scratch("s1");
    let path = dir.join("requests.jsonl");
    let [linked, dropped] = doors.map(|registry| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_envelope(tape.clone())
            .open(name, "export.tail", &file_settings(&path))
            .expect("a first-party declaration opens");
        for n in [1, 2] {
            deliver(sink.as_ref(), &big_line(n));
        }
        until("both lines on disk", || ns(&path) == Some(vec![2]));
        drop(sink);
        let granted: Vec<bool> = series
            .iter()
            .map(|(s, k)| crate::observe::first_party_series(name, s, k))
            .collect();
        let transcript =
            serde_json::json!({ "granted": granted, "folds": tape.seen() }).to_string();
        (both_ways::row(&registry, name), transcript)
    });
    assert!(
        linked.1.contains(r#""granted":[true,true,true]"#)
            && linked.1.contains("request-log file rotated by rename"),
        "the linked door grants every declared series and the sink reports: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors grant and fold the same");

    // RED ARM 1: a third party declaring the same claims is granted nothing.
    let lib = cdylib_bytes(FILE_CDYLIB).expect("built above");
    let mut third = stating(manifest("s1-third-party", declared.clone()), FILE_DOOR);
    third.publisher = "acme".into();
    let registry = both_ways::dropped_third_party(FILE_CDYLIB, third, &lib);
    let sink = ExportRows::new(&registry, dispatcher())
        .open("s1-third-party", "export.tail", &file_settings(&path))
        .expect("a third party opens; its declaration is simply not granted");
    drop(sink);
    for (s, k) in &series {
        assert!(!crate::observe::first_party_series("s1-third-party", s, k));
    }

    // RED ARM 2: a first-party claim on a host series refuses the open.
    let mut collides = declared;
    collides.metrics = vec![SeriesDecl::new(S1_HOST_SERIES, "counter")];
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(manifest("s1-collides", collides), FILE_DOOR),
            FILE_DOOR,
        )])
        .expect("the linked door admits the sink");
    let Err(refused) = ExportRows::new(&registry, dispatcher()).open(
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

/// **K9a S2 — THE VALIDATE OP, BOTH WAYS.** The FILE sink registered through the LINKED door and the
/// DROPPED-IN door answers the host's `validate` identically: settings it accepts report nothing,
/// and settings it refuses report the sink's own line under the instance — the text the host prints
/// among the configuration's errors, 1.5.5's. A module that is not an export row is not the axis's
/// to judge. RED ARM: a door whose table predates `validate` is never bound.
#[test]
fn a_sink_validates_its_settings_the_same_through_either_door() {
    let name = "s2-sink";
    let Some(doors) = both(manifest(name, file_declares()), FILE_DOOR, FILE_CDYLIB) else {
        eprintln!("skip: the file sink's cdylib is not built");
        return;
    };
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
        (both_ways::row(&registry, name), transcript)
    });
    let line = "export.tail.settings: invalid type: integer `7`, expected a string";
    let streams = [ExportStream::Logs as u8];
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

    // RED ARM: a sink whose table predates the op. On the cold wire it answered UNSUPPORTED and the
    // host took that for "nothing to report"; on the memory ABI the table is the kind's whole table,
    // so a door without `validate` is refused at the load, naming the slot — it never reaches a
    // configuration to judge.
    assert_eq!(
        refused_at_load(door_without_validate),
        format!(
            "ops slot {} is NULL",
            busbar_contract::abi::mechanism::lifecycle::slot::VALIDATE
        )
    );
}

/// **K9a S3 — PLUGIN DIAGNOSTICS, BOTH WAYS.** The request-log WEBHOOK sink, its manifest declaring
/// the `BUSBAR-NNNN` codes it raises (its own `declares.json`), registered through the LINKED door
/// and the DROPPED-IN door: both rows state the same declaration and are FIRST-PARTY — which is
/// everything the composition root reads to register the codes into the host's catalogue
/// (`root::linked::declared_diagnostics`, whose own tests hold the catalogue half) — and the sink
/// raising a code (a delivery whose connection the host could not make: BUSBAR-7072) hands the host
/// the same diagnostic either way. RED ARM, in the same test: the same declaration dropped in by a
/// THIRD party is not first-party, which the root refuses.
#[test]
fn a_declared_diagnostic_is_stated_and_raised_the_same_through_either_door() {
    let decl = webhook_declares();
    assert!(decl.diagnostics.iter().any(|d| d.code == 7072), "{decl:?}");
    let name = "s3-fixture";
    let Some(doors) = both(manifest(name, decl.clone()), WEBHOOK_DOOR, WEBHOOK_CDYLIB) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
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
        (both_ways::row(&registry, name), transcript)
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

    // RED ARM: a third party's declaration is not first-party.
    let lib = cdylib_bytes(WEBHOOK_CDYLIB).expect("built above");
    let mut third = stating(manifest("s3-third-party", decl.clone()), WEBHOOK_DOOR);
    third.publisher = "acme".into();
    let registry = both_ways::dropped_third_party(WEBHOOK_CDYLIB, third, &lib);
    let row = registry.resolve("s3-third-party").expect("admitted");
    assert_eq!(row.manifest.declares.diagnostics, decl.diagnostics);
    assert!(!row.first_party());
}

/// **K9a S4 — THE DESTINATION HANDLE, BOTH WAYS.** The request-log FILE sink, its manifest declaring
/// the `path` settings key a destination, registered through the LINKED door and the DROPPED-IN door
/// and opened with the operator's path: each delivery has the HOST append the batch
/// (`disk.append`: the sink names the key; the host appends to the path it bound), rotating at the
/// sink's `rotate_mb` — and both doors leave the same files and report the same observations. RED
/// ARM, in the same test: the same sink whose manifest does NOT declare the key is refused every
/// write — the path the operator's settings name is never created — and it reports the refusals
/// (its BUSBAR-7074 line).
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
    // Two lines fill the MiB; the third has the host rotate first.
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
            "live": ns(&path),
            "archive": ns(&archive(&path, 1)),
            "folds": tape.seen(),
        })
        .to_string()
    };
    let Some(doors) = both(declaring("s4-fixture", true), FILE_DOOR, FILE_CDYLIB) else {
        eprintln!("skip: the file sink's cdylib is not built");
        return;
    };
    let [linked, dropped] = doors.map(|registry| {
        let on_disk =
            |_: &Tape| ns(&path) == Some(vec![3, 4]) && ns(&archive(&path, 1)) == Some(vec![1, 2]);
        (
            both_ways::row(&registry, "s4-fixture"),
            run(&registry, "s4-fixture", &on_disk),
        )
    });
    assert!(linked.1.contains(r#""archive":[1,2]"#), "{}", linked.1);
    assert!(linked.1.contains(r#""live":[3,4]"#), "{}", linked.1);
    assert!(
        linked.1.contains("request-log file rotated by rename"),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors write and rotate the same");

    // RED ARM: undeclared, the key is not a destination — every write refused, nothing created,
    // and the sink reports each refusal as its open-failed line.
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            stating(declaring("s4-undeclared", false), FILE_DOOR),
            FILE_DOOR,
        )])
        .expect("the linked door admits the sink");
    let refused = run(&registry, "s4-undeclared", &|tape| {
        tape.count(busbar_export_file::OPEN_FAILED) == 4
    });
    let _ = std::fs::remove_dir_all(&dir);
    assert!(refused.contains(r#""live":null"#), "{refused}");
    assert_eq!(
        refused.matches(busbar_export_file::OPEN_FAILED).count(),
        4,
        "one refusal line per delivery: {refused}"
    );
    assert!(
        refused.contains(crate::dispatch::services::NO_DESTINATION),
        "the host's refusal, in its words: {refused}"
    );
}

/// **K9a S5 — THE HOST-CARRIED OUTBOUND REQUEST, BOTH WAYS.** The request-log WEBHOOK sink
/// registered through the LINKED door and the DROPPED-IN door, opened with a `url`: its need (open
/// web, framed by `http`, its target the `url` setting) is declared on the HOST's connection table,
/// and each delivery has the HOST carry the POST (the sink never dials) — both doors hand the table
/// the same requests and fold the same answer: nothing, for a far end that accepted every line, as
/// the 1.5.5 webhook reported nothing. RED ARM, in the same test: a target the host's policy refuses
/// never reaches the wire — nothing is carried — and the sink is told at its admission, and reports
/// it (its BUSBAR-7070 line: the exporter is disabled).
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
    let Some(doors) = both(m.clone(), WEBHOOK_DOOR, WEBHOOK_CDYLIB) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    let [linked, dropped] = doors.map(|registry| {
        (
            both_ways::row(&registry, name),
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

    // RED ARM: the policy refuses the target — nothing is carried, and the sink reports it.
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

/// **K9c — CHECK, BOTH WAYS.** The sinks' own checks across their instances, through either door:
/// the FILE sink (which takes the SDK's default `check`) has nothing to say at either phase, and the
/// WEBHOOK sink judges its instances in 1.5.5's words — its in-flight bound AMONG the operational
/// limits' checks and each instance's delivery deadline AFTER them — identically through either
/// door. A module that is not an export row is not the axis's. RED ARM: a door whose table predates
/// `check` is never bound.
#[test]
fn a_sink_starts_and_checks_the_same_through_either_door() {
    let Some(files) = both(
        manifest("k9c-sink", file_declares()),
        FILE_DOOR,
        FILE_CDYLIB,
    ) else {
        eprintln!("skip: the file sink's cdylib is not built");
        return;
    };
    let Some(hooks) = both(
        manifest("k9c-hook", webhook_declares()),
        WEBHOOK_DOOR,
        WEBHOOK_CDYLIB,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    let file_instances = [("tail".to_string(), serde_json::json!({ "path": "/tmp/x" }))];
    let hook_instances = [(
        "audit".to_string(),
        serde_json::json!({
            "url": "https://collector.example/in",
            "max_inflight_deliveries": 0,
            "delivery_timeout_secs": 0,
        }),
    )];
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

    // RED ARM: a sink whose table predates `check`. On the cold wire the host took UNSUPPORTED for
    // "no lines"; on the memory ABI such a door is refused at the load, naming the slot.
    assert_eq!(
        refused_at_load(door_without_check),
        format!(
            "ops slot {} is NULL",
            busbar_contract::abi::export::slot::CHECK
        )
    );
}

/// **K9e-2 — A DECLARED EGRESS POLICY, AND EVERY REQUEST THE SINK ASKS FOR MEETS IT.** On the export
/// kind's memory ABI a sink's egress is the egress CLASS of the need its Statement declares, and the
/// HOST's connection table judges every connection of that need under it. The WEBHOOK sink, linked
/// and dropped in, declares its one need on the table under the open-web class, framed by `http`,
/// its target the `url` setting — identically through either door. The manifest spelling of a
/// declared policy (`declares.egress`) still reads and writes as the manifest grammar states it.
#[test]
fn a_declared_egress_policy_is_granted_to_a_first_party_sink_only() {
    use crate::EgressPolicy;
    // The declaration's manifest spelling; the default is left off the signed bytes.
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
    let Some(doors) = both(
        manifest(name, webhook_declares()),
        WEBHOOK_DOOR,
        WEBHOOK_CDYLIB,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
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

/// Releases the far end when dropped.
struct Released(Arc<Far>);

impl Drop for Released {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// **K9c — A SINK'S DELIVERIES IN FLIGHT ARE BOUNDED BY ITS ADMISSION ALONE** (ARCHITECT ruling
/// MAX-INFLIGHT 2026-10-03). The request-log WEBHOOK sink, every delivery a host-carried POST,
/// LINKED and DROPPED IN, its instance configured with an in-flight bound of 600
/// (`max_inflight_deliveries`) — above the runtime's 512 blocking threads, on a dispatcher of ONE
/// worker. With the far end holding every request, 600 deliveries are in flight at once, each
/// pending on the host's connection table with no thread waiting, and never more: the 601st waits
/// its turn in the instance's queue and is carried once the far end answers. The effective
/// concurrency is the configured bound, as the 1.5.5 webhook's async deliveries were. (RED: one
/// batch at a time per instance holds 1; a delivery that holds a thread while the far end answers
/// plateaus at the pool.)
#[test]
fn a_sinks_deliveries_in_flight_reach_its_admission_bound_past_the_blocking_pool() {
    const BOUND: usize = 600;
    let name = "k9c-bound";
    let Some(doors) = both(
        manifest(name, webhook_declares()),
        WEBHOOK_DOOR,
        WEBHOOK_CDYLIB,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
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
        // Declared after the sink, so dropped before it: a failing arm still lets the far end
        // answer, and the instance's drop (which waits for its deliveries) returns.
        let _answer = Released(far.clone());
        for n in 0..=BOUND {
            deliver(sink.as_ref(), &serde_json::json!({ "n": n }));
        }
        until("every admitted delivery in flight", || {
            far.stalled() == BOUND
        });
        // Held a moment longer: nothing beyond the bound joins.
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

/// **K9e-2 — A FIRST-PARTY EGRESS CLASS IS GRANTED TO A FIRST-PARTY PLUGIN ONLY** (`BUSBAR-1.6.0.md`
/// §5; ARCHITECT ruling EGRESS-GRANT 2026-10-03). The OTLP trace sink's one need is in the
/// `loopback-allowed` class (a collector's loopback plaintext), a first-party grant: LINKED, and
/// DROPPED IN signed by the release key, it is admitted and opens through either door. RED ARM: the
/// same cdylib dropped in by a THIRD party (allowlisted, trusted, not first-party) is refused at the
/// load — the scan never admits it, and an instance naming it is refused with the grant's words —
/// while the webhook sink, whose need is in the open web, is admitted from the same third party.
#[test]
fn a_first_party_egress_class_is_refused_to_a_third_party_at_load() {
    let otlp: DoorFn = busbar_export_otlp::door::door;
    let settings = serde_json::json!({ "url": "http://127.0.0.1:4318/v1/traces" });
    let Some(doors) = both(
        manifest("k9e2-otlp", Declares::default()),
        otlp,
        "busbar_export_otlp_plugin",
    ) else {
        eprintln!("skip: the OTLP sink's cdylib is not built");
        return;
    };
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

    // RED ARM: the same collector from a third party is refused at the load.
    let lib = cdylib_bytes("busbar_export_otlp_plugin").expect("built above");
    let mut third = stating(manifest("k9e2-third-otlp", Declares::default()), otlp);
    third.publisher = "acme".into();
    let registry = both_ways::dropped_third_party("busbar_export_otlp_plugin", third, &lib);
    assert!(
        registry.resolve("k9e2-third-otlp").is_none(),
        "never admitted"
    );
    let words = "declares a `http` need in the `loopback-allowed` egress class, which the host \
                 grants to a first-party plugin only";
    let skipped = registry
        .unresolved_reason("k9e2-third-otlp")
        .expect("the scan names its refusal");
    assert_eq!(skipped.kind, crate::sign::RejectKind::EgressGrant);
    assert!(skipped.reason.contains(words), "{}", skipped.reason);
    let Err(refused) = ExportRows::new(&registry, dispatcher())
        .with_conns(Arc::new(Far::default()))
        .open("k9e2-third-otlp", "export.trace", &settings)
    else {
        panic!("a third party's collector opened");
    };
    assert!(refused.contains(words), "{refused}");

    // The open web is any trusted plugin's: the webhook from the same third party is admitted.
    let lib = cdylib_bytes(WEBHOOK_CDYLIB).expect("built");
    let mut third = stating(
        manifest("k9e2-third-hook", webhook_declares()),
        WEBHOOK_DOOR,
    );
    third.publisher = "acme".into();
    let registry = both_ways::dropped_third_party(WEBHOOK_CDYLIB, third, &lib);
    let row = registry.resolve("k9e2-third-hook").expect("admitted");
    assert!(!row.first_party());
}

/// **#85 — AN OPENED SINK'S ENVELOPE REACHES THE HOST'S OBSERVABILITY, NEVER DISCARDED** (ARCHITECT
/// rulings ENVELOPE and ENVELOPE-ALL 2026-10-03). The dispatcher stands the host's observability
/// before every door's bound sink (the export opener's included): what an opened
/// instance REPORTS — a metric of a family its Statement declares, a declared diagnostic — is handed
/// to the installed observer (the one fold every plugin's back-channel takes) under the plugin's
/// name and kind, named by what its Statement declares; behind `plugins.logs` the declared
/// diagnostic ALSO lands in the plugin's own log. Driven through the FILE sink's real Statement
/// (linked and dropped in alike: the sink is built from the stated rendering either door states).
/// RED: before the ruling the opener bound `NoSink`, and nothing reached the observer. The binding
/// itself is held per kind in `observe`'s tests.
#[test]
fn an_opened_sinks_envelope_reaches_the_host_observability() {
    use crate::dispatch::EnvelopeSink as _;
    let guard = crate::observe::testing::exclusive();
    let stated = rendering_of(FILE_DOOR).expect("renders");
    // A sink named by the FILE sink's own Statement.
    let sink = crate::observe::EnvelopeObserver::of(
        "busbar-export-file",
        busbar_contract::abi::mechanism::kind::EXPORT,
        &stated,
    );
    // A metric of a family the Statement declares, named by the family: a counter with one label.
    let counted = crate::observe::EnvelopeObserver::with_families(
        "busbar-export-file",
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
    // A family index past the Statement's is nobody's: nothing is folded for it.
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
        text: b"busbar_export_file: a log record",
    });
    let folds = crate::observe::testing::folds();
    assert_eq!(
        folds.len(),
        1,
        "one observation; the log record is not one: {folds:?}"
    );
    let (plugin, kind, metrics, diagnostics) = &folds[0];
    assert_eq!(
        (plugin.as_str(), kind.as_str()),
        ("busbar-export-file", "export")
    );
    assert!(metrics.is_empty());
    assert_eq!(diagnostics[0]["code"], "BUSBAR-7074");
    assert_eq!(diagnostics[0]["level"], "warn");

    // Behind `plugins.logs`, the declared diagnostic reaches both the plugin log and the observer.
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
    // As the dispatcher binds every door: the host's observability before the binder's log sink.
    let behind = crate::observe::EnvelopeObserver::before(
        Arc::new(
            logs.sink(
                "export.tail",
                busbar_contract::abi::mechanism::KindCode::Export,
                Arc::new(crate::dispatch::NoSink),
            )
            .expect("a log sink"),
        ),
        "busbar-export-file",
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

/// **K9a S7 — A CLOSED SPAN REACHES A COLLECTOR THE SAME THROUGH EITHER DOOR.** The OTLP trace
/// sink (its need in the `loopback-allowed` class: a first-party collector), LINKED and DROPPED IN
/// signed by the release key, is handed the same `traces` record — a closed span as the kernel's
/// producer writes it — and the HOST carries the same OTLP/HTTP request for it to the collector,
/// byte for byte: `POST` to the configured path, `application/x-protobuf`, one
/// `ExportTraceServiceRequest` holding the span's identity. (The shipped binary's end-to-end proof
/// cannot drop in a FIRST-PARTY collector — its release key's private half is not the test's — so
/// the both-doors identity of span delivery is held here, where the release key is the test's.)
#[test]
fn a_closed_span_reaches_a_collector_the_same_through_either_door() {
    let otlp: DoorFn = busbar_export_otlp::door::door;
    let name = "s7-otlp";
    let Some(doors) = both(
        manifest(name, Declares::default()),
        otlp,
        "busbar_export_otlp_plugin",
    ) else {
        eprintln!("skip: the OTLP sink's cdylib is not built");
        return;
    };
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
