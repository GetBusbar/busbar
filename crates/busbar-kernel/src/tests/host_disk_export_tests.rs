// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// These are the host's physical disk and callback-custody obligations. The exporter
// is an independently built product input; the disk lane and every append are real.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::export::{slot as export_slot, DeliverIn, ExportStream, Ops};
use busbar_contract::abi::mechanism::call::{
    Diag, MetricEntry, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_JSONL, DIAG_LOG,
    DIAG_LOG_DROPPED,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::OpsHead;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelIn, CancelOut, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::export_calls::{Delivered, ExportCalls};
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_dropped_bytes, load_linked, rendering_of, rendering_of_library, Bind,
    ConnTable, Diagnostic, DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow,
    Metric, NoSink, Plugin,
};
use busbar_plugin_loader::export_axis::ExportRows;
use busbar_plugin_loader::export_door::ExportInstance;
use busbar_plugin_loader::sign::{Declares, Manifest};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

use crate::host_disk::{append, Append, DiskLane, LANE_BOUND};
use crate::host_services::KernelServices;

const FILE_DOOR: DoorFn = file_door;

fn input(variable: &str) -> PathBuf {
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

// load_dropped holds the actual image before the public loader reports its descriptor
// address. The extra native-library reference is released only after a holder exists.
extern "C" fn file_door() -> &'static Door {
    static IMAGE: OnceLock<(Plugin<Export>, Arc<Dispatcher>, usize)> = OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let path = input("BUSBAR_TEST_EXPORT_FILE_CDYLIB");
        let stated = rendering_of_library(&path)
            .expect("read the actual file Statement")
            .expect("the actual file image exports its door");
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let held = load_dropped::<Export>(
            &path,
            &stated,
            Bind {
                instance: Arc::from("file-descriptor-holder"),
                max_inflight_cap: 1,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("hold the actual file image");
        let address = busbar_plugin_loader::dispatch::load::door_addresses_of_library(&path)
            .expect("read the held image's addresses")
            .expect("the actual file door")
            .0;
        assert_ne!(address, 0);
        (held, dispatcher, address)
    });
    // SAFETY: the loader validated this actual descriptor; IMAGE holds its library and
    // dispatcher for the process, and the descriptor is immutable product data.
    unsafe { &*(image.2 as *const Door) }
}

#[derive(Default)]
struct Tape(Mutex<Vec<String>>);
impl Tape {
    fn seen(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn count(&self, needle: &str) -> usize {
        self.seen()
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }
}
impl EnvelopeSink for Tape {
    fn metric(&self, metric: Metric<'_>) {
        self.0.lock().unwrap().push(format!(
            "metric {} {} {}",
            metric.family, metric.kind, metric.value
        ));
    }
    fn diag(&self, diagnostic: Diagnostic<'_>) {
        let text = String::from_utf8_lossy(diagnostic.text);
        let line = match diagnostic.id {
            busbar_contract::abi::mechanism::call::DIAG_LOG => {
                format!("log {} {text}", diagnostic.severity)
            }
            busbar_contract::abi::mechanism::call::DIAG_LOG_DROPPED => {
                format!("logs-dropped {text}")
            }
            id => format!("diag {id} {} {text}", diagnostic.severity),
        };
        self.0.lock().unwrap().push(line);
    }
    fn dropped(&self, why: Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn file_declaration() -> Declares {
    Declares::from_declares_json(
        &std::fs::read(input("BUSBAR_TEST_EXPORT_FILE_DECLARES"))
            .expect("the actual file declaration"),
    )
    .expect("the actual file declaration parses")
}
fn file_declares() -> Declares {
    let mut declared = file_declaration();
    declared.metrics.clear();
    declared
}
fn file_manifest(name: &str, declares: Declares) -> Manifest {
    let mut manifest: Manifest = serde_json::from_slice(
        &std::fs::read(input("BUSBAR_TEST_EXPORT_FILE_MANIFEST"))
            .expect("the actual file manifest"),
    )
    .expect("the actual manifest parses");
    manifest.name = name.into();
    manifest.alias = name.into();
    manifest.declares = declares;
    manifest.statement = Some(hex::encode(
        rendering_of(FILE_DOOR).expect("the actual file Statement"),
    ));
    manifest
}
fn file_registries(manifest: Manifest) -> [PluginRegistry; 2] {
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(manifest.clone(), FILE_DOOR)])
        .expect("the actual descriptor admits");
    let release = busbar_plugin_loader::sign::SigningKey::from_bytes(&[11; 32]);
    let signer = if manifest.publisher == busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER {
        release.clone()
    } else {
        busbar_plugin_loader::sign::SigningKey::from_bytes(&[22; 32])
    };
    let publisher = (manifest.publisher.clone(), signer.verifying_key());
    let bytes = std::fs::read(input("BUSBAR_TEST_EXPORT_FILE_CDYLIB")).unwrap();
    let signed = busbar_plugin_loader::sign::sign(&signer, manifest, &bytes);
    let dir = scratch("actual-file-package");
    std::fs::write(
        dir.join("exporter.tar.gz"),
        busbar_plugin_loader::tarball::package(&signed, "exporter", &bytes).unwrap(),
    )
    .unwrap();
    let policy = busbar_plugin_loader::sign::TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        first_party_keys: vec![busbar_plugin_loader::sign::FirstPartyKey::unnamed(
            release.verifying_key(),
        )],
        publishers: std::iter::once(publisher)
            .filter(|(_, key)| *key != release.verifying_key())
            .collect(),
        binary_version: signed.version.clone(),
        ..Default::default()
    };
    let dropped = busbar_plugin_loader::scan_and_validate(&dir, &policy)
        .expect("the actual byte package admits");
    std::fs::remove_dir_all(dir).unwrap();
    [linked, dropped]
}
fn renaming(mut declared: Declares) -> Declares {
    declared.keep.insert("path".into(), 2);
    declared
}
fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(KernelServices::new()),
    ))
}
fn instance_label(base: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{base}-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}
fn bind(label: &str, tape: Arc<Tape>, dispatcher: &Dispatcher) -> Bind {
    Bind {
        instance: instance_label(label).into(),
        max_inflight_cap: 64,
        sink: tape,
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::NoNeeds,
    }
}
fn load_file(dropped: bool, dispatcher: &Dispatcher, tape: Arc<Tape>) -> Plugin<Export> {
    let binding = bind("actual-file-host-policy", tape, dispatcher);
    if dropped {
        let path = input("BUSBAR_TEST_EXPORT_FILE_CDYLIB");
        let stated = rendering_of_library(&path).unwrap().unwrap();
        load_dropped_bytes::<Export>(
            &std::fs::read(path).unwrap(),
            "actual-file-host-policy",
            &stated,
            binding,
        )
        .expect("the actual byte-drop loads")
    } else {
        load_linked::<Export>(&LinkedRow::of(FILE_DOOR).unwrap(), binding)
            .expect("the actual descriptor loads")
    }
}
fn opened(
    plugin: Plugin<Export>,
    dispatcher: Arc<Dispatcher>,
    settings: &serde_json::Value,
) -> ExportInstance {
    plugin.grant_destinations(&renaming(file_declares()));
    ExportInstance::open(plugin, dispatcher, settings.to_string().as_bytes())
        .expect("the actual file sink opens")
}
fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn deliver(sink: &dyn ExportCalls, line: &serde_json::Value) {
    assert!(matches!(
        sink.deliver(
            ExportStream::Logs as u8,
            line.to_string().into_bytes(),
            Box::new(())
        ),
        Delivered::Queued
    ));
}
fn line(n: u32, pad: usize) -> serde_json::Value {
    serde_json::json!({"n": n, "pad": "x".repeat(pad)})
}
fn big_line(n: u32) -> serde_json::Value {
    line(n, 1_100_000)
}
fn ns_of(text: &str) -> Option<Vec<u64>> {
    if !text.is_empty() && !text.ends_with('\n') {
        return None;
    }
    text.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).ok()?["n"].as_u64())
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
    super::dir(tag)
}
fn file_settings(path: &Path) -> serde_json::Value {
    serde_json::json!({"path": path.display().to_string(), "rotate_mb": 1})
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
fn run_origin(dropped: bool, path: &Path) -> Vec<String> {
    let tape = Arc::new(Tape::default());
    let dispatcher = dispatcher();
    let sink = opened(
        load_file(dropped, &dispatcher, tape.clone()),
        dispatcher,
        &file_settings(path),
    );
    script(&sink, path);
    drop(sink);
    tape.seen()
}
fn run_compiled_in(path: &Path) -> Vec<String> {
    run_origin(false, path)
}
fn run_dropped_in(path: &Path) -> Vec<String> {
    run_origin(true, path)
}
fn rotated_record(path: &Path) -> String {
    format!(
        "log 0 busbar_export_file: request-log file rotated by rename path={p} archive={p}.1",
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
fn the_operators_keep_beside_a_destination_outranks_the_manifest() {
    for dropped in [false, true] {
        let dir = scratch("operator-keep");
        let path = dir.join("requests.jsonl");
        let d = dispatcher();
        let plugin = load_file(dropped, &d, Arc::new(Tape::default()));
        plugin.grant_destinations(&file_declares());
        let mut settings = file_settings(&path);
        settings["keep"] = serde_json::json!(2);
        let sink = ExportInstance::open(plugin, d, settings.to_string().as_bytes()).expect("opens");
        for n in 1..=4 {
            deliver(&sink, &line(n, 600_000));
        }
        until("the four lines landed", || ns(&path) == Some(vec![3, 4]));
        drop(sink);
        assert_eq!(
            ns_settled(&archive(&path, 1)),
            Some(vec![1, 2]),
            "the rotated lines are kept in the first archive"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn declared_destination_writes_and_undeclared_destination_refuses_each_delivery_both_origins() {
    let dir = scratch("declared-disk");
    let path = dir.join("requests.jsonl");
    let run = |dropped: bool, declared: bool| {
        let _ = std::fs::remove_file(&path);
        let d = dispatcher();
        let tape = Arc::new(Tape::default());
        let plugin = load_file(dropped, &d, tape.clone());
        let mut grants = file_declares();
        // This policy input grants a destination with no retention declaration:
        // the host must truncate it, whatever retention the product normally declares.
        grants.keep.clear();
        if !declared {
            grants.destinations.clear();
        }
        plugin.grant_destinations(&grants);
        let sink = ExportInstance::open(plugin, d, file_settings(&path).to_string().as_bytes())
            .expect("opens");
        for n in 1..=4 {
            deliver(&sink, &line(n, 600_000));
        }
        until("the four deliveries answered", || {
            if declared {
                ns(&path) == Some(vec![3, 4]) && !archive(&path, 1).exists()
            } else {
                tape.count("BUSBAR-7074") == 4
            }
        });
        drop(sink);
        serde_json::json!({"live":ns_settled(&path),"archive":ns_settled(&archive(&path,1)),"folds":tape.seen()}).to_string()
    };
    let linked = run(false, true);
    let dropped = run(true, true);
    assert!(linked.contains(r#""archive":null"#), "{linked}");
    assert!(linked.contains(r#""live":[3,4]"#), "{linked}");
    assert!(!linked.contains("request-log file rotated"), "{linked}");
    assert_eq!(linked, dropped, "both doors write and rotate the same");
    for dropped in [false, true] {
        let refused = run(dropped, false);
        assert!(refused.contains(r#""live":null"#), "{refused}");
        assert_eq!(
            refused.matches("BUSBAR-7074").count(),
            4,
            "one refusal line per delivery: {refused}"
        );
        assert!(
            refused.contains(busbar_plugin_loader::dispatch::services::NO_DESTINATION),
            "the host's refusal, in its words: {refused}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

// A real DiskLane with only its worker scheduling held by the test. Append is the
// production queue item; both the owned destination and its original callback stay
// together until complete() runs the unmodified append implementation.
struct HeldDisk {
    lane: Arc<DiskLane>,
    receiver: Mutex<std::sync::mpsc::Receiver<Append>>,
    held: Mutex<VecDeque<Append>>,
}
impl Default for HeldDisk {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(LANE_BOUND);
        let lane = Arc::new(DiskLane::default());
        assert!(lane.tx.set(Some(tx)).is_ok());
        Self {
            lane,
            receiver: Mutex::new(rx),
            held: Mutex::new(VecDeque::new()),
        }
    }
}
impl HeldDisk {
    fn pending(&self) -> usize {
        let receiver = self.receiver.lock().unwrap();
        let mut held = self.held.lock().unwrap();
        held.extend(receiver.try_iter());
        held.len()
    }
    fn complete(&self) -> String {
        self.pending();
        let Append { dest, bytes, later } = self.held.lock().unwrap().pop_front().unwrap();
        let path = dest.path.clone();
        later(append(&dest, &bytes).stored());
        path
    }
}

fn batch(bytes: &[u8], id: u8) -> Frame<DeliverIn, busbar_contract::abi::mechanism::call::OutHead> {
    let mut input: DeliverIn = busbar_contract::abi::sdk::door::blank_in();
    input.head = busbar_plugin_loader::dispatch::in_head();
    input.op_id = [id; 16];
    input.stream = ExportStream::Logs as u8;
    input.batch = busbar_contract::abi::mechanism::call::Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSONL,
        flags: 0,
    };
    Frame::new(input, busbar_plugin_loader::dispatch::out_head())
}
fn release(plugin: &Plugin<Export>, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut input: busbar_contract::abi::mechanism::lifecycle::ReleaseIn =
        busbar_contract::abi::sdk::door::blank_in();
    input.head = busbar_plugin_loader::dispatch::in_head();
    input.lease = lease;
    let mut frame = Frame::new(input, busbar_plugin_loader::dispatch::out_head());
    let _ = plugin.call(life::RELEASE, &mut frame);
}
fn refresh(plugin: &Plugin<Export>, settings: &serde_json::Value, generation: u64) -> Outcome {
    let bytes = settings.to_string();
    let mut input: RefreshIn = busbar_contract::abi::sdk::door::blank_in();
    input.head = busbar_plugin_loader::dispatch::in_head();
    input.generation = generation;
    input.settings = busbar_contract::abi::mechanism::call::Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut frame = Frame::new(input, busbar_plugin_loader::dispatch::out_head());
    let called = plugin.call(life::REFRESH, &mut frame);
    release(plugin, called.lease);
    called.outcome
}
// An inline ticket recycles its generation when dropped; it does not cancel the
// plugin's outstanding loan. This owner therefore retires the actual call before
// either its stable frame or its batch bytes can be released, including on unwind.
struct PendingDiskDelivery {
    ticket: busbar_plugin_loader::dispatch::InlineTicket,
    frame: Box<Frame<DeliverIn, OutHead>>,
    _payload: Box<[u8]>,
    sink: Arc<ExportInstance>,
    may_be_pending: bool,
}

impl PendingDiskDelivery {
    fn new(sink: Arc<ExportInstance>, dispatcher: &Dispatcher, bytes: &[u8], id: u8) -> Self {
        let payload = bytes.to_vec().into_boxed_slice();
        let frame = Box::new(batch(&payload, id));
        Self {
            ticket: dispatcher
                .inline_ticket()
                .expect("an inline delivery ticket"),
            frame,
            _payload: payload,
            sink,
            may_be_pending: false,
        }
    }

    fn ticket(&self) -> Ticket {
        self.ticket.ticket()
    }

    fn cross(&mut self, resume: bool) -> Outcome {
        // A panic after entry must also cancel while the original allocations live.
        self.may_be_pending = true;
        let ticket = self.ticket();
        let called =
            self.sink
                .plugin()
                .call_inline(ticket, resume, export_slot::DELIVER, &mut *self.frame);
        // READY proves completion. A host-side refusal may precede plugin entry,
        // so conservatively retain custody on every other unexpected answer.
        if called.outcome == Outcome::Ready {
            self.may_be_pending = false;
        }
        release(self.sink.plugin(), called.lease);
        called.outcome
    }

    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let outcome = self.cross(true);
            if outcome == Outcome::Ready {
                return;
            }
            assert_eq!(outcome, Outcome::Pending);
            assert!(
                Instant::now() < deadline,
                "export delivery never resumed to READY"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn cancel(&mut self) -> Outcome {
        let mut input: CancelIn = busbar_contract::abi::sdk::door::blank_in();
        input.head = busbar_plugin_loader::dispatch::in_head();
        input.ticket = self.ticket();
        let mut output: CancelOut = busbar_contract::abi::sdk::door::blank_out();
        output.head = busbar_plugin_loader::dispatch::out_head();
        let mut frame = Frame::new(input, output);
        let called = self.sink.plugin().call(life::CANCEL, &mut frame);
        if called.outcome == Outcome::Ready {
            self.may_be_pending = false;
        }
        release(self.sink.plugin(), called.lease);
        called.outcome
    }
}

impl Drop for PendingDiskDelivery {
    fn drop(&mut self) {
        if self.may_be_pending {
            let outcome = self.cancel();
            if outcome != Outcome::Ready {
                // No unwind may free a loan whose retirement was not confirmed.
                // This is a failing test process, with every owner still intact.
                use std::io::Write as _;
                let _ = writeln!(std::io::stderr(),
                    "actual exporter cancellation answered {outcome:?}; stopping with its pending frame owned");
                std::process::abort();
            }
        }
    }
}

#[test]
fn pending_export_disk_append_keeps_old_path_and_cancelled_late_reply_cannot_reach_reused_ticket_both_doors(
) {
    for dropped in [false, true] {
        let dir = scratch(if dropped {
            "refresh-disk-dropped"
        } else {
            "refresh-disk-linked"
        });
        let a = dir.join("a.jsonl");
        let b = dir.join("b.jsonl");
        let c = dir.join("c.jsonl");
        let disk = Arc::new(HeldDisk::default());
        let d = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(KernelServices::new().with_disk_lane(disk.lane.clone())),
        ));
        let plugin = load_file(dropped, &d, Arc::new(Tape::default()));
        let sink = Arc::new(opened(plugin, d.clone(), &file_settings(&a)));
        let mut old = PendingDiskDelivery::new(Arc::clone(&sink), &d, b"{\"n\":1}\n", 4);
        assert_eq!(old.cross(false), Outcome::Pending);
        until("the old disk append is held", || disk.pending() == 1);
        assert_eq!(
            refresh(sink.plugin(), &file_settings(&b), 2),
            Outcome::Ready
        );
        let mut fresh = PendingDiskDelivery::new(Arc::clone(&sink), &d, b"{\"n\":2}\n", 5);
        assert_eq!(fresh.cross(false), Outcome::Pending);
        until("both disk appends are held", || disk.pending() == 2);
        assert_eq!(disk.complete(), a.display().to_string());
        old.finish();
        assert_eq!(disk.complete(), b.display().to_string());
        fresh.finish();
        drop(old);
        drop(fresh);
        assert_eq!(ns(&a), Some(vec![1]));
        assert_eq!(ns(&b), Some(vec![2]));
        let rejected = serde_json::json!({"path":c,"bogus":1});
        assert_ne!(refresh(sink.plugin(), &rejected, 3), Outcome::Ready);

        let mut cancelled = PendingDiskDelivery::new(Arc::clone(&sink), &d, b"{\"n\":3}\n", 6);
        let old_ticket = cancelled.ticket();
        assert_eq!(cancelled.cross(false), Outcome::Pending);
        until("the cancelled disk append is held", || disk.pending() == 1);
        assert_eq!(cancelled.cancel(), Outcome::Ready);
        drop(cancelled);
        let mut reused = PendingDiskDelivery::new(Arc::clone(&sink), &d, b"{\"n\":4}\n", 7);
        assert_eq!(reused.ticket().slot, old_ticket.slot);
        assert_ne!(reused.ticket().generation, old_ticket.generation);
        assert_eq!(reused.cross(false), Outcome::Pending);
        until("the reused ticket disk append is held", || {
            disk.pending() == 2
        });

        assert_eq!(disk.complete(), b.display().to_string());
        assert_eq!(reused.cross(true), Outcome::Pending);
        assert_eq!(disk.pending(), 1);
        assert_eq!(disk.complete(), b.display().to_string());
        reused.finish();
        drop(reused);
        assert_eq!(ns(&a), Some(vec![1]));
        assert_eq!(ns(&b), Some(vec![2, 3, 4]));
        assert!(!c.exists());
        assert!(disk.pending() == 0);
        drop(sink);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn accepted_event_json_reaches_the_actual_disk_lane_unchanged() {
    use busbar_contract::abi::export::ExportField as F;
    use busbar_contract::services::{DiskDest, DiskRotate, HostServices as _, Ran};

    const ACTION: &str = "fixture.mutate";
    const RESOURCE: &str = "fixture:accepted";
    const ACTOR: &str = "fixture-admin";
    const FIRST_SEQUENCE: u64 = 1;
    const FIXTURE_UNIX_SECONDS: u64 = 1_700_000_000;
    const ONE_RECORD: usize = 1;
    const FIRST_RECORD: usize = 0;
    let dir = scratch("accepted-event-json");
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
    let mut bytes = serde_json::to_vec(&expected).unwrap();
    bytes.push(b'\n');
    let services = KernelServices::new();
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let result = services.disk_append(
        &DiskDest {
            key: "path".into(),
            path: path.display().to_string(),
            rotate_at: None,
            rotate: DiskRotate::Truncate,
        },
        bytes,
        Box::new(move |answer| sent.send(answer).unwrap()),
    );
    assert!(
        matches!(result, Ran::Later),
        "the real disk lane keeps completion off the calling crossing"
    );
    let answer = received
        .recv_timeout(Duration::from_secs(5))
        .expect("the actual append completes");
    assert_eq!(answer.outcome, Outcome::Ready, "{answer:?}");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.ends_with('\n'),
        "the accepted event is a whole JSON line"
    );
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), ONE_RECORD);
    assert_eq!(records[FIRST_RECORD], expected);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_linked_and_a_dropped_in_export_sink_register_one_row_and_fold_the_same() {
    let name = "export-fixture";
    let doors = file_registries(file_manifest(name, renaming(file_declares())));
    let dir = scratch("k5");
    let path = dir.join("requests.jsonl");
    let [linked, dropped] = doors.map(|registry| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(&registry, dispatcher())
            .with_envelope(tape.clone())
            .open(name, &instance_label("export.tail"), &file_settings(&path))
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
    let doors = file_registries(file_manifest(name, renaming(declared.clone())));
    let dir = scratch("s1");
    let path = dir.join("requests.jsonl");
    let [linked, dropped] = doors.map(|registry| {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tape = Arc::new(Tape::default());
        let sink = ExportRows::new(&registry, Arc::clone(&d))
            .with_envelope(tape.clone())
            .open(name, &instance_label("export.tail"), &file_settings(&path))
            .expect("a first-party declaration opens");
        for n in [1, 2] {
            deliver(sink.as_ref(), &big_line(n));
        }
        until("both lines on disk", || ns(&path) == Some(vec![2]));

        let granted: Vec<bool> = series
            .iter()
            .map(|(s, k)| busbar_plugin_loader::observe::first_party_series(name, s, k))
            .collect();
        drop(sink);
        assert!(
            series
                .iter()
                .all(|(s, k)| !busbar_plugin_loader::observe::first_party_series(name, s, k)),
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

    let mut third = file_manifest("s1-third-party", declared.clone());
    third.publisher = "acme".into();
    let [_, registry] = file_registries(third);
    let sink = ExportRows::new(&registry, Arc::clone(&d))
        .open(
            "s1-third-party",
            &instance_label("export.tail"),
            &file_settings(&path),
        )
        .expect("a third party opens; its declaration is simply not granted");
    drop(sink);
    for (s, k) in &series {
        assert!(!busbar_plugin_loader::observe::first_party_series(
            "s1-third-party",
            s,
            k
        ));
    }

    let mut collides = declared;
    collides.metrics = vec![SeriesDecl::new(S1_HOST_SERIES, "counter")];
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            file_manifest("s1-collides", collides),
            FILE_DOOR,
        )])
        .expect("the linked door admits the sink");
    let Err(refused) = ExportRows::new(&registry, Arc::clone(&d)).open(
        "s1-collides",
        &instance_label("export.tail"),
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

    // The descriptor holder keeps the actual product image loaded throughout this
    // narrow envelope-withholding observer. Every op below forwards unchanged.
    let door = *FILE_DOOR();
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
