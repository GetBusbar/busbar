// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `traces` STREAM, BOTH DOORS** — K9a S7 (BUSBAR-1.6.0 18b(d)) end to end through the kernel's
//! real export axis: the kernel's traces producer turns closed tracing spans into `traces` records,
//! and a sink subscribed to `traces` is handed them the same whether it came in LINKED or DROPPED IN.
//!
//! One `["cdylib", "rlib"]` export fixture is registered twice through the one registration: its
//! `rlib`'s boundary as a LINKED row, and its `cdylib`, release-signed with its manifest declaring
//! the `path` destination (K9a S4), as a DROPPED-IN row of a scanned `plugins/` directory. The kernel
//! resolves an `export:` block naming both, opens them, and the producer is installed exactly as
//! `observability::init_logging` installs it — at the span exporter's DEBUG floor. Two spans are
//! closed (a child inside a parent); each sink has the host append every record it is handed to its
//! destination.
//!
//! The two doors must leave the SAME records (byte for byte, up to the order two concurrent
//! deliveries land in), and the records must be the producer's: the child joined to its parent by
//! `parent_span_id`, both in the parent's trace, the span's own vocabulary fields carried.
//!
//! RED ARMS, in the same test: an instance of the same sink subscribed to `logs` only is handed no
//! span (its destination is never created), and a span above the DEBUG floor (`trace`) produces no
//! record at all.
//!
//! This is its own test binary because the export axis and the opened sinks are process-global,
//! set once — as they are at boot.

use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing_subscriber::layer::SubscriberExt as _;

/// The fixture's package name, snake-cased: its `cdylib`'s file stem.
const FIXTURE: &str = "busbar_export_example_plugin";

/// The first-party manifest both doors state for the fixture under `name`, declaring `path` a
/// destination.
fn statement(name: &str) -> Manifest {
    let declares = busbar_plugin_loader::sign::Declares {
        destinations: vec!["path".into()],
        ..Default::default()
    };
    Manifest {
        name: name.into(),
        alias: name.into(),
        kind: "export".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: *busbar_plugin_loader::supported_abi("export")
            .iter()
            .max()
            .expect("an export payload schema"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares,
    }
}

/// The fixture's built `cdylib` (uplifted or under `deps`, newest wins). Under CI a missing
/// artifact is a failure, never a skip.
fn cdylib() -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let file = busbar_plugin_loader::plugin_library_filename(FIXTURE);
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the {FIXTURE} cdylib is not built under CI; a both-doors proof must not skip"
    );
    std::fs::read(found?).ok()
}

/// A fresh scratch directory for this process.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-k9e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// THE DROPPED-IN DOOR: `lib` release-signed under `manifest` into a fresh `plugins/` directory,
/// scanned under a policy holding the release key. THE LINKED DOOR joins it through
/// `PluginRegistry::link`, the same admission boot runs.
fn both_doors(lib: &[u8]) -> &'static PluginRegistry {
    let release = SigningKey::from_bytes(&[11u8; 32]);
    let dir = scratch("plugins");
    let signed = sign(&release, statement("k9e-dropped"), lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libsink.so", lib).unwrap();
    std::fs::write(dir.join("sink.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let scanned = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    let entry = &busbar_export_example_plugin::BUSBAR_COLD_ENTRY;
    let linked = LinkedPlugin::boundary(statement("k9e-linked"), entry);
    let registry = scanned
        .link(vec![linked])
        .expect("the linked door admits it");
    Box::leak(Box::new(registry))
}

/// The records a destination holds, one per line, sorted (two deliveries may land in either order).
fn records(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines.sort();
    lines
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_span_reaches_a_traces_sink_the_same_through_either_door() {
    let Some(lib) = cdylib() else {
        eprintln!("skip: the export fixture's cdylib is not built");
        return;
    };
    busbar_kernel::export::plugin::install(both_doors(&lib));
    let dir = scratch("destinations");
    let [linked, dropped, logs_only] =
        ["linked.jsonl", "dropped.jsonl", "logs.jsonl"].map(|f| dir.join(f));
    let instance = |module: &str, stream: &str, path: &Path| {
        serde_json::json!({
            "module": module,
            "streams": [stream],
            "settings": { "path": path.display().to_string() },
        })
    };
    let defs: busbar_kernel::config::ExportDefs = serde_json::from_value(serde_json::json!({
        "linked": instance("k9e-linked", "traces", &linked),
        "dropped": instance("k9e-dropped", "traces", &dropped),
        "logs-only": instance("k9e-dropped", "logs", &logs_only),
    }))
    .expect("an export: block");
    let mut errors = Vec::new();
    let cfg = busbar_kernel::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    busbar_kernel::export::plugin::open(&cfg).expect("the sinks open");

    // The producer as `init_logging` installs it: the span exporter's DEBUG floor.
    let floor = tracing_subscriber::filter::LevelFilter::DEBUG;
    let producer = busbar_kernel::export::traces::layer(floor);
    assert!(producer.is_some(), "an installed axis has a producer");
    let subscriber = tracing_subscriber::registry().with(producer);
    tracing::subscriber::with_default(subscriber, || {
        let parent = tracing::debug_span!("forward", pool = "p1", ingress = "k9e", op = "chat");
        parent.in_scope(|| {
            tracing::debug_span!("adhoc", provider = "mock", model = "m1").in_scope(|| {});
            // RED ARM: above the floor — no record.
            tracing::trace_span!("too_fine", pool = "p1").in_scope(|| {});
        });
    });

    // Delivery is off the span's thread: wait for both destinations to hold both records.
    let deadline = Instant::now() + Duration::from_secs(20);
    while records(&linked).len() < 2 || records(&dropped).len() < 2 {
        assert!(
            Instant::now() < deadline,
            "the traces records never reached both doors: linked {:?}, dropped {:?}",
            records(&linked),
            records(&dropped)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Let anything that should NOT have been delivered have its chance to land.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (through_linked, through_dropped) = (records(&linked), records(&dropped));
    assert_eq!(
        through_linked, through_dropped,
        "the two doors were not handed the same records"
    );
    assert_eq!(
        through_linked.len(),
        2,
        "one record per closed span: {through_linked:?}"
    );
    let parsed: Vec<serde_json::Value> = through_linked
        .iter()
        .map(|l| serde_json::from_str(l).expect("a JSON record"))
        .collect();
    let named = |name: &str| {
        parsed
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("no `{name}` record: {parsed:?}"))
    };
    let (parent, child) = (named("forward"), named("adhoc"));
    assert_eq!(parent["pool"], "p1");
    assert_eq!(parent["ingress"], "k9e");
    assert_eq!(parent["op"], "chat");
    assert!(parent.get("parent_span_id").is_none(), "{parent}");
    assert_eq!(
        parent["trace_id"], parent["span_id"],
        "a root is its own trace"
    );
    assert_eq!(child["provider"], "mock");
    assert_eq!(child["model"], "m1");
    assert_eq!(child["parent_span_id"], parent["span_id"]);
    assert_eq!(child["trace_id"], parent["span_id"]);
    for record in &parsed {
        assert!(
            record["start"].is_u64() && record["duration_us"].is_u64(),
            "{record}"
        );
    }

    // RED ARM: the same sink, subscribed to `logs` only, was handed no span.
    assert!(
        !logs_only.exists(),
        "a sink not subscribed to `traces` was handed spans: {:?}",
        records(&logs_only)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
