// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE #11 TEST.** One crate, built BOTH ways, must be observationally identical.
//!
//! DECISIONS #11 says every plugin is compiled-in OR dropped-in over the same contract and one
//! loading path, and that the distinction is a BUILD property and nothing more. For the `plane`
//! kind that claim already had a witness (`plane_conformance_tests`, which compares the linked
//! `PLANE_DECL` against the `dlopen`ed one). For everything a plugin OBSERVES it had none, and it
//! was FALSE:
//!
//! > a COMPILED-IN plugin can reach the process-global `metrics` recorder, while the same crate
//! > built as a dropped-in `cdylib` gets its own and silently loses the counters.
//!
//! A `cdylib` statically links its own copy of the `metrics` facade. Its recorder is not the host's,
//! nothing joins them, and every counter a dropped-in sink incremented went into a registry nobody
//! ever scrapes. The same source, built the other way, linked the host's recorder and worked. Two
//! builds, two different observable behaviours, and no test anywhere said so — which is precisely
//! why #85's envelope exists: under it, reaching a recorder is not representable from either build,
//! so both REPORT and the host folds.
//!
//! ## What this test compares, and why that is the right thing
//!
//! It runs the SAME sequence of operations against the SAME constructor reached two ways, and
//! compares what the HOST was handed on the observability back-channel — `(kind, metrics,
//! diagnostics)`, byte for byte as JSON.
//!
//! That is one step short of comparing the rendered `/metrics` text, and deliberately so at this
//! layer: this crate has no metrics recorder and must not grow one (it is the loader, not the
//! engine). The step is sound because the kernel's fold is a PURE FUNCTION of exactly this tuple —
//! `busbar_kernel::observe::fold_metrics` reads the entries, the plugin name and the kind and reads
//! nothing else — so identical tuples give identical expositions. **The end-to-end
//! `/metrics`-text-level assertion is still OWED**, and it belongs wherever a recorder legitimately
//! exists; see this module's closing test for the exact shape it should take.
//!
//! ## Red-before-green, PERMANENTLY
//!
//! [`the_pre_envelope_path_loses_a_dropped_in_plugins_counters`] is the RED arm, and it stays in the
//! file. It replays what the old arrangement did over the production seam — the real cdylib answering
//! the pre-envelope BARE response through the loader's real wire call, its counters left in a
//! registry of its own — and shows the two builds diverging. A test that only ever passes cannot tell you what
//! it is protecting you from.

use super::both_ways::{export_fixture, export_webhook_fixture};
use super::*;
use busbar_contract::abi::cold::export::{ExportRequest, ExportResponse, HostResult, Rotation};
use busbar_contract::abi::export::ExportStream;

/// The export row's sink — the request-log FILE sink — opened with a destination and a rotation
/// size, so a delivery is a host-written append the host may rotate first.
const FILE_CFG: &str = r#"{"path": "/busbar-11/requests.jsonl", "rotate_mb": 1}"#;

/// What the export row's sink carries: the request-log line.
const FILE_CARRIES: [ExportStream; 1] = [ExportStream::Logs];

/// A line too large to share a 1 MiB file with another: a delivery of it to a file that already
/// holds one has the host rotate first (`rotate_mb: 1`), and the sink counts the rotation.
fn big_line(n: u32) -> serde_json::Value {
    serde_json::json!({ "n": n, "pad": "x".repeat(1_100_000) })
}

/// A manifest of the export row stating the `path` destination its sink writes.
fn with_destination(mut m: crate::sign::Manifest) -> crate::sign::Manifest {
    m.declares.destinations = vec!["path".into()];
    m
}

/// `path`'s JSON lines as their `n` fields — what one door left on disk, independent of the pad.
fn ns(path: &std::path::Path) -> Option<Vec<u64>> {
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

/// The two arms are compared on `(kind, metrics, diagnostics)`.
///
/// The PLUGIN NAME is deliberately NOT compared. The two arms load the same crate under two
/// different display names — one is a linked handler with no file behind it, the other a staged
/// `cdylib` — and a display name is host-side provenance, not plugin behaviour. Comparing it would
/// fail the test for the one difference that is supposed to exist.
type Compared = (String, Vec<serde_json::Value>, Vec<serde_json::Value>);

/// The host-assigned names the two arms load under. They are the FILTER as well as the label: the
/// fold log is process-global and other tests in this binary legitimately load the same export
/// plugin and deliver to it, so a window-based read would pick up their folds and report them as
/// this test's divergence. Filtering by the name THIS test chose is exact.
const COMPILED_IN: &str = "#11-compiled-in";
const DROPPED_IN: &str = "#11-dropped-in";

/// Keep only `who`'s folds, and drop the host-assigned name from each — leaving what the PLUGIN
/// said, which is the thing the two arms must agree on.
fn compared(who: &str, folds: Vec<crate::observe::testing::Fold>) -> Vec<Compared> {
    folds
        .into_iter()
        .filter(|(plugin, ..)| plugin == who)
        .map(|(_, k, m, d)| (k, m, d))
        .collect()
}

/// The operations both arms run, in order.
///
/// Two deliveries, each followed by the host's answer to the write it asked for (the host rotated
/// the file first), then a `streams` query. The answers give the sink something to observe — each
/// rotation is a count; the trailing query is there to prove the OPPOSITE of what one might expect
/// — having already drained on each answer's own response, the sink has nothing left to say, so
/// `streams` answers a BARE envelope and folds nothing. A drain that leaked would show up here as a
/// third fold on one arm.
fn script() -> Vec<ExportRequest> {
    let rotated = || ExportRequest::Resume {
        token: 0,
        results: vec![HostResult::Done {
            rotation: Some(Rotation {
                archive: "/busbar-11/requests.jsonl.1".into(),
                renamed: true,
                faults: Vec::new(),
            }),
        }],
    };
    vec![
        ExportRequest::Deliver {
            stream: ExportStream::Logs,
            payload: serde_json::json!({"n": 1}),
        },
        rotated(),
        ExportRequest::Deliver {
            stream: ExportStream::Logs,
            payload: serde_json::json!({"n": 2}),
        },
        rotated(),
        ExportRequest::Streams,
    ]
}

/// Run the script against the COMPILED-IN build: the handler this crate LINKS, dispatched through
/// the SDK's own op-dispatch, its envelope folded by the host.
///
/// This is what "compiled-in" has to mean under #85 — the same constructor, the same dispatch, the
/// same fold. If a compiled-in plugin were allowed to skip the fold and touch the recorder directly
/// it would not be the same plugin, which is the entire finding.
///
/// It goes through the PLUGIN's own `dispatch_compiled_in`, not through the SDK directly, so the
/// host needs no edge to the author machinery to run this: the entry point a plugin offers is the
/// plugin's to publish, on both doors.
fn run_compiled_in() {
    let handler = export_fixture::open(FILE_CFG).expect("compiled-in ctor");
    for req in script() {
        let envelope = export_fixture::dispatch_compiled_in(handler.as_ref(), req);
        crate::observe::fold(
            COMPILED_IN,
            busbar_contract::abi::mechanism::kind::EXPORT,
            &envelope,
        );
    }
}

/// Run the same script against the DROPPED-IN build: the `cdylib` on disk, `dlopen`ed and driven
/// over the six-symbol C ABI — every op of the script sent as it is, through the loader's ONE wire
/// seam, which folds each envelope for the host.
///
/// Returns `None` when the `cdylib` is not built (a scoped `cargo test -p` of an unrelated crate);
/// under CI that is a hard failure, exactly as [`sink_cdylib`] enforces.
fn run_dropped_in() -> Option<()> {
    let path = sink_cdylib()?;
    let bytes = std::fs::read(&path).expect("read the export sink cdylib");
    let sink = crate::export::load_export_from_bytes(
        &bytes,
        FILE_CFG,
        DROPPED_IN,
        busbar_contract::abi::mechanism::kind::EXPORT,
    )
    .expect("load the export sink over the ABI");
    // `load_export_from_bytes` ALREADY ran `streams` and `routes` at load, so the script below is
    // run against a sink that has answered twice. That is fine and is the point: the two arms are
    // compared on the folds the SCRIPT produces, and a load-time query folds nothing because the
    // sink has observed nothing yet.
    assert_eq!(sink.streams(), &FILE_CARRIES);
    for req in script() {
        let answer = sink
            .raw
            .transport_call::<ExportRequest, ExportResponse>(&req)
            .expect("the op crosses the ABI");
        if let ExportResponse::Streams(s) = answer {
            assert_eq!(s, FILE_CARRIES);
        }
    }
    Some(())
}

/// Locate the built `cdylib`, checking the uplifted `<profile_dir>/<name>` copy and the
/// `<profile_dir>/deps/` compiler output (a scoped `cargo test -p` only produces the latter).
/// Under CI a missing artifact is a HARD failure, never a silent skip: the equivalence this module
/// proves is the one #11 was false about, and a test that quietly stops running where it matters is
/// worse than no test.
///
/// The sink is pulled from its own repo, so its `cdylib` is built only under `deps/`, with a
/// metadata hash: [`super::both_ways::cdylib`] finds it there, and asserts under CI.
fn sink_cdylib() -> Option<std::path::PathBuf> {
    super::both_ways::cdylib(super::both_ways::fixture("export").0)
}

/// **THE EQUIVALENCE.** The same crate, built both ways, hands the host byte-identical observations.
///
/// Before the envelope this could not pass: the dropped-in arm would have folded NOTHING (its
/// counters went into its own linked registry) while the compiled-in arm folded two deliveries. The
/// RED arm below reproduces exactly that divergence, so the difference between the two arrangements
/// is visible in one file.
#[test]
fn compiled_in_and_dropped_in_report_identical_observations() {
    let guard = crate::observe::testing::exclusive();
    run_compiled_in();
    let compiled = compared(COMPILED_IN, crate::observe::testing::folds());
    drop(guard);

    let _guard = crate::observe::testing::exclusive();
    let Some(()) = run_dropped_in() else {
        // Not built under this scoped run. `sink_cdylib` already hard-fails under CI, so this arm
        // cannot quietly disappear where it matters.
        return;
    };
    let dropped = compared(DROPPED_IN, crate::observe::testing::folds());

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

/// The observations are the ones the sink actually produced — one counter, reported as a DELTA on
/// the response of the call that produced it — so the equivalence above is over real content rather
/// than over two identical nothings.
///
/// TWO folds, not three (nor five): the handler runs and is drained WITHIN one boundary call, so
/// each rotation the host reported is counted on the response to that report, a delivery (which
/// only ASKS the host to write) observes nothing, and the trailing `streams` finds nothing left to
/// report and answers bare (a bare envelope is never folded).
#[test]
fn the_reported_observations_are_the_ones_the_sink_produced() {
    let _guard = crate::observe::testing::exclusive();
    run_compiled_in();
    let folds = compared(COMPILED_IN, crate::observe::testing::folds());
    assert_eq!(folds.len(), 2, "folds: {folds:?}");
    for (kind, metrics, diagnostics) in &folds {
        assert_eq!(kind, busbar_contract::abi::mechanism::kind::EXPORT);
        assert!(diagnostics.is_empty());
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0]["name"], export_fixture::ROTATED_TOTAL);
        assert_eq!(metrics[0]["type"], "counter");
        // A DELTA of one, not a running total of one-then-two.
        assert_eq!(metrics[0]["value"], 1.0);
    }
}

/// **THE AXIS, BOTH WAYS** (DECISIONS #2 rule (1), K5's harness, item 141). The export kind's
/// fixture (reached by KIND, `[package.metadata.busbar.both-ways]`) registered through the LINKED
/// door (its `rlib`'s `BUSBAR_COLD_ENTRY`, through
/// [`PluginRegistry::link`]) and the DROPPED-IN door (its `cdylib`, signed into `plugins/`) resolves to
/// the byte-identical registry row, and the sink each door's `open_export` opens — the one load over
/// either image — answers the same streams and routes and hands the host byte-identical folds for
/// the same script. This is the equivalence above taken through the real registration and load a
/// node runs, rather than through the SDK's op-dispatch.
///
/// RED by taking `export` out of the linked door's kinds (what the tree had before item 141):
/// `link` refuses the row and the linked arm never opens.
#[test]
fn a_linked_and_a_dropped_in_export_sink_register_one_row_and_fold_the_same() {
    let manifest = with_destination(super::both_ways::statement(
        "export",
        "export-fixture",
        "the-sink",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    ));
    let dir = std::env::temp_dir().join(format!("busbar-k5-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let door = std::sync::atomic::AtomicUsize::new(0);
    let _guard = crate::observe::testing::exclusive();
    let transcript = |sink: &crate::export::DynExport| {
        let before = crate::observe::testing::folds().len();
        // Two lines too large to share the file: the second has the host rotate first.
        for n in [1, 2] {
            sink.deliver(ExportStream::Logs, &big_line(n))
                .expect("deliver");
        }
        let folds: Vec<Compared> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "export-fixture")
            .map(|(_, k, m, d)| (k.clone(), m.clone(), d.clone()))
            .collect();
        serde_json::json!({
            "streams": sink.streams(),
            "routes": sink.routes().len(),
            "folds": folds,
        })
        .to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors(
        manifest,
        |registry| {
            let n = door.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = dir.join(format!("door-{n}.jsonl"));
            let cfg = serde_json::json!({ "path": path.display().to_string(), "rotate_mb": 1 });
            registry
                .open_export("the-sink", &cfg.to_string())
                .expect("the export sink opens through its alias")
        },
        transcript,
    ) else {
        eprintln!("skip: the export sink's cdylib is not built");
        return;
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains(r#""counter""#) && linked.1.contains(export_fixture::ROTATED_TOTAL),
        "the linked sink reported the rotation its deliveries caused: {}",
        linked.1
    );
    assert_eq!(
        linked, dropped,
        "the two doors must register one row and fold the same"
    );
}

/// The host-assigned name the RED arm's pre-envelope build loads under — its own filter, for the
/// same reason [`COMPILED_IN`] and [`DROPPED_IN`] are.
const PRE_ENVELOPE: &str = "#11-pre-envelope";

/// What the pre-envelope build's plugin-side "registry" received: every metric the handler OBSERVED
/// and the pre-envelope wire had no field to carry. Process-global only because a C-ABI `call` is a
/// bare fn pointer with no closure; the RED arm is its only writer and reads it under
/// [`crate::observe::testing::exclusive`].
static PRE_ENVELOPE_PLUGIN_LOCAL: std::sync::Mutex<Vec<serde_json::Value>> =
    std::sync::Mutex::new(Vec::new());

/// The pre-envelope build's op-dispatch: the SAME constructor's handler, reached through the SAME
/// op-dispatch, set by the RED arm before its first call.
type PreEnvelopeDispatch = Box<
    dyn Fn(ExportRequest) -> busbar_contract::abi::mechanism::observe::Envelope<ExportResponse>
        + Send
        + Sync,
>;
static PRE_ENVELOPE_DISPATCH: std::sync::Mutex<Option<PreEnvelopeDispatch>> =
    std::sync::Mutex::new(None);

/// A `busbar_call` speaking the wire as it was BEFORE #85: the kind's response, BARE.
///
/// It runs the real sink's handler through its real op-dispatch, so the plugin genuinely observes
/// what it observes on the other two arms. What it cannot do is put those observations on the wire:
/// the pre-envelope response had no `metrics` field. So they go where a dropped-in cdylib's
/// statically-linked `metrics` facade sent them — into a registry of the plugin's own
/// ([`PRE_ENVELOPE_PLUGIN_LOCAL`]) that the host never scrapes.
unsafe extern "C-unwind" fn pre_envelope_call(
    _handle: *mut std::os::raw::c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let req: ExportRequest =
        serde_json::from_slice(std::slice::from_raw_parts(req, req_len)).expect("decode request");
    let envelope = {
        let dispatch = PRE_ENVELOPE_DISPATCH
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (dispatch
            .as_ref()
            .expect("the RED arm sets the dispatch first"))(req)
    };
    PRE_ENVELOPE_PLUGIN_LOCAL
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .extend(envelope.metrics);
    let boxed: Box<[u8]> = serde_json::to_vec(&envelope.result)
        .expect("encode the bare response")
        .into_boxed_slice();
    *out_len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    STATUS_OK
}

/// Free a buffer [`pre_envelope_call`] allocated.
unsafe extern "C-unwind" fn pre_envelope_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// **THE RED ARM — what the old arrangement did, kept as the witness.**
///
/// Before #85 a dropped-in sink had no wire for what it observed: its response was the kind's answer
/// BARE, and its counters went into the `metrics` facade its own object statically linked — a
/// registry nobody scrapes. The compiled-in build of the same source linked the host's recorder, so
/// the two builds diverged and nothing errored.
///
/// This arm REPLAYS that arrangement over the production seam rather than modelling it: the REAL
/// export `cdylib` is staged and wired (`stage::load_library_from_bytes` + `wire_up_raw`, its real
/// `busbar_open`), its `call` answers bare what the SAME constructor's real op-dispatch answered,
/// and the host reads it through the loader's ONE wire seam, `RawPlugin::transport_call` — whose
/// bare-shape arm is the production pre-envelope path (still live for plugins built before #85). The
/// compiled-in arm is the real one. The fold log is the host's real observer.
///
/// So it is RED-capable in every direction the claim has: if the real sink stops observing, if
/// the bare arm stops decoding (or starts inventing folds), or if the two builds stop diverging, one
/// of the assertions below fails.
///
/// The envelope makes this unrepresentable. A plugin has no symbol to call: it REPORTS, on a wire
/// that goes to exactly one place, and the host is what increments.
#[test]
fn the_pre_envelope_path_loses_a_dropped_in_plugins_counters() {
    let _guard = crate::observe::testing::exclusive();

    // Compiled-in, as the equivalence test runs it: the host folds what the plugin reported.
    run_compiled_in();
    let compiled_in = compared(COMPILED_IN, crate::observe::testing::folds());

    // Dropped-in, pre-envelope: the real cdylib wired over the real loader, answering bare.
    let Some(path) = sink_cdylib() else {
        // Not built under this scoped run; `sink_cdylib` hard-fails under CI.
        return;
    };
    let bytes = std::fs::read(&path).expect("read the export sink cdylib");
    let (lib, staged) =
        stage::load_library_from_bytes(&bytes, PRE_ENVELOPE).expect("stage the export sink cdylib");
    let mut raw = wire_up_raw(
        lib,
        FILE_CFG,
        PRE_ENVELOPE.to_string(),
        busbar_contract::abi::mechanism::kind::EXPORT,
        busbar_contract::abi::mechanism::kind::EXPORT,
        Some(staged),
    )
    .expect("wire up the export sink");
    let handler = export_fixture::open(FILE_CFG).expect("the same constructor");
    *PRE_ENVELOPE_DISPATCH
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(Box::new(move |req| {
        export_fixture::dispatch_compiled_in(handler.as_ref(), req)
    }));
    PRE_ENVELOPE_PLUGIN_LOCAL
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    raw.call = pre_envelope_call;
    raw.free = pre_envelope_free;
    for req in script() {
        match raw
            .transport_call::<ExportRequest, ExportResponse>(&req)
            .expect("the bare pre-envelope response decodes through the loader's wire seam")
        {
            ExportResponse::Host { ops, .. } => {
                assert!(matches!(req, ExportRequest::Deliver { .. }), "{req:?}");
                assert_eq!(ops.len(), 1, "one write per delivery: {ops:?}");
            }
            ExportResponse::Delivered => {
                assert!(matches!(req, ExportRequest::Resume { .. }), "{req:?}")
            }
            ExportResponse::Streams(s) => assert_eq!(s, FILE_CARRIES),
            other => panic!("unexpected response {other:?}"),
        }
    }
    drop(raw);
    let dropped_in_pre_envelope = compared(PRE_ENVELOPE, crate::observe::testing::folds());
    let plugin_local = std::mem::take(
        &mut *PRE_ENVELOPE_PLUGIN_LOCAL
            .lock()
            .unwrap_or_else(|p| p.into_inner()),
    );
    *PRE_ENVELOPE_DISPATCH
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = None;

    // The compiled-in build's counters reached the host.
    let host_saw: Vec<serde_json::Value> = compiled_in
        .iter()
        .flat_map(|(_, metrics, _)| metrics.clone())
        .collect();
    assert_eq!(
        host_saw.len(),
        2,
        "the compiled-in build must report both rotations: {compiled_in:?}"
    );
    // The pre-envelope build OBSERVED exactly the same thing — the counters existed...
    assert_eq!(
        plugin_local, host_saw,
        "the pre-envelope build must have observed what the compiled-in one reported, or the \
         divergence below is a broken fixture rather than the defect"
    );
    // ...and the host received none of it.
    assert!(
        dropped_in_pre_envelope.is_empty(),
        "the defect: a dropped-in plugin's counters land where nothing scrapes — the host folded \
         {dropped_in_pre_envelope:?}"
    );
    assert_ne!(
        compiled_in, dropped_in_pre_envelope,
        "compiled-in ≡ dropped-in was ASSERTED and false for anything a plugin observes — this \
         inequality is what #85's envelope exists to remove, and \
         `compiled_in_and_dropped_in_report_identical_observations` is what proves it did"
    );
}

/// **OWED, and named so it is not forgotten.** The assertion above compares what the host was
/// HANDED. The one #85's acceptance clause names compares what the host RENDERS:
///
/// ```ignore
/// // wherever a metrics recorder legitimately exists (the engine, not the loader):
/// install_recorder();
/// run_compiled_in();
/// let a = busbar_kernel::metrics::render();
/// reset_recorder();
/// run_dropped_in();
/// let b = busbar_kernel::metrics::render();
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

/// **K9a S1 — THE FIRST-PARTY METRIC NAMESPACE, BOTH WAYS.** The export row's sink, its manifest
/// declaring the reserved series it reports its rotations under, registered through the LINKED door
/// and the DROPPED-IN door (signed by the release key): each open GRANTS the declared series, so the
/// host renders it as declared (the kernel's `observe` tests render the grant), and the two doors
/// register one row and fold the same. RED ARMS, in the same test so the grant cannot pass
/// vacuously: the same crate dropped in by a THIRD party (allowlisted, trusted, not first-party) is
/// granted nothing whatever it declares, and a first-party claim on a series the host emits refuses
/// the open naming it.
#[test]
fn a_first_party_series_is_granted_through_either_door_and_to_nobody_else() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    crate::observe::install_host_series(|name| name == S1_HOST_SERIES);
    let series = export_fixture::ROTATED_TOTAL;
    let declaring = |name: &str, series: &str| {
        let mut m = with_destination(super::both_ways::statement(
            "export",
            name,
            &format!("{name}-alias"),
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        ));
        m.declares.metrics = vec![SeriesDecl::new(series, "counter")];
        m
    };
    let dir = std::env::temp_dir().join(format!("busbar-s1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let door = std::sync::atomic::AtomicUsize::new(0);
    let _guard = crate::observe::testing::exclusive();
    let transcript = |sink: &crate::export::DynExport| {
        let before = crate::observe::testing::folds().len();
        // Two lines too large to share the file: the second has the host rotate first.
        for n in [1, 2] {
            sink.deliver(ExportStream::Logs, &big_line(n))
                .expect("deliver");
        }
        let folds: Vec<Compared> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "s1-fixture")
            .map(|(_, k, m, d)| (k.clone(), m.clone(), d.clone()))
            .collect();
        let granted = crate::observe::first_party_series("s1-fixture", series, "counter");
        serde_json::json!({ "granted": granted, "folds": folds }).to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors(
        declaring("s1-fixture", series),
        |registry| {
            let n = door.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = dir.join(format!("door-{n}.jsonl"));
            let cfg = serde_json::json!({ "path": path.display().to_string(), "rotate_mb": 1 });
            registry
                .open_export("s1-fixture-alias", &cfg.to_string())
                .expect("a first-party declaration opens")
        },
        transcript,
    ) else {
        eprintln!("skip: the export sink's cdylib is not built");
        return;
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        linked.1.contains(r#""granted":true"#) && linked.1.contains(series),
        "the linked door grants the declared series and the sink reports under it: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors grant and fold the same");

    // RED ARM 1: a third party declaring the same kind of claim is granted nothing.
    let (crate_snake, _) = super::both_ways::fixture("export");
    let lib = std::fs::read(super::both_ways::cdylib(crate_snake).expect("built above"))
        .expect("read the cdylib");
    let mut third = declaring("s1-third-party", series);
    third.publisher = "acme".into();
    let registry = super::both_ways::dropped_third_party(crate_snake, third, &lib);
    registry
        .open_export("s1-third-party", "{}")
        .expect("a third party opens; its declaration is simply not granted");
    assert!(!crate::observe::first_party_series(
        "s1-third-party",
        series,
        "counter"
    ));

    // RED ARM 2: a first-party claim on a host series refuses the open.
    let registry = super::both_ways::linked(
        declaring("s1-collides", S1_HOST_SERIES),
        super::both_ways::fixture("export").1,
    );
    let refused = registry
        .open_export("s1-collides", "{}")
        .expect_err("a claim on a host series is refused");
    assert!(
        refused.contains(S1_HOST_SERIES) && refused.contains("the host itself emits"),
        "{refused}"
    );
}

/// **K9a S2 — THE VALIDATE OP, BOTH WAYS.** The export row's sink registered through the LINKED door
/// and the DROPPED-IN door answers the host's `validate` identically: settings it accepts report
/// nothing, and settings it refuses report the sink's own line verbatim — the text the host prints
/// among the configuration's errors. A module that is not an export row is not the axis's to judge.
/// RED ARM, in the same test: the same sink driven over a wire that predates the op (it answers
/// `STATUS_UNSUPPORTED`) reports NOTHING for the settings it would refuse — what every sink did
/// before the op, and what the op exists to change.
#[test]
fn a_sink_validates_its_settings_the_same_through_either_door() {
    let manifest = super::both_ways::statement(
        "export",
        "s2-fixture",
        "s2-sink",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    );
    let refused = serde_json::json!({ "path": 7 });
    let accepted = serde_json::json!({ "path": "/var/log/busbar/requests.jsonl", "rotate_mb": 64 });
    let transcript = |registry: &PluginRegistry| {
        serde_json::json!({
            "accepted": registry.validate_export("s2-sink", "tail", &accepted),
            "refused": registry.validate_export("s2-sink", "tail", &refused),
            "not_export": registry.validate_export("no-such-module", "tail", &refused),
        })
        .to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors(manifest, transcript, String::clone)
    else {
        eprintln!("skip: the export sink's cdylib is not built");
        return;
    };
    let line = "export.tail.settings: invalid type: integer `7`, expected a string";
    assert_eq!(
        linked.1,
        serde_json::json!({ "accepted": [], "refused": [line], "not_export": null }).to_string()
    );
    assert_eq!(linked, dropped, "both doors validate the same");

    // RED ARM: a sink that cannot decode the op (the pre-minor-2 wire) reports nothing.
    let registry = super::both_ways::linked(
        super::both_ways::statement("export", "s2-older", "s2-older", 3),
        super::both_ways::fixture("export").1,
    );
    let mut sink = registry
        .open_export("s2-older", "{}")
        .expect("the older sink opens");
    sink.raw.call = unsupported_call;
    assert_eq!(sink.validate("tail", &refused), Ok(Vec::new()));
}

/// A `busbar_call` from before an op existed: every request is one it cannot decode.
unsafe extern "C-unwind" fn unsupported_call(
    _handle: *mut std::os::raw::c_void,
    _req: *const u8,
    _req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    *out = std::ptr::null_mut();
    *out_len = 0;
    STATUS_UNSUPPORTED
}

/// **K9a S3 — PLUGIN DIAGNOSTICS, BOTH WAYS.** The request-log WEBHOOK sink (the `export-webhook`
/// row), its manifest declaring the `BUSBAR-NNNN` codes it raises (its own `declares.json`),
/// registered through the LINKED door and the DROPPED-IN door: both rows state the same declaration
/// and are FIRST-PARTY — which is everything the composition root reads to register the codes into
/// the host's catalogue (`root::linked::declared_diagnostics`, whose own tests hold the catalogue
/// half) — and the sink raising a code (a delivery the host's egress refused: BUSBAR-7072) hands the
/// host the same diagnostic either way. RED ARM, in the same test: the same declaration dropped in by
/// a THIRD party is not first-party, which the root refuses.
#[test]
fn a_declared_diagnostic_is_stated_and_raised_the_same_through_either_door() {
    crate::install_egress_carrier(&CARRIER);
    let decl = serde_json::from_str::<crate::sign::Declares>(export_webhook_fixture::DECLARES)
        .expect("the sink's declaration parses")
        .diagnostics;
    assert!(decl.iter().any(|d| d.code == 7072), "{decl:?}");
    let declaring = |name: &str| {
        let mut m = super::both_ways::statement(
            "export",
            name,
            name,
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        );
        m.declares.diagnostics = decl.clone();
        m
    };
    let cfg = serde_json::json!({ "url": "https://refused.example/in" }).to_string();
    let _guard = crate::observe::testing::exclusive();
    let transcript = |registry: &PluginRegistry| {
        let first_party = registry.resolve("s3-fixture").map(|p| p.first_party());
        let sink = registry.open_export("s3-fixture", &cfg).expect("opens");
        let before = crate::observe::testing::folds().len();
        sink.deliver(ExportStream::Logs, &serde_json::json!({ "n": 1 }))
            .expect("deliver");
        let raised: Vec<Vec<serde_json::Value>> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "s3-fixture")
            .map(|(.., d)| d.clone())
            .collect();
        serde_json::json!({ "first_party": first_party, "raised": raised }).to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors_of(
        "export-webhook",
        declaring("s3-fixture"),
        transcript,
        String::clone,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    assert!(
        linked.0.contains("webhook-delivery-transport-error"),
        "{}",
        linked.0
    );
    assert!(
        linked.1.contains(r#""first_party":true"#) && linked.1.contains("BUSBAR-7072"),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors state and raise the same");

    // RED ARM: a third party's declaration is not first-party.
    let (crate_snake, _) = super::both_ways::fixture("export-webhook");
    let lib = std::fs::read(super::both_ways::cdylib(crate_snake).expect("built above"))
        .expect("read the cdylib");
    let mut third = declaring("s3-third-party");
    third.publisher = "acme".into();
    let registry = super::both_ways::dropped_third_party(crate_snake, third, &lib);
    let row = registry.resolve("s3-third-party").expect("admitted");
    assert_eq!(row.manifest.declares.diagnostics, decl);
    assert!(!row.first_party());
}

/// Every `tracing` event that fired on this thread while it was the subscriber, rendered as
/// `LEVEL field=value ...` — how the S4 RED arm reads the lines the sink reports its refusals as.
#[derive(Clone, Default)]
struct EventLog(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl EventLog {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl tracing::Subscriber for EventLog {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Render(String);
        impl tracing::field::Visit for Render {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
        }
        let mut r = Render(format!("{}", event.metadata().level()));
        event.record(&mut r);
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push(r.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// **K9a S4 — THE DESTINATION HANDLE, BOTH WAYS.** The request-log FILE sink (the export row), its
/// manifest declaring the `path` settings key a destination, registered through the LINKED door and
/// the DROPPED-IN door and opened with the operator's path: each delivery has the HOST append the
/// line (the sink names the key; the host opens the path it resolved), rotating at the sink's
/// `rotate_mb` — and both doors leave the same files and report the same folds. RED ARM, in the same
/// test: the same sink whose manifest does NOT declare the key is refused every write — the path the
/// operator's settings name is never created — and it reports the refusals (its BUSBAR-7074 line).
#[test]
fn a_sink_writes_its_declared_destination_through_the_host_the_same_through_either_door() {
    let declaring = |name: &str, declared: bool| {
        let mut m = super::both_ways::statement(
            "export",
            name,
            name,
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        );
        if declared {
            m.declares.destinations = vec!["path".into()];
        }
        m
    };
    let dir = std::env::temp_dir().join(format!("busbar-s4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let door = std::sync::atomic::AtomicUsize::new(0);
    let _guard = crate::observe::testing::exclusive();
    let run = |registry: &PluginRegistry, name: &str| {
        let n = door.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = dir.join(format!("door-{n}.jsonl"));
        let cfg = serde_json::json!({ "path": path.display().to_string(), "rotate_mb": 1 });
        let sink = registry.open_export(name, &cfg.to_string()).expect("opens");
        let before = crate::observe::testing::folds().len();
        // Two lines fill the MiB; the third has the host rotate first.
        for n in 1..=4 {
            let line = serde_json::json!({ "n": n, "pad": "x".repeat(600_000) });
            sink.deliver(ExportStream::Logs, &line).expect("deliver");
        }
        let folds: Vec<Compared> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == name)
            .map(|(_, k, m, d)| (k.clone(), m.clone(), d.clone()))
            .collect();
        serde_json::json!({
            "live": ns(&path),
            "archive": ns(&path.with_extension("jsonl.1")),
            "folds": folds,
        })
        .to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors(
        declaring("s4-fixture", true),
        |registry| run(registry, "s4-fixture"),
        String::clone,
    ) else {
        eprintln!("skip: the export sink's cdylib is not built");
        return;
    };
    assert!(linked.1.contains(r#""archive":[1,2]"#), "{}", linked.1);
    assert!(linked.1.contains(r#""live":[3,4]"#), "{}", linked.1);
    assert!(
        linked.1.contains(export_fixture::ROTATED_TOTAL),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors write and rotate the same");

    // RED ARM: undeclared, the key is not a destination — every write refused, nothing created,
    // and the sink reports each refusal as its open-failed line.
    let registry = super::both_ways::linked(
        declaring("s4-undeclared", false),
        super::both_ways::fixture("export").1,
    );
    let log = EventLog::default();
    let refused =
        tracing::subscriber::with_default(log.clone(), || run(&registry, "s4-undeclared"));
    assert!(refused.contains(r#""live":null"#), "{refused}");
    let reported = log
        .lines()
        .iter()
        .filter(|l| l.contains(export_fixture::OPEN_FAILED))
        .count();
    assert_eq!(
        reported,
        4,
        "one refusal line per delivery: {:?}",
        log.lines()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The egress this test binary installs: it records every request it is asked to carry and answers
/// `204`, and its POLICY refuses any URL on `refused.example` before anything is sent — the shape of
/// the host's own carrier (URL policy first, then the hop).
struct RecordingCarrier(std::sync::Mutex<Vec<busbar_contract::abi::cold::export::HttpRequest>>);

impl crate::EgressCarrier for RecordingCarrier {
    fn carry(
        &self,
        request: &busbar_contract::abi::cold::export::HttpRequest,
    ) -> busbar_contract::abi::cold::export::HostResult {
        use busbar_contract::abi::cold::export::{HostResult, HttpResponse};
        if request.url.contains("stall.example") {
            // Held until released, holding the calling thread (the blocking hop).
            STALLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            while !RELEASED.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            STALLED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return HostResult::Http(HttpResponse {
                status: 204,
                body: String::new(),
            });
        }
        if request.url.contains("refused.example") {
            return HostResult::Failed {
                step: "refused".into(),
                error: "the host's egress policy refuses this target".into(),
                rotation: None,
            };
        }
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());
        HostResult::Http(HttpResponse {
            status: 204,
            body: String::new(),
        })
    }

    fn carry_async(
        &'static self,
        request: busbar_contract::abi::cold::export::HttpRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = busbar_contract::abi::cold::export::HostResult> + Send,
        >,
    > {
        Box::pin(async move {
            if !request.url.contains("stall.example") {
                return self.carry(&request);
            }
            // Held until released, AWAITED: no thread waits on the far end.
            STALLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            while !RELEASED.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            STALLED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            busbar_contract::abi::cold::export::HostResult::Http(
                busbar_contract::abi::cold::export::HttpResponse {
                    status: 204,
                    body: String::new(),
                },
            )
        })
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        match url.contains("refused.example") {
            true => Err("the host's egress policy refuses this target".into()),
            false => Ok(()),
        }
    }
}

static CARRIER: RecordingCarrier = RecordingCarrier(std::sync::Mutex::new(Vec::new()));

/// Requests to `stall.example` the carrier is holding right now, and the switch that lets them go.
static STALLED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RELEASED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// **K9a S5 — THE EGRESS CARRIER, BOTH WAYS.** The request-log WEBHOOK sink (the `export-webhook`
/// row) registered through the LINKED door and the DROPPED-IN door, opened with a `url`: each
/// delivery has the HOST carry the POST through the installed egress (the sink never dials), and
/// both doors hand the carrier the same requests and fold the same answer — nothing, for a far end
/// that accepted every line, as the 1.5.5 webhook reported nothing. RED ARM, in the same test: a
/// target the host's policy refuses never reaches the wire — nothing is carried — and the sink is
/// told, and reports it (its BUSBAR-7072 transport-error diagnostic).
#[test]
fn a_sinks_outbound_request_is_carried_by_the_host_the_same_through_either_door() {
    crate::install_egress_carrier(&CARRIER);
    let manifest = super::both_ways::statement(
        "export",
        "s5-fixture",
        "s5-fixture",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    );
    let _guard = crate::observe::testing::exclusive();
    let run = |registry: &PluginRegistry, url: &str| {
        let cfg = serde_json::json!({ "url": url }).to_string();
        let sink = registry.open_export("s5-fixture", &cfg).expect("opens");
        let before = crate::observe::testing::folds().len();
        CARRIER.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
        for n in 1..=2 {
            sink.deliver(ExportStream::Logs, &serde_json::json!({ "n": n }))
                .expect("deliver");
        }
        let carried = CARRIER.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let folds: Vec<Compared> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "s5-fixture")
            .map(|(_, k, m, d)| (k.clone(), m.clone(), d.clone()))
            .collect();
        serde_json::json!({ "carried": carried, "folds": folds }).to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors_of(
        "export-webhook",
        manifest.clone(),
        |registry| run(registry, "https://collector.example/v1"),
        String::clone,
    ) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    assert!(
        linked.1.contains(r#""body":"{\"n\":2}""#) && linked.1.contains(r#""folds":[]"#),
        "{}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors are carried the same");

    // RED ARM: the policy refuses the target — nothing is carried, and the sink reports it.
    let registry =
        super::both_ways::linked(manifest, super::both_ways::fixture("export-webhook").1);
    let refused = run(&registry, "https://refused.example/v1");
    assert!(refused.contains(r#""carried":[]"#), "{refused}");
    assert!(refused.contains("BUSBAR-7072"), "{refused}");
}

/// **K9c — START, CHECK AND ADMIT, BOTH WAYS.** The export row's FILE sink (which takes the SDK's
/// defaults for both ops)
/// starts live at the host's default admission and has nothing to check, identically through
/// either door; and an `admit` op is answered by the installed carrier's POLICY without anything
/// being carried. RED ARM: a sink over the wire that predates the ops says nothing (`None` / no
/// lines) — the host's defaults, not a refusal.
#[test]
fn a_sink_starts_and_checks_the_same_through_either_door() {
    crate::install_egress_carrier(&CARRIER);
    let manifest = super::both_ways::statement(
        "export",
        "k9c-fixture",
        "k9c-sink",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    );
    let transcript = |registry: &PluginRegistry| {
        let sink = registry.open_export("k9c-sink", "{}").expect("opens");
        let instances = [("tail".to_string(), serde_json::json!({}))];
        format!(
            "{:?} {:?} {:?}",
            sink.start(),
            sink.check(
                busbar_contract::abi::export::CheckPhase::Instances,
                &instances
            ),
            registry.check_export(
                "k9c-sink",
                busbar_contract::abi::export::CheckPhase::Limits,
                &instances
            )
        )
    };
    let Some([linked, dropped]) = super::both_ways::both_doors(manifest, transcript, String::clone)
    else {
        eprintln!("skip: the export sink's cdylib is not built");
        return;
    };
    assert_eq!(linked.1, r#"Ok(Some((true, 0, ""))) Ok([]) Some([])"#);
    assert_eq!(linked, dropped, "both doors start and check the same");

    // The admit op: the policy's verdict, nothing carried.
    use busbar_contract::abi::cold::export::{HostOp, HostResult};
    let none = crate::host::Destinations::default();
    CARRIER.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let ok = none.perform(&HostOp::Admit {
        url: "https://collector.example/in".into(),
    });
    assert_eq!(ok, HostResult::Done { rotation: None });
    let refused = none.perform(&HostOp::Admit {
        url: "https://refused.example/in".into(),
    });
    assert!(
        matches!(&refused, HostResult::Failed { step, .. } if step == "refused"),
        "{refused:?}"
    );
    assert!(CARRIER
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty());

    // RED ARM: the pre-minor-8 wire.
    let registry = super::both_ways::linked(
        super::both_ways::statement("export", "k9c-older", "k9c-older", 3),
        super::both_ways::fixture("export").1,
    );
    let mut sink = registry.open_export("k9c-older", "{}").expect("opens");
    sink.raw.call = unsupported_call;
    assert_eq!(sink.start(), Ok(None));
    assert_eq!(
        sink.check(busbar_contract::abi::export::CheckPhase::Instances, &[]),
        Ok(Vec::new())
    );
}

/// **K9c — A SINK'S DELIVERIES IN FLIGHT ARE BOUNDED BY ITS ADMISSION ALONE.** The request-log
/// WEBHOOK sink (the `export-webhook` row), whose every delivery is a host-carried POST. At an
/// in-flight bound
/// of 600 — above the runtime's 512 blocking threads — 600 deliveries are in flight at once, each
/// awaiting the far end on the host's egress, and the 601st is shed at the gate: the effective
/// concurrency is the configured bound, as the 1.5.5 webhook's async deliveries were. (RED: a
/// delivery that holds a blocking thread while the far end answers plateaus at 512.)
#[test]
fn a_sinks_deliveries_in_flight_reach_its_admission_bound_past_the_blocking_pool() {
    const BOUND: usize = 600;
    crate::install_egress_carrier(&CARRIER);
    let manifest = super::both_ways::statement(
        "export",
        "k9c-bound",
        "k9c-bound",
        busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
    );
    let registry =
        super::both_ways::linked(manifest, super::both_ways::fixture("export-webhook").1);
    // The far end is held until released: a per-delivery deadline past the wait below.
    let settings =
        serde_json::json!({ "url": "https://stall.example/in", "delivery_timeout_secs": 600 })
            .to_string();
    let sink = std::sync::Arc::new(registry.open_export("k9c-bound", &settings).expect("opens"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let (in_flight, shed) = runtime.block_on(async {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(BOUND));
        let mut shed = 0;
        for n in 0..=BOUND {
            match gate.clone().try_acquire_owned() {
                Ok(permit) => sink.deliver_detached(
                    ExportStream::Logs,
                    std::sync::Arc::new(serde_json::json!({ "n": n })),
                    permit,
                ),
                Err(_) => shed += 1,
            }
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let stalled = || STALLED.load(std::sync::atomic::Ordering::SeqCst);
        while stalled() < BOUND && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Held a moment longer: nothing beyond the bound joins.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let in_flight = stalled();
        RELEASED.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = gate.acquire_many(BOUND as u32).await;
        (in_flight, shed)
    });
    assert_eq!(
        in_flight, BOUND,
        "every admitted delivery is in flight at once"
    );
    assert_eq!(shed, 1, "the delivery past the bound is shed");
}

/// **K9e-2 — A CARRIER CARRIES ONLY THE POLICIES IT IMPLEMENTS.** The loader routes an outbound
/// request with its octets and the sink's granted policy; a carrier that implements only the open
/// web (this binary's recording one, every carrier written before the seam) carries a TEXT body
/// under it exactly as `carry` always did, and REFUSES — carrying nothing — a binary body or any
/// other policy, in words that name what it lacks.
#[test]
fn a_carrier_that_implements_no_policy_but_the_open_web_refuses_the_rest() {
    use crate::EgressPolicy;
    use busbar_contract::abi::cold::export::{HostOp, HostResult, HttpRequest};
    crate::install_egress_carrier(&CARRIER);
    let request = HttpRequest {
        method: "POST".into(),
        url: "https://k9e2-open-web.example/in".into(),
        headers: Vec::new(),
        body: "ignored: the octets travel beside the head".into(),
        timeout_ms: 1000,
    };
    let ours = || {
        CARRIER
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.url.contains("k9e2-open-web.example"))
            .map(|r| r.body.clone())
            .collect::<Vec<_>>()
    };
    let text = crate::host::carry_under(EgressPolicy::OpenWeb, &request, b"{\"a\":1}");
    assert!(
        matches!(text, HostResult::Http(ref r) if r.status == 204),
        "{text:?}"
    );
    assert_eq!(ours(), vec![r#"{"a":1}"#.to_string()], "carried as text");

    let refused = |answer: HostResult, words: &str| match answer {
        HostResult::Failed { step, error, .. } => {
            assert_eq!((step.as_str(), error.as_str()), ("refused", words))
        }
        other => panic!("expected a refusal, got {other:?}"),
    };
    refused(
        crate::host::carry_under(EgressPolicy::OpenWeb, &request, &[0x0a, 0xff]),
        "this host carries no binary request body",
    );
    refused(
        crate::host::carry_under(EgressPolicy::Collector, &request, b"{}"),
        "this host carries no `collector` plugin egress",
    );
    refused(
        crate::host::admit_under(EgressPolicy::Collector, "http://127.0.0.1:4318/v1/traces"),
        "this host carries no `collector` plugin egress",
    );
    // A binary body that is not hex never reaches any carrier.
    let not_hex = HostOp::HttpBinary(HttpRequest {
        body: "zz".into(),
        ..request.clone()
    });
    match crate::host::Destinations::default().perform(&not_hex) {
        HostResult::Failed { step, error, .. } => {
            assert_eq!(step, "request");
            assert!(
                error.starts_with("the binary request body is not hex ("),
                "{error}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ours().len(),
        1,
        "a refused request never reaches the carrier's wire"
    );
}

/// **K9e-2 — A DECLARED EGRESS POLICY IS GRANTED TO A FIRST-PARTY SINK ONLY, AND EVERY REQUEST THE
/// SINK ASKS FOR MEETS IT.** A cold sink (the `export-webhook` row), its manifest stating the
/// `egress: collector` declaration, linked, opens under it, and its admission and its carried requests are judged under that policy (this binary's
/// carrier implements only the open web, so both are refused with the policy's name — the proof
/// the policy, not the open web, reached the carrier). RED ARMS: the same declaration from a third
/// party refuses the open, naming the policy; and a sink that declares none is judged under the
/// open web, as every sink before the seam was.
#[test]
fn a_declared_egress_policy_is_granted_to_a_first_party_sink_only() {
    use crate::EgressPolicy;
    use busbar_contract::abi::cold::export::{HostOp, HostResult, HttpRequest};
    crate::install_egress_carrier(&CARRIER);
    // The declaration's manifest spelling; the default is left off the signed bytes.
    let collector = crate::sign::Declares {
        egress: EgressPolicy::Collector,
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&collector).expect("encode"),
        serde_json::json!({"egress": "collector"})
    );
    assert!(!collector.is_empty() && crate::sign::Declares::default().is_empty());
    assert_eq!(
        serde_json::to_value(crate::sign::Declares::default()).expect("encode"),
        serde_json::json!({})
    );
    let shipped = collector;
    let declaring = |name: &str| {
        let mut m = super::both_ways::statement(
            "export",
            name,
            name,
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        );
        m.declares = shipped.clone();
        m
    };
    let registry = super::both_ways::linked(
        declaring("k9e2-collector"),
        super::both_ways::fixture("export-webhook").1,
    );
    let sink = registry
        .open_export("k9e2-collector", "{}")
        .expect("a first-party declaration is granted");
    assert_eq!(sink.egress(), EgressPolicy::Collector);
    let lacks = "this host carries no `collector` plugin egress";
    let binary = HostOp::HttpBinary(HttpRequest {
        method: "POST".into(),
        url: "http://127.0.0.1:4318/v1/traces".into(),
        headers: Vec::new(),
        body: "0a00".into(),
        timeout_ms: 1000,
    });
    let admit = HostOp::Admit {
        url: "http://127.0.0.1:4318/v1/traces".into(),
    };
    for op in [&binary, &admit] {
        match sink.perform(op) {
            HostResult::Failed { step, error, .. } => {
                assert_eq!(
                    (step.as_str(), error.as_str()),
                    ("refused", lacks),
                    "{op:?}"
                )
            }
            other => panic!("{op:?} was not judged under the declared policy: {other:?}"),
        }
    }

    // RED ARM 1: a third party declaring the same policy is refused at open, naming it.
    let (crate_snake, _) = super::both_ways::fixture("export-webhook");
    let Some(path) = super::both_ways::cdylib(crate_snake) else {
        eprintln!("skip: the webhook sink's cdylib is not built");
        return;
    };
    let lib = std::fs::read(path).expect("read the cdylib");
    let mut third = declaring("k9e2-third-party");
    third.publisher = "acme".into();
    let refused = super::both_ways::dropped_third_party(crate_snake, third, &lib)
        .open_export("k9e2-third-party", "{}")
        .expect_err("a third party is not granted a policy past the open web");
    assert!(
        refused.contains(
            "declares the `collector` egress policy, which the host grants to a \
             first-party plugin only"
        ),
        "{refused}"
    );

    // RED ARM 2: declaring none is the open web — the admission reaches the carrier's own policy.
    let plain = super::both_ways::linked(
        super::both_ways::statement(
            "export",
            "k9e2-open-web",
            "k9e2-open-web",
            busbar_contract::abi::cold::export::EXPORT_ABI_VERSION,
        ),
        super::both_ways::fixture("export-webhook").1,
    )
    .open_export("k9e2-open-web", "{}")
    .expect("opens");
    assert_eq!(plain.egress(), EgressPolicy::OpenWeb);
    assert_eq!(plain.perform(&admit), HostResult::Done { rotation: None });
}
