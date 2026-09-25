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

use super::*;
use busbar_plugin::cold::export::{ExportRequest, ExportResponse};

/// The two arms are compared on `(kind, metrics, diagnostics)`.
///
/// The PLUGIN NAME is deliberately NOT compared. The two arms load the same crate under two
/// different display names — one is a linked handler with no file behind it, the other a staged
/// `cdylib` — and a display name is host-side provenance, not plugin behaviour. Comparing it would
/// fail the test for the one difference that is supposed to exist.
type Compared = (String, Vec<serde_json::Value>, Vec<serde_json::Value>);

/// The host-assigned names the two arms load under. They are the FILTER as well as the label: the
/// fold log is process-global and other tests in this binary legitimately load the same example
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
/// Two deliveries then a `streams` query. The deliveries give the sink something to observe; the
/// trailing query is there to prove the OPPOSITE of what one might expect — having already drained
/// on each delivery's own response, the sink has nothing left to say, so `streams` answers a BARE
/// envelope and folds nothing. A drain that leaked would show up here as a third fold on one arm.
fn script() -> Vec<ExportRequest> {
    vec![
        ExportRequest::Deliver {
            stream: ExportStream::Metrics,
            payload: serde_json::json!({"n": 1}),
        },
        ExportRequest::Deliver {
            stream: ExportStream::Metrics,
            payload: serde_json::json!({"n": 2}),
        },
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
    let handler = busbar_export_example_plugin::open("{}").expect("compiled-in ctor");
    for req in script() {
        let envelope = busbar_export_example_plugin::dispatch_compiled_in(handler.as_ref(), req);
        crate::observe::fold(COMPILED_IN, busbar_plugin::cold::kind::EXPORT, &envelope);
    }
}

/// Run the same script against the DROPPED-IN build: the `cdylib` on disk, `dlopen`ed and driven
/// over the six-symbol C ABI, its envelope folded by the host at the loader's ONE wire seam.
///
/// Returns `None` when the `cdylib` is not built (a scoped `cargo test -p` of an unrelated crate);
/// under CI that is a hard failure, exactly as [`example_cdylib`] enforces.
fn run_dropped_in() -> Option<()> {
    let path = example_cdylib()?;
    let bytes = std::fs::read(&path).expect("read the export example plugin cdylib");
    let sink = crate::export::load_export_from_bytes(
        &bytes,
        "{}",
        DROPPED_IN,
        busbar_plugin::cold::kind::EXPORT,
    )
    .expect("load the export example plugin over the ABI");
    // `load_export_from_bytes` ALREADY ran `streams` and `routes` at load, so the script below is
    // run against a sink that has answered twice. That is fine and is the point: the two arms are
    // compared on the folds the SCRIPT produces, and a load-time query folds nothing because the
    // sink has observed nothing yet.
    for req in script() {
        match req {
            ExportRequest::Deliver { stream, payload } => {
                sink.deliver(stream, &payload).expect("deliver");
            }
            ExportRequest::Streams => {
                assert_eq!(sink.streams(), &[ExportStream::Metrics, ExportStream::Logs]);
            }
            _ => unreachable!("the script only uses deliver + streams"),
        }
    }
    Some(())
}

/// Locate the built `cdylib`, checking BOTH the uplifted `<profile_dir>/<name>` copy and the raw
/// `<profile_dir>/deps/<name>` compiler output (a scoped `cargo test -p` only produces the latter).
/// Under CI a missing artifact is a HARD failure, never a silent skip: the equivalence this module
/// proves is the one #11 was false about, and a test that quietly stops running where it matters is
/// worse than no test.
fn example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_export_example_plugin");
        [
            profile_dir.join(&name),
            profile_dir.join("deps").join(&name),
        ]
        .into_iter()
        .filter_map(|p| {
            std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .map(|mtime| (p, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the export example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_export_example_plugin. Refusing to silently skip design decision #11's \
             compiled-in vs dropped-in equivalence."
        );
    }
    candidate
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
        // Not built under this scoped run. `example_cdylib` already hard-fails under CI, so this arm
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
/// TWO folds, not three: the handler runs and is drained WITHIN one boundary call, so each delivery
/// reports its own increment on its own response, and the trailing `streams` finds nothing left to
/// report and answers bare (a bare envelope is never folded).
#[test]
fn the_reported_observations_are_the_ones_the_sink_produced() {
    let _guard = crate::observe::testing::exclusive();
    run_compiled_in();
    let folds = compared(COMPILED_IN, crate::observe::testing::folds());
    assert_eq!(folds.len(), 2, "folds: {folds:?}");
    for (kind, metrics, diagnostics) in &folds {
        assert_eq!(kind, busbar_plugin::cold::kind::EXPORT);
        assert!(diagnostics.is_empty());
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0]["name"], "example_export_deliveries_total");
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
    let manifest = super::both_ways::statement(
        "export",
        "export-fixture",
        "the-sink",
        busbar_plugin::cold::export::EXPORT_ABI_VERSION,
    );
    let _guard = crate::observe::testing::exclusive();
    let transcript = |sink: &crate::export::DynExport| {
        let before = crate::observe::testing::folds().len();
        for n in [1, 2] {
            sink.deliver(ExportStream::Logs, &serde_json::json!({ "n": n }))
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
            registry
                .open_export("the-sink", "{}")
                .expect("the export sink opens through its alias")
        },
        transcript,
    ) else {
        eprintln!("skip: the export fixture's cdylib is not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains(r#""counter""#),
        "the linked sink reported its deliveries: {}",
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
    dyn Fn(ExportRequest) -> busbar_plugin::cold::observe::Envelope<ExportResponse> + Send + Sync,
>;
static PRE_ENVELOPE_DISPATCH: std::sync::Mutex<Option<PreEnvelopeDispatch>> =
    std::sync::Mutex::new(None);

/// A `busbar_call` speaking the wire as it was BEFORE #85: the kind's response, BARE.
///
/// It runs the real example handler through its real op-dispatch, so the plugin genuinely observes
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
/// So it is RED-capable in every direction the claim has: if the example sink stops observing, if
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
    let Some(path) = example_cdylib() else {
        // Not built under this scoped run; `example_cdylib` hard-fails under CI.
        return;
    };
    let bytes = std::fs::read(&path).expect("read the export example plugin cdylib");
    let (lib, staged) = stage::load_library_from_bytes(&bytes, PRE_ENVELOPE)
        .expect("stage the export example plugin cdylib");
    let mut raw = wire_up_raw(
        lib,
        "{}",
        PRE_ENVELOPE.to_string(),
        busbar_plugin::cold::kind::EXPORT,
        busbar_plugin::cold::kind::EXPORT,
        Some(staged),
    )
    .expect("wire up the export example plugin");
    let handler = busbar_export_example_plugin::open("{}").expect("the same constructor");
    *PRE_ENVELOPE_DISPATCH
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(Box::new(move |req| {
        busbar_export_example_plugin::dispatch_compiled_in(handler.as_ref(), req)
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
            ExportResponse::Delivered => {
                assert!(matches!(req, ExportRequest::Deliver { .. }), "{req:?}")
            }
            ExportResponse::Streams(s) => {
                assert_eq!(s, vec![ExportStream::Metrics, ExportStream::Logs])
            }
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
        "the compiled-in build must report both deliveries: {compiled_in:?}"
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

/// The series the S1 witness's sink reports its deliveries under — reserved, and declared.
const S1_SERIES: &str = "busbar_s1_example_deliveries_total";

/// A series the host itself emits, for the collision arm — installed once as this test binary's
/// host catalog (the composition root installs the real one).
const S1_HOST_SERIES: &str = "busbar_s1_host_owned_total";

/// **K9a S1 — THE FIRST-PARTY METRIC NAMESPACE, BOTH WAYS.** The export fixture, its manifest
/// declaring a reserved series, registered through the LINKED door and the DROPPED-IN door (signed
/// by the release key): each open GRANTS the declared series, so the host renders it as declared
/// (the kernel's `observe` tests render the grant), and the two doors register one row and fold the
/// same. RED ARMS, in the same test so the grant cannot pass vacuously: the same crate dropped in by
/// a THIRD party (allowlisted, trusted, not first-party) is granted nothing whatever it declares,
/// and a first-party claim on a series the host emits refuses the open naming it.
#[test]
fn a_first_party_series_is_granted_through_either_door_and_to_nobody_else() {
    use busbar_plugin::cold::observe::SeriesDecl;
    crate::observe::install_host_series(|name| name == S1_HOST_SERIES);
    let declaring = |name: &str, series: &str| {
        let mut m = super::both_ways::statement(
            "export",
            name,
            &format!("{name}-alias"),
            busbar_plugin::cold::export::EXPORT_ABI_VERSION,
        );
        m.declares.metrics = vec![SeriesDecl::new(series, "counter")];
        m
    };
    let cfg = serde_json::json!({ "series": S1_SERIES }).to_string();
    let _guard = crate::observe::testing::exclusive();
    let transcript = |sink: &crate::export::DynExport| {
        let before = crate::observe::testing::folds().len();
        sink.deliver(ExportStream::Logs, &serde_json::json!({ "n": 1 }))
            .expect("deliver");
        let folds: Vec<Compared> = crate::observe::testing::folds()[before..]
            .iter()
            .filter(|(who, ..)| who == "s1-fixture")
            .map(|(_, k, m, d)| (k.clone(), m.clone(), d.clone()))
            .collect();
        let granted = crate::observe::first_party_series("s1-fixture", S1_SERIES, "counter");
        serde_json::json!({ "granted": granted, "folds": folds }).to_string()
    };
    let Some([linked, dropped]) = super::both_ways::both_doors(
        declaring("s1-fixture", S1_SERIES),
        |registry| {
            registry
                .open_export("s1-fixture-alias", &cfg)
                .expect("a first-party declaration opens")
        },
        transcript,
    ) else {
        eprintln!("skip: the export fixture's cdylib is not built");
        return;
    };
    assert!(
        linked.1.contains(r#""granted":true"#) && linked.1.contains(S1_SERIES),
        "the linked door grants the declared series and the sink reports under it: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "both doors grant and fold the same");

    // RED ARM 1: a third party declaring the same kind of claim is granted nothing.
    let (crate_snake, _) = super::both_ways::fixture("export");
    let lib = std::fs::read(super::both_ways::cdylib(crate_snake).expect("built above"))
        .expect("read the cdylib");
    let mut third = declaring("s1-third-party", "busbar_s1_third_party_total");
    third.publisher = "acme".into();
    let registry = super::both_ways::dropped_third_party(crate_snake, third, &lib);
    registry
        .open_export("s1-third-party", "{}")
        .expect("a third party opens; its declaration is simply not granted");
    assert!(!crate::observe::first_party_series(
        "s1-third-party",
        "busbar_s1_third_party_total",
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
