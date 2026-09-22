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
//! file. It reproduces what the old arrangement did — a sink incrementing its own in-process
//! registry — and shows the two builds diverging. A test that only ever passes cannot tell you what
//! it is protecting you from.

use super::*;
use busbar_plugin::cold::export::ExportRequest;

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
                assert_eq!(sink.streams(), &[ExportStream::Metrics]);
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
        [profile_dir.join(&name), profile_dir.join("deps").join(&name)]
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
             build busbar_export_example_plugin. Refusing to silently skip DECISIONS #11's \
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
         observations — this is DECISIONS #11's real test"
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

/// **THE RED ARM — what the old arrangement did, kept as the witness.**
///
/// A sink that reaches a recorder directly increments whichever registry its own object links. Two
/// builds link two different objects, so they increment two different registries — and the host
/// scrapes exactly one of them. Modelled here with two registries and one scrape, because that is
/// the shape of the defect rather than an analogy for it: the numbers diverge, nothing errors, and
/// nothing anywhere notices.
///
/// The envelope makes this unrepresentable. A plugin has no symbol to call: it REPORTS, on a wire
/// that goes to exactly one place, and the host is what increments.
#[test]
fn the_pre_envelope_path_loses_a_dropped_in_plugins_counters() {
    // The host's registry — the one a scrape renders.
    let host_registry = std::cell::Cell::new(0u64);
    // The registry a dropped-in cdylib links: its own, reachable by nobody.
    let plugin_local_registry = std::cell::Cell::new(0u64);

    // Compiled-in: the plugin's `metrics::counter!` resolves to the HOST's recorder, because there
    // is only one object and one linked facade.
    for _ in 0..2 {
        host_registry.set(host_registry.get() + 1);
    }
    let compiled_in_scrape = host_registry.get();

    // Dropped-in: the same source, the same two increments, into the copy of the facade the cdylib
    // statically linked. The host's registry never moves.
    host_registry.set(0);
    for _ in 0..2 {
        plugin_local_registry.set(plugin_local_registry.get() + 1);
    }
    let dropped_in_scrape = host_registry.get();

    assert_eq!(compiled_in_scrape, 2);
    assert_eq!(
        dropped_in_scrape, 0,
        "the defect: a dropped-in plugin's counters land where nothing scrapes"
    );
    assert_ne!(
        compiled_in_scrape, dropped_in_scrape,
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
