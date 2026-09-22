// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the single [`ExportStream::Metrics`] stream, COUNTS every delivered batch, and drops
//! it. It is the in-tree ABI-crossing coverage for the `kind: export` seam, the
//! export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: `streams()` reports `[Metrics]` and `deliver()` drops the batch
//! after counting it. Config JSON is ignored (this sink has no configurable shape), mirroring
//! `busbar-store-example-plugin`'s config-less posture.

use busbar_plugin_sdk::{ExportHandler, ExportStream, Observations, PluginMetric};

/// The trivial sink: carries the metrics stream, counts what it was handed, drops the batches.
///
/// It counts deliveries for ONE reason: it is the in-tree witness for DECISIONS #11's
/// compiled-in ≡ dropped-in equivalence, and an equivalence over a plugin that OBSERVES NOTHING
/// proves nothing. The counter is the smallest observable effect a sink can have, so it is the
/// smallest thing whose loss would be invisible — which is exactly what the equivalence is about:
/// the same crate built as a linked rlib and as a dropped-in `cdylib` must yield the SAME metrics,
/// and before the observability envelope (#85) it could not, because a compiled-in build reached the
/// process-global recorder and a dropped-in one linked its own.
#[derive(Default)]
struct ExampleExport {
    /// Batches handed to `deliver` since the last drain. `Relaxed` is right: nothing orders against
    /// this and the only reader is the drain, which is called from the same boundary call.
    delivered: std::sync::atomic::AtomicU64,
}

/// The series this sink reports. Deliberately OUTSIDE the reserved `busbar_` namespace, which the
/// host refuses from any plugin.
const DELIVERED_TOTAL: &str = "example_export_deliveries_total";

impl ExportHandler for ExampleExport {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }

    /// Count the batch and drop it — this sink ships nothing anywhere.
    fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) {
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Hand over what has happened since the last drain and RESET.
    ///
    /// `swap`, not `load`: the SDK puts whatever this returns on the current call's envelope and the
    /// host folds a counter as a DELTA. Returning a running total instead would make every response
    /// re-report every earlier delivery, and the folded counter would grow quadratically.
    fn drain_observations(&self) -> Observations {
        let n = self.delivered.swap(0, std::sync::atomic::Ordering::Relaxed);
        if n == 0 {
            return Observations::none();
        }
        Observations::none().metric(PluginMetric::counter(DELIVERED_TOTAL, n as f64))
    }
}

/// Construct the sink. No config is read; malformed JSON in `cfg` is accepted and ignored rather than
/// a load error, since there is nothing in this plugin's config shape that could be malformed.
///
/// `pub` so the COMPILED-IN arm of the both-ways equivalence test can construct exactly the handler
/// the `cdylib`'s `busbar_open` constructs. That is the whole point of the equivalence: not two
/// similar objects built two ways, but the SAME constructor reached down two different paths. The
/// plane kind's `["cdylib", "rlib"]` conformance fixture does the same thing for the same reason.
pub fn open(_cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(ExampleExport::default()))
}

busbar_plugin_sdk::export_export_plugin!(open);

/// THE COMPILED-IN ENTRY POINT — the twin of the `busbar_call` symbol the macro above emits.
///
/// A dropped-in build is reached through `busbar_call`; a compiled-in build has to be reached
/// through something, and DECISIONS #11 says the two are the same plugin over the same contract. So
/// the compiled-in door is the same op-dispatch the C symbol runs — `dispatch_export_enveloped`,
/// including the observability envelope (#85) — and NOT a privileged shortcut into the handler.
///
/// That distinction is the whole of #11's real test. If a compiled-in plugin were allowed to skip
/// the envelope and touch the host's recorder directly, it would be a DIFFERENT plugin with
/// different observable behaviour, which is exactly what was silently true before #85.
///
/// Declared HERE rather than in the host's test so the host needs no edge to the author machinery:
/// the entry point a plugin offers is the plugin's to publish, on both doors.
pub fn dispatch_compiled_in(
    handler: &dyn ExportHandler,
    req: busbar_plugin_sdk::ExportRequest,
) -> busbar_plugin_sdk::Envelope<busbar_plugin_sdk::ExportResponse> {
    busbar_plugin_sdk::dispatch_export_enveloped(handler, req)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
