// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the [`ExportStream::Metrics`] and [`ExportStream::Logs`] streams, COUNTS every delivered
//! batch, and drops it. It is the in-tree ABI-crossing coverage for the `kind: export` seam, the
//! export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: `streams()` reports `[Metrics, Logs]` and `deliver()` drops the batch
//! after counting it. Config JSON is ignored (this sink has no configurable shape), mirroring
//! `busbar-store-example-plugin`'s config-less posture.

use busbar_plugin_sdk::{
    ExportHandler, ExportStream, HostOp, HostResult, HostStep, HttpRequest, Observations,
    PluginDiagnostic, PluginMetric,
};

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
    /// Rotations the host reported performing for this sink since the last drain (K9a S4).
    rotated: std::sync::atomic::AtomicU64,
    /// Host acts the host reported FAILING for this sink since the last drain (K9a S4).
    host_failures: std::sync::atomic::AtomicU64,
    /// Batches the host POSTed for this sink and the far end accepted (K9a S5).
    posted: std::sync::atomic::AtomicU64,
    /// The settings this instance was opened with, when they are a JSON object — read by the host
    /// seams' witnesses (K9a) and by nothing else; a sink with no settings behaves as it always did.
    settings: serde_json::Map<String, serde_json::Value>,
}

impl ExampleExport {
    /// A string setting, if the instance was opened with one under `key`.
    fn setting(&self, key: &str) -> Option<&str> {
        self.settings.get(key).and_then(serde_json::Value::as_str)
    }
}

/// The series this sink reports. Deliberately OUTSIDE the reserved `busbar_` namespace, which the
/// host refuses from any plugin.
const DELIVERED_TOTAL: &str = "example_export_deliveries_total";

/// Rotations the host performed for this sink (K9a S4's witness).
const ROTATED_TOTAL: &str = "example_export_rotations_total";

/// Host acts that failed for this sink (K9a S4's witness).
const HOST_FAILURES_TOTAL: &str = "example_export_host_failures_total";

/// Batches the host carried out for this sink and the far end accepted (K9a S5's witness).
const POSTED_TOTAL: &str = "example_export_posts_total";

impl ExportHandler for ExampleExport {
    /// `metrics` and `logs`: `logs` because it is the stream the host PUSHES today (the request-log
    /// line), so an `export:` instance naming this plugin is actually handed batches — which is what
    /// the composition root's "a dropped-in export plugin serves" test observes.
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics, ExportStream::Logs]
    }

    /// Count the batch and drop it — this sink ships nothing anywhere.
    fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) {
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// With a `path` DESTINATION configured (K9a S4's witness), have the HOST append the batch as
    /// one JSON line — rotating at `rotate_bytes` — instead of dropping it. The sink names the
    /// destination by its settings key; it never opens the path.
    fn deliver_via_host(&self, stream: ExportStream, payload: &serde_json::Value) -> HostStep {
        self.deliver(stream, payload);
        let mut ops = Vec::new();
        if self.setting("path").is_some() {
            let rotate_at = self.settings.get("rotate_bytes").and_then(|v| v.as_u64());
            ops.push(HostOp::Write {
                destination: "path".to_string(),
                data: format!("{payload}\n"),
                rotate_at,
                keep: 9,
            });
        }
        // With a `url` configured (K9a S5's witness), have the HOST POST the batch through its
        // egress — this sink never dials.
        if let Some(url) = self.setting("url") {
            ops.push(HostOp::Http(HttpRequest {
                method: "POST".into(),
                url: url.to_string(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: payload.to_string(),
                timeout_ms: 5_000,
            }));
        }
        match ops.is_empty() {
            true => HostStep::Done,
            false => HostStep::Host { token: 0, ops },
        }
    }

    /// Count what the host reports: each rotation it ran, and each act that failed.
    fn resume(&self, _token: u64, results: Vec<HostResult>) -> HostStep {
        use std::sync::atomic::Ordering::Relaxed;
        for result in results {
            let (rotation, failed, posted) = match result {
                HostResult::Done { rotation } => (rotation, false, false),
                HostResult::Failed { rotation, .. } => (rotation, true, false),
                HostResult::Http(answer) => {
                    let ok = (200..300).contains(&answer.status);
                    (None, !ok, ok)
                }
            };
            self.posted.fetch_add(u64::from(posted), Relaxed);
            self.host_failures.fetch_add(u64::from(failed), Relaxed);
            self.rotated
                .fetch_add(u64::from(rotation.is_some_and(|r| r.renamed)), Relaxed);
        }
        HostStep::Done
    }

    /// The one setting this sink has a shape for: `series`, when present, is a string (K9a S2's
    /// witness — its error is the line a built-in module's settings error would be).
    fn validate(&self, instance: &str, settings: &serde_json::Value) -> Vec<String> {
        match settings.get("series") {
            Some(v) if !v.is_string() => vec![format!(
                "export.{instance}.settings.series: must be a string naming the delivery counter"
            )],
            _ => Vec::new(),
        }
    }

    /// Hand over what has happened since the last drain and RESET.
    ///
    /// `swap`, not `load`: the SDK puts whatever this returns on the current call's envelope and the
    /// host folds a counter as a DELTA. Returning a running total instead would make every response
    /// re-report every earlier delivery, and the folded counter would grow quadratically.
    fn drain_observations(&self) -> Observations {
        use std::sync::atomic::Ordering::Relaxed;
        // `series` names the delivery counter instead: the FIRST-PARTY NAMESPACE witness (K9a S1)
        // opens the sink under a reserved name its manifest declares.
        let delivered = self.setting("series").unwrap_or(DELIVERED_TOTAL);
        let mut observed = Observations::none();
        for (series, counter) in [
            (delivered, &self.delivered),
            (ROTATED_TOTAL, &self.rotated),
            (HOST_FAILURES_TOTAL, &self.host_failures),
            (POSTED_TOTAL, &self.posted),
        ] {
            let n = counter.swap(0, Relaxed);
            if n > 0 {
                observed = observed.metric(PluginMetric::counter(series, n as f64));
            }
        }
        // `diagnostic` names a code the sink raises per drain of deliveries: the PLUGIN DIAGNOSTICS
        // witness (K9a S3) opens the sink under a code its manifest declares.
        match self.setting("diagnostic") {
            Some(code) if !observed.is_empty() => {
                observed.diagnostic(PluginDiagnostic::warn(code, "batches delivered"))
            }
            _ => observed,
        }
    }
}

/// Construct the sink. Malformed JSON in `cfg` is accepted and ignored rather than a load error;
/// a JSON object is kept for the few settings the host seams' witnesses read (see [`ExampleExport`]).
///
/// `pub` so the COMPILED-IN arm of the both-ways equivalence test can construct exactly the handler
/// the `cdylib`'s `busbar_open` constructs. That is the whole point of the equivalence: not two
/// similar objects built two ways, but the SAME constructor reached down two different paths. The
/// plane kind's `["cdylib", "rlib"]` conformance fixture does the same thing for the same reason.
pub fn open(cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    let settings = match serde_json::from_str(cfg) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    Ok(Box::new(ExampleExport {
        settings,
        ..ExampleExport::default()
    }))
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
