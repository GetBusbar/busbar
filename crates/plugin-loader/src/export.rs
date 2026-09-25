// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The EXPORT seam of the kind-neutral loader: [`DynExport`], a telemetry sink backed by a
//! dynamically-loaded plugin whose kind was bound to `export` at load. It queries the plugin's
//! declared streams ONCE at load (retaining them alongside the handle) and translates each delivery
//! into a `busbar_call` with the matching op envelope ([`busbar_plugin::cold::export`]).
//!
//! Mirrors the store/secret load seams: same trust/staging/wire-up pipeline, only the KIND (and the
//! consuming engine seam) differs. The ACTUAL wiring of a delivery to the engine's
//! metrics/audit/logs pipelines lands separately — this seam just proves an export plugin LOADS and
//! reports the streams it carries.

use crate::RawPlugin;
use busbar_plugin::cold::{
    endpoint::{EndpointRequest, EndpointResponse, Route},
    export::{ExportRequest, ExportResponse, ExportStream},
    kind as abi_kind,
};

/// A telemetry export sink loaded from a dynamic library over the kind-neutral ABI. Wraps a
/// [`RawPlugin`] whose kind was bound to `export` at load; the streams it carries are queried once at
/// load and retained here so the engine can route deliveries only for declared streams.
pub struct DynExport {
    raw: RawPlugin,
    /// The streams this instance reported to `Streams` at load — the minimal registry entry.
    streams: Vec<ExportStream>,
    /// The HTTP routes this instance declared to `Routes` at load — collected ONCE, retained so the
    /// engine's router builder can collision-check + mount them without a second ABI call.
    routes: Vec<Route>,
}

impl DynExport {
    /// The observability streams this sink declared at load.
    pub fn streams(&self) -> &[ExportStream] {
        &self.streams
    }

    /// The HTTP routes this sink declared at load (collision-checked + namespace-confined by the engine
    /// before mounting). Empty for a push-only sink with no HTTP surface.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Dispatch one inbound HTTP request (matched to a registered route of this plugin) across the ABI.
    /// The engine has already enforced the route's declared auth; this just relays the exchange. A
    /// transport failure or an unexpected response variant is an `Err` naming the plugin.
    pub fn handle_http(&self, request: &EndpointRequest) -> Result<EndpointResponse, String> {
        let req = ExportRequest::Endpoint {
            request: request.clone(),
        };
        match self
            .raw
            .transport_call::<ExportRequest, ExportResponse>(&req)?
        {
            ExportResponse::Endpoint(resp) => Ok(resp),
            other => Err(format!(
                "export plugin '{}' returned an unexpected response to http_endpoint: {other:?}",
                self.raw.path
            )),
        }
    }

    /// Hand one batch for `stream` across the ABI. Returns `Ok(())` on a `Delivered` ack; a transport
    /// failure or an unexpected response variant is an `Err` naming the plugin.
    pub fn deliver(&self, stream: ExportStream, payload: &serde_json::Value) -> Result<(), String> {
        let req = ExportRequest::Deliver {
            stream,
            payload: payload.clone(),
        };
        match self
            .raw
            .transport_call::<ExportRequest, ExportResponse>(&req)?
        {
            ExportResponse::Delivered => Ok(()),
            other => Err(format!(
                "export plugin '{}' returned an unexpected response to deliver: {other:?}",
                self.raw.path
            )),
        }
    }
}

impl DynExport {
    /// Ask the sink what it has to report NOW — the host's pull, at the moment it renders its own
    /// exposition — and fold the answer through the ONE observability path every envelope takes
    /// ([`crate::observe`]), under this sink's host-assigned name. The host validates, bounds and
    /// decides exactly as it does for an envelope; nothing here trusts the sink's entries.
    ///
    /// ADDITIVE on exactly one arm, like `routes` at load: a sink built before the op cannot decode
    /// it and says so out of band, which is the sink having nothing to report. Every OTHER failure is
    /// the sink failing to answer: it is logged naming the sink, and the host renders without this
    /// sink's contribution rather than failing the scrape.
    pub fn status(&self) {
        if let Err(e) = self.status_report() {
            tracing::warn!(error = %e, "export plugin status failed");
        }
    }

    /// [`DynExport::status`]'s answer, with a failure returned rather than logged.
    pub fn status_report(&self) -> Result<(), String> {
        match self
            .raw
            .transport_call_status::<ExportRequest, ExportResponse>(&ExportRequest::Status)
        {
            Ok(ExportResponse::Status {
                metrics,
                diagnostics,
            }) => {
                let report = busbar_plugin::cold::observe::Envelope {
                    result: (),
                    metrics,
                    diagnostics,
                };
                crate::observe::fold(&self.raw.path, abi_kind::EXPORT, &report);
                Ok(())
            }
            Ok(other) => Err(format!(
                "export plugin '{}' returned an unexpected response to status: {other:?}",
                self.raw.path
            )),
            Err(e) if e.is_unsupported() => Ok(()),
            Err(e) => Err(format!(
                "export plugin '{}' could not be asked for its status: {}",
                self.raw.path, e.message
            )),
        }
    }
}

impl DynExport {
    /// Serve one inbound request matched to this sink's route, as the route table relays it: a sink
    /// that cannot answer is a `502` with no body to the client and a warning naming it to the
    /// operator — the exchange never fails open into a partial response.
    pub fn serve(&self, request: &EndpointRequest) -> EndpointResponse {
        self.handle_http(request).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "export plugin route failed");
            EndpointResponse {
                status: 502,
                headers: Vec::new(),
                body: Vec::new(),
            }
        })
    }

    /// Hand one batch across the ABI OFF the calling thread — the host's delivery, which must never
    /// touch the request that produced it. `hold` is released when the call returns (the caller's
    /// in-flight permit); a sink that errors is logged (the error names it) and the batch is dropped.
    pub fn deliver_detached(
        self: &std::sync::Arc<Self>,
        stream: ExportStream,
        payload: std::sync::Arc<serde_json::Value>,
        hold: impl Send + 'static,
    ) {
        let sink = self.clone();
        tokio::task::spawn_blocking(move || {
            let _hold = hold;
            if let Err(e) = sink.deliver(stream, &payload) {
                tracing::warn!(error = %e, "export plugin delivery failed; this batch was dropped");
            }
        });
    }
}

impl std::fmt::Debug for DynExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynExport")
            .field("path", &self.raw.path)
            .field("streams", &self.streams)
            .field("routes", &self.routes)
            .finish()
    }
}

/// Load an EXPORT sink from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint; see
/// [`crate::load_store_from_bytes`] for the staging contract). Enforces the frozen contract (transport
/// version, kind == `export` == the signed manifest — mismatch is a hard fail-closed load error), then
/// `open`s it with `cfg_json` and queries its declared streams ONCE, retaining them on the handle.
pub fn load_export_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<DynExport, String> {
    load_export_image(crate::Image::Bytes(bytes), cfg_json, display, manifest_kind)
}

/// Load an EXPORT sink over either door's [`crate::Image`] — the one load [`load_export_from_bytes`]
/// runs, and the one a LINKED export plugin's boundary takes: the same handshake, kind cross-check,
/// `open`, and the same `streams`/`routes` questions at load.
pub fn load_export_image(
    image: crate::Image<'_>,
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<DynExport, String> {
    let raw = crate::load_image(image, cfg_json, display, abi_kind::EXPORT, manifest_kind)?;
    export_from_raw(raw, display)
}

/// Ask an already-wired plugin what it carries and hand back the sink. Split from the staging above
/// so the two questions a load asks — which streams, which routes — are exercisable over a chosen
/// set of answers rather than only over whatever a built cdylib happens to say.
fn export_from_raw(raw: RawPlugin, display: &str) -> Result<DynExport, String> {
    // Query the declared streams ONCE at load and retain them alongside the handle.
    let streams =
        match raw.transport_call::<ExportRequest, ExportResponse>(&ExportRequest::Streams)? {
            ExportResponse::Streams(s) => s,
            other => {
                return Err(format!(
                "export plugin '{display}' returned an unexpected response to streams: {other:?}"
            ))
            }
        };
    // Query the declared HTTP routes ONCE at load. ADDITIVE, and on exactly one arm: a sink built
    // against an older SDK cannot decode the `routes` op and says so out of band, which is the sink
    // saying it has no HTTP surface — that one keeps loading with an empty route table, as it did
    // before the op existed. Every OTHER failure is the sink failing to ANSWER rather than answering
    // "none": a caught panic, a backend error and a caller-protocol violation all fail the load,
    // because mounting a sink whose route table nobody has heard from mounts a gate that is not there.
    let routes =
        match raw.transport_call_status::<ExportRequest, ExportResponse>(&ExportRequest::Routes) {
            Ok(ExportResponse::Routes(r)) => r,
            Ok(other) => {
                return Err(format!(
                    "export plugin '{display}' returned an unexpected response to routes: {other:?}"
                ))
            }
            Err(e) if e.is_unsupported() => Vec::new(),
            Err(e) => {
                return Err(format!(
                    "export plugin '{display}' could not be asked for its HTTP routes: {}",
                    e.message
                ))
            }
        };
    Ok(DynExport {
        raw,
        streams,
        routes,
    })
}

#[cfg(test)]
#[path = "tests/export_tests.rs"]
mod tests;
