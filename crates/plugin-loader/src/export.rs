// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The EXPORT seam of the kind-neutral loader: [`DynExport`], a telemetry sink backed by a
//! dynamically-loaded plugin whose kind was bound to `export` at load. It queries the plugin's
//! declared streams ONCE at load (retaining them alongside the handle) and translates each delivery
//! into a `busbar_call` with the matching op envelope ([`busbar_plugin_abi::export`]).
//!
//! Mirrors the store/secret load seams: same trust/staging/wire-up pipeline, only the KIND (and the
//! consuming engine seam) differs. The ACTUAL wiring of a delivery to the engine's
//! metrics/audit/logs pipelines lands separately — this seam just proves an export plugin LOADS and
//! reports the streams it carries.

use crate::{stage, wire_up_raw, RawPlugin};
use busbar_plugin_abi::{
    export::{ExportRequest, ExportResponse, ExportStream},
    http_endpoint::{HttpEndpointRequest, HttpEndpointResponse, Route},
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
    pub fn handle_http(
        &self,
        request: &HttpEndpointRequest,
    ) -> Result<HttpEndpointResponse, String> {
        let req = ExportRequest::HttpEndpoint {
            request: request.clone(),
        };
        match self
            .raw
            .transport_call::<ExportRequest, ExportResponse>(&req)?
        {
            ExportResponse::Http(resp) => Ok(resp),
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
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::EXPORT,
        manifest_kind,
        Some(staged),
    )?;
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
    // Query the declared HTTP routes ONCE at load. ADDITIVE: a sink built against an older SDK cannot
    // decode the `routes` op and its dispatch returns the undecodable-variant signal (or an unexpected
    // arm) — treated as "no HTTP surface" rather than a load failure, so an existing metrics-push sink
    // keeps loading unchanged.
    let routes = match raw.transport_call::<ExportRequest, ExportResponse>(&ExportRequest::Routes) {
        Ok(ExportResponse::Routes(r)) => r,
        Ok(_) | Err(_) => Vec::new(),
    };
    Ok(DynExport {
        raw,
        streams,
        routes,
    })
}
