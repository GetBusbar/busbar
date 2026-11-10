// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io::Write;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Serialize, Serializer};

use super::{err_json, service, AppHandle};
use crate::v1::contract::AdminError;

pub(crate) const MAX_IDENTITIES: usize = 32;
const MAX_BODY_BYTES: usize = 64 * 1024;
pub(crate) const UPPER_BOUNDS_MS: [Option<u64>; 16] = [
    Some(1),
    Some(5),
    Some(10),
    Some(25),
    Some(50),
    Some(100),
    Some(250),
    Some(500),
    Some(1_000),
    Some(2_500),
    Some(5_000),
    Some(10_000),
    Some(30_000),
    Some(60_000),
    Some(120_000),
    None,
];

/// An exact unsigned 64-bit integer, encoded as a decimal string.
#[derive(Clone, Copy)]
pub(crate) struct ExactU64(pub u64);

impl Serialize for ExactU64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

#[cfg(feature = "openapi-schema")]
impl schemars::JsonSchema for ExactU64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TelemetryExactU64".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^(0|[1-9][0-9]*)$",
            "maxLength": 20,
            "description": "Unsigned 64-bit integer as an exact decimal string."
        })
    }
}

#[derive(Serialize)]
pub(crate) enum Phase {
    /// Producer drive returned; buffered response bytes may still be draining.
    LlmProducerDrive,
    /// A mounted handler returned its response; its body may still be streaming.
    MountedResponseReady,
}

#[cfg(feature = "openapi-schema")]
impl schemars::JsonSchema for Phase {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Phase".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "enum": ["LlmProducerDrive", "MountedResponseReady"],
            "description": "LlmProducerDrive: producer drive returned; buffered response bytes may still be draining. MountedResponseReady: mounted handler returned its response; its body may still be streaming."
        })
    }
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct Identity {
    pub plane: String,
    pub phase: Phase,
    pub pool: String,
    pub ingress_protocol: String,
    pub count: ExactU64,
    /// Observations whose existing outcome is `error` or `exhausted` (including HTTP 503).
    pub errors: ExactU64,
    /// Observations whose existing outcome is `client_error` (HTTP 4xx).
    pub client_errors: ExactU64,
    /// Cumulative sum of individual durations truncated to whole microseconds.
    pub sum_us: ExactU64,
    /// Exclusive bins corresponding to `upper_bounds_ms`; their sum equals `count`.
    pub bins: [ExactU64; 16],
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct Dropped {
    pub invalid_duration: ExactU64,
    pub integer_overflow: ExactU64,
    pub series_capacity: ExactU64,
    pub boot_nonce_unavailable: ExactU64,
    pub histogram_capacity: ExactU64,
    pub unregistered_labels: ExactU64,
}

/// Cumulative metrics for one process generation, bounded to 32 identities and 64 KiB.
/// This is a process snapshot, not a time window or a history query.
#[derive(Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct TelemetryView {
    /// Random 128-bit process nonce. Stable across scrapes and configuration reloads.
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(regex(pattern = "^[0-9a-f]{32}$"))
    )]
    pub process_boot_nonce: String,
    /// Monotonic milliseconds since shared process-generation initialization (first use), not OS
    /// process creation. Reading `GET /info` may establish this epoch before metrics are enabled.
    pub uptime_since_start_ms: ExactU64,
    /// Engine wall-clock Unix milliseconds sampled while this snapshot is captured. Distinct
    /// from monotonic uptime and from the consumer's receive time; wall time may move backwards.
    pub captured_at_unix_ms: ExactU64,
    /// Inclusive upper edge for each exclusive bin; final null means positive infinity.
    pub upper_bounds_ms: [Option<u64>; 16],
    #[cfg_attr(feature = "openapi-schema", schemars(length(max = 32)))]
    pub identities: Vec<Identity>,
    /// Identities omitted for the row cap, oversized labels, or the response byte cap.
    pub omitted_identities: ExactU64,
    pub truncated: bool,
    /// Cumulative losses. Each identity's count/sum/bins is coherent; these diagnostic counters
    /// are not a single atomic snapshot with one another or with every identity.
    pub dropped: Dropped,
}

struct BoundedBody(Vec<u8>);

impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BODY_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("telemetry response byte cap"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode(mut view: TelemetryView) -> Result<Vec<u8>, AdminError> {
    let extra = view.identities.len().saturating_sub(MAX_IDENTITIES);
    view.identities.truncate(MAX_IDENTITIES);
    view.omitted_identities.0 = view
        .omitted_identities
        .0
        .checked_add(extra as u64)
        .ok_or_else(|| AdminError::Unavailable("telemetry omission count overflow".into()))?;
    let mut body = BoundedBody(Vec::with_capacity(MAX_BODY_BYTES));
    loop {
        view.truncated = view.omitted_identities.0 != 0;
        body.0.clear();
        if serde_json::to_writer(&mut body, &view).is_ok() {
            return Ok(body.0);
        }
        if view.identities.pop().is_none() {
            return Err(AdminError::Unavailable(
                "telemetry snapshot exceeds response cap".into(),
            ));
        }
        view.omitted_identities.0 =
            view.omitted_identities.0.checked_add(1).ok_or_else(|| {
                AdminError::Unavailable("telemetry omission count overflow".into())
            })?;
    }
}

fn response(view: Result<TelemetryView, AdminError>) -> Response {
    match view.and_then(encode) {
        Ok(body) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    busbar_contract::protocol::APPLICATION_JSON,
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(error) => err_json(&error),
    }
}

pub(super) async fn get(State(handle): State<Arc<AppHandle>>) -> Response {
    response(service(&handle).telemetry())
}

#[cfg(test)]
#[path = "tests/telemetry_tests.rs"]
mod tests;
