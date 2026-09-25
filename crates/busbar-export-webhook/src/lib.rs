// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-webhook`** — the request-log WEBHOOK sink as a `kind: export` plugin (item 141,
//! owner ruling 2026-09-18 in #3): `export.<name>.module: request-log-webhook`.
//!
//! Each request-log line the host hands it is POSTed, as compact JSON with
//! `content-type: application/json` and the instance's optional `auth_header`, to the instance's
//! `https://` target — by the HOST: the sink answers each delivery with an [`HostOp::Http`] and the
//! host's egress carrier makes the request under its own URL policy (https only; loopback,
//! link-local, private, CGNAT and cloud-metadata targets refused), TLS and the instance's
//! `delivery_timeout_secs` deadline. The sink never dials. A delivery is fire-and-forget and never
//! retried: a non-2xx answer or a transport failure drops that one line and raises BUSBAR-7071 /
//! BUSBAR-7072 at debug.
//!
//! **Start.** When the host starts its sinks it asks the policy about the target
//! ([`HostOp::Admit`]); a refused target raises BUSBAR-7070 (`…; disabling this webhook exporter`)
//! and the instance takes no delivery this run — its siblings keep delivering. A live instance
//! states its admission: `max_inflight_deliveries` in flight at once under the `webhook` gate; past
//! it the host sheds the line and counts `busbar_webhook_logs_dropped_total` (the manifest's shed
//! counter).
//!
//! **Settings** are checked in two phases, as they always were: their SHAPE while the configuration
//! is resolved ([`ExportHandler::validate`]: `export.<name>.settings: …`), and the delivery deadline
//! and in-flight bound while it is validated ([`ExportHandler::check`], after the limits).
//!
//! The one registration both doors take states [`NAME`], [`ALIAS`] and [`DECLARES`] (the manifest
//! `declares` section its signed tarball carries: the shed counter and the three catalogue codes it
//! raises) over its boundary — [`linked::EXPORT`] for the linked door.

#![deny(unsafe_code)]

use busbar_plugin_sdk::{
    DiagLevel, ExportHandler, ExportStream, HostOp, HostResult, HostStep, HttpRequest,
    Observations, PluginDiagnostic,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The plugin's canonical name.
pub const NAME: &str = "busbar-export-webhook";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "request-log-webhook";
/// The manifest `declares` section both doors state (`--declares-file` for the signed tarball).
pub const DECLARES: &str = include_str!("../declares.json");

/// The in-flight ceiling: the host's semaphore holds at most `usize::MAX >> 3` permits, and a
/// larger bound panics where the gate is built rather than failing validation.
const MAX_PERMITS: usize = usize::MAX >> 3;
/// The ceiling every duration in a busbar configuration is bounded by (30 years, in seconds).
const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;
/// The gate the host counts this sink's sheds under.
const GATE: &str = "webhook";
/// The token of the start-time admission ask ([`HostOp::Admit`]); deliveries count from 1.
const START: u64 = 0;

const DISABLED: &str = "BUSBAR-7070";
const NON_2XX: &str = "BUSBAR-7071";
const TRANSPORT_ERROR: &str = "BUSBAR-7072";

mod config;
use config::DEFAULT_MAX_INFLIGHT;
pub use config::{ExportAuthHeader, WebhookSettings};

/// This sink's settings (the configuration's `WebhookSettings`).
pub type Settings = WebhookSettings;

/// One opened instance.
struct Webhook {
    /// Its settings, when they parse (the host refused the configuration otherwise; a sink opened
    /// only to validate or check settings still opens).
    settings: Option<Settings>,
    /// The next delivery's token.
    next: AtomicU64,
    /// Diagnostics raised since the last drain.
    raised: Mutex<Vec<PluginDiagnostic>>,
}

impl Webhook {
    fn raise(&self, d: PluginDiagnostic) {
        self.raised
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(d);
    }

    /// The target as its diagnostics name it: userinfo masked, quoted as a string field is.
    fn shown_url(&self) -> String {
        let url = self.settings.as_ref().map_or("", |s| s.url.as_str());
        format!("{:?}", mask_userinfo(url))
    }
}

impl ExportHandler for Webhook {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Logs]
    }

    fn validate(&self, instance: &str, settings: &serde_json::Value) -> Vec<String> {
        match serde_json::from_value::<Settings>(settings.clone()) {
            Ok(_) => Vec::new(),
            Err(e) => vec![format!("export.{instance}.settings: {e}")],
        }
    }

    fn check(&self, instances: &[(String, serde_json::Value)]) -> Vec<String> {
        check(instances)
    }

    fn start(&self) -> HostStep {
        match &self.settings {
            Some(s) => HostStep::Host {
                token: START,
                ops: vec![HostOp::Admit { url: s.url.clone() }],
            },
            None => stopped(),
        }
    }

    fn deliver_via_host(&self, _stream: ExportStream, payload: &serde_json::Value) -> HostStep {
        let Some(s) = &self.settings else {
            return HostStep::Done;
        };
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(h) = &s.auth_header {
            headers.push((h.name.clone(), h.value.clone()));
        }
        HostStep::Host {
            token: self.next.fetch_add(1, Ordering::Relaxed),
            ops: vec![HostOp::Http(HttpRequest {
                method: "POST".to_string(),
                url: s.url.clone(),
                headers,
                body: payload.to_string(),
                timeout_ms: s.delivery_timeout_secs.saturating_mul(1000),
            })],
        }
    }

    fn resume(&self, token: u64, results: Vec<HostResult>) -> HostStep {
        let outcome = results.into_iter().next();
        if token == START {
            return match (outcome, &self.settings) {
                (Some(HostResult::Done { .. }), Some(s)) => HostStep::Started {
                    live: true,
                    inflight: s.max_inflight_deliveries.clamp(1, MAX_PERMITS) as u64,
                    gate: GATE.to_string(),
                },
                (Some(HostResult::Failed { error, .. }), _) => {
                    let message = format!("{error}; disabling this webhook exporter");
                    self.raise(PluginDiagnostic::new(DISABLED, DiagLevel::Error, message));
                    stopped()
                }
                _ => stopped(),
            };
        }
        match outcome {
            Some(HostResult::Http(answer)) if (200..300).contains(&answer.status) => {}
            Some(HostResult::Http(answer)) => self.raise(
                PluginDiagnostic::new(
                    NON_2XX,
                    DiagLevel::Debug,
                    "request-log webhook delivery returned a non-2xx status; this log was dropped",
                )
                .field("webhook_url", self.shown_url())
                .field("status", answer.status.to_string()),
            ),
            Some(HostResult::Failed { error, .. }) => self.raise(
                PluginDiagnostic::new(
                    TRANSPORT_ERROR,
                    DiagLevel::Debug,
                    "request-log webhook delivery failed (transport error); this log was dropped",
                )
                .field("webhook_url", self.shown_url())
                .field("error_kind", error),
            ),
            _ => {}
        }
        HostStep::Done
    }

    fn drain_observations(&self) -> Observations {
        let raised = std::mem::take(&mut *self.raised.lock().unwrap_or_else(|e| e.into_inner()));
        raised
            .into_iter()
            .fold(Observations::none(), Observations::diagnostic)
    }
}

/// Started, taking nothing this run.
fn stopped() -> HostStep {
    HostStep::Started {
        live: false,
        inflight: 0,
        gate: GATE.to_string(),
    }
}

/// The checks the configuration's VALIDATION runs across every webhook instance, in order: the
/// in-flight bound — one bound over the instances, the largest configured (64 with none), so a
/// generous instance is never refused for a stingy sibling — then each instance's delivery
/// deadline, numbered by its position among them.
pub fn check(instances: &[(String, serde_json::Value)]) -> Vec<String> {
    let parsed: Vec<Settings> = instances
        .iter()
        .filter_map(|(_, s)| serde_json::from_value(s.clone()).ok())
        .collect();
    let mut errors = Vec::new();
    let bound = parsed
        .iter()
        .map(|w| w.max_inflight_deliveries)
        .max()
        .unwrap_or(DEFAULT_MAX_INFLIGHT);
    if bound < 1 {
        errors.push(
            "export.request-log-webhook.settings.max_inflight_deliveries must be >= 1 (a 0-permit \
             semaphore admits nothing, silently dropping every webhook delivery)"
                .to_string(),
        );
    }
    if bound > MAX_PERMITS {
        errors.push(format!(
            "export.request-log-webhook.settings.max_inflight_deliveries must be <= \
             {MAX_PERMITS} (tokio::sync::Semaphore's hard permit ceiling — a value above \
             it panics at build time instead of failing validation)"
        ));
    }
    for (i, w) in parsed.iter().enumerate() {
        if w.delivery_timeout_secs > MAX_DURATION_SECS {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: {}, above the {MAX_DURATION_SECS}-second (30-year) \
                 ceiling every duration is bounded by — a delivery deadline that far out overflows \
                 the clock",
                w.url, w.delivery_timeout_secs
            ));
        }
        if w.delivery_timeout_secs < 1 {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: 0, which would abort every delivery — it must be \
                 >= 1",
                w.url
            ));
        }
    }
    errors
}

/// `url` with any userinfo (`scheme://user:pass@host/…`) replaced by `***`, safe for a log line;
/// a URL with none, or a string that is not a URL, unchanged.
pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    if parsed.username().is_empty() && parsed.password().is_none() {
        return url.to_string();
    }
    if parsed.set_password(None).is_err() || parsed.set_username("***").is_err() {
        let host = parsed.host_str().unwrap_or("");
        return match parsed.port() {
            Some(p) => format!("{}://***@{host}:{p}", parsed.scheme()),
            None => format!("{}://***@{host}", parsed.scheme()),
        };
    }
    parsed.into()
}

/// Open an instance with its settings (JSON text). Never fails: settings that do not parse are the
/// configuration's refusal, reported by [`ExportHandler::validate`] — a sink opened only to answer
/// that must open.
pub fn open(cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(Webhook {
        settings: serde_json::from_str(cfg).ok(),
        next: AtomicU64::new(START + 1),
        raised: Mutex::new(Vec::new()),
    }))
}

busbar_plugin_sdk::export_export_plugin!(open);

/// THE COMPILED-IN ENTRY POINT — the same op-dispatch and envelope the `busbar_call` symbol runs.
pub fn dispatch_compiled_in(
    handler: &dyn ExportHandler,
    req: busbar_plugin_sdk::ExportRequest,
) -> busbar_plugin_sdk::Envelope<busbar_plugin_sdk::ExportResponse> {
    busbar_plugin_sdk::dispatch_export_enveloped(handler, req)
}

/// THE LINKED DOOR's entry: what the composition root's linked table registers through the one
/// registration a dropped-in tarball of this crate also takes.
pub mod linked {
    /// `(name, alias, declares, boundary)`.
    pub const EXPORT: (&str, &str, &str, &busbar_plugin_sdk::__abi::ColdEntry) = (
        super::NAME,
        super::ALIAS,
        super::DECLARES,
        &super::BUSBAR_COLD_ENTRY,
    );
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
