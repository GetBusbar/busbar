// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Built-in observability EXPORTERS: the distribution half of the observability
//! streams, lifted OUT of core into compiled-in modules that CONSUME the `export` plugin kind + the
//! plugin HTTP endpoint registration. PRESENCE + settings (the `export:` config block,
//! [`crate::config::ExportCfg`]) is the on/off switch, exactly like the built-in `env`/`file` secret
//! modules — no config boolean, no dynamic tarball.
//!
//! The COLLECTION half stays core: the Prometheus recorder + the ~57 emit sites + the
//! scrape-time gauge derivation live in [`crate::metrics`]; the request-log projection is still built
//! in the request-finish path. These modules move only the DISTRIBUTION:
//!
//! - [`prometheus`] — PULL. Serves `/metrics` via the endpoint-registration `handle_http` path (the
//!   well-known-`/metrics` exception), rendering the recorder registry. When `export.prometheus` is
//!   present the recorder is installed (collection on) and a `GET /metrics` plugin route is
//!   registered; absent ⇒ no recorder, `/metrics` unmounted, every emit site a true no-op.
//! - the `request-log-webhook` and `request-log-file` sinks are GONE from this crate: each body is
//!   a crate of kind `export`, which this crate may not name. What is left here is the config
//!   layer's own job — resolving the operator's `module:` token, the settings under it and, for a
//!   webhook, the SSRF verdict on its target — which this module hands to the composition root as
//!   [`request_log_webhook_instances`] and [`request_log_file_instances`]. The one piece of a
//!   webhook DELIVERY that is not the sink's is the socket, and that is the engine's egress client:
//!   [`webhook_send`], which leaves with that client and not with the sink.
//!
//! WHAT LEFT. The FAN-OUT is not here any more: the composition root builds one payload per
//! distinct projection, sheds for each sink against a gate it owns, and calls the sink. With the
//! last PUSH body gone to its own crate, this module states no sink at all — it resolves the
//! operator's document into INSTANCES and hands them over, which is the only half of a built-in
//! sink a config layer ever owned.

pub mod prometheus;

use crate::config::ExportCfg;
use crate::plugin_routes::{RouteDecl, RouteKind};
/// The projection grammar, re-exported for the COMPOSITION ROOT. The grammar itself lives in the
/// plugin ABI beside its vocabulary (`busbar_plugin::cold::export::projection`); the root reaches it
/// through here rather than naming the ABI crate directly, because the root's edge into this crate
/// is the one the retirement already accounts for and a second one into the ABI would be a new
/// undeclared dependency for a re-export.
pub use busbar_plugin::cold::export::projection::{build_request_log, Projection, RequestLogFacts};
use busbar_plugin_loader::ExportStream;
use busbar_plugin_loader::Route;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;

/// The streams the `request-log-file` sink carries. Its BODY is a crate of kind `export`, which
/// this crate may not name — but resolving which sink an operator's `module:` token names, and what
/// that sink was therefore granted, is the config layer's own job and stays here beside the token.
/// It moves out with the config layer, not with the sink.
pub(crate) const REQUEST_LOG_FILE_STREAMS: &[ExportStream] = &[ExportStream::Logs];

/// The streams the `otlp` sink carries. It has no module of its own in this crate — its config
/// surface is `ExportCfg::otlp` and its span pipeline is the tracing subscriber — so its
/// declaration sits here beside its siblings'. It moves to `busbar-export-otlp` with the pipeline.
pub(crate) const OTLP_STREAMS: &[ExportStream] = &[ExportStream::Traces];

/// The live plugin-route declarations the built-in exporters contribute — today just the
/// `prometheus` exporter's `GET /metrics`. Built at App construction from the resolved `export:` block
/// and folded into the [`crate::plugin_routes::PluginRouteTable`] on the App snapshot.
///
/// **A config apply UNMOUNTS but cannot MOUNT.** The two directions are not symmetric, and an earlier
/// version of this comment claimed they were:
///
/// - **Removing** `export.prometheus` takes effect immediately. The path stays registered on the
///   router, but [`crate::plugin_routes::plugin_route_dispatch`] resolves the owner from the CURRENT
///   snapshot on every request, finds nothing, and 404s. No rebuild needed.
/// - **Adding** it does NOT take effect until restart. Each declared PATH is registered on the axum
///   router once, at boot (`plugin_routes.rs`, `on(filter, plugin_route_dispatch)`), and a config
///   apply swaps only `Arc<App>` — the router is never rebuilt. If no `prometheus` instance existed
///   at boot, `/metrics` was never registered, so it keeps 404ing however many times the operator
///   PUTs the config. The metrics recorder is additionally `OnceLock`-guarded and installed once.
///
/// This is the SAME boot-frozen mechanism already documented for `max_inbound_concurrent` in
/// [`crate::admin::v1::json::handlers`]'s `reload_to_apply_fields`, and the
/// `export:` named map REPORTS it the same way: a mutation that introduces a route path the router
/// never registered at boot answers with `reload_to_apply` naming that path plus a `note` saying a
/// restart is required ([`crate::plugin_routes::paths_awaiting_restart`]). The apply is still a no-op
/// for the route itself — genuinely hot-mounting one is a router rebuild, not done here — but it is no
/// longer a SILENT one.
pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    prometheus::route_decl(cfg).into_iter().collect()
}

/// The manifest-level `(owner, kind, route)` mirror of [`route_decls`] for the `--validate`/boot
/// collision preflight — WITHOUT the live dispatchers, so a loaded third-party export plugin claiming
/// a path a built-in exporter already owns (e.g. `GET /metrics`) fails loudly before boot.
pub(crate) fn route_owners(cfg: &ExportCfg) -> Vec<(String, RouteKind, Route)> {
    prometheus::route_owner(cfg).into_iter().collect()
}

/// The streams the `request-log-webhook` sink carries. Its BODY is a crate of kind `export`, which
/// this crate may not name — the same split as the file sink's below: resolving which sink an
/// operator's `module:` token names, and what that sink was therefore granted, is the config
/// layer's own job and stays here beside the token.
pub(crate) const REQUEST_LOG_WEBHOOK_STREAMS: &[ExportStream] = &[ExportStream::Logs];

/// One configured `request-log-webhook` instance, as data for the composition root to build its
/// sink crate from — an ALREADY-VALIDATED target plus the policy numbers the composition enforces.
///
/// The SSRF guard runs HERE, at resolution, and not in the sink: whether an operator's URL may be
/// POSTed to at all is a judgement on the operator's document, made once by whoever reads that
/// document, and a sink asked to re-decide it per delivery would be deciding it in the wrong place.
/// A target that fails the guard is never turned into an instance at all (it is reported and left
/// disabled, the exact posture the single-webhook config had), so everything on this struct is a
/// target the guard already passed.
pub struct RequestLogWebhookInstance {
    /// The validated `https://` target every delivery of this instance is addressed to.
    pub url: String,
    /// The SAME target with any embedded userinfo masked — the ONLY spelling that may appear in a
    /// log line. It is computed here, beside the masker, so the sink crate holds no masker and can
    /// never log the wrong one of the two.
    pub display_url: String,
    /// The optional `{name, value}` auth header the operator configured for this instance.
    pub auth: Option<(String, String)>,
    /// This instance's OWN per-delivery deadline (`settings.delivery_timeout_secs`): the `export:`
    /// map holds NAMED instances, so two webhook sinks can legitimately want different deadlines.
    pub timeout: Duration,
    /// How many deliveries of THIS instance may be in flight at once — its own budget, enforced by
    /// the composition root against a gate of its own, never reconciled across instances.
    pub max_inflight: usize,
    /// The streams + fields THIS instance was granted.
    pub projection: Projection,
}

/// Every configured `module: request-log-webhook` instance whose target survives the SSRF guard, in
/// config order. Empty ⇒ no webhook sink, and in that case the composition root builds no delivery
/// client at all (the default config pays nothing).
pub fn request_log_webhook_instances(cfg: &ExportCfg) -> Vec<RequestLogWebhookInstance> {
    let mut instances = Vec::new();
    for w in &cfg.request_log_webhooks {
        match busbar_unit_egress::sink_guard::validate_webhook_url(Some(w.url.clone())) {
            Ok(Some(url)) => instances.push(RequestLogWebhookInstance {
                display_url: busbar_unit_egress::sink_guard::mask_userinfo(&url),
                url,
                auth: w
                    .auth_header
                    .as_ref()
                    .map(|h| (h.name.clone(), h.value.clone())),
                timeout: Duration::from_secs(w.delivery_timeout_secs),
                // CLAMPED, not trusted: `config_validate` rejects a `max_inflight_deliveries`
                // outside `1..=Semaphore::MAX_PERMITS`, but the gate the root builds from this must
                // not be the thing that panics (0 permits would also black-hole the sink silently)
                // if this is ever reached unvalidated.
                max_inflight: w
                    .max_inflight_deliveries
                    .clamp(1, tokio::sync::Semaphore::MAX_PERMITS),
                projection: w.projection,
            }),
            Ok(None) => {}
            Err(msg) => crate::diagnostics::diag_error!(
                crate::diagnostics::WEBHOOK_EXPORTER_DISABLED,
                "{msg}; disabling this webhook exporter"
            ),
        }
    }
    instances
}

/// Put ONE stated delivery on the wire: the target, the headers and the body the sink stated, that
/// instance's own deadline, the permit holding its slot, and the callback the outcome (an answered
/// status, or a URL-FREE cause) is handed back to. Fire-and-forget — it returns immediately.
pub type RequestLogWebhookSend = Arc<
    dyn Fn(
            String,
            Vec<(String, String)>,
            Vec<u8>,
            Duration,
            OwnedSemaphorePermit,
            Box<dyn FnOnce(Result<u16, String>) + Send>,
        ) + Send
        + Sync,
>;

/// The process's webhook delivery, built ONCE by the composition root and shared by every webhook
/// sink it composes. Call it only when at least one instance is configured: it builds a client.
///
/// WHY THIS IS STILL HERE. The sink frames the POST; opening the socket is the ENGINE's egress
/// client on the cold open-web posture, which no crate of kind `export` may name. It is its own
/// client rather than the shared upstream pool because webhook delivery is a background,
/// seconds-cadence push with its own SSRF posture. Delivery posture matches the retired reqwest
/// client where it matters: 10s connect bound (the engine's connect deadline, now spanning TLS
/// too), reqwest-default pooling (unbounded idle per host, 90s idle timeout — sinks are
/// operator-configured hosts, exactly the shape the LLM lanes pool for); the per-DELIVERY total
/// timeout is each target's own `delivery_timeout_secs`, applied per request below. This goes with
/// the egress client when the egress client goes.
pub fn request_log_webhook_send() -> RequestLogWebhookSend {
    let client = crate::proxy::build_egress_client(&crate::proxy::EgressClientSpec::pooled_webpki(
        usize::MAX,
        90,
        false,
        false,
    ));
    Arc::new(move |url, headers, body, timeout, permit, outcome| {
        let client = client.clone();
        let Ok(uri) = url.parse::<http::Uri>() else {
            // Structurally unreachable: the target survived its guard at resolution. Answered as a
            // transport failure so the sink reports it rather than losing the line in silence.
            outcome(Err("target URL does not parse".to_string()));
            return;
        };
        // The header vocabulary is the WIRE'S, which is why it is applied here and not stated in a
        // crate of kind `export`. A pair this wire refuses is dropped and the delivery still goes,
        // the posture the in-engine sink had.
        let mut head = http::HeaderMap::new();
        for (name, value) in headers {
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::header::HeaderValue::from_str(&value),
            ) {
                head.insert(n, v);
            }
        }
        busbar_substrate::detached::spawn_detached(async move {
            let _permit = permit; // slot releases on task end via the owned permit's Drop.
            let req = busbar_substrate::egress::engine::request(
                http::Method::POST,
                uri,
                head,
                bytes::Bytes::from(body),
            );
            // This target's own per-delivery deadline over the whole send — the same span the
            // retired per-request reqwest `.timeout()` covered.
            let deadline = tokio::time::Instant::now() + timeout;
            match busbar_substrate::egress::engine::send_bounded(&client, req, deadline).await {
                Ok(resp) => outcome(Ok(resp.status().as_u16())),
                // The cause string is URL-free by construction (hyper errors never carry the URL).
                Err(e) => outcome(Err(e.into_cause())),
            }
        });
    })
}

/// One configured `request-log-file` instance, as data for the composition root to build its sink
/// crate from. The typed `settings:` shape stays with the config layer — it is `deny_unknown_fields`
/// and frozen, and resolving an operator's token to the sink it names is what a config layer is FOR
/// — but the sink itself is a crate of kind `export`, which this crate may not name.
pub struct FileInstance {
    /// The JSONL file path each line is appended to.
    pub path: String,
    /// Size (MiB) at which the file is rotated; absent ⇒ never rotate.
    pub rotate_mb: Option<u64>,
    /// The streams + fields THIS instance was granted.
    pub projection: Projection,
}

/// Every configured `module: request-log-file` instance, in config order. Empty ⇒ no file sink.
/// 1.5.3: `export:` is a NAMED map, so two file instances (a local tail file and an audit-mount
/// file, say) are a legitimate configuration and each is its own sink with its own capacity.
pub fn request_log_file_instances(cfg: &ExportCfg) -> Vec<FileInstance> {
    cfg.request_log_files
        .iter()
        .map(|f| FileInstance {
            path: f.path.clone(),
            rotate_mb: f.rotate_mb,
            projection: f.projection,
        })
        .collect()
}

/// The composition root's request-log fan-out, installed once at boot.
///
/// THE SEAM. The distribution half of observability is not core's: the root loads the export sinks,
/// sheds for them and fans one line out to each. What stays here is the request-finish path's
/// single call and the compute gate in front of it — core still decides whether a `logs` record is
/// produced at all (`ExportCfg::projection_union`), because that is a decision about work core
/// would otherwise do, and it still owns the facts. Where those facts GO is behind this pointer.
static REQUEST_LOG_SINK: OnceLock<fn(&RequestLogFacts<'_>)> = OnceLock::new();

/// Install the root's fan-out. Called once, at boot, before the listener binds. A second call is
/// ignored rather than fatal, the same posture the sinks' own boot-once locks had.
pub fn install_request_log_sink(sink: fn(&RequestLogFacts<'_>)) {
    let _ = REQUEST_LOG_SINK.set(sink);
}

/// The projection a test sink is given, minted THROUGH the real path: an instance that subscribes
/// to `logs` and overrides nothing, which resolves to the produced default set — exactly what
/// `build_request_log` fills in, so a test that is not ABOUT the projection sees the same payload
/// the pre-projection code produced.
///
/// It goes through `projection::resolve_projection` rather than a mint-from-parts hatch because
/// resolution is now the only public way to obtain a `Projection` at all: the parts constructor is
/// private to the grammar and its test-only door does not leave that crate. A test helper that
/// could widen a projection would be the one hole in "the operator grants, nothing else does".
#[cfg(test)]
pub(crate) fn test_logs_projection() -> Projection {
    let mut errors = Vec::new();
    let p = busbar_plugin::cold::export::projection::resolve_projection(
        "test",
        "request-log-file",
        Some(&[ExportStream::Logs]),
        Some(&["logs".to_string()]),
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    p
}

/// Hand the request-log facts to the composition root's fan-out. A single pointer read when
/// nothing is installed (`--validate`, a test binary, a deployment with no PUSH sink), which is the
/// same "the read runs ONLY when declared" posture the compute gate in front of this call keeps.
pub(crate) fn deliver_request_log(facts: &RequestLogFacts<'_>) {
    if let Some(sink) = REQUEST_LOG_SINK.get() {
        sink(facts);
    }
}

#[cfg(test)]
#[path = "tests/seam_tests.rs"]
mod tests;
