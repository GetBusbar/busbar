// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar-core — the busbar engine LIBRARY. Everything a request touches lives here: the protocol
// registry and dialects, the MCP/A2A planes, the admin plane and its transaction choke point, the
// config load/validate pipeline, the proxy engine, auth, governance, trust, audit, the durability
// sink, hooks, ingress, the IR, TLS termination and the router builders. The `busbar` BINARY is a
// thin composition root over this crate: argument parsing, config location, process lifecycle and
// (from step 4 of 1.6.0) protocol registration. See docs/code-layout.md and the split plan.
//
// VISIBILITY DOCTRINE: `pub` here is the lib/bin seam, not an API promise (`publish = false`; the
// manifest header says the same). Security-relevant internals — the audit chain's sink, the token
// signer, the durable-state statics, the trust sweeper — stay `pub(crate)` behind one boot entry
// point each; see `boot.rs`.

// busbar contains ZERO `unsafe` code; enforce that as a compile-time guarantee so any future PR
// that introduces an `unsafe` block fails to build rather than slipping in unreviewed.
#![forbid(unsafe_code)]


pub mod a2a;
pub mod admin;
/// THE APPEND-ONLY HASH CHAIN, in core. One append, one digest, one verifier, for every stream of
/// evidence busbar keeps — a plane supplies the record type and nothing else. `admin::audit` is the
/// admin-mutation STREAM that runs on it, not a second mechanism.
pub mod audit;
pub mod auth;
pub mod auth_cache;
pub mod billing;
/// THE BOOT SEAM: one entry point per boot action, so the internals each action composes stay
/// crate-private. See the module header.
pub mod boot;
pub mod breaker;
pub mod catalogue;
pub mod config;
pub mod config_validate;
pub mod core_routes;
pub mod cost;
// The durable-write choke point moved to the shared `busbar-api` crate so the plugin-loader
// (plugins.fetch cache write) can route through the SAME primitive. Re-exported here so every
// existing `crate::durable::*` call site in this binary resolves unchanged.
pub use busbar_api::durable;
pub mod egress_auth;
pub mod endpoints;
pub mod eventstream;
pub mod export;
pub mod failover;
pub mod governance;
pub mod handlers;
pub mod health;
pub mod hooks;
pub mod ingress;
pub mod ir;
pub mod json;
pub mod limits;
pub mod lossless;
pub mod mcp;
pub mod media;
pub mod metrics;
pub mod net_guard;
pub mod oauth_as;
pub mod observability;
pub mod operation;
pub mod plane;
pub mod plugin_routes;
pub mod profile;
pub mod proto;
pub mod proxy;
pub mod sigv4;
pub mod state;
pub mod store;
pub mod telemetry;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub mod transport;
pub mod trust;


use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;

use auth::AuthMiddleware;

use proto::ProtocolRegistry;
use state::{App, Lane, WeightedLane};
use store::{HealthState, LaneData};


// The upstream-request timeout, pool-idle, and request-body caps that used to live here as `const`s
// are now operator-tunable (`limits.upstream_request_timeout_secs` / `pool_max_idle_per_host` /
// `request_body_max_bytes`), each defaulting to its historical value at the config layer. They are
// threaded from `cfg.limits` into the client builder and router below; the egress translate-body cap
// is COUPLED to `request_body_max_bytes` via `crate::limits::translate_body_max_bytes`.

/// DEPRECATED (1.5.3) environment variable name for the providers.yaml path — migrated to the
/// top-level `providers_file:` key in config.yaml. Still honored for one release (see
/// [`providers_override_from_env`]).
pub const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";

/// Environment variable name for the config.yaml path — the one irreducible bootstrap env var.
pub const ENV_CONFIG: &str = "BUSBAR_CONFIG";

/// Default path to the deployment config file.
///
/// A UNIX path, and it is NOT made platform-conditional on purpose. On Windows `/etc/busbar/...` is
/// drive-relative — it resolves against whatever drive the process is running from — so the default
/// is not a usable location there and `BUSBAR_CONFIG` is effectively required. That is the right
/// failure: the miss is loud (the config file is not found, named, at startup, before anything is
/// served) and the fix is one env var. Inventing a second default like
/// `C:\ProgramData\busbar\config.yaml` would instead make busbar SILENTLY read a *different* file
/// per platform, and this constant is the bootstrap of every other trust decision in the process —
/// "which file is my config" is the one question that must never have a platform-dependent answer
/// nobody was told about. Documented for operators in `docs/operations.md`.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";

/// Response header name for the W3C Server-Timing field.
const HEADER_SERVER_TIMING: &str = "server-timing";

/// Sentinel value stored in the `UPSTREAM_RTT_US` task-local when NO upstream hop was dispatched
/// (admin / health / early error). `server_timing_dur_ms` treats this as "report the full request
/// time" rather than subtracting a nonexistent RTT. Only this exact u64::MAX meaning is replaced
/// with the const; overflow/conversion fallbacks that happen to produce u64::MAX are NOT this.
const NO_UPSTREAM_RTT: u64 = u64::MAX;


/// Return the open-relay banner to emit when the auth chain is EMPTY (open front door), or `None`
/// when an auth module is engaged. `chain_empty` = the resolved `auth.chain` is empty. `auth_present`
/// distinguishes an explicit empty chain (operator opted in) from a missing `auth:` block
/// (serde-defaulted to open — the silent foot-gun the banner must call out).
pub fn open_relay_banner(chain_empty: bool, auth_present: bool) -> Option<&'static str> {
    if !chain_empty {
        return None;
    }
    Some(if auth_present {
        "auth is DISABLED (auth.chain is empty) — busbar is running as an OPEN RELAY; do not run this in production"
    } else {
        "auth is DISABLED: no `auth:` block in config — busbar is running as an OPEN RELAY (anyone can use it). Add `auth:` with `chain: [keys]` (and mint virtual keys via the admin API) before exposing it; do not run this in production"
    })
}


/// Return the INERT-KEYS banner to emit when a DURABLE governance store still holds virtual keys
/// from a prior run but the running `auth.chain` does NOT name the `keys` verifier. Enforcement of a
/// virtual key is now decided by the CHAIN SHAPE, not the admin token: only when `keys` is in the
/// data-plane chain does any request resolve to (and get governed by) a stored vkey. So if `keys`
/// is absent, the persisted keys' per-key controls (budget, RPM/TPM, allowed_pools) are silently
/// NOT enforced — no data-plane request ever resolves them. A RAM store can never reach this state
/// (it starts empty every boot), so this is scoped to durable stores. Returns `None` when the state
/// does not apply (RAM store, no keys, or `keys` IS in the chain). `key_count` is the number of keys
/// the store reports at boot; `keys_in_chain` is whether `auth.chain` names the `keys` verifier.
pub fn inert_durable_keys_banner(
    store_is_durable: bool,
    key_count: usize,
    keys_in_chain: bool,
) -> Option<String> {
    if store_is_durable && key_count > 0 && !keys_in_chain {
        Some(format!(
            "durable governance store contains {key_count} key(s) but auth.chain does not name the \
             `keys` verifier — those keys are INERT and NOT enforced (per-key budget / RPM / TPM / \
             allowed_pools are bypassed; no data-plane request resolves them). Add `keys` to \
             auth.chain to enforce them."
        ))
    } else {
        None
    }
}


/// Resolve each model's single `context_max` from the pool members that reference it.
///
/// A model is realized as exactly one lane (keyed by model name in `by_model`), so its
/// context window must be single-valued across every pool that lists it. We accept the same
/// `context_max` repeated (including the same `Some(_)` in multiple pools, and a mix of an
/// explicit value with `None` — the explicit value wins, since `None` only means "unspecified
/// here"), but reject two DIFFERENT explicit limits for the same model: that is an operator
/// contradiction that previously resolved nondeterministically to whichever pool iterated last.
pub fn resolve_model_context_max(
    pools: &HashMap<String, config::PoolCfg>,
) -> Result<HashMap<String, Option<usize>>, String> {
    let mut resolved: HashMap<String, Option<usize>> = HashMap::new();
    for pool in pools.values() {
        for m in &pool.members {
            match resolved.get(&m.model) {
                // First sighting of this model, or this member adds no opinion (None) — keep what
                // we have / record what we got.
                None => {
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(None) => {
                    // Previously unspecified; let any value (including another None) refine it.
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(Some(existing)) => match m.context_max {
                    // No opinion here, or an identical opinion — both fine, keep the explicit value.
                    None => {}
                    Some(c) if c == *existing => {}
                    Some(c) => {
                        return Err(format!(
                            "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                            m.model, existing, c
                        ));
                    }
                },
            }
        }
    }
    Ok(resolved)
}


/// Resolve a boot-time boolean upstream knob under the env→config migration precedence: the DEPRECATED
/// env var, when SET, wins (honored for one release) — `"0"` or empty means OFF, anything else ON; when
/// UNSET, the config value (`advanced.upstream_*`, carried on `cfg.limits`) stands. The deprecation
/// WARN is emitted at the call site (only when the env var is present). Module-level so the precedence
/// is unit-testable without building the whole client; see `tests/tests.rs`.
pub fn upstream_bool_env_override(env: Option<std::ffi::OsString>, config_val: bool) -> bool {
    match env {
        Some(v) => v != "0" && !v.is_empty(),
        None => config_val,
    }
}


/// Render a native ingress error envelope (`application/json`) for the fallback handlers, in the
/// dialect the path is spoken in — attaching the `x-amzn-*` headers when that dialect is Bedrock,
/// so the response is indistinguishable from a real vendor 404/405, and answering in JSON-RPC on a
/// path a plane has been MOUNTED on. Shared by the 404 catch-all, [`method_not_allowed_handler`]
/// (405, wrong method on a valid path) and the oversized-body 413 reshape.
///
/// `planes` is the mount table, and it is a parameter rather than something inferred here because
/// a mount is a fact about the deployment: no amount of looking at the path reveals it, and the
/// version of this function that tried shipped an OpenAI envelope onto the MCP plane.
pub fn fallback_error_response(
    planes: &crate::plane::PlaneDispatch,
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    // The NATIVE-API root speaks the frozen admin envelope for EVERY response — including unmatched
    // paths and wrong methods, which previously fell through to the vendor-native shaping below and
    // leaked `{error:{type}}` bodies onto a surface that promises `{error:{code}}`.
    // Boundary-safe: exact root or root + '/'.
    {
        use crate::admin::v1::contract::{AdminError, API_ROOT};
        if path == API_ROOT || path.starts_with(&format!("{API_ROOT}/")) {
            let e = if status == axum::http::StatusCode::METHOD_NOT_ALLOWED {
                AdminError::MethodNotAllowed
            } else {
                AdminError::not_found("resource")
            };
            return crate::admin::v1::json::err_json(&e);
        }
    }
    // ONE resolver, ONE shaping seam. The provider-specific response headers (Bedrock
    // `x-amzn-RequestId`/`x-amzn-errortype`; Anthropic `request-id`) come with it, dispatched
    // through the writer vtable inside `proxy::ingress_error`, so this handler matches the shape
    // the hot path produces and carries no provider name-branch of its own.
    crate::ingress::native::native_error(planes.ingress_of(path), status, kind, message)
}


// NOTE: the 404 fallback handler is superseded by `ingress::protocol_dispatch`, which owns the
// catch-all and reproduces the same native-envelope 404 shaping for non-protocol paths.

/// 405 fallback: a valid ingress path hit with the wrong method (e.g. GET on a POST-only ingress).
/// axum's built-in 405 is an `Allow`-header-only empty body; reshape to the protocol-native envelope
/// so an SDK sees a vendor-shaped error instead of a bare proxy tell.
async fn method_not_allowed_handler(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    uri: axum::http::Uri,
) -> axum::response::Response {
    fallback_error_response(
        &app.planes,
        uri.path(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        crate::admin::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}


/// The SENTINEL substring in the `text/plain` body axum's `DefaultBodyLimit` emits when a request
/// exceeds the limit — used to distinguish axum's OWN body-limit 413 from a forward-path-relayed
/// upstream 413, which must pass through untouched.
///
/// SUBSTRING, NOT BYTE-EQUALITY, and that is the fix. This was pinned to axum 0.7's EXACT body
/// (`"length limit exceeded"`), and axum-core 0.5 renders the same rejection as
/// `"Failed to buffer the request body: length limit exceeded"` — the `__define_rejection!`
/// Error-variant arm prefixes the outer `FailedToBufferBody` prose onto the inner error. So on
/// axum 0.8 the equality gate NEVER matched and the whole reshape was dead code in production:
/// every oversized request, admin and data plane alike, answered with a bare `text/plain` body.
/// That broke the admin surface's frozen `{error:{code}}` envelope (tooling that branches on `code`
/// throws on parse) and handed official OpenAI/Anthropic/Bedrock SDKs a router tell instead of the
/// vendor-native JSON envelope.
///
/// Matching the inner error's own words survives that wrapping. The residual risk — a relayed
/// UPSTREAM `text/plain` 413 whose body happens to contain this phrase being reshaped into a JSON
/// envelope of the same status — is far smaller than the risk this replaced, and is bounded to the
/// envelope shape (the status is 413 either way).
///
/// THE REAL GUARD IS THE TEST, not this constant. Every prior test of this path hand-constructed
/// the marker and called the pure reshape function, so all four stayed green while the layer was
/// dead. `oversized_request_413_is_reshaped_on_the_live_stack` drives a real oversized request
/// through the real layer stack, so the next time axum changes its prose the build goes red instead
/// of the reshape silently switching itself off.
const AXUM_BODY_LIMIT_413_MARKER: &[u8] = b"length limit exceeded";


/// Reshape an oversized-body rejection into a protocol-native error. axum's `DefaultBodyLimit`
/// rejects a too-large request with HTTP 413 and a bare `text/plain` body (`"length limit
/// exceeded"`) — a router/proxy tell no native vendor API emits. This middleware wraps the
/// body-limit layer: it captures the request path, runs the inner
/// stack, and when the result is axum's OWN body-limit 413 (identified by the
/// [`AXUM_BODY_LIMIT_413_MARKER`] sentinel body — NOT merely any non-JSON 413), it replaces that
/// response with the inferred ingress protocol's native JSON `request_too_large` envelope (Bedrock
/// variants also gain `x-amzn-*` headers, via [`fallback_error_response`]). Any other 413 — a
/// forward-path-relayed UPSTREAM 413 (whatever its content-type), or one a real ingress handler
/// already shaped as JSON — is passed through untouched.
///
/// The envelope is the one the PATH's resolved ingress speaks, which is why this layer takes the
/// swappable app handle: a body cap fires OUTSIDE routing and OUTSIDE auth, so the mount table is
/// the only thing that can tell it whether `/mcp` is an MCP plane or an unclaimed residual path.
/// Before it had one, every oversized POST — mounted plane or not — was answered in an OpenAI
/// envelope.
async fn reshape_body_limit_413(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    // The snapshot is taken AFTER the inner stack runs, so a config apply mid-request shapes the
    // answer with the mount table that is live when the answer is written.
    let resp = next.run(req).await;
    reshape_oversized_413(&handle.load().planes, &path, resp).await
}


/// Per-process count of requests that entered the middleware stack — the idleness signal for the
/// jemalloc idle-purge fallback (bumped once per request in `server_timing`, read every sweep tick
/// by the purge thread). Wraps harmlessly (only equality-across-a-window is compared).
pub static REQUEST_ACTIVITY_TICKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);


/// Compute the `Server-Timing` `dur` value (milliseconds) for a request: Busbar's own processing
/// time = total request wall-clock minus the upstream round-trip. `upstream_us == u64::MAX` means
/// "no upstream hop" (admin/health/early error), so the full time is reported. Saturating, so clock
/// skew (upstream measured slightly larger than total) can never underflow into a huge value.
fn server_timing_dur_ms(total_us: u64, upstream_us: u64) -> f64 {
    let internal_us = if upstream_us == NO_UPSTREAM_RTT {
        total_us
    } else {
        total_us.saturating_sub(upstream_us)
    };
    internal_us as f64 / 1000.0
}


/// Always-installed OUTERMOST-ISH middleware: bumps the jemalloc idle-purge activity ticker (see
/// `spawn_jemalloc_idle_purge_fallback`) on every request. Split out of `server_timing`
/// so the ticker keeps incrementing regardless of whether `advanced.response_headers.server_timing`
/// is enabled — the `server_timing` layer itself is now COMPOSED OUT of the stack entirely when
/// disabled (see `apply_common_layers`), so this is the one piece of its old unconditional behavior
/// that must survive the split. One relaxed atomic add; no allocation, no `Instant::now()`.
async fn request_activity_tick(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    REQUEST_ACTIVITY_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    next.run(req).await
}


/// Outermost middleware: stamps a standard `Server-Timing: busbar;dur=<ms>` response header
/// reporting the latency Busbar itself added — total request wall-clock MINUS the upstream
/// round-trip — so operators (and browser DevTools / APM tools) can see the gateway's own cost
/// in-band on every response, without scraping `/metrics` or wiring traces. The upstream RTT is
/// recorded by the forward path into the [`proxy::UPSTREAM_RTT_US`] task-local for the duration
/// of this scope; a request that never dispatched upstream (admin / health / early error) reports
/// its full processing time. W3C `Server-Timing` `dur` is milliseconds; emitted at µs precision.
///
/// Gated by `advanced.response_headers.server_timing` (default `false`) — but NOT with an internal
/// `if` check like the pre-task-#139 version. `apply_common_layers` installs this middleware LAYER
/// ONLY when the flag is enabled (composition, mirroring `apply_inbound_concurrency_limit`'s
/// `max_inbound_concurrent > 0` gate), so a disabled deployment never runs this function at all: no
/// per-request `Arc<AtomicU64>` allocation, no `Instant::now()`, no task-local `.scope()` — the
/// former anti-pattern where the flag only suppressed the RESPONSE HEADER after paying the full
/// per-request cost regardless.
async fn server_timing(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    let slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(NO_UPSTREAM_RTT));
    let start = std::time::Instant::now();
    let mut resp = proxy::UPSTREAM_RTT_US
        .scope(slot.clone(), next.run(req))
        .await;
    let total_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let dur_ms = server_timing_dur_ms(total_us, slot.load(Ordering::Relaxed));
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("busbar;dur={dur_ms:.3}")) {
        resp.headers_mut()
            .insert(axum::http::HeaderName::from_static(HEADER_SERVER_TIMING), v);
    }
    resp
}


/// Pure reshaping step of [`reshape_body_limit_413`], split out so it is unit-testable without
/// constructing a `Next`. Returns `resp` unchanged unless it is axum's OWN body-limit 413 —
/// identified by status 413 with a non-JSON content-type AND a body exactly equal to
/// [`AXUM_BODY_LIMIT_413_MARKER`] — in which case it is replaced by the inferred ingress protocol's
/// native JSON `request_too_large` envelope. A 413 a real ingress handler already shaped as
/// `application/json`, or any forward-relayed UPSTREAM 413 (different/non-marker body), is passed
/// through verbatim (the body is buffered to inspect the sentinel, then re-attached unchanged).
async fn reshape_oversized_413(
    planes: &crate::plane::PlaneDispatch,
    path: &str,
    resp: axum::response::Response,
) -> axum::response::Response {
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    // A handler (or upstream relay) that already produced an `application/json` 413 is a native
    // too-large envelope — leave it alone without even buffering the body; re-wrapping would
    // corrupt it, and axum's own body-limit reject is never JSON.
    let is_json = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|ct| ct.starts_with(crate::proxy::APPLICATION_JSON));
    if is_json {
        return resp;
    }
    // Non-JSON 413: it could be axum's OWN body-limit reject (reshape it) OR a forward-relayed
    // UPSTREAM 413 that happens to be non-JSON (e.g. a `text/plain`/`text/html` upstream error —
    // must pass through untouched). Distinguish by the sentinel body. Buffer the body so
    // we can compare it; if it is not the sentinel, re-attach the buffered bytes verbatim.
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        // A 413 body that fails to buffer cannot be confirmed as axum's sentinel; pass the
        // already-consumed parts through with an empty body rather than reshape a non-axum reject.
        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    if !bytes
        .windows(AXUM_BODY_LIMIT_413_MARKER.len())
        .any(|w| w == AXUM_BODY_LIMIT_413_MARKER)
    {
        // A relayed upstream 413 (or any non-axum 413): pass through untouched, body re-attached.
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    fallback_error_response(
        planes,
        path,
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        // CANONICAL kind for an oversized payload across the protocol writers.
        crate::proxy::KIND_REQUEST_TOO_LARGE,
        "request body exceeds the maximum allowed size",
    )
}


/// Everything the DISK half of configuration produces, shared by boot and runtime reload.
pub struct LoadedConfig {
    pub deploy: config::DeployCfg,
    pub defs: HashMap<String, config::ProviderDef>,
    /// The RESOLVED providers-catalog path actually read (1.5.3): `config.providers_file` relative to
    /// the config dir, the deprecated `BUSBAR_PROVIDERS` override, or `providers.yaml` next to the
    /// config. Carried so callers display / re-use the same file across a reload.
    pub providers_path: std::path::PathBuf,
    /// The resolved config-overlay backend path (1.5.3): `Some` = a writable file backend (mutable
    /// config); `None` = either the config is LOCKED (`config.locked: true`) or its backend is not
    /// writable (a read-only config mount — busbar boots and serves, but refuses config mutations).
    /// The boot invariant guarantees `overlay_path.is_none()` whenever busbar cannot durably persist,
    /// so a `Some` path is always one that was probed writable.
    pub overlay_path: Option<std::path::PathBuf>,
    /// `config.locked` (1.5.3): `true` ⇒ admin-API config mutations are refused at runtime.
    pub config_locked: bool,
    /// `true` ⇒ the config did NOT declare `config.locked: true`, but its overlay backend is not
    /// writable (the read-only config mount the documented Docker quickstart creates). Busbar boots
    /// and serves; admin-API config mutations are refused because they could not be persisted.
    /// Distinguished from `config_locked` so the boot log can tell the operator which of the two
    /// postures they are in — one they chose, one the filesystem chose for them.
    pub config_read_only: bool,
    /// The persisted overlay document (API-registered hooks), applied onto the RESOLVED config
    /// (`overlay::merge_into(&mut RootCfg, …)`) after `config::resolve` - the runtime registry is
    /// synthesized there, so the overlay merges post-resolve. `None` = absent / safe mode.
    pub overlay_doc: Option<config::overlay::OverlayDoc>,
    /// `${VAR}` refs that were UNSET during interpolation. Empty under Strict (boot/reload); populated
    /// under Lenient (--validate), where it becomes the "set these at runtime" note.
    pub unset_env_vars: Vec<String>,
}


/// `providers_override`: the DEPRECATED `BUSBAR_PROVIDERS` path (Some ⇒ set), or the live
/// providers path a runtime reload wants to re-use. When `None`, the catalog path is resolved from
/// `config.providers_file` (relative to the config dir) or defaults to `providers.yaml` next to the
/// resolved config.yaml (1.5.3).
pub fn load_config_from_disk(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
) -> Result<LoadedConfig, String> {
    let mut unset_env_vars: Vec<String> = Vec::new();
    // 1.5.3: read + parse config.yaml FIRST — it may name the providers catalog (`providers_file:`).
    let raw_config = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read config file '{}': {e} (set {ENV_CONFIG})",
            config_path.display()
        )
    })?;
    let interpolated_config =
        config::interpolate_env_with(&raw_config, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("config.yaml: {e}"))?;
    // LOUD FAIL-CLOSED on a 1.x config: detect the 1.x structural markers BEFORE the
    // typed parse, so an outdated config gets the NAMED "run --migrate-config" error instead of
    // a pile of unknown-field messages - and, critically, so nothing from 1.x can half-parse
    // into 1.5.0 semantics (the `allowed_pools: []` all->none flip, vanished budgets).
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&interpolated_config) {
        let markers = config::migrate::detect_legacy_markers(&doc);
        if !markers.is_empty() {
            return Err(format!(
                "config.yaml: {}",
                config::migrate::legacy_config_error(&markers)
            ));
        }
    }
    let deploy: config::DeployCfg = serde_yaml::from_str(&interpolated_config).map_err(|e| {
        format!(
            "config.yaml: invalid YAML: {}",
            config::augment_config_error(e)
        )
    })?;

    // 1.5.3: resolve the providers CATALOG path. Precedence: the explicit override (the deprecated
    // `BUSBAR_PROVIDERS` env var, or a runtime reload re-using its boot path) > `config.providers_file`
    // (relative to the config dir) > `providers.yaml` next to the resolved config.yaml.
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let providers_path: std::path::PathBuf = match providers_override {
        Some(p) => p.to_path_buf(),
        None => match deploy.providers_file.as_deref() {
            Some(f) => {
                let p = std::path::Path::new(f);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    config_dir.join(p)
                }
            }
            None => config_dir.join("providers.yaml"),
        },
    };
    let raw_providers = std::fs::read_to_string(&providers_path).map_err(|e| {
        format!(
            "cannot read providers file '{}': {e} (set `providers_file:` in config.yaml, or {ENV_PROVIDERS})",
            providers_path.display()
        )
    })?;
    let interpolated_providers =
        config::interpolate_env_with(&raw_providers, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("providers.yaml: {e}"))?;
    let defs: HashMap<String, config::ProviderDef> = serde_yaml::from_str(&interpolated_providers)
        .map_err(|e| format!("providers.yaml: invalid YAML: {e}"))?;

    // 1.5.3: resolve the config-management posture + overlay backend from the `config:` block, and
    // ENFORCE the boot invariant (`locked` XOR a writable overlay). The deprecated
    // `BUSBAR_CONFIG_OVERLAY` env var is honored only when `config.overlay` is unset. The writability
    // probe runs at boot/reload (Strict) but not under `--validate` (Lenient), which must stay
    // side-effect-free.
    let env_overlay = std::env::var("BUSBAR_CONFIG_OVERLAY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let probe_fs = matches!(env_mode, config::EnvSubst::Strict);
    let resolution = config::overlay::resolve_backend(
        &deploy.config,
        config_path,
        env_overlay.as_deref(),
        probe_fs,
    )?;
    let overlay_path = resolution.path;
    let config_locked = resolution.locked;
    let config_read_only = resolution.read_only_backend;

    if safe_mode {
        // `--safe-mode`: boot on the operator-owned base config ALONE — the persisted overlay
        // (API-registered hooks) is quarantined, not deleted. The escape hatch for "an applied
        // hook is harming traffic and re-applies itself every boot".
        tracing::warn!(
            "SAFE MODE: config overlay NOT merged — running on base config.yaml alone (the \
             overlay file is untouched; boot without --safe-mode to re-apply it)"
        );
        return Ok(LoadedConfig {
            deploy,
            defs,
            providers_path,
            overlay_path,
            config_locked,
            config_read_only,
            overlay_doc: None,
            unset_env_vars,
        });
    }
    // An overlay from a NEWER busbar is refused, not ignored: it is intact and meaningful, so
    // starting without it would run with the operator's API-registered hooks and groups — security
    // gates included — silently absent. `--safe-mode` boots on base config alone without touching
    // the file, so this is a one-flag recovery rather than a brick.
    if let Some(p) = overlay_path.as_ref() {
        if let config::overlay::OverlayReadState::VersionTooNew(v) = config::overlay::read_state(p)
        {
            return Err(format!(
                "config overlay '{}' was written by a newer busbar (overlay version {v}; this                  binary understands {}). Starting without it would silently drop API-registered                  hooks and groups. Upgrade busbar, or boot with --safe-mode to run on config.yaml                  alone (the overlay is left untouched).",
                p.display(),
                config::overlay::OVERLAY_VERSION
            ));
        }
    }
    let overlay_doc = overlay_path.as_ref().and_then(|p| {
        let doc = config::overlay::read(p);
        if let Some(ref d) = doc {
            tracing::info!(
                path = %p.display(),
                hooks = d.hooks.len(),
                "config overlay loaded (merged onto the resolved config after resolve)"
            );
        }
        doc
    });
    Ok(LoadedConfig {
        deploy,
        defs,
        providers_path,
        overlay_path,
        config_locked,
        config_read_only,
        overlay_doc,
        unset_env_vars,
    })
}


/// Build a complete `App` from a RESOLVED config — the ONE construction path shared by boot
/// (`prior = None`) and the config plane's apply/reload (`prior = Some(current)`). On apply,
/// process-lifetime state is REUSED from the prior snapshot (HTTP client pool, governance key DB,
/// version history, mutation-rate windows) and the health store is rebuilt with every surviving
/// lane's learned state RESTORED BY STABLE IDENTITY — so a lane-set change never
/// misattributes or discards breaker/latency knowledge. Errors are returned (never process-exit):
/// boot maps them to `die`, the apply endpoints to `invalid_request` — an invalid apply changes
/// nothing.
///
/// PLUGIN PRE-FLIGHT — the ONE pipeline shared byte-for-byte by BOOT (`build_app_from_config`),
/// config APPLY/RELOAD, and `busbar --validate`, so the pre-flight gate can never drift from real
/// boot behavior. Fail-closed at every step:
///
/// 1. CONSISTENCY: a non-`memory` `store.module` with `plugins.enabled: false` (or the block
///    absent) is an error NAMING THE FLAG — a dropped-in tarball is inert until the switch is on.
/// 2. POLICY: `plugins.trust` resolves (embedded first-party key + third-party publishers + the
///    explicit opt-ins + anti-downgrade floors); a malformed key is an error.
/// 3. SCAN: when enabled, every tarball in `plugins.dir` runs the three-phase pipeline
///    (structural -> trust -> conflict) via [`busbar_plugin_loader::scan_and_validate`]. ANY
///    invalid tarball/manifest or ANY name/alias conflict aborts with every problem named; an
///    untrusted plugin is SKIPPED (warn-logged, never `dlopen`ed).
/// 4. RESOLUTION: the configured `store.module` (alias OR canonical name, resolved against the
///    manifest registry — never a filename) must resolve to a loadable `kind: store` plugin.
///
/// Returns the validated registry (empty when plugins are disabled and no plugin is referenced).
/// NO plugin code runs in this function (manifest-only; `dlopen` happens later, at store open).
pub fn plugins_preflight(
    store_cfg: Option<&config::StoreCfg>,
    auth_cfg: Option<&config::AuthCfg>,
    identity_providers: &config::IdentityProviders,
    hooks_cfg: &std::collections::HashMap<String, config::HookCfg>,
    plugins_cfg: &config::PluginsCfg,
    export_cfg: &config::ExportCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let store_ref = store_cfg
        .map(|g| g.module.as_str())
        .unwrap_or(config::GOVERNANCE_STORE_MEMORY);
    let store_is_plugin = store_ref != config::GOVERNANCE_STORE_MEMORY;

    // Every non-builtin `auth.chain` module is a `kind: auth` plugin — the same manifest-only
    // pre-flight the store ref gets, so `--validate` catches a missing/wrong-kind/untrusted auth
    // plugin BEFORE boot. `keys` is engine-handled (never a plugin); `test-groups-module` is the
    // compiled-in test stand-in — ONLY actually registered under `#[cfg(test)]`
    // (`AuthMiddleware::new`, `crates/busbar/src/auth/mod.rs`), so filtering it out
    // unconditionally here made `--validate`/`config_validate::validate` silently agree a RELEASE
    // config naming it is fine, while real boot still hard-failed (the invariant `--validate`
    // clean => the plugin half of boot succeeds too, documented a few lines below, broke). Gate
    // the exemption the same way the module itself is gated.
    let auth_plugin_refs: Vec<&str> = auth_cfg
        .map(|a| {
            a.chain
                .iter()
                .map(|e| e.module.as_str())
                .filter(|m| is_real_auth_plugin_ref(m, cfg!(test)))
                .collect()
        })
        .unwrap_or_default();
    let has_auth_plugin = !auth_plugin_refs.is_empty();

    // Every `identity-providers:` DEFINITION whose `module:` is not a built-in is likewise a
    // `kind: auth` plugin reference — checked here over the DEFINITION map rather than over the
    // resolved chain, because that is the only layer that sees an UNREFERENCED definition.
    // `resolve_auth` is keyed off `auth.chain:`/`auth.admin_auth:`, and `AuthCfg.methods` only
    // exists at all when an `auth:` block does, so a provider defined through
    // `PUT /identity-providers/{name}` and not yet referenced was validated by NOTHING: the API
    // answered 200 and stored a `module:` that can never authenticate anyone. `export:` has had the
    // equivalent check since 1.5.3 (`resolve_export` refuses an unknown exporter and names the
    // built-ins); it just needed no registry, because the export vocabulary is a const list.
    // Carries (name, module) pairs so the diagnostics can name the offending DEFINITION, not only
    // the module string — two providers can share one typo'd module.
    let idp_plugin_refs: Vec<(&str, &str)> = identity_providers
        .iter()
        .map(|(name, def)| (name.as_str(), def.module.trim()))
        // An EMPTY module is `resolve_auth`'s rule ("must be a non-empty module name"), reported
        // there in its own words; do not shadow it with a less specific "no such plugin".
        .filter(|(_, m)| !m.is_empty() && is_real_identity_provider_plugin_ref(m, cfg!(test)))
        .collect();
    let idp_refs_human = |refs: &[(&str, &str)]| {
        refs.iter()
            .map(|(n, m)| format!("identity-providers.{n} (module '{m}')"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Every hook references a `kind: hook` plugin — the same manifest-only pre-flight the store/auth
    // refs get. Deduped for the messages, but validated as the set of names each hook declares.
    let hook_plugin_refs: Vec<String> = {
        let mut v: Vec<String> = hooks_cfg.values().map(|h| h.plugin.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let has_hook_plugin = !hook_plugin_refs.is_empty();

    // 1. Consistency: referencing a plugin store while the master switch is off is a NAMED error.
    if store_is_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "store.module: '{store_ref}' requires the plugin subsystem, but plugins.enabled is \
             false (the default). Set plugins.enabled: true and place the signed \
             '{store_ref}' store plugin tarball in the plugins directory ('{}'), or set \
             store.module: memory.",
            plugins_cfg.dir
        ));
    }
    // Same consistency gate for an auth plugin: a configured `kind: auth` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-open front door.
    if has_auth_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "auth.chain names plugin module(s) [{}], which require the plugin subsystem, but \
             plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed auth plugin tarball(s) in the plugins directory ('{}').",
            auth_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for a hook plugin: a configured `kind: hook` module cannot load with
    // the plugin subsystem off — fail-closed, never a silently-absent gate.
    if has_hook_plugin && !plugins_cfg.enabled {
        return Err(format!(
            "the hooks registry names plugin module(s) [{}], which require the plugin subsystem, \
             but plugins.enabled is false (the default). Set plugins.enabled: true and place the \
             signed `kind: hook` plugin tarball(s) in the plugins directory ('{}').",
            hook_plugin_refs.join(", "),
            plugins_cfg.dir
        ));
    }

    // Same consistency gate for an identity-provider DEFINITION: with the plugin subsystem off the
    // registry is empty by construction, so the only modules that can ever back a provider are the
    // built-ins — naming anything else is a config error today, not a latent one. Ordered AFTER the
    // `auth.chain` gate on purpose: a provider that IS on a chain gets that gate's more specific
    // "auth.chain names plugin module(s)" wording, and this one covers the definitions no chain
    // reaches.
    if !idp_plugin_refs.is_empty() && !plugins_cfg.enabled {
        return Err(format!(
            "{} require(s) the plugin subsystem, but plugins.enabled is false (the default). With \
             plugins off, a provider's `module:` must be one of the built-ins: {}. Set \
             plugins.enabled: true and place the signed `kind: auth` plugin tarball(s) in the \
             plugins directory ('{}'), or name a built-in.",
            idp_refs_human(&idp_plugin_refs),
            config::BUILTIN_IDENTITY_PROVIDERS.join(" | "),
            plugins_cfg.dir
        ));
    }

    // 2. Policy resolution (embedded first-party key + configured third-party trust).
    let policy = plugins_cfg
        .to_policy()
        .map_err(|e| format!("plugins.trust is invalid: {e}"))?;

    // Disabled and nothing referenced: the registry is empty and NOTHING in the directory is even
    // read (drop-is-inert).
    if !plugins_cfg.enabled {
        tracing::info!(
            "plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"
        );
        return Ok(busbar_plugin_loader::PluginRegistry::empty());
    }

    // 3. Three-phase scan over the plugins directory. Fail-closed on invalid/conflict.
    let dir = std::path::Path::new(&plugins_cfg.dir);
    let registry = busbar_plugin_loader::scan_and_validate(dir, &policy)
        .map_err(|errs| format!("plugin validation failed:\n  - {}", errs.join("\n  - ")))?;
    tracing::info!(
        dir = %plugins_cfg.dir,
        loadable = registry.loadable().len(),
        skipped = registry.skipped().len(),
        "plugins: enabled"
    );
    for s in registry.skipped() {
        tracing::warn!(
            plugin = %s.manifest.name,
            file = %s.file,
            reason = %s.reason,
            "plugin present but NOT loaded (trust policy)"
        );
    }
    for p in registry.loadable() {
        match &p.verdict {
            busbar_plugin_sign::Verdict::Trusted {
                publisher,
                first_party,
            } => tracing::info!(
                plugin = %p.manifest.name,
                alias = %p.manifest.alias,
                kind = %p.manifest.kind,
                version = %p.manifest.version,
                publisher = %publisher,
                first_party,
                "plugin validated"
            ),
            busbar_plugin_sign::Verdict::Allowed { reason, .. } => tracing::warn!(
                plugin = %p.manifest.name,
                alias = %p.manifest.alias,
                kind = %p.manifest.kind,
                reason = %reason,
                "plugin validated as UNVERIFIED (permitted by an explicit plugins.trust opt-in)"
            ),
        }
    }

    // 4. The configured store must resolve to a loadable store plugin.
    if store_is_plugin {
        match registry.resolve(store_ref) {
            Some(p) if p.manifest.kind == "store" => {}
            Some(p) => {
                return Err(format!(
                    "store.module: '{store_ref}' resolves to plugin '{}' of kind '{}', not a \
                     store plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(store_ref) {
                    Some(s) => format!(
                        "store.module: '{store_ref}' matches plugin '{}' ({}) but it was not \
                         loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching store.module: '{store_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed tarball actually IN the \
                         folder? Add it to plugins.fetch or drop the signed tarball in the \
                         directory, or set store.module: memory.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 5. Every configured auth-chain plugin must resolve to a loadable `kind: auth` plugin. Same
    // manifest-only resolution as the store ref (no `dlopen` here; the real load happens in
    // `AuthMiddleware::new` at App construction). A missing/wrong-kind/untrusted auth plugin fails
    // `--validate` and boot alike — a typo'd or absent front-door module must never pass silently.
    for auth_ref in &auth_plugin_refs {
        match registry.resolve(auth_ref) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "auth.chain module '{auth_ref}' resolves to plugin '{}' of kind '{}', not an \
                     `auth` plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(auth_ref) {
                    Some(s) => format!(
                        "auth.chain module '{auth_ref}' matches plugin '{}' ({}) but it was not \
                         loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching auth.chain module '{auth_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed `kind: auth` tarball \
                         actually IN the folder? Add it to plugins.fetch or drop the signed tarball \
                         in the directory, or remove it from auth.chain.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 6. Every hook's `plugin:` ref must resolve to a loadable `kind: hook` plugin. Same manifest-only
    // resolution as store/auth (no `dlopen` here; the real load happens in `resolve_gate_transport` at
    // App construction). A missing/wrong-kind/untrusted hook plugin fails `--validate` and boot alike.
    for hook_ref in &hook_plugin_refs {
        match registry.resolve(hook_ref) {
            Some(p) if p.manifest.kind == "hook" => {}
            Some(p) => {
                return Err(format!(
                    "a hook references plugin '{hook_ref}', which resolves to plugin '{}' of kind \
                     '{}', not a `hook` plugin",
                    p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(hook_ref) {
                    Some(s) => format!(
                        "a hook references plugin '{hook_ref}', matching plugin '{}' ({}) but it \
                         was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "no plugin matching the hook reference '{hook_ref}' is installed in '{}' \
                         (plugins ARE enabled; loadable: [{}]). Two things to check: is the plugin \
                         subsystem enabled? (it is) — and is the signed `kind: hook` tarball \
                         actually IN the folder? Add it to plugins.fetch or drop the signed tarball \
                         in the directory, or remove the hook.",
                        plugins_cfg.dir,
                        registry
                            .loadable()
                            .iter()
                            .map(|p| p.manifest.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
        }
    }

    // 6b. Every `identity-providers:` DEFINITION's non-built-in `module:` must resolve to a loadable
    // `kind: auth` plugin — the definition-side counterpart of the `auth.chain` resolution above,
    // and the check that finally covers a provider NO chain references (the admin API's whole write
    // surface). Manifest-only, like its siblings.
    for (name, module) in &idp_plugin_refs {
        match registry.resolve(module) {
            Some(p) if p.manifest.kind == "auth" => {}
            Some(p) => {
                return Err(format!(
                    "identity-providers.{name}.module: '{module}' resolves to plugin '{}' of kind \
                     '{}', not an `auth` plugin. A provider's `module:` must be a built-in or a \
                     `kind: auth` plugin; the modules available right now are: {}.",
                    p.manifest.name,
                    p.manifest.kind,
                    valid_identity_provider_modules(&registry)
                ));
            }
            None => {
                return Err(match registry.unresolved_reason(module) {
                    Some(s) => format!(
                        "identity-providers.{name}.module: '{module}' matches plugin '{}' ({}) but \
                         it was not loaded: {}",
                        s.manifest.name, s.file, s.reason
                    ),
                    None => format!(
                        "identity-providers.{name}.module: no `kind: auth` plugin named or aliased \
                         '{module}' is installed in '{}' (plugins ARE enabled), and it is not a \
                         built-in. The modules a provider may name right now are: {}. Check the \
                         spelling against the plugin's manifest name/alias (see --list-plugins), \
                         add the signed tarball to the plugins directory, or name a built-in.",
                        plugins_cfg.dir,
                        valid_identity_provider_modules(&registry)
                    ),
                });
            }
        }
    }

    // 7. PLUGIN HTTP ROUTE COLLISION CHECK — MANIFEST-LEVEL, nothing dlopened. Walk every
    // loadable export/hook plugin's DECLARED routes in the SAME deterministic scan order the registry
    // produced, namespace-confine each, and fail LOUD naming the owning plugin on the first
    // {path, method} collision — e.g. `plugin "datadog" cannot register GET /metrics — already
    // registered by "prometheus"`. The IDENTICAL check backs boot and `--validate` (both call this
    // preflight), and the SAME confinement + first-to-claim logic backs the live table built at App
    // construction (`plugin_routes::build_route_table`), so the manifest check and what actually mounts
    // cannot diverge. Route declarations are read straight from each signed manifest; a plugin that
    // declares none contributes nothing (today's manifests carry no routes, so the set is empty until
    // the export/hook route-manifest field lands — the wiring is here so that is a data change, not a
    // control-flow one).
    let route_owners: Vec<(String, crate::plugin_routes::RouteKind)> = registry
        .loadable()
        .iter()
        .filter_map(|p| match p.manifest.kind.as_str() {
            "export" => Some((
                p.manifest.name.clone(),
                crate::plugin_routes::RouteKind::Export,
            )),
            "hook" => Some((
                p.manifest.name.clone(),
                crate::plugin_routes::RouteKind::Hook,
            )),
            _ => None,
        })
        .collect();
    let mut route_decls: Vec<(
        String,
        crate::plugin_routes::RouteKind,
        busbar_plugin_loader::Route,
    )> = route_owners
        .into_iter()
        .flat_map(|(name, kind)| {
            // A plugin's DECLARED routes are read straight from its signed manifest. The manifest
            // route field is not yet defined, so this yields nothing today; when it lands, map each
            // declared route to `(name, kind, route)` HERE — the confinement + collision logic is
            // already wired and tested.
            Vec::<busbar_plugin_loader::Route>::new()
                .into_iter()
                .map(move |r| (name.clone(), kind, r))
        })
        .collect();
    // The BUILT-IN exporters (`crate::export`) also claim routes (the `prometheus` exporter's
    // `GET /metrics`). Prepend them in the SAME collision set so a loaded third-party export/hook
    // plugin that tries to claim a path a built-in already owns fails LOUD at `--validate`/boot, e.g.
    // `plugin "datadog" cannot register GET /metrics — already registered by "prometheus"`.
    let mut built_in = crate::export::route_owners(export_cfg);
    built_in.append(&mut route_decls);
    let route_decls = built_in;
    crate::plugin_routes::preflight_route_collisions(&route_decls)
        .map_err(|e| format!("plugin route registration conflict: {e}"))?;

    Ok(registry)
}


/// Resolve the operator ADMIN credential — the `admin-tokens` chain entry's `token:` secret ref —
/// with the BLANK-TOKEN guard. Shared by boot and the apply/reload path so the two cannot drift.
///
/// FAIL-CLOSED twice over:
/// * an unresolvable ref refuses boot/apply (a silently-absent token would lock the admin API
///   while the operator believes it is guarded);
/// * a ref that resolves to EMPTY or ALL-WHITESPACE is refused too. The
///   documented boot guard for this had been lost in the move to secret refs, and the consequence
///   is worse than the docs described: the digest is computed over the blank string, so
///   `admin_token_hash` is `Some(sha256(""))` — a REAL credential that an `Authorization: Bearer `
///   with an empty value satisfies. An env var that expanded to nothing would silently hand the
///   whole admin surface to an unauthenticated caller.
fn resolve_admin_token(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<busbar_api::Redacted<String>>, String> {
    let Some(r) = auth.and_then(|a| a.admin_token_ref()) else {
        return Ok(None);
    };
    let token = resolver
        .resolve_string(r)
        .map_err(|e| format!("auth.admin_auth admin-tokens token did not resolve: {e}"))?;
    if token.trim().is_empty() {
        return Err(
            "auth.admin_auth admin-tokens `token:` resolved to an EMPTY/whitespace-only value. \
             Refusing to start: the digest would be taken over the blank string, so an empty \
             credential would authenticate as the operator. Check the referenced env var / file \
             actually holds the token, or remove the `token:` to disable the admin API deliberately."
                .to_string(),
        );
    }
    Ok(Some(busbar_api::Redacted::new(token)))
}


/// Parse resolved bytes into a 32-byte ed25519 secret: accept RAW 32 bytes or 64 hex chars. Shared
/// by the signing-key resolver and the `--generate-signing-key` self-check.
fn parse_signing_secret(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.len() == 64 {
            if let Ok(v) = hex::decode(s) {
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                return Ok(out);
            }
        }
    }
    Err(
        "auth.signing_key must resolve to a 32-byte ed25519 secret key (raw 32 bytes or 64 hex \
         characters)"
            .to_string(),
    )
}


/// Resolve the KEY-SIGNING key. `auth.signing_key` is a reference to an EXISTING secret
/// (env/file/plugin) resolving to the ed25519 secret material (32 raw bytes, or 64 hex chars) busbar
/// mints + verifies virtual-key tokens with. Fleet-shared: every node resolves the SAME secret so
/// they verify each other's tokens.
///
/// 1.5.1 BREAKING CHANGE: busbar NO LONGER auto-generates and persists a signing key at boot (the
/// 1.5.0 behavior wrote `busbar-signing.key` beside the config, which boot-looped a read-only config
/// mount with a misleading Permission-denied). When `auth.signing_key` is absent this returns `None`;
/// `config_validate` fails CLOSED at `--validate`/boot if the deployment actually uses signed-token
/// auth (the `keys` verifier in the chain), and the mint path fails closed with a clear message
/// otherwise. Generate a key with `busbar --generate-signing-key`.
///
/// FAIL-CLOSED: a configured-but-unresolvable / malformed signing key refuses boot.
fn resolve_signing_key(
    auth: Option<&config::AuthCfg>,
    resolver: &config::secret::SecretResolver,
) -> Result<Option<governance::signing::TokenSigner>, String> {
    use governance::signing::{TokenSigner, DEFAULT_KID};

    let Some(sk) = auth.and_then(|a| a.signing_key.as_ref()) else {
        // No configured key: busbar does not generate one (1.5.1). A deployment that verifies
        // busbar-signed keys is REQUIRED to provide it (enforced fail-closed by config_validate);
        // one that never issues signed tokens simply has no signer.
        return Ok(None);
    };
    let bytes = resolver.resolve(sk).map_err(|e| {
        format!(
            "auth.signing_key did not resolve: {e}. auth.signing_key is a reference to an EXISTING \
             secret (env/file/plugin) - it does NOT generate a key. Provide the key first (a \
             32-byte raw or 64-hex-char ed25519 secret: `busbar --generate-signing-key`, or \
             `openssl rand -hex 32`), or OMIT auth.signing_key entirely if this deployment never \
             issues busbar-signed keys."
        )
    })?;
    let secret = parse_signing_secret(&bytes)?;
    Ok(Some(TokenSigner::from_secret_bytes(&secret, DEFAULT_KID)))
}


/// Validate ONE `secrets:` block key against the plugin registry and return the plugin's CANONICAL
/// name. Fail-closed (an `Err`) when the key names a reserved built-in resolver (`env`/`file`, which
/// take no module-level config), when no loadable plugin is named or aliased by it, or when the
/// resolved plugin is not `kind: secret`. Shared by `build_secret_resolver` (boot) and the
/// `--validate` pre-flight so both apply the identical policy (a mistyped/aliased
/// `secrets:` key must never silently open a plugin with `{}`).
fn validate_secret_module(
    registry: &busbar_plugin_loader::PluginRegistry,
    module: &str,
) -> Result<String, String> {
    if module == config::secret::SECRET_MODULE_ENV || module == config::secret::SECRET_MODULE_FILE {
        return Err(format!(
            "secrets.{module}: '{module}' is a built-in secret resolver, not a plugin; it takes no \
             module-level configuration. Remove this `secrets:` entry (reference it inline as \
             {{ {module}: … }} where the secret is used)."
        ));
    }
    match registry.resolve(module) {
        Some(p) if p.manifest.kind == "secret" => Ok(p.manifest.name.clone()),
        Some(p) => Err(format!(
            "secrets.{module}: plugin '{}' has kind '{}', not 'secret'; only a kind: secret plugin \
             can back a `secrets:` block entry",
            p.manifest.name, p.manifest.kind
        )),
        None => Err(format!(
            "secrets.{module}: no loadable `kind: secret` plugin is named or aliased '{module}' \
             (check the spelling against the plugin's manifest name/alias, and that the plugin \
             loaded — see --list-plugins)"
        )),
    }
}


/// THE POST-RESOLVE HALF OF `--validate`, in one place.
///
/// `config_validate::validate` is only part of what makes a config valid: the plugin pre-flight
/// (consistency, trust resolution, the three-phase tarball scan, store resolution) and the two
/// secret-reference checks are the rest, and they cannot run until the registry exists. Every caller
/// that asks "is this config valid?" must run ALL of it -- `--validate` assembled the steps by hand
/// and `POST /api/v1/admin/config/validate` ran only the first, so the admin dry-run answered
/// `ok: true` for configs the CLI rejects and an operator could ship one straight into a failed boot.
///
/// Whether `m` names a REAL `auth.chain` plugin ref that must resolve against the plugin registry
/// (`true`) vs a builtin/test stand-in that's exempt (`false`). `keys` is engine-handled, never a
/// plugin. `test-groups-module` is ONLY actually registered as a chain module under
/// `#[cfg(test)]` (`AuthMiddleware::new`, `crates/busbar/src/auth/mod.rs`) — `is_test_build` MUST
/// be `cfg!(test)` at the real call site, so this exemption only fires in a test binary. Module-
/// level (not inlined into the `.filter(...)` closure) so the exact predicate that determines
/// `--validate`/`config_validate::validate`'s pass/fail is unit-testable independent of which
/// binary flavor happens to be running `cargo test` — see `tests/tests.rs`. A prior version
/// exempted `test-groups-module` UNCONDITIONALLY (no `is_test_build` gate at all), which made
/// `--validate` silently agree a RELEASE config naming it was fine while real boot still hard-
/// failed (`AuthMiddleware::new` has no non-test arm for it) — breaking the documented invariant
/// a few lines below ("a clean `--validate` means the plugin half of boot succeeds too").
fn is_real_auth_plugin_ref(m: &str, is_test_build: bool) -> bool {
    m != config::KEYS_MODULE && !(is_test_build && m == "test-groups-module")
}


/// The DEFINITION-side twin of [`is_real_auth_plugin_ref`]: whether an
/// `identity-providers.<name>.module:` is a REAL `kind: auth` plugin reference that must resolve
/// against the registry, as opposed to a built-in the engine handles inline
/// ([`config::BUILTIN_IDENTITY_PROVIDERS`] — `keys` and `admin-tokens`) or a compiled-in test
/// stand-in. Separate from the chain predicate because the two answer different questions over
/// different vocabularies: `auth.chain:` never carries `admin-tokens` (that plane is `admin_auth:`),
/// so the chain predicate exempts only `keys`, while EVERY built-in is legal as a definition's
/// module. Same `is_test_build` discipline for the same reason: `test-scope-module` /
/// `test-groups-module` are only ever registered under `#[cfg(test)]` (`AuthPlugins::build`,
/// `crates/busbar/src/auth/mod.rs`), so exempting them unconditionally would make `--validate`
/// silently bless a RELEASE config that real boot still hard-fails.
fn is_real_identity_provider_plugin_ref(m: &str, is_test_build: bool) -> bool {
    !config::BUILTIN_IDENTITY_PROVIDERS.contains(&m)
        && !(is_test_build && matches!(m, "test-groups-module" | "test-scope-module"))
}


/// The human list of every module an `identity-providers.<name>.module:` may legally name RIGHT NOW:
/// the built-ins, plus every loaded `kind: auth` plugin. Named as a SET, never counted — the same
/// "name the whole valid vocabulary" discipline the `export.<n>.streams:` diagnostic follows.
fn valid_identity_provider_modules(registry: &busbar_plugin_loader::PluginRegistry) -> String {
    let mut names: Vec<String> = config::BUILTIN_IDENTITY_PROVIDERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    names.extend(
        registry
            .loadable()
            .iter()
            .filter(|p| p.manifest.kind == "auth")
            .map(|p| p.manifest.name.clone()),
    );
    names.join(" | ")
}


/// Manifest-only, like the pre-flight it wraps: nothing is `dlopen`ed and no store is opened, so it
/// is safe on the admin read path.
pub fn preflight_plugins_and_secrets(
    deploy: &config::DeployCfg,
    cfg: &config::RootCfg,
) -> Result<busbar_plugin_loader::PluginRegistry, String> {
    let registry = plugins_preflight(
        deploy.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &deploy.plugins,
        &cfg.export,
    )?;
    validate_secret_modules(&registry, &cfg.secrets)?;
    validate_secret_refs(&registry, cfg)?;
    Ok(registry)
}


/// Validate EVERY `secrets:` block entry against the registry (the `--validate` counterpart of the
/// per-entry check `build_secret_resolver` runs at boot). Returns the FIRST offending entry's error.
fn validate_secret_modules(
    registry: &busbar_plugin_loader::PluginRegistry,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<(), String> {
    for module in secret_modules.keys() {
        validate_secret_module(registry, module)?;
    }
    Ok(())
}


/// Validate every SECRET REFERENCE's module against the plugin registry — the deferred half of the
/// secret-reference check `config_validate` cannot do (it runs before the registry exists). The
/// built-in `env`/`file` modules always pass; ANY OTHER module name is a `kind: secret` PLUGIN
/// reference (the 1.5.0 "secrets are plugins" feature: `api_key: { module: acme-vault, … }`, TLS
/// cert/key, `auth.signing_key`, the admin token) and must resolve to a LOADED, TRUSTED, `kind:
/// secret` plugin. A genuine typo (no built-in, no plugin) is a hard boot / `--validate` error;
/// an installed vault/aws-sm plugin PASSES. Shared by boot (`build_app_from_config`) and the
/// `--validate` pre-flight so the two cannot drift. Returns the FIRST offending reference's error.
fn validate_secret_refs(
    registry: &busbar_plugin_loader::PluginRegistry,
    cfg: &config::RootCfg,
) -> Result<(), String> {
    for (what, r) in config_validate::secret_refs(cfg) {
        if r.module == config::secret::SECRET_MODULE_ENV
            || r.module == config::secret::SECRET_MODULE_FILE
        {
            continue; // built-in resolver — already structurally checked in config_validate
        }
        match registry.resolve(&r.module) {
            Some(p) if p.manifest.kind == "secret" => {}
            Some(p) => {
                return Err(format!(
                    "{what} references secret module '{}', but plugin '{}' has kind '{}', not \
                     'secret'; only a `kind: secret` plugin can back a secret reference",
                    r.module, p.manifest.name, p.manifest.kind
                ));
            }
            None => {
                return Err(format!(
                    "{what} references secret module '{}', which is not a built-in (`env` | `file`) \
                     and no loadable `kind: secret` plugin is named or aliased '{}'. Fix the \
                     spelling, install/trust the plugin (see --list-plugins), or use a built-in, \
                     e.g.:\n\n    {what}: {{ env: MY_SECRET_VAR }}\n",
                    r.module, r.module
                ));
            }
        }
    }
    Ok(())
}


/// RESOLVE every built-in (`env` / `file`) secret reference, for `--validate` ONLY.
///
/// `config_validate` proves a reference is well-FORMED; it cannot prove the variable is set or the
/// file is readable, because it runs before anything touches the environment. Without this,
/// `--validate` reported a config VALID while boot would warn and then serve a gateway whose every
/// upstream request fails on a missing credential: success reported for something that cannot work.
///
/// DELIBERATELY NOT IN `preflight_plugins_and_secrets`. That pre-flight is SHARED with boot and with
/// the admin apply/reload path, where an unresolvable secret is a WARNING by design, not a refusal
/// (`test_admin_v1_config_settings_unresolvable_store_secret_warns_not_rejects` pins that). A live
/// config change must not be rejected for a secret that may resolve on the next deploy. The operator
/// asking `--validate` is asking a different question, and deserves the strict answer.
///
/// Returns the FIRST unresolvable reference's error, naming the field so it is actionable.
pub fn validate_builtin_secrets_resolve(cfg: &config::RootCfg) -> Result<(), String> {
    let builtins = config::secret::SecretResolver::builtins_only();
    for (what, r) in config_validate::secret_refs(cfg) {
        if r.module != config::secret::SECRET_MODULE_ENV
            && r.module != config::secret::SECRET_MODULE_FILE
        {
            continue; // plugin-backed: the plugin may not be loadable here, and preflight covers it
        }
        if let Err(e) = builtins.resolve(r) {
            return Err(format!("{what}: {e}"));
        }
    }
    Ok(())
}


/// Build the [`config::secret::SecretResolver`] the engine resolves every secret reference through:
/// the built-in `env`/`file` modules inline, and any OTHER module name via a loaded `kind: secret`
/// plugin from `registry` (opened per resolution; a secret module is off every hot path so the
/// per-call open + resolve is fine). FAIL-CLOSED: `open_secret` errors surface as an unresolvable
/// secret. When the plugin subsystem is off the registry is empty and every non-built-in reference
/// is a fail-closed error at resolve time.
fn build_secret_resolver(
    registry: Arc<busbar_plugin_loader::PluginRegistry>,
    secret_modules: &std::collections::BTreeMap<String, config::SecretModuleCfg>,
) -> Result<config::secret::SecretResolver, String> {
    // MODULE-LEVEL config delivery for `kind: secret` plugins: resolve each configured
    // `secrets.<module>.settings` ONCE at boot and hand it to the plugin's `open()`, exactly as
    // `store.settings` configures the store plugin. Without this a secret plugin's `open()` always
    // received `{}`, so a Vault-style plugin's address/namespace/token/CA had to be repeated in EVERY
    // SecretRef — multiplying secret exposure and defeating the open-vs-resolve separation the ABI
    // is designed around.
    //
    // The module config is resolved against the BUILT-IN env/file resolvers ONLY (a `builtins_only`
    // resolver). A secret module cannot resolve its OWN `open()` config through a secret plugin —
    // that would be a bootstrap cycle — so `{ token: { env: VAULT_TOKEN } }` resolves but
    // `{ token: { module: some-other-secret-plugin } }` is a fail-closed error.
    let builtins = config::secret::SecretResolver::builtins_only();
    // Key the open-config map by the plugin's CANONICAL name, not by the literal `secrets:` block
    // key: a `SecretRef` may name the plugin by EITHER its canonical name or its alias, and
    // the registry resolves both — but a bare string-equality lookup on the block key would MISS the
    // other spelling and silently open the plugin with `{}` (dropping the operator's configured
    // address/token/CA). Canonicalize the block key through the SAME by_name/by_alias resolution the
    // registry uses, so a `secrets:` entry written under an alias and a `SecretRef` written under the
    // canonical name (or vice versa) line up. A `secrets:` entry that resolves to NOTHING — a typo, or
    // a module that names one of the reserved built-in resolvers (`env`/`file`, which take no
    // module-level open config) — is a hard boot error: silently passing `{}` for a mis-typed module
    // is exactly the failure this closes. The `--validate` path applies the identical policy via the
    // shared `validate_secret_module`/`validate_secret_modules` helpers.
    let mut open_config: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    // Which `secrets:` block key produced each canonical entry, so an ALIAS/CANONICAL collision can
    // be named precisely.
    let mut claimed_by: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (module, mcfg) in secret_modules {
        // Validate + canonicalize the block key against the registry (shared with --validate). A
        // reserved built-in name, an unknown module, or a non-secret plugin is a hard error here.
        let canonical = validate_secret_module(&registry, module)?;
        // TWO SPELLINGS, ONE MODULE: a `secrets:` block written under BOTH a plugin's alias and its
        // canonical name canonicalizes to the same key, and the second insert silently DROPPED the
        // first entry's open() config — one of the two blocks (address, token, CA) just vanished,
        // with the module still loading happily on the survivor. Ambiguous by construction: there is
        // no defensible rule for which one wins. Fail LOUD and name both spellings.
        if let Some(previous) = claimed_by.get(&canonical) {
            return Err(format!(
                "secrets: the module '{canonical}' is configured TWICE — once as '{previous}' and \
                 once as '{module}' (an alias and its canonical name resolve to the same plugin). \
                 One of the two blocks would be silently dropped; keep exactly one."
            ));
        }
        let resolved = config::secret::resolve_settings(&mcfg.settings, &builtins)
            .map_err(|e| format!("secrets.{module} settings: {e}"))?;
        claimed_by.insert(canonical.clone(), module.clone());
        open_config.insert(canonical, serde_json::Value::Object(resolved).to_string());
    }
    Ok(config::secret::SecretResolver::with_plugin(Box::new(
        move |module: &str, settings: &str| -> Result<Vec<u8>, String> {
            // Canonicalize the referenced module the SAME way, so an alias-vs-name spelling difference
            // between the `secrets:` block and this `SecretRef` still finds the configured open() JSON.
            // A module that does not resolve falls through to `open_secret` below, which produces the
            // authoritative "no such plugin" error.
            let canonical = registry
                .resolve(module)
                .map(|p| p.manifest.name.as_str())
                .unwrap_or(module);
            // Deliver the module's configured open() JSON (default `{}` for an unconfigured module).
            let open_cfg = open_config
                .get(canonical)
                .map(String::as_str)
                .unwrap_or("{}");
            let m = registry.open_secret(module, open_cfg)?;
            m.resolve(
                &serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(settings)
                    .map_err(|e| format!("secret settings are not a JSON object: {e}"))?,
            )
            .map_err(|e| e.to_string())
        },
    )))
}


/// A queued-but-not-yet-applied governance credential rotation: `build_app_from_config` resolves it
/// but does NOT invoke it (see the call site below for why). `Send` because it is carried across the
/// `spawn_blocking` boundary the admin transaction (`txn.rs`) applies it on.
pub type GovCredentialRotation = Box<dyn FnOnce() + Send>;


/// The `plugins.fetch` download closure the engine hands to `busbar_plugin_loader::fetch_plugins`.
/// Enforces the SAME cloud-metadata SSRF denylist provider URLs face (fetch is off-box, key-adjacent
/// I/O) and requires https for a public host, then performs the GET. The GET runs on a DEDICATED
/// std::thread with its own current-thread runtime, so it is safe whether the caller sits on a tokio
/// worker (boot) or a `spawn_blocking` thread (reload) — a nested `block_on` on a runtime thread would
/// otherwise panic. The loader owns cache/verify/atomic-write; this owns network + SSRF.
fn plugin_fetch_downloader(blocked: &[String]) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    plugin_fetch_downloader_with_cap(blocked, config::DEFAULT_PLUGIN_FETCH_MAX_BYTES)
}


/// Same as [`plugin_fetch_downloader`] with an explicit download-size cap — split out so a test can
/// exercise the over-cap rejection path against a small in-memory server without actually moving
/// hundreds of megabytes through loopback. Production always calls [`plugin_fetch_downloader`], which
/// pins `cap` to [`config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`].
fn plugin_fetch_downloader_with_cap(
    blocked: &[String],
    cap: usize,
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| -> Result<Vec<u8>, String> {
        // Scheme: https required for a public host; plaintext http only for loopback/private (a local
        // dev registry). Mirrors the provider base_url rule.
        let https = config_validate::scheme_is(url, "https");
        if !https {
            let host_local = config_validate::extract_normalized_host(url)
                .as_deref()
                .map(config_validate::host_is_private_or_loopback)
                .unwrap_or(false);
            if !(config_validate::scheme_is(url, "http") && host_local) {
                return Err(format!(
                    "plugins.fetch url must use https for a public host (got '{url}')"
                ));
            }
        }
        // SSRF: never fetch from a cloud-metadata host (no per-provider carve-outs; the operator
        // denylist still extends the built-in list).
        if let Some(bad) = config_validate::ssrf_blocked_host(url, &[], false, &blocked) {
            return Err(format!(
                "plugins.fetch url '{url}' targets a blocked cloud-metadata host '{bad}'"
            ));
        }
        let url = url.to_string();
        std::thread::scope(|s| {
            s.spawn(|| -> Result<Vec<u8>, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("fetch runtime: {e}"))?;
                rt.block_on(async {
                    let resp = reqwest::Client::new()
                        .get(&url)
                        .send()
                        .await
                        .map_err(|e| format!("GET {url}: {e}"))?;
                    let status = resp.status();
                    if !status.is_success() {
                        return Err(format!("GET {url}: HTTP {status}"));
                    }
                    // A declared Content-Length over the cap is rejected BEFORE reading a single body
                    // byte — the fast, cheap path for the common case of an honest oversized response.
                    // Not load-bearing on its own (a dishonest/absent header falls through to the
                    // streamed cap below), just an early exit.
                    if let Some(len) = resp.content_length() {
                        if len as usize > cap {
                            return Err(format!(
                                "GET {url}: declared Content-Length {len} exceeds the {cap}-byte \
                                 plugins.fetch download cap"
                            ));
                        }
                    }
                    // Stream with a running byte counter (never `resp.bytes()`, which buffers the
                    // ENTIRE — possibly multi-gigabyte — body before any cap could apply) so a
                    // mistyped or compromised URL serving an unbounded body is rejected with a clear
                    // error instead of OOMing busbar on boot or `/plugins/reload`.
                    let (bytes, end) = crate::proxy::read_capped(resp, cap).await;
                    match end {
                        crate::proxy::ReadEnd::Complete => Ok(bytes.to_vec()),
                        crate::proxy::ReadEnd::Truncated => Err(format!(
                            "GET {url}: response exceeded the {cap}-byte plugins.fetch download cap; \
                             refusing to buffer a truncated download"
                        )),
                        crate::proxy::ReadEnd::TransportError => {
                            Err(format!("read body {url}: connection failed mid-download"))
                        }
                    }
                })
            })
            .join()
            .map_err(|_| "plugins.fetch download thread panicked".to_string())?
        })
    }
}


pub fn build_app_from_config(
    cfg: config::RootCfg,
    plugins_cfg: config::PluginsCfg,
    overlay_path: Option<std::path::PathBuf>,
    base_hook_names: std::collections::HashSet<String>,
    base_group_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
) -> Result<(state::App, Option<GovCredentialRotation>), String> {
    // Install the resolved operational limits process-wide BEFORE any subsystem reads them —
    // running here (not in main) so a config APPLY/RELOAD refreshes them too. The values threaded
    // explicitly (client/store/router/TLS) read `cfg.limits` directly; the deep call-stack sites
    // (translate-body cap, metrics gauge limit, webhook timeout, governance sqlite/sweep, health
    // probe fallbacks, routing policy timeout) read the installed values.
    //
    // …THROUGH A GUARD, because everything below this line is fallible. The install has to come
    // first (the build itself reads these values), but a build that goes on to FAIL must not leave
    // the rejected config's limits installed under the old `App` that keeps serving. The guard
    // restores the previous values on drop unless the build reaches its `Ok`, so "an invalid apply
    // changes nothing" holds for process-wide limits the same way it holds for everything else.
    let limits_guard = limits::InstallGuard::install(&cfg.limits);
    // The config version this App will carry — computed ONCE up front because hook-transport
    // resolution stamps it into every socket configure preamble (the preamble's
    // settings_version must be the REAL version of the settings it delivers, not a hardcoded 0).
    let app_config_version = prior.map_or(0, |p| p.config_version.wrapping_add(1));
    // Semantic validation — the same gate boot has always had, now on the ONE construction path
    // so an apply/reload validates identically and an invalid config changes nothing.
    if let Err(validation_errors) = config_validate::validate(&cfg) {
        return Err(format!(
            "config validation failed:\n  - {}",
            validation_errors.join("\n  - ")
        ));
    }
    // The resolved `export:` block drives the built-in exporters' plugin-route table below. Captured
    // before `cfg`'s fields are consumed by the `App` struct literal.
    let cfg_export = cfg.export.clone();
    let auth_cfg = cfg
        .auth
        .clone()
        .unwrap_or_else(config::AuthCfg::default_none);

    // DECLARATIVE PLUGIN FETCH (`plugins.fetch:`) — download the operator-declared signed tarballs
    // into `plugins.dir` BEFORE preflight scans it. Runs at BOOT and on `POST /plugins/reload` (both
    // reach this construction path), NEVER in `--validate` (that path never calls
    // `build_app_from_config`, preserving its zero-side-effect/no-network contract), and NEVER
    // per-request. `prior.is_none()` is the boot(fatal-on-miss) vs reload(warn-on-miss) discriminator.
    // Signature verification stays the trust gate below; fetch is integrity/cache + delivery only.
    if plugins_cfg.enabled && !plugins_cfg.fetch.is_empty() {
        let specs = plugins_cfg.fetch_specs()?;
        let dir = std::path::Path::new(&plugins_cfg.dir).to_path_buf();
        // Ensure the target dir exists so the atomic rename has a home.
        if let Err(e) = crate::durable::create_dir_all(&dir) {
            return Err(format!(
                "plugins.fetch: cannot create plugins dir '{}': {e}",
                dir.display()
            ));
        }
        let downloader = plugin_fetch_downloader(&cfg.blocked_metadata_hosts);
        let outcomes =
            busbar_plugin_loader::fetch_plugins(&dir, &specs, prior.is_none(), &downloader)
                .map_err(|errs| format!("plugins.fetch failed:\n  - {}", errs.join("\n  - ")))?;
        for outcome in &outcomes {
            match outcome {
                busbar_plugin_loader::FetchOutcome::Cached { filename } => {
                    tracing::info!(filename, "plugins.fetch: cached (pin match, no download)")
                }
                busbar_plugin_loader::FetchOutcome::Fetched { filename } => {
                    tracing::info!(filename, "plugins.fetch: downloaded + verified")
                }
                busbar_plugin_loader::FetchOutcome::Warned { url, error } => {
                    tracing::warn!(
                        url,
                        error,
                        "plugins.fetch: miss on reload; keeping current artifact"
                    )
                }
            }
        }
    }

    // PLUGIN PRE-FLIGHT (the ONE shared pipeline; see the fn doc). Run UP FRONT so the secret
    // resolver - and the store open below - both draw on the same validated registry. A non-memory
    // store, an unresolvable secret plugin, or any invalid tarball fails boot here.
    let plugin_registry = Arc::new(plugins_preflight(
        cfg.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &plugins_cfg,
        &cfg.export,
    )?);

    // Every SECRET REFERENCE whose module is not a built-in (`env`/`file`) must resolve to a loaded
    // `kind: secret` plugin — the deferred half of the check `config_validate::validate` cannot do
    // (it runs before the registry exists). A typo'd module fails boot HERE; the documented vault
    // `api_key: { module: acme-vault }` passes once the plugin is loaded + trusted. This is the boot
    // twin of the `--validate` check, sharing `validate_secret_refs`/`config_validate::secret_refs`.
    validate_secret_refs(&plugin_registry, &cfg)?;

    // The SECRET RESOLVER: built-in env/file resolve inline; any other module delegates to a
    // loaded `kind: secret` plugin via the registry (fail-closed if the plugin subsystem is off or
    // the module is unknown). Shared by provider keys, the admin token, and the TLS listener.
    let secret_resolver = Arc::new(build_secret_resolver(
        plugin_registry.clone(),
        &cfg.secrets,
    )?);

    let mut lanes_data = Vec::new();
    // Validated provider handle for each lane, captured in lockstep with `lanes_data` below. The
    // first loop already resolves `cfg.providers.get(&mc.provider)` (failing loud via `die` on a
    // missing provider), so the lane-build loop reuses that handle instead of re-looking it up —
    // there is no second lookup and no `expect` on the startup path.
    let mut lane_provider_cfgs: Vec<&config::ProviderCfg> = Vec::new();
    let mut by_model = HashMap::new();
    // Per-model configured default_max_tokens (injected at the translation seam for protocols that
    // require max_tokens). Captured here because `cfg.models` is consumed by this loop.
    let mut model_default_max_tokens: std::collections::HashMap<String, Option<u32>> =
        std::collections::HashMap::new();
    // Single source of truth for each provider's resolved API key. The secret-bearing env read
    // happens exactly once per provider here; both the empty-key warning below and the later
    // `Lane.api_key` population reuse this value, so the warning and the captured key can never
    // diverge (and we don't read the same env var twice).
    let mut provider_api_keys: HashMap<String, String> = HashMap::new();
    // Build lanes in a DETERMINISTIC order (sorted by model name) rather than `cfg.models`'
    // HashMap iteration order, which is randomized per process start. Lane index is assigned here
    // (`by_model` → `lanes_data.len()`), so a random iteration order gave each lane a different
    // index every boot — surfacing as non-reproducible `/stats` lane ordering and metric lane-series
    // identity that shifts across restarts (a scrape/dashboard annoyance and a flaky-test source).
    // Sorting makes the whole observable surface stable. (Mirrors the deterministic-resolution fix
    // already applied to `model_context_max` below.)
    // Resolve the COST MODEL from THIS config (rate card + budget groups + flat fee) BEFORE
    // `cfg.models` is consumed below. Rebuilt on every apply/reload - unlike the GovState ledger,
    // which survives the swap - so a rate-card correction reprices every derived figure on the
    // next read (tokens are the truth).
    let cost = Arc::new(crate::cost::CostModel::resolve_parts(
        cfg.rate_card.as_ref(),
        cfg.per_request_fee,
        &cfg.groups,
    ));

    let mut sorted_models: Vec<_> = cfg.models.into_iter().collect();
    sorted_models.sort_by(|a, b| a.0.cmp(&b.0));
    for (model, mc) in sorted_models {
        model_default_max_tokens.insert(model.clone(), mc.default_max_tokens);
        let Some(provider_cfg) = cfg.providers.get(&mc.provider) else {
            return Err(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ));
        };
        let key = provider_api_keys.entry(mc.provider.clone()).or_insert_with(|| {
            // Resolve the provider credential through its SECRET REFERENCE. An unresolvable
            // secret degrades to the empty key with a loud warning (parity with the old empty
            // env-var posture: keyless local upstreams - ollama/vLLM - are legitimate).
            match secret_resolver.resolve_string(&provider_cfg.api_key) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(provider = %mc.provider, "provider api_key did not resolve: {e}");
                    String::new()
                }
            }
        });
        if key.is_empty() {
            eprintln!(
                "[warn] provider {} api_key ({}) empty",
                mc.provider,
                provider_cfg.api_key.describe()
            );
        }
        let limited = mc.max_requests >= 0;
        // `max_concurrent` is an OPT-IN limiter: omitted (None) = UNBOUNDED. Realize "unbounded" as a
        // semaphore seeded with `Semaphore::MAX_PERMITS` (usize::MAX >> 3) — a lane will never reach
        // 2^60 concurrent in-flight requests, so this never throttles, yet it keeps the entire
        // permit-based dispatch path (which every selection route depends on) intact. A literal
        // usize::MAX would PANIC: `Semaphore::new` asserts `permits <= MAX_PERMITS`. `max` records the
        // same count so /stats `inflight = max - available` stays coherent.
        let max_concurrent = mc
            .max_concurrent
            .unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        by_model.insert(model.clone(), lanes_data.len());
        lane_provider_cfgs.push(provider_cfg);
        lanes_data.push(LaneData {
            model: model.clone(),
            provider: mc.provider.clone(),
            max: max_concurrent,
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            limited,
            budget: if limited { mc.max_requests } else { -1 },
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            upstream_model: mc.upstream_model.clone(),
            attempt_timeout_ms: mc.attempt_timeout_ms,
            reasoning: mc.reasoning.unwrap_or(false),
            prompt_caching: mc.prompt_caching.unwrap_or(false),
        });

        eprintln!(
            "  model {} via {} ({}) max {}{}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            // Show the operator-facing form: an omitted cap reads "unbounded", not 2^60.
            match mc.max_concurrent {
                Some(n) => n.to_string(),
                None => "unbounded".to_string(),
            },
            // Surface the alias→wire-id indirection at boot so an operator can see this lane sends a
            // different model string upstream than the config key it's filed under.
            match &mc.upstream_model {
                Some(u) => format!(" → upstream {u}"),
                None => String::new(),
            }
        );
    }

    let registry = ProtocolRegistry::with_builtins();

    // Build a map from model name to context_max. A model is one lane shared across every pool that
    // names it, so its context_max must be single-valued. Previously the last pool to iterate (in
    // nondeterministic HashMap order) silently won, so a model carrying `context_max: Some(128000)`
    // in one pool and `None` (or a different limit) in another could end up with whichever value the
    // iteration happened to land on — defeating the context-length failover exclusion in proxy engine
    // and losing pool-specific limits without a diagnostic. Resolve it deterministically and fail
    // loud on a genuine conflict instead.
    let model_context_max = resolve_model_context_max(&cfg.pools)?;

    let mut lanes = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        // Reuse the provider handle resolved (and validated via `die`) in the lanes_data loop above,
        // captured in lockstep into `lane_provider_cfgs`. No redundant re-lookup / `expect` here.
        let provider_cfg = lane_provider_cfgs[idx];
        let Some(protocol) = registry.get(&provider_cfg.protocol) else {
            return Err(format!(
                "provider '{}' uses unknown protocol '{}' (supported: anthropic, openai, gemini, bedrock, responses, cohere)",
                ld.provider, provider_cfg.protocol
            ));
        };
        // Reuse the single env read captured in the lanes_data loop above (same source of truth as
        // the empty-key warning); no second read of the secret-bearing env var.
        let api_key = provider_api_keys
            .get(&ld.provider)
            .cloned()
            .unwrap_or_default();
        // Resolve the outbound credential once. Most auth styles are a simple sync lookup; the OAuth
        // styles parse their credential material here (failing loud on a bad key) and start a
        // background token minter/refresher. `api_key` carries that material.
        //
        // Both OAuth mechanisms vet their token endpoint (oauth `token_url`, jwt-bearer SA `token_uri`)
        // for SSRF against the operator's REAL metadata posture so the boot-time check matches
        // config_validate's validate-time check EXACTLY (validate == apply) and both mechanisms behave
        // identically: the allow-override set is the SAME union config_validate builds (this provider's
        // `allow_metadata_hosts` ∪ the global `security.allow_metadata_hosts`), plus the nuclear
        // `allow_all_metadata` and the operator's extra `blocked_metadata_hosts`. Threading it into
        // jwt-bearer too means a global `blocked_metadata_hosts` deny is enforced on a jwt
        // `token_uri`, and `allow_all_metadata` uniformly disables the guard for both.
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();
        let ssrf = egress_auth::MetadataSsrfPolicy {
            allow_overrides: &allow_overrides,
            allow_all: cfg.allow_all_metadata,
            blocked_hosts: &cfg.blocked_metadata_hosts,
        };
        let credential = match provider_cfg.auth {
            // `jwt-bearer`: `api_key` is the service-account JSON (inline) or a key-file path. A
            // configured `scope:` overrides the default cloud-platform scope (else `None` → default).
            // A configured `subject:` (RFC 7523 `sub`) is opt-in: `None` (the default, every existing
            // Vertex AI config) omits the claim entirely, unchanged from before this field existed.
            Some(config::ProviderAuth::JwtBearer) => egress_auth::jwt_bearer::build(
                &api_key,
                provider_cfg.scope.as_deref(),
                provider_cfg.subject.as_deref(),
                &ssrf,
            )
            .map_err(|e| format!("provider '{}' (jwt-bearer auth): {e}", ld.provider))?,
            // `oauth-client-credentials`: `api_key` is `client_id:client_secret`; `token_url`+`scope`
            // come from the provider config (required — the config validator also rejects them absent).
            Some(config::ProviderAuth::OAuthClientCredentials) => {
                let token_url = provider_cfg.token_url.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `token_url`",
                        ld.provider
                    )
                })?;
                let scope = provider_cfg.scope.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `scope`",
                        ld.provider
                    )
                })?;
                egress_auth::oauth_client_credentials::build(&api_key, token_url, scope, &ssrf)
                    .map_err(|e| {
                        format!(
                            "provider '{}' (oauth-client-credentials auth): {e}",
                            ld.provider
                        )
                    })?
            }
            _ => egress_auth::resolve(&provider_cfg.protocol, provider_cfg.auth),
        };
        let base_url = provider_cfg.base_url.trim_end_matches('/').to_string();
        lanes.push(Lane {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            // Precompute the SigV4 signed-host once at boot (pure function of base_url) so the forward
            // path borrows it into SigningContext instead of re-parsing/allocating it per request.
            signing_host: proxy::host_from_base(&base_url),
            base_url,
            api_key: busbar_api::Redacted::new(api_key),
            credential,
            protocol,
            max: ld.max,
            error_map: Arc::new(provider_cfg.error_map.clone()),
            context_max: model_context_max.get(&ld.model).copied().flatten(),
            path: provider_cfg.path.clone(),
            path_base: provider_cfg.path_base.clone(),
            health: provider_cfg.health.clone(),
            upstream_model: ld.upstream_model.clone(),
            attempt_timeout_ms: ld.attempt_timeout_ms,
            reasoning: ld.reasoning,
            prompt_caching: ld.prompt_caching,
            default_max_tokens: model_default_max_tokens.get(&ld.model).copied().flatten(),
        });
    }

    let mut pools = HashMap::new();
    for (name, pool) in &cfg.pools {
        // Wire per-member weights from config into the pool structure.
        // Each pool member has a weight; default is 1 if not specified.
        let mut weighted_members: Vec<WeightedLane> = Vec::with_capacity(pool.members.len());
        for m in pool.members.iter() {
            {
                let Some(&lane_idx) = by_model.get(&m.model) else {
                    return Err(format!(
                        "pool '{name}' references unknown model '{}'",
                        m.model
                    ));
                };
                weighted_members.push(WeightedLane {
                    idx: lane_idx,
                    weight: m.weight, // from config PoolMember.weight (default 1)
                    // Per-member attempt cap: one model, different hang budgets per pool/workload.
                    attempt_timeout_ms: m.attempt_timeout_ms,
                    reasoning: m.reasoning,
                });
            }
        }
        pools.insert(name.clone(), weighted_members);
    }

    eprintln!("busbar: {} models, {} pools", lanes.len(), pools.len());
    for (n, wl_vec) in &pools {
        let agg: usize = wl_vec.iter().map(|wl| lanes[wl.idx].max).sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            n,
            wl_vec
                .iter()
                .map(|wl| lanes[wl.idx].model.clone())
                .collect::<Vec<_>>()
                .join(", "),
            agg
        );
    }

    // Loud warning for an empty `auth.chain` (open relay). Not fatal — busbar still starts (useful for
    // local dev) — but operators must not run this in production. NOTE: an ABSENT `auth:` block
    // serde-defaults to an empty chain too (`AuthCfg::default_none`), so a config that merely omits
    // `auth:` silently becomes an open relay. Surface this at ERROR level (not warn — a warn is
    // suppressed under RUST_LOG=error, the very level an operator most likely runs in production)
    // AND unconditionally on stderr, so the open-relay state cannot be masked by log configuration.
    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty(), cfg.auth.is_some()) {
        eprintln!("[error] {banner}");
        tracing::error!("{banner}");
    }

    // FAIL-CLOSED: the auth chain resolves every non-builtin `auth.chain` module as a `kind: auth`
    // plugin via the SAME validated registry the store/secret plugins load through. A configured
    // auth plugin that cannot be loaded (missing/untrusted tarball, wrong kind, ABI failure) aborts
    // boot here rather than silently dropping the module and leaving the front door open.
    let auth_mw = Arc::new(
        AuthMiddleware::new(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth chain construction failed: {e}"))?,
    );
    // ADMIN-plane external auth plugins (1.5.2 admin-plane OIDC): resolve every non-builtin
    // `admin_auth:` entry as a signed `kind: auth` plugin through the SAME validated registry. Runs
    // on boot AND reload (this whole function is `build_app_from_config`, called on both), so a
    // reload can never leave a stale/empty admin chain. FAIL-CLOSED: an unresolvable admin module
    // aborts the build rather than silently disabling the admin plane.
    let admin_modules = Arc::new(
        crate::auth::AdminAuthChain::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("admin auth chain construction failed: {e}"))?,
    );
    // HOSTED-LOGIN methods (1.5.2): resolve every `auth.methods:` entry as a login-capable
    // `kind: auth` plugin (ABI v2). Also runs on boot AND reload (this whole fn). FAIL-CLOSED: an
    // unresolvable method — or a `browser_login` method backed by a pre-v2 plugin (capability gate)
    // — aborts the build rather than surfacing a 500 at request time.
    let login_methods = Arc::new(
        crate::auth::token::LoginMethods::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth.methods (hosted login) construction failed: {e}"))?,
    );
    // Thread the operator-configured hard-down cooldown + honored-Retry-After ceiling into the store
    // (both default to their historical const at the config layer).
    // Carry-over: an APPLY/RELOAD (prior = Some) restores every surviving lane's learned
    // health state BY STABLE IDENTITY from the prior store; boot (None) starts fresh.
    let store: Arc<dyn crate::store::LaneRuntime> = match prior {
        Some(p) => Arc::new(HealthState::new_with_limits_restored(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
            &p.store.export_health(),
        )),
        None => Arc::new(HealthState::new_with_limits(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
        )),
    };

    // Global default failover config — the fallback for pools that don't set their own. A fixed
    // default (not "whatever pool HashMap iteration happens to yield first", which was
    // nondeterministic across restarts).
    let failover_cfg = Some(crate::config::FailoverCfg {
        timeout_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
        exclusions: None,
        max_hops: crate::config::DEFAULT_FAILOVER_CAP,
    });

    // The fallback-pool routing table: on_exhausted `fallback_pool:<name>` looks a pool up here,
    // so it mirrors the pools map (any pool can be a fallback target).
    let fallback_pools = pools.clone();

    // The upstream HTTP client, built ONCE — as N per-thread SHARDS (see `UpstreamClients`): each
    // worker thread keeps its own client/pool, so no request ever crosses another core's pool
    // lock. Constructed before the pool-runtime loop so the webhook routing transport can reuse
    // it (a shard clone shares that shard's connection pool + the `redirect:none` SSRF posture);
    // the sharded set is then moved into `App` below.
    let upstream_client = if let Some(p) = prior {
        // REUSED across applies: the pooled connections + their kept-alive upstream sockets.
        p.client.clone()
    } else {
        // Opt-in HTTP/2 PRIOR-KNOWLEDGE for CLEARTEXT upstreams (no TLS/ALPN to negotiate over):
        // `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE=1` makes the shared client assume h2 without ALPN. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps ALPN (safe against h1 upstreams);
        // it exists so a cleartext h2c backend (e.g. the benchmark mock, or an in-mesh h2c service)
        // can exercise multiplexing without TLS. It FORCES h2, so every configured upstream must speak
        // h2c when set — never enable it against a mixed/h1 fleet. Read once at client-build time.
        // 1.5.3: home is `advanced.upstream_h2_prior_knowledge` in config.yaml (carried on
        // `cfg.limits`); the `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` env var overrides it for one release,
        // with a deprecation warn.
        let h2_env = std::env::var_os("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE");
        if h2_env.is_some() {
            tracing::warn!(
                "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE is DEPRECATED; set \
                 `advanced.upstream_h2_prior_knowledge` in config.yaml (honored for now)."
            );
        }
        let h2_prior_knowledge =
            upstream_bool_env_override(h2_env, cfg.limits.upstream_h2_prior_knowledge);
        // Opt-out ESCAPE HATCH for the ALPN h2 default: `BUSBAR_UPSTREAM_HTTP1_ONLY=1` pins the
        // shared client to HTTP/1.1 (reqwest `.http1_only()`), so ALPN never offers h2 at all. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps the ALPN default (h2 where the
        // backend accepts it, h1 otherwise); it exists as an operational rollback lever in case a
        // specific upstream negotiates h2 but misbehaves on it (flow-control stalls, broken
        // keep-alive pings, intermediary bugs) and you need the pre-h2 wire behavior back without a
        // rebuild. Mutually exclusive in spirit with the h2c opt-in above (forcing h1 AND forcing
        // h2 makes no sense); if both are set, http1-only wins because it is applied last. Read
        // once at client-build time. 1.5.3: home is `advanced.upstream_http1_only` in config.yaml
        // (carried on `cfg.limits`); the `BUSBAR_UPSTREAM_HTTP1_ONLY` env var overrides it for one
        // release, with a deprecation warn.
        let http1_env = std::env::var_os("BUSBAR_UPSTREAM_HTTP1_ONLY");
        if http1_env.is_some() {
            tracing::warn!(
                "BUSBAR_UPSTREAM_HTTP1_ONLY is DEPRECATED; set `advanced.upstream_http1_only` in \
                 config.yaml (honored for now)."
            );
        }
        let http1_only = upstream_bool_env_override(http1_env, cfg.limits.upstream_http1_only);
        let shard_count = crate::state::UpstreamClients::shard_count();
        // The per-host idle budget is divided across shards so the TOTAL kept-alive sockets
        // toward any single upstream stay at the configured value (never below 1 per shard).
        let idle_per_host_per_shard = cfg
            .limits
            .pool_max_idle_per_host
            .div_ceil(shard_count)
            .max(1);
        let make_one = || {
            let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(
                cfg.limits.upstream_request_timeout_secs,
            ));
            builder = builder
                // Bound the TCP connect separately from the coarse overall timeout: a stalled SYN would
                // otherwise hang up to the streaming `.timeout()` (minutes) before failover kicks in.
                .connect_timeout(Duration::from_secs(10))
                // Keep idle upstream sockets alive so a middlebox silently dropping a long-idle
                // keep-alive connection is detected proactively, not discovered as a spurious failure on
                // the next request (added latency + a needless failover hop).
                .tcp_keepalive(Duration::from_secs(60))
                // Disable Nagle's algorithm on the EGRESS sockets. Busbar writes a whole request body in
                // one shot and then immediately awaits the response, so Nagle has nothing to coalesce —
                // but on a small body it interacts with the peer's delayed-ACK to hold the final segment
                // for up to ~40 ms waiting for an ACK that only arrives once the peer's timer fires. That
                // manifests as a bimodal tail-latency spike (a native SDK, which also sets TCP_NODELAY,
                // never sees it) and is pure added latency on the request path. Inbound accepted sockets
                // already set this (tls.rs serve loops); this brings the egress leg to parity. `axum`'s
                // own serve() defaults nodelay on; reqwest does NOT, so it must be set explicitly.
                .tcp_nodelay(true)
                // HTTP/2 to the upstream, NEGOTIATED via ALPN (NOT prior-knowledge): over TLS the client
                // offers `h2,http/1.1` and uses whichever the backend accepts, so an h2-capable provider
                // (Anthropic, OpenAI, Vertex, Bedrock all speak h2) multiplexes many concurrent requests
                // over ONE connection — collapsing the per-request connect+TLS handshake and the socket /
                // epoll pressure that caps proxy RPS on a core-bound box — while an HTTP/1-only backend
                // transparently stays on h1. By DEFAULT we do NOT call `.http2_prior_knowledge()` (that
                // would FORCE h2 and break every h1 upstream and a plaintext h1 mock) — it is applied only
                // when the cleartext-h2c opt-in below is set. H2 keep-alive pings keep a multiplexed
                // connection healthy through idle gaps without the h1 trick of holding N sockets open. No
                // behavior change against an h1-only upstream on the default (ALPN) path.
                .http2_keep_alive_interval(Duration::from_secs(30))
                .http2_keep_alive_timeout(Duration::from_secs(10))
                .http2_adaptive_window(true)
                .pool_max_idle_per_host(idle_per_host_per_shard)
                // Idle keep-alive lifetime — EXPLICIT 300s default, replacing reqwest's implicit 90s:
                // the warm working set (amortized TCP+TLS handshakes / h2 sessions) survives
                // inter-burst gaps of a few minutes instead of being reaped and re-paid as cold
                // handshakes when the next burst lands. Safe at 300s because `tcp_keepalive(60s)`
                // above actively validates idle sockets (a silently-dropped connection is caught by
                // the probe, not by a failed request), and bounded by `pool_max_idle_per_host` + OS
                // reclamation. Operator-tunable via `limits.pool_idle_timeout_secs`.
                .pool_idle_timeout(Duration::from_secs(cfg.limits.pool_idle_timeout_secs))
                // SSRF guard: do NOT follow redirects. The startup SSRF blocklist (config_validate.rs
                // ssrf_blocked_host) only vets the configured base_url; it does not see redirect targets.
                // reqwest's default policy follows up to 10 redirects, so a compromised/malicious upstream
                // could 30x-redirect a vetted base_url to an internal address (169.254.169.254 metadata,
                // localhost, RFC1918) and busbar would follow it — forwarding the signed request
                // (x-api-key / SigV4 Authorization on same-host redirects) to the internal target,
                // defeating the blocklist at runtime. Upstream AI provider APIs do not redirect as part of
                // normal operation, so disabling redirect following entirely closes the vector at no cost.
                .redirect(reqwest::redirect::Policy::none());
            // Cleartext h2c opt-in (bench / in-mesh): FORCE h2 without ALPN. Default-off; when set, every
            // upstream must speak h2c. Applied last so it overrides the ALPN default above.
            if h2_prior_knowledge {
                builder = builder.http2_prior_knowledge();
            }
            // HTTP/1-only escape hatch: pin the client to h1 (no ALPN h2 offer). Applied last so it
            // wins over both the ALPN default and the h2c opt-in above.
            if http1_only {
                builder = builder.http1_only();
            }
            builder.build().expect("build upstream HTTP client")
        };
        crate::state::UpstreamClients::build(shard_count, make_one)
    };

    // The `default:` hook (if any) — the base ordering that pools which named none inherit, replacing
    // the compiled-in weighted backstop (everything-is-a-hook model). At most one (validated).
    let default_hook = hooks::default_hook_name(&cfg.hooks).map(str::to_string);
    // The hook plugin-resolution environment: the validated registry + shared projectors. Every hook
    // `plugin:` ref opens a `DlopenPolicy` through this. Built once and cloned into each resolver and
    // onto `App` (for the control-plane reads + scrape).
    let hook_env = hooks::HookEnv::new(plugin_registry.clone(), secret_resolver.clone());

    // FAIL-CLOSED: resolve every hook's SecretRef settings ONCE, up front, so an unresolvable
    // hook secret aborts boot/reload here — matching the store path (above) and the auth chain
    // (`AuthMiddleware::new`). Without this, a gate whose SecretRef fails to resolve would be
    // silently dropped from the routing chain by `resolve_pool_gates`/`resolve_on_error_chain`
    // (fail-OPEN), letting traffic the gate was configured to restrict/reject flow unfiltered.
    hook_env.preresolve_hook_secrets(&cfg.hooks)?;

    // The store's SecretRefs are resolved only on the BOOT arm (`prior == None`), because the store
    // backend is reused across a hot reload. So a `PUT /config/settings` naming an unresolvable ref
    // returned 200, persisted it, and the NEXT restart died in `resolve_settings` before serving.
    //
    // WARN, never fail: the store is restart-to-apply, so staging a ref whose secret the
    // orchestrator mounts on the next deploy is a legitimate workflow — and `tls` already accepts
    // exactly that. Rejecting here would make the store stricter than the block beside it.
    if let Some(store_cfg) = cfg.store.as_ref() {
        if let Err(e) = config::secret::resolve_settings(&store_cfg.settings, &secret_resolver) {
            tracing::warn!(
                store = %store_cfg.module,
                error = %e,
                "store settings hold a secret reference that does not resolve here; the store is \
                 restart-to-apply, so THIS WILL FAIL THE NEXT RESTART unless the secret exists then"
            );
        }
    }

    // FAIL-CLOSED (open-time variant): actually OPEN every referenced decision/rewrite gate up
    // front so an `open()`-time failure of a PRESENT plugin aborts boot/reload here — matching the
    // store (`open_store`) and auth (`AuthMiddleware::new`) paths. Without this, a gate whose plugin
    // fails to `open()` (constructor rejecting cfg_json, staging/mmap failure, ABI/kind mismatch
    // observable only on load) is silently `filter_map`-dropped by the resolvers below (fail-OPEN),
    // letting traffic a Reject/restrict/rewrite gate was configured to filter flow unfiltered while
    // boot reports success. A GENUINELY-ABSENT plugin stays the legitimate fail-open skip.
    // `plugins_preflight` is manifest-only (no dlopen) and `preresolve_hook_secrets` only resolves
    // SecretRefs, so neither catches an `open()` failure — this pass does.
    hook_env.preopen_gate_hooks(&cfg.hooks)?;

    // Per-pool runtime config (failover/exclusions), keyed by pool name.
    let mut pool_runtime = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        pool_runtime.insert(
            pool_name.clone(),
            state::PoolRuntime {
                failover: pool_cfg.failover.clone(),
                // 1.5.3: the pool's own `upstream_credentials:` OVERRIDES the all-pools
                // `pools.upstream_credentials:` default; `None` inherits it.
                upstream_credentials: pool_cfg.upstream_credentials,
                affinity: pool_cfg.affinity.clone(),
                breaker: pool_cfg.breaker.as_ref().map(store::BreakerCfg::from),
                // Operator-declared member metadata (tier/cost/tags) keyed by lane idx, for the
                // routing Candidate projection. Mirrors the WeightedLane construction's target→lane
                // mapping (by_model). Read only inside the policy arm of the seam.
                members: pool_cfg
                    .members
                    .iter()
                    .filter_map(|m| {
                        by_model.get(&m.model).map(|&idx| {
                            (
                                idx,
                                state::MemberMeta {
                                    tier: m.tier.clone(),
                                    // The routing cost scalar derives from the member's
                                    // MODEL's rate_card entry - cost lives on no pool member.
                                    cost_per_mtok: cfg
                                        .rate_card
                                        .as_ref()
                                        .and_then(|card| card.get(&m.model))
                                        .map(crate::config::rate_entry_per_mtok),
                                    tags: m.tags.clone(),
                                },
                            )
                        })
                    })
                    .collect(),
                // Resolve the routing policy ONCE here. `weighted` (default) ⇒ `None` ⇒ the zero-cost
                // inline SWRR path; a `default:` hook replaces that base for pools that named none; a
                // `kind: hook` plugin base opens a `DlopenPolicy` through the plugin registry.
                policy: hooks::resolve_pool_ordering(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    default_hook.as_deref(),
                    app_config_version,
                ),
                // This pool's decision gates, resolved once here (priority carried for the phase-2
                // chain merge). NOT re-resolved on config apply yet — same scope caveat as `policy`.
                gates: hooks::resolve_pool_gates(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    app_config_version,
                ),
                rewrite_hooks: hooks::resolve_pool_rewrites(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    app_config_version,
                ),
            },
        );
    }

    // Parse on_exhausted configs per pool
    let mut on_exhausted_cfgs = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(ref on_exc) = pool_cfg.on_exhausted {
            // The structured config value maps directly (unknown spellings already failed parse).
            let mode = on_exc.to_runtime();
            tracing::info!(pool = %pool_name, on_exhausted = ?mode, "pool exhaustion policy");
            on_exhausted_cfgs.insert(pool_name.clone(), mode);
        } else {
            // Default to Status503 if not specified
            on_exhausted_cfgs.insert(pool_name.clone(), crate::config::OnExhausted::Status503);
        }
    }

    // PLUGIN PRE-FLIGHT: the same fail-closed pipeline `--validate` runs (consistency -> policy ->
    // three-phase scan -> store resolution). Runs on EVERY construction path (boot, apply, reload),
    // so a bad plugin state can never produce a partial App. When plugins are disabled and nothing
    // references one, this is a no-op empty registry.
    // open the governance store + load the virtual-key cache when enabled.
    // Credentials RE-RESOLVED on this apply/reload; the rotation closure is handed back to the
    // caller (see `Ok((app, rotate_gov_credentials))` below) rather than applied here. Resolution
    // itself happens HERE and is FAIL-CLOSED: an `auth.admin_auth` token ref or an `auth.signing_key`
    // that no longer resolves aborts the apply rather than silently leaving the old credential live.
    let mut rotate_gov_credentials: Option<GovCredentialRotation> = None;
    let governance = if let Some(p) = prior {
        // REUSED across applies: the keys + spend/rate state must survive config changes. But the
        // CREDENTIALS on it are config, not state: `GovState` used to freeze the admin-token digest
        // and the signing key at construction, so rotating either SecretRef and reloading had no
        // effect whatsoever — the process kept accepting the boot-time credential for its entire
        // life. Re-resolve both refs against the fresh resolver and swap them
        // into the reused instance.
        //
        // SCOPE: a credential is re-resolved exactly when THIS config DECLARES it — an
        // `admin-tokens` entry in `auth.admin_auth`/`auth.chain` for the admin token, an explicit
        // `auth.signing_key` for the signing key. A config that declares neither is not asserting
        // "no credential"; it simply does not own that credential (the dev signing key is
        // generate-and-persist at BOOT, and re-running that on every reload would churn key
        // material), so the live one stands. REMOVING a declaration therefore still needs a restart
        // — documented, and the narrow case; ROTATING one, the operational path that matters and
        // the one that silently did nothing, now works.
        if let Some(gs) = p.governance.clone() {
            let auth = cfg.auth.as_ref();
            let declares_admin_tokens = auth.is_some_and(|a| {
                a.admin_auth
                    .iter()
                    .chain(a.chain.iter())
                    .any(|e| e.module == crate::config::ADMIN_TOKENS_MODULE)
            });
            // FAIL-CLOSED: a declared ref that no longer resolves ABORTS the apply. The alternative
            // — carry on serving with the old credential — is exactly the defect being fixed.
            let admin_token: Option<Option<busbar_api::Redacted<String>>> = if declares_admin_tokens
            {
                // Declared with no token ref resolves to `None`: the admin API is credential-less
                // BY CONFIGURATION, so fail closed and disable it rather than keep the old secret.
                Some(
                    resolve_admin_token(auth, &secret_resolver)
                        .map_err(|e| format!("{e} (nothing was changed)"))?,
                )
            } else {
                None
            };
            let signer = match auth.and_then(|a| a.signing_key.as_ref()) {
                Some(_) => Some(resolve_signing_key(auth, &secret_resolver)?),
                None => None,
            };
            if admin_token.is_some() || signer.is_some() {
                rotate_gov_credentials = Some(Box::new(move || {
                    if let Some(token) = admin_token {
                        gs.set_admin_token(token.as_ref().map(|r| r.expose_secret().as_str()));
                    }
                    if let Some(signer) = signer {
                        gs.set_signing_key(signer);
                    }
                }));
            }
        }
        p.governance.clone()
    } else {
        // Governance is ALWAYS available (it is inert until an admin token is set and virtual keys are
        // minted). Only the STORE backend is a choice: ephemeral RAM by default, or a store PLUGIN
        // (resolved by alias or canonical name from the validated registry — the engine sees only the
        // returned `dyn Store`, exactly like a compiled-in backend).
        let g = cfg.store.clone().unwrap_or_default();
        let store: Arc<dyn governance::Store> =
            if g.module == crate::config::GOVERNANCE_STORE_MEMORY {
                tracing::warn!(
                    "store: in-memory (ephemeral) - keys, groups' usage, and ledgers reset on \
                     restart; configure a durable store plugin for persistence"
                );
                Arc::new(governance::MemoryStore::new())
            } else {
                // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) against the secret
                // store BEFORE the settings cross the ABI (ADR-0010). FAIL-CLOSED: an unresolvable
                // ref refuses the store load rather than handing the plugin a dangling reference.
                let resolved = config::secret::resolve_settings(&g.settings, &secret_resolver)
                    .map_err(|e| format!("store '{}' settings: {e}", g.module))?;
                let cfg_json = serde_json::Value::Object(resolved).to_string();
                match plugin_registry.open_store(&g.module, &cfg_json) {
                    Ok(s) => Arc::from(s),
                    Err(e) => return Err(format!("store '{}' plugin load failed: {e}", g.module)),
                }
            };
        // The operator ADMIN credential: the `admin-tokens` chain entry's `token:` secret ref.
        // FAIL-CLOSED: a configured-but-unresolvable admin token refuses boot (a silently-absent
        // token would lock the admin API while the operator believes it is guarded).
        let admin_token: Option<busbar_api::Redacted<String>> =
            resolve_admin_token(cfg.auth.as_ref(), &secret_resolver)?;
        // The KEY-SIGNING key: resolve `auth.signing_key` (a secret ref) to 32 ed25519 secret
        // bytes. ABSENT => no signer (1.5.1: busbar no longer auto-generates one; config_validate
        // has already failed closed if the `keys` verifier is in the chain). Fleet deployments
        // provide it (shared) so every node verifies the same tokens.
        let signer = resolve_signing_key(cfg.auth.as_ref(), &secret_resolver)?;
        match governance::GovState::new_with_signer(
            store,
            admin_token.as_ref().map(|r| r.expose_secret().clone()),
            signer,
        ) {
            Ok(gs) => {
                let gs = Arc::new(gs);
                // BOOT-ONLY crash-recovery: hydrate the in-memory token-ledger cells (key buckets +
                // budget-group buckets) from the durable store so a restart resumes enforcement from
                // the persisted ledger. A no-op for the empty RAM store.
                // Fail-open: a store error here is FATAL - resuming with empty (reset) budget
                // cells would let a maxed-out key spend its whole cap again. Fail boot loudly.
                if let Err(e) = gs.hydrate_budgets(&cost, crate::store::now()) {
                    return Err(format!(
                        "governance boot: budget hydration failed ({e}); refusing to start with an \
                         unenforced (reset) ledger. Fix the durable store and restart."
                    ));
                }
                // BOOT FAIL-CLOSED: every stored key naming a budget_group must resolve in THIS
                // config (mint validates it; a shared durable store can carry keys minted under a
                // config another node no longer has). A dangling reference is a boot error naming
                // the offender with the paste-ready fix.
                // A store error reading the keys here must NOT be swallowed (the old `if let
                // Ok(keys)` skipped the whole dangling-reference check on error, so a boot-time store
                // blip published a config whose keys were never validated). Propagate it - fail boot.
                let keys = gs.all_keys().map_err(|e| {
                    format!(
                        "governance boot: could not read stored keys to validate budget_group \
                         references ({e}); refusing to start unvalidated. Fix the durable store and \
                         restart."
                    )
                })?;
                for k in &keys {
                    if let Some(group) = k.group.as_deref() {
                        if cost.group_named(group).is_none() {
                            return Err(format!(
                                "virtual key '{}' names group '{group}', which does not exist in the top-level groups block.\n\
                                 Paste this under groups and set real limits:\n\n    {group}:\n      limits:\n        - {{ budget: 0, per: month }}\n",
                                k.id
                            ));
                        }
                    }
                }
                // INERT-KEYS GUARD: a durable store may carry virtual keys minted in a prior run
                // whose data-plane chain no longer names the `keys` verifier — no request then
                // resolves them and their per-key controls are silently bypassed. Surface it LOUD:
                // ERROR level (survives RUST_LOG=error) AND unconditionally on stderr, mirroring the
                // open-relay banner so log config can't mask it. RAM stores can't reach this state,
                // so `key_count` there is 0 (or the store is non-durable) and the banner is None.
                // `all_keys()` failure is non-fatal — treat as 0 keys (the enforcement gate is
                // unaffected; we only lose the advisory). Inertness is now recomputed from CHAIN
                // SHAPE (is `keys` in the running chain?), not the admin token.
                let store_is_durable = g.module != crate::config::GOVERNANCE_STORE_MEMORY;
                let key_count = gs.all_keys().map(|k| k.len()).unwrap_or(0);
                let keys_in_chain = auth_mw.keys_in_chain;
                if let Some(banner) =
                    inert_durable_keys_banner(store_is_durable, key_count, keys_in_chain)
                {
                    eprintln!("[error] {banner}");
                    tracing::error!("{banner}");
                }
                Some(gs)
            }
            Err(e) => return Err(format!("governance init failed: {e}")),
        }
    };

    // Resolve the global rewrite hooks (prompt: rw gates in global_hooks) into priority-ordered
    // transports ONCE. Empty unless the operator configured a rewrite hook — zero cost by default.
    let rewrite_hooks =
        hooks::resolve_rewrite_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);
    // Resolve the global request-stage tap hooks the same way. Empty unless configured.
    let tap_hooks = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Request,
    );
    let tap_hooks_candidate = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Candidate,
    );
    let tap_hooks_routing = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Routing,
    );
    let tap_hooks_response = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Response,
    );
    // Resolve the global DECISION gates (non-rewrite gates in global_hooks) — fired for a verdict on
    // every request. Empty unless configured.
    let global_gates =
        hooks::resolve_gate_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);

    // THE OTHER TWO PLANES' GATES, resolved by the SAME function, from the SAME registry, on the
    // same generation — which is the point. `tools.hooks:` / `agents.hooks:` and the per-entry
    // lists have parsed and validated since 1.5.3 and fired nothing, because nothing resolved them
    // and nothing called them. These two lines and their two firing sites are the whole of what was
    // missing; the grammar, the validation and the cross-plane refusal were already there.
    //
    // Empty on every deployment that attaches nothing, which is every deployment that does not
    // spell the key — so the dispatch paths' lookups cost one hash probe against an empty map.
    let mcp_server_gates = hooks::resolve_container_gates(
        cfg.tool_defs
            .servers
            .iter()
            .map(|(name, def)| (name.as_str(), def.hooks.as_slice())),
        &cfg.tool_defs.all_server_hooks,
        &cfg.hooks,
        &hook_env,
        app_config_version,
    );
    let a2a_agent_gates = hooks::resolve_container_gates(
        cfg.agent_defs
            .agents
            .iter()
            .map(|(name, def)| (name.as_str(), def.hooks.as_slice())),
        &cfg.agent_defs.all_agent_hooks,
        &cfg.hooks,
        &hook_env,
        app_config_version,
    );

    // EVERY fallible step of THIS build has now succeeded, so `rotate_gov_credentials` (if any) is
    // ready to run. It is NOT invoked here, though: `GovState` is a process-lifetime `Arc` shared
    // with the OLD `App` that is still serving, so invoking it now would mutate the live engine's
    // credentials even though the candidate `App` returned below is only a CANDIDATE — the admin
    // transaction wrapping this call (`txn.rs`) still has a fallible PERSIST step to run, and on a
    // persist failure the transaction discards this candidate and swaps nothing. Firing the
    // rotation here would leave the "nothing was changed" response a lie: the shared `GovState`
    // would already carry the new credential while the old (rejected) `App` keeps serving. The
    // caller is responsible for invoking the returned closure — after its own persist step (if any)
    // has succeeded, never before.

    // The probe schedule is live state, not config-derived: it carries each lane's next-probe deadline
    // and the prober generation. `App::clone` shares it (Arc), so an in-place mutation swap keeps the
    // phase; a REBUILD must do the same, or a mutation cadence faster than the probe interval —
    // /config/settings meters at 10/min, the default interval is 30s — replaces every generation before
    // its first tick and probing goes dark while still logging that it is enabled. Carried ONLY when the
    // lane set is identical, because deadlines are indexed by lane: a changed lane set makes the old
    // indices mean something else, and a genuine lane change SHOULD re-establish probing.
    //
    // zip ≡ set-equality HERE, not in general: `cfg.models` is a `HashMap<String, ModelCfg>`, so model
    // names are UNIQUE keys, and both lane vectors are built by sorting those keys before reaching this
    // point. Two vectors built from the same unique-key set via the same deterministic sort are
    // identical element-for-element, so an elementwise compare and a set compare accept exactly the
    // same configs. Do NOT reuse this shortcut for a lane source that is not sorted-from-a-unique-key-
    // set: there the zip would start accepting a shifted-index pairing.
    let probe_schedule = match prior {
        Some(p)
            if p.lanes.len() == lanes.len()
                && p.lanes
                    .iter()
                    .zip(lanes.iter())
                    .all(|(a, b)| a.model == b.model && a.provider == b.provider) =>
        {
            p.probe_schedule.clone()
        }
        _ => Arc::new(crate::health::ProbeSchedule::new(lanes.len())),
    };

    // Plugin HTTP routes: the BUILT-IN exporters (`crate::export`) declare their routes
    // into the snapshot — today the `prometheus` exporter's `GET /metrics` when `export.prometheus` is
    // configured. Rebuilt on every config apply. A collision (a future loaded export/hook plugin
    // claiming a built-in's path) is a LOUD build failure naming the owner, never last-writer-wins.
    //
    // The rebuilt TABLE is not the same thing as what the ROUTER serves: each path is registered on
    // the router once, at boot, and an apply swaps only `Arc<App>`. So REMOVING `export.prometheus`
    // takes effect immediately (`plugin_route_dispatch` resolves the owner from the current snapshot
    // and 404s), while ADDING it needs a RESTART. `boot_route_paths` below is what remembers which
    // paths the router actually has, so a config mutation can SAY so instead of
    // reporting success for a route that will keep 404ing.
    let plugin_routes = std::sync::Arc::new(crate::plugin_routes::build_route_table(
        crate::export::route_decls(&cfg_export),
    )?);
    // Seeded ONCE, on a fresh boot (`prior == None`) from the table that is about to be mounted;
    // every rebuild inherits the boot value unchanged. Deliberately NOT recomputed per rebuild — a
    // recomputed set would say every newly declared path is already mounted, which is the exact
    // silent no-op this exists to report.
    let boot_route_paths = prior.map_or_else(
        || std::sync::Arc::new(plugin_routes.paths()),
        |p| p.boot_route_paths.clone(),
    );

    // THE A2A PLANE, lowered ONCE and read twice below: as the registry the re-verification job
    // sweeps, and as the source of the dispatch table's A2A admission facts. Lowering it twice would
    // let the mounted surface and the registry behind it come from two different readings of one
    // config generation.
    let a2a_plane =
        crate::a2a::plane::A2aPlane::from_config(&cfg.agent_defs, cfg.public_url.as_deref());

    // THE AUTHORIZATION SERVER, built ONCE, and only when the operator asked for one. Everything
    // this plane costs hangs off this `Option`: absent, nothing below runs, `App::oauth_as` is
    // `None`, `oauth_as::routes::mount` returns the router untouched, and no sweeper exists.
    //
    // The RFC 8707 `allowed_resources` list is busbar's OWN protected resources and nothing else.
    // Left unset, `oauth-as` would mint a token carrying whatever `resource` a client asked for in
    // its `aud`, which any resource server verifying against our JWKS would then honour — so the
    // list is derived here, from the planes this deployment actually serves, rather than configured
    // separately where it could disagree with them.
    let oauth_as_plane = match cfg.oauth_as.as_ref() {
        None => None,
        Some(identity) => {
            let key_material = match identity.signing_key() {
                None => {
                    tracing::warn!(
                        "oauth_as: no signing_key configured, so an EPHEMERAL ES256 key was \
                         generated. Every token this deployment issues stops verifying when the \
                         process restarts. Set `oauth_as.signing_key` for anything but a trial."
                    );
                    None
                }
                Some(reference) => Some(
                    secret_resolver
                        .resolve_string(reference)
                        .map_err(|e| format!("oauth_as.signing_key: {e}"))?,
                ),
            };
            let protected_resources: Vec<String> = cfg
                .mcp
                .as_ref()
                .map(|r| r.canonical_uri().to_string())
                .into_iter()
                .collect();
            let plane = crate::oauth_as::plane::AsPlane::build(
                identity.clone(),
                key_material.as_deref(),
                protected_resources,
            )
            .map_err(|e| e.to_string())?;
            let plane = Arc::new(plane);
            // `Storage::sweep_expired` is the only thing that reclaims anything in `oauth-as`, and
            // it runs when it is called and never otherwise. Spawned here, once per generation.
            crate::oauth_as::plane::spawn_sweeper(
                Arc::clone(plane.server()),
                std::time::Duration::from_secs(60),
            );
            Some(plane)
        }
    };

    // The generation's hook CONTENT ceiling, installed once here and read on the hook seam with a
    // single relaxed load — never recomputed per request, and never consulted at all on a
    // deployment with no content-granted hook, because no content projection is built there.
    crate::proxy::set_hook_content_max_bytes(cfg.limits.hook_content_max_bytes);

    let app = App {
        // The all-pools `upstream_credentials:` default (1.5.3 — moved off `auth:`).
        upstream_credentials: cfg.upstream_credentials,
        // Telemetry-bank slot table for this generation, registered BEFORE the config-derived
        // collections move into the snapshot. Identical label sets across applies re-intern to the
        // same slots, so hot-path counters accumulate monotonically across config generations.
        tslots: Arc::new(telemetry::AppSlots::build(
            &lanes,
            &pools,
            &by_model,
            crate::plane::Plane::Llm,
        )),
        probe_schedule,
        lanes,
        store,
        by_model,
        pools,
        client: upstream_client.clone(),
        auth: auth_mw.clone(),
        rewrite_hooks,
        tap_hooks,
        tap_hooks_candidate,
        tap_hooks_routing,
        tap_hooks_response,
        global_gates,
        mcp_server_gates,
        a2a_agent_gates,
        hook_env: hook_env.clone(),
        hook_registry: cfg.hooks.clone(),
        requested_signals: hooks::requested_signals(&cfg.hooks),
        any_content_hook: hooks::any_content_hook(&cfg.hooks),
        export_projections: cfg.export.projection_union(),
        global_hooks: cfg.global_hooks.clone(),
        groups_registry: cfg.groups.clone(),
        base_group_names,
        // The two NAMED-DEFINITION maps the generic admin CRUD serves, carried verbatim off the
        // resolved config (the EFFECTIVE base+overlay shape).
        identity_providers: cfg.identity_providers.clone(),
        export_defs: cfg.export_defs.clone(),
        agent_defs: cfg.agent_defs.clone(),
        // THE A2A PLANE, built only when `agents:` defines one. A deployment that fronts no agents
        // gets `None` here and nothing downstream: no registry, no re-verification job. Built from
        // THIS generation's config on every apply, deliberately — a registration an operator
        // removed must stop being re-verified, and one whose pin they changed must be judged
        // against the pin they now declare.
        a2a: a2a_plane.clone(),
        // History + rate windows are Arc-shared across applies (process-lifetime state).
        versions: prior.map_or_else(
            || Arc::new(admin::versions::VersionLog::new()),
            |p| p.versions.clone(),
        ),
        mutation_limiter: prior.map_or_else(
            || Arc::new(admin::rate::MutationLimiter::new()),
            |p| p.mutation_limiter.clone(),
        ),
        idempotency_cache: prior.map_or_else(
            || Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            |p| p.idempotency_cache.clone(),
        ),
        base_hook_names,
        admin_chain: cfg.admin_auth.clone(),
        admin_modules,
        login_methods,
        public_url: cfg.public_url.clone(),
        // The MCP plane, and the dispatch table that governs it, are built from ONE validated
        // object in ONE act: the resource that mounts the ingress is the same resource whose
        // canonical URI becomes the audience the middleware enforces there. Absent `mcp:`, the
        // dispatch table is empty and `admission_for` answers `None` for every path, so the
        // audience check costs one `Option` test on the hot path and changes nothing.
        //
        // THE SECOND CONSUMER. A2A mounts and admits through the very same two verbs, with its own
        // strings and no new code in `plane/` — which is the claim that module's own doc made when
        // it was written for a consumer that did not exist yet. A2A admits only when it has a
        // RECEIVING side (`A2aPlane::admission` answers `None` without a `public_url`), so a
        // delegation-only deployment claims no path and binds no audience.
        planes: Arc::new({
            let mut dispatch = crate::plane::PlaneDispatch::default();
            if let Some(r) = cfg.mcp.as_ref() {
                dispatch = dispatch
                    .mount(
                        crate::plane::Plane::Mcp,
                        r.mount_path(),
                        crate::plane::WIRE_JSONRPC,
                    )
                    .admit(crate::plane::Plane::Mcp, r.admission());
            }
            if let Some(admission) = a2a_plane.as_ref().and_then(|p| p.admission()) {
                dispatch = dispatch
                    .mount(
                        crate::plane::Plane::A2a,
                        crate::a2a::serve::MOUNT_PATH,
                        crate::plane::WIRE_JSONRPC,
                    )
                    // THE SECOND BINDING'S PATH, claimed by the same act and for the same reason.
                    // gRPC is served at the path the vendored `a2a.proto` dictates rather than under
                    // the plane's mount, and a claimed path is where `admission_for` finds the RFC
                    // 8707 audience — so leaving it out would not merely mislabel the leg, it would
                    // admit a token minted for some other resource on it.
                    .mount(
                        crate::plane::Plane::A2a,
                        crate::a2a::serve::GRPC_MOUNT_PATH,
                        crate::plane::WIRE_GRPC,
                    )
                    .admit(crate::plane::Plane::A2a, admission);
            }
            dispatch
        }),
        mcp: cfg.mcp.clone().map(Arc::new),
        oauth_as: oauth_as_plane.clone(),
        // THE CATALOGUE SNAPSHOT, built here and only here. It takes the next PIN GENERATION on
        // construction, so every config apply — including one that changes nothing about `tools:` —
        // moves the generation and a call admitted under the previous one is refused at dispatch —
        // an in-flight call cannot outlive the approval it was admitted under, which is the whole
        // point of taking the generation here rather than reading config at dispatch time.
        // Building it beside the `App` is what makes the swap atomic: the
        // whole `Arc<App>` is replaced under one lock, so there is no window in which the catalogue
        // and the config that produced it disagree.
        mcp_catalogue: Arc::new(crate::mcp::catalogue::Catalogue::build(&cfg.tool_defs)),
        mcp_servers: Arc::new(cfg.tool_defs.clone()),
        mcp_pool: Arc::new(crate::mcp::client::pool::McpConnectionPool::new()),
        // CARRIED ACROSS THE APPLY. A sighting is what accumulated, not what the operator intended,
        // so a config apply must not erase it: dropping the observations here would clear a
        // quarantine as a side effect of an unrelated edit.
        mcp_sightings: prior.map_or_else(
            || Arc::new(crate::mcp::client::catalogue::CatalogueCache::new()),
            |p| p.mcp_sightings.clone(),
        ),
        // CARRIED ACROSS THE APPLY for the same reason, and it is the same class of mistake: an
        // approval already spent is evidence, not intent, and a config apply that forgot it would
        // hand every outstanding confirmation back to whoever still holds it.
        mcp_spent_approvals: prior.map_or_else(
            || Arc::new(crate::mcp::askstate::SpentAskStates::new()),
            |p| p.mcp_spent_approvals.clone(),
        ),
        // CARRIED ACROSS THE APPLY, same class again: an epoch bump is a caller's own announcement
        // that its roots changed, and an apply that reset it would re-validate roots answers the
        // caller disavowed — inside the very TTL window the seal exists to police.
        mcp_roots_epochs: prior.map_or_else(
            || Arc::new(crate::mcp::roots::RootsEpochs::new()),
            |p| p.mcp_roots_epochs.clone(),
        ),
        // CARRIED ACROSS THE APPLY, and here the reason is sharper than for the two above: the
        // durable sink is attached to this instance once at boot, so rebuilding it on an apply would
        // silently detach it and every later quarantine would stop being written down.
        mcp_demotions: prior.map_or_else(
            || Arc::new(crate::mcp::demotion::DurableDemotions::new()),
            |p| p.mcp_demotions.clone(),
        ),
        credential_cache: prior.map_or_else(
            || Arc::new(auth_cache::CredentialCache::new()),
            |p| p.credential_cache.clone(),
        ),
        auth_scope_caps: cfg
            .auth
            .as_ref()
            .map(project_auth_scope_caps)
            .unwrap_or_default(),
        role_bindings: cfg
            .auth
            .as_ref()
            .map(|a| a.role_bindings.clone())
            .unwrap_or_default(),
        config_path: config_paths.0,
        providers_path: config_paths.1,
        overlay_path,
        config_version: app_config_version,
        max_keys_per_principal: cfg.limits.max_keys_per_principal,
        max_auto_provisioned_groups: cfg.limits.max_auto_provisioned_groups,
        failover_cfg,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        queued_depth: std::sync::Arc::new(crate::state::QueuedDepth::default()),
        governance,
        secret_resolver,
        cost,
        plugins_dir: std::path::PathBuf::from(&plugins_cfg.dir),
        plugins_cfg,
        default_max_tokens: cfg.limits.default_max_tokens,
        reasoning_effort_budgets: {
            let b = cfg.limits.reasoning_effort_budgets;
            [b.minimal, b.low, b.medium, b.high]
        },
        // Where `auth.key_ttl` is finally READ: the self-serve mint's token lifetime.
        // Config-validate already proved this parses; the fallback keeps a bad value from panicking.
        self_key_ttl_secs: cfg
            .auth
            .as_ref()
            .and_then(|a| a.key_ttl.as_deref())
            .map(|s| admin::parse_duration_secs(s).unwrap_or(admin::DEFAULT_KEY_TTL_SECS))
            .unwrap_or(admin::DEFAULT_KEY_TTL_SECS),
        // Arc-shared like `versions`/`mutation_limiter`: a REBUILD carries the SAME counter forward
        // (ids stay monotonic across a config reload) while a fresh boot seeds it once from OS
        // entropy (see `state::seed_request_id_counter`) so restarts don't restamp `0, 1, 2, …`.
        request_id_counter: prior.map_or_else(
            || {
                Arc::new(std::sync::atomic::AtomicU64::new(
                    state::seed_request_id_counter(),
                ))
            },
            |p| p.request_id_counter.clone(),
        ),
        plugin_routes,
        boot_route_paths,
    };
    // The build reached its end without a single fallible step refusing: KEEP the limits installed
    // at the top. Every earlier `return Err` / `?` drops the guard instead and rolls them back.
    limits_guard.commit();
    Ok((app, rotate_gov_credentials))
}


/// Build the busbar HTTP router for a given `App` state with default limits. Factored out so the
/// full route table + auth middleware can be exercised end-to-end in tests; production (`main`) calls
/// `build_router_with_limits` with the operator-configured values, so this convenience wrapper is
/// reached only from the test harness.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_router(app: std::sync::Arc<state::App>) -> Router {
    // Convenience builder for tests / callers without an explicit limits handle: the historical 32
    // MiB body cap (via the installed `limits`, falling back to the default when uninstalled) and NO
    // inbound-concurrency layer (`0` = unlimited) — byte-for-byte today's behavior. Production goes
    // through `build_router_with_limits` with the operator-configured values.
    build_router_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0
}


/// Router builder with EXPLICIT limits, building the COMBINED router (admin mounted on the data
/// routes). Used only by the test harness (`build_router`) to exercise the full route table + auth
/// middleware end-to-end on one router; production always serves admin on its OWN listener via
/// `build_split_routers_with_limits`, so admin and data never share a listener at runtime.
/// `max_inbound_concurrent == 0` ⇒ NO concurrency layer (a true no-op); `> 0` wraps the whole router
/// in a `limits::admission::InboundAdmissionLayer` as the OUTERMOST layer.
#[cfg_attr(not(test), allow(dead_code))]
fn build_router_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, std::sync::Arc<state::AppHandle>) {
    // Capture the plugin route table before `app` moves into the handle (both planes mount from it).
    let plugin_routes = app.plugin_routes.clone();
    // The MCP resource is captured before `app` moves into the handle, for the same reason the
    // plugin route table is: the mount is decided ONCE, from this generation's config, and a route
    // set is not something a later hot-swap can rewrite.
    let mcp = app.mcp.clone();
    let a2a = app.a2a.clone();
    let oauth_as = app.oauth_as.clone();
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // TEST-ONLY combined router: mount the Admin API v1 onto the DATA route table so one router
    // exercises the whole surface. Production never does this — `build_split_routers_with_limits`
    // mounts admin on its OWN router served on a separate listener. Both planes' plugin routes are
    // mounted here (the combined router IS both listeners).
    let (router, core_routes) = base_data_router(
        &plugin_routes,
        mcp.as_deref(),
        a2a.as_ref(),
        oauth_as.as_ref(),
    );
    let router = admin::transport::mount(router, &admin::JsonV1);
    let router = crate::plugin_routes::mount_plugin_routes(router, &plugin_routes, true);
    let router = apply_common_layers(
        router,
        core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    (
        apply_inbound_concurrency_limit(router, max_inbound_concurrent),
        handle,
    )
}


/// The DATA-plane route table — protocols, discovery, and health/metrics/stats — WITHOUT the admin
/// surface. Pre-state (`Router<Arc<AppHandle>>`); the admin API is mounted separately (onto this
/// router in the single-listener case, or onto its own router in the split case) so it can move to
/// a dedicated listener without any of these routes coming with it.
fn base_data_router(
    plugin_routes: &crate::plugin_routes::PluginRouteTable,
    mcp: Option<&crate::mcp::McpResource>,
    a2a: Option<&std::sync::Arc<crate::a2a::plane::A2aPlane>>,
    oauth_as: Option<&std::sync::Arc<crate::oauth_as::plane::AsPlane>>,
) -> (
    Router<std::sync::Arc<state::AppHandle>>,
    crate::core_routes::CoreRouteTable,
) {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    // EVERY core route is mounted through `CoreRouter::route`, which takes the handler and the
    // admission bar in ONE act (`core_routes`): a route the auth middleware knows nothing about is
    // not a thing this function can produce.
    let router = crate::core_routes::CoreRouter::new()
        .route("/stats", RouteMethod::Get, RouteAuth::Key, endpoints::stats)
        // The liveness probe is the one always-open core route: a probe must not require a caller
        // token. Declared here rather than asserted by the middleware, so the openness belongs to
        // the route and travels with whichever router mounts it.
        .route(
            crate::auth::HEALTHZ_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            endpoints::healthz,
        );
    // METRICS ARE OPT-IN (the built-in `prometheus` EXPORTER, `export.prometheus`). 1.5.3: busbar's
    // OWN `/metrics` exposition is no longer a core route here — it is served by the built-in
    // prometheus exporter through the plugin HTTP endpoint registration (`mount_plugin_routes` below,
    // the well-known `/metrics` exception), resolved at scrape time so a hot-swap never leaves it
    // stale. The HOOK-metrics scrape (`/metrics/hooks`) stays a core route, mounted only
    // when the recorder is installed (`metrics::enabled()`), reserved against plugin claims.
    let router = if metrics::enabled() {
        // A SEPARATE exposition from busbar's own `/metrics` so a hook can never type-conflict or
        // shadow a first-party series. Verbatim hook metric names + an auto `hook="<name>"` label, so
        // an external dashboard built against a hook repoints here and just works.
        // Stale-while-revalidate; never blocks on a hook socket.
        router.route(
            "/metrics/hooks",
            RouteMethod::Get,
            RouteAuth::Key,
            crate::hooks::scrape::handler,
        )
    } else {
        router
    };
    let router = router
        // busbar's OWN API keeps explicit routes (it is not a protocol dialect): discovery,
        // health/metrics/stats above, and the named/adhoc conveniences below.
        // OpenAI list-models: SDKs call `models.list()` first; UIs build pickers from it.
        // Governance-scoped like /stats (restricted keys see only their reachable names).
        // Token exchange (1.5.2): a verified IdP identity mints its own self-serve key. DATA plane
        // only, and declared `RouteAuth::None` because the handler runs the auth chain ITSELF (it
        // needs the identified principal to self-scope the minted key). The declaration is what
        // confines that bypass to this router: the admin plane, which does not mount the route,
        // does not inherit its bypass.
        .route(
            crate::auth::exchange::AUTH_TOKEN_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            crate::auth::token::browser,
        )
        .route(
            crate::auth::exchange::AUTH_TOKEN_PATH,
            RouteMethod::Post,
            RouteAuth::None,
            crate::auth::exchange::exchange,
        )
        .route(
            "/v1/models",
            RouteMethod::Get,
            RouteAuth::Key,
            endpoints::list_models,
        )
        .route(
            "/v1beta/models",
            RouteMethod::Get,
            RouteAuth::Key,
            endpoints::list_models_v1beta,
        )
        .route(
            "/{name}/v1/messages",
            RouteMethod::Post,
            RouteAuth::Key,
            ingress::named,
        )
        .route(
            "/{provider}/{model}/v1/messages",
            RouteMethod::Post,
            RouteAuth::Key,
            ingress::adhoc,
        );
    // THE MCP PLANE, mounted only when `mcp:` is configured. A deployment that is not an MCP server
    // carries none of these routes: no ingress, no metadata document, nothing in the route table and
    // therefore nothing for the auth middleware to consult. That is the same posture the AS design
    // requires of its own routes, and it is what makes "is this deployment an MCP server?" a
    // question the mounted surface answers rather than a config flag someone has to trust.
    //
    // The paths are CONCRETE, derived from the operator's canonical URI at mount time. No prefix
    // matching anywhere: `/.well-known/oauth-protected-resource/mcp` is registered as that exact
    // string, so the auth middleware's exact-match discipline survives a route whose path is not a
    // literal (see `core_routes::CoreRoute::path`).
    let router = match mcp {
        None => router,
        Some(resource) => router
            // RFC 9728 §3: the protected-resource metadata document is READ WITHOUT CREDENTIALS.
            // It must be — every caller who needs it is by definition one that does not have a
            // token yet, so requiring one would be a discovery loop with no entrance. This is the
            // ONE open route on this plane and it says so at the mount, where the openness travels
            // with the route rather than being asserted from a distance.
            .route(
                resource.metadata_path().to_string(),
                RouteMethod::Get,
                RouteAuth::None,
                crate::ingress::protocol::metadata_handler::<crate::mcp::envelope::McpWords>,
            )
            // The endpoint itself. `RouteAuth::Key` sends it through the normal chain, where the
            // plane's admission facts make the verifier require this deployment's canonical URI as
            // the token's audience — the RFC 8707 confused-deputy defence, enforced in the verifier
            // rather than in the handler so a route added here later cannot forget it.
            .route(
                resource.mount_path().to_string(),
                RouteMethod::Post,
                RouteAuth::Key,
                crate::mcp::envelope::rpc,
            )
            // GET and DELETE answer 405: this revision has no GET stream and no sessions. They are
            // `RouteAuth::Key` like the POST, so an anonymous caller gets the 401 challenge and the
            // 405 is only ever shown to an admitted one — a protected resource should not describe
            // its own surface before it knows who is asking.
            .route(
                resource.mount_path().to_string(),
                RouteMethod::Get,
                RouteAuth::Key,
                crate::mcp::envelope::legacy_verb,
            )
            .route(
                resource.mount_path().to_string(),
                RouteMethod::Delete,
                RouteAuth::Key,
                crate::mcp::envelope::legacy_verb,
            ),
    };

    // THE A2A PLANE, mounted on exactly the same terms and by the plane's own module: no `agents:`
    // (or no `public_url`, so no receiving side) means no route in the table at all, which is what
    // keeps "is this deployment an A2A server?" a question the mounted surface answers.
    let router = crate::a2a::receive::mount(router, a2a);
    // THE AUTHORIZATION SERVER'S ROUTES, or none of them. Same posture as the two planes above: a
    // deployment that is not an authorization server carries no `/authorize`, no `/token`, no
    // metadata document and nothing in the route table.
    let router = crate::oauth_as::routes::mount(router, oauth_as);
    // PLUGIN HTTP ROUTES: the collision-checked, namespace-confined `none`/`key`-auth
    // routes an export/hook plugin declared. Reserved HERE — BEFORE the catch-all fallback below —
    // because `ingress::protocol_dispatch` claims every unclaimed path by construction, so a plugin
    // route wired after it would never match. The admin-auth routes are mounted on the admin listener
    // instead (see `build_split_routers_with_limits`), physically absent from this data plane.
    // They carry their OWN declared auth (`plugin_routes::PluginRouteTable`), so they are outside
    // the core table by construction rather than by omission.
    let router =
        router.map_router(|r| crate::plugin_routes::mount_plugin_routes(r, plugin_routes, false));
    router
        .map_router(|r| {
            r
                // EVERY protocol endpoint — chat and the 1.2 operations, all six dialects — flows
                // through the catch-all: Router (dumb protocol ID from path+headers) → that
                // protocol's RequestHandler (reads path+body, decides the operation) → its
                // OperationHandler cell. Adding a protocol or an operation never touches this file.
                // Unknown paths / wrong methods keep the pre-collapse native-envelope 404/405
                // shaping (no bare-proxy tells). A fallback claims no path, so it declares no route:
                // it takes the normal data-plane bar like any unclaimed path always has.
                .fallback(ingress::protocol_dispatch)
                // Wrong-method hits on a VALID path (axum's built-in 405) get the same
                // native-envelope treatment as the 404 fallback above.
                .method_not_allowed_fallback(method_not_allowed_handler)
        })
        .into_parts()
}


/// Apply the shared middleware stack — auth chain, request-body cap, 413 reshaping, server-timing —
/// and bind the swappable `AppHandle` state. Identical for the single-listener router and each
/// split-plane router, so both planes get the SAME auth + limit posture and both see config-apply
/// hot-swaps (they share one `handle`).
fn apply_common_layers(
    router: Router<std::sync::Arc<state::AppHandle>>,
    core_routes: crate::core_routes::CoreRouteTable,
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
) -> Router {
    let router = router
        // The router's state is a swappable `AppHandle` (the config-apply hot-swap seam). Every
        // handler reads the CURRENT snapshot via the `CurrentApp` extractor; the auth middleware
        // loads it too. Until an admin apply calls `swap()`, this is identical to a fixed `Arc<App>`.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            auth::auth_middleware,
        ))
        // THIS ROUTER's core route-auth table, handed to the auth middleware. Applied AFTER the
        // auth layer, which in axum means OUTSIDE it, so the extension is present by the time the
        // middleware extracts it. Per-router (not per-process) on purpose: the data plane and the
        // admin plane mount different core routes, and a route's bypass belongs to the plane that
        // serves it.
        .layer(axum::Extension(std::sync::Arc::new(core_routes)))
        // Cap request body size (buffered before the handler) to bound per-request memory. Driven by
        // `limits.request_body_max_bytes` (default 32 MiB); COUPLED with the egress translate-body cap
        // (`limits::translate_body_max_bytes`) — both read the SAME knob so an accepted request is
        // always buffer-translatable on the cross-protocol path.
        .layer(axum::extract::DefaultBodyLimit::max(request_body_max_bytes))
        // Outermost: reshape the body-limit layer's bare-text 413 into a protocol-native JSON
        // envelope. Must wrap the `DefaultBodyLimit` layer above, so it is applied LAST (the last
        // `.layer()` is the outermost on the response path) and therefore sees that layer's 413.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            reshape_body_limit_413,
        ))
        // THE PLANE INGRESS BOUNDARY. Outside the auth layer, which in axum means it observes the
        // FINAL response — including a 401 the auth chain issued before any handler ran, which on
        // a mounted plane is exactly the failure an operator has no other signal for. It emits for
        // a path a plane CLAIMS BY MOUNT and passes everything else straight through, so the
        // residual plane (every protocol endpoint, `/healthz`, `/metrics`, the admin surface) is
        // untouched and cannot be double-counted against `ingress::finish_inner`.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            crate::plane::observe::observe,
        ));
    // Always installed (cheap: one relaxed atomic add, no allocation) — the jemalloc idle-purge
    // activity ticker must keep incrementing whether or not `server_timing` below is installed.
    let router = router.layer(axum::middleware::from_fn(request_activity_tick));
    // Outermost, and COMPOSED IN ONLY WHEN ENABLED, for speed: an earlier version
    // installed this layer UNCONDITIONALLY and gated only the response header with a runtime `if`
    // inside `server_timing`, so every request paid an `Arc<AtomicU64>` allocation, an
    // `Instant::now()`, and a task-local `.scope()` even with the header suppressed. Gated on
    // `advanced.response_headers.server_timing` (default `false`): when `false` the layer is simply
    // NOT ADDED to the stack — zero per-request cost — mirroring
    // `apply_inbound_concurrency_limit`'s `max_inbound_concurrent > 0` composition gate below. Must
    // stay the LAST `.layer()` when present so it wraps (and times) everything inside it.
    let router = if server_timing_enabled {
        router.layer(axum::middleware::from_fn(server_timing))
    } else {
        router
    };
    router.with_state(handle.clone())
}


/// Build SEPARATE data-plane and admin-plane routers sharing ONE `AppHandle`, for the split-listener
/// deployment (`admin_listen` set). The admin surface is mounted ONLY on the admin router — it is
/// absent from the data router, so the data listener physically cannot serve `/api/v1/admin/*` (no
/// double-exposure: the whole point of splitting is that admin is not reachable on the public bind).
/// Both planes carry the identical middleware stack; the inbound-concurrency cap applies to the DATA
/// plane only (the low-volume admin plane is uncapped, matching today's default). Returns
/// `(data_router, admin_router, shared_handle)`.
pub fn build_split_routers_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    // Capture the plugin route table before `app` moves into the handle.
    let plugin_routes = app.plugin_routes.clone();
    let mcp = app.mcp.clone();
    let a2a = app.a2a.clone();
    let oauth_as = app.oauth_as.clone();
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // DATA plane: protocols + health/metrics/stats + the `none`/`key`-auth plugin routes, NO admin
    // mount and NO admin-auth plugin routes (those are physically absent from the data listener).
    let (data, data_core_routes) = base_data_router(
        &plugin_routes,
        mcp.as_deref(),
        a2a.as_ref(),
        oauth_as.as_ref(),
    );
    let data = apply_common_layers(
        data,
        data_core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    let data = apply_inbound_concurrency_limit(data, max_inbound_concurrent);
    // ADMIN plane: a liveness probe (unauthenticated, like the data plane's) + the admin surface +
    // the `admin`-auth plugin routes (confined to this listener exactly like `/api/v1/admin/*`).
    // `/healthz` bypasses auth so probes work on the admin port too; every `/api/v1/admin/*` route
    // stays behind the admin auth chain.
    let (admin, admin_core_routes) = crate::core_routes::CoreRouter::new()
        .route(
            crate::auth::HEALTHZ_PATH,
            busbar_plugin_loader::RouteMethod::Get,
            busbar_plugin_loader::RouteAuth::None,
            endpoints::healthz,
        )
        .into_parts();
    let admin = admin::transport::mount(admin, &admin::JsonV1);
    let admin = crate::plugin_routes::mount_plugin_routes(admin, &plugin_routes, true);
    let admin = apply_common_layers(
        admin,
        admin_core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    (data, admin, handle)
}


/// OUTERMOST inbound-concurrency cap. `max_inbound_concurrent == 0` disables the layer entirely (a
/// true no-op) — but `0` is NOT the default; `DEFAULT_MAX_INBOUND_CONCURRENT` is `8192`, so the layer
/// IS installed out of the box and an operator opts OUT with `0`, not in. When `> 0` (including the
/// default), [`limits::admission::InboundAdmissionLayer`] (one `AdmissionGate`, shared across ALL
/// requests) bounds in-flight inbound work: a request that arrives with the cap FULL is SHED with a
/// 503 immediately rather than queued for a permit (Bug 4). Applied as the last `.layer()` so it is
/// outermost (it must admission-control before any inner work, including body buffering). Factored
/// out so the add-only-when-`>0` rule is unit-testable in isolation.
/// Project the resolved `auth:` block onto [`state::App::auth_scope_caps`] — the per-PROVIDER admin
/// trust CEILING (`max_admin_scope:`) the admin authorization step floors every non-`admin-tokens`
/// verdict against.
///
/// KEYED BY PROVIDER NAME, not by the backing plugin MODULE. That is the whole point of the 1.5.3
/// named-definition pattern and the invariant [`crate::auth::ChainVerdict::Identified`] states
/// verbatim: two NAMED providers may share one plugin module and must get INDEPENDENT bindings and
/// ceilings. The lookup side (`auth::module_admin_scope_cap`) reads this map with the provider NAME
/// (the identity a chain verdict carries), and `role_bindings` is name-keyed too — so a module-keyed
/// build here disagreed with both. The dominant effect was fail-CLOSED (a miss floors to
/// `read-only`, silently ignoring an operator's explicit `max_admin_scope: full`), but a config in
/// which one provider's NAME equals a DIFFERENT provider's MODULE handed the first provider's
/// ceiling to the second — an escalation. Name-keying closes both.
fn project_auth_scope_caps(a: &config::AuthCfg) -> std::collections::HashMap<String, String> {
    a.chain
        .iter()
        .chain(a.admin_auth.iter())
        .filter_map(|e| {
            e.max_admin_scope
                .as_ref()
                .map(|sc| (e.name.clone(), sc.clone()))
        })
        .collect()
}


fn apply_inbound_concurrency_limit(router: Router, max_inbound_concurrent: usize) -> Router {
    if max_inbound_concurrent > 0 {
        router.layer(limits::admission::InboundAdmissionLayer::new(
            max_inbound_concurrent,
        ))
    } else {
        router
    }
}
