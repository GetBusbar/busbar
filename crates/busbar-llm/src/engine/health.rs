// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Active health probing.
//!
//! busbar's breaker is fundamentally *passive*: it trips on real request failures and recovers via
//! the half-open probe on the next organic request. Active probing layers a background prober on
//! top, per the provider's `health:` config:
//!
//! - `none` — no probing (the default; pure passive health).
//! - `dead` — re-probe ONLY tripped lanes, so a recovered upstream is picked back up promptly
//!   instead of waiting for organic traffic to drive the half-open probe.
//! - `active` — probe EVERY lane, so a silently-dead upstream trips out before real traffic hits.
//!
//! A probe is a one-token request built by the lane's protocol writer (`probe_body`), sent with the
//! lane's own auth/path. A 2xx recovers a tripped lane (→ Closed); any failure is recorded as a
//! transient (which, on a Closed lane in `active` mode, can trip it out).

use std::sync::Arc;
use std::time::Duration;

use axum::http::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};

use busbar_substrate::breaker::{classify, normalize_raw_error, Disposition, RawUpstreamError};
use busbar_substrate::plane_host::LlmHealthMode as HealthMode;
use busbar_core::state::App;
use busbar_substrate::store::{now, BreakerCfg};

use crate::engine::AppEngineExt;

/// Cap on the bytes read from a non-2xx probe response before breaker classification, mirroring the
/// request path's size-capped read: a hostile/misconfigured upstream must not force an unbounded
/// heap allocation just because a probe failed. 64 KiB is far more than any error envelope needs.
const PROBE_ERROR_BODY_CAP: usize = 64 * 1024;

// Default probe interval / timeout (the PROCESS-WIDE fallback used when a per-lane `health:` block
// omits `interval_secs` / `timeout_secs`). Operator-tunable via `health.default_probe_interval_secs`
// / `health.default_probe_timeout_secs` (defaults 30 / 5), read through `busbar_core::limits`. The per-lane
// override still wins (see `unwrap_or` below).

/// The probe schedule, shared by every clone-derived snapshot of one `App` lineage.
///
/// `AppHandle::swap` re-spawns the probers on EVERY config mutation — a hook PATCH, a group create,
/// a settings apply — because a prober holds a `Weak<App>` and must be re-attached to the new
/// snapshot. Each fresh generation built its own `interval`, whose first tick is discarded so the
/// gateway does not probe a cold upstream before traffic has established health. That means a
/// generation must survive a full interval before it can probe ONCE. Under swap churn faster than
/// the probe interval — an onboarding wave that auto-provisions a group per new subject, or a script
/// applying settings in a loop — every generation was replaced before its first tick, and health
/// probing went entirely DARK for the duration plus one interval, while logging that it was enabled.
///
/// Carrying the deadline here makes the schedule phase-stable across swaps: at each deadline the
/// live generation probes, and the stale ones exit. A full rebuild from disk mints a new schedule,
/// which is correct — a reload genuinely re-establishes probing.
pub struct ProbeSchedule {
    /// Bumped by every `spawn_probers`. A prober whose captured generation is no longer current
    /// exits at its next tick, so generations never double-probe during the window where the old
    /// snapshot is still alive on an in-flight request.
    generation: std::sync::atomic::AtomicU64,
    /// The reference point the deadlines are measured from. A MONOTONIC timer instant, not wall
    /// clock: the deadlines feed `interval_at`, so mixing in a wall-clock reading would make the
    /// schedule drift with clock adjustments and would not survive a paused test clock at all.
    origin: tokio::time::Instant,
    /// Per-lane next-probe deadline, milliseconds after `origin`. `None` = not yet scheduled.
    deadlines: Vec<std::sync::atomic::AtomicU64>,
}

/// Sentinel for "this lane has no deadline yet" — `0` is a legitimate deadline at `origin`.
const UNSCHEDULED: u64 = u64::MAX;

/// Advance THIS prober's deadline slot, and only this prober's. Returns the value the caller now
/// owns.
///
/// Must be `compare_exchange`, not `fetch_min` and not `store`:
///   - `store` (the previous code) would silently revert a clamp that a NEWER generation's
///     spawn-time `fetch_min` landed between our generation check and here — the newer schedule
///     would run one cycle stale.
///   - `fetch_min` would never take, because `next` is always LATER than what we own; the slot would
///     freeze at a past instant, and every subsequent rebuild would inherit an already-elapsed
///     deadline and probe immediately. (It would NOT spin: the ticker is built once at
///     `interval_at` and never re-derived from the slot, and it is set to `MissedTickBehavior::Skip`.)
///
/// Spawn-time only ever biases the deadline EARLIER; tick-time only ever moves it LATER. The
/// asymmetry is why one primitive cannot serve both.
fn advance_owned_deadline(slot: &std::sync::atomic::AtomicU64, owned: u64, next: u64) -> u64 {
    use std::sync::atomic::Ordering;
    match slot.compare_exchange(owned, next, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => next,
        // Someone else moved the slot: they own it now, adopt their value.
        Err(theirs) => theirs,
    }
}

impl ProbeSchedule {
    pub fn new(lane_count: usize) -> Self {
        Self {
            generation: std::sync::atomic::AtomicU64::new(0),
            origin: tokio::time::Instant::now(),
            deadlines: (0..lane_count)
                .map(|_| std::sync::atomic::AtomicU64::new(UNSCHEDULED))
                .collect(),
        }
    }

    /// Milliseconds from `origin` to now.
    fn elapsed_ms(&self) -> u64 {
        tokio::time::Instant::now()
            .saturating_duration_since(self.origin)
            .as_millis() as u64
    }
}

/// Spawn one background prober task per lane that has a probing mode configured. A no-op for lanes
/// with `mode: none` (or no `health:` block).
///
/// Each prober holds a `Weak<App>` to the snapshot it belongs to, NOT a strong `Arc`: on a config
/// reload/apply a fresh `App` is built and `spawn_probers` is called again for it, while the old
/// snapshot is swapped out of the `AppHandle`. Once the old snapshot's last in-flight request drops
/// it, the old probers' `Weak::upgrade` returns `None` and they exit. This (a) re-establishes probing
/// for lanes added/changed by the reload — a strong-`Arc` prober captured only the boot snapshot and
/// never saw reloaded lanes — and (b) prevents the old generation from leaking forever (one task-set
/// per reload) and writing outcomes into an orphaned store. Callers: boot (`main.rs`) and
/// `AppHandle::swap` — which runs on EVERY config mutation (reload, apply, and each hook/auth swap), so
/// no swap site can forget to re-attach probing.
pub fn spawn_probers(app: &Arc<App>) {
    use std::sync::atomic::Ordering;
    let schedule = app.engine_tables().probe_schedule().clone();
    let my_gen = schedule.generation.fetch_add(1, Ordering::Relaxed) + 1;
    for i in 0..app.engine_tables().lanes().len() {
        let Some(h) = app.engine_tables().lanes()[i].health.clone() else {
            continue;
        };
        if h.mode == HealthMode::None {
            continue;
        }
        let interval = Duration::from_secs(
            h.interval_secs
                .unwrap_or_else(busbar_core::limits::default_probe_interval_secs)
                .max(1),
        );
        let timeout = Duration::from_secs(
            h.timeout_secs
                .unwrap_or_else(busbar_core::limits::default_probe_timeout_secs)
                .max(1),
        );
        let mode = h.mode;
        let weak = Arc::downgrade(app);
        let model = app.engine_tables().lanes()[i].model.clone();
        // Inherit this lane's deadline, or schedule the first probe one interval out (the
        // deliberate "don't probe a cold upstream at startup" behaviour, now expressed as a
        // deadline instead of a discarded first tick).
        let first = schedule
            .elapsed_ms()
            .saturating_add(interval.as_millis() as u64);
        let deadline_ms = match schedule.deadlines.get(i) {
            // MONOTONE-EARLIEST at spawn time: keep whichever deadline is sooner. `UNSCHEDULED` is
            // `u64::MAX` precisely so it is the identity for `min` and an unscheduled slot takes
            // `first`. This both inherits a racing generation's already-landed deadline (never
            // pushing it out) and makes a SHORTENED `interval_secs` take effect within one new
            // interval instead of waiting out the old one. Same monotonicity posture as the audit
            // log's `fetch_max` seq. Strictly subsumes the old
            // `compare_exchange(UNSCHEDULED, first)`: that was the `min` identity case.
            Some(slot) => slot.fetch_min(first, Ordering::Relaxed).min(first),
            // Lane count grew without a rebuild: fall back to an unshared schedule for this lane.
            None => first,
        };
        // Only the FIRST generation announces probing. A swap burst re-spawns per lane, and the
        // line claims probing was just enabled — logging it every time amplifies the burst and
        // misdescribes what happened.
        if my_gen == 1 {
            tracing::info!(
                lane = %model,
                mode = ?mode,
                interval_secs = interval.as_secs(),
                "active health probing enabled for lane"
            );
        }
        let schedule = schedule.clone();
        tokio::spawn(async move {
            let start = schedule.origin + Duration::from_millis(deadline_ms);
            let mut ticker = tokio::time::interval_at(start, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Tracks the deadline THIS prober currently owns, so `advance_owned_deadline`'s
            // compare_exchange has the right expected value each tick.
            let mut owned = deadline_ms;
            loop {
                ticker.tick().await;
                // A newer generation owns the schedule now — exit rather than probe alongside it.
                if schedule.generation.load(Ordering::Relaxed) != my_gen {
                    return;
                }
                if let Some(slot) = schedule.deadlines.get(i) {
                    let next = schedule
                        .elapsed_ms()
                        .saturating_add(interval.as_millis() as u64);
                    owned = advance_owned_deadline(slot, owned, next);
                }
                // Upgrade the Weak each tick (holding no strong ref across the sleep). `None` means
                // this snapshot was replaced by a reload and fully released — this prober is now
                // stale, so exit rather than probe an orphaned store forever.
                let Some(app) = weak.upgrade() else {
                    tracing::debug!(lane = %model, "health prober exiting: app snapshot replaced by reload");
                    return;
                };
                let should = match mode {
                    HealthMode::Active => true,
                    // Re-probe a lane the breaker is suppressing in ANY cell — whether fully tripped
                    // (Open) OR just in a soft cooldown (Closed but a sub-threshold transient armed a
                    // cooldown). Both make the lane unusable; dead mode's job is to recover either early.
                    HealthMode::Dead => app.store.lane_needs_probe(i, now()),
                    HealthMode::None => false,
                };
                if should {
                    probe_lane(&app, i, timeout).await;
                }
                // `app` strong ref drops here, before the next tick wait — never held across the sleep.
            }
        });
    }
}

/// Send a single health probe to lane `i` and fold the outcome into the breaker, running a non-2xx
/// response through the SAME two-stage disposition pipeline organic traffic uses
/// (the cell's `extract_error` → `normalize_raw_error` → `breaker::classify`) rather than forcing
/// every failure to a transient cooldown:
///   - 2xx → recover the lane if it was tripped (→ Closed), THEN push a success outcome into every
///     cell's sliding error-rate window (`record_probe_success_all_cells`). Recording the success is
///     what makes probe-outcome accounting SYMMETRIC: failures already feed the window via
///     `record_probe_failure_all_cells`, so without a matching success record a lane that fails some
///     probes and succeeds others would show a 100%-error window (every cell holds only failures) and
///     the error-rate breaker would trip a perfectly recoverable lane (LOW #23). The success is
///     recorded AFTER recovery so no cell is HalfOpen at that point — the success push therefore never
///     *forces* a HalfOpen→Closed transition (recovery, when warranted, already happened via
///     `recover_lane`); on an already-healthy lane the cells are Closed and the push only feeds the
///     window. The success counts toward the lane's `ok` stat, exactly mirroring how a failed probe
///     feeds the breaker — probe accounting is now fully two-sided rather than failure-only.
///   - `HardDown` (Auth/Billing — e.g. an invalid credential or exhausted balance) → record a
///     hard-down trip on every cell the lane routes against, matching organic semantics. Previously
///     these were mis-recorded as transient, so an auth-dead lane oscillated between cooldown and
///     re-probe forever instead of being parked dead (and the prober kept firing guaranteed-401s).
///   - `TransientUpstream` (5xx/429/timeout/overloaded/network) and transport errors → record a
///     transient failure across all cells (drives the trip evaluation in `active` mode and re-arms
///     the cooldown on a tripped lane).
///   - `ClientFault` / `ContextLength` → the LANE is healthy; the probe request itself was rejected
///     as malformed or too large for this model. Record NOTHING — penalizing the breaker here would
///     bench a working lane over a probe-construction issue, matching the organic "record nothing"
///     disposition for these classes.
pub(crate) async fn probe_lane(app: &Arc<App>, i: usize, timeout: Duration) {
    let lane = &app.engine_tables().lanes()[i];

    // No key, no probe — we can't authenticate (e.g. a passthrough deployment with no static key),
    // and a guaranteed 401 would only thrash the breaker.
    if lane.api_key.expose_secret().is_empty() {
        return;
    }

    // No active probe for a `path_base` lane (Claude/Gemini on Vertex). The probe builds its URL from
    // the writer's default path and sends the native model-in-body form; it does NOT apply the lane's
    // `path_base` (`{path_base}/{model}:rawPredict`) nor the Vertex wire transform (model-strip +
    // `anthropic_version`) that organic forwarding does. Probing such a lane would hit the wrong URL with
    // the wrong body, never 2xx, and bench a HEALTHY lane. Skip it — passive half-open breaker recovery
    // on organic traffic still restores a tripped path_base lane. (Active probing of path_base lanes
    // needs the probe to route through the organic EgressCtx path — a follow-up.)
    if lane.path_base.is_some() {
        return;
    }

    // No probe for an OAuth lane (jwt-bearer / oauth-client-credentials) whose first token has not
    // minted yet: during that boot/reload window `credential.headers_for` emits no auth header, so the
    // probe would send an unauthenticated request and the guaranteed 401 (classified HardDown) would
    // park a HEALTHY lane dead. Skip until the token is live — the background minter fills it within a
    // second, and organic traffic + passive half-open recovery cover the gap.
    if !lane.credential.is_ready() {
        return;
    }

    // Probe body via the neutral dialect seam (the concrete writer relocated to the plugin at A4b).
    let body = busbar_substrate::proto::decl_for(lane.protocol)
        .and_then(|d| d.dialect())
        .map(|dc| dc.probe_body(lane.wire_model()))
        .unwrap_or_default();
    let url_path = lane.path.clone().unwrap_or_else(|| {
        busbar_substrate::proto::decl_for(lane.protocol)
            .and_then(|d| d.dialect())
            .map(|dc| dc.upstream_path_for_stream(lane.wire_model(), false))
            .unwrap_or_default()
    });

    // SigV4 signs over the URI-encoded canonical path, so the probe MUST send the wire request over
    // the SAME encoding or AWS rejects with SignatureDoesNotMatch (every Bedrock modelId carries a
    // reserved `:` that signs as `%3A` but a raw send transmits `:`). Encode the path ONCE via the
    // shared `sign_and_wire_path` helper — the identical primitive the organic forward path uses —
    // and reuse it for both the signed canonical URI and the wire URL so signed == sent.
    let wire_path = crate::engine::sign_and_wire_path(&url_path);
    let signing_ctx = busbar_substrate::proto::SigningContext {
        host: &lane.signing_host,
        canonical_uri: wire_path.split('?').next().unwrap_or(&wire_path),
        body: &body,
        timestamp_epoch: now(),
        // Active health probes use busbar's own configured lane key (never a forwarded caller
        // token), so the native API-key shape (Token mode) is correct here.
        upstream_creds: busbar_api::UpstreamCreds::Own,
    };
    let auth = crate::engine::lane_auth_headers(lane, lane.api_key.expose_secret(), &signing_ctx);

    // Send the SAME native-SDK fingerprint headers the organic forward path sends, so a probe is
    // indistinguishable from real traffic to the backend: the shared client emits no default
    // User-Agent (its absence is a proxy tell), and a missing Accept differs from what a native SDK
    // sends. The probe is non-streaming, so `wants_stream = false`. Without these, a backend could
    // fingerprint and special-case busbar's health probes — defeating the indistinguishability
    // guarantee.
    //
    // The probe rides the SAME owned egress client stack (`crate::engine::egress_request` +
    // the lane-sharded `EgressClient`) as the forward path, assembling its header map in the
    // engine's exact insertion order — auth headers first, then CT/UA/Accept — so the probe's wire
    // fingerprint (client stack, TLS/ALPN posture, header shape) stays byte-identical to organic
    // traffic. The probe composes its own URL (probe-specific path, not necessarily a lane egress
    // target), so it parses the `http::Uri` here; a seconds-cadence background parse, not hot-path.
    let egress_name = lane.protocol;
    let uri: http::Uri = match format!("{}{}", lane.base_url, wire_path).parse() {
        Ok(u) => u,
        Err(_) => {
            // A malformed probe URL is a probe-construction issue, not upstream health — record
            // nothing, same disposition as the ClientFault arm below. (The organic path proves the
            // same base_url composes into a valid URL, so this arm is effectively unreachable.)
            tracing::warn!(lane = %lane.model, "health probe URL failed to parse; lane not penalized");
            return;
        }
    };
    let mut headers = http::HeaderMap::with_capacity(auth.len() + 3);
    for (name, value) in auth {
        headers.insert(name, value);
    }
    headers.insert(
        CONTENT_TYPE,
        // Declaration constants all three: static bytes, no per-probe allocs — and byte-identical
        // to the forward path's headers, which is this probe's indistinguishability contract.
        axum::http::HeaderValue::from_static(crate::engine::APPLICATION_JSON),
    );
    headers.insert(
        USER_AGENT,
        axum::http::HeaderValue::from_static(crate::engine::egress_user_agent(egress_name)),
    );
    headers.insert(
        ACCEPT,
        axum::http::HeaderValue::from_static(crate::engine::egress_accept(egress_name, false)),
    );
    let req = crate::engine::egress_request(uri, headers, bytes::Bytes::from(body));
    // TIMEOUT RE-PROVISION: reqwest's per-request `.timeout(timeout)` bounded the ENTIRE probe
    // lifecycle — connect, headers, AND the body read. The owned client carries no per-request
    // total timeout, so re-provide the same bound as ONE deadline shared by the send below and the
    // capped error-body read (`read_capped_error_body`), so a black-holed upstream can never hang
    // the prober past its configured `timeout_secs`.
    let deadline = tokio::time::Instant::now() + timeout;
    let res =
        tokio::time::timeout_at(deadline, app.engine_tables().client().get().request(req)).await;

    // Classify the probe outcome through the organic disposition pipeline so auth/billing failures
    // reach HardDown instead of being mis-filed as transient cooldowns. Carry the server-requested
    // `Retry-After` alongside the disposition so a transient probe failure honors the upstream's
    // cooldown floor (the captured value is otherwise dropped by `classify`, which returns only the
    // Disposition).
    let (disposition, retry_after_secs) = match res {
        Ok(Ok(r)) if r.status().is_success() => {
            if app.store.lane_needs_probe(i, now()) {
                // Probe tests the shared upstream → recover the lane in every cell (all pools +
                // default), clearing both Open trips and soft cooldowns. This runs FIRST so that by
                // the time we record the success outcome below, every cell is Closed and the success
                // push can never force a HalfOpen→Closed transition (recovery already happened here).
                app.store.recover_lane(i);
                tracing::info!(lane = %lane.model, "lane recovered via health probe");
            }
            // Record the 2xx as a SUCCESS in every cell's sliding error-rate window — the symmetric
            // counterpart to the failed-probe `record_probe_failure_all_cells` below. Without this,
            // probes only ever fed FAILURES into the window, so a lane that intermittently fails
            // probes presented a 100%-error window to the error-rate breaker and tripped spuriously
            // (LOW #23). This does NOT force any breaker transition — recovery, when warranted,
            // already happened above; here we only push the outcome.
            app.store.record_probe_success_all_cells(i);
            return;
        }
        Ok(Ok(r)) => {
            // Non-2xx: run the body through Stage 1a (the cell's `extract_error`) → Stage 1b
            // (normalize_raw_error + the lane's error_map) → Stage 2 (classify), exactly as the
            // forwarding path does, capturing the Retry-After header the body-only extractor can't
            // see so the cooldown floor is honored.
            //
            // Stage 1a asks the CELL that spoke to this upstream — the probe is a chat exchange over
            // HTTP against the lane's protocol — rather than the lane's chat vtable. Identical
            // vocabulary for all six protocols (chat's codec delegates to that very reader), and an
            // outbound attempt with no lane behind it can be attributed the same way.
            let status = r.status();
            let retry_after_secs = busbar_substrate::breaker::parse_retry_after(r.headers());
            let body = read_capped_error_body(r.into_body(), deadline).await;
            // Stage 1a asks the CELL that spoke to this upstream. For chat over HTTP that cell's
            // `extract_error` is uniformly `protocol_error(protocol, …)` (its error vocabulary is the
            // PROTOCOL's, shared by every operation it serves), so calling `protocol_error` directly
            // is byte-identical to `chat(protocol).extract_error(…)` — and does not require a concrete
            // chat codec, which core no longer carries in production (G6 A4b: `ChatOperation` and the
            // chat IR relocated to the `busbar-llm` plugin).
            let mut raw: RawUpstreamError =
                busbar_substrate::handlers::protocol_error(lane.protocol, status.as_u16(), &body);
            raw.retry_after_secs = retry_after_secs;
            (
                classify(&normalize_raw_error(&raw, &lane.error_map)),
                retry_after_secs,
            )
        }
        // Transport error (connect/reset/TLS) from the owned client: treat as a transient network
        // failure, as the organic path does. No HTTP response, so no Retry-After. Same disposition
        // the reqwest error took before the cutover.
        Ok(Err(_)) => (Disposition::TransientUpstream, None),
        // The probe deadline elapsed before response headers arrived — reqwest's `.timeout()`
        // surfaced this as a request error, which took this same transient arm.
        Err(_elapsed) => (Disposition::TransientUpstream, None),
    };

    match disposition {
        Disposition::HardDown => {
            // Auth/Billing: the lane is definitively bad (e.g. invalid credential). Park it down in
            // EVERY cell organic traffic routes against via the canonical all-cells primitive
            // `record_hard_down_all_cells`, mirroring the all-cells reach of a successful probe's
            // `recover_lane` and a failed probe's `record_probe_failure_all_cells`. All three probe
            // outcomes (success / transient / hard-down) now derive their cell set from the SAME live
            // `pool_cells` map under ONE lock — rather than this path uniquely iterating CONFIG pool
            // membership (which took N per-pool locks and eagerly lazy-created a cell for every config
            // member the lane may never be routed against). Using the shared primitive keeps the trip
            // and recover bases in lockstep against any future change to how cells are materialized.
            app.store
                .record_hard_down_all_cells(i, "health-probe hard-down (auth/billing)");
            tracing::warn!(lane = %lane.model, "lane hard-down via health probe (parked dead, recovers on a 2xx probe)");
        }
        Disposition::TransientUpstream => {
            // A transient failed probe must trip the SAME cells a successful probe (recover_lane)
            // clears — the default cell AND every per-pool cell — because organic traffic routes
            // against per-pool cells. Each cell is evaluated against ITS OWN pool's resolved breaker
            // config (trip thresholds + cooldown backoff): resolve the per-pool `BreakerCfg` from
            // `app.pool_runtime` by pool name, falling back to the ADR-0002 default for the bare `""`
            // default cell and any pool without its own breaker block — matching the per-pool cfg the
            // organic forward path resolves (proxy engine `breaker_cfg`). This replaces the prior
            // one-size `BreakerCfg::default()` that ignored per-pool thresholds/cooldowns (#24/#25).
            let resolve_cfg = |pool: &str| -> BreakerCfg {
                app.engine_tables()
                    .pool_runtime()
                    .get(pool)
                    .and_then(|r| r.breaker.clone())
                    .unwrap_or_default()
            };
            app.store.record_probe_failure_all_cells(
                i,
                "health-probe",
                &resolve_cfg,
                retry_after_secs,
            );
        }
        // The lane is healthy; the probe REQUEST was rejected (malformed / too large for the model).
        // Record nothing — do not bench a working lane over a probe-construction issue.
        Disposition::ClientFault | Disposition::ContextLength => {
            tracing::debug!(
                lane = %lane.model,
                "health probe got a client-fault/context-length response; lane not penalized"
            );
        }
    }
}

/// Read at most `PROBE_ERROR_BODY_CAP` bytes of a non-2xx probe response body for breaker
/// classification. Streams chunk-by-chunk and stops once the cap is reached so a hostile or
/// misconfigured upstream cannot force an unbounded allocation on the probe path.
///
/// Internal-only, not a silent-drop hazard: 64 KiB is far beyond any real error envelope (a
/// truncated body would need a pathological/hostile upstream), the resulting breaker disposition
/// (`HardDown`/`TransientUpstream`/…) is itself always logged (`tracing::warn!`/`info!` at each
/// call site below) so a misclassification from an oversized body is observable through the
/// breaker transition it produces, not silent — no user/hook/operator/audit-facing data is capped
/// here, only this probe's own internal classification input.
///
/// Reads hyper body frames directly (the probe rides the owned egress client), under the SAME
/// probe deadline that bounded the send — re-providing reqwest's whole-lifecycle `.timeout()`,
/// which previously covered this read too. A deadline expiry mid-body classifies on what arrived,
/// exactly like a mid-body transport error did before.
async fn read_capped_error_body(
    mut body: hyper::body::Incoming,
    deadline: tokio::time::Instant,
) -> Vec<u8> {
    use http_body_util::BodyExt;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(None) => break,         // end of body
            Ok(Some(Err(_))) => break, // mid-body transport error — classify on what we have
            Err(_elapsed) => break,    // probe deadline hit mid-body — classify on what we have
        };
        // Non-data frames (trailers) carry no body bytes.
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        let remaining = PROBE_ERROR_BODY_CAP.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break; // this chunk filled the cap
        }
    }
    buf
}

#[cfg(test)]
#[path = "proxy_tests/health_tests.rs"]
mod tests;
