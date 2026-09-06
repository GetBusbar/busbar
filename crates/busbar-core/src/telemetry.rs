// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TELEMETRY BANK — per-thread metric cells for the request hot path, one scrape-time
//! aggregator.
//!
//! ## Why this layer exists
//!
//! The request hot path used to update ~26 Prometheus metric sites through the `metrics` facade
//! macros. Every one of those is a shared atomic in the global recorder's registry: at high RPS on
//! many cores the increments ping-pong the metric cache lines between cores, and that contention
//! measurably caps throughput (part of a measured −36% collapse from concurrency 64→1024). The fix
//! is ONE proper layer, not N ad-hoc thread-local hacks:
//!
//! * **Per-thread bank** — each thread that emits owns a private block of pre-registered slots. A
//!   hot-path write is a plain add into the thread's OWN cell: the cells are `AtomicU64` with
//!   `Relaxed` ordering, but only the OWNING thread ever writes them (owner-writes-only), so in
//!   steady state the cache line stays exclusive to its core. The atomic type exists purely so the
//!   aggregator can READ other threads' cells safely during a concurrent scrape.
//! * **Slot registration once per config generation** — label combinations are bounded (pools and
//!   models come from config; outcomes/protocols/dispositions are fixed vocabularies), so slots are
//!   interned ONCE when an `App` snapshot is built ([`AppSlots::build`]) and the hot path holds a
//!   plain slot index. It never allocates and never builds a `metrics::Key`/label map. Re-applying a
//!   config re-interns the same label sets to the SAME slots, so counts accumulate monotonically
//!   across generations.
//! * **One aggregator** — [`flush_to_recorder`] runs at scrape time (called from
//!   `metrics::render()`): it sums every thread's cells per slot and pushes the DELTA since the last
//!   flush into the process-global `metrics-exporter-prometheus` recorder. The exposition is
//!   rendered by the SAME recorder as before, so metric names, labels, HELP/TYPE lines, and
//!   formatting are byte-identical to the pre-bank output. Histogram slots buffer raw samples
//!   per thread and drain them into the recorder at flush, so the summary/quantile rendering is
//!   unchanged too (samples are just delivered at scrape time instead of request time).
//!
//! ## THE RULE — observation only
//!
//! If ENFORCEMENT depends on a count, it does NOT go through the bank. Budget cells, `max_concurrent`
//! permits, rate windows, breaker failure counters — anything a decision reads — counts inline where
//! the decision is made. The bank's cells are eventually-consistent by design (a thread's adds are
//! only globally visible at the next scrape), which is exactly right for OBSERVATION and exactly
//! wrong for enforcement. Adding a new observability counter tomorrow = registering a slot here; a
//! new enforcement counter never touches this module.
//!
//! ## What stays on the plain `metrics` macros
//!
//! Cold-path and boot-path metrics keep the macro emission (migrating them is churn without
//! benefit — they fire far off the steady-state request path or with runtime-resolved label
//! vocabularies the config-time registration can't enumerate):
//! * route-policy selection/rejection counters (`policy` can be an operator-defined hook name
//!   resolved at hook-fire time; rejections additionally carry a dynamic clamped `status`),
//! * webhook / tap backpressure drop counters (global anomaly signals),
//! * the billing-truncation counter (anomaly path),
//! * every scrape-time gauge in `metrics.rs` (they are already scrape-driven).
//!
//! [`AppSlots`] lookups fall back to the identical macro emission whenever a label value is not in
//! the current generation's registered set (e.g. a custom ingress protocol, or unit tests driving a
//! bare `App`), so output is preserved in every case — the bank is a fast path, never a gate.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::state::App;

// ── THE BANK, RE-EXPORTED BY IDENTITY FROM THE NEUTRAL SUBSTRATE ─────────────────────────────────
//
// The per-thread cells, the intern tables and the scrape-time aggregator moved DOWN to
// `busbar_substrate::telemetry` (they name no `App` and feed the recorder install that moved with
// them). These are the SAME items, re-exported at their historical `crate::telemetry::…` paths, so
// every emit site below and every core call site elsewhere resolves unchanged.
#[cfg(test)]
pub(crate) use busbar_substrate::telemetry::drain_serial;
pub(crate) use busbar_substrate::telemetry::{
    counter_slot, histogram_slot, CounterSlot, HistogramSlot, DISPOSITIONS, OUTCOMES, REASONS,
};
// The capacity knobs and per-thread storage the retention batteries below read directly. Test-only
// on both sides of the seam, so core's shipped surface gains nothing.
#[cfg(test)]
pub(crate) use busbar_substrate::telemetry::bank_internals::{
    hist_chunk_materialized, HIST_DRAIN_THRESHOLD,
};

// ── Per-App slot tables (registered once per config generation) ─────────────────────────────────

/// The banked slots for one request family: `busbar_requests_total` (per outcome) and
/// `busbar_request_duration_seconds`, for a fixed `(ingress_protocol, pool)` pair ON THE PLANE THIS
/// BANK REGISTERS (see [`AppSlots::build`]).
#[derive(Clone, Copy)]
struct RequestFamily {
    requests: [CounterSlot; OUTCOMES.len()],
    duration: HistogramSlot,
}

/// The banked slots for one `(pool label, lane)` pair on the upstream walk:
/// attempts, per-disposition failures, and breaker trips.
#[derive(Clone, Copy)]
struct LaneFamily {
    attempts: CounterSlot,
    failures: [CounterSlot; DISPOSITIONS.len()],
    trips: CounterSlot,
}

/// All hot-path metric slots for ONE `App` snapshot, resolved at config load (`App` construction)
/// so the request path never interns, allocates, or touches the recorder registry. Lookups are
/// read-only probes into maps owned by the (immutable) `App` — no shared-cache-line writes.
///
/// Every lookup method returns the slots for values in THIS generation's bounded label space; a
/// miss (custom protocol, label from a different generation, bare test `App`) falls back to the
/// exact macro emission the site used before the bank, so `/metrics` output is preserved always.
pub(crate) struct AppSlots {
    /// The plane this bank's request families belong to. The bank's inputs (`lanes`, `pools`,
    /// `by_model`) are the MODEL plane's routing tables, so a request from any other plane must
    /// miss the bank and take a different emission path — it is carried as a field rather than
    /// assumed at the lookup so that guard is explicit. Note the banked `busbar_requests_total` /
    /// `busbar_request_duration_seconds` families carry NO `plane` label (they are the model
    /// plane's v1.5.4-identical series); the mounted planes emit their own `busbar_plane_*`
    /// families from `request_finished` instead.
    banked_plane: &'static str,
    /// pool label (ingress convention: pools ∪ models ∪ "unresolved") → per-protocol request
    /// families, indexed by position in `proto::KNOWN_PROTOCOLS`.
    request: HashMap<Box<str>, Box<[RequestFamily]>>,
    /// engine pool label (pools ∪ models, matching `proxy::metric_pool_label`) → lane idx → family.
    lane: HashMap<Box<str>, HashMap<usize, LaneFamily>>,
    /// engine pool label → failover-reason slots, indexed by position in [`REASONS`].
    failover: HashMap<Box<str>, [CounterSlot; REASONS.len()]>,
}

impl AppSlots {
    /// Register every hot-path slot for one config generation. Label spaces registered here are
    /// exactly the bounded sets the emission sites can produce: configured pool names, configured
    /// lane MODEL strings, the `"unresolved"` sentinel, and the fixed vocabularies above.
    /// NEUTRAL LABEL PROJECTION inputs (money-path Phase 3-4 B): `pools` is each pool label paired
    /// with its member lane indices, `by_model` is the direct-model index (model label → lane index),
    /// and `lane_model` resolves a lane index to its model-string label. Expressed this way, banking
    /// one plane's bounded label space names no `Lane`/`WeightedLane`, so telemetry need not relocate
    /// when the routing tables move into `busbar-llm`. Byte-identical banking to the prior
    /// table-typed form — the SAME pool/model/lane label sets.
    pub(crate) fn build<'a>(
        pools: &[(&'a str, Vec<usize>)],
        by_model: &[(&'a str, usize)],
        lane_model: impl Fn(usize) -> Option<&'a str>,
        plane: &'static str,
    ) -> AppSlots {
        use crate::metrics::{
            BREAKER_TRIPS_TOTAL, FAILOVERS_TOTAL, REQUESTS_TOTAL, REQUEST_DURATION_SECONDS,
            UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL,
        };

        // STATED by the caller, not assumed here: `lanes`/`pools`/`by_model` are one plane's
        // routing tables, and the caller is the only place that knows whose. Assuming it would make
        // this function silently wrong the day a second plane grows a bounded routing table worth
        // banking, which is exactly the direction the plane spine is going.
        let banked_plane = plane;

        // Ingress pool labels: configured pools, model-routed labels, and the pre-routing sentinel.
        let mut ingress_labels: Vec<&str> = pools.iter().map(|(pool, _)| *pool).collect();
        ingress_labels.extend(by_model.iter().map(|(model, _)| *model));
        ingress_labels.push(crate::proxy::POOL_LABEL_UNRESOLVED);
        ingress_labels.sort_unstable();
        ingress_labels.dedup();

        let mut request = HashMap::with_capacity(ingress_labels.len());
        for pool in &ingress_labels {
            let families: Box<[RequestFamily]> = crate::proto::known_protocols()
                .iter()
                .map(|proto| RequestFamily {
                    requests: std::array::from_fn(|oi| {
                        counter_slot(
                            REQUESTS_TOTAL,
                            &[
                                ("ingress_protocol", proto),
                                ("pool", pool),
                                ("outcome", OUTCOMES[oi]),
                            ],
                        )
                    }),
                    duration: histogram_slot(
                        REQUEST_DURATION_SECONDS,
                        &[("ingress_protocol", proto), ("pool", pool)],
                    ),
                })
                .collect();
            request.insert(Box::from(*pool), families);
        }

        // Engine labels: named pools walk their members; model-routed traffic is labeled by the
        // lane's model string (`metric_pool_label` resolves the empty cell key to the model).
        let mut lane_map: HashMap<Box<str>, HashMap<usize, LaneFamily>> = HashMap::new();
        let mut engine_labels: Vec<(&str, Vec<usize>)> = Vec::new();
        for (pool, member_idxs) in pools {
            engine_labels.push((*pool, member_idxs.clone()));
        }
        for (model, idx) in by_model {
            engine_labels.push((*model, vec![*idx]));
        }

        let mut failover = HashMap::with_capacity(engine_labels.len());
        for (pool, member_idxs) in &engine_labels {
            let mut per_lane = HashMap::with_capacity(member_idxs.len());
            for &idx in member_idxs {
                let Some(lane_label) = lane_model(idx) else {
                    continue;
                };
                per_lane.insert(
                    idx,
                    LaneFamily {
                        attempts: counter_slot(
                            UPSTREAM_ATTEMPTS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                        failures: std::array::from_fn(|di| {
                            counter_slot(
                                UPSTREAM_FAILURES_TOTAL,
                                &[
                                    ("pool", pool),
                                    ("lane", lane_label),
                                    ("disposition", DISPOSITIONS[di]),
                                ],
                            )
                        }),
                        trips: counter_slot(
                            BREAKER_TRIPS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                    },
                );
            }
            lane_map
                .entry(Box::from(*pool))
                .or_default()
                .extend(per_lane);
            failover.entry(Box::from(*pool)).or_insert_with(|| {
                std::array::from_fn(|ri| {
                    counter_slot(FAILOVERS_TOTAL, &[("pool", pool), ("reason", REASONS[ri])])
                })
            });
        }

        AppSlots {
            banked_plane,
            request,
            lane: lane_map,
            failover,
        }
    }

    fn request_family(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
    ) -> Option<&RequestFamily> {
        if plane != self.banked_plane {
            return None;
        }
        let proto_idx = crate::proto::known_protocols()
            .iter()
            .position(|p| *p == ingress_protocol)?;
        self.request.get(pool).map(|fams| &fams[proto_idx])
    }

    fn lane_family(&self, pool_label: &str, lane_idx: usize) -> Option<&LaneFamily> {
        self.lane.get(pool_label)?.get(&lane_idx)
    }
}

// ── Hot-path emit helpers (bank fast path, macro fallback) ──────────────────────────────────────

/// `busbar_requests_total` + `busbar_request_duration_seconds` for one finished request, on ANY
/// plane. The single emission site for the request families: the model plane calls it from
/// `ingress::finish_inner` and every mounted plane calls it from `plane::observe`.
///
/// TWO SERIES, split so the model plane stays v1.5.4-identical. The MODEL plane
/// (`plane == Plane::Llm`) emits `busbar_requests_total` / `busbar_request_duration_seconds` with
/// exactly the v1.5.4 label set `{ingress_protocol, pool, outcome}` — NO `plane` label — so a
/// pure-LLM `/metrics` scrape is byte-identical to v1.5.4. The MOUNTED planes (MCP, A2A) emit the
/// parallel `busbar_plane_requests_total` / `busbar_plane_request_duration_seconds` families, which
/// carry the extra `plane` label so `sum by (plane)` compares them — without ever altering the
/// label identity of the two pre-existing model-plane families.
///
/// Bank fast path when `(plane, ingress_protocol, pool)` is in this generation's registered set (the
/// bank holds only the model plane's label space); otherwise the cached-handle helpers in `metrics.rs`.
pub(crate) fn request_finished(
    app: &App,
    plane: &str,
    ingress_protocol: &str,
    pool: &str,
    outcome: &'static str,
    seconds: f64,
) {
    // Mounted (non-model) planes emit on their OWN `busbar_plane_*` families, keeping the two
    // model-plane families label-identical to v1.5.4. The bank holds only the model plane's label
    // space, so a mounted-plane request would miss it anyway; routing here is explicit rather than
    // relying on that miss, and it targets the correct (plane-labelled) family.
    if !crate::plane::is_fallback(plane) {
        crate::metrics::incr_plane_requests_total(plane, ingress_protocol, pool, outcome);
        crate::metrics::record_plane_request_duration(plane, ingress_protocol, pool, seconds);
        return;
    }
    // Model plane: bank fast path, else the cached-handle helpers — byte-identical series either way.
    let fam = app.tslots.request_family(plane, ingress_protocol, pool);
    let outcome_idx = OUTCOMES.iter().position(|o| *o == outcome);
    match (fam, outcome_idx) {
        (Some(fam), Some(oi)) if fam.requests[oi].is_valid() => fam.requests[oi].incr(),
        _ => crate::metrics::incr_requests_total(ingress_protocol, pool, outcome),
    }
    match fam {
        Some(fam) if fam.duration.is_valid() => fam.duration.record(seconds),
        _ => crate::metrics::record_request_duration(ingress_protocol, pool, seconds),
    }
}

// `upstream_attempt_on` / `upstream_failure_on` — THE EMIT for this family, on EVERY plane — MOVED
// DOWN to the neutral substrate (`busbar_substrate::telemetry`) so the synchronous client legs
// (`mcp::client::wire`, `a2a::relay`) name them without reaching into core. They take NO `&App` and
// never did (both labels are operator-configured and bounded, so the emit is a pure `metrics` write);
// that is exactly what let them relocate. Re-exported here so core's own `App`-holding wrappers
// ([`upstream_attempt`]/[`upstream_failure`], which resolve the lane label out of `app.lanes`) and
// `crate::telemetry::*` call sites resolve unchanged.
pub use busbar_substrate::telemetry::{outcome_of, upstream_attempt_on, upstream_failure_on};

/// `busbar_upstream_attempts_total` for one dispatch attempt on `(pool label, lane)`.
pub fn upstream_attempt(app: &App, pool_label: &str, lane_idx: usize) {
    match app.tslots.lane_family(pool_label, lane_idx) {
        Some(fam) if fam.attempts.is_valid() => fam.attempts.incr(),
        _ => upstream_attempt_on(
            pool_label,
            app.engine_tables_view()
                .lane_view(lane_idx)
                .map(|l| l.model)
                .unwrap_or(""),
        ),
    }
}

/// `busbar_upstream_failures_total` for one classified failure on `(pool label, lane)`.
pub fn upstream_failure(app: &App, pool_label: &str, lane_idx: usize, disposition: &'static str) {
    let fam = app.tslots.lane_family(pool_label, lane_idx);
    let di = DISPOSITIONS.iter().position(|d| *d == disposition);
    match (fam, di) {
        (Some(fam), Some(di)) if fam.failures[di].is_valid() => fam.failures[di].incr(),
        _ => upstream_failure_on(
            pool_label,
            app.engine_tables_view()
                .lane_view(lane_idx)
                .map(|l| l.model)
                .unwrap_or(""),
            disposition,
        ),
    }
}

/// `busbar_breaker_trips_total` for one logical Closed→Open trip on `(pool label, lane)`.
pub fn breaker_trip(app: &App, pool_label: &str, lane_idx: usize) {
    match app.tslots.lane_family(pool_label, lane_idx) {
        Some(fam) if fam.trips.is_valid() => fam.trips.incr(),
        _ => metrics::counter!(
            crate::metrics::BREAKER_TRIPS_TOTAL,
            "pool" => pool_label.to_owned(),
            "lane" => app.engine_tables_view().lane_view(lane_idx).map(|l| l.model.to_owned()).unwrap_or_default()
        )
        .increment(1),
    }
}

/// `busbar_failovers_total` for one failover event on `pool label`, by reason.
pub fn failover(app: &App, pool_label: &str, reason: &'static str) {
    let slots = app.tslots.failover.get(pool_label);
    let ri = REASONS.iter().position(|r| *r == reason);
    match (slots, ri) {
        (Some(slots), Some(ri)) if slots[ri].is_valid() => slots[ri].incr(),
        _ => metrics::counter!(
            crate::metrics::FAILOVERS_TOTAL,
            "pool" => pool_label.to_owned(),
            "reason" => reason
        )
        .increment(1),
    }
}

/// `busbar_translations_total` for one cross-protocol hop. Both names come from the fixed protocol
/// vocabulary, so the slots are config-independent: one process-lifetime table over
/// `KNOWN_PROTOCOLS × KNOWN_PROTOCOLS` (from ≠ to), resolved by a short linear scan (≤30 static-str
/// compares — no hash, no allocation). Unknown (plugin) protocol names fall back to the macro.
pub fn translation(from: &str, to: &str) {
    static SLOTS: OnceLock<Vec<(&'static str, &'static str, CounterSlot)>> = OnceLock::new();
    let table = SLOTS.get_or_init(|| {
        let mut v = Vec::new();
        for f in crate::proto::known_protocols() {
            for t in crate::proto::known_protocols() {
                if f != t {
                    v.push((
                        *f,
                        *t,
                        counter_slot(
                            crate::metrics::TRANSLATIONS_TOTAL,
                            &[("from", f), ("to", t)],
                        ),
                    ));
                }
            }
        }
        v
    });
    match table
        .iter()
        .find(|(f, t, slot)| *f == from && *t == to && slot.is_valid())
    {
        Some((_, _, slot)) => slot.incr(),
        None => metrics::counter!(
            crate::metrics::TRANSLATIONS_TOTAL,
            "from" => from.to_string(),
            "to" => to.to_string()
        )
        .increment(1),
    }
}

#[cfg(test)]
#[path = "tests/telemetry_tests.rs"]
mod tests;
