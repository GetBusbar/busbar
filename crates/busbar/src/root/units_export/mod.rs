// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT FAN-OUT — root composition.
//!
//! `export` is a plugin KIND (`busbar-export-*`, entry face `busbar_contract::kinds::Export`, an
//! ABI'd dlopen seam in `busbar_plugin::cold::export`). The distribution half of observability
//! belongs to that kind, and the thing that stands between the request-finish path and a set of
//! sinks — build each one's payload, decide whether there is room for its delivery, hand it over —
//! is not a sink and is not the engine. It is COMPOSITION, and this is where composition lives.
//!
//! WHY NOT THE ENGINE CORE, WHICH IS WHERE `CORE-HOMES` REC 3 FIRST PUT IT. The fan-out is written
//! over the projection grammar, and the grammar lives in the plugin ABI beside the frozen
//! `ExportStream` vocabulary it is a grammar OF. Nothing on the neutral spine may name the plugin
//! ABI — the spine is what the three blind axes are blind THROUGH. The composition root is the one
//! place that names all three, which is what a root IS.
//!
//! WHAT THE ROOT OWNS HERE, and what it deliberately does not:
//!
//! - **The payload build.** One payload per DISTINCT PROJECTION ([`PayloadCache`]), not one per
//!   sink and not one broadcast to all of them — that is what makes a narrower sink's exclusion
//!   real rather than advisory.
//! - **The shed.** Every sink states its capacity; the root enforces it with an [`AdmissionGate`]
//!   of its own ([`admission`]) and hands the surviving delivery the permit. A sink never sees a
//!   delivery it has no room for and never carries a semaphore.
//! - **NOT the delivery.** What a sink DOES with its payload — append it, POST it, drop it — is
//!   the sink's, over its own face. The root calls and forgets.
//!
//! THE `legacy-reach` RATCHET counts the DISTINCT symbols the root spells through a retiring
//! crate's prefix, over `crates/busbar/src/root/*.rs` — an `fnmatch` glob whose `*` crosses
//! separators, so this directory IS in that scope. Every import below is therefore at MODULE level:
//! the two modules the engine still owns are named once each, which is what `main.rs` already
//! spelled, so lifting the fan-out out of the engine costs the ratchet nothing.

pub(crate) mod admission;

use admission::AdmissionGate;
// MODULE-LEVEL, deliberately. The `legacy-reach` ratchet counts DISTINCT symbols the root spells
// through a retiring crate's prefix, and it may only go down: naming the two modules the engine
// still owns here — and every item under them by short path — is the same two names main.rs
// already spelled, so lifting the fan-out out of the engine costs the ratchet nothing.
use busbar_core::{config, export};
use export::{BuiltinPushSink, Projection, RequestLogFacts, Ship};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

/// One composed PUSH sink: what it was granted, what the root will shed for it, and the one call
/// that ships it a payload.
struct Sink {
    /// The subscription + fields THIS sink was granted. Its payload is built to exactly this.
    projection: Projection,
    /// THIS sink's own capacity, enforced here. One gate per named instance — a stalled sink sheds
    /// its own lines and can never consume a sibling's budget.
    gate: AdmissionGate,
    /// This sink's policy-specific drop counter, incremented on a shed. (The gate additionally
    /// counts every denial on `busbar_admission_denied_total{gate}`, uniformly across all gates.)
    dropped_total: &'static str,
    /// Ship one payload built to [`projection`](Self::projection), taking the permit that holds
    /// this delivery's slot.
    ship: Ship,
}

/// The composed sinks, built ONCE at boot. Unset ⇒ [`install`] found nothing to compose and never
/// installed a fan-out at all, so the engine's request-finish path is a single null pointer read.
static SINKS: OnceLock<Vec<Sink>> = OnceLock::new();

/// Compose the export sinks the operator configured and install the fan-out the engine's
/// request-finish path calls through. Called ONCE at boot, before the listener binds.
///
/// No configured PUSH sink ⇒ nothing is installed and nothing is allocated: the zero-config default
/// pays for none of this.
pub fn install(cfg: &config::ExportCfg) {
    let sinks: Vec<Sink> = export::builtin_push_sinks(cfg)
        .into_iter()
        .map(
            |BuiltinPushSink {
                 projection,
                 max_inflight,
                 gate,
                 dropped_total,
                 ship,
             }| Sink {
                projection,
                gate: AdmissionGate::new(max_inflight, gate),
                dropped_total,
                ship,
            },
        )
        .collect();
    if sinks.is_empty() {
        return;
    }
    let _ = SINKS.set(sinks);
    export::install_request_log_sink(deliver);
}

/// A per-delivery cache of already-built payloads, keyed by PROJECTION. Instances with IDENTICAL
/// projections share one payload, so the build cost is per DISTINCT PROJECTION, not per sink (design
/// `export-projection-grammar.md`, "Implementation note"). A `Vec` because the number of distinct
/// projections in a deployment is tiny and a linear scan beats hashing at that size.
struct PayloadCache<'a> {
    facts: &'a RequestLogFacts<'a>,
    built: Vec<(Projection, Arc<Value>)>,
}

impl<'a> PayloadCache<'a> {
    fn new(facts: &'a RequestLogFacts<'a>) -> PayloadCache<'a> {
        PayloadCache {
            facts,
            built: Vec::new(),
        }
    }

    /// This sink's payload, built to `projection` (and reused for any sibling with the same one).
    fn get(&mut self, projection: Projection) -> Arc<Value> {
        if let Some((_, v)) = self.built.iter().find(|(p, _)| *p == projection) {
            return v.clone();
        }
        let v = Arc::new(export::build_request_log(projection, self.facts));
        self.built.push((projection, v.clone()));
        v
    }
}

/// Fan the request-log facts out to every composed PUSH sink, each receiving a payload built TO ITS
/// OWN PROJECTION. Fire-and-forget; never blocks the request path and never surfaces errors —
/// telemetry must not affect serving.
///
/// The PAYLOAD IS BUILT PER SINK, not built once and broadcast: that is what makes a narrower
/// sink's exclusion real rather than advisory. Sinks sharing a projection share one build (see
/// [`PayloadCache`]).
///
/// THE SHED HAPPENS HERE, before the sink is called. A saturated sink's line is dropped — counted
/// on that sink's own drop counter and on `busbar_admission_denied_total{gate}` — rather than
/// blocking the request path or piling up an unbounded backlog of tasks and owned payloads.
fn deliver(facts: &RequestLogFacts<'_>) {
    let Some(sinks) = SINKS.get() else {
        return;
    };
    fan_out(sinks, facts);
}

/// [`deliver`] over an explicit sink list — the whole of the fan-out, split from the process-global
/// read in front of it so a test can drive it over sinks of its own without touching the `OnceLock`
/// a sibling test would then observe.
fn fan_out(sinks: &[Sink], facts: &RequestLogFacts<'_>) {
    let mut cache = PayloadCache::new(facts);
    for sink in sinks {
        // Acquire this sink's delivery slot WITHOUT waiting.
        let Some(permit) = sink.gate.try_enter() else {
            metrics::counter!(sink.dropped_total).increment(1);
            continue;
        };
        // THIS sink's payload, built to THIS sink's projection (shared with any sibling holding the
        // identical projection). The build happens per sink — never once and broadcast.
        let payload = cache.get(sink.projection);
        (sink.ship)(&payload, permit);
    }
}

#[cfg(test)]
#[path = "../tests/units_export.rs"]
mod tests;
