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
//! - **NOT the delivery.** What a sink DOES with its payload — frame it as a POST, append it, drop
//!   it — is the sink's, over its own face. The root calls and forgets. The one exception is the
//!   SOCKET a webhook delivery goes out on: a connection pool is a property of this process and its
//!   egress posture, so the root opens it and hands the sink's framed request to it.
//!
//! THE `legacy-reach` RATCHET counts the DISTINCT symbols the root spells through a retiring
//! crate's prefix, over `crates/busbar/src/root/*.rs` — an `fnmatch` glob whose `*` crosses
//! separators, so this directory IS in that scope. Every import below is therefore at MODULE level:
//! the two modules the engine still owns are named once each, which is what `main.rs` already
//! spelled, so lifting the fan-out out of the engine costs the ratchet nothing.

pub(crate) mod admission;
mod reports;
pub mod routes;
pub mod traces;

use admission::AdmissionGate;
// THE ONE EXPORT FACE. Every composed sink is held as a `dyn Export` and every delivery goes
// through `receive`: after construction this module cannot tell which sink it is holding, which is
// the whole of what "the root mounts by KIND, never by name" means on this path.
use busbar_contract::{Delivery, Export, ExportHost, ExportItem};
// MODULE-LEVEL, deliberately. The `legacy-reach` ratchet counts DISTINCT symbols the root spells
// through a retiring crate's prefix, and it may only go down: naming the two modules the engine
// still owns here — and every item under them by short path — is the same two names main.rs
// already spelled, so lifting the fan-out out of the engine costs the ratchet nothing.
use busbar_core::{config, export, metrics};
use busbar_export_webhook::{WebhookSink, GATE as WEBHOOK_GATE};
use export::{ExportDeliverySend, Projection, RequestLogFacts};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

/// Run one delivery: the record, already built to the sink's projection, and the permit that holds
/// this delivery's slot.
///
/// It is the ROOT's decision and only the root's — WHICH THREAD the sink's `receive` runs on and
/// WHAT the sink is lent while it runs — because both are properties of this process. What the
/// sink DOES with the record is behind [`Export::receive`] and is not spelled here at all.
type Ship = Box<dyn Fn(&Arc<Value>, tokio::sync::OwnedSemaphorePermit) + Send + Sync>;

/// One composed PUSH sink: what it was granted, what the root will shed for it, which stream it
/// declared, and the one call that runs a delivery.
struct Sink {
    /// The subscription + fields THIS sink was granted. Its payload is built to exactly this.
    projection: Projection,
    /// THIS sink's own capacity, enforced here. One gate per named instance — a stalled sink sheds
    /// its own lines and can never consume a sibling's budget.
    gate: AdmissionGate,
    /// This sink's policy-specific drop counter, incremented on a shed. (The gate additionally
    /// counts every denial on `busbar_admission_denied_total{gate}`, uniformly across all gates.)
    dropped_total: &'static str,
    /// Run one delivery of a payload built to [`projection`](Self::projection), taking the permit
    /// that holds this delivery's slot.
    ship: Ship,
}

/// WHAT THE RECORD THIS FAN-OUT BUILDS IS, in the frozen export vocabulary's own token: the
/// per-request operational record. It is stated here because this is the module that BUILDS it —
/// every payload below is a request log and nothing else — and each sink composed here declares the
/// same token for itself, which its own cells assert.
const REQUEST_LOG: &str = "logs";

/// WHAT THIS PROCESS LENDS A SINK that has nothing to ask it for — the file sink, whose only
/// outside is the path it was configured with.
struct NoLoan;

impl ExportHost for NoLoan {
    fn send(&self, _delivery: Delivery) -> bool {
        false
    }
    fn read(&self, _stream: &str) -> Option<String> {
        None
    }
}

/// WHAT THIS PROCESS LENDS A WEBHOOK DELIVERY: the egress wire, for the length of ONE `receive`,
/// with the slot this delivery was admitted under riding along so the in-flight bound is a bound on
/// EXCHANGES and not on calls.
///
/// The socket is the reason this exists. A connection pool on the cold open-web posture is a
/// property of this process and its egress posture, which no crate of kind `export` may name — so
/// the sink states the delivery and this lends it the wire.
struct WireLoan {
    send: ExportDeliverySend,
    timeout: std::time::Duration,
    /// The slot, taken out exactly once by the single `send` a `receive` makes.
    permit: std::sync::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
    /// What this process does with the outcome the wire comes back with. Bound at composition, at
    /// the one point the sink's crate is named at all.
    outcome: Arc<dyn Fn(Result<u16, String>) + Send + Sync>,
}

impl ExportHost for WireLoan {
    fn send(&self, delivery: Delivery) -> bool {
        let Some(permit) = self.permit.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            // The slot is already spent: one admitted delivery is one exchange, and a second send
            // inside one `receive` would put a line on the wire nobody sheds for.
            return false;
        };
        let outcome = self.outcome.clone();
        (self.send)(
            delivery.target,
            delivery.headers,
            delivery.body,
            self.timeout,
            Box::new(permit),
            Box::new(move |result| outcome(result)),
        );
        true
    }

    fn read(&self, _stream: &str) -> Option<String> {
        None
    }
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
    let mut sinks = file_sinks(cfg);
    sinks.extend(webhook_sinks(cfg));
    if sinks.is_empty() {
        return;
    }
    let _ = SINKS.set(sinks);
    export::install_request_log_sink(deliver);
}

/// Compose one `busbar-export-file` sink per configured `request-log-file` instance.
///
/// The crate states its capacity, its retention bound and its gate label; the root builds it, holds
/// it, sheds for it, chooses the thread its blocking write runs on, and turns its reports into this
/// process's diagnostics and counters. None of those four is a sink's business, which is why the
/// crate names neither a runtime, nor a recorder, nor a diagnostics registry — nor, in fact,
/// anything at all outside the standard library.
fn file_sinks(cfg: &config::ExportCfg) -> Vec<Sink> {
    export::request_log_file_instances(cfg)
        .into_iter()
        .map(|instance| {
            // The ONE point this composition names the sink's crate: building it. Everything after
            // this line is a `dyn Export` and could be any sink of the kind.
            let sink: Arc<dyn Export> = Arc::new(busbar_export_file::FileSink::new(
                instance.path,
                instance.rotate_mb,
                Arc::new(reports::EngineFileReport),
            ));
            Sink {
                projection: instance.projection,
                gate: AdmissionGate::new(
                    busbar_export_file::MAX_INFLIGHT_APPENDS,
                    busbar_export_file::MODULE,
                ),
                dropped_total: metrics::FILE_LOGS_DROPPED_TOTAL,
                ship: Box::new(move |payload, permit| {
                    // The write is blocking and the request path is async, so it goes to the
                    // blocking pool. That is a decision about THIS process's runtime, which is
                    // exactly why the sink does not make it. The permit rides along and returns the
                    // slot when the task ends.
                    let sink = sink.clone();
                    let payload = payload.clone();
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        // Already built to THIS sink's projection, so an ungranted field is never
                        // written to disk. The record goes over the face; the sink frames it.
                        let line = payload.to_string();
                        let _ack = sink.receive(
                            ExportItem {
                                stream: REQUEST_LOG,
                                bytes: line.as_bytes(),
                            },
                            &NoLoan,
                        );
                    });
                }),
            }
        })
        .collect()
}

/// Compose one `busbar-export-webhook` sink per configured `request-log-webhook` instance.
///
/// The crate states its gate label and frames each delivery as the POST that carries it; the root
/// builds it, holds it, sheds for it, opens the socket, applies the deadline and turns its reports
/// into this process's diagnostics. The socket is the reason the send is not the crate's: a
/// connection pool on the cold open-web posture is the engine's egress client, which no crate of
/// kind `export` may name — so the root takes the client, and the sink keeps the framing.
///
/// No configured instance ⇒ NO client is built at all: the default config pays nothing.
fn webhook_sinks(cfg: &config::ExportCfg) -> Vec<Sink> {
    let instances = export::request_log_webhook_instances(cfg);
    if instances.is_empty() {
        return Vec::new();
    }
    compose_webhook_sinks(instances, export::export_delivery_send())
}

/// [`webhook_sinks`] over an explicit instance list and an explicit send — the whole of the webhook
/// composition, split from the config read and the client build in front of it so a test can drive
/// it over a send of its own and see the bytes that would have gone out on the wire.
fn compose_webhook_sinks(
    instances: Vec<export::RequestLogWebhookInstance>,
    send: ExportDeliverySend,
) -> Vec<Sink> {
    instances
        .into_iter()
        .map(|instance| {
            let projection = instance.projection;
            let max_inflight = instance.max_inflight;
            // The ONE point this composition names the sink's crate: building it, and binding the
            // one thing the face has no half for — what the sink makes of an outcome its wire came
            // back with. Everything after these lines is a `dyn Export`.
            let timeout = instance.timeout;
            let built = Arc::new(WebhookSink::new(
                instance.url,
                instance.display_url,
                instance.auth,
                instance.timeout,
                Arc::new(reports::EngineWebhookReport),
            ));
            let judge = built.clone();
            let outcome: Arc<dyn Fn(Result<u16, String>) + Send + Sync> =
                Arc::new(move |result| judge.observe(result));
            let sink: Arc<dyn Export> = built;
            let send = send.clone();
            Sink {
                projection,
                gate: AdmissionGate::new(max_inflight, WEBHOOK_GATE),
                dropped_total: metrics::WEBHOOK_LOGS_DROPPED_TOTAL,
                ship: Box::new(move |payload, permit| {
                    // Already built to THIS sink's projection, so an ungranted field is never put
                    // on the wire. The record goes over the face; the sink frames the delivery and
                    // puts it on the wire THIS loan lends it, because the wire is the root's and
                    // the framing is the sink's.
                    let body = payload.to_string();
                    let loan = WireLoan {
                        send: send.clone(),
                        timeout,
                        permit: std::sync::Mutex::new(Some(permit)),
                        outcome: outcome.clone(),
                    };
                    let _ack = sink.receive(
                        ExportItem {
                            stream: REQUEST_LOG,
                            bytes: body.as_bytes(),
                        },
                        &loan,
                    );
                }),
            }
        })
        .collect()
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
            ::metrics::counter!(sink.dropped_total).increment(1);
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
