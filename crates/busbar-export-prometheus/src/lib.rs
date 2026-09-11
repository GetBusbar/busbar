// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BUILT-IN `prometheus` EXPORT SINK — a PULL sink: it is scraped rather than shipped to.
//!
//! WHAT A PULL SINK IS. A push sink states a delivery and its composer puts it on a wire. A pull
//! sink states a ROUTE and its composer mounts it; the delivery is the answer it gives when
//! somebody arrives on that route. So the two halves of this crate are the two halves of that
//! sentence: [`ROUTES`], the `GET /metrics` it declares, and [`PrometheusSink::render`], what it
//! says when the declared route is hit.
//!
//! WHAT IT DOES NOT DO, AND WHY THAT IS THE WHOLE DESIGN. It does not collect. It does not walk a
//! governance store, read a breaker's atomics, name a recorder or hold a registry — a sink of this
//! kind may name none of those, and a sink that could would be the engine wearing a crate's name.
//! It asks the HOST the face hands it for exactly ONE thing, `ExportHost::read("metrics")`: this
//! process's exposition, with whatever it derives at observation time already refreshed. That call
//! is made HERE, inside
//! `serve`, and not by the composer before it: the refresh is part of answering a scrape, it must
//! not happen for a request this sink is going to refuse, and a sink that let its composer decide
//! when to read would be a sink whose freshness guarantee lives somewhere it cannot see.
//!
//! WHAT IS POLICY, AND THEREFORE IS HERE. Three decisions, and they are the reason this file is not
//! four lines of plumbing:
//!
//!   * A scrape with no exposition behind it is REFUSED, not answered empty. The recorder install is
//!     a one-time background step (its clock calibration must not delay a listener bind), and on a
//!     thread-per-core data plane every worker accepts the instant its own bind completes — so a
//!     scrape can land before the install finishes. `200` with an empty body reads to an operator
//!     as "this endpoint has nothing to say"; a refusal reads as "not yet, retry", which is the
//!     true one. The two states must be distinguishable ON THE WIRE.
//!   * The refusal carries [`RETRY_AFTER_SECS`] and NO body. There is no exposition to show and a
//!     real one is not being padded out with a fake.
//!   * An exposition is [`CONTENT_TYPE`]. That string is the Prometheus text format's own, and it
//!     is pinned by this release's scrape golden byte for byte.

use busbar_contract::{
    AbiVersion, Ack, Export, ExportHost, ExportItem, Kind, Plugin, RouteBar, RouteStatement,
    ServeRequest, Served, EXPORT_ABI,
};

/// The operator-facing module token this sink answers to, and the OWNER name a route-collision
/// diagnostic spells when a third-party plugin tries to claim a path this sink already declared.
pub const MODULE: &str = "prometheus";

/// The well-known Prometheus/OpenMetrics scrape path. It is the one path an export sink may claim
/// OUTSIDE its own `/exports/<name>/*` namespace, and the reason is not this sink's convenience:
/// external tooling — every scrape config in the world — expects `/metrics` at a fixed path.
pub const METRICS_PATH: &str = "/metrics";

/// What this sink carries and what it asks its host to read — one frozen export token, named once
/// so the declaration and the reading can never disagree.
const METRICS: &[&str] = &["metrics"];

/// The content type of a Prometheus text exposition. Pinned by the 1.5.5 scrape golden.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// How long a refused scraper is told to wait. The recorder install is sub-second, or (far more
/// rarely) has permanently failed and was logged at install time; a short retry is the right
/// operator action under either.
pub const RETRY_AFTER_SECS: u32 = 1;

/// EVERY ROUTE THIS SINK DECLARES. One: the well-known scrape path, behind the data-plane token
/// bar — which is the bar `/metrics` has always carried, and lowering it here would be this crate
/// quietly publishing a deployment's spend and breaker state to anyone who can reach the port.
///
/// It is the CONTRACT's declaration vocabulary, not this crate's: every sink of the kind states a
/// route the same way, and the host translates one spelling rather than one per sink.
const ROUTES: &[RouteStatement] = &[RouteStatement {
    path: METRICS_PATH,
    method: "GET",
    bar: RouteBar::Key,
}];

/// The sink. Zero-sized: everything it would otherwise hold belongs to the process it was composed
/// into, and it reaches that through [`Scrape`] at the moment of the scrape rather than through a
/// handle baked in when it was built — so a configuration swap can never leave it answering from a
/// generation that has retired.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrometheusSink;

impl Plugin for PrometheusSink {
    fn key(&self) -> &'static str {
        MODULE
    }
    fn kind(&self) -> Kind {
        Kind::Export
    }
    fn abi(&self) -> AbiVersion {
        EXPORT_ABI
    }
}

/// THE FACE. What this sink carries, what it declares it will serve, what it says when the declared
/// route is hit — and, because it is a PULL sink and is scraped rather than delivered to, the half
/// of the face that says so by refusing.
impl Export for PrometheusSink {
    /// The aggregate exposition, in the frozen export vocabulary's own token — and the same token
    /// it asks its host to read when a scrape arrives.
    fn streams(&self) -> &'static [&'static str] {
        METRICS
    }

    /// A PULL SINK IS NEVER HANDED AN ITEM. It is scraped: nothing is pushed to it, so there is no
    /// record here that reached anywhere and [`Ack::Retry`] is the only true thing to say about
    /// one. Stated rather than defaulted, because a sink that is silent about half the face is a
    /// sink whose behaviour lives in somebody else's file.
    fn receive(&self, _item: ExportItem<'_>, _host: &dyn ExportHost) -> Ack {
        Ack::Retry
    }

    fn routes(&self) -> &'static [RouteStatement] {
        ROUTES
    }

    /// Answer one scrape.
    ///
    /// The reader runs HERE — `host.read` is called inside this method, once, and only on the path
    /// that is going to answer with it. A refused scrape does no work at all, which matters because
    /// the refresh behind that call walks a store.
    fn serve(&self, _req: &ServeRequest<'_>, host: &dyn ExportHost) -> Served {
        match host.read(METRICS[0]) {
            Some(exposition) => Served {
                status: 200,
                headers: vec![("content-type".to_string(), CONTENT_TYPE.to_string())],
                body: exposition.into_bytes(),
            },
            None => Served {
                status: 503,
                headers: vec![("retry-after".to_string(), RETRY_AFTER_SECS.to_string())],
                body: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
