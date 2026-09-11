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
//! It asks its composer for exactly ONE thing, [`Scrape::registry`]: this process's exposition,
//! with whatever it derives at observation time already refreshed. That call is made HERE, inside
//! `render`, and not by the composer before it: the refresh is part of answering a scrape, it must
//! not happen for a request this sink is going to refuse, and a sink that let its composer decide
//! when to read would be a sink whose freshness guarantee lives somewhere it cannot see.
//!
//! WHAT IS POLICY, AND THEREFORE IS HERE. Three decisions, and they are the reason this file is not
//! four lines of plumbing:
//!
//!   * A scrape with no registry behind it is REFUSED, not answered empty. The recorder install is
//!     a one-time background step (its clock calibration must not delay a listener bind), and on a
//!     thread-per-core data plane every worker accepts the instant its own bind completes — so a
//!     scrape can land before the install finishes. `200` with an empty body reads to an operator
//!     as "this endpoint has nothing to say"; a refusal reads as "not yet, retry", which is the
//!     true one. The two states must be distinguishable ON THE WIRE.
//!   * The refusal carries [`RETRY_AFTER_SECS`] and NO body. There is no exposition to show and a
//!     real one is not being padded out with a fake.
//!   * An exposition is [`CONTENT_TYPE`]. That string is the Prometheus text format's own, and it
//!     is pinned by this release's scrape golden byte for byte.

/// The operator-facing module token this sink answers to, and the OWNER name a route-collision
/// diagnostic spells when a third-party plugin tries to claim a path this sink already declared.
pub const MODULE: &str = "prometheus";

/// The well-known Prometheus/OpenMetrics scrape path. It is the one path an export sink may claim
/// OUTSIDE its own `/exports/<name>/*` namespace, and the reason is not this sink's convenience:
/// external tooling — every scrape config in the world — expects `/metrics` at a fixed path.
pub const METRICS_PATH: &str = "/metrics";

/// The content type of a Prometheus text exposition. Pinned by the 1.5.5 scrape golden.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// How long a refused scraper is told to wait. The recorder install is sub-second, or (far more
/// rarely) has permanently failed and was logged at install time; a short retry is the right
/// operator action under either.
pub const RETRY_AFTER_SECS: u32 = 1;

/// The bar a host enforces before a request reaches this sink. Stated in the sink's OWN words: a
/// crate of kind `export` names no router, no auth chain and no wire vocabulary — not even the
/// name of the protocol its composer will serve it over — so it says what it NEEDS and its
/// composer says that in whatever language this process's front door speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// Unauthenticated.
    Open,
    /// A valid client token — the data-plane bar.
    Key,
}

/// ONE ROUTE THIS SINK DECLARES IT WILL SERVE. Data, not a mount: the sink states it and its
/// composer decides whether this process can honour it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteStatement {
    /// The absolute path.
    pub path: &'static str,
    /// The uppercase request-method token.
    pub method: &'static str,
    /// The bar the host enforces before the request arrives here.
    pub auth: Auth,
}

/// EVERY ROUTE THIS SINK DECLARES. One: the well-known scrape path, behind the data-plane token bar
/// — which is the bar `/metrics` has always carried, and lowering it here would be this crate
/// quietly publishing a deployment's spend and breaker state to anyone who can reach the port.
pub const ROUTES: &[RouteStatement] = &[RouteStatement {
    path: METRICS_PATH,
    method: "GET",
    auth: Auth::Key,
}];

/// THE ONE READING OF THE PROCESS THIS SINK TAKES. Implemented by whoever composed the sink into a
/// process, because a registry is a property of a process and not of a sink.
pub trait Scrape {
    /// This process's metric registry as a Prometheus text exposition, with everything it derives
    /// at observation time refreshed FIRST — so what comes back is true as of this call and not as
    /// of some earlier one.
    ///
    /// `None` when no registry is installed. That is deliberately not the same value as `Some("")`:
    /// "nothing installed" and "installed and empty" are different facts about the process and this
    /// sink answers them differently.
    fn registry(&self) -> Option<String>;
}

/// WHAT THIS SINK SAYS, stated as what it is — a status, a header list and a body — and turned into
/// this process's own response type by its composer. The sink names no wire vocabulary of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The response status.
    pub status: u16,
    /// The response headers, in the order they were decided.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

/// The sink. Zero-sized: everything it would otherwise hold belongs to the process it was composed
/// into, and it reaches that through [`Scrape`] at the moment of the scrape rather than through a
/// handle baked in when it was built — so a configuration swap can never leave it answering from a
/// generation that has retired.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrometheusSink;

impl PrometheusSink {
    /// Answer one scrape.
    ///
    /// The reader runs HERE — `scrape.registry()` is called inside this method, once, and only on
    /// the path that is going to answer with it. A refused scrape does no work at all, which
    /// matters because the refresh behind that call walks a store.
    pub fn render(&self, scrape: &dyn Scrape) -> Served {
        match scrape.registry() {
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
