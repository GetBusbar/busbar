// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PULL HALF OF THE EXPORT FAN-OUT — the routes the composed sinks declare.
//!
//! A push sink states a delivery and the root puts it on a wire ([`super`]); a PULL sink states a
//! ROUTE and the root mounts it. Same composition, same place, one direction reversed — so both
//! live here, and the engine learns what it serves the same way either way: from a declaration the
//! root hands it, never from a branch inside it.
//!
//! WHAT THE ROOT OWNS HERE, and what it deliberately does not:
//!
//! - **The translation.** The sink states its route in ITS OWN words — a path, a method token, a
//!   bar — because a crate of kind `export` names no router and no wire vocabulary. The root says
//!   the same three facts in the words this process's router speaks. That translation is the whole
//!   of what a composer is for, and it is the reason the sink can be scraped by a busbar and by
//!   anything else without knowing which.
//! - **The reading of the process.** The sink asks for one thing — this process's registry — and
//!   the root is what can answer it, because a registry belongs to a process. The engine hands the
//!   root's dispatcher a kind-neutral reading of the live generation; the root presents that
//!   reading to the sink as the sink's own [`busbar_export_prometheus::Scrape`].
//! - **NOT the policy.** Whether a scrape with no registry behind it is an empty `200` or a
//!   refusal, what an exposition's content type is, how long a refused scraper waits — every one of
//!   those is the sink's, decided in the sink, and this file relays what it decided without
//!   inspecting it.
//!
//! THE ENGINE KNOWS NONE OF THIS. It does not know a `prometheus` sink exists, that `/metrics` is a
//! path anything claims, or that any declaration is built in: it confines what it was handed by
//! KIND, refuses a collision, mounts it and dispatches to it. That is what makes an export an
//! export rather than this one.

use super::config;
// THE ONE EXPORT FACE. A composed sink's route declarations and the answer it gives on one of them
// are read through `dyn Export`; after construction this module cannot tell which sink it holds.
use busbar_contract::{Delivery, Export, ExportHost, RouteBar, ServeRequest};
use busbar_plugin_loader::{
    HttpDispatch, HttpEndpointRequest, HttpEndpointResponse, ProcessSnapshot, Route, RouteAuth,
    RouteDecl, RouteKind, RouteMethod,
};
use std::sync::Arc;

/// What the root hands over: a function of the resolved `export:` block to the routes the sinks
/// composed from it declare. Spelled here, in the root's own words, rather than through the
/// engine's alias for the same type — the root's reach into the retiring engine is a ratchet, and a
/// name for a type it already builds every part of is not worth one of its places.
type Declarer = Arc<dyn Fn(&config::ExportCfg) -> Vec<RouteDecl> + Send + Sync>;

/// THE DECLARER the composition root hands the engine: what the sinks composed from a given
/// `export:` block serve.
///
/// It is asked again on every config apply, with the NEW block, which is what makes removing an
/// instance take its route away.
pub fn declarer() -> Declarer {
    Arc::new(|cfg: &config::ExportCfg| {
        let mut decls = Vec::new();
        // One composed `prometheus` sink when the operator configured one. The sink is zero-sized,
        // so "composing" it is stating that it exists; everything it needs of this process it asks
        // for at the moment of a scrape.
        if cfg.prometheus.is_some() {
            let sink: Arc<dyn Export> = Arc::new(busbar_export_prometheus::PrometheusSink);
            decls.extend(declare(sink));
        }
        decls
    })
}

/// Say a sink's stated routes in the words this process's router speaks, and bind each to the
/// dispatcher that answers it. The CONTRACT's route vocabulary crosses into this process's router
/// vocabulary here and nowhere else — and it is one translation for every sink of the kind, not one
/// per sink, which is what putting the declaration on the face bought.
///
/// The owner is the sink's OWN registry key, read off `Plugin::key`: the name a collision
/// diagnostic spells is the name the sink answers to, never a string this composition invented
/// about it.
fn declare(sink: Arc<dyn Export>) -> Vec<RouteDecl> {
    let owner = sink.key().to_string();
    let dispatch: Arc<dyn HttpDispatch> = Arc::new(SinkRoute(sink.clone()));
    sink.routes()
        .iter()
        .map(|stated| RouteDecl {
            owner: owner.clone(),
            kind: RouteKind::Export,
            route: Route {
                path: stated.path.to_string(),
                method: method_of(stated.method),
                auth: match stated.bar {
                    RouteBar::Open => RouteAuth::None,
                    RouteBar::Key => RouteAuth::Key,
                },
            },
            dispatch: dispatch.clone(),
        })
        .collect()
}

/// The sink states its method as the uppercase token that rides the wire; this process's router
/// spells the same method as an enum. An unknown token is this composition's own bug, not an
/// operator's input — a sink's declared routes are compiled-in constants — so it is a panic at
/// composition time (before any listener binds) rather than a route quietly not mounted.
fn method_of(token: &str) -> RouteMethod {
    match token {
        "GET" => RouteMethod::Get,
        "POST" => RouteMethod::Post,
        "PUT" => RouteMethod::Put,
        "PATCH" => RouteMethod::Patch,
        "DELETE" => RouteMethod::Delete,
        other => {
            panic!("a composed export sink declared an HTTP method this root cannot say: {other}")
        }
    }
}

/// ANY composed sink, presented to the engine as a dispatcher. It holds the face and nothing else,
/// and resolves everything the sink needs from the reading the engine takes of the CURRENT
/// generation at the moment of the request.
struct SinkRoute(Arc<dyn Export>);

impl HttpDispatch for SinkRoute {
    fn handle_http(
        &self,
        req: &HttpEndpointRequest,
        process: &dyn ProcessSnapshot,
    ) -> HttpEndpointResponse {
        let served = self.0.serve(
            &ServeRequest {
                path: &req.path,
                method: &req.method,
                headers: &req.headers,
                body: &req.body,
            },
            &ProcessLoan(process),
        );
        HttpEndpointResponse {
            status: served.status,
            headers: served.headers,
            body: served.body,
        }
    }
}

/// WHAT THIS PROCESS LENDS A SINK ANSWERING A SCRAPE: its reading of itself, and no wire — a sink
/// serving a route has a caller to answer and nothing to push.
///
/// It borrows for the length of one dispatch: the sink cannot hold it, and what it reads is true as
/// of this request rather than as of whenever the route was mounted.
struct ProcessLoan<'a>(&'a dyn ProcessSnapshot);

impl ExportHost for ProcessLoan<'_> {
    /// Nothing. This loan is made for an INBOUND request, and a sink answering one has nowhere to
    /// send: the answer is the response, not a delivery.
    fn send(&self, _delivery: Delivery) -> bool {
        false
    }

    /// This process's exposition of the stream the sink asks for. The engine's reading is taken at
    /// the moment of the request and the refresh behind it happens inside the sink's `serve`, on
    /// the path that is going to answer with it.
    fn read(&self, _stream: &str) -> Option<String> {
        self.0.metrics()
    }
}

#[cfg(test)]
#[path = "../tests/units_export_routes.rs"]
mod tests;
