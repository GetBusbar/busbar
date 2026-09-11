// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE-DECLARATION FACE — what a plugin says about the HTTP it serves, and how a host hands
//! it a matched request.
//!
//! A plugin of kind `export` or `hook` may serve HTTP. It does not mount anything: it DECLARES,
//! as data, the `{path, method, auth}` triples it will answer ([`RouteDecl`]), and the host mounts
//! what it was told, confines it to the namespace its kind allows, refuses a collision, enforces
//! the declared auth bar, and only then hands the request back through [`HttpDispatch`]. A
//! declaration is a statement, never a mount: the plugin's self-report is never trusted to PLACE a
//! route, only to describe one.
//!
//! THE FACE IS HERE, on the kind-neutral loader, and not on the engine, because it is the same
//! face for every plugin that has one. A dlopen'd sink reaches it over the ABI
//! ([`crate::DynExport::routes`] / [`crate::DynExport::handle_http`]); an in-tree sink the
//! composition root builds reaches it by implementing [`HttpDispatch`] directly. NEITHER is a
//! special case of the other, and that is the whole point: the host mounts a declared route by
//! KIND, never by name, so no host file may contain a branch that spells one sink.
//!
//! WHAT A DISPATCHER IS HANDED, AND WHAT IT IS NOT. It is handed the request and a
//! [`ProcessSnapshot`] — the reading, taken at the moment of the request, of the process it was
//! mounted into. It is NOT handed the engine's `App`, and no arm of this face can be made to yield
//! one: a plugin of a kind is identical to every other plugin of that kind, and "this one gets the
//! engine's state because it is built in" is exactly the special case the face exists to abolish.

use crate::{HttpEndpointRequest, HttpEndpointResponse, Route};
use std::sync::Arc;

/// The KIND of the plugin that declared a route. It drives namespace confinement (a hook is
/// confined under `/hooks/<name>/*`; an observability sink may claim the well-known `/metrics`),
/// which is a rule about the KIND and never about the individual plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteKind {
    /// A `kind: export` sink.
    Export,
    /// A `kind: hook` policy.
    Hook,
}

/// THE READING A MOUNTED ROUTE TAKES OF THE PROCESS IT WAS MOUNTED INTO, at the moment of the
/// request — the kind-neutral snapshot that replaces handing a dispatcher the engine's own state.
///
/// It is a snapshot and not a handle: the host resolves it per request from the CURRENT generation,
/// so a hot-swap can never leave a dispatcher reading a retired one, and nothing here can be held
/// past the call. Every method is an ANSWER, never a capability — there is nothing on this face a
/// dispatcher can use to change the process.
pub trait ProcessSnapshot {
    /// This process's metric registry, rendered in the Prometheus text exposition, with whatever it
    /// derives at observation time refreshed first. `None` when this process has no registry
    /// installed — which is a DIFFERENT answer from an empty one, and the caller decides what to
    /// say about it.
    ///
    /// It is the host that owns the registry and the reads behind it (a governance store, a
    /// breaker's atomics), which is why this is asked of the process rather than done by the
    /// plugin: a sink of any kind may name no store, no recorder and no engine.
    fn metrics(&self) -> Option<String>;
}

/// Serve one inbound request the host already auth-gated and matched to this plugin's declared
/// route. Object-safe, so a live route table holds `Arc<dyn HttpDispatch>` and resolves it per
/// request. Called on a blocking thread by the host, so a synchronous read inside an
/// implementation cannot stall an async executor.
pub trait HttpDispatch: Send + Sync {
    /// Answer `req`, reading whatever it needs of the running process off `process`.
    fn handle_http(
        &self,
        req: &HttpEndpointRequest,
        process: &dyn ProcessSnapshot,
    ) -> HttpEndpointResponse;
}

/// ONE ROUTE A PLUGIN DECLARES, with the live dispatcher that will answer it — the whole of what a
/// host needs to mount a plugin's HTTP surface, BEFORE collision and confinement resolution.
#[derive(Clone)]
pub struct RouteDecl {
    /// The declaring plugin's config name: the namespace root confinement is measured from, and the
    /// owner a collision diagnostic names.
    pub owner: String,
    /// The declaring plugin's kind, which is what confinement is a rule about.
    pub kind: RouteKind,
    /// The declared route.
    pub route: Route,
    /// The dispatcher that answers it.
    pub dispatch: Arc<dyn HttpDispatch>,
}

impl std::fmt::Debug for RouteDecl {
    /// Hand-rolled because a dispatcher is a trait object with no `Debug`: the three DECLARED facts
    /// are what a reader of a diagnostic wants, and the dispatcher's address is not one of them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteDecl")
            .field("owner", &self.owner)
            .field("kind", &self.kind)
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "tests/routes_tests.rs"]
mod tests;
