// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};

pub type PlaneResponse = axum::response::Response;

pub type PlaneRouteFuture = Pin<Box<dyn Future<Output = PlaneResponse> + Send>>;

pub type PlaneRouteFn = Arc<dyn Fn(PlaneReqCtx) -> PlaneRouteFuture + Send + Sync>;

pub type PlaneRefuseFn =
    Arc<dyn Fn(busbar_contract::caps::ReasonCode, &str) -> PlaneResponse + Send + Sync>;

/// A KERNEL-SHAPED REFUSAL: what the kernel decided, outside the
/// auth chain and before any unit, for a request at `path` — the reason, the status and the words —
/// handed to the plane whose door owns the path to render the body.
#[derive(Clone, Copy, Debug)]
pub struct KernelRefusal<'a> {
    /// Why.
    pub reason: busbar_contract::caps::ReasonCode,
    /// The status the kernel answers.
    pub status: u16,
    /// The kernel's words.
    pub text: &'a str,
    /// The request path, as received (raw).
    pub path: &'a str,
    /// The request target the plane reads its path rule off (path and query).
    pub target: &'a str,
    /// The original sealed line, when the inbound caller already selected one.
    pub selected_line: Option<&'a crate::guest::Line>,
}

pub type PlaneRefuseByPathFn =
    Arc<dyn Fn(&KernelRefusal<'_>) -> Option<PlaneResponse> + Send + Sync>;

/// THE ROUTE IDENTITY a door route and its unit-less refusal share: the route's axum path pattern,
/// as mounted, and its method. One key for both, so the two cannot name different routes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DoorRouteId {
    /// The axum path pattern.
    pub path: String,
    /// The method.
    pub method: RouteMethod,
}

/// One door route's unit-less refusal, keyed by the route's identity ([`DoorRouteId`]): the data
/// router records it beside the route's admission bar, and the auth middleware renders a `401` it
/// decides on that route through it, instead of the residual data plane's envelope.
#[derive(Clone)]
pub struct PlaneRefusalSpec {
    /// The door route it words the `401` of.
    pub route: DoorRouteId,
    /// Its plane's rendering.
    pub refuse: PlaneRefuseFn,
    /// The issued-id prefix of the tickets the route takes: `Some` for a `CLAIM_TICKET` claim whose
    /// plane declares one; `None` = the route takes keys alone.
    pub ticket_prefix: Option<String>,
    /// THE SIGNED PATHS of its plane: the raw-affix target
    /// (`<prefix>*<suffix>`, `abi::plane::CLAIM_RAW_AFFIX`) of every
    /// claim the plane flags `abi::plane::CLAIM_SIGNED_INGRESS`, whatever this route's own path and
    /// verb. The auth middleware puts a request to a path one of them matches through the
    /// signed-request pre-step, by path and whatever its verb.
    pub signed_ingress: Arc<[String]>,
}

impl std::fmt::Debug for PlaneRefusalSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneRefusalSpec")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

pub fn pair_door_refusals(
    routes: &[PlaneRouteSpec],
    refusals: &[PlaneRefusalSpec],
) -> Result<(), String> {
    let credentialed: Vec<DoorRouteId> = routes
        .iter()
        .filter(|r| matches!(r.auth, RouteAuth::Key))
        .map(PlaneRouteSpec::route_id)
        .collect();
    let mut seen: std::collections::HashSet<&DoorRouteId> = std::collections::HashSet::new();
    for r in refusals {
        if !seen.insert(&r.route) {
            return Err(format!(
                "the door route {} {} has two refusal specs; one route words its 401 once",
                r.route.method.as_str(),
                r.route.path
            ));
        }
        if !credentialed.contains(&r.route) {
            return Err(format!(
                "a refusal spec names {} {}, which is no door route that takes a credential",
                r.route.method.as_str(),
                r.route.path
            ));
        }
    }
    if let Some(bare) = credentialed.iter().find(|id| !seen.contains(id)) {
        return Err(format!(
            "the door route {} {} takes a credential and has no refusal spec: its 401 would be \
             worded in another plane's dialect",
            bare.method.as_str(),
            bare.path
        ));
    }
    Ok(())
}

pub struct PlaneRouteSpec {
    pub path: String,

    pub method: RouteMethod,

    pub auth: RouteAuth,

    pub handler: PlaneRouteFn,
}

impl PlaneRouteSpec {
    #[must_use]
    pub(crate) fn route_id(&self) -> DoorRouteId {
        DoorRouteId {
            path: self.path.clone(),
            method: self.method,
        }
    }
}

pub struct PlaneReqCtx {
    pub request: crate::limits::process_admission::RequestLease,
    /// The actual live handle serving this request, distinct from its pinned engine snapshot.
    pub handle: Arc<crate::state::AppHandle>,
    pub path: String,

    pub uri: axum::http::Uri,

    pub method: RouteMethod,

    pub headers: HeaderMap,

    pub body: Bytes,

    pub gov: Option<busbar_contract::records::PlaneRequestCtx>,

    pub signed_authority: Option<crate::auth::SignedRequestAuthority>,

    pub principal: Option<busbar_contract::auth::AuthPrincipal>,

    pub caller_credential: Option<crate::auth::CallerCredential>,

    pub ticket: Option<Vec<u8>>,

    pub host_ticket_admission: Option<crate::host_services::HostTicketAdmission>,

    /// The consumed credential carriers the request presented, each with its `Authorization`
    /// scheme word (empty for any other carrier).
    pub consumed_fields: Vec<(axum::http::HeaderName, String)>,

    pub engine: Arc<dyn Any + Send + Sync>,

    pub slot: Arc<dyn Any + Send + Sync>,

    pub scheme: u8,
}

/// THE LISTENER'S SCHEME, as a request extension: the listener that accepted the connection
/// states, on every request it serves, whether the connector terminated connection security on
/// it (`SCHEME_SECURE`) or not (`SCHEME_PLAIN`), and [`PlaneReqCtx::scheme`] carries it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerScheme(pub u8);

#[cfg(test)]
#[path = "tests/plane_routes_pairing.rs"]
mod pairing_tests;
