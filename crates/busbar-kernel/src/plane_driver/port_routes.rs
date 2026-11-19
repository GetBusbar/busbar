// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane's routes, and where core mounts them (IF §8.6 RouteRec, §12.11, §12.24, §12.27; PLANE-DRIVER.md
//! slice 8). [`plan`] reads `PlanePort::routes()` once, at open, with the admission and challenge each
//! route states (`PlanePort::route_admission`, `PlanePort::route_challenge`), and sorts them:
//!
//! * `data`: mounted on the data listeners (a `ROUTE_CATALOG` route is answered with `render(RENDER_CATALOG)`);
//! * `admin`: `ROUTE_ADMIN`, mounted on the admin router under the instance's admin mount, behind the admin scope
//!   middleware, with the plane's `D_ADMIN_OPENAPI` fragment merged into the admin document;
//! * `upgrade`: `ROUTE_UPGRADE`, the §12.27 WebSocket upgrade sequence;
//! * `line`: the one `ROUTE_LINE` route, bound to the process's stdin/stdout carrier, **never mounted**;
//! * `recovery`: `ROUTE_RECOVERY` routes, where core delivers durable-work polls ([`recovery_request`]),
//!   **never mounted** (no client can reach them).
//!
//! The adapter already refuses a describe that breaks these rules; the plan re-checks them, because a mount table
//! is where a wrong flag becomes an exposed route. Each mounted route carries its effective class set (§12.11):
//! the operator's `routes.<id>.auth` when it lies inside the route's mask, else the lowest bit plus `AUTH_TICKET`
//! when the mask holds both `AUTH_PRINCIPAL` and `AUTH_TICKET`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_abi::plane::{
    ADMIN_HYDRATE, AUTH_OPERATOR, AUTH_PRINCIPAL, ROUTE_ADMIN, ROUTE_CATALOG, ROUTE_LINE,
    ROUTE_RECOVERY, ROUTE_UPGRADE, RQ_RECOVERY,
};
use busbar_ports::plane::{PlaneIn, PlanePort, RouteInfo};
use busbar_ports::{CallCx, PortError};

use super::port_auth::effective_classes;
use crate::auth::route_record::{wire, PlaneMethods, RecordRefused, RouteRecord};

/// How long the plane has to answer one admin call.
const ADMIN_GRACE: Duration = Duration::from_secs(30);

/// One route as core mounts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mounted {
    pub route: u32,
    pub methods: u32,
    pub flags: u32,
    pub auth: u32,
    /// The class set the route runs under (§12.11).
    pub effective: u32,
    pub pattern: Box<str>,
    /// D_ROUTE_CRED_HEADER, lowercase.
    pub cred_header: Option<Box<str>>,
    /// The route's declared resource kinds: the route's own list, shared.
    pub resource_kinds: Arc<[Box<str>]>,
    /// A `ROUTE_CATALOG` route.
    pub catalog: bool,
    /// The route's record as its plane stated it (D_ROUTE_ADMISSION, D_ROUTE_CHALLENGE), built and
    /// validated when the route was mounted ([`plan`]). It is the one source of the route's
    /// admission: a route that states none is not mounted, it refuses its plane.
    pub record: RouteRecord,
}

/// The route table of one plane instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortRoutes {
    pub data: Vec<Mounted>,
    pub admin: Vec<Mounted>,
    pub upgrade: Vec<Mounted>,
    pub line: Option<Mounted>,
    pub recovery: Vec<Mounted>,
    /// The OpenAPI fragment of the admin routes.
    pub admin_openapi: Option<String>,
}

/// Why a plane's routes cannot be mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRefused {
    /// The route states no admission (plane 2.0: one D_ROUTE_ADMISSION per route, no default).
    NoAdmission { route: u32 },
    /// The route's stated record is incomplete or contradicts itself.
    Record { route: u32, why: RecordRefused },
    /// The route's mask names no usable class, or the operator's choice lies outside it.
    Classes { route: u32 },
    /// ROUTE_ADMIN, ROUTE_LINE, ROUTE_RECOVERY or ROUTE_UPGRADE beside another ROUTE_* bit (CATALOG included).
    Flags { route: u32 },
    /// A ROUTE_ADMIN route whose auth mask is not exactly AUTH_OPERATOR.
    AdminAuth { route: u32 },
    /// A ROUTE_RECOVERY route whose auth mask is not exactly AUTH_PRINCIPAL.
    RecoveryAuth { route: u32 },
    /// Resource admission requires unambiguous kinds on a principal HTTP data route.
    Resources { route: u32 },
    /// ROUTE_ADMIN routes and no D_ADMIN_OPENAPI.
    AdminWithoutOpenapi,
    /// More than one ROUTE_LINE route.
    TwoLines,
}

impl std::fmt::Display for RouteRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAdmission { route } => write!(f, "route {route} states no admission"),
            Self::Record { route, why } => write!(f, "route {route}: {why}"),
            Self::Classes { route } => write!(f, "route {route} names no usable auth class"),
            Self::Flags { route } => {
                write!(f, "route {route} combines route flags that do not combine")
            }
            Self::AdminAuth { route } => write!(f, "admin route {route} is not operator-only"),
            Self::RecoveryAuth { route } => {
                write!(f, "recovery route {route} is not principal-only")
            }
            Self::Resources { route } => {
                write!(f, "route {route} has invalid resource admission metadata")
            }
            Self::AdminWithoutOpenapi => f.write_str("admin routes without an OpenAPI fragment"),
            Self::TwoLines => f.write_str("more than one line route"),
        }
    }
}

impl std::error::Error for RouteRefused {}

/// The record `r` states through its port: the admission and challenge its plane declared
/// (`PlanePort::route_admission`, `PlanePort::route_challenge`), read once, here.
///
/// The loader already judged the admission by the contract's load rules against the image's own
/// methods (`vocab::route1::check`); the mount table sees a port, not a method table, so the three
/// rules that ask what the image implements are the loader's alone and are not asked again here.
fn stated_record(port: &dyn PlanePort, r: &RouteInfo) -> Result<RouteRecord, RouteRefused> {
    let (scope, money, callers, walk_kind) = port
        .route_admission(r.route)
        .ok_or(RouteRefused::NoAdmission { route: r.route })?;
    let refused = |why| RouteRefused::Record {
        route: r.route,
        why,
    };
    let item = wire::AdmissionItem {
        route: r.route,
        scope,
        money,
        callers,
        walk_kind,
    };
    let record = RouteRecord::from_wire(
        r.flags,
        r.auth,
        r.cred_header.as_deref(),
        &r.resource_kinds,
        &item,
        port.route_challenge(r.route),
    )
    .ok_or_else(|| refused(RecordRefused::Admission))?;
    record
        .validate(
            r.methods,
            PlaneMethods {
                render: true,
                select_resources: true,
                upstream: true,
            },
        )
        .map_err(refused)?;
    Ok(record)
}

/// Sorts `port`'s routes into the mount table, each with the record it states. `configured` is the
/// operator's `routes.<id>.auth` class set, if any.
///
/// # Errors
/// A [`RouteRefused`] naming the first route that cannot be mounted.
pub fn plan(
    port: &dyn PlanePort,
    configured: &dyn Fn(u32) -> Option<u32>,
) -> Result<PortRoutes, RouteRefused> {
    const SPECIAL: u32 = ROUTE_ADMIN | ROUTE_LINE | ROUTE_RECOVERY | ROUTE_UPGRADE;
    const ALL: u32 = SPECIAL | ROUTE_CATALOG;
    let admin_openapi = port.admin_openapi();
    let mut table = PortRoutes {
        admin_openapi: admin_openapi.map(str::to_owned),
        ..PortRoutes::default()
    };
    let mut any_admin = false;
    for r in port.routes() {
        if !r.resource_kinds.is_empty() {
            let mut kinds = std::collections::BTreeSet::new();
            if r.flags != 0
                || r.auth != AUTH_PRINCIPAL
                || r.resource_kinds.len() > 8
                || r.resource_kinds.iter().any(|kind| {
                    !busbar_plugin_abi::resource_admission::valid_kind(kind) || !kinds.insert(kind)
                })
            {
                return Err(RouteRefused::Resources { route: r.route });
            }
        }
        let special = r.flags & SPECIAL;
        let alone = special == 0 || (r.flags & ALL == special && special.count_ones() == 1);
        if !alone {
            return Err(RouteRefused::Flags { route: r.route });
        }
        let effective = effective_classes(r.auth, configured(r.route))
            .map_err(|_| RouteRefused::Classes { route: r.route })?;
        if special == ROUTE_ADMIN && r.auth != AUTH_OPERATOR {
            return Err(RouteRefused::AdminAuth { route: r.route });
        }
        if special == ROUTE_RECOVERY && r.auth != AUTH_PRINCIPAL {
            return Err(RouteRefused::RecoveryAuth { route: r.route });
        }
        let mounted = Mounted {
            record: stated_record(port, r)?,
            route: r.route,
            methods: r.methods,
            flags: r.flags,
            auth: r.auth,
            effective,
            pattern: r.pattern.clone(),
            cred_header: r.cred_header.clone(),
            resource_kinds: Arc::clone(&r.resource_kinds),
            catalog: r.flags & ROUTE_CATALOG != 0,
        };
        match special {
            ROUTE_ADMIN => {
                any_admin = true;
                table.admin.push(mounted);
            }
            ROUTE_UPGRADE => table.upgrade.push(mounted),
            ROUTE_LINE => {
                if table.line.replace(mounted).is_some() {
                    return Err(RouteRefused::TwoLines);
                }
            }
            ROUTE_RECOVERY => table.recovery.push(mounted),
            _ => table.data.push(mounted),
        }
    }
    if any_admin && admin_openapi.is_none() {
        return Err(RouteRefused::AdminWithoutOpenapi);
    }
    Ok(table)
}

/// The request core originates to deliver a durable-work poll (§12.24 step 3): a GET on the recovery route the
/// WORK_OPEN target matched, with that target's path and query, `RQ_RECOVERY`, `work` = the reference WORK_OPEN
/// answered, identity = the principal restored from the work row. It has no client; the caller discards the client
/// side.
#[must_use]
pub fn recovery_request<'a>(
    route: &'a Mounted,
    work: &'a str,
    identity: &'a [u8],
    target: &'a str,
    request_id: u64,
) -> PlaneIn<'a> {
    let (path, query) = target_parts(target);
    PlaneIn {
        route: route.route,
        flags: RQ_RECOVERY,
        auth: route.effective,
        method: "GET",
        path,
        query,
        headers: &[],
        identity,
        request_id,
        carrier: 0,
        work,
        ticket_record: &[],
    }
}

/// A WORK target's path and query (no fragment): `/jobs/1?cursor=2` is (`/jobs/1`, `cursor=2`).
#[must_use]
fn target_parts(target: &str) -> (&str, &str) {
    let target = target.split('#').next().unwrap_or_default();
    target.split_once('?').unwrap_or((target, ""))
}

/// The recovery route a WORK target's path lies on (the same match WORK_OPEN was admitted under), if any.
#[must_use]
pub fn recovery_route<'r>(routes: &'r PortRoutes, target: &str) -> Option<&'r Mounted> {
    use busbar_contract::route::{path_matches, PATH_PATTERN};
    let (path, _) = target_parts(target);
    routes
        .recovery
        .iter()
        .find(|route| path_matches(PATH_PATTERN, &route.pattern, path))
}

fn admin_cx() -> CallCx {
    // The node's monotonic clock, read once for this call: the deadline is set from it and the
    // plane is handed it.
    let mono_ns = crate::store::monotonic_ns();
    CallCx {
        deadline: busbar_contract::mono_instant::instant_at(mono_ns) + ADMIN_GRACE,
        request_id: 0,
        stack: Default::default(),
        mono_ns,
    }
}

/// `admin(ADMIN_HYDRATE)`: `stored` = the records the plane asked core to keep, handed back at start.
///
/// # Errors
/// The plane refused, failed or faulted.
pub async fn admin_hydrate(port: &dyn PlanePort, stored: &[u8]) -> Result<Vec<u8>, PortError> {
    port.admin(admin_cx(), ADMIN_HYDRATE, stored).await
}

#[cfg(test)]
#[path = "tests/port_routes_tests.rs"]
mod tests;
