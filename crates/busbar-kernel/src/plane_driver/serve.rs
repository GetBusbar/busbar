// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex, PoisonError};

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    FieldList, OutField, ServeIn, ServeOut, AUDIT_APPLIED, AUDIT_REJECTED, ROUTE_CARRIES_OWN_TOKEN,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane_calls::{Lent, PlaneCalls};

use super::{blob, refusal_status, BufferCaps, HeadFields, NO_FIELD};
use crate::auth::{AuthPrincipal, ConsumedCredentials};

/// One admin route of an instance's snapshot, in snapshot order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeRoute {
    /// The verb.
    pub verb: String,
    /// The target, relative to the admin mount; a `{param}` segment matches one segment.
    pub target: String,
    /// `ROUTE_PUBLIC` or `0`.
    pub flags: u32,
    /// The word its audit row names; empty = never audited.
    pub audit_verb: String,
}

/// One published plane instance: its current snapshot's routes and the calls that serve them.
#[derive(Clone)]
pub struct ServeTable {
    /// The instance.
    pub instance: String,
    /// The `audit_kind` its tail states: the audit row's action and resource prefix.
    pub audit_kind: String,
    /// The instance's calls.
    pub calls: Arc<dyn PlaneCalls>,
    /// The host buffers' capacities.
    pub caps: BufferCaps,
    /// The snapshot's admin routes, in its order.
    pub routes: Vec<ServeRoute>,
    /// The kernel's record write path and the instance a served request's record writes are keyed
    /// by (SEAM-L(t)); `None` = none: a request whose answer writes a record then answers 502.
    pub records: Option<(
        Arc<crate::host_services::KernelServices>,
        busbar_contract::services::Caller,
    )>,
}

impl std::fmt::Debug for ServeTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeTable")
            .field("instance", &self.instance)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

/// A route a snapshot may not publish: it overlaps `with` (an instance, or `kernel`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    /// The route's verb and target.
    pub route: (String, String),
    /// What it overlaps.
    pub with: String,
}

/// THE PUBLISHED INSTANCES' ADMIN TABLE: a value, never a process static. The boot generation is
/// built with one and every generation after it carries it ([`crate::state::App::serve_tables`]);
/// the composition root publishes its door planes into the boot generation's, and lends it (a clone
/// shares the one table) to what answers on it: the admin router's fallback and a stated admin
/// route read it off the live generation, the data listener's public mount holds it. Two
/// generations built apart hold two tables, each answering only for the instances published into
/// it.
///
/// A request reads the published snapshot without a lock and holds the one instance it is served
/// by (an `Arc`), never a copy of it; a publish or a withdraw replaces the snapshot, one at a time.
#[derive(Clone, Default)]
pub struct ServeTables(pub(crate) Arc<Published>);

/// The snapshot requests read, and the turn its writers take.
#[derive(Default)]
pub(crate) struct Published {
    pub(crate) now: arc_swap::ArcSwap<Snapshot>,
    pub(crate) writing: Mutex<()>,
}

/// ONE PUBLISHED SNAPSHOT: the instances' tables, in publication order, and the route index each
/// request resolves through (built with the snapshot, [`crate::off_path::plane_serve::snapshot`]).
#[derive(Default)]
pub(crate) struct Snapshot {
    pub(crate) tables: Vec<Arc<ServeTable>>,
    pub(crate) admin: RouteIndex,
    pub(crate) public: RouteIndex,
}

/// One class's routes, `(table, route)` in snapshot order, by their target's second `/`-separated
/// element: each literal element's bucket also holds, in order, every route whose element there is
/// a `{param}` (those alone are `any`); `short` holds the targets with no second element.
#[derive(Default)]
pub(crate) struct RouteIndex {
    pub(crate) by_segment: std::collections::BTreeMap<String, Vec<(usize, usize)>>,
    pub(crate) any: Vec<(usize, usize)>,
    pub(crate) short: Vec<(usize, usize)>,
}

impl RouteIndex {
    /// The routes `path` may fill: the one bucket its second element names.
    fn bucket(&self, path: &str) -> &[(usize, usize)] {
        match path.split('/').nth(1) {
            Some(segment) => self
                .by_segment
                .get(segment)
                .map_or(self.any.as_slice(), Vec::as_slice),
            None => &self.short,
        }
    }
}

/// The first route of `index` that `path` fills and `method` names, and whether any route of it
/// filled `path` at all (a wrong verb, then).
fn resolve<'p>(
    snapshot: &Snapshot,
    index: &RouteIndex,
    method: &str,
    path: &'p str,
) -> (Option<(Arc<ServeTable>, usize, &'p str)>, bool) {
    let mut named = false;
    for &(t, i) in index.bucket(path) {
        let table = &snapshot.tables[t];
        let route = &table.routes[i];
        let Some(name) = fill(&route.target, path) else {
            continue;
        };
        named = true;
        if route.verb.eq_ignore_ascii_case(method) {
            return (Some((Arc::clone(table), i, name)), true);
        }
    }
    (None, named)
}

impl std::fmt::Debug for ServeTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.0.now.load();
        f.debug_list()
            .entries(snapshot.tables.iter().map(|t| &t.instance))
            .finish()
    }
}

pub(crate) fn param(segment: &str) -> bool {
    segment.len() > 1 && segment.starts_with('{') && segment.ends_with('}')
}

fn fill<'p>(target: &str, path: &'p str) -> Option<&'p str> {
    let (mut t, mut p, mut first) = (target.split('/'), path.split('/'), None);
    loop {
        match (t.next(), p.next()) {
            (None, None) => return Some(first.unwrap_or("")),
            (Some(ts), Some(ps)) if param(ts) && !ps.is_empty() => {
                first.get_or_insert(ps);
            }
            (Some(ts), Some(ps)) if ts == ps => {}
            _ => return None,
        }
    }
}

fn lent_head(
    headers: &axum::http::HeaderMap,
    consumed: Option<&ConsumedCredentials>,
) -> HeadFields {
    let stripped;
    let headers = if ConsumedCredentials::fields_of(consumed, headers).is_empty() {
        headers
    } else {
        let mut copy = headers.clone();
        ConsumedCredentials::strip_from(consumed, &mut copy);
        stripped = copy;
        &stripped
    };
    headers
        .iter()
        .filter(|(n, _)| !NEVER_KEPT.contains(&n.as_str()))
        .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

/// A served request's target, `path` or `path?query`, as the pieces [`serve_authorized`] lends
/// joined.
fn target_of<'a>(path: &'a str, query: Option<&'a str>) -> [&'a [u8]; 3] {
    match query {
        Some(q) => [path.as_bytes(), b"?", q.as_bytes()],
        None => [path.as_bytes(), b"", b""],
    }
}

/// `pieces`, joined into the one owned buffer the crossing lends.
fn joined(pieces: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![0; pieces.iter().map(|p| p.len()).sum()];
    let mut at = 0;
    for piece in pieces {
        bytes[at..at + piece.len()].copy_from_slice(piece);
        at += piece.len();
    }
    bytes
}

impl ServeTables {
    pub async fn answer(&self, req: Request) -> Option<Response> {
        use crate::admin::gate::{ApiError, ADMIN_PREFIX};
        let uri = req.uri().clone();
        let path = uri
            .path()
            .strip_prefix(ADMIN_PREFIX)
            .unwrap_or_else(|| uri.path());
        let (table, index, name) = {
            let snapshot = self.0.now.load();
            let (found, named) = resolve(&snapshot, &snapshot.admin, req.method().as_str(), path);
            match found {
                Some(f) => f,
                None if named => {
                    return Some(crate::admin::gate::err_json(&ApiError::MethodNotAllowed));
                }
                None => return None,
            }
        };
        let head = lent_head(req.headers(), req.extensions().get());
        let principal = req.extensions().get::<AuthPrincipal>().cloned();
        let body = match Bytes::from_request(req, &()).await {
            Ok(body) => body,
            Err(refused) => return Some(refused.into_response()),
        };
        let target = target_of(path, uri.query());
        let (routes, route) = (table.routes.len(), &table.routes[index]);
        let calls = &*table.calls;
        let at = index as u32;
        // `answer` is mounted behind core admin authorization. Public routes never
        // enter here. Read-only verbs receive no trust mutation authority.
        let authority = matches!(route.verb.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
            .then(|| {
                table
                    .records
                    .as_ref()
                    .map(|(services, caller)| (services.as_ref(), caller, name))
            })
            .flatten();
        let served = serve_authorized(
            calls,
            table.caps,
            (routes, at),
            &target,
            head,
            body,
            authority,
        )
        .await;
        let actor = principal.unwrap_or(AuthPrincipal(None));
        let served = match served {
            Ok(s) => write_served_records(
                table.records.as_ref(),
                &super::CoreAudit,
                &s,
                actor.actor_id(),
            )
            .await
            .map(|()| s),
            Err(e) => Err(e),
        };
        Some(audited_reply(&table, route, name, &actor, served).await)
    }

    pub async fn answer_public(
        &self,
        method: &str,
        path: &str,
        target: &str,
        headers: &axum::http::HeaderMap,
        body: Bytes,
    ) -> Response {
        let found = {
            let snapshot = self.0.now.load();
            resolve(&snapshot, &snapshot.public, method, path).0
        };
        let Some((table, index, name)) = found else {
            return status_only(404);
        };
        let route = &table.routes[index];

        let own_token = route.flags & ROUTE_CARRIES_OWN_TOKEN != 0;
        let head: HeadFields = headers
            .iter()
            .filter(|(n, _)| {
                !NEVER_KEPT.contains(&n.as_str())
                    || (own_token && *n == axum::http::header::AUTHORIZATION)
            })
            .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let served = serve(
            &*table.calls,
            table.caps,
            table.routes.len(),
            index as u32,
            target.as_bytes(),
            head,
            body,
        )
        .await;

        let served = match served {
            Ok(s) => write_served_records(
                table.records.as_ref(),
                &super::CoreAudit,
                &s,
                AuthPrincipal(None).actor_id(),
            )
            .await
            .map(|()| s),
            Err(e) => Err(e),
        };
        audited_reply(&table, route, name, &AuthPrincipal(None), served).await
    }
}

async fn audited_reply(
    table: &ServeTable,
    route: &ServeRoute,
    name: &str,
    actor: &AuthPrincipal,
    served: Result<Served, Unserved>,
) -> Response {
    let s = match served {
        Ok(s) => s,
        Err(unserved) => return status_only(unserved.status()),
    };
    let outcome = match s.audit {
        AUDIT_APPLIED => Some(busbar_contract::vocab::OUTCOME_APPLIED),
        AUDIT_REJECTED => Some(busbar_contract::vocab::OUTCOME_REJECTED),
        _ => None,
    };
    if let Some(outcome) = outcome.filter(|_| !route.audit_verb.is_empty()) {
        let (action, resource) =
            crate::cold::served_audit_names(&table.audit_kind, &route.audit_verb, name);
        if let Err(error) = crate::audit::auditlog::emit_admin_hostless_confirmed(
            &action,
            &resource,
            outcome,
            actor.actor_id(),
        )
        .await
        {
            tracing::warn!(%error, "the served route's audit record is not confirmed");
            return status_only(503);
        }
    }
    reply(&s).unwrap_or_else(|unserved| status_only(unserved.status()))
}

/// ONE ADMIN REQUEST as the admin shim hands it to [`ServeTables::served_at`]: its verb, its path
/// relative to the admin mount and its query, its head fields as received, what the auth gate
/// consumed of them ([`ConsumedCredentials`]), and the principal the gate admitted.
#[derive(Debug, Clone, Copy)]
pub struct AdminServe<'a> {
    /// The verb.
    pub method: &'a str,
    /// The path, relative to the admin mount.
    pub path: &'a str,
    /// The query, without its `?`; `None` = none.
    pub query: Option<&'a str>,
    /// The head fields, as the request carried them.
    pub headers: &'a axum::http::HeaderMap,
    /// The credentials the auth gate consumed; `None` = a route the gate did not judge.
    pub consumed: Option<&'a ConsumedCredentials>,
    /// The principal the gate admitted; `None` = the open admin posture.
    pub principal: Option<&'a AuthPrincipal>,
}

impl ServeTables {
    /// Every published instance's routes, in publication order: what an admin read reports as an
    /// instance's `runtime.plane.routes` (ADMIN-API-1.6 §5.3). Reads the snapshot without a lock.
    #[must_use]
    pub fn published(&self) -> Vec<(String, Vec<ServeRoute>)> {
        self.0
            .now
            .load()
            .tables
            .iter()
            .map(|table| (table.instance.clone(), table.routes.clone()))
            .collect()
    }

    pub async fn served_at(
        &self,
        req: AdminServe<'_>,
        body: Bytes,
    ) -> Option<Result<Served, Unserved>> {
        self.served_at_to(&super::CoreAudit, req, body).await
    }

    pub(crate) async fn served_at_to(
        &self,
        sink: &dyn super::AuditSink,
        req: AdminServe<'_>,
        body: Bytes,
    ) -> Option<Result<Served, Unserved>> {
        let (table, index, name) = {
            let snapshot = self.0.now.load();
            resolve(&snapshot, &snapshot.admin, req.method, req.path).0
        }?;

        let head = lent_head(req.headers, req.consumed);
        let target = target_of(req.path, req.query);
        let calls = &*table.calls;
        // This is the gated admin door's path. Lend the same live-ticket authority
        // as `answer`; a plane's own request bytes cannot authorize a trust write.
        let authority = matches!(
            table.routes[index].verb.as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        )
        .then(|| {
            table
                .records
                .as_ref()
                .map(|(services, caller)| (services.as_ref(), caller, name))
        })
        .flatten();
        let served = serve_authorized(
            calls,
            table.caps,
            (table.routes.len(), index as u32),
            &target,
            head,
            body,
            authority,
        )
        .await;
        let anonymous = AuthPrincipal(None);
        let actor = req.principal.unwrap_or(&anonymous);
        Some(match served {
            Ok(s) => write_served_records(table.records.as_ref(), sink, &s, actor.actor_id())
                .await
                .map(|()| s),
            Err(e) => Err(e),
        })
    }
}

pub async fn write_served_records(
    records: Option<&(
        Arc<crate::host_services::KernelServices>,
        busbar_contract::services::Caller,
    )>,
    sink: &dyn super::AuditSink,
    served: &Served,
    actor: &str,
) -> Result<(), Unserved> {
    use busbar_contract::abi::plane::{RECORD_AUDIT, RECORD_PUT};
    // The acks are awaited after every write is issued; a few fit inline.
    let mut acks: smallvec::SmallVec<
        [tokio::sync::oneshot::Receiver<Result<(), &'static str>>; 4],
    > = smallvec::SmallVec::new();
    for (kind, op, key, value) in &served.records {
        match *op {
            RECORD_AUDIT => {
                let principal = busbar_contract::caps::PrincipalId::new(actor);
                super::audit_row_to(sink, *kind, key, value, Some(&principal))
                    .map_err(|()| Unserved::Fault)?;
            }
            RECORD_PUT => {
                let (services, caller) = records.ok_or(Unserved::Fault)?;
                let schema = services.record_kind(caller, *kind).ok_or(Unserved::Fault)?;
                let bytes = busbar_contract::kinds::RecordBytes::new(value.clone())
                    .map_err(|_| Unserved::Fault)?;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let acked: crate::host_records::Acked = Box::new(move |r| {
                    let _ = tx.send(r);
                });
                services
                    .record_write(caller, schema.as_str(), key, bytes, acked)
                    .map_err(|_| Unserved::Fault)?;
                acks.push(rx);
            }
            _ => return Err(Unserved::Fault),
        }
    }
    for rx in acks {
        match rx.await {
            Ok(Ok(())) => {}
            _ => return Err(Unserved::Fault),
        }
    }
    Ok(())
}

/// Why a request was not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The index names no route of the snapshot; nothing crossed.
    NoRoute,
    /// No request ticket could be minted: the in-flight cap the route step refuses a unit for
    /// (`InFlightCap`, class `Busy`), so it answers that refusal's status, 429.
    NoTicket,
    /// The plane FAULTed, answered short twice, or answered what no reply can be.
    Fault,
}

impl Unserved {
    pub fn status(self) -> u32 {
        match self {
            Unserved::NoRoute => 404,
            Unserved::NoTicket => refusal_status(ReasonCode::InFlightCap),
            Unserved::Fault => refusal_status(ReasonCode::PlanePanic),
        }
    }
}

/// The plane's answer to one served request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The reply status.
    pub status: u32,
    /// The reply's head fields.
    pub fields: HeadFields,
    /// The reply body.
    pub body: Vec<u8>,
    /// `AUDIT_*`, as the plane reported it.
    pub audit: u32,
    /// The answer's record writes, `(kind, op, key, value)`, in the plane's order (SEAM-L(t)).
    pub records: Vec<(u32, u32, Vec<u8>, Vec<u8>)>,
}

struct Bufs {
    target: Vec<u8>,
    head: FieldList,
    body: Bytes,
    reply: Vec<u8>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
    records: Vec<busbar_contract::abi::plane::RecordWrite>,
}

impl Bufs {
    fn frame(&mut self, route: u32) -> (ServeIn, ServeOut) {
        let input = ServeIn {
            route,
            target: AbiStr::over(&self.target),
            fields: self.head.as_ptr(),
            fields_len: self.head.len(),
            body: blob(&self.body),
            reply_buf: self.reply.as_mut_ptr(),
            reply_cap: self.reply.len(),
            fields_buf: self.fields.as_mut_ptr(),
            fields_cap: self.fields.len(),
            arena_buf: self.arena.as_mut_ptr(),
            arena_cap: self.arena.len(),
            records_buf: self.records.as_mut_ptr(),
            records_cap: self.records.len(),
            ..blank_in()
        };
        (input, blank_out())
    }

    fn span(&self, s: Span) -> Vec<u8> {
        let start = s.offset as usize;
        let end = start.saturating_add(s.len as usize);
        self.arena.get(start..end).unwrap_or_default().to_vec()
    }
}

struct Held<'c> {
    calls: &'c dyn PlaneCalls,
    ticket: Ticket,
    crossing: bool,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.crossing {
            self.calls.drop_client(self.ticket);
        }
        self.calls.recycle(self.ticket);
    }
}

pub async fn serve(
    calls: &dyn PlaneCalls,
    caps: BufferCaps,
    routes: usize,
    route: u32,
    target: &[u8],
    head: HeadFields,
    body: Bytes,
) -> Result<Served, Unserved> {
    serve_authorized(calls, caps, (routes, route), &[target], head, body, None).await
}

async fn serve_authorized(
    calls: &dyn PlaneCalls,
    caps: BufferCaps,
    (routes, route): (usize, u32),
    target: &[&[u8]],
    head: HeadFields,
    body: Bytes,
    authority: Option<(
        &crate::host_services::KernelServices,
        &busbar_contract::services::Caller,
        &str,
    )>,
) -> Result<Served, Unserved> {
    if route as usize >= routes {
        return Err(Unserved::NoRoute);
    }
    let ticket = calls.mint().ok_or(Unserved::NoTicket)?;
    let mut held = Held {
        calls,
        ticket,
        crossing: false,
    };
    let _authority = authority.and_then(|(services, caller, counterparty)| {
        services.grant_trust_decision(caller, ticket, counterparty)
    });
    let keep = Arc::new(Mutex::new(Bufs {
        target: joined(target),
        head: FieldList::new(head),
        body,
        reply: vec![0; caps.reply],
        fields: vec![NO_FIELD; caps.fields],
        arena: vec![0; caps.arena],
        records: vec![super::NO_RECORD; caps.records],
    }));
    let lock = || keep.lock().unwrap_or_else(PoisonError::into_inner);
    for recall in [false, true] {
        let (input, out) = lock().frame(route);
        let lent: Lent = keep.clone();
        held.crossing = true;
        let mut flight = calls.serve(ticket, input, out, lent);
        let done = (&mut *flight).await;
        held.crossing = false;
        match (done.outcome, flight.out()) {
            (AbiOutcome::Ready, Some(o)) => {
                let b = lock();
                let reply = b.reply.get(..o.reply_written as usize).unwrap_or_default();
                let fields = b.fields.iter().take(o.fields_written as usize);
                let records = b.records.iter().take(o.records_written as usize);
                return Ok(Served {
                    status: o.status,
                    fields: fields.map(|f| (b.span(f.name), b.span(f.value))).collect(),
                    body: reply.to_vec(),
                    audit: o.audit,
                    records: records
                        .map(|w| (w.kind, w.op, b.span(w.key), b.span(w.value)))
                        .collect(),
                });
            }
            (AbiOutcome::Failed, Some(o)) if done.short && !recall => {
                let mut b = lock();
                let reply = b.reply.len().max(o.reply_needed as usize);
                let fields = b.fields.len().max(o.fields_needed as usize);
                let arena = b.arena.len().max(o.arena_needed as usize);
                let records = b.records.len().max(o.records_needed as usize);
                b.reply.resize(reply, 0);
                b.fields.resize(fields, NO_FIELD);
                b.arena.resize(arena, 0);
                b.records.resize(records, super::NO_RECORD);
            }
            _ => break,
        }
    }
    Err(Unserved::Fault)
}

fn reply(s: &Served) -> Result<Response, Unserved> {
    let status = u16::try_from(s.status).ok();
    let status = status.and_then(|n| StatusCode::from_u16(n).ok());
    let mut resp = Response::new(Body::from(s.body.clone()));
    *resp.status_mut() = status.ok_or(Unserved::Fault)?;
    for (n, v) in &s.fields {
        let name = HeaderName::from_bytes(n).map_err(|_| Unserved::Fault)?;
        let value = HeaderValue::from_bytes(v).map_err(|_| Unserved::Fault)?;
        resp.headers_mut().append(name, value);
    }
    Ok(resp)
}

fn status_only(status: u32) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = u16::try_from(status)
        .ok()
        .and_then(|n| StatusCode::from_u16(n).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    resp
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/serve_tests.rs"]
mod tests;
