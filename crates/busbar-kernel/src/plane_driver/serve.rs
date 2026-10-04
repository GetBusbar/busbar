// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S `serve` OP AND THE ADMIN TABLE IT ANSWERS ON (`BUSBAR-1.6.0.md` B.9, B.10;
//! ARCHITECT C2c S5 rulings Q1-Q6, 2026-10-01). A plane instance's snapshot names its admin
//! routes; the kernel serves them on the admin router, behind the auth middleware every admin
//! path crosses (`required_scope(method, path)`), from a table read at request time over each
//! instance's CURRENT snapshot. An instance that is not published mounts nothing, and the
//! router's own `404` answers.
//!
//! - A route that overlaps another instance's, or a reserved kernel admin route, is refused when
//!   the snapshot is published (boot and refresh). The table is the router's fallback, so a
//!   kernel route always matches first and is never shadowed.
//! - The credentials the auth gate consumed ([`ConsumedCredentials`]) and the contract's
//!   [`NEVER_KEPT`] fields never cross to the plane.
//! - The plane reports the audit outcome ([`ServeOut::audit`]); the kernel writes the row under
//!   the route's `audit_verb`, as the admin shim writes a plane verb's.
//! - One short answer is re-called once; a second short answer or a FAULT answers 502. An index
//!   past the snapshot never crosses.
//! - A [`ROUTE_PUBLIC`] route is never on this table.

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    FieldList, OutField, ServeIn, ServeOut, AUDIT_APPLIED, AUDIT_REJECTED, ROUTE_PUBLIC,
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

static TABLES: RwLock<Vec<ServeTable>> = RwLock::new(Vec::new());

fn param(segment: &str) -> bool {
    segment.len() > 1 && segment.starts_with('{') && segment.ends_with('}')
}

/// Whether two targets can match one path.
fn overlap(a: &str, b: &str) -> bool {
    let (a, b): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
    a.len() == b.len()
        && a.iter()
            .zip(&b)
            .all(|(x, y)| x == y || param(x) || param(y))
}

/// The first parameter `path` fills in `target` (`""` for none), when it fills the whole target.
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

/// PUBLISH `table` (an instance's open or refresh), replacing the instance's last one. Refused,
/// with nothing changed, when one of its admin routes overlaps another of its own, another
/// instance's, or a `reserved` kernel admin route `(verb, target)`.
pub fn publish(table: ServeTable, reserved: &[(&str, &str)]) -> Result<(), Collision> {
    let mut tables = TABLES.write().unwrap_or_else(PoisonError::into_inner);
    let mut seen: Vec<(&str, &str, &str)> =
        reserved.iter().map(|(v, t)| (*v, *t, "kernel")).collect();
    for t in tables.iter().filter(|t| t.instance != table.instance) {
        seen.extend(admin(&t.routes).map(|r| (&*r.verb, &*r.target, &*t.instance)));
    }
    for r in admin(&table.routes) {
        if let Some((_, _, with)) = seen
            .iter()
            .find(|(v, t, _)| v.eq_ignore_ascii_case(&r.verb) && overlap(t, &r.target))
        {
            return Err(Collision {
                route: (r.verb.clone(), r.target.clone()),
                with: (*with).to_string(),
            });
        }
        seen.push((&r.verb, &r.target, &table.instance));
    }
    tables.retain(|t| t.instance != table.instance);
    tables.push(table);
    Ok(())
}

/// The instance is retired or no longer configured: its routes leave the table.
pub fn withdraw(instance: &str) {
    let mut tables = TABLES.write().unwrap_or_else(PoisonError::into_inner);
    tables.retain(|t| t.instance != instance);
}

fn admin(routes: &[ServeRoute]) -> impl Iterator<Item = &ServeRoute> {
    routes.iter().filter(|r| r.flags & ROUTE_PUBLIC == 0)
}

/// THE ADMIN ROUTER'S FALLBACK: a request no kernel route matched, answered by the published
/// instance whose admin route it names. `None` = no instance names the path (the router's `404`);
/// a path an instance names under another verb answers the admin surface's `405`. The body is read
/// only for a served route, under the inbound body limit, so an unmatched path answers as before.
pub async fn answer(req: Request) -> Option<Response> {
    use crate::admin::v1::contract::{AdminError, ADMIN_PREFIX};
    let uri = req.uri().clone();
    let path = uri.path().strip_prefix(ADMIN_PREFIX).unwrap_or(uri.path());
    let (table, index, name) = {
        let tables = TABLES.read().unwrap_or_else(PoisonError::into_inner);
        let mut named = false;
        let mut found = None;
        'tables: for t in tables.iter() {
            for (i, r) in t.routes.iter().enumerate() {
                let Some(name) = fill(&r.target, path).filter(|_| r.flags & ROUTE_PUBLIC == 0)
                else {
                    continue;
                };
                named = true;
                if r.verb.eq_ignore_ascii_case(req.method().as_str()) {
                    found = Some((t.clone(), i, name.to_string()));
                    break 'tables;
                }
            }
        }
        match found {
            Some(f) => f,
            None if named => {
                return Some(crate::admin::v1::json::err_json(
                    &AdminError::MethodNotAllowed,
                ))
            }
            None => return None,
        }
    };
    let mut headers = req.headers().clone();
    ConsumedCredentials::strip_from(req.extensions().get(), &mut headers);
    let principal = req.extensions().get::<AuthPrincipal>().cloned();
    let body = match Bytes::from_request(req, &()).await {
        Ok(body) => body,
        Err(refused) => return Some(refused.into_response()),
    };
    let head: HeadFields = headers
        .iter()
        .filter(|(n, _)| !NEVER_KEPT.contains(&n.as_str()))
        .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect();
    let target = match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    let (routes, route) = (table.routes.len(), &table.routes[index]);
    let calls = &*table.calls;
    let at = index as u32;
    let served = serve(calls, table.caps, routes, at, target.as_bytes(), head, body).await;
    Some(
        match served.and_then(|s| reply(&s).map(|resp| (s.audit, resp))) {
            Ok((audit, resp)) => {
                let outcome = match audit {
                    AUDIT_APPLIED => Some(busbar_contract::vocab::OUTCOME_APPLIED),
                    AUDIT_REJECTED => Some(busbar_contract::vocab::OUTCOME_REJECTED),
                    _ => None,
                };
                if let Some(outcome) = outcome.filter(|_| !route.audit_verb.is_empty()) {
                    let actor = principal.unwrap_or(AuthPrincipal(None));
                    crate::audit_ring::AUDIT.record_by(
                        &format!("{}.{}", table.audit_kind, route.audit_verb),
                        &format!("{}:{name}", table.audit_kind),
                        outcome,
                        actor.actor_id(),
                    );
                }
                resp
            }
            Err(unserved) => status_only(unserved.status()),
        },
    )
}

/// SERVE ONE ADMIN REQUEST by the published instance whose admin route names `method` and `path`
/// (relative to the admin mount): the head fields `headers` (the contract's never-kept fields
/// struck) and `body`. `None` when no published instance names it. The registry row of a door
/// plane mounts its stated admin routes through this (its `admin_routes` handler), so the request is
/// served by the instance's own `serve` op, as the router's fallback serves it.
pub async fn served_at(
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    body: Bytes,
) -> Option<Result<Served, Unserved>> {
    let (table, index) = {
        let tables = TABLES.read().unwrap_or_else(PoisonError::into_inner);
        tables.iter().find_map(|t| {
            t.routes.iter().enumerate().find_map(|(i, r)| {
                (r.flags & ROUTE_PUBLIC == 0
                    && r.verb.eq_ignore_ascii_case(method)
                    && fill(&r.target, path).is_some())
                .then(|| (t.clone(), i))
            })
        })
    }?;
    let head: HeadFields = headers
        .iter()
        .filter(|(n, _)| !NEVER_KEPT.contains(&n.as_str()))
        .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect();
    let calls = &*table.calls;
    Some(
        serve(
            calls,
            table.caps,
            table.routes.len(),
            index as u32,
            path.as_bytes(),
            head,
            body,
        )
        .await,
    )
}

/// Why a request was not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The index names no route of the snapshot; nothing crossed.
    NoRoute,
    /// No request ticket could be minted.
    NoTicket,
    /// The plane FAULTed, answered short twice, or answered what no reply can be.
    Fault,
}

impl Unserved {
    /// The status the kernel answers it with.
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
}

/// One request's host buffers, lent to every crossing of it.
struct Bufs {
    target: Vec<u8>,
    head: FieldList,
    body: Bytes,
    reply: Vec<u8>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
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

/// The request's ticket: back to the dispatcher when the request ends, and handed to its
/// client-drop path first when the caller went away with a crossing in flight.
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

/// SERVE route `route` of a snapshot of `routes` admin routes: `target`, the head fields `head`
/// and `body`, on a request ticket, with one re-call for a short answer.
pub async fn serve(
    calls: &dyn PlaneCalls,
    caps: BufferCaps,
    routes: usize,
    route: u32,
    target: &[u8],
    head: HeadFields,
    body: Bytes,
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
    let keep = Arc::new(Mutex::new(Bufs {
        target: target.to_vec(),
        head: FieldList::new(head),
        body,
        reply: vec![0; caps.reply],
        fields: vec![NO_FIELD; caps.fields],
        arena: vec![0; caps.arena],
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
                return Ok(Served {
                    status: o.status,
                    fields: fields.map(|f| (b.span(f.name), b.span(f.value))).collect(),
                    body: reply.to_vec(),
                    audit: o.audit,
                });
            }
            (AbiOutcome::Failed, Some(o)) if done.short && !recall => {
                // THE ONE RE-CALL, on the same ticket, with what the answer said it needs.
                let mut b = lock();
                let reply = b.reply.len().max(o.reply_needed as usize);
                let fields = b.fields.len().max(o.fields_needed as usize);
                let arena = b.arena.len().max(o.arena_needed as usize);
                b.reply.resize(reply, 0);
                b.fields.resize(fields, NO_FIELD);
                b.arena.resize(arena, 0);
            }
            _ => break,
        }
    }
    Err(Unserved::Fault)
}

/// The served answer as the admin surface sends it; a status or a field no reply can carry is a
/// FAULT of the answer.
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
