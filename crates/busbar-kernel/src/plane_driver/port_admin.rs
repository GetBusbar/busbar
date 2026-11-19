// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ROUTE_ADMIN on the admin listener (IF §8.6, PLANE-DRIVER slice 8): the admin routes the MIN-3 plane instances
//! declare, served through [`PortDriver::serve`] for an operator.
//!
//! The admin router borrows the request generation's completed seats. The operator chain has
//! already authenticated this request before it reaches these routes; the generation and its
//! instances stay owned for the entire asynchronous answer.

use busbar_contract::route::{method_bit, path_matches, PATH_PATTERN};

use super::port::{HttpHead, HttpIn, PortSeat, ServeIn, Served};
use super::port_auth::{Credentials, Principal, Subject};
use super::port_routes::Mounted;
use super::port_session::ToClient;
use super::HeadFields;

/// The admin route of `routes` the request names: its method is in the route's mask and its path matches the
/// route's pattern. First match in route order.
#[must_use]
pub fn matching<'a>(routes: &'a [Mounted], method: &str, path: &str) -> Option<&'a Mounted> {
    let bit = method_bit(method);
    if bit == 0 {
        return None;
    }
    routes
        .iter()
        .find(|m| m.methods & bit != 0 && path_matches(PATH_PATTERN, &m.pattern, path))
}

/// Whether an installed plane declares an admin route this request names (so the caller reads the body and asks
/// [`answer`]; any other request is the router's).
#[must_use]
pub fn serves(seats: &[PortSeat], method: &str, path: &str) -> bool {
    seats
        .iter()
        .any(|seat| matching(&seat.driver.routes().admin, method, path).is_some())
}

/// The status, head fields and joined body of the client items. No head = the plane wrote no answer: 502 with
/// nothing, never a 200 nobody stated. Trailers and the end mark carry nothing on a buffered reply.
#[must_use]
pub fn joined(items: Vec<ToClient>) -> (u16, HeadFields, Vec<u8>) {
    let mut head = None;
    let mut body = Vec::new();
    for item in items {
        match item {
            ToClient::Head { status, fields } => {
                head.get_or_insert((status, fields));
            }
            ToClient::Body(bytes) | ToClient::Msg { bytes, .. } => body.extend_from_slice(&bytes),
            ToClient::Trailers(_) | ToClient::End => {}
        }
    }
    match head {
        Some((status, fields)) => (status, fields, body),
        None => (502, Vec::new(), Vec::new()),
    }
}

/// One admin request the admin listener's operator chain admitted.
pub struct AdminRequest {
    pub request: crate::limits::process_admission::RequestLease,
    pub method: String,
    pub path: String,
    pub query: String,
    /// The request's head fields as they arrived, credential carriers included: [`answer`] strips
    /// them before anything is handed to the plane.
    pub headers: axum::http::HeaderMap,
    /// The carriers the admin gate consumed judging this request (its `ConsumedCredentials`
    /// extension): every one is stripped from the head the plane is handed, as the data router
    /// strips them, and the gate's hold on the caller credential is released before the plane
    /// is entered. `None`: the gate judged nothing (the floor still applies).
    pub consumed: Option<crate::auth::ConsumedCredentials>,
    /// Who the admin gate admitted (its `AuthPrincipal` extension): the subject the plane's
    /// admin route is served as, and so the principal every audit row it states is written under.
    pub principal: crate::auth::AuthPrincipal,
    pub body: bytes::Bytes,
    pub request_id: u64,
    pub now_s: u64,
}

/// The head fields under which an admin credential travels: the bearer the operator chain judges,
/// a proxy's own credential, the browser session of an admin login, and the 1.5 carrier that 1.6
/// no longer reads but an old client may still send its admin secret in. A plane's admin route is
/// never handed any of them. This is the floor: [`answer`] also strips every carrier the admin
/// gate consumed ([`AdminRequest::consumed`]) before the head is copied for the plane.
const ADMIN_CREDENTIAL_FIELDS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-admin-token",
];

/// The head fields a plane's admin route is handed: everything the request carried except the
/// admin credential, in the order it arrived. The gate has judged the credential already and the
/// plane is told only that the caller is the operator (`Credentials::operator`) and who the gate
/// admitted ([`AdminRequest::principal`]); the secret itself
/// never crosses to the plane (the data path's rule is `auth::native_data::withheld_carriers`).
pub(crate) fn plane_headers(mut headers: Vec<(String, Vec<u8>)>) -> Vec<(String, Vec<u8>)> {
    headers.retain(|(name, _)| {
        !ADMIN_CREDENTIAL_FIELDS
            .iter()
            .any(|withheld| name.eq_ignore_ascii_case(withheld))
    });
    headers
}

/// A plane's answer: status, head fields, body.
pub type AdminAnswer = (u16, HeadFields, Vec<u8>);

/// The answer of the installed plane whose admin route the request names, or `None` when no installed plane has
/// one (the router answers not-found). A plane that fails the request answers 502 with nothing.
pub async fn answer(seats: &[PortSeat], request: AdminRequest) -> Option<AdminAnswer> {
    let (seat, route) = seats.iter().find_map(|seat| {
        matching(&seat.driver.routes().admin, &request.method, &request.path)
            .map(|route| (seat, route.route))
    })?;
    let AdminRequest {
        request,
        method,
        path,
        query,
        mut headers,
        consumed,
        principal,
        body,
        request_id,
        now_s,
    } = request;
    // Every carrier the gate consumed is withheld, then the gate's hold on the caller credential
    // is released: neither crosses to the plane.
    if let Some(consumed) = consumed {
        consumed.strip(&mut headers);
    }
    let headers = headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    // The plane's admin route is served as the principal the admin gate admitted: the subject its
    // identity records and every audit row it states name.
    let principal = match principal.0 {
        Some(admitted) => Principal::Verified(Subject::Principal(std::sync::Arc::new(admitted))),
        None => Principal::Anonymous,
    };
    let input = ServeIn {
        request,
        admission: None,
        invocation: None,
        route,
        http: HttpIn::new(
            HttpHead::Text {
                method,
                path,
                query,
                headers: plane_headers(headers),
            },
            body,
            request_id,
        ),
        creds: Credentials {
            bearer: None,
            principal,
            operator: true,
            signed: None,
        },
        audience: "",
        now_s,
        unit: None,
        upstream: None,
        client: None,
        carrier: None,
        intents: std::sync::Arc::clone(&seat.intents),
        models: Vec::new(),
    };
    Some(match Box::pin(seat.driver.serve(input)).await {
        Ok(Served::Refused(refused)) => joined(refused.items),
        Ok(Served::Ran(ran)) => joined(ran.client),
        Err(error) => {
            tracing::warn!(instance = %seat.instance, route, ?error, "a plane admin request failed");
            (502, Vec::new(), Vec::new())
        }
    })
}

#[cfg(test)]
#[path = "tests/port_admin_tests.rs"]
mod tests;
