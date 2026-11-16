// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Route auth (IF §12.11): the effective class set of a route, the per-request classification of a
//! {PRINCIPAL, TICKET} route, and the route's effective chain ("Route credential header", round 23), which
//! replaces the per-route default inbound style. W1-K7 parses `routes.<id>.auth` and
//! `routes.<id>.auth_instances`; these are their semantics, run at config load (never per request).

use busbar_plugin_abi::plane::{
    AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS, AUTH_TICKET,
};

pub use crate::off_path::auth::route_chain::{effective_chain, effective_classes};

/// The two classes a {PRINCIPAL, TICKET} route takes together (round 15).
pub(crate) const EITHER: u32 = AUTH_PRINCIPAL | AUTH_TICKET;

/// Every class bit a RouteRec.auth mask may hold.
pub(crate) const CLASSES: [(u32, &str); 6] = [
    (AUTH_PRINCIPAL, "principal"),
    (AUTH_OPTIONAL, "optional"),
    (AUTH_PUBLIC, "public"),
    (AUTH_TICKET, "ticket"),
    (AUTH_SIGNED_INGRESS, "signed_ingress"),
    (AUTH_OPERATOR, "operator"),
];

/// The class word of one class bit, as `routes.<id>.auth` writes it.
#[must_use]
pub(crate) fn class_word(class: u32) -> Option<&'static str> {
    CLASSES
        .iter()
        .find(|(bit, _)| *bit == class)
        .map(|(_, w)| *w)
}

/// Round 15, per request: the class a request on a route with effective set `classes` is run under (its
/// `PlaneReq.auth`). On a {PRINCIPAL, TICKET} route, a bearer credential `is_ticket` holds for runs TICKET (a
/// refused ticket is final, never retried as PRINCIPAL); anything else runs PRINCIPAL. Every other set is one class.
pub fn applied_class(classes: u32, bearer: Option<&str>, is_ticket: impl Fn(&str) -> bool) -> u32 {
    if classes != EITHER {
        return classes;
    }
    match bearer {
        Some(credential) if is_ticket(credential) => AUTH_TICKET,
        _ => AUTH_PRINCIPAL,
    }
}

/// One configured auth instance as the route rule reads it: its configured name and its image's D_CRED_HEADER
/// names (lowercase), in config order.
#[derive(Clone, Copy, Debug)]
pub struct ConfiguredAuth<'a> {
    pub name: &'a str,
    pub cred_headers: &'a [Box<str>],
}

/// One route as the rule reads it.
#[derive(Clone, Copy, Debug)]
pub struct RouteAuth<'a> {
    /// The plane instance that declared the route.
    pub plane: &'a str,
    /// The route id.
    pub id: &'a str,
    /// The route's D_ROUTE_CRED_HEADER, lowercase (`RouteInfo.cred_header`).
    pub cred_header: Option<&'a str>,
    /// `routes.<id>.auth_instances`, as configured.
    pub auth_instances: Option<&'a [Box<str>]>,
}
