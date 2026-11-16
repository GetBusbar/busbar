// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Route auth (IF §12.11): the effective class set of a route, the per-request classification of a
//! {PRINCIPAL, TICKET} route, and the route's effective chain ("Route credential header", round 23), which
//! replaces the per-route default inbound style. W1-K7 parses `routes.<id>.auth` and
//! `routes.<id>.auth_instances`; these are their semantics, run at config load (never per request).

use busbar_plugin_abi::plane::{
    AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS, AUTH_TICKET,
};

/// The two classes a {PRINCIPAL, TICKET} route takes together (round 15).
const EITHER: u32 = AUTH_PRINCIPAL | AUTH_TICKET;

/// Every class bit a RouteRec.auth mask may hold.
const CLASSES: [(u32, &str); 6] = [
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

/// The effective class set of a route: `configured` is `routes.<id>.auth` as class bits (one class, or the
/// pair PRINCIPAL|TICKET), None = the default: the mask's lowest bit, plus TICKET when the mask holds both
/// PRINCIPAL and TICKET. A configured class outside the mask, or any other combination, is a CONFIG refusal
/// naming the route. `mask` = 0 (a describe that offers no class) is refused the same way.
pub fn effective_classes(route: &str, mask: u32, configured: Option<u32>) -> Result<u32, String> {
    let Some(set) = configured else {
        let lowest = mask & mask.wrapping_neg();
        if lowest == 0 {
            return Err(format!("route '{route}' offers no auth class"));
        }
        return Ok(if mask & EITHER == EITHER {
            lowest | AUTH_TICKET
        } else {
            lowest
        });
    };
    let single = set.count_ones() == 1 && class_word(set).is_some();
    if !single && set != EITHER {
        return Err(format!(
            "routes.{route}.auth must be one class word or [principal, ticket]"
        ));
    }
    if let Some((_, word)) = CLASSES
        .iter()
        .find(|(bit, _)| set & bit != 0 && mask & bit == 0)
    {
        return Err(format!(
            "routes.{route}.auth names '{word}', which route '{route}' does not offer"
        ));
    }
    Ok(set)
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

/// The route's effective chain (round 23, first match wins): (1) `routes.<id>.auth_instances`, in that order,
/// each a configured auth instance; (2) the route's D_ROUTE_CRED_HEADER `h`: every configured instance whose image
/// declares D_CRED_HEADER `h`, in config order, none being a CONFIG refusal; (3) the data chain. An instance
/// selected by (2) is never added to the data chain. Err = the CONFIG text.
pub fn effective_chain<'a>(
    route: RouteAuth<'_>,
    configured: &[ConfiguredAuth<'a>],
    data_chain: &[&'a str],
) -> Result<Vec<&'a str>, String> {
    if let Some(names) = route.auth_instances {
        return names
            .iter()
            .map(|n| {
                configured
                    .iter()
                    .find(|c| c.name == &**n)
                    .map(|c| c.name)
                    .ok_or_else(|| {
                        format!(
                            "routes.{}.auth_instances names '{n}', which is not a configured auth instance",
                            route.id
                        )
                    })
            })
            .collect();
    }
    let Some(header) = route.cred_header else {
        return Ok(data_chain.to_vec());
    };
    let chain: Vec<&'a str> = configured
        .iter()
        .filter(|c| {
            c.cred_headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(header))
        })
        .map(|c| c.name)
        .collect();
    if chain.is_empty() {
        return Err(format!(
            "route '{}/{}' takes its credential in '{header}' and no configured auth instance reads it; \
             configure one or set routes.{}.auth_instances",
            route.plane, route.id, route.id
        ));
    }
    Ok(chain)
}
