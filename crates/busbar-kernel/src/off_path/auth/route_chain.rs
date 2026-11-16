// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`crate::auth::route_chain`]'s config-load half (IF §12.11): a route's effective class set and its
//! effective chain, each refused as CONFIG text naming the route. Both run when routes are loaded,
//! never per request; the request path only classifies with [`crate::auth::route_chain::applied_class`].

use busbar_plugin_abi::plane::AUTH_TICKET;

use crate::auth::route_chain::{class_word, ConfiguredAuth, RouteAuth, CLASSES, EITHER};

/// The effective class set of a route: `configured` is `routes.<id>.auth` as class bits (one class, or the
/// pair PRINCIPAL|TICKET), None = the default: the mask's lowest bit, plus TICKET when the mask holds both
/// PRINCIPAL and TICKET. A configured class outside the mask, or any other combination, is a CONFIG refusal
/// naming the route. `mask` = 0 (a describe that offers no class) is refused the same way.
pub fn effective_classes(route: &str, mask: u32, configured: Option<u32>) -> Result<u32, String> {
    let Some(set) = configured else {
        let lowest = mask.isolate_lowest_one();
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
