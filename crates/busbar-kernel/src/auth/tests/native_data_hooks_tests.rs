// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A route with a hook bound (gap G7 of the inbound admission design): it is mounted exactly
//! where its hooks run, and never served unhooked.

use super::NativeDataRoute;
use crate::auth::route_record::{CallerState, Money, RouteClass, RouteRecord, Scope, Who};

fn stated(class: RouteClass, who: Who, scope: Scope, money: Money) -> RouteRecord {
    RouteRecord {
        class,
        who,
        cred_header: None,
        challenge: None,
        scope,
        scope_stated: true,
        money,
        caller_state: CallerState::Shared,
    }
}

/// RED before hooks ran on the native path: every route of a seat with a hook was left
/// unmounted ("the native data path does not run route hooks"), so a v1.5.5 customer with a
/// hook lost its model-serving routes and its model list.
#[test]
fn a_hook_bound_route_that_opens_a_unit_and_a_catalog_are_served() {
    for (what, record) in [
        (
            "a model-serving route: the walk, a unit",
            stated(
                RouteClass::Data,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::Unit,
            ),
        ),
        (
            "a principal's route that opens a unit and names no walk",
            stated(RouteClass::Data, Who::PRINCIPAL, Scope::none(), Money::Unit),
        ),
        (
            "the model list: no session, no hook to run",
            stated(
                RouteClass::Catalog,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::None,
            ),
        ),
    ] {
        assert_eq!(NativeDataRoute::hooks_run(&record), Ok(()), "{what}");
    }
}

/// The other half, which must hold before and after: a hook-bound route whose request would
/// run no hook stays unmounted. Serving it would skip a policy the operator configured.
#[test]
fn a_hook_bound_route_whose_hooks_would_not_run_stays_unmounted() {
    for (what, record) in [
        (
            "the plane selects resources: a selected request runs no hook",
            stated(
                RouteClass::Data,
                Who::PRINCIPAL,
                Scope::selected(&["mcp_tool"]),
                Money::Unit,
            ),
        ),
        (
            "a walk and a selection",
            stated(
                RouteClass::Data,
                Who::PRINCIPAL,
                Scope::walk_and_selected("mcp_server", &["mcp_tool"]),
                Money::Unit,
            ),
        ),
        (
            "a walk that opens no unit",
            stated(
                RouteClass::Data,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::None,
            ),
        ),
        (
            "verified, not billed",
            stated(RouteClass::Data, Who::PRINCIPAL, Scope::none(), Money::None),
        ),
        (
            "public",
            stated(RouteClass::Data, Who::PUBLIC, Scope::none(), Money::None),
        ),
        (
            "optional",
            stated(RouteClass::Data, Who::OPTIONAL, Scope::none(), Money::None),
        ),
        (
            "an upgrade (the native upgrade path keeps its own refusal)",
            stated(
                RouteClass::Upgrade,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::Unit,
            ),
        ),
    ] {
        let why = NativeDataRoute::hooks_run(&record).expect_err(what);
        assert!(
            why.contains("a route with a hook bound"),
            "{what}: the reason names the hook: {why}"
        );
    }
}
