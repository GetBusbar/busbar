// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reference plane: one route of every admission, each with a complete record. It is the
//! stand-in on the plane's side of every boundary test (the admission table, the listener's class
//! dispatch, the loader's record rules), so the engine proves its half without a real plane, and a
//! real plane's route table is checked against the same rules without the engine.

use super::admission_table::Admission;
use super::route_record::{CallerState, Money, PlaneMethods, RouteClass, RouteRecord, Scope, Who};

/// One route of the reference plane.
pub struct ReferenceRoute {
    pub route: u32,
    pub methods: u32,
    pub pattern: &'static str,
    pub admission: Admission,
    pub record: RouteRecord,
}

/// What the reference plane implements: everything a record's rules can ask for.
pub const METHODS: PlaneMethods = PlaneMethods {
    render: true,
    select_resources: true,
    upstream: true,
};

fn record(class: RouteClass, who: Who, scope: Scope, money: Money) -> RouteRecord {
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

/// The reference plane's route table: every admission a client can reach, once, plus the route
/// that keeps state per caller and the one that declares a challenge.
pub fn routes() -> Vec<ReferenceRoute> {
    use busbar_contract::route::{METHOD_GET, METHOD_POST};
    let mut distinct = record(
        RouteClass::Data,
        Who::PRINCIPAL,
        Scope::walk_and_selected("ref_server", &["ref_tool"]),
        Money::Unit,
    );
    distinct.caller_state = CallerState::Distinct;
    distinct.challenge =
        Some("Bearer resource_metadata=\"{public_url}/.well-known/reference\"".into());
    let mut signed = record(
        RouteClass::Data,
        Who::SIGNED_INGRESS,
        Scope::none(),
        Money::None,
    );
    signed.cred_header = Some("webhook-signature".into());
    vec![
        ReferenceRoute {
            route: 1,
            methods: METHOD_POST,
            pattern: "/ref/walk",
            admission: Admission::Walk,
            record: record(
                RouteClass::Data,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::Unit,
            ),
        },
        ReferenceRoute {
            route: 2,
            methods: METHOD_POST,
            pattern: "/ref/selected",
            admission: Admission::Selected,
            record: distinct,
        },
        ReferenceRoute {
            route: 3,
            methods: METHOD_POST,
            pattern: "/ref/principal",
            admission: Admission::PrincipalOnly,
            record: record(RouteClass::Data, Who::PRINCIPAL, Scope::none(), Money::Unit),
        },
        ReferenceRoute {
            route: 4,
            methods: METHOD_GET,
            pattern: "/ref/principal-free",
            admission: Admission::PrincipalOnly,
            record: record(RouteClass::Data, Who::PRINCIPAL, Scope::none(), Money::None),
        },
        ReferenceRoute {
            route: 5,
            methods: METHOD_GET,
            pattern: "/ref/catalog",
            admission: Admission::Catalog,
            record: record(
                RouteClass::Catalog,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::None,
            ),
        },
        ReferenceRoute {
            route: 6,
            methods: METHOD_GET,
            pattern: "/ref/public",
            admission: Admission::Public,
            record: record(RouteClass::Data, Who::PUBLIC, Scope::none(), Money::None),
        },
        ReferenceRoute {
            route: 7,
            methods: METHOD_GET,
            pattern: "/ref/optional",
            admission: Admission::Optional,
            record: record(RouteClass::Data, Who::OPTIONAL, Scope::none(), Money::None),
        },
        ReferenceRoute {
            route: 8,
            methods: METHOD_POST,
            pattern: "/ref/ticket",
            admission: Admission::Ticket,
            record: record(
                RouteClass::Data,
                Who::PRINCIPAL.with(Who::TICKET),
                Scope::none(),
                Money::Unit,
            ),
        },
        ReferenceRoute {
            route: 9,
            methods: METHOD_POST,
            pattern: "/ref/signed",
            admission: Admission::SignedIngress,
            record: signed,
        },
        ReferenceRoute {
            route: 10,
            methods: METHOD_GET,
            pattern: "/ref/upgrade",
            admission: Admission::Upgrade,
            record: record(
                RouteClass::Upgrade,
                Who::PRINCIPAL,
                Scope::walk("pool"),
                Money::Unit,
            ),
        },
        ReferenceRoute {
            route: 11,
            methods: METHOD_GET,
            pattern: "/health",
            admission: Admission::Operator,
            record: record(RouteClass::Admin, Who::OPERATOR, Scope::none(), Money::None),
        },
    ]
}

/// The reference route of an admission (the first, where the table has two).
pub fn route_of(admission: Admission) -> Option<ReferenceRoute> {
    routes()
        .into_iter()
        .find(|route| route.admission == admission)
}
