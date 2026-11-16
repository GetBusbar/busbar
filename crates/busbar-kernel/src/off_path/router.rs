// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The router's off-path code: composing a data router for a published `App` snapshot or a
//! prepared listener (its routes, door verbs and fallbacks), preparing a listener, and the auth
//! scope projection a snapshot is built with. It runs once per configuration generation or
//! listener preparation, never per request; the handlers it mounts stay in `crate::router`.

use axum::Router;

use crate::router::{
    method_not_allowed_handler, mount_plane_route, mount_plane_session, private_not_found,
    unchanged_dispatch_layer, PreparedListener,
};
use crate::{config, endpoints, ingress, state};

pub(crate) fn base_data_router_scoped(
    plugin_routes: &crate::plugin_routes::PluginRouteTable,
    plane_slots: &std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    oauth_as: Option<&std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    doors: Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
    root_surface: bool,
) -> (
    Router<std::sync::Arc<state::AppHandle>>,
    crate::core_routes::CoreRouteTable,
) {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};

    let router = if root_surface {
        let router = crate::core_routes::CoreRouter::new()
            .route("/stats", RouteMethod::Get, RouteAuth::Key, endpoints::stats)
            .route(
                crate::auth::HEALTHZ_PATH,
                RouteMethod::Get,
                RouteAuth::None,
                endpoints::healthz,
            )
            .route(
                crate::auth::LIVEZ_PATH,
                RouteMethod::Get,
                RouteAuth::None,
                endpoints::livez,
            )
            .route(
                crate::auth::READYZ_PATH,
                RouteMethod::Get,
                RouteAuth::None,
                endpoints::readyz,
            );

        router
            .route(
                crate::auth::exchange::AUTH_TOKEN_PATH,
                RouteMethod::Get,
                RouteAuth::None,
                crate::auth::login::seam::browser,
            )
            .route(
                crate::auth::exchange::AUTH_TOKEN_PATH,
                RouteMethod::Post,
                RouteAuth::None,
                crate::auth::exchange::exchange,
            )
    } else {
        crate::core_routes::CoreRouter::new()
    };

    let mut router = router;
    for decl in crate::plane_driver::registry::plane_decls() {
        let Some(slot) = plane_slots.get(decl.key) else {
            continue;
        };

        if let Some(routes) = decl.routes {
            for spec in routes(slot.as_ref()) {
                router = mount_plane_route(router, slot.clone(), spec);
            }
        }
    }

    let unslotted: std::sync::Arc<dyn std::any::Any + Send + Sync> = std::sync::Arc::new(());
    let door_paths: std::collections::BTreeSet<String> =
        doors.iter().map(|spec| spec.path.clone()).collect();
    for spec in doors {
        router = mount_plane_route(router, std::sync::Arc::clone(&unslotted), spec);
    }

    for spec in sessions {
        router = mount_plane_session(router, std::sync::Arc::clone(&unslotted), spec);
    }

    for path in door_paths {
        let claimed = router
            .methods_at(&path)
            .into_iter()
            .map(crate::plugin_routes::method_filter_of)
            .reduce(axum::routing::MethodFilter::or);
        if let Some(rest) = claimed.and_then(unclaimed_verbs) {
            router = router.map_router(|r| {
                r.route(&path, axum::routing::on(rest, method_not_allowed_handler))
            });
        }
    }

    let router = match crate::oauth_as::seam::seam() {
        Some(seam) if root_surface => (seam.mount)(router, oauth_as),
        _ => router,
    };

    let router =
        router.map_router(|r| crate::plugin_routes::mount_plugin_routes(r, plugin_routes, false));
    router
        .map_router(|r| {
            let r = if root_surface {
                r.fallback(ingress::protocol_dispatch)
            } else {
                r.fallback(private_not_found)
            };
            r.method_not_allowed_fallback(method_not_allowed_handler)
        })
        .into_parts()
}

fn unclaimed_verbs(claimed: axum::routing::MethodFilter) -> Option<axum::routing::MethodFilter> {
    use axum::routing::MethodFilter;
    let all = [
        (MethodFilter::GET, axum::http::Method::GET),
        (MethodFilter::POST, axum::http::Method::POST),
        (MethodFilter::PUT, axum::http::Method::PUT),
        (MethodFilter::PATCH, axum::http::Method::PATCH),
        (MethodFilter::DELETE, axum::http::Method::DELETE),
        (MethodFilter::OPTIONS, axum::http::Method::OPTIONS),
        (MethodFilter::TRACE, axum::http::Method::TRACE),
        (MethodFilter::CONNECT, axum::http::Method::CONNECT),
        (MethodFilter::HEAD, axum::http::Method::HEAD),
    ];
    let get_claimed = claimed_has(claimed, &axum::http::Method::GET);
    all.into_iter()
        .filter(|(_, m)| !claimed_has(claimed, m))
        .filter(|(_, m)| !(get_claimed && *m == axum::http::Method::HEAD))
        .map(|(f, _)| f)
        .reduce(MethodFilter::or)
}

fn claimed_has(filter: axum::routing::MethodFilter, method: &axum::http::Method) -> bool {
    use axum::routing::MethodFilter;
    let one = match *method {
        axum::http::Method::GET => MethodFilter::GET,
        axum::http::Method::POST => MethodFilter::POST,
        axum::http::Method::PUT => MethodFilter::PUT,
        axum::http::Method::PATCH => MethodFilter::PATCH,
        axum::http::Method::DELETE => MethodFilter::DELETE,
        axum::http::Method::OPTIONS => MethodFilter::OPTIONS,
        axum::http::Method::TRACE => MethodFilter::TRACE,
        axum::http::Method::CONNECT => MethodFilter::CONNECT,
        axum::http::Method::HEAD => MethodFilter::HEAD,
        _ => return false,
    };
    filter.or(one) == filter
}

impl PreparedListener {
    pub fn new(
        app: &state::App,
        plugins: &crate::plugin_routes::PluginRouteTable,
        doors: Vec<crate::plane_routes::PlaneRouteSpec>,
        sessions: Vec<crate::plane_routes::PlaneSessionSpec>,
        refusals: Vec<crate::plane_routes::PlaneRefusalSpec>,
        refuse_by_path: Option<crate::plane_routes::PlaneRefuseByPathFn>,
        root_surface: bool,
    ) -> Result<Self, String> {
        crate::plane_routes::pair_door_refusals(&doors, &sessions, &refusals)?;
        let (router, core_routes) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let empty_slots = std::collections::BTreeMap::new();
            base_data_router_scoped(
                plugins,
                if root_surface {
                    &app.plane_slots
                } else {
                    &empty_slots
                },
                if root_surface {
                    app.oauth_as.as_ref()
                } else {
                    None
                },
                doors,
                sessions,
                root_surface,
            )
        }))
        .map_err(|_| "candidate physical routes cannot be mounted together".to_string())?;
        let core_routes = core_routes.with_door_refusals(refusals.clone());
        Ok(Self {
            data: None,
            router,
            core_routes,
            refusals,
            refuse_by_path,
            root_surface,
            dispatch_layer: unchanged_dispatch_layer,
        })
    }
}

pub(crate) fn project_auth_scope_caps<M: FromIterator<(String, String)>>(a: &config::AuthCfg) -> M {
    a.chain
        .iter()
        .chain(a.admin_auth.iter())
        .filter_map(|e| {
            e.max_admin_scope
                .as_ref()
                .map(|sc| (e.name.clone(), sc.clone()))
        })
        .collect()
}
