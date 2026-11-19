// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mounting the authorization server's routes: once, when the node starts. The public endpoints go on
//! the data listener ([`mount`]); the operator approval pages go on the admin listener
//! ([`seam_mount_operator`]). The handlers they reach are the request path, in [`super::routes`].

use std::sync::Arc;

use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_kernel::core_routes::CoreRouter;

use super::operator::{consent_screen, consent_submit, device_decide, device_page};
use super::routes::{authorize, forward};

pub(crate) fn seam_mount(
    router: CoreRouter,
    plane: Option<&Arc<dyn std::any::Any + Send + Sync>>,
) -> CoreRouter {
    mount(
        router,
        plane.and_then(|p| p.downcast_ref::<super::plane::AsPlane>()),
    )
}

pub(crate) fn mount(router: CoreRouter, plane: Option<&super::plane::AsPlane>) -> CoreRouter {
    let Some(plane) = plane else {
        return router;
    };
    let id = plane.identity();

    let router = if id.fapi2() {
        router.route(
            id.par_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
    } else {
        router
    };
    let router = router
        .route(
            id.metadata_path().to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            forward,
        )
        .route(
            id.jwks_path().to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            forward,
        )
        .route(
            id.authorize_path().to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            authorize,
        )
        .route(
            id.token_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
        .route(
            id.device_authorization_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
        .route(
            id.revocation_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        )
        .route(
            id.register_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        );
    router
}

/// The operator approval pages, mounted on the ADMIN listener's router (#140): the contract keeps
/// every `RouteAuth::Admin` route physically off the data listener, and the admin listener is
/// loopback by default precisely so an open admin posture is not public. Mounted at boot whether
/// or not `oauth_as:` is on (the paths are fixed, so no reload can strand them); each handler reads
/// the current plane and answers 404 while the authorization server is off.
pub(crate) fn seam_mount_operator(router: CoreRouter) -> CoreRouter {
    use crate::config::{OPERATOR_CONSENT_PATH, OPERATOR_DEVICE_PATH};
    router
        .route(
            OPERATOR_DEVICE_PATH,
            RouteMethod::Get,
            RouteAuth::Admin,
            device_page,
        )
        .route(
            OPERATOR_DEVICE_PATH,
            RouteMethod::Post,
            RouteAuth::Admin,
            device_decide,
        )
        .route(
            OPERATOR_CONSENT_PATH,
            RouteMethod::Get,
            RouteAuth::Admin,
            consent_screen,
        )
        .route(
            OPERATOR_CONSENT_PATH,
            RouteMethod::Post,
            RouteAuth::Admin,
            consent_submit,
        )
}
