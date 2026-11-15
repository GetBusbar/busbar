// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mounting the authorization server's routes: once, when the node starts. The handlers they reach
//! are the request path, in [`super::routes`].

use std::sync::Arc;

use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_kernel::core_routes::CoreRouter;

use super::routes::{authorize, consent_screen, consent_submit, device_verification, forward};

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
            id.verification_path().to_string(),
            RouteMethod::Get,
            RouteAuth::Admin,
            device_verification,
        )
        .route(
            id.verification_path().to_string(),
            RouteMethod::Post,
            RouteAuth::Admin,
            device_verification,
        )
        .route(
            id.consent_path().to_string(),
            RouteMethod::Get,
            RouteAuth::Admin,
            consent_screen,
        )
        .route(
            id.consent_path().to_string(),
            RouteMethod::Post,
            RouteAuth::Admin,
            consent_submit,
        )
        .route(
            id.register_path().to_string(),
            RouteMethod::Post,
            RouteAuth::None,
            forward,
        );
    router
}
