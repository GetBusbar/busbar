// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plane_routes::{FramedSession, SessionPipe};
use axum::response::Response;

pub struct SessionUpgrade(FramedSession);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for SessionUpgrade {
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        let slot = parts
            .extensions
            .get::<FramedSession>()
            .cloned()
            .ok_or(axum::http::StatusCode::FORBIDDEN)?;
        if !slot.admit().await {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
        Ok(Self(slot))
    }
}

pub fn bridge(upgrade: SessionUpgrade, pipe: SessionPipe) -> Response {
    upgrade.0.put(pipe);
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = axum::http::StatusCode::SWITCHING_PROTOCOLS;
    response
}
