// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(test)]
use crate::v1::contract::taxonomy::MethodTag;
#[cfg(test)]
use crate::v1::contract::{taxonomy::ErrKind, AdminError};

#[cfg(test)]
impl MethodTag {
    pub fn as_str(self) -> &'static str {
        match self {
            MethodTag::Get => "get",
            MethodTag::Post => "post",
            MethodTag::Put => "put",
            MethodTag::Patch => "patch",
            MethodTag::Delete => "delete",
        }
    }
}

#[cfg(test)]
pub fn method_tag(m: &axum::http::Method) -> Option<MethodTag> {
    use axum::http::Method;
    Some(match *m {
        Method::GET => MethodTag::Get,
        Method::POST => MethodTag::Post,
        Method::PUT => MethodTag::Put,
        Method::PATCH => MethodTag::Patch,
        Method::DELETE => MethodTag::Delete,
        _ => return None,
    })
}

#[cfg(test)]
pub fn err_kind_of(e: &AdminError) -> Option<ErrKind> {
    match e {
        AdminError::NotFound { .. } => Some(ErrKind::NotFound),
        AdminError::Validation(_) => Some(ErrKind::Validation),
        AdminError::VersionConflict(_) => Some(ErrKind::VersionConflict),
        AdminError::Conflict(_) => Some(ErrKind::Conflict),
        AdminError::Forbidden { .. } => Some(ErrKind::Forbidden),

        AdminError::Unauthorized => None,
        AdminError::MethodNotAllowed => None,
        AdminError::RateLimited => None,
        AdminError::Internal => None,

        AdminError::Unavailable(_) => None,
        AdminError::RetryLater { .. } => None,
        AdminError::UnpricedClass { .. } => Some(ErrKind::UnpricedClass),
        AdminError::PluginText { .. } => Some(ErrKind::Validation),
    }
}

pub async fn apply_config(
    state: axum::extract::State<std::sync::Arc<busbar_kernel::state::AppHandle>>,
    principal: axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::extract::FromRequestParts;
    use axum::response::IntoResponse;
    let (mut parts, ()) = axum::http::Request::new(()).into_parts();
    parts.headers = headers;
    let headers = match busbar_kernel::inbound::http_projection::AdminHeaders::from_request_parts(
        &mut parts,
        &(),
    )
    .await
    {
        Ok(headers) => headers,
        Err(error) => return error.into_response(),
    };
    crate::v1::json::apply_config(state, principal, headers, body).await
}

pub fn openapi_json() -> String {
    crate::v1::json::openapi_json()
}

/// Exercise the production replay middleware around a controlled effect handler.
pub fn with_idempotency(
    router: axum::Router,
    app: std::sync::Arc<busbar_kernel::state::App>,
) -> axum::Router {
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));
    router
        .route(
            "/api/v1/admin/operations/{key}",
            axum::routing::get(crate::v1::json::generation::get_operation)
                .with_state(handle.clone()),
        )
        .layer(axum::middleware::from_fn(
            crate::v1::json::generation::preconditions,
        ))
        .layer(axum::Extension(handle))
}

#[cfg(feature = "openapi-schema")]
pub fn openapi_doc() -> serde_json::Value {
    crate::v1::json::openapi_doc()
}

/// Hold the shared plugin scan gate (DES-359 r3 L9 tests): while the guard lives, every catalog
/// read, schema read, install and remove waits on it within its bound.
pub async fn hold_scan_gate() -> tokio::sync::MutexGuard<'static, ()> {
    crate::v1::service::scan_gate("test.hold")
        .await
        .expect("the scan gate is free when a test takes it")
}
