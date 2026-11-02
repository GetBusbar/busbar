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
        AdminError::UnpricedClass { .. } => Some(ErrKind::UnpricedClass),
    }
}

pub async fn apply_config(
    state: axum::extract::State<std::sync::Arc<busbar_kernel::state::AppHandle>>,
    principal: axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    crate::v1::json::apply_config(state, principal, headers, body).await
}

pub fn openapi_json() -> String {
    crate::v1::json::openapi_json()
}

#[cfg(feature = "openapi-schema")]
pub fn openapi_doc() -> serde_json::Value {
    crate::v1::json::openapi_doc()
}
