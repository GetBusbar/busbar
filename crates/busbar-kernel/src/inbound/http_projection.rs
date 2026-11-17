// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One funded native HTTP map, moved through the actual Admin consumers.

#[cfg(test)]
#[path = "tests/http_projection.rs"]
mod tests;

use std::sync::Arc;

use axum::http::{
    header, request::Parts, HeaderMap, HeaderName, HeaderValue, Method, Request, Uri,
};
use axum::response::{IntoResponse, Response};
use busbar_contract::secure::SecureVec;

use super::request_snapshot::ChargedRequestSnapshot;
use crate::limits::process_admission::{ByteCredit, RequestLease};

#[derive(Debug)]
pub struct ProjectionRefused;

impl IntoResponse for ProjectionRefused {
    fn into_response(self) -> Response {
        crate::admin::gate::admin_error_envelope(
            503,
            "unavailable",
            "request projection unavailable",
        )
    }
}

struct MapCredit {
    snapshot: Arc<ChargedRequestSnapshot>,
    _credit: ByteCredit,
}

#[derive(Clone)]
struct Carrier(Arc<MapCredit>);

impl Carrier {
    fn matches(&self, extensions: &axum::http::Extensions) -> bool {
        extensions
            .get::<Arc<ChargedRequestSnapshot>>()
            .is_some_and(|snapshot| Arc::ptr_eq(snapshot, &self.0.snapshot))
            && extensions
                .get::<RequestLease>()
                .is_some_and(|lease| self.0.snapshot.request().same_request(lease))
    }
}

struct NormalizedName {
    bytes: SecureVec,
    _credit: ByteCredit,
}

impl AsRef<[u8]> for NormalizedName {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parts drop before credit. No public constructor accepts an arbitrary unpaired map.
pub struct HttpProjection {
    parts: Parts,
    carrier: Carrier,
}

impl HttpProjection {
    pub fn from_snapshot(snapshot: Arc<ChargedRequestSnapshot>) -> Result<Self, ProjectionRefused> {
        use axum::http::header::{HeaderMapPlan, ProjectionError};

        let plan =
            HeaderMapPlan::for_values(snapshot.headers().len()).map_err(|_| ProjectionRefused)?;
        let credit = snapshot
            .request()
            .try_reserve(plan.allocation_bytes())
            .map_err(|_| ProjectionRefused)?;
        let fields = snapshot.header_fields().map(|(name, value)| {
            let name = if name.iter().any(u8::is_ascii_uppercase) {
                let credit = snapshot
                    .request()
                    .try_reserve(name.len())
                    .map_err(|_| ProjectionError::Capacity)?;
                let mut bytes = SecureVec::with_capacity(name.len())
                    .map_err(|_| ProjectionError::Allocation)?;
                for byte in name.iter() {
                    bytes
                        .extend(&[byte.to_ascii_lowercase()])
                        .map_err(|_| ProjectionError::Allocation)?;
                }
                bytes::Bytes::from_owner(NormalizedName {
                    bytes,
                    _credit: credit,
                })
            } else {
                name
            };
            Ok((
                HeaderName::from_lowercase_shared(name)
                    .map_err(|_| ProjectionError::InvalidField)?,
                HeaderValue::from_maybe_shared(value).map_err(|_| ProjectionError::InvalidField)?,
            ))
        });
        let headers = HeaderMap::try_from_plan(plan, fields).map_err(|_| ProjectionRefused)?;
        let method =
            Method::from_maybe_shared(snapshot.method_bytes()).map_err(|_| ProjectionRefused)?;
        let uri = Uri::from_maybe_shared(snapshot.target_bytes()).map_err(|_| ProjectionRefused)?;
        let (mut parts, ()) = Request::new(()).into_parts();
        parts.method = method;
        parts.uri = uri;
        parts.headers = headers;
        parts.extensions.insert(snapshot.request().clone());
        parts.extensions.insert(Arc::clone(&snapshot));
        Ok(Self {
            parts,
            carrier: Carrier(Arc::new(MapCredit {
                snapshot,
                _credit: credit,
            })),
        })
    }

    pub fn from_parts(mut parts: Parts) -> Result<Self, ProjectionRefused> {
        let carrier = parts
            .extensions
            .remove::<Carrier>()
            .ok_or(ProjectionRefused)?;
        if !carrier.matches(&parts.extensions) {
            drop(parts);
            return Err(ProjectionRefused);
        }
        Ok(Self { parts, carrier })
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    pub fn into_request<B>(mut self, body: B) -> Request<B> {
        self.parts.extensions.insert(self.carrier);
        Request::from_parts(self.parts, body)
    }
}

/// Final extractor moves the map and its reservation; it never clones map storage.
pub struct AdminHeaders {
    headers: HeaderMap,
    _carrier: Option<Carrier>,
}

impl std::ops::Deref for AdminHeaders {
    type Target = HeaderMap;
    fn deref(&self) -> &Self::Target {
        &self.headers
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AdminHeaders {
    type Rejection = ProjectionRefused;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let carrier = parts.extensions.get::<Carrier>();
        if let Some(carrier) = &carrier {
            if !carrier.matches(&parts.extensions) {
                return Err(ProjectionRefused);
            }
        } else if parts
            .extensions
            .get::<Arc<ChargedRequestSnapshot>>()
            .is_some()
        {
            return Err(ProjectionRefused);
        }
        let headers = std::mem::take(&mut parts.headers);
        let carrier = parts.extensions.remove::<Carrier>();
        Ok(Self {
            headers,
            _carrier: carrier,
        })
    }
}

/// Fund the replacement before touching the existing entry. Planned native maps stay in
/// hardened mode; remove then insert frees a unique slot and collapses all duplicates.
pub fn replace_if_match<B>(
    request: &mut Request<B>,
    bytes: &[u8],
) -> Result<(), ProjectionRefused> {
    let value = if let Some(carrier) = request.extensions().get::<Carrier>() {
        if !carrier.matches(request.extensions()) {
            return Err(ProjectionRefused);
        }
        let bytes = carrier
            .0
            .snapshot
            .request()
            .copy_input(bytes)
            .map_err(|_| ProjectionRefused)?
            .into_bytes();
        HeaderValue::from_maybe_shared(bytes).map_err(|_| ProjectionRefused)?
    } else {
        if request
            .extensions()
            .get::<Arc<ChargedRequestSnapshot>>()
            .is_some()
        {
            return Err(ProjectionRefused);
        }
        HeaderValue::from_bytes(bytes).map_err(|_| ProjectionRefused)?
    };
    let headers = request.headers_mut();
    if headers.get_all(header::IF_MATCH).iter().count() == 1 {
        *headers.get_mut(header::IF_MATCH).ok_or(ProjectionRefused)? = value;
    } else {
        headers.remove(header::IF_MATCH).ok_or(ProjectionRefused)?;
        headers.insert(header::IF_MATCH, value);
    }
    Ok(())
}
