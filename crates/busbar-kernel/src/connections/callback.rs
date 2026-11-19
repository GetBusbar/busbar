// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The caller-connection callback route (IF §12.12 round 21): K10 serves the browser's return from the
//! authorization server on each upstream's `connect_callback` path (the path of its `connection` form's
//! `redirect_uri`), so the operator's registered `redirect_uri` keeps working. Each path is a GET claim on the
//! data listener under §12.26 ([`CallbackPath::claim`]): a path another owner already claims refuses the config,
//! never shadows it. The answer page is core's own text; no plugin text reaches the browser.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_contract::route::METHOD_GET;

use crate::path_claims::{ListenerId, PathClaim};
use crate::upstreams::{ConfiguredUpstreams, Upstreams};

/// What the callback came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallbackAnswer {
    /// The grant is stored: send the browser to `location` (the BEGIN's checked `return_to`).
    Connected { location: Box<str> },
    /// The state is unknown, spent, expired or was minted for another callback path, or the auth plugin answered
    /// SECURITY_CHECK (e.g. an `iss` mismatch): nothing is stored.
    SecurityCheck,
    /// The auth instance or the store could not finish: nothing is stored; the caller starts the connection again.
    Failed,
}

impl CallbackAnswer {
    /// The browser response: 303 to `location`, or core's security-check (400) or failed (502) page. Never cached.
    #[must_use]
    pub fn into_response(self) -> Response {
        let no_store = (header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        match self {
            Self::Connected { location } => match HeaderValue::from_str(&location) {
                Ok(location) => (
                    StatusCode::SEE_OTHER,
                    [no_store, (header::LOCATION, location)],
                )
                    .into_response(),
                Err(_) => Self::Failed.into_response(),
            },
            Self::SecurityCheck => (
                StatusCode::BAD_REQUEST,
                [no_store],
                "The connection couldn't be verified (the security check didn't match). Start the connection again.",
            )
                .into_response(),
            Self::Failed => (
                StatusCode::BAD_GATEWAY,
                [no_store],
                "The connection couldn't be completed. Start the connection again.",
            )
                .into_response(),
        }
    }
}
