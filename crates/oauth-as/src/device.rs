// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Device authorization grant shapes, mirrored from RFC 8628: the section 3.2 device authorization
//! response, and the grant record whose state machine [`crate::server::AuthorizationServer`]
//! drives (`Pending` to `Approved`/`Denied`, expiry by clock, single-use redemption by removal).

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::client::ClientId;
use crate::scope::ScopeSet;

/// The RFC 8628 section 3.2 device authorization response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code the device polls the token endpoint with.
    pub device_code: String,
    /// The short code the end user types at `verification_uri`.
    pub user_code: String,
    /// Where the user goes to enter the code.
    pub verification_uri: String,
    /// `verification_uri` with the code embedded, for QR codes and deep links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of `device_code` and `user_code` in seconds (REQUIRED by the RFC).
    pub expires_in: u64,
    /// Minimum seconds between token-endpoint polls (the RFC default is 5).
    pub interval: u64,
}

/// Where a device grant stands in its lifecycle. Expiry is not a stored state: it is derived from
/// [`DeviceGrant::expires_at`] against the clock, so a grant cannot be "un-expired" by a state
/// write and an expired-but-unpolled grant needs no sweeper to be correct (hosts may still sweep
/// storage for hygiene).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceGrantState {
    /// Waiting for the user to act at the verification URI.
    Pending,
    /// The user approved; the next well-paced poll redeems the grant (single use).
    Approved {
        /// The authenticated resource owner who approved.
        subject: String,
    },
    /// The user declined; the next poll returns `access_denied`.
    Denied,
}

/// One device grant, persisted through [`crate::store::Storage`] keyed by `device_code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGrant {
    /// The device verification code (the storage key; high-entropy, never shown to the user).
    pub device_code: String,
    /// The user-facing code, in display form (for example `WDJB-MJHT`). Lookups go through
    /// [`normalize_user_code`], so user entry is case- and hyphen-insensitive per the RFC 8628
    /// section 6.1 recommendation.
    pub user_code: String,
    /// The client the grant was authorized for; polls from any other client are `invalid_grant`.
    pub client_id: ClientId,
    /// The scope that will be granted on approval.
    pub scope: ScopeSet,
    /// Lifecycle state; see [`DeviceGrantState`].
    pub state: DeviceGrantState,
    /// Issuance instant.
    pub created_at: SystemTime,
    /// Expiry instant; at and after this the poll answer is `expired_token` (once) and the grant
    /// is removed.
    pub expires_at: SystemTime,
    /// The CURRENT minimum poll spacing. Starts at the configured interval and grows by the
    /// server's `slow_down` increment (RFC 8628 section 3.5: plus 5 seconds) each time the device
    /// polls too fast, mirroring the pace the client is required to adopt.
    pub interval: Duration,
    /// When the device last polled; `None` until the first poll. The first poll is never
    /// `slow_down`.
    pub last_poll_at: Option<SystemTime>,
}

/// Normalize a user-typed code for lookup: uppercase, with hyphens and whitespace removed
/// (RFC 8628 section 6.1 recommends processing "with all these variations").
pub fn normalize_user_code(entered: &str) -> String {
    entered
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_authorization_response_shape_is_rfc8628_3_2() {
        let r = DeviceAuthorizationResponse {
            device_code: "dc".into(),
            user_code: "WDJB-MJHT".into(),
            verification_uri: "https://example.com/device".into(),
            verification_uri_complete: None,
            expires_in: 600,
            interval: 5,
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({
                "device_code": "dc",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "expires_in": 600,
                "interval": 5,
            }),
            "absent verification_uri_complete must be omitted, not null"
        );
    }

    #[test]
    fn user_code_normalization_is_case_hyphen_and_space_insensitive() {
        for entry in [
            "WDJB-MJHT",
            "wdjb-mjht",
            "wdjbmjht",
            " wdjb mjht ",
            "WdJb-MjHt",
        ] {
            assert_eq!(normalize_user_code(entry), "WDJBMJHT", "entry {:?}", entry);
        }
    }
}
