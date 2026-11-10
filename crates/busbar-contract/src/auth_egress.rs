// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared request-signing and credential-presentation descriptors.

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
#[derive()]
pub struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `runtime.region-1.example.com`. Borrowed from the lane's
    pub host: &'a str,
    /// URI-encoded request path (no query), e.g. `/model/vendor.model%3A0/invoke`. Borrowed (like
    pub canonical_uri: &'a str,
    /// The exact request body bytes that will be sent.
    pub body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub timestamp_epoch: u64,
    /// The UPSTREAM-credential mode for this request. Lets a writer resolve a credential whose scheme
    pub upstream_creds: crate::config::UpstreamCreds,
}

/// A protocol's declared egress credential-header builder: the resolved per-request credential
pub type EgressAuthHeaders = fn(&str, &SigningContext) -> Vec<(String, Vec<u8>)>;

impl<'a> std::fmt::Debug for SigningContext<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningContext")
            .field("host", &self.host)
            .field("canonical_uri", &"<redacted>")
            .field("body", &self.body)
            .field("timestamp_epoch", &self.timestamp_epoch)
            .field("upstream_creds", &self.upstream_creds)
            .finish()
    }
}
