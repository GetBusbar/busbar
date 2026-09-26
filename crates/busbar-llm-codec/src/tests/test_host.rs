// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST HOST: what this crate's own tests reach in the host, over its dev-dependency on the
//! kernel — the test registration seam (which also arms the host services a composition root arms),
//! the egress-auth unit a dialect's declared credential scheme is presented by, and the operator
//! `error_map` classifier. Test-only by construction (`#[cfg(test)]` at its one `mod` line).

use busbar_contract::http;
use busbar_contract::protocol::SigningContext;
use busbar_contract::upstream::{CanonicalSignal, RawUpstreamError};

/// Publish this plane's dialect declarations into the host's test registry, ONCE — the lazy
/// counterpart of the composition root's `install_protocols` for a test binary, where no `main` runs
/// one. Registration is also where the host arms the services the plane reaches through the contract
/// (entropy, the wall clock, the translation cap, the usage-tap count), so a test that mints an id or
/// taps usage sees the host a shipped binary has. `Once`-guarded.
pub fn ensure_test_protocols_registered() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| busbar_kernel::proto::register_test_protocols(crate::DECLS));
}

/// The credential headers the host presents for `key` on a lane of `protocol` (#83a S2-a) — the
/// kernel's egress-auth unit reading this plane's DECLARED egress scheme, exactly as an egress
/// request is decorated. A dialect's auth is asserted through here, never through a builder of its
/// own: the plane holds no credential.
pub fn presented_auth_headers(
    protocol: &str,
    key: &str,
    ctx: &SigningContext,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    ensure_test_protocols_registered();
    busbar_kernel::egress_auth::resolve(protocol, None).headers_for(key, ctx)
}

/// A signing context for a static-credential presentation — a lane's own key, a JSON body to a
/// plain path. A static scheme reads nothing from it but the credential mode.
pub fn test_signing_ctx() -> SigningContext<'static> {
    SigningContext {
        host: "upstream.internal",
        canonical_uri: "/v1/chat/completions",
        body: b"{}",
        timestamp_epoch: 1_752_000_000,
        upstream_creds: busbar_contract::config::UpstreamCreds::Own,
    }
}

/// The host's operator `error_map` classifier over an EMPTY map — the release path's second stage,
/// which the per-dialect classification tests drive through `ProtocolReader::classify`.
pub fn classify_with_no_error_map(raw: &RawUpstreamError) -> CanonicalSignal {
    busbar_kernel::breaker::normalize_raw_error(raw, &std::collections::HashMap::new())
}
