// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL HOP SPECIFICATION — the pure-data description of one outbound governed hop a plane
//! hands the host-mediated fetch adapter.
//!
//! [`HopSpec`] names only `std` types (a couple of borrowed slices, two allowlist flags, two opaque
//! host-side refs, a deadline and an already-judged pinned address). The FETCH ADAPTER that consumes
//! it — the `buffered` / `stream_head` / `pump` drivers that reach the `plane_host` FFI egress vtable
//! — stays in `busbar_core::egress::seam`, because that half drives core-owned unsafe drivers. This
//! is only the neutral INPUT to that adapter, relocated so a plane crate builds a hop spec without
//! reaching into core; core re-exports it, so `busbar_core::egress::seam::HopSpec` still resolves.

/// The one hop the adapter opens, as neutral data. The plane composes protocol on top; this carries
/// only what an outbound request IS — verb, url, headers, body — plus the host's allowlist stance and
/// the opaque mTLS client-identity ref (never a key).
pub struct HopSpec<'a> {
    pub verb: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// The host allowlist stance for this hop (lowered from the plane's per-registration policy).
    pub allow_private: bool,
    pub allow_plaintext: bool,
    /// The opaque host-side client-identity ref (`0` = present none). Never a key.
    pub client_identity_ref: u64,
    /// The opaque host-side trust-anchor ref (`0` = no extra roots — trust only the platform roots).
    /// Never certificate bytes. Carries a private-CA registration (the a2a `trusting_root` fixture).
    pub trust_anchor_ref: u64,
    /// The per-hop end-to-end deadline. [`Duration::ZERO`] ⇒ the host's default ceiling.
    pub timeout: std::time::Duration,
    /// The plane's ALREADY-JUDGED pinned address for this hop (Design A). `Some` ⇒ the host connects
    /// to THIS address and does NOT resolve the URL host (the plane resolved-then-pinned plane-side and
    /// hands the survivor over); `None` ⇒ the host resolves the URL host itself. The URL host is still
    /// used for SNI / cert-name / mTLS in either case.
    pub resolved_addr: Option<std::net::IpAddr>,
}
