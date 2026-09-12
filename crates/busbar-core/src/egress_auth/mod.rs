// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE EGRESS-AUTH SEAM moved DOWN into `busbar-substrate` (the LLM plane named
//! `busbar_core::egress_auth` as its last backwards reach); this module re-exports it (glob) so
//! every historical `busbar_core::egress_auth::…` name — `resolve`, `prebuild_auth`,
//! `CredentialProvider`, `MetadataSsrfPolicy`, `api_key_headers`, and the `jwt_bearer` /
//! `oauth_client_credentials` mint modules — resolves unchanged, and hosts the two egress-auth
//! tests that must stay core-side (below).
//!
//! Mirrors the sibling `gate` submodule, which relocated the same way in Phase-B B1: the real
//! content lives in `busbar_substrate::egress_auth`, and the local `pub mod gate;` below keeps
//! core's own gate shim (which hosts the gate tests that name `crate::admin::audit`). The glob's
//! `gate` is shadowed by that explicit declaration.

pub use busbar_substrate::egress_auth::*;

/// THE SEAT for the token-endpoint judgement the two self-minting OAuth mechanisms are handed.
///
/// A `jwt-bearer` or `oauth-client-credentials` credential does not present a configured key: it
/// POSTs busbar's own authority — a signed service-account assertion, or a `client_id` and its
/// secret — to a configured token endpoint and takes a short-lived bearer back. So that endpoint is
/// not a destination like any other; it is the one place busbar hands its own credential over, and
/// two guards stand on it:
///
/// 1. TLS for a public host: `https` always, plaintext only for a private/loopback endpoint (a
///    co-located identity provider, the local-dev case).
/// 2. NEVER a cloud-metadata / IMDS endpoint the operator has not allow-listed — a typo or a
///    hostile template pointing the endpoint at the instance identity service would POST the
///    credential straight into it.
///
/// ## WHY THE JUDGEMENT IS SEATED HERE AND MADE ON THE UNIT'S PREDICATES
///
/// The two guards used to be written INSIDE the two credential mechanisms, in
/// `busbar_substrate::egress_auth`, each reaching into the substrate's own copy of the SSRF
/// control. That is the wrong place twice over: the substrate is frozen and dissolving (it may not
/// name the unit that owns this control, and it gains no dependency), and a mechanism that mints
/// over the network has no business also deciding what an address means — that decision is the
/// VERIFY half of egress auth. The mechanisms now render a verdict they are HANDED
/// ([`TokenEndpointVerdict`]) and hold no string predicate about an address at all.
///
/// The predicates this composes are the trust unit's `net` module — the ONE surviving copy of that
/// control, the copy `crates/busbar/tests/net_guard_extraction_parity.rs` pins against the dying
/// one — so this check cannot know a different metadata list, a different canonicalization or a
/// different allow-override rule from the destination check the same lane already went through.
///
/// It is seated in THIS crate because this crate is already the party that assembles the posture:
/// it builds the [`MetadataSsrfPolicy`] the `--validate` dry-run passes (`config_validate`) and the
/// one the boot/apply path carries to the plane that mints (`appbuild`'s `PlaneBuildInput`).
/// Seating the judge where the posture is assembled is what makes validate-time and apply-time the
/// SAME check rather than two checks that happen to agree — the asymmetry this closed was one
/// mechanism honouring the deployment-global stance and the other ignoring it. The edge it uses is
/// the legacy drain the kind table grants by name, and it dies with this crate: the composition
/// below is twenty lines and moves into the egress-auth unit on the first commit that can pay for
/// them (`loc-ceilings:unit-total` is pinned to its own measurement and carries no slack).
///
/// ORDER IS LOAD-BEARING. The scheme is judged FIRST, so a spelling with no scheme at all (a bare
/// `host:port`) is refused as insecure and never reaches the denylist arm — which is also why
/// composing on the surviving copy cannot change the answer for any input: the one place that copy
/// is deliberately STRICTER than the dying one (it judges a scheme-less authority instead of
/// ignoring it) sits behind a guard nothing scheme-less gets past.
///
/// A plain `fn` (not a closure) because that is the shape the seam takes: it travels by pointer
/// through the neutral plane-build carrier, which holds no type that could be compiled twice.
pub fn token_endpoint_judge(
    url: &str,
    ssrf: &MetadataSsrfPolicy<'_>,
) -> busbar_substrate::egress_auth::TokenEndpointVerdict {
    use busbar_substrate::egress_auth::TokenEndpointVerdict as Verdict;
    use busbar_unit_trust::net::{
        extract_normalized_host, host_is_private_or_loopback, scheme_is, ssrf_blocked_host,
    };
    let host_private = extract_normalized_host(url)
        .as_deref()
        .map(host_is_private_or_loopback)
        .unwrap_or(false);
    if !(scheme_is(url, "https") || (host_private && scheme_is(url, "http"))) {
        return Verdict::InsecureScheme;
    }
    match ssrf_blocked_host(
        url,
        ssrf.allow_overrides,
        ssrf.allow_all,
        ssrf.blocked_hosts,
    ) {
        Some(host) => Verdict::BlockedMetadataHost { host },
        None => Verdict::Admitted,
    }
}

// Core's gate re-export shim (hosts the core-only `gate_tests`, which name `crate::admin::audit` /
// `crate::audit`). Explicitly declared so it shadows the glob's `gate`.
pub mod gate;

// THE PREBUILT-AUTH DIFFERENTIAL PROOF stays core-side: `resolve` reads the LLM dialect
// `ProtocolDecl`s, and only core's `proto::decl_for` wrapper seeds a built-in decl under
// `#[cfg(test)]` — a bare `cargo test -p busbar-substrate` registers none, so `resolve("bedrock")`
// would there wrongly report lane-constant. It names only the re-exported `crate::egress_auth`
// surface plus `crate::proto` / `crate::config`, all still valid here.
#[cfg(test)]
#[path = "tests/prebuilt_auth_tests.rs"]
mod prebuilt_auth_tests;

// The seated token-endpoint judgement's own suite: the two guards, their ORDER, and the operator
// posture arriving intact. The cases are the ones the two credential mechanisms used to carry, one
// copy each; they are here now because the judgement is here now.
#[cfg(test)]
#[path = "tests/token_endpoint_tests.rs"]
mod token_endpoint_tests;

// The crate-wide license-header meta-test scans this crate's whole `src` (via `CARGO_MANIFEST_DIR`),
// so it stays with busbar-core; it is not egress-auth-specific.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;
