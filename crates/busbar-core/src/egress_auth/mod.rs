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

// The crate-wide license-header meta-test scans this crate's whole `src` (via `CARGO_MANIFEST_DIR`),
// so it stays with busbar-core; it is not egress-auth-specific.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;
