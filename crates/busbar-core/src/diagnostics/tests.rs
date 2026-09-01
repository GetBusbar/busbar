// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The coverage lint that keeps core's own migrated files honest. The catalog invariants and the
//! docs-in-sync gate moved to `busbar-substrate` with the catalog; this test stays here because it
//! scans CORE's tree (via core's `CARGO_MANIFEST_DIR`).

// ── COVERAGE LINT (opt-in, grows per migrated file) ─────────────────────────────────────────
//
// Files listed here have been migrated to the `diag_*!` macros. The lint asserts each contains
// NO bare `tracing::warn!` / `tracing::error!` (every operator diagnostic in a migrated file must
// carry a code). Add a file here as its cluster is converted; the set grows until it covers the
// whole app, at which point coverage is total. This is what forces the audit to completion.

/// Paths relative to `crates/busbar-core` (this crate's manifest dir).
const MIGRATED_FILES: &[&str] = &[
    "src/admin/audit.rs",
    // The forward-engine sources (`proxy/response_body.rs`, `proxy/usage.rs`, `proxy/hooks.rs`,
    // `proxy/engine/{mod,walk}.rs`) RELOCATED to the `busbar-llm` plugin's `src/engine/` with the
    // money-path pivot (1.6.0 money-path Phase 3-4 C). Core does NOT scan a plane crate's tree — the
    // plane-purity lint forbids core naming a plane path — and `busbar-llm` carries its own
    // uncoded-diagnostic floor, so these are no longer listed here (mirroring the substrate/plane note).
    "src/handlers/mod.rs",
    "src/metrics.rs",
    "src/auth/exchange.rs",
    "src/auth/token.rs",
    "src/auth/mod.rs",
    "src/auth/self_keys.rs",
    "src/egress_auth/mod.rs",
    "src/egress_auth/bearer_token.rs",
    "src/trust/verify.rs",
    "src/oauth_as/plane.rs",
    // `sigv4` / `eventstream` (and the other neutral utils) RELOCATED to `busbar-substrate`; each
    // carries its own uncoded-diagnostic floor in that crate, so core no longer scans them here.
    "src/governance/mod.rs",
    "src/governance/revocation.rs",
    "src/governance/state.rs",
    "src/appbuild.rs",
    "src/boot.rs",
    "src/preflight.rs",
    "src/telemetry.rs",
    "src/tls.rs",
    "src/config/overlay.rs",
    "src/config/mod.rs",
    "src/config_validate/mod.rs",
    // The A2A and MCP plane sources moved to the sibling `busbar-a2a` / `busbar-mcp` crates (the plane
    // extraction). Core does NOT scan a plane crate's tree — a neutral crate must name no plane path
    // (the plane-purity lint enforces this); each plane crate enforces its own uncoded-diagnostic floor. So neither the
    // A2A nor the MCP sources are listed here.
    "src/export/webhook.rs",
    "src/export/file.rs",
    "src/ir/mod.rs",
    "src/proto/mod.rs",
    "src/plane/approvals.rs",
    "src/plane/quarantine.rs",
    "src/calllog.rs",
    "src/admin/mod.rs",
    "src/admin/v1/service.rs",
    "src/admin/v1/json/handlers.rs",
    "src/store/planes.rs",
    "src/store/in_memory/mod.rs",
    "src/store/in_memory/breaker.rs",
    "src/store/in_memory/availability.rs",
];

#[test]
fn migrated_files_have_no_uncoded_warn_or_error() {
    let root = env!("CARGO_MANIFEST_DIR");
    for rel in MIGRATED_FILES {
        let path = format!("{root}/{rel}");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read migrated file {path}: {e}"));
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue; // doc/comment mentions are fine
            }
            for needle in ["tracing::warn!", "tracing::error!"] {
                assert!(
                    !line.contains(needle),
                    "{rel}:{} still emits a bare `{needle}` — migrated files must use \
                     `diag_warn!`/`diag_error!` so every diagnostic carries a code:\n  {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }
}
