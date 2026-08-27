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
    "src/proxy/response_body.rs",
    "src/proxy/usage.rs",
    "src/proxy/hooks.rs",
    "src/proxy/engine/mod.rs",
    "src/proxy/engine/walk.rs",
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
    "src/sigv4.rs",
    "src/governance/mod.rs",
    "src/governance/revocation.rs",
    "src/governance/state.rs",
    "src/appbuild.rs",
    "src/boot.rs",
    "src/eventstream.rs",
    "src/preflight.rs",
    "src/telemetry.rs",
    "src/tls.rs",
    "src/config/overlay.rs",
    "src/config/mod.rs",
    "src/config_validate/mod.rs",
    // The A2A plane's sources moved to the `busbar-a2a` crate (the plane extraction). Unlike the MCP
    // entries below (dropped), these are REPOINTED to the sibling crate so core keeps enforcing their
    // uncoded-diagnostic floor — the same files, at their new home, read relative to this manifest.
    "../busbar-a2a/src/a2a/mod.rs",
    "../busbar-a2a/src/a2a/serve.rs",
    "../busbar-a2a/src/a2a/route.rs",
    "../busbar-a2a/src/a2a/transport.rs",
    "../busbar-a2a/src/a2a/pushback.rs",
    "../busbar-a2a/src/a2a/receive.rs",
    "../busbar-a2a/src/a2a/local.rs",
    "../busbar-a2a/src/a2a/verbs.rs",
    "../busbar-a2a/src/a2a/pushdeliver.rs",
    "../busbar-a2a/src/a2a/originate.rs",
    "../busbar-a2a/src/a2a/plane.rs",
    // The MCP plane's sources moved to the `busbar-mcp` crate (Phase-B B2); their uncoded-diagnostic
    // floor is enforced by that crate's own suite now, so core no longer scans them here.
    "src/export/webhook.rs",
    "src/export/file.rs",
    "src/ir/mod.rs",
    "src/proto/mod.rs",
    "src/plane/taskstore.rs",
    "src/plane/approvals.rs",
    "src/plane/quarantine.rs",
    "src/plane/calllog.rs",
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
