// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invariants that keep the diagnostics catalog honest, and the docs-in-sync gate.

use super::*;

/// No two registry entries share a code. A collision would make one code un-resolvable.
#[test]
fn codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for d in REGISTRY {
        assert!(
            seen.insert(d.code),
            "duplicate diagnostic code {} ({})",
            d.code,
            d.slug
        );
    }
}

/// The thousands digit of every code equals its class ordinal — the whole point of the scheme.
#[test]
fn code_thousands_digit_matches_class() {
    for d in REGISTRY {
        assert_eq!(
            d.code / 1000,
            d.class.ordinal(),
            "{} ({}) is in class {:?} (ordinal {}) but its code's thousands digit is {}",
            d.banner(),
            d.slug,
            d.class,
            d.class.ordinal(),
            d.code / 1000,
        );
        assert!(
            d.code % 1000 != 0,
            "{} ({}): the x000 slot is reserved for the class itself, not a member",
            d.banner(),
            d.slug
        );
    }
}

/// Slugs are unique, kebab-case, and non-empty — they are stable doc anchors and URL fragments.
#[test]
fn slugs_are_unique_and_kebab_case() {
    let mut seen = std::collections::BTreeSet::new();
    for d in REGISTRY {
        assert!(
            seen.insert(d.slug),
            "duplicate slug {:?} (code {})",
            d.slug,
            d.code
        );
        assert!(!d.slug.is_empty(), "{} has an empty slug", d.banner());
        assert!(
            d.slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "slug {:?} (code {}) is not kebab-case (lowercase/digits/hyphen only)",
            d.slug,
            d.code
        );
        assert!(
            !d.slug.starts_with('-') && !d.slug.ends_with('-') && !d.slug.contains("--"),
            "slug {:?} (code {}) has a leading/trailing/double hyphen",
            d.slug,
            d.code
        );
    }
}

/// The banner renders zero-padded to four digits: `BUSBAR-1001`, not `BUSBAR-1`.
#[test]
fn banner_is_zero_padded() {
    assert_eq!(
        DURABLE_WRITETHROUGH_BELOW_FLOOR.banner().to_string(),
        "BUSBAR-1001"
    );
    assert_eq!(Banner(42).to_string(), "BUSBAR-0042");
}

/// Every non-retired entry has a summary and an action — an operator who lands here must learn
/// what it means AND what to do.
#[test]
fn every_live_entry_documents_meaning_and_action() {
    for d in REGISTRY {
        if d.retired {
            continue;
        }
        assert!(
            d.summary.len() > 20,
            "{} ({}) has no real summary",
            d.banner(),
            d.slug
        );
        assert!(
            d.action.len() > 3,
            "{} ({}) has no action (use \"None — self-heals.\" if truly none)",
            d.banner(),
            d.slug
        );
    }
}

/// `by_code` resolves a known code and rejects an unknown one.
#[test]
fn lookup_by_code_works() {
    assert_eq!(
        by_code(1001).map(|d| d.slug),
        Some("durable-writethrough-below-floor")
    );
    assert!(by_code(9999).is_none());
}

// ── DOCS-IN-SYNC ────────────────────────────────────────────────────────────────────────────
//
// The committed docs/diagnostics.{md,json} MUST equal a fresh render of REGISTRY. Regenerate
// after any catalog change with:
//   UPDATE_DIAGNOSTICS=1 cargo test -p busbar-core diagnostics::tests

#[test]
fn committed_markdown_matches_registry() {
    let fresh = render_markdown();
    if std::env::var("UPDATE_DIAGNOSTICS").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_DIAGNOSTICS_MD, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_DIAGNOSTICS_MD}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_DIAGNOSTICS_MD).unwrap_or_else(|e| {
        panic!("read {COMMITTED_DIAGNOSTICS_MD}: {e} — generate it with UPDATE_DIAGNOSTICS=1")
    });
    assert_eq!(
        committed, fresh,
        "docs/diagnostics.md is stale — regenerate with \
         `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-core diagnostics::tests`"
    );
}

#[test]
fn committed_json_matches_registry() {
    let fresh = render_json();
    if std::env::var("UPDATE_DIAGNOSTICS").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_DIAGNOSTICS_JSON, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_DIAGNOSTICS_JSON}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_DIAGNOSTICS_JSON).unwrap_or_else(|e| {
        panic!("read {COMMITTED_DIAGNOSTICS_JSON}: {e} — generate it with UPDATE_DIAGNOSTICS=1")
    });
    assert_eq!(
        committed, fresh,
        "docs/diagnostics.json is stale — regenerate with UPDATE_DIAGNOSTICS=1"
    );
}

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
    "src/handlers/chat.rs",
    "src/handlers/mod.rs",
    "src/metrics.rs",
    "src/auth/exchange.rs",
    "src/auth/token.rs",
    "src/auth/mod.rs",
    "src/auth/self_keys.rs",
    "src/egress_auth/mod.rs",
    "src/egress_auth/bearer_token.rs",
    "src/trust/sweep.rs",
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
    "src/a2a/mod.rs",
    "src/a2a/serve.rs",
    "src/a2a/route.rs",
    "src/a2a/transport.rs",
    "src/a2a/pushback.rs",
    "src/a2a/receive.rs",
    "src/a2a/local.rs",
    "src/a2a/verbs.rs",
    "src/a2a/pushdeliver.rs",
    "src/a2a/originate.rs",
    "src/a2a/plane.rs",
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
