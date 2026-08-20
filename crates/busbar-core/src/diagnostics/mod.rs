// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The diagnostics catalog: every operator-facing `warn!`/`error!` carries a stable
//! `BUSBAR-NNNN` code an operator can paste into the docs and land on an entry that says what
//! it means, whether it needs action, and what to do.
//!
//! This module is the SINGLE SOURCE OF TRUTH (the "internal_errors" registry). Each diagnostic
//! is a [`Diagnostic`] const; [`REGISTRY`] collects them all. The `docs/diagnostics.md` page and
//! `docs/diagnostics.json` are GENERATED from `REGISTRY` (see [`render_markdown`]/[`render_json`])
//! and a test asserts the committed files match a fresh render, so the docs can never drift.
//!
//! ## Codes
//!
//! `BUSBAR-NNNN`. The thousands digit is the [`Class`]; the last three are the member. Codes are
//! append-only and immutable: retiring a diagnostic sets `retired: true` and keeps the number, so
//! an operator's old logs stay resolvable. Never recycle a number.
//!
//! ## Emitting
//!
//! Use [`diag_warn!`], [`diag_error!`], [`diag_debug!`] instead of the bare `tracing` macros. They
//! attach the `diag = "BUSBAR-NNNN"` field so the code shows in every line and is greppable:
//!
//! ```ignore
//! use crate::diagnostics::{diag_warn, DURABLE_WRITETHROUGH_BELOW_FLOOR};
//! diag_warn!(DURABLE_WRITETHROUGH_BELOW_FLOOR, seq, durable_floor, "seq predates the durable floor");
//! ```
//!
//! ## Severity → level
//!
//! [`Severity::BenignRecurring`] is the log-spam bucket: expected, self-healing, may fire per
//! request/tick — it lives at `debug!` or a `warn!`-once latch, NEVER an unlatched `warn!`.
//! [`Severity::Actionable`] is a `warn!`/`error!` at human cadence (latched if it can recur).
//! [`Severity::Fatal`] is a boot refusal / exit.

use std::fmt;

#[cfg(test)]
mod tests;

/// The class of a diagnostic — the thousands digit of its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// 1000 — durable audit floor, single-writer detach, store-outage backfill.
    Durability,
    /// 2000 — audit chain verification, tamper evidence, snapshot restore.
    Audit,
    /// 3000 — config.yaml parse/validate/schema, providers file, overrides.
    Config,
    /// 4000 — tokens, oauth_as/cimd, egress_auth, trust, sigv4 credentials.
    Auth,
    /// 5000 — upstream, egress gate, SSRF guard, breaker, availability, handlers.
    Proxy,
    /// 6000 — loader, ABI floor, signature/trust, plugin_routes, hooks.
    Plugins,
    /// 7000 — a2a, mcp, export, ir, proto, plane store.
    Plane,
    /// 8000 — holds, quotas, metering, appbuild, governance state.
    Governance,
    /// 9000 — startup, tls, telemetry, eventstream, preflight, jemalloc.
    Boot,
}

impl Class {
    /// The thousands multiplier: `Durability` → 1, `Boot` → 9. The code's `code / 1000`.
    pub const fn ordinal(self) -> u16 {
        match self {
            Class::Durability => 1,
            Class::Audit => 2,
            Class::Config => 3,
            Class::Auth => 4,
            Class::Proxy => 5,
            Class::Plugins => 6,
            Class::Plane => 7,
            Class::Governance => 8,
            Class::Boot => 9,
        }
    }

    /// Human title for the class, used as the section heading in the generated docs page.
    pub const fn title(self) -> &'static str {
        match self {
            Class::Durability => "Durability & write-through",
            Class::Audit => "Audit chain",
            Class::Config => "Config",
            Class::Auth => "Auth & identity",
            Class::Proxy => "Proxy & routing",
            Class::Plugins => "Plugins",
            Class::Plane => "Plane protocols",
            Class::Governance => "Governance & cost",
            Class::Boot => "Boot & lifecycle",
        }
    }

    /// Every class, in code order — the iteration order for the generated docs.
    pub const ALL: [Class; 9] = [
        Class::Durability,
        Class::Audit,
        Class::Config,
        Class::Auth,
        Class::Proxy,
        Class::Plugins,
        Class::Plane,
        Class::Governance,
        Class::Boot,
    ];
}

/// How severe a diagnostic is — this decides the log level the emitting site uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Expected, self-healing, may fire per request/tick. `debug!` or a `warn!`-once latch.
    BenignRecurring,
    /// An operator can and should act (misconfig, outage, refusal). `warn!` or `error!`.
    Actionable,
    /// Boot refuses / the process exits. `error!` then exit.
    Fatal,
}

impl Severity {
    /// Stable lowercase token for the machine (`diagnostics.json`) form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::BenignRecurring => "benign_recurring",
            Severity::Actionable => "actionable",
            Severity::Fatal => "fatal",
        }
    }
}

/// One catalog entry. Constructed as a `const` per code; all are gathered into [`REGISTRY`].
#[derive(Debug, Clone, Copy)]
pub struct Diagnostic {
    /// The numeric code, e.g. `1001`. Rendered as `BUSBAR-1001`.
    pub code: u16,
    /// The class this code belongs to; `class.ordinal()` must equal `code / 1000`.
    pub class: Class,
    /// Stable kebab-case anchor: the docs URL fragment and a rename-proof identity. Never changes.
    pub slug: &'static str,
    /// Short human title.
    pub title: &'static str,
    /// Intended severity → the log level the emitting site uses.
    pub severity: Severity,
    /// One to three sentences: what the condition means.
    pub summary: &'static str,
    /// What an operator should do, or `"None — self-heals."` for benign-recurring.
    pub action: &'static str,
    /// The version the code was introduced in.
    pub since: &'static str,
    /// A retired code: kept for historical log resolution, no longer emitted.
    pub retired: bool,
}

impl Diagnostic {
    /// The `BUSBAR-NNNN` banner, zero-allocation (a [`fmt::Display`] wrapper over the code).
    pub const fn banner(&self) -> Banner {
        Banner(self.code)
    }
}

/// `Display`s as `BUSBAR-0001`. Used as the `diag` field on every emitted line.
#[derive(Debug, Clone, Copy)]
pub struct Banner(pub u16);

impl fmt::Display for Banner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BUSBAR-{:04}", self.0)
    }
}

/// Look a code up (e.g. for a future `GET /diagnostics` or a CLI `busbar explain 1001`).
pub fn by_code(code: u16) -> Option<&'static Diagnostic> {
    REGISTRY.iter().copied().find(|d| d.code == code)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CATALOG. Add a const here (codes ascending within a class), then add it to REGISTRY below,
// then regenerate the docs: `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-core diagnostics`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The archetype: an audit entry whose seq is at/below the recovered durable floor.
pub const DURABLE_WRITETHROUGH_BELOW_FLOOR: Diagnostic = Diagnostic {
    code: 1001,
    class: Class::Durability,
    slug: "durable-writethrough-below-floor",
    title: "Durable audit write-through skipped (seq at or below the recovered floor)",
    severity: Severity::BenignRecurring,
    summary: "An audit entry's sequence number is at or below the recovered durable floor, so it \
              is already persisted under that seq and the write-through is correctly skipped — the \
              entry is retained in the in-memory ring. A single occurrence at boot is expected \
              after a durable-store restore.",
    action:
        "None — self-healing. If it warns repeatedly for DIFFERENT sequence numbers, suspect a \
             second node writing the same durable store (see BUSBAR-1002).",
    since: "1.6.0",
    retired: false,
};

/// A tail ahead of what this node persisted — a second writer on the same durable audit store.
pub const DURABLE_SECOND_WRITER_DETACH: Diagnostic = Diagnostic {
    code: 1002,
    class: Class::Durability,
    slug: "durable-second-writer-detach",
    title: "Durable audit log has another writer — this node detached its durable sink",
    severity: Severity::Actionable,
    summary: "The durable audit store's tail is ahead of what this node last persisted, which can \
              only mean a second busbar is writing the same store. The durable audit log supports \
              exactly ONE writer; two nodes overwrite each other's entries and break the hash \
              chain, which the next boot reports as tampering. This node has detached its durable \
              sink and now audits only to its ephemeral in-memory ring.",
    action: "Ensure exactly one busbar instance is pointed at this durable audit store. Give the \
             other instance its own store, then restart this node to re-attach a durable sink.",
    since: "1.6.0",
    retired: false,
};

/// The in-memory audit ring is not yet reconciled with the durable tail, so writes are held.
pub const DURABLE_AUDIT_RING_UNRECONCILED: Diagnostic = Diagnostic {
    code: 1003,
    class: Class::Durability,
    slug: "durable-audit-ring-unreconciled",
    title: "Durable audit write-through held — ring not yet reconciled with the durable tail",
    severity: Severity::Actionable,
    summary:
        "This process's in-memory audit ring is not yet reconciled with the durable tail (the \
              boot restore did not read or verify it, and a retry read is still failing), so the \
              write-through is held rather than risk overwriting durable history. The entry is \
              retained in the RAM ring and will backfill once the store answers with a verifiable \
              tail.",
    action:
        "Check the durable audit store is reachable and returns a verifiable tail. This clears \
             itself once a tail read succeeds (logged as recovery at info level).",
    since: "1.6.0",
    retired: false,
};

/// Appending an audit entry to the durable store failed — a store outage; entry retained in RAM.
pub const DURABLE_AUDIT_WRITETHROUGH_FAILED: Diagnostic = Diagnostic {
    code: 1004,
    class: Class::Durability,
    slug: "durable-audit-writethrough-failed",
    title: "Durable audit write-through failed (entry retained in the in-memory ring)",
    severity: Severity::Actionable,
    summary: "Appending an audit entry to the durable store failed — typically a durable-store \
              outage. The entry is retained in the in-memory ring and the state snapshot and will \
              backfill on the next successful write-through, so nothing is lost from the ring.",
    action: "Investigate the durable audit store outage. No entries are lost from the in-memory \
             ring; they persist once the store recovers and the next mutation backfills them.",
    since: "1.6.0",
    retired: false,
};

/// A durable-chain seq was pruned from the ring before it could persist — an unrepairable gap.
pub const DURABLE_AUDIT_BACKFILL_GAP: Diagnostic = Diagnostic {
    code: 1005,
    class: Class::Durability,
    slug: "durable-audit-backfill-gap",
    title: "Durable audit chain has an unrepairable gap (a seq was pruned before it persisted)",
    severity: Severity::Actionable,
    summary: "A durable-chain sequence number is no longer in the in-memory ring (it was pruned \
              during a store outage longer than the ring bound), so it can never be backfilled \
              in-process. The durable chain therefore has an unrepairable gap at that seq and \
              catch-up stops below the hole. This is real durable-audit data loss for that seq.",
    action: "Recent entries remain in the in-memory ring, but the DURABLE log has a permanent gap \
             at the named seq. Resolve the store outage that caused it; restore the durable store \
             from a backup if the durable chain's completeness is required for compliance.",
    since: "1.6.0",
    retired: false,
};

/// EVERY diagnostic, in ascending code order. The tests assert uniqueness and class alignment.
pub static REGISTRY: &[&Diagnostic] = &[
    &DURABLE_WRITETHROUGH_BELOW_FLOOR,
    &DURABLE_SECOND_WRITER_DETACH,
    &DURABLE_AUDIT_RING_UNRECONCILED,
    &DURABLE_AUDIT_WRITETHROUGH_FAILED,
    &DURABLE_AUDIT_BACKFILL_GAP,
];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Emit macros. `pub(crate)` — internal to busbar-core. Sites `use crate::diagnostics::diag_warn;`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const.
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field.
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm).
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}
pub(crate) use {diag_debug, diag_error, diag_warn};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Doc generation — `docs/diagnostics.md` (human) and `docs/diagnostics.json` (machine).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Path of the committed markdown page, relative to the repo root (this crate is `crates/busbar-core`).
pub const COMMITTED_DIAGNOSTICS_MD: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.md");
/// Path of the committed machine-readable catalog.
pub const COMMITTED_DIAGNOSTICS_JSON: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");

/// Render the operator-facing markdown page from [`REGISTRY`]: one section per class, a table
/// anchored by slug so `…/diagnostics#<slug>` deep-links.
pub fn render_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Busbar diagnostics catalog\n\n");
    out.push_str(
        "Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its \
         `diag` field. Find the code below for what it means, whether it needs action, and what \
         to do. This page is generated from the code — do not edit by hand.\n\n",
    );
    out.push_str("Codes are grouped by class (the thousands digit).\n\n");
    for class in Class::ALL {
        let mut rows: Vec<&Diagnostic> = REGISTRY
            .iter()
            .copied()
            .filter(|d| d.class == class)
            .collect();
        if rows.is_empty() {
            continue;
        }
        rows.sort_by_key(|d| d.code);
        out.push_str(&format!(
            "## {}xxx — {}\n\n",
            class.ordinal(),
            class.title()
        ));
        for d in rows {
            let retired = if d.retired { " *(retired)*" } else { "" };
            out.push_str(&format!(
                "<a id=\"{slug}\"></a>\n### {banner} — {title}{retired}\n\n\
                 - **Severity:** {sev}\n- **Since:** {since}\n- **Slug:** `{slug}`\n\n\
                 {summary}\n\n**What to do:** {action}\n\n",
                slug = d.slug,
                banner = d.banner(),
                title = d.title,
                retired = retired,
                sev = d.severity.as_str(),
                since = d.since,
                summary = d.summary,
                action = d.action,
            ));
        }
    }
    out
}

/// Render the machine-readable catalog (stable field order, pretty, trailing newline).
pub fn render_json() -> String {
    // Hand-rolled to avoid a serde derive dependency on a doc artifact and to pin field order.
    let mut items = Vec::new();
    let mut sorted = REGISTRY.to_vec();
    sorted.sort_by_key(|d| d.code);
    for d in sorted {
        items.push(format!(
            "  {{\n    \"code\": \"{banner}\",\n    \"number\": {num},\n    \"class\": \"{class}\",\n    \
             \"slug\": \"{slug}\",\n    \"title\": {title},\n    \"severity\": \"{sev}\",\n    \
             \"summary\": {summary},\n    \"action\": {action},\n    \"since\": \"{since}\",\n    \
             \"retired\": {retired}\n  }}",
            banner = d.banner(),
            num = d.code,
            class = class_key(d.class),
            slug = d.slug,
            title = json_str(d.title),
            sev = d.severity.as_str(),
            summary = json_str(d.summary),
            action = json_str(d.action),
            since = d.since,
            retired = d.retired,
        ));
    }
    format!("[\n{}\n]\n", items.join(",\n"))
}

/// Stable lowercase key for a class in the JSON form.
fn class_key(c: Class) -> &'static str {
    match c {
        Class::Durability => "durability",
        Class::Audit => "audit",
        Class::Config => "config",
        Class::Auth => "auth",
        Class::Proxy => "proxy",
        Class::Plugins => "plugins",
        Class::Plane => "plane",
        Class::Governance => "governance",
        Class::Boot => "boot",
    }
}

/// Minimal JSON string escaping for the doc artifact (quote, backslash, control chars).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
