// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The diagnostics catalog: every operator-facing `warn!`/`error!` carries a stable
//! `BUSBAR-NNNN` code an operator can paste into the docs and land on an entry that says what
//! it means, whether it needs action, and what to do.
//!
//! This module is the SINGLE SOURCE OF TRUTH (the "internal_errors" registry). Its entries are
//! data, `catalog.toml` beside this file; `build.rs` renders each as a [`Diagnostic`] const, and
//! [`REGISTRY`] collects them all. The `docs/diagnostics.md` page and
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
//! Use [`diag_warn!`](crate::diag_warn), [`diag_error!`](crate::diag_error),
//! [`diag_debug!`](crate::diag_debug) instead of the bare `tracing` macros. They
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

mod emit;
pub use emit::emit;

#[cfg(test)]
#[path = "tests/catalog_tests.rs"]
mod catalog_tests;

// ── THE SHAPES live in `busbar_contract::diagnostic` (DECISIONS #83; #83a O3, SD-1): the entry struct
//    a plane fills, its class and severity, and the banner. Re-exported here under their historical
//    paths, so every caller (and every catalog const below) compiles unchanged.
pub use busbar_contract::diagnostic::{Banner, Class, Diagnostic, Severity};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE PLANE-CONTRIBUTED CATALOG. The neutral [`REGISTRY`] carries only the plane-AGNOSTIC built-in
// diagnostics; each extracted plane crate OWNS its own `Diagnostic` consts, and the composition
// root folds them (with every first-party plugin's declared codes) ONCE into a [`Catalogue`] it
// lends by value to every reader. The runtime catalog an operator sees is [`Catalogue::all`] —
// `REGISTRY ∪ the root's fold` — so a plane's codes resolve through [`Catalogue::by_code`] on the
// catalogue the root lent, and a build with a plane compiled out never sees (or renders) that
// plane's diagnostics. The kernel holds no catalogue of its own: everything crosses the ABI, the
// host names no plane const, and a plane never edits this file. Numbering/identity is preserved on
// the move — a plane const keeps its `BUSBAR-NNNN`, so an operator's old logs stay resolvable —
// codes are REGISTERED, never renumbered.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// ONE RUNTIME CATALOGUE: the neutral built-ins ([`REGISTRY`]) and the plane-contributed and
/// plugin-declared entries the composition root folded, lent by value. `Copy`: the root folds once
/// and leaks the fold, and every reader (the plugin observer, the main log's declared-diagnostic
/// line, a rendered page) holds the same rows by pointer.
#[derive(Clone, Copy, Debug)]
pub struct Catalogue {
    installed: &'static [&'static Diagnostic],
}

impl Catalogue {
    /// The neutral built-ins alone: a no-planes build, or a reader no root lent a fold to.
    pub const NEUTRAL: Catalogue = Catalogue { installed: &[] };

    /// The catalogue over `installed`, the root's fold of every linked plane's owned diagnostics and
    /// every first-party plugin's declared ones.
    #[must_use]
    pub const fn lent(installed: &'static [&'static Diagnostic]) -> Catalogue {
        Catalogue { installed }
    }

    /// The plane-contributed and plugin-declared entries the root folded, without the built-ins.
    #[must_use]
    pub fn installed(self) -> &'static [&'static Diagnostic] {
        self.installed
    }

    /// THE FULL RUNTIME CATALOG: neutral built-ins ([`REGISTRY`]) followed by the root's fold. This
    /// is what a `GET /diagnostics`, a CLI `explain`, or a rendered docs page reads — never the bare
    /// [`REGISTRY`], which is only the neutral half.
    #[must_use]
    pub fn all(self) -> Vec<&'static Diagnostic> {
        REGISTRY
            .iter()
            .copied()
            .chain(self.installed.iter().copied())
            .collect()
    }

    /// Look a code up across the FULL catalog (neutral built-ins ∪ the root's fold), e.g. for a
    /// plugin's reported banner or a CLI `busbar explain 1001`.
    #[must_use]
    pub fn by_code(self, code: u16) -> Option<&'static Diagnostic> {
        REGISTRY
            .iter()
            .copied()
            .chain(self.installed.iter().copied())
            .find(|d| d.code == code)
    }
}

// The emit macros a PLUGIN crate reaches are `busbar_contract`'s (#83a O3: the diagnostic shapes and
// the `diag = "BUSBAR-NNNN"` log format are the contract's); this crate's own `#[macro_export]`
// twins, which expand identically, are at the bottom of this module.

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CATALOG is data: `catalog.toml` beside this file. `build.rs` renders each entry as a
// `Diagnostic` const of the same name, and `REGISTRY` in the file's order.
// ─────────────────────────────────────────────────────────────────────────────────────────────
include!(concat!(env!("OUT_DIR"), "/diagnostics_catalog.rs"));

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Doc generation — `docs/diagnostics.md` (human) and `docs/diagnostics.json` (machine).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Render the operator-facing markdown page for an arbitrary catalog slice: one section per class, a
/// table anchored by slug so `…/diagnostics#<slug>` deep-links. Shared by the neutral snapshot and
/// each plane crate's own snapshot, so the doc form of every diagnostic is byte-identical wherever it
/// is owned.
pub fn render_markdown_for(catalog: &[&Diagnostic]) -> String {
    let mut out = String::new();
    out.push_str("# Busbar diagnostics catalog\n\n");
    out.push_str(
        "Every operator-facing log line from busbar carries a stable `BUSBAR-NNNN` code in its \
         `diag` field. Find the code below for what it means, whether it needs action, and what \
         to do. This page is generated from the code — do not edit by hand.\n\n",
    );
    out.push_str("Codes are grouped by class (the thousands digit).\n\n");
    for class in Class::ALL {
        let mut rows: Vec<&Diagnostic> = catalog
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

/// Render the machine-readable catalog for an arbitrary catalog slice (stable field order, pretty,
/// trailing newline). Shared by the neutral snapshot and each plane crate's own snapshot.
pub fn render_json_for(catalog: &[&Diagnostic]) -> String {
    // Hand-rolled to avoid a serde derive dependency on a doc artifact and to pin field order.
    let mut items = Vec::new();
    let mut sorted = catalog.to_vec();
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Emit macros. `#[macro_export]` (was crate-internal): an out-of-tree plugin crate relocated off
// core names these at `busbar_kernel::diagnostics::{diag_warn, diag_debug, diag_error}` on its own hot
// path, so they must cross the crate boundary — the one mechanism a `macro_rules!` has for that is `#[macro_export]`
// (which also surfaces them at the crate root). The `pub use` below re-exports them at their
// historical `crate::diagnostics::…` path so every in-crate `use crate::diagnostics::diag_warn;`
// caller is unchanged. Sites in this crate use `use crate::diagnostics::diag_warn;`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const.
#[macro_export]
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field.
#[macro_export]
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm).
#[macro_export]
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}
pub use crate::{diag_debug, diag_error, diag_warn};
