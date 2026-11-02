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

pub use busbar_contract::diagnostic::{Banner, Class, Diagnostic, Severity};

/// ONE RUNTIME CATALOGUE: the neutral built-ins ([`REGISTRY`]) and the plane-contributed and
/// plugin-declared entries the composition root folded, lent by value. `Copy`: the root folds once
/// and leaks the fold, and every reader (the plugin observer, the main log's declared-diagnostic
/// line, a rendered page) holds the same rows by pointer.
#[derive(Clone, Copy, Debug)]
pub struct Catalogue {
    installed: &'static [&'static Diagnostic],
}

impl Catalogue {
    pub const NEUTRAL: Catalogue = Catalogue { installed: &[] };

    #[must_use]
    pub const fn lent(installed: &'static [&'static Diagnostic]) -> Catalogue {
        Catalogue { installed }
    }

    #[must_use]
    pub fn installed(self) -> &'static [&'static Diagnostic] {
        self.installed
    }

    #[must_use]
    pub fn all(self) -> Vec<&'static Diagnostic> {
        REGISTRY
            .iter()
            .copied()
            .chain(self.installed.iter().copied())
            .collect()
    }

    #[must_use]
    pub fn by_code(self, code: u16) -> Option<&'static Diagnostic> {
        REGISTRY
            .iter()
            .copied()
            .chain(self.installed.iter().copied())
            .find(|d| d.code == code)
    }
}

include!(concat!(env!("OUT_DIR"), "/diagnostics_catalog.rs"));

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

pub fn render_json_for(catalog: &[&Diagnostic]) -> String {
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
