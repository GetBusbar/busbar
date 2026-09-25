// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAGNOSTIC SHAPES (DECISIONS #83: contract = shapes; #83a O3) — the catalog-entry struct a
//! plane FILLS to own its codes, its class and severity, the `BUSBAR-NNNN` banner every emitter
//! prints byte-for-byte, and the three emit macros that attach that banner as the shared
//! `diag = "BUSBAR-NNNN"` log field.
//!
//! The CATALOG itself — the kernel's codes, the registry, the composition-root install seam and the
//! docs renderers — is semantics and stays out of this crate. The one code that lives here is the
//! one both sides of the codec seam print ([`USAGE_TAP_DECODE_FAILED`], #83a O5): a code a plane and
//! the kernel both emit must be one constant, never two numbers.
//!
//! Relocated, module-path-only and byte-identical, from `busbar-substrate-values::diagnostics`,
//! which re-exports every item under its historical path (and the three macros at its crate root),
//! so every caller compiles unchanged.
//!
//! ## Codes
//!
//! `BUSBAR-NNNN`. The thousands digit is the [`Class`]; the last three are the member. Codes are
//! append-only and immutable: retiring a diagnostic sets `retired: true` and keeps the number, so
//! an operator's old logs stay resolvable. Never recycle a number.

use std::fmt;

/// The class of a diagnostic — the thousands digit of its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// 1000 — durable audit floor, single-writer detach, store-outage backfill.
    Durability,
    /// 2000 — audit chain verification, tamper evidence, snapshot restore.
    Audit,
    /// 3000 — config.yaml parse/validate/schema, providers file, overrides.
    Config,
    /// 4000 — tokens, the authorization server, egress auth, trust, request-signing credentials.
    Auth,
    /// 5000 — upstream, egress gate, SSRF guard, breaker, availability, handlers.
    Proxy,
    /// 6000 — loader, ABI floor, signature/trust, plugin_routes, hooks.
    Plugins,
    /// 7000 — the planes, export, ir, proto, plane store.
    Plane,
    /// 8000 — holds, quotas, metering, appbuild, governance state.
    Governance,
    /// 9000 — startup, tls, telemetry, eventstream, preflight, the allocator.
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

/// One catalog entry. Constructed as a `const` per code; all are gathered into the catalog
/// registry.
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// CROSS-CRATE EMIT MACROS. `#[macro_export]` hoists each to this crate's ROOT
// (`busbar_contract::diag_warn!`). The expansion is `::tracing::warn!(diag = %DIAG.banner(), …)`:
// the EXPANDING crate supplies `tracing`, so this crate takes no logging dependency, and the field
// spelling is the shared log format every emitter writes.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const. The
/// one spelling every crate emits through.
#[macro_export]
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field. The one spelling every crate emits through.
#[macro_export]
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm). The
/// one spelling every crate emits through.
#[macro_export]
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ONE SHARED CODE (#83a O5): emitted on BOTH sides of the codec seam, so its constant is a shape.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Usage tap: read_response could not decode a same-protocol 2xx body. Warn-once (latched).
pub const USAGE_TAP_DECODE_FAILED: Diagnostic = Diagnostic {
    code: 5029,
    class: Class::Proxy,
    slug: "usage-tap-decode-failed",
    title: "Usage tap: read_response failed to decode a same-protocol 2xx body",
    severity: Severity::BenignRecurring,
    summary: "The usage tap's `read_response` could not decode a same-protocol 2xx body into the \
              IR, so it bills 0 tokens for the request. Warned once per (protocol, reason); \
              BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None — self-heals per request. If a metered dialect bills 0 tokens repeatedly, the \
             upstream's response shape may have changed; check for a busbar update covering it.",
    since: "1.6.0",
    retired: false,
};
