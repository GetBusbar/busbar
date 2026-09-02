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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE PLANE-CONTRIBUTED CATALOG SEAM. The neutral [`REGISTRY`] carries only the plane-AGNOSTIC
// built-in diagnostics; each extracted plane crate OWNS its own `Diagnostic` consts and hands them
// to [`install_diagnostics`] at the composition root, exactly as a plane hands its `&PlaneDecl` to
// `install_planes`. The runtime catalog an operator sees is [`all`] — `REGISTRY ∪ installed` — so a
// plane's codes resolve through [`by_code`] once registered, and a build with a plane compiled out
// never sees (or renders) that plane's diagnostics. Everything crosses the ABI: substrate names no
// plane const; a plane never edits this file. Numbering/identity is preserved on the move — a plane
// const keeps its `BUSBAR-NNNN`, so an operator's old logs stay resolvable — codes are REGISTERED,
// never renumbered.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Plane-contributed diagnostics installed by the COMPOSITION ROOT before the catalog is first read.
static INSTALLED: std::sync::OnceLock<&'static [&'static Diagnostic]> = std::sync::OnceLock::new();

/// INSTALL PLANE-CONTRIBUTED DIAGNOSTICS — the composition root's one write into the diagnostics
/// axis, and the seam an extracted plane crate registers its owned consts through. Exactly
/// `install_planes`' shape and contract on the diagnostics axis. `pub`, not `pub(crate)`: the
/// `busbar` binary is the composition root and calls this from `main` (`register_diagnostics`),
/// folding each linked plane's `DIAGNOSTICS` slice in before anything reads the catalog.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub fn install_diagnostics(diags: &'static [&'static Diagnostic]) {
    assert!(
        INSTALLED.set(diags).is_ok(),
        "install_diagnostics called twice: there is one composition root, and it registers once"
    );
}

/// The plane-contributed diagnostics registered at the composition root, or an empty slice when no
/// plane registered any (a no-planes build, or before `install_diagnostics` ran).
pub fn installed_diagnostics() -> &'static [&'static Diagnostic] {
    INSTALLED.get().copied().unwrap_or(&[])
}

/// THE FULL RUNTIME CATALOG: neutral built-ins ([`REGISTRY`]) followed by every plane-contributed
/// diagnostic the composition root installed. This is what a `GET /diagnostics`, a CLI `explain`, or
/// a rendered docs page reads — never the bare [`REGISTRY`], which is only the neutral half.
pub fn all() -> Vec<&'static Diagnostic> {
    REGISTRY
        .iter()
        .copied()
        .chain(installed_diagnostics().iter().copied())
        .collect()
}

/// Look a code up across the FULL catalog (neutral built-ins ∪ installed plane diagnostics), e.g.
/// for a future `GET /diagnostics` or a CLI `busbar explain 1001`.
pub fn by_code(code: u16) -> Option<&'static Diagnostic> {
    REGISTRY
        .iter()
        .copied()
        .chain(installed_diagnostics().iter().copied())
        .find(|d| d.code == code)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// CROSS-CRATE EMIT MACROS. busbar-core keeps its own `pub(crate)` `macro_rules!` twins for its 16
// in-tree call sites (a `pub(crate)` macro cannot cross a crate boundary), and these `#[macro_export]`
// versions are the ones a PLUGIN crate reaches: a plane extracted from core into its own crate can no
// longer name `crate::diagnostics::diag_warn`, so it emits coded diagnostics with the identical banner
// form through `busbar_substrate::diagnostics::{diag_warn, SOME_DIAG}`. The expansion is byte-identical
// to core's (`::tracing::warn!(diag = %DIAG.banner(), …)`); the expanding crate supplies `tracing`.
//
// `#[macro_export]` hoists the macro to the substrate CRATE ROOT, so a plugin reaches it as
// `busbar_substrate::diag_warn!` (imported `use busbar_substrate::{diag_warn, diag_error, diag_debug};`
// alongside the `Diagnostic` const it names). Deliberately NOT re-exported under this `diagnostics`
// module: core does `pub use busbar_substrate::diagnostics::*`, and a public macro re-export here would
// be glob-imported into core where core's own `pub(crate)` `diag_warn` shadows it — the exact
// crate-root pollution core's diagnostics header calls out. A crate-root-only export sidesteps that and
// still gives a future plugin the macro.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const. The
/// cross-crate twin of busbar-core's local `diag_warn!`.
#[macro_export]
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field. The cross-crate twin of core's `diag_error!`.
#[macro_export]
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm). The
/// cross-crate twin of core's `diag_debug!`.
#[macro_export]
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CATALOG. Add a const here (codes ascending within a class), then add it to REGISTRY below,
// then regenerate the docs: `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-substrate diagnostics`.
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

// ── 2000 — Audit chain ────────────────────────────────────────────────────────────────────────

/// The durable audit log failed hash-chain verification at boot — tamper evidence, not a read hiccup.
/// Lives in `boot.rs`, but the subject is the audit chain's integrity, so it is a 2000 code.
pub const AUDIT_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2001,
    class: Class::Audit,
    slug: "audit-chain-verify-failed",
    title: "Durable audit chain failed hash-chain verification at boot (tamper evidence)",
    severity: Severity::Actionable,
    summary:
        "The persisted durable audit log was read at boot but does NOT verify against its own \
              hash chain, so busbar started with an empty in-memory ring rather than trust a log \
              whose integrity is broken. This is distinct from a store read hiccup (BUSBAR-9001): \
              the bytes were read and the chain does not add up, which is tamper evidence — the \
              durable log was altered out from under busbar, or its store is corrupt.",
    action:
        "Treat the durable audit store as compromised until explained: capture it for forensic \
             review before it is overwritten. A verification failure means someone or something \
             rewrote persisted audit history; restore the store from a trusted backup once the \
             cause is understood. The running node audits only to its ephemeral ring until a \
             verifiable durable log is restored.",
    since: "1.6.0",
    retired: false,
};

// ── 3000 — Config ─────────────────────────────────────────────────────────────────────────────

/// The config overlay backend is not writable at boot; busbar serves but refuses config mutations.
pub const CONFIG_OVERLAY_NOT_WRITABLE: Diagnostic = Diagnostic {
    code: 3001,
    class: Class::Config,
    slug: "config-overlay-not-writable",
    title: "Config overlay backend is not writable (admin-API config mutations refused)",
    severity: Severity::Actionable,
    summary:
        "The config overlay backend is NOT writable at boot (typically the config directory is \
              mounted read-only), so busbar starts WITHOUT a durable config overlay: it serves \
              traffic normally, but every admin-API config mutation is refused, because a change \
              that cannot be persisted would silently revert on restart.",
    action:
        "If a read-only config is intended, set `config.locked: true` to say so and silence this \
             warning. If you want a mutable config, point `config.overlay.file` at a writable path \
             (mount a writable volume and set e.g. `config.overlay.file: \
             /var/lib/busbar/busbar-overlay.json`).",
    since: "1.6.0",
    retired: false,
};

/// The overlay writability probe file could not be removed after being created; it may leak.
pub const CONFIG_OVERLAY_PROBE_LEAK: Diagnostic = Diagnostic {
    code: 3002,
    class: Class::Config,
    slug: "config-overlay-probe-leak",
    title: "Overlay writability probe file could not be removed (may be left behind)",
    severity: Severity::Actionable,
    summary: "After creating a temporary probe file to test overlay writability, busbar could not \
              remove it. The probe name is pid-scoped, so a leaked probe is never reclaimed by a \
              later boot and slowly accumulates stray files in the config directory. Minor, but \
              surfaced rather than swallowed.",
    action: "Remove the leaked probe file(s) from the config directory and investigate why unlink \
             failed there (permissions, a network filesystem without delete-on-close). Overlay \
             writes still work; only the probe cleanup failed.",
    since: "1.6.0",
    retired: false,
};

/// A read-modify-write apply found the overlay unreadable/corrupt; refuses to overwrite it.
pub const CONFIG_OVERLAY_CORRUPT_REFUSE_WRITE: Diagnostic = Diagnostic {
    code: 3003,
    class: Class::Config,
    slug: "config-overlay-corrupt-refuse-write",
    title: "Config overlay unreadable/corrupt on apply (refusing to overwrite)",
    severity: Severity::Actionable,
    summary: "An admin apply tried to read-modify-write the config overlay but found the existing \
              overlay present yet unreadable/corrupt, so busbar REFUSED to overwrite it — a blind \
              overwrite would drop the hook AND group deletion tombstones every section carries and \
              could resurrect a deleted item. This apply was NOT persisted.",
    action: "Fix or remove the corrupt overlay file to restore durability, then re-apply. Until then \
             admin config mutations cannot be persisted (they are refused, not silently lost).",
    since: "1.6.0",
    retired: false,
};

/// A read-modify-write apply found the overlay written by a NEWER busbar; refuses to overwrite it.
pub const CONFIG_OVERLAY_VERSION_TOO_NEW_RMW: Diagnostic = Diagnostic {
    code: 3004,
    class: Class::Config,
    slug: "config-overlay-version-too-new-rmw",
    title: "Config overlay written by a newer busbar on apply (refusing to overwrite)",
    severity: Severity::Actionable,
    summary: "An admin apply found the config overlay was written by a NEWER busbar than this \
              binary, so busbar REFUSED to overwrite it: this binary cannot represent everything the \
              newer overlay holds, and a write would silently discard whatever it does not \
              understand. This apply was NOT persisted.",
    action: "Apply config mutations from a busbar at least as new as the one that wrote the overlay, \
             or roll the overlay back to a version this binary understands. This binary serves on \
             the overlay it can read but cannot persist changes to it.",
    since: "1.6.0",
    retired: false,
};

/// At boot the overlay is present but corrupt; busbar starts on base config.yaml alone.
pub const CONFIG_OVERLAY_CORRUPT_BASE_ONLY: Diagnostic = Diagnostic {
    code: 3005,
    class: Class::Config,
    slug: "config-overlay-corrupt-base-only",
    title: "Config overlay corrupt at boot (starting on base config.yaml alone)",
    severity: Severity::Actionable,
    summary: "At boot the config overlay is present but unreadable/corrupt, so busbar fails soft and \
              starts on the base config.yaml ALONE — API-applied hooks (INCLUDING security GATES \
              that enforce admission control), groups, and plugin version pins are NOT restored. Any \
              gate registered only via the admin API is now ABSENT until re-applied. busbar never \
              bricks boot on a corrupt overlay, but it must not disarm those gates silently.",
    action: "Fix or remove the corrupt overlay file to restore durability, then restart so the \
             API-applied hooks and gates are re-loaded. Until then, re-apply any admin-API gates the \
             deployment depends on, or run on base config.yaml deliberately.",
    since: "1.6.0",
    retired: false,
};

/// At boot the overlay was written by a NEWER busbar; the boot caller refuses to start (fatal).
pub const CONFIG_OVERLAY_VERSION_TOO_NEW: Diagnostic = Diagnostic {
    code: 3006,
    class: Class::Config,
    slug: "config-overlay-version-too-new",
    title: "Config overlay written by a newer busbar (boot refuses to start)",
    severity: Severity::Fatal,
    summary:
        "At boot the config overlay is intact and meaningful but was written by a NEWER busbar \
              than this one. Ignoring it would run without hooks and groups the operator believes \
              are persisted — security gates included — so the boot caller REFUSES to start rather \
              than silently disarm them.",
    action: "Boot a busbar at least as new as the one that wrote the overlay, or roll the overlay \
             back to a version this binary understands. This is a deliberate boot refusal, not a \
             crash — resolve the version mismatch and restart.",
    since: "1.6.0",
    retired: false,
};

/// An overlay patch does not parse against this binary's structs; the entry is dropped whole.
pub const CONFIG_OVERLAY_PATCH_UNPARSABLE: Diagnostic = Diagnostic {
    code: 3007,
    class: Class::Config,
    slug: "config-overlay-patch-unparsable",
    title: "Config overlay patch does not parse (entry not applied)",
    severity: Severity::Actionable,
    summary: "The config overlay holds a named-map patch that, merged against base config, does not \
              produce a definition this binary can parse (it faces the same typed \
              `deny_unknown_fields` parse config.yaml does). busbar drops the entry WHOLE rather \
              than half-apply it, so that named definition is never applied and sits inert in the \
              overlay.",
    action: "Edit or remove the offending overlay entry (the log names the section and entry), then \
             reload. The operator's stored data is untouched; the entry is simply not applied until \
             it parses.",
    since: "1.6.0",
    retired: false,
};

/// A plugins.min_versions anti-downgrade floor is not valid semver; the control is disarmed.
pub const CONFIG_ANTIDOWNGRADE_FLOOR_INVALID: Diagnostic = Diagnostic {
    code: 3008,
    class: Class::Config,
    slug: "config-antidowngrade-floor-invalid",
    title: "plugins.min_versions floor is not valid semver (anti-downgrade disarmed)",
    severity: Severity::Actionable,
    summary: "A `plugins.min_versions` anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version \
              (e.g. a stray leading `v`). It cannot be satisfied, so the floored plugin is refused, \
              and — more subtly — an operator who believes the anti-downgrade control is armed does \
              not get the protection they configured.",
    action: "Fix or remove the named `plugins.min_versions` entry so the floor is a bare \
             MAJOR.MINOR.PATCH version. Until then that plugin is refused and the anti-downgrade \
             floor for it is effectively disarmed.",
    since: "1.6.0",
    retired: false,
};

/// A plugins.first_party_floors floor is not valid semver; the plugin is refused unconditionally.
pub const CONFIG_FIRSTPARTY_FLOOR_INVALID: Diagnostic = Diagnostic {
    code: 3009,
    class: Class::Config,
    slug: "config-firstparty-floor-invalid",
    title: "plugins.first_party_floors floor is not valid semver (plugin refused unconditionally)",
    severity: Severity::Actionable,
    summary: "A `plugins.first_party_floors` floor is not a valid MAJOR.MINOR.PATCH version. It \
              cannot be satisfied, and because a first-party floor REPLACES the binary-version floor, \
              the named plugin is refused UNCONDITIONALLY until this is fixed — a stricter failure \
              than an invalid `min_versions` floor.",
    action: "Fix or remove the named `plugins.first_party_floors` entry so the floor is a bare \
             MAJOR.MINOR.PATCH version. Until then that first-party plugin is refused on every boot.",
    since: "1.6.0",
    retired: false,
};

/// A pool mixes upstream protocols; cross-protocol failover translates via the IR and may lose features.
pub const CONFIG_POOL_HETEROGENEOUS: Diagnostic = Diagnostic {
    code: 3010,
    class: Class::Config,
    slug: "config-pool-heterogeneous",
    title: "Heterogeneous pool (cross-protocol failover may not preserve all features)",
    severity: Severity::Actionable,
    summary: "A pool's members span more than one upstream protocol, so cross-protocol failover \
              within the pool translates requests and replies via busbar's internal representation \
              (IR) and may not preserve every provider-specific feature. Advisory: the pool is valid \
              and serves, but mixed protocols carry a fidelity caveat.",
    action: "None required if intentional. If a feature is being lost across failover, split the \
             pool so each pool is single-protocol, keeping cross-protocol members in a fallback tier \
             rather than the same failover pool.",
    since: "1.6.0",
    retired: false,
};

/// An auth chain entry grants max_admin_scope: full — principals it identifies hold full admin.
pub const CONFIG_AUTH_CHAIN_FULL_SCOPE: Diagnostic = Diagnostic {
    code: 3011,
    class: Class::Config,
    slug: "config-auth-chain-full-scope",
    title: "auth.chain entry grants max_admin_scope: full",
    severity: Severity::Actionable,
    summary:
        "An auth chain entry sets `max_admin_scope: full`, so every principal identified by that \
              module can hold FULL admin authority — the default ceiling is read-only. A security \
              advisory: a compromised or over-broad identity source behind that module becomes an \
              admin-authority source.",
    action:
        "Confirm the named module's chain is trusted end to end and that granting full admin to \
             everyone it identifies is intended. Lower `max_admin_scope` (or scope the module's \
             principals) if full admin is broader than needed.",
    since: "1.6.0",
    retired: false,
};

/// auth.chain names `keys` and auth.admin_auth is explicitly empty — anyone can mint keys.
pub const CONFIG_OPEN_ADMIN_MINT: Diagnostic = Diagnostic {
    code: 3012,
    class: Class::Config,
    slug: "config-open-admin-mint",
    title: "auth.chain names `keys` with an empty admin_auth (anyone can mint virtual keys)",
    severity: Severity::Actionable,
    summary:
        "The auth chain names the built-in `keys` verifier while `auth.admin_auth` is explicitly \
              empty, so the admin API has no credential gating it — ANYONE can mint virtual keys \
              through it. Acceptable only for local development.",
    action: "Configure `auth.admin_auth` (an `admin-tokens` entry with a `token:`, or an admin \
             module granting `mint`/`full`) before exposing busbar's admin API to any untrusted \
             network, so key minting is gated by an operator credential.",
    since: "1.6.0",
    retired: false,
};

/// upstream_credentials: passthrough with a non-empty configured api_key on a provider; key is inert.
pub const CONFIG_PASSTHROUGH_UNUSED_APIKEY: Diagnostic = Diagnostic {
    code: 3013,
    class: Class::Config,
    slug: "config-passthrough-unused-apikey",
    title: "passthrough provider has a non-empty api_key that is never forwarded (inert config)",
    severity: Severity::Actionable,
    summary: "A provider is configured with a NON-EMPTY api_key while `upstream_credentials` is \
              `passthrough`, under which the upstream key is the caller's own token (or empty), so \
              the configured api_key is NEVER forwarded — it is inert dead config. A legitimate \
              passthrough provider that itself signs per-request via SigV4 and needs no static \
              key, hence a warning rather than a hard reject.",
    action: "If you intended static-key gating, use `upstream_credentials: own` (plus an auth \
             chain). Otherwise clear the referenced provider secret so the config reflects that no \
             static key is used on that passthrough provider.",
    since: "1.6.0",
    retired: false,
};

// ── 4000 — Auth & identity ──────────────────────────────────────────────────────────────────────

/// Token-exchange could not mint a self-serve key — a keystore/HMAC fault, not a client error.
pub const TOKEN_EXCHANGE_MINT_FAILED: Diagnostic = Diagnostic {
    code: 4001,
    class: Class::Auth,
    slug: "token-exchange-mint-failed",
    title: "Token-exchange could not mint a self-serve key",
    severity: Severity::Actionable,
    summary: "An authenticated, authorized token-exchange request could not be completed because \
              minting the self-serve key failed inside busbar (a keystore write or HMAC/signing \
              fault), so the caller receives a 500. The identity was valid; the failure is on \
              busbar's side, not the client's.",
    action: "Investigate the keystore / signing subsystem — check disk, permissions, and the \
             key-derivation secret. The condition is rare; capture the logged detail and file a \
             bug if it recurs.",
    since: "1.6.0",
    retired: false,
};

/// A login plugin is not returning, so its offload permit could not be acquired. Warn-once (latched).
pub const LOGIN_OFFLOAD_SATURATED: Diagnostic = Diagnostic {
    code: 4002,
    class: Class::Auth,
    slug: "login-offload-saturated",
    title: "Login plugin offload saturated (permit not acquired; login rejected fail-closed)",
    severity: Severity::Actionable,
    summary: "A login-plugin call could not obtain a blocking-offload permit within the wait \
              window because the offload budget is fully in flight — a login plugin is wedged and \
              not returning. busbar rejects the login fail-closed rather than complete a login it \
              never ran. Warned once on entry to the saturated state; recurrence logs at debug.",
    action: "Investigate the login plugin (LDAP/AD bind, an OIDC token/userinfo round-trip) — it \
             is blocking past its timeout. Restore or restart it; the saturation clears once calls \
             return within budget.",
    since: "1.6.0",
    retired: false,
};

/// A login plugin's blocking call panicked; the login is rejected fail-closed.
pub const LOGIN_PLUGIN_PANICKED: Diagnostic = Diagnostic {
    code: 4003,
    class: Class::Auth,
    slug: "login-plugin-panicked",
    title: "Login plugin call panicked (login rejected fail-closed)",
    severity: Severity::Actionable,
    summary: "A login plugin's blocking call panicked (the offloaded task returned a join error), \
              so busbar rejects the login fail-closed rather than complete a login it never \
              verified. A panicking plugin is a plugin bug.",
    action:
        "Fix the login plugin — a panic on the login path is a bug in that plugin. Capture the \
             logged method/op context and the plugin's own logs; logins via that method fail until \
             it is corrected.",
    since: "1.6.0",
    retired: false,
};

/// The auth chain is empty (open relay) — acceptable only in dev. Boot-time config warning.
pub const AUTH_CHAIN_OPEN_RELAY: Diagnostic = Diagnostic {
    code: 4004,
    class: Class::Auth,
    slug: "auth-chain-open-relay",
    title: "auth.chain is empty (open relay)",
    severity: Severity::Actionable,
    summary: "The auth chain was built with no verifiers and no keys-in-chain, so every data-plane \
              request is admitted unauthenticated — an OPEN RELAY. This is acceptable only for \
              local development. Emitted once when the chain is built.",
    action: "Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing \
             busbar to any untrusted network. An open relay in production forwards anyone's traffic \
             on your upstream credentials.",
    since: "1.6.0",
    retired: false,
};

/// An auth plugin is not returning, so the chain offload permit could not be acquired. Warn-once.
pub const AUTH_OFFLOAD_SATURATED: Diagnostic = Diagnostic {
    code: 4005,
    class: Class::Auth,
    slug: "auth-offload-saturated",
    title: "Auth chain offload saturated (permit not acquired; request denied fail-closed)",
    severity: Severity::Actionable,
    summary: "The auth chain could not obtain a blocking-offload permit within the wait window \
              because the offload budget is fully in flight — an auth plugin is wedged and not \
              returning. The chain never ran, so the credential is unverified and busbar denies \
              fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.",
    action: "Investigate the auth plugin — it is blocking past its timeout and starving the \
             offload budget. Restore or restart it; the saturation clears once chain calls return \
             within budget.",
    since: "1.6.0",
    retired: false,
};

/// The auth chain's blocking task panicked; the request is denied fail-closed. Warn-once (latched).
pub const AUTH_CHAIN_PANICKED: Diagnostic = Diagnostic {
    code: 4006,
    class: Class::Auth,
    slug: "auth-chain-panicked",
    title: "Auth chain panicked (request denied fail-closed)",
    severity: Severity::Actionable,
    summary: "The auth chain's blocking task panicked, so busbar denies the request fail-closed \
              rather than admit an unverified credential. A panicking chain is a plugin bug. Warned \
              once on entry to the panicking state; recurrence logs at debug.",
    action: "Fix the auth plugin — a panic in the chain is a bug in one of its modules. Capture the \
             logged error and the plugin's own logs; requests are denied until it is corrected.",
    since: "1.6.0",
    retired: false,
};

/// admin_auth names a module with no resolved plugin — a post-boot invariant breach.
pub const ADMIN_MODULE_UNRESOLVED: Diagnostic = Diagnostic {
    code: 4007,
    class: Class::Auth,
    slug: "admin-module-unresolved",
    title: "admin_auth names a module with no resolved plugin",
    severity: Severity::Actionable,
    summary: "The admin auth chain named a module that has no resolved plugin, and busbar skipped \
              it fail-closed. This is supposed to be impossible after a successful boot — \
              `AdminAuthChain::build` fails closed on any unresolvable name — so reaching it means \
              the admin-module table drifted from the configured chain.",
    action: "Investigate the admin auth configuration and plugin load state; a named admin module \
             is missing at runtime. Restart busbar so boot re-resolves the chain, and file a bug \
             with the logged module name if it persists.",
    since: "1.6.0",
    retired: false,
};

/// An admin auth plugin is not returning; the admin offload permit could not be acquired. Warn-once.
pub const ADMIN_OFFLOAD_SATURATED: Diagnostic = Diagnostic {
    code: 4008,
    class: Class::Auth,
    slug: "admin-offload-saturated",
    title: "Admin auth offload saturated (permit not acquired; request denied fail-closed)",
    severity: Severity::Actionable,
    summary: "The admin auth chain could not obtain a blocking-offload permit within the wait \
              window because the admin offload budget is fully in flight — an admin auth plugin is \
              wedged and not returning. The chain never ran, so busbar denies fail-closed. Warned \
              once on entry to the saturated state; recurrence logs at debug.",
    action: "Investigate the admin auth plugin — it is blocking past its timeout. Restore or \
             restart it; admin access is denied until admin-chain calls return within budget.",
    since: "1.6.0",
    retired: false,
};

/// The admin auth chain did not complete within its deadline (or panicked); denied. Warn-once.
pub const ADMIN_CHAIN_STALLED: Diagnostic = Diagnostic {
    code: 4009,
    class: Class::Auth,
    slug: "admin-chain-stalled",
    title: "Admin auth chain did not complete in time (request denied fail-closed)",
    severity: Severity::Actionable,
    summary: "The admin auth chain's offloaded task did not complete within its deadline, or it \
              panicked, so busbar denies the admin request fail-closed rather than admit an \
              unverified operator. Warned once on entry to the stalled state; recurrence logs at \
              debug.",
    action:
        "Investigate the admin auth plugin — it is slow or crashing on the admin path. Restore \
             or restart it; admin access is denied until the chain completes within its deadline.",
    since: "1.6.0",
    retired: false,
};

/// An admin request was forbidden but its audit record was suppressed (already recorded this window).
pub const ADMIN_FORBIDDEN_SUPPRESSED: Diagnostic = Diagnostic {
    code: 4010,
    class: Class::Auth,
    slug: "admin-forbidden-suppressed",
    title: "Admin request forbidden (audit record suppressed this window)",
    severity: Severity::BenignRecurring,
    summary: "An admin request was forbidden (insufficient scope for the path), and a durable audit \
              record for it was suppressed because one was already written for this principal in \
              the current rate window. This is a per-request signal of a CLIENT-side authorization \
              failure, not an operator problem, so it is emitted at debug to avoid log spam under a \
              client that keeps retrying a forbidden call.",
    action: "None — self-heals; the client is being correctly refused. Persistent volume from one \
             principal indicates a misconfigured client or a probe; the durable audit chain already \
             carries the first occurrence per window.",
    since: "1.6.0",
    retired: false,
};

/// `keys` in the auth chain configured alongside upstream_credentials: passthrough. Warn-once (latched).
pub const KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT: Diagnostic = Diagnostic {
    code: 4011,
    class: Class::Auth,
    slug: "keys-in-chain-passthrough-conflict",
    title: "auth.chain names `keys` alongside upstream_credentials: passthrough",
    severity: Severity::Actionable,
    summary: "The auth chain names the `keys` verifier while `upstream_credentials` is set to \
              `passthrough`. keys-in-chain requires a valid virtual key on every request and \
              supersedes passthrough's accept-and-forward-the-caller-credential intent, so \
              passthrough never takes effect. Warned once at first request.",
    action: "Resolve the config conflict: use `upstream_credentials: own` (or omit it) alongside \
             `keys`, or drop `keys` from the chain if you genuinely want to forward caller \
             credentials. The two settings are mutually exclusive.",
    since: "1.6.0",
    retired: false,
};

/// A client presented a principal id unsafe to use as a self-serve subject — a client error.
pub const SELF_SUBJECT_UNSAFE: Diagnostic = Diagnostic {
    code: 4012,
    class: Class::Auth,
    slug: "self-subject-unsafe",
    title: "Token-exchange refused an unsafe self-serve subject",
    severity: Severity::BenignRecurring,
    summary: "A token-exchange request presented a principal id that is unsafe as a self-serve \
              subject — empty, containing a '/' route separator or a control character, or carrying \
              a reserved `vk_`/`user:`/`group:` prefix — so busbar refused it with a 403. This is a \
              CLIENT-supplied bad value, not an operator problem, so it is emitted at debug to avoid \
              spam from a misbehaving client.",
    action: "None — self-heals; the client must present a valid subject id. If a legitimate \
             identity is being rejected, its id needs to be reshaped to avoid the reserved prefixes \
             and separators.",
    since: "1.6.0",
    retired: false,
};

/// A configured egress API key contains bytes invalid for an HTTP header value.
pub const EGRESS_APIKEY_INVALID_BYTES: Diagnostic = Diagnostic {
    code: 4013,
    class: Class::Auth,
    slug: "egress-apikey-invalid-bytes",
    title: "Egress API key contains invalid header bytes (auth header omitted)",
    severity: Severity::Actionable,
    summary: "A configured egress credential (a static `api-key`/`x-goog-api-key`) contains bytes \
              that are invalid in an HTTP header value (typically an ASCII control character), so \
              busbar omits the auth header entirely and the upstream will reject with 401. The \
              credential is misconfigured.",
    action: "Fix the configured egress credential — remove stray whitespace/control characters \
             (often a trailing newline from how the secret was pasted or injected). Requests to \
             that upstream 401 until the key is a valid header value.",
    since: "1.6.0",
    retired: false,
};

/// A minted OAuth token contains bytes invalid for an HTTP header value.
pub const EGRESS_OAUTH_TOKEN_INVALID_BYTES: Diagnostic = Diagnostic {
    code: 4014,
    class: Class::Auth,
    slug: "egress-oauth-token-invalid-bytes",
    title: "Minted OAuth token contains invalid header bytes (auth header omitted)",
    severity: Severity::Actionable,
    summary: "An OAuth token minted for egress contains bytes invalid in an HTTP header value, so \
              busbar omits the `Bearer` auth header and the upstream will reject with 401. Fires on \
              mint (per refresh), not per request, and is near-unreachable for a well-formed token \
              endpoint.",
    action: "Investigate the OAuth token endpoint — it returned an access token with control or \
             non-ASCII bytes. Requests to that upstream 401 until it mints a header-safe token.",
    since: "1.6.0",
    retired: false,
};

/// The OAuth token endpoint returned a 200 with an empty access_token. Warn-once (latched).
pub const EGRESS_OAUTH_EMPTY_TOKEN: Diagnostic = Diagnostic {
    code: 4015,
    class: Class::Auth,
    slug: "egress-oauth-empty-token",
    title: "OAuth token endpoint returned a 200 with an empty access_token",
    severity: Severity::Actionable,
    summary: "The upstream OAuth token endpoint answered 200 but with an EMPTY access_token. busbar \
              treats it as a (retryable) mint failure rather than storing it, because an empty \
              token collides with the pre-first-mint sentinel and would wedge the lane permanently. \
              It retries on the refresh cadence.",
    action: "Investigate the OAuth token endpoint / client-credentials configuration — a 200 with \
             no token usually means a misconfigured client, scope, or audience. Egress to that \
             upstream 401s until a non-empty token is minted.",
    since: "1.6.0",
    retired: false,
};

/// An OAuth token mint (background refresh) failed; busbar keeps the current token and retries.
pub const EGRESS_OAUTH_MINT_FAILED: Diagnostic = Diagnostic {
    code: 4016,
    class: Class::Auth,
    slug: "egress-oauth-mint-failed",
    title: "OAuth token mint (refresh) failed; retrying",
    severity: Severity::Actionable,
    summary: "The background OAuth token refresh failed to mint a new token. busbar keeps serving \
              the current token and retries soon; if retries keep failing past expiry, egress \
              requests carry a stale/empty token and the upstream 401s. Fires on the refresh \
              cadence, not per request.",
    action: "Investigate the OAuth token endpoint — a transient outage self-heals on the next \
             retry; sustained failures mean a credential/endpoint/network problem that will 401 \
             egress once the current token expires.",
    since: "1.6.0",
    retired: false,
};

/// A scheduled trust sweep could not be ATTEMPTED for a subject; its trust state is unchanged.
pub const TRUST_SWEEP_NOT_ATTEMPTED: Diagnostic = Diagnostic {
    code: 4017,
    class: Class::Auth,
    slug: "trust-sweep-not-attempted",
    title: "Scheduled trust sweep could not be attempted (registration not contacted)",
    severity: Severity::Actionable,
    summary: "A scheduled trust sweep could not even be ATTEMPTED for a registration (a local \
              precondition failed before any contact), so the upstream was not contacted and its \
              trust state is unchanged. The registration is not re-verified this tick.",
    action: "Investigate the logged reason for the named subject — typically a local resource or \
             config problem preventing the sweep from starting. Trust state is preserved, not \
             demoted; resolve the cause so the registration is re-verified on schedule.",
    since: "1.6.0",
    retired: false,
};

/// A scheduled trust sweep could not authenticate the upstream; recorded as a failed contact.
pub const TRUST_SWEEP_CONTACT_FAILED: Diagnostic = Diagnostic {
    code: 4018,
    class: Class::Auth,
    slug: "trust-sweep-contact-failed",
    title: "Scheduled trust sweep could not authenticate the upstream (failed contact recorded)",
    severity: Severity::Actionable,
    summary:
        "A scheduled trust sweep reached the upstream but could not authenticate it, so busbar \
              records a failed contact against the registration. Repeated failed contacts feed the \
              anomaly breaker toward suspension (see BUSBAR-4021).",
    action:
        "Investigate the named upstream's reachability and credentials for the logged subject. \
             A transient failure is recorded and self-heals on a later clean sweep; persistent \
             failures will suspend the registration.",
    since: "1.6.0",
    retired: false,
};

/// The upstream DRIFTED from the approved pin; the registration is demoted until re-approved.
pub const TRUST_UPSTREAM_DRIFTED: Diagnostic = Diagnostic {
    code: 4019,
    class: Class::Auth,
    slug: "trust-upstream-drifted",
    title: "Upstream drifted from the approved pin (registration demoted)",
    severity: Severity::Actionable,
    summary: "A scheduled trust sweep found the upstream DRIFTED from its approved pin — something \
              changed underneath a standing approval — so busbar demoted the registration and it \
              stops serving until an operator re-approves. This is the headline trust diagnostic: \
              the operator's first notice that a pinned upstream changed.",
    action: "Review the logged drift (pin change, added/removed/changed attributes) for the named \
             subject. If the change is expected, re-approve the registration to restore service; if \
             not, treat it as a potential compromise of that upstream.",
    since: "1.6.0",
    retired: false,
};

/// A clean trust observation was made but is not yet believed (recovery backoff pending).
pub const TRUST_RECOVERY_HELD: Diagnostic = Diagnostic {
    code: 4020,
    class: Class::Auth,
    slug: "trust-recovery-held",
    title: "Clean trust observation held (recovery backoff not yet elapsed)",
    severity: Severity::BenignRecurring,
    summary:
        "A scheduled trust sweep made a clean observation, but the recovery backoff since the \
              last drift has not yet elapsed, so the observation is not yet believed and the \
              registration stays demoted for now. This is the expected self-healing backoff, so it \
              is emitted at debug.",
    action: "None — self-heals. The registration recovers automatically once enough consecutive \
             clean observations accumulate past the recovery backoff.",
    since: "1.6.0",
    retired: false,
};

/// The anomaly breaker suspended a registration after repeated failures.
pub const TRUST_REGISTRATION_SUSPENDED: Diagnostic = Diagnostic {
    code: 4021,
    class: Class::Auth,
    slug: "trust-registration-suspended",
    title: "Anomaly breaker suspended a trust registration",
    severity: Severity::Actionable,
    summary: "The trust anomaly breaker suspended a registration — accumulated failed contacts or \
              drift crossed its threshold — so the registration stops serving until the condition \
              clears or an operator intervenes. A transition event, emitted once per suspension.",
    action: "Investigate the named subject's upstream (see the preceding contact-failure or drift \
             diagnostics for the cause). Resolve the underlying fault; the registration recovers or \
             requires re-approval depending on why it was suspended.",
    since: "1.6.0",
    retired: false,
};

/// A scheduled trust sweep task panicked; the sweep job continues.
pub const TRUST_SWEEP_PANICKED: Diagnostic = Diagnostic {
    code: 4022,
    class: Class::Auth,
    slug: "trust-sweep-panicked",
    title: "Scheduled trust sweep panicked (job continues)",
    severity: Severity::Actionable,
    summary: "A scheduled trust sweep pass panicked. busbar catches the panic and CONTINUES the \
              sweep job — exiting would turn one bad upstream into a deployment that silently never \
              sweeps again — but that tick's registrations were not all swept. A panicking sweep is \
              a code bug.",
    action: "Capture the logged plane context and file a bug — a sweep pass should never panic. The \
             job keeps running, but investigate promptly since the panicking tick left some \
             registrations un-swept.",
    since: "1.6.0",
    retired: false,
};

/// oauth_as expired-record sweep failed; retried on the next tick. Warn-once (latched, transition-only).
pub const OAUTH_AS_SWEEP_FAILED: Diagnostic = Diagnostic {
    code: 4023,
    class: Class::Auth,
    slug: "oauth-as-sweep-failed",
    title: "oauth_as expired-record sweep failed (retrying next tick)",
    severity: Severity::BenignRecurring,
    summary: "The oauth_as authorization-server sweep of expired records failed for a tick — \
              typically a transient store hiccup — so busbar retries on the next tick. Expired \
              records simply linger until a sweep succeeds. Warned once on entry to the failing \
              state; recurrence logs at debug so a persistent store problem cannot spam.",
    action: "None if it clears on the next tick. Sustained failures indicate an oauth_as store \
             problem worth investigating; expired records accumulate until a sweep succeeds.",
    since: "1.6.0",
    retired: false,
};

/// HMAC-SHA256 init failed during SigV4 signing — documented unreachable.
pub const SIGV4_HMAC_INIT_FAILED: Diagnostic = Diagnostic {
    code: 4024,
    class: Class::Auth,
    slug: "sigv4-hmac-init-failed",
    title: "SigV4 HMAC-SHA256 init failed (documented unreachable)",
    severity: Severity::Actionable,
    summary: "Initializing HMAC-SHA256 for AWS SigV4 signing failed. This is documented as \
              unreachable — HMAC-SHA256 accepts a key of any length — so reaching it indicates a \
              serious crypto-library inconsistency. busbar returns an empty signature, which the \
              upstream rejects.",
    action: "Capture the logged error and file a bug; this should not be possible. SigV4-signed \
             egress fails to authenticate until it is resolved.",
    since: "1.6.0",
    retired: false,
};

/// oauth_as has no configured signing_key, so an EPHEMERAL ES256 key was generated at boot.
/// Lives in `appbuild.rs`, but the subject is auth & identity (token signing), so it is a 4000 code.
pub const OAUTH_AS_EPHEMERAL_SIGNING_KEY: Diagnostic = Diagnostic {
    code: 4025,
    class: Class::Auth,
    slug: "oauth-as-ephemeral-signing-key",
    title: "oauth_as generated an ephemeral ES256 signing key (tokens die on restart)",
    severity: Severity::Actionable,
    summary: "The oauth_as authorization server has no `signing_key` configured, so busbar generated \
              an EPHEMERAL ES256 key at boot. Every token this deployment issues is signed with that \
              in-memory key and stops verifying the moment the process restarts, because a new key is \
              generated on the next boot. Acceptable only for a trial or local development.",
    action: "Set `oauth_as.signing_key` to a durable key reference before relying on issued tokens \
             across restarts. Until then, every restart invalidates all outstanding oauth_as tokens.",
    since: "1.6.0",
    retired: false,
};

// ── 5000 — Proxy & routing ──────────────────────────────────────────────────────────────────────

/// Same-protocol non-stream billing copy hit the reassembly cap; the tail (with usage) is kept.
pub const USAGE_TAP_REASSEMBLY_CAP_EXCEEDED: Diagnostic = Diagnostic {
    code: 5001,
    class: Class::Proxy,
    slug: "usage-tap-reassembly-cap-exceeded",
    title: "Same-protocol non-stream body exceeded the usage-tap reassembly cap (tail retained)",
    severity: Severity::BenignRecurring,
    summary: "A same-protocol non-streaming JSON response body grew past the usage-tap reassembly \
              cap, so busbar dropped the oldest bytes and retained only the TAIL (where every \
              dialect's `usage` object sits) to still bill the request. The client receives the \
              body verbatim regardless; only the internal billing copy is truncated.",
    action: "None — self-heals; the trailing usage object still bills correctly for a recognized \
             dialect. If BILLING_TRUNCATED_TOTAL climbs steadily, some upstream is returning \
             unusually large bodies whose usage may undercount for an unrecognized dialect.",
    since: "1.6.0",
    retired: false,
};

/// Upstream transport error mid-stream, after the first byte already reached the client.
pub const UPSTREAM_MIDSTREAM_TRANSPORT_ERROR: Diagnostic = Diagnostic {
    code: 5002,
    class: Class::Proxy,
    slug: "upstream-midstream-transport-error",
    title: "Mid-stream upstream transport error (generic interruption returned to the client)",
    severity: Severity::BenignRecurring,
    summary: "An upstream transport error occurred AFTER the first byte of a streaming response \
              was already sent to the client. busbar returns a generic, vendor-neutral \
              interruption frame in the client's ingress protocol rather than leaking the raw \
              transport error, and records a compensating breaker transient.",
    action: "None — self-heals per request; the circuit breaker already tracks the upstream \
             fault. A sustained rate indicates a flaky upstream lane worth investigating via \
             breaker telemetry.",
    since: "1.6.0",
    retired: false,
};

/// Upstream transport error before the first byte of a streaming response arrived.
pub const UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR: Diagnostic = Diagnostic {
    code: 5003,
    class: Class::Proxy,
    slug: "upstream-prefirstbyte-transport-error",
    title: "Pre-first-byte upstream transport error (body stream terminated generically)",
    severity: Severity::BenignRecurring,
    summary: "An upstream transport error occurred BEFORE the first byte of a streaming response \
              arrived. busbar terminates the body stream with a generic message, refunds the \
              request budget unit, and records a compensating breaker transient so the failed \
              attempt counts against the lane.",
    action: "None — self-heals; failover and the breaker handle it. Persistent occurrence on one \
             lane points to an unhealthy upstream endpoint.",
    since: "1.6.0",
    retired: false,
};

/// A (pool, lane) circuit breaker transitioned Closed→Open. Warn-once per logical trip.
pub const LANE_BREAKER_TRIPPED: Diagnostic = Diagnostic {
    code: 5004,
    class: Class::Proxy,
    slug: "lane-breaker-tripped",
    title: "Lane circuit breaker tripped (Closed→Open)",
    severity: Severity::BenignRecurring,
    summary: "A circuit breaker for a (pool, lane) transitioned Closed→Open after accumulated \
              failures crossed its threshold, so busbar stops sending traffic to that lane until \
              the breaker's cooldown lets it probe for recovery. Emitted once per logical trip.",
    action: "Traffic fails over to healthy lanes automatically. If a lane trips repeatedly, \
             investigate that upstream's health, credentials, or rate limits.",
    since: "1.6.0",
    retired: false,
};

/// A routing-policy hook errored; the pool's `on_error` fallback was applied. Warn-once (latched).
pub const ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK: Diagnostic = Diagnostic {
    code: 5005,
    class: Class::Proxy,
    slug: "routing-policy-failed-on-error-fallback",
    title: "Routing policy failed; on_error fallback applied",
    severity: Severity::Actionable,
    summary: "A routing-policy hook returned an ERROR while deciding a request, so busbar applied \
              the pool's configured `on_error` fallback. A hook binary that is down, crashing, or \
              returning garbage degrades every request in the pool to the fallback. Warned once \
              per fault window; continued failures log at debug.",
    action: "Fix the routing-policy hook — check that its process is running, reachable, and \
             returning a valid decision. The pool serves via `on_error` until it recovers.",
    since: "1.6.0",
    retired: false,
};

/// A routing-policy hook exceeded its deadline; the `on_error` fallback was applied. Warn-once.
pub const ROUTING_POLICY_DEADLINE_EXCEEDED: Diagnostic = Diagnostic {
    code: 5006,
    class: Class::Proxy,
    slug: "routing-policy-deadline-exceeded",
    title: "Routing policy deadline exceeded; on_error fallback applied",
    severity: Severity::Actionable,
    summary: "A routing-policy hook did not answer within the seam's hard wall-clock deadline, so \
              busbar applied the pool's `on_error` fallback. A slow hook adds latency to every \
              request in the pool. Warned once per fault window; continued timeouts log at debug.",
    action: "Investigate why the routing-policy hook is slow (overload, blocking I/O, an \
             undersized deadline). Tune the hook or raise its configured timeout if the latency \
             is legitimate.",
    since: "1.6.0",
    retired: false,
};

/// An `on_error` fallback hook answered for a failed gate — a recovery signal.
pub const ON_ERROR_FALLBACK_ANSWERED: Diagnostic = Diagnostic {
    code: 5007,
    class: Class::Proxy,
    slug: "on-error-fallback-answered",
    title: "on_error fallback hook answered for the failed gate",
    severity: Severity::BenignRecurring,
    summary: "After a routing gate failed, one of its configured `on_error` fallback hooks \
              answered and decided the request. This is a RECOVERY signal: the fallback chain did \
              its job.",
    action: "None — informational. The paired gate-failure diagnostic (BUSBAR-5005/5006) names \
             the primary hook to fix.",
    since: "1.6.0",
    retired: false,
};

/// An `on_error` fallback hook itself failed; the chain continued. Warn-once (latched).
pub const ON_ERROR_FALLBACK_HOOK_FAILED: Diagnostic = Diagnostic {
    code: 5008,
    class: Class::Proxy,
    slug: "on-error-fallback-hook-failed",
    title: "on_error fallback hook failed; continuing down the chain",
    severity: Severity::Actionable,
    summary: "An `on_error` fallback hook itself returned an error, so busbar continued down the \
              fallback chain to the next link (or the reserved terminal). The fallback chain meant \
              to cover a broken primary is itself partly broken. Warned once per fault window.",
    action: "Fix the failing fallback hook. The request is still served by a later chain link or \
             the terminal policy, but the chain has less depth than configured.",
    since: "1.6.0",
    retired: false,
};

/// An `on_error` fallback hook exceeded its deadline; the chain continued. Warn-once (latched).
pub const ON_ERROR_FALLBACK_DEADLINE_EXCEEDED: Diagnostic = Diagnostic {
    code: 5009,
    class: Class::Proxy,
    slug: "on-error-fallback-deadline-exceeded",
    title: "on_error fallback hook deadline exceeded; continuing down the chain",
    severity: Severity::Actionable,
    summary: "An `on_error` fallback hook exceeded its deadline, so busbar continued down the \
              fallback chain. Warned once per fault window; continued timeouts log at debug.",
    action: "Investigate why the fallback hook is slow, or raise its timeout if the latency is \
             expected. The chain still resolves via a later link or the terminal policy.",
    since: "1.6.0",
    retired: false,
};

/// A cross-protocol non-stream upstream body failed mid-transfer; success not recorded.
pub const CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED: Diagnostic = Diagnostic {
    code: 5010,
    class: Class::Proxy,
    slug: "crossproto-nonstream-midtransfer-failed",
    title: "Cross-protocol non-stream upstream body failed mid-transfer",
    severity: Severity::BenignRecurring,
    summary: "On a cross-protocol non-streaming route, the upstream body failed mid-transfer, so \
              busbar did not record success or usage, refunded the request budget, records a \
              compensating breaker transient, and returns an ingress-native error.",
    action: "None — self-heals; the breaker compensates. A sustained rate indicates a flaky \
             upstream lane.",
    since: "1.6.0",
    retired: false,
};

/// A cross-protocol success body exceeded busbar's translation cap; cannot translate.
pub const CROSSPROTO_TRANSLATION_CAP_EXCEEDED: Diagnostic = Diagnostic {
    code: 5011,
    class: Class::Proxy,
    slug: "crossproto-translation-cap-exceeded",
    title: "Cross-protocol non-stream success body exceeded the translation cap",
    severity: Severity::BenignRecurring,
    summary:
        "A cross-protocol non-streaming success body exceeded busbar's translation cap, so it \
              cannot be translated into the client's protocol and the client receives a 500 with \
              no completion. This is busbar's OWN cap, not an upstream fault, so tokens are not \
              charged and the breaker success stands.",
    action: "None — self-heals per request. If it recurs for legitimately large replies, raise \
             the translated-body cap (`limits`) so those replies translate.",
    since: "1.6.0",
    retired: false,
};

/// A binary/opaque cross-protocol upstream body failed the egress codec's read_response.
pub const CROSSPROTO_BINARY_CODEC_FAILED: Diagnostic = Diagnostic {
    code: 5012,
    class: Class::Proxy,
    slug: "crossproto-binary-codec-failed",
    title: "Cross-protocol binary response failed the egress codec (read_response)",
    severity: Severity::BenignRecurring,
    summary: "A binary/opaque cross-protocol upstream response could not be decoded by the egress \
              codec's `read_response`, so busbar returns an ingress-native 500 rather than leaking \
              the upstream's native body. Often a broken or renamed upstream response field.",
    action: "None — self-heals per request. If it recurs for one upstream, the provider may have \
             changed its response shape; check for a busbar update covering that dialect.",
    since: "1.6.0",
    retired: false,
};

/// A JSON 2xx cross-protocol upstream body was rejected by the egress codec.
pub const CROSSPROTO_JSON_CODEC_FAILED: Diagnostic = Diagnostic {
    code: 5013,
    class: Class::Proxy,
    slug: "crossproto-json-codec-failed",
    title: "Cross-protocol JSON response failed the egress codec (read_response_value)",
    severity: Severity::BenignRecurring,
    summary: "A JSON 2xx cross-protocol upstream response was rejected by the egress codec's \
              `read_response_value` (e.g. a missing expected field), so busbar returns an \
              ingress-native 500 instead of leaking the upstream body. Same root-cause family as \
              BUSBAR-5012.",
    action: "None — self-heals per request. Recurrence for one upstream suggests a changed or \
             renamed response field; check for a busbar update.",
    since: "1.6.0",
    retired: false,
};

/// Degraded-path cross-protocol response not translatable; ingress-native error returned.
pub const CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED: Diagnostic = Diagnostic {
    code: 5014,
    class: Class::Proxy,
    slug: "crossproto-response-not-translatable-degraded",
    title: "Degraded cross-protocol response not translatable (ingress-native error returned)",
    severity: Severity::BenignRecurring,
    summary: "On the degraded path, a cross-protocol upstream response could not be translated \
              into the client's protocol, so busbar returns an ingress-native error rather than \
              leaking the upstream's native wire format to a different-protocol client. This is a \
              deliberate refusal to relay a foreign-format body, not a busbar fault.",
    action: "None — self-heals per request; returning the native error is the correct, safe \
             behavior.",
    since: "1.6.0",
    retired: false,
};

/// Cross-protocol response not translatable (would leak the upstream's native body).
pub const CROSSPROTO_RESPONSE_NOT_TRANSLATABLE: Diagnostic = Diagnostic {
    code: 5015,
    class: Class::Proxy,
    slug: "crossproto-response-not-translatable",
    title: "Cross-protocol response not translatable (ingress-native error returned)",
    severity: Severity::BenignRecurring,
    summary: "A cross-protocol upstream response could not be translated into the client's \
              protocol, so busbar returns an ingress-native error instead of leaking the \
              upstream's native body to a different-protocol client. This is normal, safe \
              operation — an open-relay refusal — not a fault.",
    action: "None — self-heals per request; refusing to relay an untranslatable foreign body is \
             the intended behavior.",
    since: "1.6.0",
    retired: false,
};

/// A rewrite-gate hook rejected the request. Normal policy enforcement.
pub const REWRITE_GATE_REJECTED: Diagnostic = Diagnostic {
    code: 5016,
    class: Class::Proxy,
    slug: "rewrite-gate-rejected",
    title: "Rewrite gate rejected the request",
    severity: Severity::BenignRecurring,
    summary: "A rewrite-gate hook rejected the request, so busbar returns the hook's clamped \
              status and sanitized message in the client's native envelope. This is normal policy \
              enforcement, not an error.",
    action: "None — self-heals per request. The ROUTE_POLICY counters carry the volume; a client \
             seeing rejections should adjust its request to satisfy the policy.",
    since: "1.6.0",
    retired: false,
};

/// Materializing the validated request body for the rewrite pass failed; fail-closed reject.
pub const REWRITE_BODY_MATERIALIZE_FAILED: Diagnostic = Diagnostic {
    code: 5017,
    class: Class::Proxy,
    slug: "rewrite-body-materialize-failed",
    title: "Materializing the validated request body for the rewrite pass failed",
    severity: Severity::Actionable,
    summary: "busbar could not materialize the validated request body into a DOM for the rewrite \
              pass, so it fails CLOSED and rejects the request rather than forwarding it \
              un-rewritten. Unreachable in practice (the bytes already validated), but \
              operator-visible if it ever fires.",
    action: "Investigate — this indicates a serious internal inconsistency (validated bytes that \
             no longer parse). Capture the request context and file a bug; the request was safely \
             rejected, not mis-forwarded.",
    since: "1.6.0",
    retired: false,
};

/// Re-serializing a committed rewrite failed; reject rather than forward the un-rewritten body.
pub const REWRITE_RESERIALIZE_FAILED: Diagnostic = Diagnostic {
    code: 5018,
    class: Class::Proxy,
    slug: "rewrite-reserialize-failed",
    title: "Re-serializing a committed rewrite failed (request rejected to protect the invariant)",
    severity: Severity::Actionable,
    summary: "A committed request rewrite could not be re-serialized into the retained bytes, so \
              busbar rejects the request rather than risk a failover hop forwarding the ORIGINAL \
              un-rewritten body. Protects the rewrite invariant (fail-closed) across failover. Not \
              realistically reachable.",
    action: "Investigate the rewrite hook and request that triggered it; a rewrite that produces \
             an unserializable body is a bug. The request was safely rejected, never forwarded \
             un-rewritten.",
    since: "1.6.0",
    retired: false,
};

/// A decision-gate hook rejected the request. Normal policy enforcement.
pub const DECISION_GATE_REJECTED: Diagnostic = Diagnostic {
    code: 5019,
    class: Class::Proxy,
    slug: "decision-gate-rejected",
    title: "Decision gate rejected the request",
    severity: Severity::BenignRecurring,
    summary: "A decision-gate hook rejected the request; busbar returns the gate's clamped status \
              and sanitized message in the client's native envelope. Normal policy enforcement.",
    action: "None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.",
    since: "1.6.0",
    retired: false,
};

/// A decision gate's restrict left no eligible lane; on_empty weighted escape.
pub const DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE: Diagnostic = Diagnostic {
    code: 5020,
    class: Class::Proxy,
    slug: "decision-gate-restrict-weighted-escape",
    title: "Decision gate restrict left no eligible lane; on_empty: weighted escape",
    severity: Severity::BenignRecurring,
    summary: "A decision gate's restrict left no eligible lane, and its `on_empty` policy is \
              `weighted`, so busbar skips that restriction and falls back to weighted selection \
              across the full pool. Normal advisory-restrict behavior.",
    action: "None — self-heals per request. If the restriction should be enforced strictly, set \
             its `on_empty` to reject.",
    since: "1.6.0",
    retired: false,
};

/// A decision gate's restrict left no eligible lane; on_empty reject (fail-closed).
pub const DECISION_GATE_RESTRICT_REJECT: Diagnostic = Diagnostic {
    code: 5021,
    class: Class::Proxy,
    slug: "decision-gate-restrict-reject",
    title: "Decision gate restrict left no eligible lane (on_empty: reject)",
    severity: Severity::BenignRecurring,
    summary:
        "A decision gate's restrict left no eligible lane and its `on_empty` policy is reject \
              (fail-closed), so busbar rejects the request rather than route to an ineligible \
              lane. This is the correct compliance behavior.",
    action: "None — self-heals per request; the counters carry the volume. If rejections are \
             unexpected, review the pool membership tags against the restrict's required tags.",
    since: "1.6.0",
    retired: false,
};

/// A routing-policy hook rejected the request. Normal policy enforcement.
pub const ROUTING_POLICY_REJECTED: Diagnostic = Diagnostic {
    code: 5022,
    class: Class::Proxy,
    slug: "routing-policy-rejected",
    title: "Routing policy rejected the request",
    severity: Severity::BenignRecurring,
    summary: "A routing-policy hook rejected the request; busbar returns the policy's clamped \
              status and sanitized message in the client's native envelope. Normal policy \
              enforcement.",
    action: "None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.",
    since: "1.6.0",
    retired: false,
};

/// A routing policy's restrict left no eligible lane; on_empty weighted escape.
pub const ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE: Diagnostic = Diagnostic {
    code: 5023,
    class: Class::Proxy,
    slug: "routing-policy-restrict-weighted-escape",
    title: "Routing policy restrict left no eligible lane; on_empty: weighted escape",
    severity: Severity::BenignRecurring,
    summary: "A routing policy's restrict left no eligible lane and its `on_empty` is `weighted`, \
              so busbar escapes to full-pool weighted selection. Normal advisory-restrict \
              behavior.",
    action: "None — self-heals per request. Set `on_empty` to reject if the restriction must be \
             enforced strictly.",
    since: "1.6.0",
    retired: false,
};

/// A routing policy's restrict left no eligible lane; on_empty reject (fail-closed).
pub const ROUTING_POLICY_RESTRICT_REJECT: Diagnostic = Diagnostic {
    code: 5024,
    class: Class::Proxy,
    slug: "routing-policy-restrict-reject",
    title: "Routing policy restrict left no eligible lane (on_empty: reject)",
    severity: Severity::BenignRecurring,
    summary: "A routing policy's restrict left no eligible lane and its `on_empty` is reject \
              (fail-closed), so busbar rejects the request rather than route to an ineligible \
              upstream. Correct compliance behavior.",
    action: "None — self-heals per request. If unexpected, review pool membership tags against \
             the restrict's required tags.",
    since: "1.6.0",
    retired: false,
};

/// No response headers within the per-attempt cap; failing over to the next lane.
pub const ATTEMPT_TIMEOUT_FAILOVER: Diagnostic = Diagnostic {
    code: 5025,
    class: Class::Proxy,
    slug: "attempt-timeout-failover",
    title: "No response headers within the attempt cap; failing over",
    severity: Severity::BenignRecurring,
    summary: "An upstream attempt returned no response headers within its per-attempt \
              time-to-headers cap, so busbar fails over to the next candidate lane. Expected under \
              a slow lane; failover is normal operation.",
    action: "None — self-heals via failover; telemetry counters carry the volume. If one lane \
             times out constantly, investigate its latency or raise its `attempt_timeout_ms`.",
    since: "1.6.0",
    retired: false,
};

/// A lane's breaker is hard-down on its fresh logical trip. Warn-once (latched).
pub const LANE_HARD_DOWN: Diagnostic = Diagnostic {
    code: 5026,
    class: Class::Proxy,
    slug: "lane-hard-down",
    title: "Lane hard-down (breaker trip)",
    severity: Severity::BenignRecurring,
    summary: "A lane's circuit breaker is hard-down (tripped) and this is the FRESH logical trip, \
              so busbar fails over and stops routing to the lane until its cooldown allows a \
              recovery probe. Recurring still-down probes log at debug. Emitted once per logical \
              trip.",
    action: "Traffic fails over automatically. Investigate the named upstream's health if a lane \
             stays hard-down.",
    since: "1.6.0",
    retired: false,
};

/// Usage tap: unknown ingress protocol for a same-protocol 2xx body. Warn-once (latched).
pub const USAGE_TAP_UNKNOWN_PROTOCOL: Diagnostic = Diagnostic {
    code: 5027,
    class: Class::Proxy,
    slug: "usage-tap-unknown-protocol",
    title: "Usage tap: unknown ingress protocol for a same-protocol 2xx body",
    severity: Severity::BenignRecurring,
    summary: "The usage tap could not recognize the ingress protocol of a same-protocol 2xx body, \
              so it bills 0 tokens for the request. Warned once per (protocol, reason); \
              BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None if the protocol is genuinely unmetered. If a metered dialect is billing 0 \
             tokens, the protocol name is unexpected — check the route configuration and for a \
             busbar update covering it.",
    since: "1.6.0",
    retired: false,
};

/// Usage tap: a same-protocol 2xx body did not parse as JSON. Warn-once (latched).
pub const USAGE_TAP_BAD_JSON: Diagnostic = Diagnostic {
    code: 5028,
    class: Class::Proxy,
    slug: "usage-tap-bad-json",
    title: "Usage tap: failed to parse a same-protocol 2xx body as JSON",
    severity: Severity::BenignRecurring,
    summary:
        "The usage tap could not parse a same-protocol 2xx body as JSON, so it bills 0 tokens \
              for the request. Warned once per (protocol, reason); the raw body is never logged \
              (it may carry secrets). BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None — self-heals per request. Sustained occurrence for one upstream means it is \
             returning non-JSON 2xx bodies busbar cannot meter; investigate that upstream.",
    since: "1.6.0",
    retired: false,
};

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

/// No response headers within the per-attempt cap on the degraded path.
pub const ATTEMPT_TIMEOUT_DEGRADED: Diagnostic = Diagnostic {
    code: 5030,
    class: Class::Proxy,
    slug: "attempt-timeout-degraded",
    title: "No response headers within the attempt cap (degraded path)",
    severity: Severity::BenignRecurring,
    summary: "On the degraded routing path, an upstream attempt returned no response headers \
              within its per-attempt cap, so busbar records a breaker transient and tries the next \
              degraded candidate. Degraded-path sibling of BUSBAR-5025.",
    action: "None — self-heals via the degraded candidate walk; telemetry counters carry the \
             volume.",
    since: "1.6.0",
    retired: false,
};

/// A compliance restrict left no eligible lane in the fallback pool; fail closed.
pub const FALLBACK_RESTRICT_NO_ELIGIBLE_LANE: Diagnostic = Diagnostic {
    code: 5031,
    class: Class::Proxy,
    slug: "fallback-restrict-no-eligible-lane",
    title: "Compliance restrict left no eligible lane in the fallback pool (fail closed)",
    severity: Severity::BenignRecurring,
    summary: "A compliance restrict re-applied against a fallback pool left no eligible lane, so \
              busbar fails closed (503) rather than spill to an ineligible upstream. Fail-closed \
              is the correct behavior for a compliance restriction.",
    action: "None — self-heals per request. If the fallback pool should serve this traffic, \
             ensure its members carry the tags the restrict requires.",
    since: "1.6.0",
    retired: false,
};

/// The Prometheus recorder failed to install at boot; /metrics will be empty.
pub const PROMETHEUS_RECORDER_INSTALL_FAILED: Diagnostic = Diagnostic {
    code: 5032,
    class: Class::Proxy,
    slug: "prometheus-recorder-install-failed",
    title: "Prometheus recorder install failed; /metrics will be empty",
    severity: Severity::Actionable,
    summary: "The Prometheus metrics recorder failed to install at boot, so the /metrics endpoint \
              will be empty for the life of the process. busbar continues serving proxy traffic, \
              but is blind to metrics.",
    action: "Investigate the boot error (often a duplicate recorder install or a conflicting \
             exporter). Restart busbar after resolving it; /metrics stays empty until then.",
    since: "1.6.0",
    retired: false,
};

/// The metrics maintenance (drain) thread failed to spawn at boot.
pub const METRICS_MAINTENANCE_THREAD_SPAWN_FAILED: Diagnostic = Diagnostic {
    code: 5033,
    class: Class::Proxy,
    slug: "metrics-maintenance-thread-spawn-failed",
    title: "Could not spawn the metrics maintenance thread (observations drain on scrape only)",
    severity: Severity::Actionable,
    summary: "busbar could not spawn the metrics maintenance (drain) thread at boot, so buffered \
              metric observations now drain only when /metrics is scraped instead of on a timer. \
              Metrics are still correct but may lag between scrapes.",
    action: "Investigate the thread-spawn failure (typically OS thread/resource exhaustion). \
             Metrics remain available on scrape; restart after resolving the resource limit for \
             timely draining.",
    since: "1.6.0",
    retired: false,
};

/// A /metrics scrape could not list virtual keys; per-key gauges skipped this scrape.
pub const METRICS_SCRAPE_LIST_KEYS_FAILED: Diagnostic = Diagnostic {
    code: 5034,
    class: Class::Proxy,
    slug: "metrics-scrape-list-keys-failed",
    title: "Metrics scrape: failed to list virtual keys (per-key gauges skipped)",
    severity: Severity::BenignRecurring,
    summary:
        "A /metrics scrape could not list virtual keys from the governance store (a transient \
              store hiccup), so it skips the per-key spend/token gauges for this scrape. Other \
              gauges still refresh.",
    action: "None — self-heals on the next scrape once the store responds. Sustained failures \
             indicate a governance-store problem worth investigating.",
    since: "1.6.0",
    retired: false,
};

/// Virtual-key count exceeds the per-key gauge limit; gauges truncated. Warn-once (latched).
pub const METRICS_KEY_GAUGE_LIMIT_EXCEEDED: Diagnostic = Diagnostic {
    code: 5035,
    class: Class::Proxy,
    slug: "metrics-key-gauge-limit-exceeded",
    title: "Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating)",
    severity: Severity::Actionable,
    summary:
        "The number of virtual keys exceeds the per-key gauge limit (`metrics.key_gauge_limit`), \
              so busbar emits gauges for only the first `limit` keys to bound Prometheus \
              cardinality and scrape-path DB load. Some keys have no per-key series. Warned once \
              until the count drops back under the limit.",
    action: "Raise `metrics.key_gauge_limit` if you need per-key series for all keys and can \
             afford the cardinality, or reduce the number of active virtual keys. Aggregate group \
             gauges are unaffected.",
    since: "1.6.0",
    retired: false,
};

/// A /metrics scrape could not read one key's usage; that key's gauges skipped this scrape.
pub const METRICS_SCRAPE_KEY_USAGE_READ_FAILED: Diagnostic = Diagnostic {
    code: 5036,
    class: Class::Proxy,
    slug: "metrics-scrape-key-usage-read-failed",
    title: "Metrics scrape: usage read failed; skipping key",
    severity: Severity::BenignRecurring,
    summary: "During a /metrics scrape, reading one virtual key's usage from the store failed, so \
              busbar skips that key's gauges for this scrape and continues with the rest. Per-key, \
              per-scrape.",
    action: "None — self-heals on the next scrape. A high volume across keys points to a \
             governance-store problem.",
    since: "1.6.0",
    retired: false,
};

/// A /metrics scrape could not read a group ledger bucket; that bucket skipped this scrape.
pub const METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED: Diagnostic = Diagnostic {
    code: 5037,
    class: Class::Proxy,
    slug: "metrics-scrape-group-ledger-read-failed",
    title: "Metrics scrape: group ledger read failed; skipping bucket",
    severity: Severity::BenignRecurring,
    summary: "During a /metrics scrape, reading a group budget bucket's ledger from the store \
              failed, so busbar skips that bucket's gauges for this scrape and continues. \
              Per-bucket, per-scrape.",
    action: "None — self-heals on the next scrape. Sustained failures indicate a governance-store \
             problem.",
    since: "1.6.0",
    retired: false,
};

// ── 6000 — Plugins ────────────────────────────────────────────────────────────────────────────

/// A plugin fetch missed on reload; busbar kept the current on-disk artifact. Boot/reload notice.
/// Lives in `appbuild.rs`, but the subject is the plugin loader, so it is a 6000 code.
pub const PLUGINS_FETCH_RELOAD_MISS: Diagnostic = Diagnostic {
    code: 6001,
    class: Class::Plugins,
    slug: "plugins-fetch-reload-miss",
    title: "plugins.fetch missed on reload (keeping the current artifact)",
    severity: Severity::Actionable,
    summary: "During a reload, fetching a pinned plugin artifact missed (the source did not return a \
              usable download for the pinned spec), so busbar kept the artifact already on disk and \
              continued the reload. The running plugin is unchanged; the intended refresh did not \
              land.",
    action: "Check the plugin source (registry/URL) and the pinned spec for the named artifact — a \
             transient fetch miss self-heals on the next reload, a persistent one means the pin no \
             longer resolves. busbar keeps serving the current artifact until a fetch succeeds.",
    since: "1.6.0",
    retired: false,
};

/// A plugin is present in the directory but not loaded because the trust policy skips it.
/// Lives in `preflight.rs`, but the subject is plugin trust, so it is a 6000 code.
pub const PLUGIN_SKIPPED_TRUST_POLICY: Diagnostic = Diagnostic {
    code: 6002,
    class: Class::Plugins,
    slug: "plugin-skipped-trust-policy",
    title: "Plugin present but NOT loaded (skipped by trust policy)",
    severity: Severity::Actionable,
    summary: "A plugin artifact is present in the plugins directory but was NOT loaded because the \
              configured trust policy skipped it (unsigned, an untrusted publisher, or a failed \
              signature/floor check). busbar fails closed: an untrusted plugin is left inert rather \
              than loaded. Emitted once per skipped plugin at boot.",
    action: "If the plugin should load, sign it with a trusted publisher key or add that publisher \
             to `plugins.trust` (the log names the plugin, file, and reason). If the skip is \
             intended, remove the artifact from the directory to silence the notice.",
    since: "1.6.0",
    retired: false,
};

/// A plugin was loaded but its signature is UNVERIFIED, permitted by an explicit plugins.trust opt-in.
/// Lives in `preflight.rs`, but the subject is plugin trust, so it is a 6000 code.
pub const PLUGIN_LOADED_UNVERIFIED: Diagnostic = Diagnostic {
    code: 6003,
    class: Class::Plugins,
    slug: "plugin-loaded-unverified",
    title: "Plugin loaded UNVERIFIED (permitted by an explicit plugins.trust opt-in)",
    severity: Severity::Actionable,
    summary: "A plugin was loaded even though its signature is UNVERIFIED — its code is running \
              unauthenticated, permitted only because an explicit `plugins.trust` opt-in \
              (`allow_unsigned`/`allow_third_party`) let it through. Security-relevant: unverified \
              plugin code runs in-process with busbar's privileges. Emitted once per such plugin at \
              boot.",
    action: "Prefer a signed artifact from a trusted publisher and remove the `plugins.trust` \
             opt-in once you no longer need it. If running unverified is a deliberate, understood \
             choice (e.g. a locally-built plugin), the opt-in is what keeps it explicit.",
    since: "1.6.0",
    retired: false,
};

// ── 7000 — Plane protocols ──────────────────────────────────────────────────────────────────────

/// The RAM (ephemeral) store was resolved while a STATEFUL plane (one carrying per-task state) is
/// configured, so in-flight plane task state is dropped on restart.
pub const STATEFUL_PLANE_EPHEMERAL_STORE: Diagnostic = Diagnostic {
    code: 7030,
    class: Class::Plane,
    slug: "stateful-plane-ephemeral-store",
    title: "Stateful plane on the in-memory store — plane task state is lost on restart",
    severity: Severity::Actionable,
    summary: "busbar resolved the in-memory (ephemeral) store while a STATEFUL plane is configured — \
              a plane subject (a tool, an agent, or a pool of them). Such planes carry \
              per-task state that lives only in RAM with this store, so it is DROPPED on restart: a \
              task that was mid-flight when the process restarts will break on its next request. \
              Stateless planes are deliberately NOT warned — a restart costs \
              them nothing, so warning there would be noise. This is a WARN, not a boot refusal: a \
              durable store is opt-in and RAM is the convenience default.",
    action: "Configure a durable store (sqlite/postgres) so plane task state survives a restart. \
             No action is needed if losing in-flight task state on restart is acceptable for this \
             deployment.",
    since: "1.6.0",
    retired: false,
};

// ── 8000 — Governance & cost ────────────────────────────────────────────────────────────────────

/// A revocation denylist re-sync is still outstanding from an earlier window; store hasn't answered.
pub const REVOCATION_RESYNC_OUTSTANDING: Diagnostic = Diagnostic {
    code: 8001,
    class: Class::Governance,
    slug: "revocation-resync-outstanding",
    title: "Revocation denylist re-sync still outstanding from an earlier window",
    severity: Severity::Actionable,
    summary: "A revocation-denylist re-sync launched in an earlier window has not returned — the \
              governance store has not answered for at least a full sync window — so busbar keeps \
              serving the last-known revocations and does not start a second overlapping read. A \
              peer's revoke may not be visible on this node until the store recovers. The CAS bound \
              rate-limits this warning to once per window.",
    action: "Investigate the governance store's health and latency. Revocations already known stay \
             enforced (fail-closed); the risk is a NEW revoke made elsewhere not yet reaching this \
             node. Re-sync resumes automatically once the store answers.",
    since: "1.6.0",
    retired: false,
};

/// A revocation denylist re-sync store read returned an error; the prior set is kept (fail-closed).
pub const REVOCATION_RESYNC_FAILED: Diagnostic = Diagnostic {
    code: 8002,
    class: Class::Governance,
    slug: "revocation-resync-failed",
    title: "Revocation denylist re-sync failed (keeping the previously-known revocations)",
    severity: Severity::Actionable,
    summary: "A revocation-denylist re-sync read from the governance store returned an error, so \
              busbar keeps the previously-known revocations in place (fail-closed: a store blip never \
              widens access) and leaves the set marked stale so the next window retries. A peer's \
              revoke may not be visible on this node until a later sync succeeds.",
    action: "Investigate the governance store — a transient error self-heals on the next window's \
             retry; sustained failures mean the store is unreachable and cross-node revocations are \
             not propagating.",
    since: "1.6.0",
    retired: false,
};

/// A principal id collides with a reserved bucket namespace (group:/vk_); no synthetic key minted.
pub const GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION: Diagnostic = Diagnostic {
    code: 8003,
    class: Class::Governance,
    slug: "governance-key-reserved-namespace-collision",
    title: "Refused to synthesize a governance key (principal id collides with a reserved namespace)",
    severity: Severity::BenignRecurring,
    summary: "A principal id (attacker-influenceable at the IdP) starts with a reserved ledger-bucket \
              prefix (`group:` or `vk_`), which would alias a group's or a real virtual key's ledger \
              and rate bucket. busbar fails closed and synthesizes NO key for that principal rather \
              than mint a colliding bucket. This is a per-request, caller-side signal, not an \
              operator problem, so it is emitted at debug.",
    action: "None — self-heals; the principal is correctly refused data-plane access. If a legitimate \
             identity is being rejected, its IdP subject must be reshaped to avoid the reserved \
             `group:` and `vk_` prefixes.",
    since: "1.6.0",
    retired: false,
};

/// An unrecognized limit-window word (corrupt/foreign store row); enforced as all-time ('total').
pub const LIMIT_WINDOW_UNRECOGNIZED: Diagnostic = Diagnostic {
    code: 8004,
    class: Class::Governance,
    slug: "limit-window-unrecognized",
    title: "Unrecognized limit window (enforcing as all-time 'total')",
    severity: Severity::Actionable,
    summary: "A limit's window word was not recognized — it can only arise from a corrupt or foreign \
              store row, since config parse rejects unknown windows. busbar fails SAFE and enforces \
              the limit as the all-time ('total') window, the tightest enforcement, never wider, and \
              surfaces the value so the corruption is visible instead of silent.",
    action: "Inspect the governance store row for the named window value — it was written by \
             something other than a validated config load. Enforcement is safe (all-time) in the \
             meantime; correct the row so the intended window applies.",
    since: "1.6.0",
    retired: false,
};

/// refresh_self: tombstone of the prior binding failed AND the rollback failed — two live bindings.
pub const REFRESH_SELF_INCONSISTENT_BINDING: Diagnostic = Diagnostic {
    code: 8005,
    class: Class::Governance,
    slug: "refresh-self-inconsistent-binding",
    title: "Self-serve refresh left an inconsistent binding (tombstone AND rollback both failed)",
    severity: Severity::Actionable,
    summary: "During a self-serve key refresh, tombstoning the prior binding failed and the \
              compensating rollback of the newly-minted binding ALSO failed, so the subject may now \
              have TWO live bindings in the store for one identity. busbar exhausted its best-effort \
              recovery and surfaces the inconsistent state for inspection. Rare.",
    action: "Inspect the governance store for the named subject — it may hold two live bindings \
             (old_id and new_id). Tombstone whichever is not intended so the subject has exactly one \
             valid credential.",
    since: "1.6.0",
    retired: false,
};

/// refresh_self: cache reconcile failed after the store tombstone; prior binding evicted surgically.
pub const REFRESH_SELF_CACHE_REFRESH_FAILED: Diagnostic = Diagnostic {
    code: 8006,
    class: Class::Governance,
    slug: "refresh-self-cache-refresh-failed",
    title: "Self-serve refresh: cache reconcile failed after tombstoning the prior binding",
    severity: Severity::Actionable,
    summary: "During a self-serve key refresh, the store tombstone of the prior binding committed but \
              the follow-up cache reconcile (a store round-trip) failed. busbar evicted the prior \
              binding directly from the cache so its old token stops verifying immediately; the store \
              is consistent, but the rest of the cache may be stale until the next successful \
              refresh.",
    action: "Investigate the governance store's reachability — the durable state is correct and the \
             old credential no longer verifies. The cache self-heals on the next successful reconcile; \
             sustained failures mean the store is unhealthy.",
    since: "1.6.0",
    retired: false,
};

/// A group was missing at accrual; tokens were ledgered to the key bucket only (self-degrading).
pub const ACCRUAL_GROUP_MISSING: Diagnostic = Diagnostic {
    code: 8007,
    class: Class::Governance,
    slug: "accrual-group-missing",
    title: "Group missing at accrual (tokens ledgered to the key bucket only)",
    severity: Severity::BenignRecurring,
    summary: "A group referenced by a key was gone by the time usage was accrued (the group was \
              deleted between admission and accrual), so busbar degrades to ledgering the tokens on \
              the key's own bucket only rather than lose them. The request was already admitted and \
              served; nothing is lost. This is a per-request, self-degrading path, so it is emitted \
              at debug.",
    action: "None — self-heals; tokens are preserved on the key bucket. Frequent occurrence for one \
             key means a group is being deleted out from under active keys; reconcile the key's group \
             assignment.",
    since: "1.6.0",
    retired: false,
};

/// Metering flush had key(s) fail to persist this tick; already aggregated to one warn per tick.
pub const METERING_FLUSH_PARTIAL_FAILURE: Diagnostic = Diagnostic {
    code: 8008,
    class: Class::Governance,
    slug: "metering-flush-partial-failure",
    title: "Metering flush: some keys failed to persist this tick (retained for retry)",
    severity: Severity::Actionable,
    summary: "A metering flush tick could not persist one or more keys' usage deltas to the store. \
              busbar retains the failed deltas and retries them on the next tick, so no usage is \
              lost. This is already collapsed to ONE aggregate warning per tick (per-key detail is at \
              debug), so it fires at a human cadence, not per key.",
    action: "Investigate the governance store if the failure count stays non-zero across ticks — a \
             transient store hiccup self-heals on the next flush. Usage is retained and re-tried, so \
             billing is not lost, only delayed.",
    since: "1.6.0",
    retired: false,
};

/// Metering write-behind accumulator hit its cap; a new cell was coalesced into an overflow sentinel.
pub const METERING_PENDING_OVERFLOW_COALESCED: Diagnostic = Diagnostic {
    code: 8019,
    class: Class::Governance,
    slug: "metering-pending-overflow-coalesced",
    title: "Metering accumulator at cap: a cell was coalesced into an overflow sentinel",
    severity: Severity::Actionable,
    summary: "The write-behind metering accumulator (pending_metering) reached its cap while a NEW \
              (key_id, bucket, model, provider) cell arrived — a sustained governance-store outage \
              with diverse keys/models, where every flush re-queues the failed cells while new ones \
              keep arriving. Rather than grow without bound OR silently drop billable usage, busbar \
              COALESCES the arriving cell's counts into a per-bucket overflow sentinel: the day's \
              token and request TOTALS are preserved, only their per-key/model/provider ATTRIBUTION \
              is collapsed. Each coalesce also increments busbar_metering_pending_coalesced_total. \
              Per-event detail is at debug; this is the human-cadence signal.",
    action: "Restore the governance store — the accumulator overflows only under a sustained write \
             outage. Usage is not lost (totals are retained under the overflow sentinel key), but \
             once the store recovers the retained deltas flush and normal per-key attribution \
             resumes. A steadily climbing coalesced counter means the outage has outlasted the cap.",
    since: "1.6.0",
    retired: false,
};

/// delete_key: tombstone committed and key evicted, but the full cache reconcile failed.
pub const DELETE_KEY_CACHE_RECONCILE_FAILED: Diagnostic = Diagnostic {
    code: 8009,
    class: Class::Governance,
    slug: "delete-key-cache-reconcile-failed",
    title: "delete_key: tombstone committed and key evicted, but cache reconcile failed",
    severity: Severity::Actionable,
    summary: "An admin key deletion committed the tombstone in the store and evicted the deleted key \
              from the in-memory caches (it no longer authenticates), but the follow-up full cache \
              reconcile failed. The deletion is durable and the key is dead; only OTHER cache entries \
              may be stale until the next successful refresh. Rare admin path.",
    action: "Investigate the governance store's reachability — the deletion itself is complete and \
             safe. The cache self-heals on the next successful refresh; sustained failures indicate \
             an unhealthy store.",
    since: "1.6.0",
    retired: false,
};

/// rotate_key: new generation committed and key evicted, but cache reconcile failed; new secret lost.
pub const ROTATE_KEY_CACHE_RECONCILE_FAILED: Diagnostic = Diagnostic {
    code: 8010,
    class: Class::Governance,
    slug: "rotate-key-cache-reconcile-failed",
    title: "rotate_key: new generation committed, but cache reconcile failed (new secret not returned)",
    severity: Severity::Actionable,
    summary: "An admin key rotation committed the new generation in the store — so the PREVIOUS \
              credential is permanently dead — and evicted the key from the caches, but the follow-up \
              cache reconcile failed, so the freshly-minted secret could not be returned to the \
              admin. The rotation IS durable; the new secret is simply lost from this response. Rare \
              admin path.",
    action: "Re-rotate the key to obtain a fresh secret — the previous credential is already dead and \
             will not come back. Investigate the governance store's reachability, which is why the \
             reconcile failed.",
    since: "1.6.0",
    retired: false,
};

/// Budget flush had bucket(s) fail to persist this tick; already aggregated to one warn per tick.
pub const BUDGET_FLUSH_PARTIAL_FAILURE: Diagnostic = Diagnostic {
    code: 8011,
    class: Class::Governance,
    slug: "budget-flush-partial-failure",
    title: "Budget flush: some buckets failed to persist this tick (re-marked dirty for retry)",
    severity: Severity::Actionable,
    summary: "A budget flush tick could not persist one or more group-budget buckets to the store. \
              busbar re-marks those buckets dirty and retries them on the next tick, so no spend is \
              lost. This is already collapsed to ONE aggregate warning per tick (per-bucket detail is \
              at debug), so it fires at a human cadence, not per bucket.",
    action: "Investigate the governance store if the failure count stays non-zero across ticks — a \
             transient store hiccup self-heals on the next flush. Spend is retained and re-tried, so \
             budgets are not lost, only delayed.",
    since: "1.6.0",
    retired: false,
};

/// --safe-mode boot: the config overlay was quarantined; running on base config.yaml alone.
pub const SAFE_MODE_OVERLAY_QUARANTINED: Diagnostic = Diagnostic {
    code: 8012,
    class: Class::Governance,
    slug: "safe-mode-overlay-quarantined",
    title: "SAFE MODE: config overlay not merged (running on base config.yaml alone)",
    severity: Severity::Actionable,
    summary: "busbar was booted with `--safe-mode`, so the persisted config overlay (API-registered \
              hooks) was NOT merged and busbar is running on the operator-owned base config.yaml \
              alone. This is the intentional escape hatch for an applied hook that harms traffic and \
              re-applies itself every boot. The overlay file is untouched, not deleted.",
    action: "This is an operator-requested state. Repair or remove the offending overlay entry, then \
             boot WITHOUT `--safe-mode` to re-apply the overlay. Until then, API-registered hooks are \
             not in effect.",
    since: "1.6.0",
    retired: false,
};

/// A provider api_key SecretRef did not resolve at boot; degraded to an empty key.
pub const PROVIDER_API_KEY_UNRESOLVED: Diagnostic = Diagnostic {
    code: 8013,
    class: Class::Governance,
    slug: "provider-api-key-unresolved",
    title: "Provider api_key did not resolve (degraded to an empty key)",
    severity: Severity::Actionable,
    summary: "A provider's `api_key` secret reference did not resolve at boot, so busbar degraded that \
              provider to an empty key. This is legitimate for keyless local upstreams (ollama/vLLM), \
              but for a real provider it means egress will be unauthenticated and the upstream will \
              reject with 401.",
    action: "If the provider needs a key, fix its `api_key` secret reference (the secret is missing \
             or the resolver could not read it) and restart. If the upstream is genuinely keyless, no \
             action is needed.",
    since: "1.6.0",
    retired: false,
};

/// auth.chain is empty (open relay) — emitted at error so RUST_LOG=error cannot mask it.
pub const OPEN_RELAY_NO_AUTH: Diagnostic = Diagnostic {
    code: 8014,
    class: Class::Governance,
    slug: "open-relay-no-auth",
    title: "auth.chain is empty — OPEN RELAY (every request admitted unauthenticated)",
    severity: Severity::Actionable,
    summary: "The auth chain is empty (either explicitly, or because the `auth:` block is absent and \
              serde-defaults to none), so every data-plane request is admitted unauthenticated — an \
              OPEN RELAY forwarding anyone's traffic on your upstream credentials. Emitted at ERROR \
              (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr so the \
              state cannot be masked by log configuration. Acceptable only for local development.",
    action: "Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar \
             to any untrusted network. This is the same open-relay condition as BUSBAR-4004, surfaced \
             at boot.",
    since: "1.6.0",
    retired: false,
};

/// A store settings SecretRef does not resolve at boot; restart-to-apply, so it WILL fail next restart.
pub const STORE_SECRET_REF_UNRESOLVED: Diagnostic = Diagnostic {
    code: 8015,
    class: Class::Governance,
    slug: "store-secret-ref-unresolved",
    title: "Store settings hold a secret reference that does not resolve here",
    severity: Severity::Actionable,
    summary: "A governance-store `settings` value holds a secret reference that does not resolve on \
              this boot. busbar warns rather than fails, because the store is restart-to-apply and \
              staging a ref whose secret the orchestrator mounts on the next deploy is a legitimate \
              workflow. But if the secret is still absent at the next restart, THAT restart will fail \
              in resolve_settings before serving.",
    action: "Ensure the named store secret reference resolves before the next restart. If you are \
             staging it for an upcoming deploy, no action now; otherwise fix the reference so the \
             next restart does not die resolving it.",
    since: "1.6.0",
    retired: false,
};

/// The in-memory (ephemeral) governance store was selected; keys/usage/ledgers reset on restart.
pub const GOVERNANCE_STORE_EPHEMERAL: Diagnostic = Diagnostic {
    code: 8016,
    class: Class::Governance,
    slug: "governance-store-ephemeral",
    title: "Governance store is in-memory (ephemeral) — state resets on restart",
    severity: Severity::Actionable,
    summary: "busbar selected the in-memory (ephemeral) governance store, so virtual keys, groups' \
              usage, and ledgers live only in RAM and are LOST on restart. This is the default when \
              no durable store plugin is configured — fine for a trial or local development, but not \
              for anything that must retain keys or spend across restarts.",
    action: "Configure a durable governance store plugin for persistence if keys, usage, or budgets \
             must survive a restart. No action is needed for ephemeral/dev use.",
    since: "1.6.0",
    retired: false,
};

/// Durable store is configured with keys but keys-in-chain is off; durable keys are inert.
pub const DURABLE_KEYS_INERT: Diagnostic = Diagnostic {
    code: 8017,
    class: Class::Governance,
    slug: "durable-keys-inert",
    title: "Durable keys are inert (keys exist but `keys` is not in the running auth chain)",
    severity: Severity::Actionable,
    summary: "A durable governance store holds virtual keys, but the running auth chain does not \
              include the `keys` verifier, so those keys enforce nothing — every request bypasses \
              key-based governance. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) \
              and unconditionally on stderr, the same pattern as the open-relay banner, so the inert \
              state cannot be masked by log configuration.",
    action: "Add `keys` to `auth.chain` so the durable keys actually gate traffic, or remove the keys \
             if key-based governance is not intended. Until then, minted keys are dead weight.",
    since: "1.6.0",
    retired: false,
};

// ── 9000 — Boot & lifecycle ─────────────────────────────────────────────────────────────────────

/// The durable audit log could not be READ at boot (a store hiccup); busbar starts on an empty ring.
pub const BOOT_AUDIT_RESTORE_READ_FAILED: Diagnostic = Diagnostic {
    code: 9001,
    class: Class::Boot,
    slug: "boot-audit-restore-read-failed",
    title: "Durable audit log could not be read at boot (starting with an empty ring)",
    severity: Severity::Actionable,
    summary: "busbar could not READ the durable audit log from the governance store at boot — a \
              store hiccup, not a chain-verification failure — so it started with an empty in-memory \
              audit ring. This is deliberately distinct from BUSBAR-2001 (chain verification \
              failed): here the bytes could not be read at all, so there is no tamper signal, just a \
              store that did not answer.",
    action: "Investigate the governance store's reachability at boot. If the store recovers, restart \
             so the durable history is restored into the ring; a transient hiccup needs no action \
             beyond confirming the store is healthy.",
    since: "1.6.0",
    retired: false,
};

/// The ONE-TIME legacy-audit-table → `plane_records` migration could not be completed at boot (a
/// store write hiccup); the durable seam has not yet taken over the pre-existing audit history.
pub const BOOT_AUDIT_MIGRATE_FAILED: Diagnostic = Diagnostic {
    code: 9012,
    class: Class::Boot,
    slug: "boot-audit-migrate-failed",
    title: "Legacy audit table could not be migrated into the durable journal seam at boot",
    severity: Severity::Actionable,
    summary: "busbar found audit history in the legacy durable table but could not copy it into the \
              neutral `plane_records` the durable audit seam now reads at boot — a store read/write \
              hiccup, not a chain-verification failure. The migration is IDEMPOTENT and is retried on \
              the next boot, so the pre-existing history reappears once the store is healthy; until \
              then the seam-backed audit read (`GET /audit`) reflects only records written since this \
              boot.",
    action: "Investigate the governance store's write path at boot (the same store the audit log \
             persists to). Once it accepts writes, restart so the one-time migration completes and \
             the durable history is restored into the seam; a transient hiccup needs no action \
             beyond confirming the store is healthy.",
    since: "1.6.0",
    retired: false,
};

/// The TLS accept loop is failing persistently (fd exhaustion?); busbar backs off. Backoff-latched.
pub const TLS_ACCEPT_PERSISTENT_FAILURE: Diagnostic = Diagnostic {
    code: 9002,
    class: Class::Boot,
    slug: "tls-accept-persistent-failure",
    title: "TLS accept loop failing persistently (backing off)",
    severity: Severity::Actionable,
    summary: "A TLS listener's accept loop is failing persistently — commonly file-descriptor \
              exhaustion — so busbar backs off before retrying rather than spin hot on the error. \
              On unix each of the N data-plane workers runs its own accept loop, so the warning \
              can fire from one worker or from several at once. The warning is already \
              rate-limited by the backoff delay, so each loop fires at a human cadence, not per \
              failed accept.",
    action:
        "Investigate the accept failure — most often the process fd limit (raise `ulimit -n` / \
             the systemd `LimitNOFILE`) or a resource leak holding sockets open. Each listener \
             keeps retrying with backoff and recovers on its own once accepts succeed.",
    since: "1.6.0",
    retired: false,
};

/// The telemetry bank's slot table is full; further label sets fall back to the metrics macros. Warn-once.
pub const TELEMETRY_SLOT_TABLE_FULL: Diagnostic = Diagnostic {
    code: 9003,
    class: Class::Boot,
    slug: "telemetry-slot-table-full",
    title: "Telemetry slot table full (further label sets fall back to the metrics macros)",
    severity: Severity::BenignRecurring,
    summary: "The telemetry bank's pre-registered slot table reached its cap, so further label sets \
              fall back to the ordinary metrics macros instead of a reserved slot — correct, just \
              slower on that path. Warned ONCE per table (a latch), never per registration, so it \
              cannot spam.",
    action: "None — self-heals; the fallback path is correct. If a deployment legitimately needs \
             more distinct label sets than the slot cap, that cap is a build-time bound; the metrics \
             remain accurate via the fallback in the meantime.",
    since: "1.6.0",
    retired: false,
};

/// An oversized `:event-type` header dropped an event-stream frame. Per-request data path; debug.
pub const EVENTSTREAM_EVENTTYPE_HEADER_OVERSIZE: Diagnostic = Diagnostic {
    code: 9004,
    class: Class::Boot,
    slug: "eventstream-eventtype-header-oversize",
    title: "Event-stream :event-type header exceeds the string cap (frame dropped)",
    severity: Severity::BenignRecurring,
    summary: "An event-stream `:event-type` header exceeded the AWS type-7 string cap, so busbar \
              dropped the frame rather than emit a malformed one. This is unreachable for any real \
              upstream event name (the only caller-supplied value on the frame); it guards the data \
              path and fires per-frame, so it is emitted at debug.",
    action: "None — self-heals per frame; a real upstream event name never trips it. Sustained \
             occurrence would mean a caller is supplying an over-long event-type, worth checking the \
             ingress path.",
    since: "1.6.0",
    retired: false,
};

/// An oversized `:exception-type` header dropped an event-stream exception frame. Per-request; debug.
pub const EVENTSTREAM_EXCEPTIONTYPE_HEADER_OVERSIZE: Diagnostic = Diagnostic {
    code: 9005,
    class: Class::Boot,
    slug: "eventstream-exceptiontype-header-oversize",
    title: "Event-stream :exception-type header exceeds the string cap (frame dropped)",
    severity: Severity::BenignRecurring,
    summary: "An event-stream `:exception-type` header exceeded the AWS type-7 string cap, so busbar \
              dropped the exception frame — a swallowed mid-stream error signal — rather than emit a \
              malformed one. It fires per-frame on the streaming data path and is near-unreachable \
              for a real exception type, so it is emitted at debug.",
    action: "None — self-heals per frame. If it recurs, an upstream mid-stream error carried an \
             over-long exception-type name; check the egress dialect mapping for that upstream.",
    since: "1.6.0",
    retired: false,
};

/// An event-stream frame exceeded MAX_FRAME_BYTES; busbar drops it rather than truncate. Per-request; debug.
pub const EVENTSTREAM_FRAME_OVERSIZE: Diagnostic = Diagnostic {
    code: 9006,
    class: Class::Boot,
    slug: "eventstream-frame-oversize",
    title: "Event-stream frame exceeds MAX_FRAME_BYTES (frame dropped)",
    severity: Severity::BenignRecurring,
    summary: "An event-stream frame's total size exceeded MAX_FRAME_BYTES, so busbar dropped it \
              rather than byte-truncate the payload (a truncated JSON body is worse for a native SDK \
              than no frame). Unreachable for any real upstream event-stream delta; it only guards \
              a pathological multi-MiB single event and fires per-frame, so it is emitted at debug.",
    action: "None — self-heals per frame; dropping is graceful (nothing is emitted for that event). \
             Sustained occurrence would indicate an upstream emitting abnormally large single \
             events, worth investigating that lane.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_TASK_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2041,
    class: Class::Audit,
    slug: "plane-task-chain-verify-failed",
    title: "Per-task provenance chain failed hash-chain verification on restore (tamper)",
    severity: Severity::Actionable,
    summary: "A persisted plane task's provenance events were read at boot but do NOT verify against \
              their own hash chain, which is tamper evidence — the persisted events were altered, or \
              the store is corrupt. The chain is resumed from the broken tail rather than refused, \
              so that corrupting one event cannot silently stop all further provenance for the task.",
    action: "Treat the durable governance store as compromised until explained: capture it for \
             forensic review before it is overwritten, then restore from a trusted backup once the \
             cause is understood.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_CALLLOG_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2042,
    class: Class::Audit,
    slug: "plane-calllog-chain-verify-failed",
    title: "Plane per-call records failed hash-chain verification on restore (tamper evidence)",
    severity: Severity::Actionable,
    summary: "A principal's persisted plane per-call records were read at boot but do NOT verify \
              against their own hash chain, which is tamper evidence. They are still restored and \
              the chain resumes from the broken tail, because refusing here would convert a \
              detection control into a deletion primitive — anyone able to write to the store could \
              delete a caller's history by corrupting one record.",
    action: "Treat the durable governance store as compromised until explained: capture it for \
             forensic review before it is overwritten, then restore from a trusted backup once the \
             cause is understood.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_AUDITLOG_CHAIN_VERIFY_FAILED: Diagnostic = Diagnostic {
    code: 2043,
    class: Class::Audit,
    slug: "plane-auditlog-chain-verify-failed",
    title: "Admin audit records failed hash-chain verification on restore (tamper evidence)",
    severity: Severity::Actionable,
    summary: "The persisted admin audit records were read at boot through the durable journal seam \
              but do NOT verify against their own hash chain, which is tamper evidence. They are \
              still restored and the chain resumes from the broken tail, because refusing here would \
              convert a detection control into a deletion primitive — anyone able to write to the \
              store could delete audit history by corrupting one record.",
    action: "Treat the durable governance store as compromised until explained: capture it for \
             forensic review before it is overwritten, then restore from a trusted backup once the \
             cause is understood.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_AUDITLOG_WRITE_FAILED: Diagnostic = Diagnostic {
    code: 2044,
    class: Class::Audit,
    slug: "plane-auditlog-write-failed",
    title: "Admin audit record could not be written through the durable journal seam (evidence lost)",
    severity: Severity::Actionable,
    summary: "The admin audit record could NOT be written through the durable journal seam, so this \
              mutation is being served but its evidence is being lost on that path. The chain \
              position is unchanged, so the chain stays contiguous — what is missing is this one \
              record, not the ones after it. This can recur per mutation during a store outage, so \
              it warns on the transition into the failing state and holds subsequent occurrences at \
              debug.",
    action: "Restore the durable governance store's write path. Once writes succeed again the latch \
             resets and a future outage re-warns.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_CALLLOG_ROW_UNREADABLE: Diagnostic = Diagnostic {
    code: 2045,
    class: Class::Audit,
    slug: "plane-calllog-row-unreadable",
    title: "Persisted plane per-call record could not be decoded on restore (skipped, not dropped)",
    severity: Severity::Actionable,
    summary: "A principal's persisted plane per-call record could not be decoded at boot — a body \
              from a store format no released build wrote, or a corrupt row. It is COUNTED and \
              SKIPPED per-record rather than allowed to abort the whole rehydrate (which would drop \
              every OTHER principal's working set), but the skip is reported here so a silently \
              lost evidence row is never invisible. Usually an engine-version mismatch or a corrupt \
              store.",
    action: "Note the principal. If many rows are unreadable, suspect a store format mismatch after \
             an upgrade or downgrade; capture the durable governance store for review.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_JOURNAL_ROW_UNREADABLE: Diagnostic = Diagnostic {
    code: 2046,
    class: Class::Audit,
    slug: "plane-journal-row-unreadable",
    title: "Persisted journal record could not be reframed on restore (skipped, not dropped)",
    severity: Severity::Actionable,
    summary:
        "A scoped journal record could not be reframed at boot — a body from a store format no \
              released build wrote, or a corrupt row. It is COUNTED and SKIPPED per-record rather \
              than allowed to abort the whole rehydrate (which would drop every OTHER scope's \
              working set), but the skip is reported here so a silently lost evidence row is never \
              invisible. Usually an engine-version mismatch or a corrupt store.",
    action:
        "Note the scope. If many rows are unreadable, suspect a store format mismatch after an \
             upgrade or downgrade; capture the durable governance store for review.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_AUDIT_ROW_UNREADABLE: Diagnostic = Diagnostic {
    code: 2047,
    class: Class::Audit,
    slug: "plane-audit-row-unreadable",
    title: "Persisted admin audit record could not be decoded on restore (skipped, not dropped)",
    severity: Severity::Actionable,
    summary:
        "A persisted admin audit record could not be decoded at boot on the neutral `plane_records` \
              path — a body from a store format no released build wrote, or a corrupt or tampered \
              row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole \
              restore, but the skip is reported here so a silently lost evidence row on this \
              tamper-evidence surface is never invisible. On the admin audit log an undecodable row \
              may be tamper evidence, not merely a format mismatch.",
    action:
        "Treat the durable governance store as suspect: if rows are unreadable on a store a released \
             build wrote, capture it for forensic review before it is overwritten and restore from a \
             trusted backup once the cause is understood.",
    since: "1.6.0",
    retired: false,
};

pub const WEBHOOK_EXPORTER_DISABLED: Diagnostic = Diagnostic {
    code: 7070,
    class: Class::Plane,
    slug: "webhook-exporter-disabled",
    title: "Webhook log exporter disabled (invalid configuration)",
    severity: Severity::Actionable,
    summary: "A request-log webhook exporter could not be built from its configuration and has been \
              disabled, so its request logs are NOT delivered. This is a config problem surfaced at \
              boot, not a transient delivery failure.",
    action: "Fix the named webhook exporter's configuration (URL, auth header, or projection) and \
             restart to re-enable delivery.",
    since: "1.6.0",
    retired: false,
};

pub const WEBHOOK_DELIVERY_NON_2XX: Diagnostic = Diagnostic {
    code: 7071,
    class: Class::Plane,
    slug: "webhook-delivery-non-2xx",
    title: "Webhook log delivery returned non-2xx (log dropped)",
    severity: Severity::BenignRecurring,
    summary:
        "A request-log webhook delivery got a non-2xx response from the sink, so that one log \
              line was dropped (deliveries are fire-and-forget and never retried). This can recur \
              per request when a sink is unhealthy, so it is logged at debug.",
    action: "If logs are being lost, check the webhook sink's health and the delivery counters. \
             `WEBHOOK_LOGS_DROPPED_TOTAL` tracks the volume.",
    since: "1.6.0",
    retired: false,
};

pub const WEBHOOK_DELIVERY_TRANSPORT_ERROR: Diagnostic = Diagnostic {
    code: 7072,
    class: Class::Plane,
    slug: "webhook-delivery-transport-error",
    title: "Webhook log delivery transport error (log dropped)",
    severity: Severity::BenignRecurring,
    summary:
        "A request-log webhook delivery failed with a transport error (connection/timeout/DNS), \
              so that one log line was dropped. Deliveries are fire-and-forget and never retried; \
              this can recur per request when a sink is unreachable, so it is logged at debug.",
    action: "If logs are being lost, check the webhook sink's reachability and the delivery \
             counters. `WEBHOOK_LOGS_DROPPED_TOTAL` tracks the volume.",
    since: "1.6.0",
    retired: false,
};

pub const FILE_LOG_APPEND_FAILED: Diagnostic = Diagnostic {
    code: 7073,
    class: Class::Plane,
    slug: "file-log-append-failed",
    title: "Request-log file append failed (log dropped)",
    severity: Severity::Actionable,
    summary:
        "Writing a line to the request-log file failed, so that log line was dropped. Telemetry \
              writes are fire-and-forget and never block serving, but a persistent failure means \
              request logs are being lost — usually a disk-full or permission problem.",
    action:
        "Check the log file's path for free space and write permission. Serving is unaffected; \
             only request-log durability is.",
    since: "1.6.0",
    retired: false,
};

pub const FILE_LOG_OPEN_FAILED: Diagnostic = Diagnostic {
    code: 7074,
    class: Class::Plane,
    slug: "file-log-open-failed",
    title: "Request-log file open failed (log dropped)",
    severity: Severity::Actionable,
    summary: "The request-log file could not be opened for append, so that log line was dropped. A \
              persistent failure means request logs are being lost — usually a missing directory, a \
              permission problem, or a full disk.",
    action: "Ensure the log file's directory exists and is writable, and that the disk is not full. \
             Serving is unaffected; only request-log durability is.",
    since: "1.6.0",
    retired: false,
};

pub const FILE_LOG_RETENTION_FAILED: Diagnostic = Diagnostic {
    code: 7075,
    class: Class::Plane,
    slug: "file-log-retention-failed",
    title: "Request-log archive retention cleanup failed",
    severity: Severity::Actionable,
    summary: "During rotation, deleting the oldest request-log archive failed, so the archive series \
              may grow past its retention limit and consume more disk than intended. No log data is \
              lost by this failure itself.",
    action: "Check the log directory's permissions and free space so retention cleanup can remove \
             the oldest archive on the next rotation.",
    since: "1.6.0",
    retired: false,
};

pub const FILE_LOG_SHIFT_FAILED: Diagnostic = Diagnostic {
    code: 7076,
    class: Class::Plane,
    slug: "file-log-shift-failed",
    title: "Request-log archive shift failed during rotation",
    severity: Severity::Actionable,
    summary:
        "Renaming an archived request-log file to its next slot during rotation failed, so the \
              older archive was left in place rather than lost. Rotation degrades but no recorded \
              data is discarded.",
    action: "Check the log directory's permissions and that no external process holds the archive \
             files, so the shift can complete on the next rotation.",
    since: "1.6.0",
    retired: false,
};

pub const FILE_LOG_ROTATE_RENAME_FAILED: Diagnostic = Diagnostic {
    code: 7077,
    class: Class::Plane,
    slug: "file-log-rotate-rename-failed",
    title: "Request-log rotation rename failed (file grows past cap)",
    severity: Severity::Actionable,
    summary: "Renaming the current request-log file to its first archive slot failed, so busbar keeps \
              APPENDING to the current file rather than truncating it — no recorded data is lost, but \
              the file will grow past its `rotate_mb` cap until this is resolved.",
    action: "Check the log directory's permissions and free space so the rotation rename can \
             succeed. No data is lost in the meantime; the file simply exceeds its size cap.",
    since: "1.6.0",
    retired: false,
};

pub const IR_CLAMP_N_TO_1: Diagnostic = Diagnostic {
    code: 7078,
    class: Class::Plane,
    slug: "ir-clamp-n-to-1",
    title: "Cross-protocol transcode clamped n>1 to 1",
    severity: Severity::BenignRecurring,
    summary: "On a cross-protocol hop the neutral response IR carries a single candidate, so a \
              request asking for n>1 completions is clamped to n=1 before the egress writer emits it \
              — otherwise extra choices would be generated, billed, and then dropped. Fires per \
              request on the affected seam, so it is logged at debug.",
    action: "None — self-heals. To use n>1, route the request to a same-protocol lane where the \
             body is forwarded verbatim.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_REASONING: Diagnostic = Diagnostic {
    code: 7079,
    class: Class::Plane,
    slug: "ir-drop-reasoning",
    title: "Cross-protocol transcode dropped a reasoning/thinking ask",
    severity: Severity::BenignRecurring,
    summary: "A request's reasoning/thinking parameter was dropped on the cross-protocol seam because \
              the target lane does not declare the reasoning capability; the request proceeds at the \
              backend's default thinking level. Fires per request on the affected seam, logged at \
              debug.",
    action: "None — self-heals. Set `reasoning: true` on the model or pool member if the backend \
             accepts thinking params.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_PROMPT_CACHE: Diagnostic = Diagnostic {
    code: 7080,
    class: Class::Plane,
    slug: "ir-drop-prompt-cache",
    title: "Cross-protocol transcode dropped prompt-cache breakpoints",
    severity: Severity::BenignRecurring,
    summary: "Prompt-cache breakpoints were cleared on the cross-protocol seam because the target \
              lane's dialect gates its cache marker per model and the lane does not declare the \
              capability; the request proceeds uncached. Fires per request on the affected seam, \
              logged at debug.",
    action:
        "None — self-heals. Set `prompt_caching: true` on the model if the backend accepts cache \
             markers.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_CACHE_CONTROL_OVER_CAP: Diagnostic = Diagnostic {
    code: 7081,
    class: Class::Plane,
    slug: "ir-drop-cache-control-over-cap",
    title: "Cross-protocol transcode dropped cache_control breakpoints past the dialect cap",
    severity: Severity::BenignRecurring,
    summary:
        "The request carried more cache_control breakpoints than the egress dialect allows (the \
              target vendor 400s past its documented cap), so the breakpoints past the cap were \
              dropped before the writer emitted them. Reachable only cross-protocol; fires per \
              request, logged at debug.",
    action:
        "None — self-heals. Reduce the number of cache breakpoints, or route to a same-protocol \
             lane if the full set is load-bearing.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_HOSTED_TOOLS: Diagnostic = Diagnostic {
    code: 7082,
    class: Class::Plane,
    slug: "ir-drop-hosted-tools",
    title: "Cross-protocol transcode dropped hosted (built-in) tools",
    severity: Severity::BenignRecurring,
    summary: "One or more provider-hosted (built-in) tools were dropped on the cross-protocol seam \
              because they have no function-tool equivalent on a backend that does not host them; forwarding \
              them would emit a malformed empty-name function tool the upstream rejects. Fires per \
              request, logged at debug.",
    action: "None — self-heals. Route hosted-tool requests to a lane whose backend hosts them.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_MESSAGE_NAME: Diagnostic = Diagnostic {
    code: 7083,
    class: Class::Plane,
    slug: "ir-drop-message-name",
    title: "Cross-protocol transcode dropped per-message participant names (messages[].name)",
    severity: Severity::BenignRecurring,
    summary: "Per-message participant names (`messages[].name`) were dropped on the \
              cross-protocol seam because no target protocol models a per-message speaker name, so a \
              multi-speaker transcript reaches the backend with its speaker labels removed. Fires \
              per request, logged at debug.",
    action: "None — self-heals. Put the speaker in the message text, or route to a same-protocol lane that models them.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_CACHED_CONTENT: Diagnostic = Diagnostic {
    code: 7084,
    class: Class::Plane,
    slug: "ir-drop-cached-content",
    title: "Cross-protocol transcode dropped a provider cachedContent reference",
    severity: Severity::BenignRecurring,
    summary:
        "A provider `cachedContent` reference was dropped on the cross-protocol seam because the \
              referenced context cache lives server-side at the origin provider and cannot be projected into \
              `contents`: the backend answers on the visible history only and the caller is billed \
              full uncached input. Fires per request, logged at debug.",
    action: "None — self-heals. Route cachedContent requests to a same-protocol lane to use the cache.",
    since: "1.6.0",
    retired: false,
};

pub const IR_DROP_UNMODELED_KEYS: Diagnostic = Diagnostic {
    code: 7085,
    class: Class::Plane,
    slug: "ir-drop-unmodeled-keys",
    title: "Cross-protocol transcode dropped unmodeled request keys",
    severity: Severity::BenignRecurring,
    summary: "The source dialect's unmodeled top-level request keys were dropped on the \
              cross-protocol seam because no target writer can re-emit a foreign dialect's key, so \
              every key named in the log is not forwarded to the backend. Fires per request; only \
              key names are logged (never their values), at debug.",
    action:
        "None — self-heals. Route to a same-protocol lane (which forwards the caller's original \
             bytes verbatim) if a named field is load-bearing.",
    since: "1.6.0",
    retired: false,
};

pub const IR_TRUNCATE_STOP_SEQUENCES: Diagnostic = Diagnostic {
    code: 7086,
    class: Class::Plane,
    slug: "ir-truncate-stop-sequences",
    title: "Stop sequences truncated to the protocol's documented cap",
    severity: Severity::BenignRecurring,
    summary: "The request carried more stop sequences than the target protocol's documented cap \
              allows, so the excess were dropped before forwarding. Fires per request on the \
              affected seam, logged at debug.",
    action: "None — self-heals. Reduce the number of stop sequences, or route to a same-protocol \
             lane if the full set is required.",
    since: "1.6.0",
    retired: false,
};

pub const PROTO_AUTH_INVALID_HEADER_BYTES: Diagnostic = Diagnostic {
    code: 7087,
    class: Class::Plane,
    slug: "proto-auth-invalid-header-bytes",
    title: "Egress credential has invalid header bytes (auth header omitted)",
    severity: Severity::BenignRecurring,
    summary:
        "An egress authorization credential contained bytes that are not valid in an HTTP header \
              (e.g. an ASCII control character), so the Authorization header was omitted entirely \
              rather than sent malformed — the upstream will reject the request with 401. The key \
              itself is never logged, only the protocol name. This is a bad-credential misconfig \
              that can recur per request, so it is logged at debug.",
    action:
        "Fix the misconfigured lane's credential — the configured secret contains invalid header \
             bytes. The protocol name in the log line locates the lane.",
    since: "1.6.0",
    retired: false,
};

pub const PROTO_DROP_PROVIDER_METADATA: Diagnostic = Diagnostic {
    code: 7088,
    class: Class::Plane,
    slug: "proto-drop-provider-metadata",
    title: "Cross-protocol transcode dropped response-side provider metadata",
    severity: Severity::BenignRecurring,
    summary:
        "Response-side provider metadata (a vendor guardrail `trace`, a vendor `safetyRatings`) \
              was dropped on the cross-protocol seam because it is a vendor-scoped artifact the \
              caller's protocol has no shape to receive. Fires per response on the affected seam, \
              logged at debug.",
    action: "None — self-heals. If this metadata is compliance evidence, route the request to a \
             same-protocol lane where the upstream body reaches the client verbatim.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_TASK_ROW_UNREADABLE: Diagnostic = Diagnostic {
    code: 7089,
    class: Class::Plane,
    slug: "plane-task-row-unreadable",
    title: "Persisted plane task row could not be read back (not resumable)",
    severity: Severity::Actionable,
    summary: "A persisted plane task row could not be decoded at boot, so that task is NOT resumable \
              and is reported rather than skipped silently. Usually an engine-version mismatch or a \
              corrupt row.",
    action: "Note the task id. If many rows are unreadable, suspect a store format mismatch after an \
             upgrade or downgrade; capture the store for review.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_SSRF_CALLBACK_AT_STORE: Diagnostic = Diagnostic {
    code: 7090,
    class: Class::Plane,
    slug: "plane-ssrf-callback-at-store",
    title: "SSRF-refused push callback reached the task store (dropped)",
    severity: Severity::Actionable,
    summary:
        "A push callback URL that the SSRF guard refuses reached the plane task store and was \
              dropped there. The store is the last line of defence — a callback should have been \
              validated by the caller before it got this far, so reaching the store means a caller \
              path skipped validation.",
    action:
        "Find the caller that stored this callback without validating it (a code-level defect in \
             a submission path) and add the SSRF check before the store.",
    since: "1.6.0",
    retired: false,
};

pub const APPROVAL_LEDGER_UNREACHABLE_REFUSED: Diagnostic = Diagnostic {
    code: 7091,
    class: Class::Plane,
    slug: "approval-ledger-unreachable-refused",
    title: "Spent-approval ledger unreachable — redemption refused",
    severity: Severity::Actionable,
    summary:
        "The shared spent-approval ledger could not be reached, so an approval redemption was \
              REFUSED: a ledger that cannot say whether an approval was already spent must not be \
              read as saying it was not (a double-spend on a money-moving tool is the defect the \
              gate exists to stop).",
    action:
        "Restore connectivity to the shared spent-approval ledger's durable store. Until then, \
             approval redemptions fail closed by design.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_CALLLOG_EMPTY_CHAIN: Diagnostic = Diagnostic {
    code: 7092,
    class: Class::Plane,
    slug: "plane-calllog-empty-chain",
    title: "Durable plane call log enumerates a principal with NO records",
    severity: Severity::Actionable,
    summary:
        "The durable plane call log named a principal and then produced no records for it, so its \
              chain is reopened at seq 1 and the discrepancy is reported rather than skipped. The \
              verifier alone cannot distinguish this from a caller's evidence being deleted \
              wholesale.",
    action:
        "Confirm whether this principal was expected to have call history. If it was, treat the \
             store as possibly tampered and capture it for review before it is overwritten.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_CALLLOG_WRITE_FAILED: Diagnostic = Diagnostic {
    code: 7093,
    class: Class::Plane,
    slug: "plane-calllog-write-failed",
    title: "Durable plane per-call record could not be written (evidence lost)",
    severity: Severity::Actionable,
    summary: "The durable plane per-call record could NOT be written, so this call is being served but \
              its evidence is being lost. The chain position is unchanged, so the chain stays \
              contiguous — what is missing is this one record, not the ones after it. This can recur \
              per request during a store outage, so it warns on the transition into the failing \
              state and holds subsequent occurrences at debug.",
    action: "Restore the durable governance store's write path. Once writes succeed again the latch \
             resets and a future outage re-warns.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_DEMOTION_WRITE_FAILED: Diagnostic = Diagnostic {
    code: 7094,
    class: Class::Plane,
    slug: "plane-demotion-write-failed",
    title: "Durable plane demotion record could not be written",
    severity: Severity::Actionable,
    summary: "The durable plane demotion record could NOT be written, so this upstream is demoted only \
              in the current process and a restart will re-open it until the next sweep looks again. \
              Usually a durable store-write outage.",
    action: "Restore the durable governance store's write path so demotions persist across restarts.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_DEMOTION_CLEAR_FAILED: Diagnostic = Diagnostic {
    code: 7095,
    class: Class::Plane,
    slug: "plane-demotion-clear-failed",
    title: "Durable plane demotion record could not be cleared",
    severity: Severity::Actionable,
    summary: "The durable plane demotion record for an upstream could NOT be cleared even though it is \
              serving again in the current process, so a restart would re-establish a quarantine the \
              operator has already worked. Usually a durable store-write outage.",
    action: "Restore the durable governance store's write path so a cleared demotion does not \
             reappear after a restart.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_DEMOTIONS_UNREAD: Diagnostic = Diagnostic {
    code: 7096,
    class: Class::Plane,
    slug: "plane-demotions-unread",
    title: "Durable plane demotion records could not be read at boot",
    severity: Severity::Actionable,
    summary: "The durable plane demotion records could NOT be read at boot, so any upstream this \
              deployment had demoted is re-opened until the first sweep looks again. Usually a \
              durable store-read outage.",
    action:
        "Restore the durable governance store's read path and restart so persisted demotions are \
             re-applied before a listener binds.",
    since: "1.6.0",
    retired: false,
};

pub const TRUST_VERIFY_REFUSED_ON_DRIFT: Diagnostic = Diagnostic {
    code: 7097,
    class: Class::Plane,
    slug: "trust-verify-refused-on-drift",
    title: "Verify-on-call refused a call because the upstream's advertised surface drifted",
    severity: Severity::BenignRecurring,
    summary: "On the request path, verify-on-call re-fetched the upstream's advertised surface (a \
              tool's name+args+description, or an agent card) within `verify_ttl` and found \
              it DRIFTED from the fingerprint the operator approved, so the call was refused BEFORE \
              dispatch. The refusal itself is the signal; this is a warn-once-per-subject note so \
              persistent drift does not spam.",
    action: "Review the change on the trust surface and re-approve the new fingerprint if it is \
             legitimate, or investigate the upstream if it is not.",
    since: "1.6.0",
    retired: false,
};

pub const TRUST_VERIFY_UNREACHABLE: Diagnostic = Diagnostic {
    code: 7098,
    class: Class::Plane,
    slug: "trust-verify-unreachable",
    title: "Verify-on-call could not reach an upstream to re-verify, and refused fail-closed",
    severity: Severity::Actionable,
    summary: "On the request path, verify-on-call needed to re-verify an upstream whose recorded \
              observation was older than `verify_ttl`, and the re-fetch FAILED (unreachable or \
              unverifiable). The call was REFUSED fail-closed rather than served against a snapshot \
              older than the operator's bound. Latched per subject.",
    action: "Restore reachability to the named upstream. Calls to it are refused until a re-fetch \
             succeeds within `verify_ttl`; a larger `verify_ttl` widens the drift-serving window \
             and is an explicit, documented security downgrade.",
    since: "1.6.0",
    retired: false,
};

/// The abandonment sweep could not settle an idle active task as canceled — a store outage.
pub const PLANE_TASK_ABANDON_UNRECORDED: Diagnostic = Diagnostic {
    code: 7099,
    class: Class::Plane,
    slug: "plane-task-abandon-unrecorded",
    title:
        "Abandoned plane task could not be transitioned to canceled (durable store write failed)",
    severity: Severity::Actionable,
    summary: "The submit-time retention sweep found an ACTIVE task idle past the abandonment \
              ceiling (24h since its last update) and tried to settle it as `canceled` through the \
              normal durable write path, but the row upsert or chained event append failed. The \
              task stays active in the working set (never ahead of the store) and the next sweep \
              retries. Typically a durable-store outage. Warned once on the transition into the \
              failing state; subsequent failures hold at debug to avoid spam.",
    action: "Investigate the durable task-store outage. Abandoned tasks settle (and then age out \
             of the working set) once the store accepts writes again.",
    since: "1.6.0",
    retired: false,
};

pub const ADMIN_STORE_OPERATION_FAILED: Diagnostic = Diagnostic {
    code: 1006,
    class: Class::Durability,
    slug: "admin-store-operation-failed",
    title: "Admin store operation failed (generic 500; store detail logged server-side)",
    severity: Severity::Actionable,
    summary: "An admin API CRUD or read operation against the governance/durable store returned an \
              error, so busbar answers the admin request with a generic 500. The store's own error \
              (which may embed SQL fragments or backend paths) is logged server-side only — the HTTP \
              body carries no store internals. The `operation` field names which call failed.",
    action: "Investigate the durable/governance store's health and reachability for the named \
             operation. A transient store hiccup self-heals on retry; sustained failures mean the \
             store backend is unhealthy and admin mutations/reads cannot complete.",
    since: "1.6.0",
    retired: false,
};

pub const ADMIN_STORE_TASK_JOIN_FAILED: Diagnostic = Diagnostic {
    code: 1007,
    class: Class::Durability,
    slug: "admin-store-task-join-failed",
    title: "Admin store blocking task failed to join (cancelled or panicked)",
    severity: Severity::Actionable,
    summary: "An admin store operation ran on a `spawn_blocking` task that failed to join — the \
              blocking store closure was cancelled or panicked — so busbar maps it to a generic 500 \
              rather than let a JoinError propagate as an unwrap on the request path. The blocking \
              store closures do not panic in normal operation.",
    action: "Investigate the logged operation and store backend — a panic in a blocking store \
             closure is a bug or a resource failure. Capture the error and file a bug if it recurs; \
             the request was safely failed, not mis-served.",
    since: "1.6.0",
    retired: false,
};

pub const GROUP_DELETE_KEY_READ_FAILED: Diagnostic = Diagnostic {
    code: 1008,
    class: Class::Durability,
    slug: "group-delete-key-read-failed",
    title: "Group delete could not read keys to check bindings (admin 500)",
    severity: Severity::Actionable,
    summary: "Deleting a group requires a full key scan to count how many keys are still bound to \
              it, and that store read failed, so busbar answers the admin delete with a generic 500 \
              rather than delete a group with unknown live bindings. No group state was changed.",
    action: "Investigate the governance store's reachability — the key scan could not complete. \
             Retry the delete once the store is healthy; a transient read error self-heals.",
    since: "1.6.0",
    retired: false,
};

pub const USAGE_BLOCKING_TASK_JOIN_FAILED: Diagnostic = Diagnostic {
    code: 1009,
    class: Class::Durability,
    slug: "usage-blocking-task-join-failed",
    title: "Admin /usage blocking task failed to join (cancelled or panicked)",
    severity: Severity::Actionable,
    summary: "The admin /usage read ran on a `spawn_blocking` task that failed to join (cancelled or \
              panicked), so busbar answers the request with a generic 500. Distinct from a store \
              error returned by the read itself (BUSBAR-1006): here the blocking task did not \
              complete at all.",
    action: "Investigate the logged context and store backend — a blocking-task panic is a bug or a \
             resource failure. Capture the error and file a bug if it recurs; the request was safely \
             failed.",
    since: "1.6.0",
    retired: false,
};

pub const ADMIN_AUTH_CHAIN_EMPTY: Diagnostic = Diagnostic {
    code: 4026,
    class: Class::Auth,
    slug: "admin-auth-chain-empty",
    title: "admin_auth chain is EMPTY (open, anonymous, full-authority dev posture)",
    severity: Severity::Actionable,
    summary: "An EMPTY admin_auth chain was seen: the admin API's open dev posture admits every \
              admin request anonymously with FULL authority. The live `PUT /api/v1/admin/admin-auth` \
              REFUSES to apply an empty chain (and an admin-scope dry-run reports it as no earned \
              grant, never full), so this posture can only be entered deliberately via config.yaml \
              at boot — never flipped open by one unnoticed API call.",
    action: "Leave `admin_auth` empty ONLY for local development. To opt into the open posture, set \
             `admin_auth: []` in config.yaml and restart. Otherwise configure a non-empty chain (an \
             `admin-tokens` entry with a `token:`, or an admin module) before exposing the admin API \
             to any untrusted network.",
    since: "1.6.0",
    retired: false,
};

pub const ADMIN_CREATEKEY_MALFORMED_BODY: Diagnostic = Diagnostic {
    code: 4027,
    class: Class::Auth,
    slug: "admin-createkey-malformed-body",
    title: "create_key request body failed to parse (client 400)",
    severity: Severity::BenignRecurring,
    summary: "A create_key request body did not parse as valid JSON, so busbar returns a generic 400. \
              The body carries secrets (an AWS secret_access_key, the bearer being minted), so only \
              its byte length is logged, never the raw error or an input fragment. This is a \
              CLIENT-side bad request, not an operator problem, so it is emitted at debug.",
    action: "None — self-heals; the client must send well-formed JSON. Persistent volume from one \
             caller indicates a broken client worth fixing, but it is not a busbar fault.",
    since: "1.6.0",
    retired: false,
};

pub const CREATEKEY_UNKNOWN_POOL: Diagnostic = Diagnostic {
    code: 4028,
    class: Class::Auth,
    slug: "createkey-unknown-pool",
    title: "create_key allowed_pools names an unconfigured pool (key still created)",
    severity: Severity::BenignRecurring,
    summary: "A create_key request listed an `allowed_pools` entry that names no configured pool — a \
              likely typo. The key is still created (the entry activates if the pool is configured \
              later), so this is a non-fatal advisory. It is a per-request, caller-side signal, so it \
              is emitted at debug.",
    action: "None required — the key was created. If the pool name was a typo, correct it or \
             configure the named pool so the allowed_pools entry takes effect.",
    since: "1.6.0",
    retired: false,
};

pub const ADMIN_UPDATEKEY_MALFORMED_BODY: Diagnostic = Diagnostic {
    code: 4029,
    class: Class::Auth,
    slug: "admin-updatekey-malformed-body",
    title: "update_key request body failed to parse (client 400)",
    severity: Severity::BenignRecurring,
    summary: "An update_key request body did not parse as valid JSON, so busbar returns a generic \
              400, logging only the body's byte length (never the raw serde error or an input \
              fragment). Mirror of BUSBAR-4027 for the update path. This is a CLIENT-side bad \
              request, so it is emitted at debug.",
    action: "None — self-heals; the client must send well-formed JSON. Persistent volume from one \
             caller indicates a broken client worth fixing.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_BREAKER_TRIPPED: Diagnostic = Diagnostic {
    code: 5038,
    class: Class::Proxy,
    slug: "plane-breaker-tripped",
    title: "Plane breaker tripped (upstream target failing; dispatches fast-fail)",
    severity: Severity::Actionable,
    summary: "A plane target's circuit breaker transitioned Closed→Open because the upstream \
              target is failing, so further dispatches fast-fail until the half-open probe recovers \
              it. Names the specific target (every plane target shares one degenerate lane, so \
              without this the operator would not learn WHICH server is down). Emitted once per \
              logical trip, not per failure.",
    action: "Investigate the named plane target's health (the tool, agent, or server it fronts). \
             Traffic to it fast-fails until the breaker's half-open probe finds it healthy again.",
    since: "1.6.0",
    retired: false,
};

pub const PLANE_BREAKER_HARD_DOWN: Diagnostic = Diagnostic {
    code: 5039,
    class: Class::Proxy,
    slug: "plane-breaker-hard-down",
    title: "Plane breaker tripped hard-down (definitive auth/billing failure; sticky cooldown)",
    severity: Severity::Actionable,
    summary: "A plane target answered a DEFINITIVE failure (auth/billing), so busbar trips \
              its breaker hard-down: dispatches fast-fail for a sticky cooldown rather than keep \
              retrying a target that will keep rejecting. Emitted per hard-down disposition for the \
              named target.",
    action: "Fix the named target's credentials or billing/quota with its provider — a hard-down is \
             a definitive rejection, not a transient blip. It recovers via the half-open probe once \
             the underlying auth/billing fault is resolved.",
    since: "1.6.0",
    retired: false,
};

pub const LANE_HARD_DOWN_ALL_CELLS: Diagnostic = Diagnostic {
    code: 5040,
    class: Class::Proxy,
    slug: "lane-hard-down-all-cells",
    title: "Lane hard-down across all cells (sticky cooldown; recovers via half-open probe)",
    severity: Severity::Actionable,
    summary: "A lane was recorded hard-down across ALL its per-pool cells at once (the all-cells \
              variant of BUSBAR-5026) — every pool's view of the lane is tripped Open with a sticky \
              cooldown. The lane is RECOVERABLE via the half-open probe (it is not marked dead), so \
              it re-admits once a probe succeeds.",
    action: "Investigate the named upstream/model lane's health — a hard-down across all cells means \
             a definitive lane-wide fault. Traffic fails over automatically; the lane recovers via \
             the half-open probe once the upstream is healthy.",
    since: "1.6.0",
    retired: false,
};

pub const BREAKER_UNEXPECTED_STATE_CLASSIFY: Diagnostic = Diagnostic {
    code: 5041,
    class: Class::Proxy,
    slug: "breaker-unexpected-state-classify",
    title: "Unexpected breaker state on classify (fail-safe: deny admission)",
    severity: Severity::Actionable,
    summary: "The breaker classify path read a cell state that is not one of the three valid \
              encodings (Closed/Open/HalfOpen). This is IMPOSSIBLE under the atomic-sentinel \
              invariant, so reaching it means a real invariant break or memory corruption. busbar \
              fails SAFE — treats the cell as never-elapsing Open so admission is denied — rather \
              than panic the dispatching task. Warned once per process; recurrence logs at debug.",
    action: "Capture the logged state value and file a bug — a breaker cell should never hold an \
             unexpected state. Requests to that cell are safely denied (fail-closed) until it is \
             re-armed; investigate for memory corruption if it persists.",
    since: "1.6.0",
    retired: false,
};

pub const BREAKER_UNEXPECTED_STATE_PROBE: Diagnostic = Diagnostic {
    code: 5042,
    class: Class::Proxy,
    slug: "breaker-unexpected-state-probe",
    title: "Unexpected breaker state on probe acquisition (fail-safe: refuse)",
    severity: Severity::Actionable,
    summary: "The breaker probe-acquisition path read an unexpected cell state (not \
              Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar refuses \
              the probe acquisition (admits nobody) rather than panic the dispatching task. Same \
              invariant-break family as BUSBAR-5041. Warned once per process; recurrence logs at \
              debug.",
    action: "Capture the logged state value and file a bug. Probe acquisition is safely refused; \
             investigate for memory corruption if it persists.",
    since: "1.6.0",
    retired: false,
};

pub const BREAKER_UNEXPECTED_STATE_READ: Diagnostic = Diagnostic {
    code: 5043,
    class: Class::Proxy,
    slug: "breaker-unexpected-state-read",
    title: "Unexpected breaker state on state read (reporting Closed)",
    severity: Severity::Actionable,
    summary: "A breaker cell state read (a total, side-effect-free projection) found an unexpected \
              encoding. Impossible under the atomic-sentinel invariant; busbar reports the benign \
              Closed default rather than panic, keeping the read total for any encoding. Same family \
              as BUSBAR-5041. Warned once per process; recurrence logs at debug.",
    action: "Capture the logged state value and file a bug — this read should never see an unexpected \
             state. The projection is safe; investigate for memory corruption if it persists.",
    since: "1.6.0",
    retired: false,
};

pub const BREAKER_UNEXPECTED_STATE_RECORD_FAILURE: Diagnostic = Diagnostic {
    code: 5044,
    class: Class::Proxy,
    slug: "breaker-unexpected-state-record-failure",
    title: "Unexpected breaker state in record_failure (no-op)",
    severity: Severity::Actionable,
    summary: "The breaker failure-recording path read an unexpected cell state (not \
              Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar treats it \
              as a no-op (like the already-Open case) rather than panic the task. Same family as \
              BUSBAR-5041. Warned once per process; recurrence logs at debug.",
    action: "Capture the logged state value and file a bug — a breaker cell should never hold an \
             unexpected state. The failure record is safely dropped; investigate for memory \
             corruption if it persists.",
    since: "1.6.0",
    retired: false,
};

pub const PLUGINS_DIR_FINGERPRINT_FAILED: Diagnostic = Diagnostic {
    code: 6004,
    class: Class::Plugins,
    slug: "plugins-dir-fingerprint-failed",
    title: "Cannot fingerprint the plugins dir (bypassing the catalog cache)",
    severity: Severity::BenignRecurring,
    summary: "A real I/O error (not a missing directory) meant the plugins directory could not be \
              fingerprinted, so its content-hash freshness signal cannot be trusted and busbar \
              bypasses the catalog cache for this read, falling through to the real scan. \
              Self-healing: it clears once the directory is readable. Warned once on entry to the \
              failing state; recurrence logs at debug.",
    action:
        "Investigate the plugins directory's readability (permissions, a stale/hung mount). The \
             catalog read still works via the direct scan; the cache re-engages once the directory \
             fingerprints cleanly again.",
    since: "1.6.0",
    retired: false,
};

pub const PLUGIN_CATALOG_SCAN_GATE_TIMEOUT: Diagnostic = Diagnostic {
    code: 6005,
    class: Class::Plugins,
    slug: "plugin-catalog-scan-gate-timeout",
    title: "Plugin catalog scan gate not acquired within the wait bound (retryable 503)",
    severity: Severity::Actionable,
    summary: "A plugin catalog scan could not acquire the scan gate within its bounded wait, which \
              signals a PRIOR scan is not returning — typically a stale or hung plugins_dir mount. \
              busbar answers with a retryable Unavailable (503) rather than hang this request behind \
              the wedged scan.",
    action: "Investigate the plugins_dir mount — a hung scan usually means the directory's \
             filesystem is stalled (e.g. an unresponsive network mount). Resolve the mount; the gate \
             frees once the prior scan returns or is unwedged.",
    since: "1.6.0",
    retired: false,
};

pub const PLUGIN_CATALOG_BLOCKING_TASK_FAILED: Diagnostic = Diagnostic {
    code: 6006,
    class: Class::Plugins,
    slug: "plugin-catalog-blocking-task-failed",
    title: "Plugin catalog blocking task failed to join (fail-soft to the compiled-in row)",
    severity: Severity::Actionable,
    summary: "The plugin catalog store scan ran on a `spawn_blocking` task that failed to join \
              (cancelled or panicked). busbar fails SOFT to the always-true compiled-in catalog row \
              rather than a 500 — this is just a plugin CATALOG read — the same posture it takes on \
              an unparseable plugins_cfg. Rare.",
    action: "Investigate the logged context if it recurs — a blocking-task join failure on the \
             catalog read is unusual. The catalog is served fail-soft in the meantime, so the admin \
             read still returns.",
    since: "1.6.0",
    retired: false,
};

pub const PLUGIN_ROLLBACK_PIN_PERSIST_FAILED: Diagnostic = Diagnostic {
    code: 6007,
    class: Class::Plugins,
    slug: "plugin-rollback-pin-persist-failed",
    title: "Plugin rollback could not persist the version pin (nothing swapped, fail-closed)",
    severity: Severity::Actionable,
    summary: "A plugin rollback tried to persist the lowered version pin to the config overlay and \
              the write failed, so busbar FAILS CLOSED and swaps nothing — the running engine still \
              serves the current plugin. Persisting the pin is the whole point of the rollback: a \
              swallowed failure would swap the live engine while disk still carried the \
              rolled-forward state, so a restart would silently re-upgrade.",
    action: "Investigate the config overlay's writability (the log names the plugin). Fix the \
             overlay path/permissions and re-issue the rollback; nothing was changed, so it is safe \
             to retry.",
    since: "1.6.0",
    retired: false,
};

pub const PLUGIN_ROLLBACK_REVERT_FAILED: Diagnostic = Diagnostic {
    code: 6008,
    class: Class::Plugins,
    slug: "plugin-rollback-revert-failed",
    title: "Plugin rollback rebuild failed AND reverting the version pin failed (disk out of sync)",
    severity: Severity::Actionable,
    summary: "A plugin rollback's rebuild failed AFTER the lowered pin was persisted, and the \
              compensating revert of that pin ALSO failed, so disk now carries the rolled-forward pin \
              while the running engine still serves the prior plugin. A restart would honor the \
              stale on-disk pin and contradict the running engine. Loud because disk and the live \
              engine now disagree.",
    action: "Fix the config overlay so the version pin matches the plugin the running engine serves \
             BEFORE restarting (the log names the plugin and both errors). Until then a restart would \
             come up in a state the running engine rejected.",
    since: "1.6.0",
    retired: false,
};

// ── 1.6.0 bin crate (`crates/busbar`) + admin-read orphans ──────────────────────────────────────
// Diagnostics emitted from the `busbar` binary (argument parsing, config LOCATION, boot/lifecycle)
// and two admin READ paths in busbar-core that reached this catalog after their neighbours. Classed
// by SUBJECT, not by the file they live in: a config-parse failure in `main.rs` is a 3000 code, a
// metadata-SSRF posture line is 5000, a plugin-trust CLI check is 6000, boot/lifecycle is 9000.

/// `--print-metadata-blocklist` could not read/parse config, so it printed the built-in denylist only.
pub const CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE: Diagnostic = Diagnostic {
    code: 3014,
    class: Class::Config,
    slug: "cli-metadata-blocklist-config-unreadable",
    title: "--print-metadata-blocklist printed the built-in denylist only (config unreadable)",
    severity: Severity::Actionable,
    summary: "`busbar --print-metadata-blocklist` could not parse or env-interpolate config.yaml, so \
              it printed the HARDCODED cloud-metadata denylist ALONE and skipped the operator's \
              `security.blocked_metadata_hosts` additions. The list shown is therefore INCOMPLETE — it \
              omits whatever the config would have added — even though the running gateway (once it \
              boots on a valid config) would enforce the full union.",
    action: "Run `busbar` (or `busbar --validate`) normally to see the precise parse/interpolation \
             error, fix config.yaml, then re-run the flag to see the full effective denylist. The \
             error itself is not echoed here because it could quote a config value.",
    since: "1.6.0",
    retired: false,
};

/// `--validate` found config.yaml/providers.yaml invalid (load, resolve, semantic, or secret phase).
pub const CLI_VALIDATE_CONFIG_INVALID: Diagnostic = Diagnostic {
    code: 3015,
    class: Class::Config,
    slug: "cli-validate-config-invalid",
    title: "--validate rejected the config (load, resolve, semantic, or secret-resolution failure)",
    severity: Severity::Actionable,
    summary:
        "`busbar --validate` ran the exact load → resolve → semantic-validate → strict-secret \
              pipeline boot runs and the config did NOT pass at one of those phases, so it exits \
              non-zero. Because `--validate` mirrors boot, this same config would fail to boot the \
              gateway. The specific phase and offending entries are printed alongside this code.",
    action: "Fix the reported errors in config.yaml / providers.yaml (a parse/structure error, a \
             cross-reference the resolver rejected, a semantic-validation failure, or an unset \
             required secret) and re-run `--validate` until it reports `ok`.",
    since: "1.6.0",
    retired: false,
};

/// `--list-plugins` could not read config, so it inventoried using the default plugins block.
pub const CLI_LIST_PLUGINS_CONFIG_UNREADABLE: Diagnostic = Diagnostic {
    code: 3016,
    class: Class::Config,
    slug: "cli-list-plugins-config-unreadable",
    title: "--list-plugins fell back to the default plugins block (config unreadable)",
    severity: Severity::Actionable,
    summary: "`busbar --list-plugins` could not read/parse config.yaml, so it inventoried the plugins \
              directory using the DEFAULT `plugins:` block (default dir and trust policy) rather than \
              the deployment's configured one. The inventory shown may not reflect the directory, \
              trust policy, or store selection the running gateway would actually use.",
    action: "This is informational and best-effort pre-deployment. To inventory against the real \
             config, fix config.yaml so it parses (run `busbar --validate` to see the error) and \
             re-run `--list-plugins`.",
    since: "1.6.0",
    retired: false,
};

/// GET /config/settings read the overlay while unreadable/corrupt and reported NO root overrides.
pub const CONFIG_SETTINGS_OVERLAY_UNREADABLE: Diagnostic = Diagnostic {
    code: 3017,
    class: Class::Config,
    slug: "config-settings-overlay-unreadable",
    title: "Config-settings read found the overlay unreadable/corrupt (reported no root overrides)",
    severity: Severity::Actionable,
    summary: "A `GET /config/settings` read found the persisted config overlay present but \
              unreadable/corrupt, so it returned an EMPTY set of root overrides. Nothing is mutated, \
              but the response cannot be distinguished from a genuine \"no overrides set\" — the \
              operator's stored single-value overrides may exist on disk yet be absent from this \
              answer.",
    action: "Fix or remove the corrupt overlay file to restore durable reads (see BUSBAR-3005 for the \
             boot-time counterpart). Until then this endpoint under-reports the stored root settings.",
    since: "1.6.0",
    retired: false,
};

/// GET /config/settings read the overlay written by a NEWER busbar and reported NO root overrides.
pub const CONFIG_SETTINGS_OVERLAY_VERSION_TOO_NEW: Diagnostic = Diagnostic {
    code: 3018,
    class: Class::Config,
    slug: "config-settings-overlay-version-too-new",
    title: "Config-settings read found a newer-busbar overlay (reported no root overrides)",
    severity: Severity::Actionable,
    summary: "A `GET /config/settings` read found the config overlay was written by a NEWER busbar \
              than this binary, so — rather than misrepresent fields it cannot parse — it returned an \
              EMPTY set of root overrides. The response cannot be distinguished from a genuine \"no \
              overrides set\", so stored overrides may exist yet be absent from this answer.",
    action: "Read config settings from a busbar at least as new as the one that wrote the overlay, or \
             roll the overlay back to a version this binary understands (see BUSBAR-3006 for the \
             boot-time counterpart).",
    since: "1.6.0",
    retired: false,
};

/// The spawn_blocking task backing GET /config/settings panicked or the runtime is shutting down.
pub const CONFIG_SETTINGS_READ_TASK_JOIN_FAILED: Diagnostic = Diagnostic {
    code: 3019,
    class: Class::Config,
    slug: "config-settings-read-task-join-failed",
    title: "Config-settings overlay read task failed to join (500 rather than a fabricated 200)",
    severity: Severity::Actionable,
    summary: "The blocking task that reads the config overlay for `GET /config/settings` failed to \
              join — it panicked, or the runtime is shutting down — so busbar returns 500 rather than \
              a fabricated empty-settings 200 that would misreport \"no overrides set\" when the read \
              never completed. A panic here is a bug.",
    action: "Retry the request; a shutdown-race clears on its own. A repeatable failure is a panic in \
             the overlay read path — capture the logged join error and file a bug.",
    since: "1.6.0",
    retired: false,
};

/// A rate_card entry prices a model at all-zero across every tier: it meters as FREE and uncapped.
pub const CONFIG_RATE_CARD_ALL_ZERO: Diagnostic = Diagnostic {
    code: 3020,
    class: Class::Config,
    slug: "config-rate-card-all-zero",
    title: "rate_card entry prices a model at ALL ZERO (metered as free, uncapped)",
    severity: Severity::Actionable,
    summary: "A model has a `rate_card` entry present but every tier (input, output, cache_read, \
              cache_write) is zero, so its token usage prices to $0: budget-group `budget:` limits \
              never accrue token cost against it and it is effectively uncapped on spend. This is \
              LEGAL (a deliberately free model is a valid choice, e.g. a self-hosted lane), so it is \
              a WARNING, not a boot error — but an accidental all-zero entry (a paste of the \
              completeness stub left unfilled) silently under-bills every request to that model.",
    action: "If the model is intentionally free, ignore this. Otherwise fill in the model's \
             `rate_card` rates (micro-units per token) so its usage prices and counts against any \
             `budget:` limit.",
    since: "1.6.0",
    retired: false,
};

/// The nuclear `allow_all_metadata` is set: the cloud-metadata SSRF guard is OFF. Security posture.
pub const METADATA_PROTECTION_DISABLED: Diagnostic = Diagnostic {
    code: 5045,
    class: Class::Proxy,
    slug: "metadata-protection-disabled",
    title: "Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set)",
    severity: Severity::Actionable,
    summary: "The deployment set the nuclear `allow_all_metadata` escape hatch, so busbar's \
              cloud-metadata SSRF guard is OFF and EVERY cloud-metadata endpoint (e.g. \
              169.254.169.254, the GCP/Azure metadata hosts) is reachable through the proxy. That is a \
              security-relevant degradation: a crafted upstream URL or a compromised plugin can reach \
              the instance's credential endpoint. Emitted once at boot.",
    action: "Remove `allow_all_metadata` unless a specific, understood need requires it. If metadata \
             access is genuinely needed, scope it with `security.blocked_metadata_hosts` instead of \
             disabling the guard wholesale (`--print-metadata-blocklist` shows the effective list).",
    since: "1.6.0",
    retired: false,
};

/// `--validate`'s plugin pre-flight (the exact pipeline boot runs) failed. Plugin-trust subject.
pub const CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED: Diagnostic = Diagnostic {
    code: 6009,
    class: Class::Plugins,
    slug: "cli-validate-plugin-preflight-failed",
    title: "--validate plugin pre-flight failed (structure, trust, conflict, or store resolution)",
    severity: Severity::Actionable,
    summary: "`busbar --validate` ran the same plugin pre-flight boot runs — consistency, trust-policy \
              resolution, the three-phase scan of every tarball (structural → trust → conflict), and \
              store resolution — and it FAILED. Because this is the boot pipeline (manifest-only, no \
              dlopen), the same plugin set would fail the plugin half of boot.",
    action: "Fix the reported plugin problem: a malformed manifest, a signature/trust-policy rejection, \
             an ABI-floor or version-floor violation, a name/alias conflict, or an unresolvable \
             `store.module`. Re-run `--validate` until it reports `ok`.",
    since: "1.6.0",
    retired: false,
};

/// `--list-plugins` could not build a trust policy from `plugins.trust` — the config is invalid.
pub const CLI_LIST_PLUGINS_TRUST_INVALID: Diagnostic = Diagnostic {
    code: 6010,
    class: Class::Plugins,
    slug: "cli-list-plugins-trust-invalid",
    title: "--list-plugins could not build a trust policy (plugins.trust is invalid)",
    severity: Severity::Actionable,
    summary: "`busbar --list-plugins` could not compile a trust policy from the `plugins.trust` block \
              (e.g. an unparsable trust anchor or a malformed policy), so it cannot compute per-tarball \
              signature verdicts and exits non-zero. The running gateway would reject this same \
              `plugins.trust` at boot.",
    action: "Fix the `plugins.trust` block (the logged error names the problem), then re-run \
             `--list-plugins` or `--validate`.",
    since: "1.6.0",
    retired: false,
};

/// A group `/usage` read could not derive a bucket's usage from the governance store. Read-path fault.
pub const GROUP_USAGE_READ_FAILED: Diagnostic = Diagnostic {
    code: 8018,
    class: Class::Governance,
    slug: "group-usage-read-failed",
    title: "Group usage read failed (could not derive a bucket's usage from the governance store)",
    severity: Severity::Actionable,
    summary: "An admin group `/usage` read could not derive a bucket's usage from the governance store \
              (a store read error while computing enforcement-matched spend), so the request returns \
              500 rather than a partial or understated usage view. No governance state is mutated; the \
              read simply could not complete for the named group/bucket.",
    action: "Investigate the governance store's health for the logged group and bucket (reachability, \
             the underlying store error). The condition is a read-path fault; usage reads recover once \
             the store answers.",
    since: "1.6.0",
    retired: false,
};

/// A boot-time fatal error: the binary printed a one-line reason and exited non-zero (`die`).
pub const BOOT_FATAL_ERROR: Diagnostic = Diagnostic {
    code: 9007,
    class: Class::Boot,
    slug: "boot-fatal-error",
    title: "Boot refused (fatal misconfiguration or startup error; process exits non-zero)",
    severity: Severity::Fatal,
    summary: "The binary hit a fatal startup condition — a misconfiguration or other boot-time failure \
              the process cannot serve past — so it printed a single-line reason to stderr and exited \
              non-zero rather than a Rust panic backtrace. The specific reason is printed alongside \
              this code. This is a deliberate refusal, not a crash.",
    action: "Read the printed reason, fix the underlying config/environment problem, and restart. \
             `busbar --validate` reproduces most boot refusals without binding a listener.",
    since: "1.6.0",
    retired: false,
};

/// An explicitly-set worker-thread count (env or config) is not a positive integer; default used.
pub const WORKER_THREADS_INVALID: Diagnostic = Diagnostic {
    code: 9008,
    class: Class::Boot,
    slug: "worker-threads-invalid",
    title: "Configured worker-thread count is invalid (ignored; default used)",
    severity: Severity::Actionable,
    summary: "An explicitly-set data-plane worker count — `TOKIO_WORKER_THREADS`/`advanced.worker_threads` \
              — is not a positive integer (e.g. `0`, or non-numeric), so busbar IGNORES it and boots on \
              the default worker count (one per core). The operator's intended worker count is NOT in \
              effect. Emitted pre-tracing, to stderr, at boot.",
    action: "Set the data-plane worker count to a positive integer (at least 1) or remove it to accept \
             the default. The gateway runs, but on the default worker count, not the value provided.",
    since: "1.6.0",
    retired: false,
};

/// A shutdown-signal handler could not be installed; that signal will not trigger graceful drain.
pub const SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED: Diagnostic = Diagnostic {
    code: 9009,
    class: Class::Boot,
    slug: "shutdown-signal-handler-install-failed",
    title: "Shutdown-signal handler not installed (that signal won't trigger graceful drain)",
    severity: Severity::Actionable,
    summary: "A graceful-shutdown signal handler (SIGINT/ctrl_c, SIGTERM on unix, or \
              CTRL_CLOSE/CTRL_SHUTDOWN on Windows) failed to register. busbar fails soft — that one \
              branch parks forever so the others still trigger the drain — but a stop delivered ONLY \
              via the failed signal will kill the process without draining in-flight requests.",
    action: "Investigate the logged registration error (an unusual sandbox or signal-handling \
             environment). Other shutdown signals still drain; if the affected signal is your \
             deployment's stop path, restart in an environment where it can register.",
    since: "1.6.0",
    retired: false,
};

/// The jemalloc idle-purge fallback could not start; a fully idle process may hold freed RSS.
pub const JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE: Diagnostic = Diagnostic {
    code: 9010,
    class: Class::Boot,
    slug: "jemalloc-idle-purge-fallback-unavailable",
    title: "jemalloc idle-purge fallback unavailable (idle RSS may not return to the OS)",
    severity: Severity::Actionable,
    summary: "The fallback idle-purge helper (for targets where jemalloc's background purge threads \
              are compiled out, e.g. static-musl or macOS) could not start — its worker thread failed \
              to spawn, or it could not read `opt.dirty_decay_ms`. A fully IDLE process may therefore \
              hold freed-but-unpurged dirty pages and its RSS can ratchet at the last burst's peak \
              until traffic resumes. Request behavior is unaffected.",
    action: "Usually benign — RSS is reclaimed the moment traffic resumes, and under load the helper \
             does nothing. If steady idle RSS on a musl/macOS build matters, investigate the logged \
             spawn/mallctl error; the gateway serves normally regardless.",
    since: "1.6.0",
    retired: false,
};

/// `--generate-signing-key` could not obtain OS entropy to mint an ed25519 key.
pub const SIGNING_KEY_GENERATION_FAILED: Diagnostic = Diagnostic {
    code: 9011,
    class: Class::Boot,
    slug: "signing-key-generation-failed",
    title: "--generate-signing-key could not mint a key (OS entropy source unavailable)",
    severity: Severity::Actionable,
    summary: "`busbar --generate-signing-key` could not mint a fresh ed25519 signing secret because \
              the OS entropy source was unavailable, so it printed nothing and exited non-zero. No key \
              was generated and nothing was written.",
    action: "Retry on a host with a working RNG (`/dev/urandom` / `getrandom`). A persistent failure \
             points at a broken or blocked entropy source in the environment.",
    since: "1.6.0",
    retired: false,
};

/// The NEUTRAL, plane-agnostic built-in diagnostics, in ascending code order. Plane-specific
/// diagnostics (`MCP_*`/`A2A_*`) are NOT here — each plane crate owns its consts and registers them
/// via [`install_diagnostics`]; the full runtime catalog is [`all`] (`REGISTRY ∪ installed`). The
/// tests assert uniqueness and class alignment over this neutral half; each plane crate asserts the
/// same over its own `DIAGNOSTICS`. There is no cross-half code collision because numbering was
/// preserved on the move.
pub static REGISTRY: &[&Diagnostic] = &[
    &DURABLE_WRITETHROUGH_BELOW_FLOOR,
    &DURABLE_SECOND_WRITER_DETACH,
    &DURABLE_AUDIT_RING_UNRECONCILED,
    &DURABLE_AUDIT_WRITETHROUGH_FAILED,
    &DURABLE_AUDIT_BACKFILL_GAP,
    &AUDIT_CHAIN_VERIFY_FAILED,
    &CONFIG_OVERLAY_NOT_WRITABLE,
    &CONFIG_OVERLAY_PROBE_LEAK,
    &CONFIG_OVERLAY_CORRUPT_REFUSE_WRITE,
    &CONFIG_OVERLAY_VERSION_TOO_NEW_RMW,
    &CONFIG_OVERLAY_CORRUPT_BASE_ONLY,
    &CONFIG_OVERLAY_VERSION_TOO_NEW,
    &CONFIG_OVERLAY_PATCH_UNPARSABLE,
    &CONFIG_ANTIDOWNGRADE_FLOOR_INVALID,
    &CONFIG_FIRSTPARTY_FLOOR_INVALID,
    &CONFIG_POOL_HETEROGENEOUS,
    &CONFIG_RATE_CARD_ALL_ZERO,
    &CONFIG_AUTH_CHAIN_FULL_SCOPE,
    &CONFIG_OPEN_ADMIN_MINT,
    &CONFIG_PASSTHROUGH_UNUSED_APIKEY,
    &TOKEN_EXCHANGE_MINT_FAILED,
    &LOGIN_OFFLOAD_SATURATED,
    &LOGIN_PLUGIN_PANICKED,
    &AUTH_CHAIN_OPEN_RELAY,
    &AUTH_OFFLOAD_SATURATED,
    &AUTH_CHAIN_PANICKED,
    &ADMIN_MODULE_UNRESOLVED,
    &ADMIN_OFFLOAD_SATURATED,
    &ADMIN_CHAIN_STALLED,
    &ADMIN_FORBIDDEN_SUPPRESSED,
    &KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
    &SELF_SUBJECT_UNSAFE,
    &EGRESS_APIKEY_INVALID_BYTES,
    &EGRESS_OAUTH_TOKEN_INVALID_BYTES,
    &EGRESS_OAUTH_EMPTY_TOKEN,
    &EGRESS_OAUTH_MINT_FAILED,
    &TRUST_SWEEP_NOT_ATTEMPTED,
    &TRUST_SWEEP_CONTACT_FAILED,
    &TRUST_UPSTREAM_DRIFTED,
    &TRUST_RECOVERY_HELD,
    &TRUST_REGISTRATION_SUSPENDED,
    &TRUST_SWEEP_PANICKED,
    &OAUTH_AS_SWEEP_FAILED,
    &SIGV4_HMAC_INIT_FAILED,
    &OAUTH_AS_EPHEMERAL_SIGNING_KEY,
    &USAGE_TAP_REASSEMBLY_CAP_EXCEEDED,
    &UPSTREAM_MIDSTREAM_TRANSPORT_ERROR,
    &UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR,
    &LANE_BREAKER_TRIPPED,
    &ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
    &ROUTING_POLICY_DEADLINE_EXCEEDED,
    &ON_ERROR_FALLBACK_ANSWERED,
    &ON_ERROR_FALLBACK_HOOK_FAILED,
    &ON_ERROR_FALLBACK_DEADLINE_EXCEEDED,
    &CROSSPROTO_NONSTREAM_MIDTRANSFER_FAILED,
    &CROSSPROTO_TRANSLATION_CAP_EXCEEDED,
    &CROSSPROTO_BINARY_CODEC_FAILED,
    &CROSSPROTO_JSON_CODEC_FAILED,
    &CROSSPROTO_RESPONSE_NOT_TRANSLATABLE_DEGRADED,
    &CROSSPROTO_RESPONSE_NOT_TRANSLATABLE,
    &REWRITE_GATE_REJECTED,
    &REWRITE_BODY_MATERIALIZE_FAILED,
    &REWRITE_RESERIALIZE_FAILED,
    &DECISION_GATE_REJECTED,
    &DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    &DECISION_GATE_RESTRICT_REJECT,
    &ROUTING_POLICY_REJECTED,
    &ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
    &ROUTING_POLICY_RESTRICT_REJECT,
    &ATTEMPT_TIMEOUT_FAILOVER,
    &LANE_HARD_DOWN,
    &USAGE_TAP_UNKNOWN_PROTOCOL,
    &USAGE_TAP_BAD_JSON,
    &USAGE_TAP_DECODE_FAILED,
    &ATTEMPT_TIMEOUT_DEGRADED,
    &FALLBACK_RESTRICT_NO_ELIGIBLE_LANE,
    &PROMETHEUS_RECORDER_INSTALL_FAILED,
    &METRICS_MAINTENANCE_THREAD_SPAWN_FAILED,
    &METRICS_SCRAPE_LIST_KEYS_FAILED,
    &METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
    &METRICS_SCRAPE_KEY_USAGE_READ_FAILED,
    &METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED,
    &PLUGINS_FETCH_RELOAD_MISS,
    &PLUGIN_SKIPPED_TRUST_POLICY,
    &PLUGIN_LOADED_UNVERIFIED,
    &STATEFUL_PLANE_EPHEMERAL_STORE,
    &REVOCATION_RESYNC_OUTSTANDING,
    &REVOCATION_RESYNC_FAILED,
    &GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION,
    &LIMIT_WINDOW_UNRECOGNIZED,
    &REFRESH_SELF_INCONSISTENT_BINDING,
    &REFRESH_SELF_CACHE_REFRESH_FAILED,
    &ACCRUAL_GROUP_MISSING,
    &METERING_FLUSH_PARTIAL_FAILURE,
    &METERING_PENDING_OVERFLOW_COALESCED,
    &DELETE_KEY_CACHE_RECONCILE_FAILED,
    &ROTATE_KEY_CACHE_RECONCILE_FAILED,
    &BUDGET_FLUSH_PARTIAL_FAILURE,
    &SAFE_MODE_OVERLAY_QUARANTINED,
    &PROVIDER_API_KEY_UNRESOLVED,
    &OPEN_RELAY_NO_AUTH,
    &STORE_SECRET_REF_UNRESOLVED,
    &GOVERNANCE_STORE_EPHEMERAL,
    &DURABLE_KEYS_INERT,
    &BOOT_AUDIT_RESTORE_READ_FAILED,
    &BOOT_AUDIT_MIGRATE_FAILED,
    &TLS_ACCEPT_PERSISTENT_FAILURE,
    &TELEMETRY_SLOT_TABLE_FULL,
    &EVENTSTREAM_EVENTTYPE_HEADER_OVERSIZE,
    &EVENTSTREAM_EXCEPTIONTYPE_HEADER_OVERSIZE,
    &EVENTSTREAM_FRAME_OVERSIZE,
    &PLANE_TASK_CHAIN_VERIFY_FAILED,
    &PLANE_CALLLOG_CHAIN_VERIFY_FAILED,
    &PLANE_AUDITLOG_CHAIN_VERIFY_FAILED,
    &PLANE_AUDITLOG_WRITE_FAILED,
    &PLANE_CALLLOG_ROW_UNREADABLE,
    &PLANE_JOURNAL_ROW_UNREADABLE,
    &PLANE_AUDIT_ROW_UNREADABLE,
    &WEBHOOK_EXPORTER_DISABLED,
    &WEBHOOK_DELIVERY_NON_2XX,
    &WEBHOOK_DELIVERY_TRANSPORT_ERROR,
    &FILE_LOG_APPEND_FAILED,
    &FILE_LOG_OPEN_FAILED,
    &FILE_LOG_RETENTION_FAILED,
    &FILE_LOG_SHIFT_FAILED,
    &FILE_LOG_ROTATE_RENAME_FAILED,
    &IR_CLAMP_N_TO_1,
    &IR_DROP_REASONING,
    &IR_DROP_PROMPT_CACHE,
    &IR_DROP_CACHE_CONTROL_OVER_CAP,
    &IR_DROP_HOSTED_TOOLS,
    &IR_DROP_MESSAGE_NAME,
    &IR_DROP_CACHED_CONTENT,
    &IR_DROP_UNMODELED_KEYS,
    &IR_TRUNCATE_STOP_SEQUENCES,
    &PROTO_AUTH_INVALID_HEADER_BYTES,
    &PROTO_DROP_PROVIDER_METADATA,
    &PLANE_TASK_ROW_UNREADABLE,
    &PLANE_SSRF_CALLBACK_AT_STORE,
    &APPROVAL_LEDGER_UNREACHABLE_REFUSED,
    &PLANE_CALLLOG_EMPTY_CHAIN,
    &PLANE_CALLLOG_WRITE_FAILED,
    &PLANE_DEMOTION_WRITE_FAILED,
    &PLANE_DEMOTION_CLEAR_FAILED,
    &PLANE_DEMOTIONS_UNREAD,
    &TRUST_VERIFY_REFUSED_ON_DRIFT,
    &TRUST_VERIFY_UNREACHABLE,
    &PLANE_TASK_ABANDON_UNRECORDED,
    &ADMIN_STORE_OPERATION_FAILED,
    &ADMIN_STORE_TASK_JOIN_FAILED,
    &GROUP_DELETE_KEY_READ_FAILED,
    &USAGE_BLOCKING_TASK_JOIN_FAILED,
    &ADMIN_AUTH_CHAIN_EMPTY,
    &ADMIN_CREATEKEY_MALFORMED_BODY,
    &CREATEKEY_UNKNOWN_POOL,
    &ADMIN_UPDATEKEY_MALFORMED_BODY,
    &PLANE_BREAKER_TRIPPED,
    &PLANE_BREAKER_HARD_DOWN,
    &LANE_HARD_DOWN_ALL_CELLS,
    &BREAKER_UNEXPECTED_STATE_CLASSIFY,
    &BREAKER_UNEXPECTED_STATE_PROBE,
    &BREAKER_UNEXPECTED_STATE_READ,
    &BREAKER_UNEXPECTED_STATE_RECORD_FAILURE,
    &PLUGINS_DIR_FINGERPRINT_FAILED,
    &PLUGIN_CATALOG_SCAN_GATE_TIMEOUT,
    &PLUGIN_CATALOG_BLOCKING_TASK_FAILED,
    &PLUGIN_ROLLBACK_PIN_PERSIST_FAILED,
    &PLUGIN_ROLLBACK_REVERT_FAILED,
    &CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE,
    &CLI_VALIDATE_CONFIG_INVALID,
    &CLI_LIST_PLUGINS_CONFIG_UNREADABLE,
    &CONFIG_SETTINGS_OVERLAY_UNREADABLE,
    &CONFIG_SETTINGS_OVERLAY_VERSION_TOO_NEW,
    &CONFIG_SETTINGS_READ_TASK_JOIN_FAILED,
    &METADATA_PROTECTION_DISABLED,
    &CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED,
    &CLI_LIST_PLUGINS_TRUST_INVALID,
    &GROUP_USAGE_READ_FAILED,
    &BOOT_FATAL_ERROR,
    &WORKER_THREADS_INVALID,
    &SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED,
    &JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE,
    &SIGNING_KEY_GENERATION_FAILED,
];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Doc generation — `docs/diagnostics.md` (human) and `docs/diagnostics.json` (machine).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Path of the committed markdown page, relative to the repo root (this crate is `crates/busbar-substrate`).
pub const COMMITTED_DIAGNOSTICS_MD: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.md");
/// Path of the committed machine-readable catalog.
pub const COMMITTED_DIAGNOSTICS_JSON: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");

/// Render the operator-facing markdown page for the NEUTRAL built-in catalog ([`REGISTRY`]). A plane
/// crate renders its own page from its `DIAGNOSTICS` via [`render_markdown_for`].
pub fn render_markdown() -> String {
    render_markdown_for(REGISTRY)
}

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

/// Render the machine-readable catalog for the NEUTRAL built-in catalog ([`REGISTRY`]). A plane
/// crate renders its own from its `DIAGNOSTICS` via [`render_json_for`].
pub fn render_json() -> String {
    render_json_for(REGISTRY)
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
