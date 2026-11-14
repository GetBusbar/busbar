// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The diagnostics catalog: every operator-facing `warn!`/`error!` carries a stable
//! `BUSBAR-NNNN` code an operator can paste into the docs and land on an entry that says what
//! it means, whether it needs action, and what to do.
//!
//! This module is the SINGLE SOURCE OF TRUTH (the "internal_errors" registry). Its entries are
//! the `diagnostics!` table below; each becomes a [`Diagnostic`] const, and [`REGISTRY`] collects
//! them all. The `docs/diagnostics.md` page and
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
pub mod pages;

#[cfg(test)]
#[path = "tests/pages_tests.rs"]
mod pages_tests;

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

/// Declares each built-in diagnostic as a `pub const` and lists them, in the table's order, in
/// [`REGISTRY`]. An entry is `NAME = code, Class, Severity, "slug", "since", retired,` then its
/// title, summary and action; `NAME in path;` re-exports a const defined at `path` instead.
macro_rules! diagnostics {
    ($($(#[$meta:meta])* $name:ident
        $(= $code:literal, $class:ident, $severity:ident, $slug:literal, $since:literal,
            $retired:literal, $title:literal, $summary:literal, $action:literal)?
        $(in $($segment:ident)::+)?;)*) => {
        $(
            $(#[$meta])*
            $(pub const $name: Diagnostic = Diagnostic {
                code: $code,
                class: Class::$class,
                slug: $slug,
                title: $title,
                severity: Severity::$severity,
                summary: $summary,
                action: $action,
                since: $since,
                retired: $retired,
            };)?
            $(pub use $($segment)::+::$name;)?
        )*
        /// The host's built-in diagnostics, in the table's order. Plane-contributed ones are not
        /// here: the composition root folds them into the [`Catalogue`] it lends, and the full
        /// runtime catalog is [`Catalogue::all`].
        pub static REGISTRY: &[&Diagnostic] = &[$(&$name,)*];
    };
}

// THE HOST DIAGNOSTICS CATALOG. Codes are `BUSBAR-NNNN`: the thousands digit is the class. They
// are append-only: a retired code keeps its number (`retired` is `true`). Add an entry anywhere
// (the rendered docs sort by code), then regenerate the docs:
// `UPDATE_DIAGNOSTICS=1 cargo test -p busbar catalogue_tests`.
diagnostics! {
    /// RETIRED in 1.6.0: operational environment overrides are migration input only.
    DEPRECATED_ENV_VAR_HONORED = 3021, Config, Actionable, "deprecated-env-var-honored", "1.5.0", true,
        "A deprecated environment variable is set and still honored — RETIRED",
        "RETIRED. Serving no longer applies deprecated operational environment overrides. Use --migrate-config with the old deployment environment and working directory to capture provider, worker and upstream HTTP settings; old file-overlay selection is migration input only.",
        "Run the 1.6 migration before serving, review and validate its output, then remove the retired variables from launchers. See docs/migration-1.6.md.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    DURABLE_WRITETHROUGH_BELOW_FLOOR = 1001, Durability, BenignRecurring, "durable-writethrough-below-floor", "1.6.0", true,
        "Durable audit write-through skipped (seq at or below the recovered floor) — RETIRED",
        "RETIRED. Nothing emits this code: the durable audit log is the journal-backed audit log, whose write, read-back and chain failures report as BUSBAR-2044, BUSBAR-2047 and BUSBAR-2043.",
        "Nothing emits this code. See BUSBAR-2044.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    DURABLE_SECOND_WRITER_DETACH = 1002, Durability, Actionable, "durable-second-writer-detach", "1.6.0", true,
        "Durable audit log has another writer — this node detached its durable sink — RETIRED",
        "RETIRED. Nothing emits this code: the durable audit log is the journal-backed audit log, whose write, read-back and chain failures report as BUSBAR-2044, BUSBAR-2047 and BUSBAR-2043.",
        "Nothing emits this code. See BUSBAR-2044.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    DURABLE_AUDIT_RING_UNRECONCILED = 1003, Durability, Actionable, "durable-audit-ring-unreconciled", "1.6.0", true,
        "Durable audit write-through held — ring not yet reconciled with the durable tail — RETIRED",
        "RETIRED. Nothing emits this code: the durable audit log is the journal-backed audit log, whose write, read-back and chain failures report as BUSBAR-2044, BUSBAR-2047 and BUSBAR-2043.",
        "Nothing emits this code. See BUSBAR-2044.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    DURABLE_AUDIT_WRITETHROUGH_FAILED = 1004, Durability, Actionable, "durable-audit-writethrough-failed", "1.6.0", true,
        "Durable audit write-through failed (entry retained in the in-memory ring) — RETIRED",
        "RETIRED. Nothing emits this code: the durable audit log is the journal-backed audit log, whose write, read-back and chain failures report as BUSBAR-2044, BUSBAR-2047 and BUSBAR-2043.",
        "Nothing emits this code. See BUSBAR-2044.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    DURABLE_AUDIT_BACKFILL_GAP = 1005, Durability, Actionable, "durable-audit-backfill-gap", "1.6.0", true,
        "Durable audit chain has an unrepairable gap (a seq was pruned before it persisted) — RETIRED",
        "RETIRED. Nothing emits this code: the durable audit log is the journal-backed audit log, whose write, read-back and chain failures report as BUSBAR-2044, BUSBAR-2047 and BUSBAR-2043.",
        "Nothing emits this code. See BUSBAR-2044.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    AUDIT_CHAIN_VERIFY_FAILED = 2001, Audit, Actionable, "audit-chain-verify-failed", "1.6.0", true,
        "Durable audit chain failed hash-chain verification at boot (tamper evidence) — RETIRED",
        "RETIRED. Nothing emits this code: a durable audit log that fails hash-chain verification reports as BUSBAR-2043.",
        "Nothing emits this code. See BUSBAR-2043.";

    /// A read-modify-write apply found the overlay unreadable/corrupt; refuses to overwrite it.
    CONFIG_OVERLAY_CORRUPT_REFUSE_WRITE = 3003, Config, Actionable, "config-overlay-corrupt-refuse-write", "1.6.0", false,
        "Config overlay unreadable/corrupt on apply (refusing to overwrite)",
        "An admin apply tried to read-modify-write the config overlay but found the existing overlay present yet unreadable/corrupt, so busbar REFUSED to overwrite it — a blind overwrite would drop the hook AND group deletion tombstones every section carries and could resurrect a deleted item. This apply was NOT persisted.",
        "Fix or remove the corrupt overlay file to restore durability, then re-apply. Until then admin config mutations cannot be persisted (they are refused, not silently lost).";

    /// A read-modify-write apply found the overlay written by a NEWER busbar; refuses to overwrite it.
    CONFIG_OVERLAY_VERSION_TOO_NEW_RMW = 3004, Config, Actionable, "config-overlay-version-too-new-rmw", "1.6.0", false,
        "Config overlay written by a newer busbar on apply (refusing to overwrite)",
        "An admin apply found the config overlay was written by a NEWER busbar than this binary, so busbar REFUSED to overwrite it: this binary cannot represent everything the newer overlay holds, and a write would silently discard whatever it does not understand. This apply was NOT persisted.",
        "Apply config mutations from a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands. This binary serves on the overlay it can read but cannot persist changes to it.";

    /// At boot the overlay is present but corrupt; busbar starts on base config.yaml alone.
    CONFIG_OVERLAY_CORRUPT_BASE_ONLY = 3005, Config, Actionable, "config-overlay-corrupt-base-only", "1.6.0", false,
        "Config overlay corrupt at boot (starting on base config.yaml alone)",
        "At boot the config overlay is present but unreadable/corrupt, so busbar fails soft and starts on the base config.yaml ALONE — API-applied hooks (INCLUDING security GATES that enforce admission control), groups, and plugin version pins are NOT restored. Any gate registered only via the admin API is now ABSENT until re-applied. busbar never bricks boot on a corrupt overlay, but it must not disarm those gates silently.",
        "Fix or remove the corrupt overlay file to restore durability, then restart so the API-applied hooks and gates are re-loaded. Until then, re-apply any admin-API gates the deployment depends on, or run on base config.yaml deliberately.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    CONFIG_OVERLAY_REJECTED = 3023, Config, Actionable, "config-overlay-rejected", "1.6.0", true,
        "Config overlay rejected at read (the reason, naming the key and the file) — RETIRED",
        "RETIRED. Nothing emits this code: an unreadable overlay reports as BUSBAR-3005 at boot and BUSBAR-3017 on the settings read.",
        "Nothing emits this code. See BUSBAR-3005 and BUSBAR-3017.";

    /// At boot the overlay was written by a NEWER busbar; the boot caller refuses to start (fatal).
    CONFIG_OVERLAY_VERSION_TOO_NEW = 3006, Config, Fatal, "config-overlay-version-too-new", "1.6.0", false,
        "Config overlay written by a newer busbar (boot refuses to start)",
        "At boot the config overlay is intact and meaningful but was written by a NEWER busbar than this one. Ignoring it would run without hooks and groups the operator believes are persisted — security gates included — so the boot caller REFUSES to start rather than silently disarm them.",
        "Boot a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands. This is a deliberate boot refusal, not a crash — resolve the version mismatch and restart.";

    /// An overlay patch does not parse against this binary's structs; the entry is dropped whole.
    CONFIG_OVERLAY_PATCH_UNPARSABLE = 3007, Config, Actionable, "config-overlay-patch-unparsable", "1.6.0", false,
        "Config overlay patch does not parse (entry not applied)",
        "The config overlay holds a named-map patch that, merged against base config, does not produce a definition this binary can parse (it faces the same typed `deny_unknown_fields` parse config.yaml does). busbar drops the entry WHOLE rather than half-apply it, so that named definition is never applied and sits inert in the overlay.",
        "Edit or remove the offending overlay entry (the log names the section and entry), then reload. The operator's stored data is untouched; the entry is simply not applied until it parses.";

    /// A plugins.min_versions anti-downgrade floor is not valid semver; the control is disarmed.
    CONFIG_ANTIDOWNGRADE_FLOOR_INVALID = 3008, Config, Actionable, "config-antidowngrade-floor-invalid", "1.6.0", false,
        "plugins.min_versions floor is not valid semver (anti-downgrade disarmed)",
        "A `plugins.min_versions` anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (e.g. a stray leading `v`). It cannot be satisfied, so the floored plugin is refused, and — more subtly — an operator who believes the anti-downgrade control is armed does not get the protection they configured.",
        "Fix or remove the named `plugins.min_versions` entry so the floor is a bare MAJOR.MINOR.PATCH version. Until then that plugin is refused and the anti-downgrade floor for it is effectively disarmed.";

    /// A plugins.first_party_floors floor is not valid semver; the plugin is refused unconditionally.
    CONFIG_FIRSTPARTY_FLOOR_INVALID = 3009, Config, Actionable, "config-firstparty-floor-invalid", "1.6.0", false,
        "plugins.first_party_floors floor is not valid semver (plugin refused unconditionally)",
        "A `plugins.first_party_floors` floor is not a valid MAJOR.MINOR.PATCH version. It cannot be satisfied, and because a first-party floor REPLACES the binary-version floor, the named plugin is refused UNCONDITIONALLY until this is fixed — a stricter failure than an invalid `min_versions` floor.",
        "Fix or remove the named `plugins.first_party_floors` entry so the floor is a bare MAJOR.MINOR.PATCH version. Until then that first-party plugin is refused on every boot.";

    /// A pool mixes upstream protocols; cross-protocol failover translates via the IR and may lose features.
    CONFIG_POOL_HETEROGENEOUS = 3010, Config, Actionable, "config-pool-heterogeneous", "1.6.0", false,
        "Heterogeneous pool (cross-protocol failover may not preserve all features)",
        "A pool's members span more than one upstream protocol, so cross-protocol failover within the pool translates requests and replies via busbar's internal representation (IR) and may not preserve every provider-specific feature. Advisory: the pool is valid and serves, but mixed protocols carry a fidelity caveat.",
        "None required if intentional. If a feature is being lost across failover, split the pool so each pool is single-protocol, keeping cross-protocol members in a fallback tier rather than the same failover pool.";

    /// A rate_card entry prices a model at all-zero across every tier: it meters as FREE and uncapped.
    CONFIG_RATE_CARD_ALL_ZERO = 3020, Config, Actionable, "config-rate-card-all-zero", "1.6.0", false,
        "rate_card entry prices a model at ALL ZERO (metered as free, uncapped)",
        "A model has a `rate_card` entry present but every tier (input, output, cache_read, cache_write) is zero, so its token usage prices to $0: budget-group `budget:` limits never accrue token cost against it and it is effectively uncapped on spend. This is LEGAL (a deliberately free model is a valid choice, e.g. a self-hosted lane), so it is a WARNING, not a boot error — but an accidental all-zero entry (a paste of the completeness stub left unfilled) silently under-bills every request to that model.",
        "If the model is intentionally free, ignore this. Otherwise fill in the model's `rate_card` rates (micro-units per token) so its usage prices and counts against any `budget:` limit.";

    /// A configured lane lacks rates for declared billable classes; startup continues with a warning.
    CONFIG_RATE_CARD_MISSING = 3026, Config, Actionable, "config-rate-card-missing", "1.6.0", false,
        "Declared billable classes have no configured rate",
        "A plugin declares billable classes for a configured lane, but that lane lacks one or more rates. Startup continues and raw counts remain available. With a present card, missing classes remain unpriced; a rate on another lane does not price them. With no card for the plane, usage-based pricing is disabled. An explicit zero rate is a configured free class, not a missing rate. Class-parent relationships are reporting and cap projections, not inherited prices.",
        "Configure the named lane and classes in the plane's rate_card. Use an explicit zero only for deliberately free usage. Invalid rates, unknown class names and other structural mistakes still prevent startup.";

    /// A provider URL names a private or loopback host the destination guard refuses (1.5.5 upgrade).
    CONFIG_PROVIDER_DESTINATION_REFUSED = 3025, Config, Actionable, "config-provider-destination-refused", "1.6.0", false,
        "A provider URL names a private or loopback host the destination guard refuses",
        "A provider's `base_url` or `token_url` names a private or loopback address (an RFC 1918, loopback, link-local, CGNAT or unique-local literal, or the `localhost` name), and `advanced.block_private_addresses` is on (the default) and `advanced.allow_destinations` does not name it. The destination guard refuses every request to it, so the provider would fail on its first request rather than at startup. 1.5.5 had no such guard. Emitted once per URL at config load, naming the provider, the key and the host.",
        "Add exactly that host to `advanced.allow_destinations` (`busbar --migrate-config` adds the hosts a provider's plane reports), or point the provider at a public address. Turning `block_private_addresses` off also admits it, and every other private address with it.";

    /// RETIRED: a metadata host-list entry that names no host is refused at startup, not warned about.
    CONFIG_METADATA_ENTRY_NAMES_NO_HOST = 3024, Config, Actionable, "config-metadata-entry-names-no-host", "1.6.0", true,
        "A metadata host-list entry names no host (it matches nothing and is dropped) — RETIRED",
        "RETIRED. Nothing emits this code: a metadata host-list entry that names no host is refused at startup by config validation, naming the key and the entry.",
        "Nothing emits this code. Fix the entry config validation names.";

    /// An auth chain entry grants max_admin_scope: full — principals it identifies hold full admin.
    CONFIG_AUTH_CHAIN_FULL_SCOPE = 3011, Config, Actionable, "config-auth-chain-full-scope", "1.6.0", false,
        "auth.chain entry grants max_admin_scope: full",
        "An auth chain entry sets `max_admin_scope: full`, so every principal identified by that module can hold FULL admin authority — the default ceiling is read-only. A security advisory: a compromised or over-broad identity source behind that module becomes an admin-authority source.",
        "Confirm the named module's chain is trusted end to end and that granting full admin to everyone it identifies is intended. Lower `max_admin_scope` (or scope the module's principals) if full admin is broader than needed.";

    /// auth.chain names `keys` and auth.admin_auth is explicitly empty — anyone can mint keys.
    CONFIG_OPEN_ADMIN_MINT = 3012, Config, Actionable, "config-open-admin-mint", "1.6.0", false,
        "auth.chain names `keys` with an empty admin_auth (anyone can mint virtual keys)",
        "The auth chain names the built-in `keys` verifier while `auth.admin_auth` is explicitly empty, so the admin API has no credential gating it — ANYONE can mint virtual keys through it. Acceptable only for local development.",
        "Configure `auth.admin_auth` (an admin credential entry, or an admin module granting `mint`/`full`) before exposing busbar's admin API to any untrusted network, so key minting is gated by an operator credential.";

    /// upstream_credentials: passthrough with a non-empty configured api_key on a provider; key is inert.
    CONFIG_PASSTHROUGH_UNUSED_APIKEY = 3013, Config, Actionable, "config-passthrough-unused-apikey", "1.6.0", false,
        "passthrough provider has a non-empty api_key that is never forwarded (inert config)",
        "A provider is configured with a NON-EMPTY api_key while `upstream_credentials` is `passthrough`, under which the upstream key is the caller's own token (or empty), so the configured api_key is NEVER forwarded — it is inert dead config. A legitimate passthrough provider may itself sign each request and need no static key, hence a warning rather than a hard reject.",
        "If you intended static-key gating, use `upstream_credentials: own` (plus an auth chain). Otherwise clear the referenced provider secret so the config reflects that no static key is used on that passthrough provider.";

    /// Token-exchange could not mint a self-serve key — a keystore/HMAC fault, not a client error.
    TOKEN_EXCHANGE_MINT_FAILED = 4001, Auth, Actionable, "token-exchange-mint-failed", "1.6.0", false,
        "Token-exchange could not mint a self-serve key",
        "An authenticated, authorized token-exchange request could not be completed because minting the self-serve key failed inside busbar (a keystore write or HMAC/signing fault), so the caller receives a 500. The identity was valid; the failure is on busbar's side, not the client's.",
        "Investigate the keystore / signing subsystem — check disk, permissions, and the key-derivation secret. The condition is rare; capture the logged detail and file a bug if it recurs.";

    /// A login plugin is not returning, so its offload permit could not be acquired. Warn-once (latched).
    LOGIN_OFFLOAD_SATURATED = 4002, Auth, Actionable, "login-offload-saturated", "1.6.0", false,
        "Login plugin offload saturated (permit not acquired; login rejected fail-closed)",
        "A login-plugin call could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — a login plugin is wedged and not returning. busbar rejects the login fail-closed rather than complete a login it never ran. Warned once on entry to the saturated state; recurrence logs at debug.",
        "Investigate the login plugin (its directory bind or identity-provider round-trip) — it is blocking past its timeout. Restore or restart it; the saturation clears once calls return within budget.";

    /// A login plugin's blocking call panicked; the login is rejected fail-closed.
    LOGIN_PLUGIN_PANICKED = 4003, Auth, Actionable, "login-plugin-panicked", "1.6.0", false,
        "Login plugin call panicked (login rejected fail-closed)",
        "A login plugin's blocking call panicked (the offloaded task returned a join error), so busbar rejects the login fail-closed rather than complete a login it never verified. A panicking plugin is a plugin bug.",
        "Fix the login plugin — a panic on the login path is a bug in that plugin. Capture the logged method/op context and the plugin's own logs; logins via that method fail until it is corrected.";

    /// The auth chain is empty (open relay) — acceptable only in dev. Boot-time config warning.
    AUTH_CHAIN_OPEN_RELAY = 4004, Auth, Actionable, "auth-chain-open-relay", "1.6.0", false,
        "auth.chain is empty (open relay)",
        "The auth chain was built with no verifiers and no keys-in-chain, so every data-plane request is admitted unauthenticated — an OPEN RELAY. This is acceptable only for local development. Emitted once when the chain is built.",
        "Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. An open relay in production forwards anyone's traffic on your upstream credentials.";

    /// An auth plugin is not returning, so the chain offload permit could not be acquired. Warn-once.
    AUTH_OFFLOAD_SATURATED = 4005, Auth, Actionable, "auth-offload-saturated", "1.6.0", false,
        "Auth chain offload saturated (permit not acquired; request denied fail-closed)",
        "The auth chain could not obtain a blocking-offload permit within the wait window because the offload budget is fully in flight — an auth plugin is wedged and not returning. The chain never ran, so the credential is unverified and busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.",
        "Investigate the auth plugin — it is blocking past its timeout and starving the offload budget. Restore or restart it; the saturation clears once chain calls return within budget.";

    /// The auth chain's blocking task panicked; the request is denied fail-closed. Warn-once (latched).
    AUTH_CHAIN_PANICKED = 4006, Auth, Actionable, "auth-chain-panicked", "1.6.0", false,
        "Auth chain panicked (request denied fail-closed)",
        "The auth chain's blocking task panicked, so busbar denies the request fail-closed rather than admit an unverified credential. A panicking chain is a plugin bug. Warned once on entry to the panicking state; recurrence logs at debug.",
        "Fix the auth plugin — a panic in the chain is a bug in one of its modules. Capture the logged error and the plugin's own logs; requests are denied until it is corrected.";

    /// admin_auth names a module with no resolved plugin — a post-boot invariant breach.
    ADMIN_MODULE_UNRESOLVED = 4007, Auth, Actionable, "admin-module-unresolved", "1.6.0", false,
        "admin_auth names a module with no resolved plugin",
        "The admin auth chain named a module that has no resolved plugin, and busbar skipped it fail-closed. This is supposed to be impossible after a successful boot — `AdminAuthChain::build` fails closed on any unresolvable name — so reaching it means the admin-module table drifted from the configured chain.",
        "Investigate the admin auth configuration and plugin load state; a named admin module is missing at runtime. Restart busbar so boot re-resolves the chain, and file a bug with the logged module name if it persists.";

    /// An admin auth plugin is not returning; the admin offload permit could not be acquired. Warn-once.
    ADMIN_OFFLOAD_SATURATED = 4008, Auth, Actionable, "admin-offload-saturated", "1.6.0", false,
        "Admin auth offload saturated (permit not acquired; request denied fail-closed)",
        "The admin auth chain could not obtain a blocking-offload permit within the wait window because the admin offload budget is fully in flight — an admin auth plugin is wedged and not returning. The chain never ran, so busbar denies fail-closed. Warned once on entry to the saturated state; recurrence logs at debug.",
        "Investigate the admin auth plugin — it is blocking past its timeout. Restore or restart it; admin access is denied until admin-chain calls return within budget.";

    /// The admin auth chain did not complete within its deadline (or panicked); denied. Warn-once.
    ADMIN_CHAIN_STALLED = 4009, Auth, Actionable, "admin-chain-stalled", "1.6.0", false,
        "Admin auth chain did not complete in time (request denied fail-closed)",
        "The admin auth chain's offloaded task did not complete within its deadline, or it panicked, so busbar denies the admin request fail-closed rather than admit an unverified operator. Warned once on entry to the stalled state; recurrence logs at debug.",
        "Investigate the admin auth plugin — it is slow or crashing on the admin path. Restore or restart it; admin access is denied until the chain completes within its deadline.";

    /// An admin request was forbidden but its audit record was suppressed (already recorded this window).
    ADMIN_FORBIDDEN_SUPPRESSED = 4010, Auth, BenignRecurring, "admin-forbidden-suppressed", "1.6.0", false,
        "Admin request forbidden (audit record suppressed this window)",
        "An admin request was forbidden (insufficient scope for the path), and a durable audit record for it was suppressed because one was already written for this principal in the current rate window. This is a per-request signal of a CLIENT-side authorization failure, not an operator problem, so it is emitted at debug to avoid log spam under a client that keeps retrying a forbidden call.",
        "None — self-heals; the client is being correctly refused. Persistent volume from one principal indicates a misconfigured client or a probe; the durable audit chain already carries the first occurrence per window.";

    /// `keys` in the auth chain configured alongside upstream_credentials: passthrough. Warn-once (latched).
    KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT = 4011, Auth, Actionable, "keys-in-chain-passthrough-conflict", "1.6.0", false,
        "auth.chain names `keys` alongside upstream_credentials: passthrough",
        "The auth chain names the `keys` verifier while `upstream_credentials` is set to `passthrough`. keys-in-chain requires a valid virtual key on every request and supersedes passthrough's accept-and-forward-the-caller-credential intent, so passthrough never takes effect. Warned once at first request.",
        "Resolve the config conflict: use `upstream_credentials: own` (or omit it) alongside `keys`, or drop `keys` from the chain if you genuinely want to forward caller credentials. The two settings are mutually exclusive.";

    /// A client presented a principal id unsafe to use as a self-serve subject — a client error.
    SELF_SUBJECT_UNSAFE = 4012, Auth, BenignRecurring, "self-subject-unsafe", "1.6.0", false,
        "Token-exchange refused an unsafe self-serve subject",
        "A token-exchange request presented a principal id that is unsafe as a self-serve subject — empty, containing a '/' route separator or a control character, or carrying a reserved `vk_`/`user:`/`group:` prefix — so busbar refused it with a 403. This is a CLIENT-supplied bad value, not an operator problem, so it is emitted at debug to avoid spam from a misbehaving client.",
        "None — self-heals; the client must present a valid subject id. If a legitimate identity is being rejected, its id needs to be reshaped to avoid the reserved prefixes and separators.";

    /// A configured egress API key contains bytes invalid for a header value: the auth plugin that presents a static header omits it and raises this code, at warn, on each request it meets.
    EGRESS_APIKEY_INVALID_BYTES = 4013, Auth, Actionable, "egress-apikey-invalid-bytes", "1.6.0", false,
        "Egress API key contains invalid header bytes (auth header omitted)",
        "A configured static egress credential contains bytes that are invalid in a header value (an ASCII control character, such as a trailing newline), so the auth plugin omits the auth header and the upstream rejects the request with 401. It is raised on each request that would have carried the header.",
        "Fix the credential's configured value: strip the control character (often a trailing newline in the secret's source). Egress to that upstream 401s until it is fixed.";

    /// A minted token contains bytes invalid for a header value: the auth plugin that mints it omits the header and raises this code, at warn, when such a token is minted.
    EGRESS_OAUTH_TOKEN_INVALID_BYTES = 4014, Auth, Actionable, "egress-oauth-token-invalid-bytes", "1.6.0", false,
        "Minted OAuth token contains invalid header bytes (auth header omitted)",
        "A token minted for egress contains bytes invalid in a header value, so the `Bearer` auth header is omitted and the upstream rejects the request with 401. It is raised when such a token is minted.",
        "Investigate the token endpoint: a minted token with a control character in it is malformed. Egress to that upstream 401s until a well-formed token is minted.";

    /// The OAuth token endpoint returned a 200 with an empty access_token. Warn-once (latched).
    EGRESS_OAUTH_EMPTY_TOKEN = 4015, Auth, Actionable, "egress-oauth-empty-token", "1.6.0", false,
        "OAuth token endpoint returned a 200 with an empty access_token",
        "The upstream OAuth token endpoint answered 200 but with an EMPTY access_token. busbar treats it as a (retryable) mint failure rather than storing it, because an empty token collides with the pre-first-mint sentinel and would wedge the lane permanently. It retries on the refresh cadence.",
        "Investigate the OAuth token endpoint / client-credentials configuration — a 200 with no token usually means a misconfigured client, scope, or audience. Egress to that upstream 401s until a non-empty token is minted.";

    /// An OAuth token mint (background refresh) failed; busbar keeps the current token and retries.
    EGRESS_OAUTH_MINT_FAILED = 4016, Auth, Actionable, "egress-oauth-mint-failed", "1.6.0", false,
        "OAuth token mint (refresh) failed; retrying",
        "The background OAuth token refresh failed to mint a new token. busbar keeps serving the current token and retries soon; if retries keep failing past expiry, egress requests carry a stale/empty token and the upstream 401s. Fires on the refresh cadence, not per request.",
        "Investigate the OAuth token endpoint — a transient outage self-heals on the next retry; sustained failures mean a credential/endpoint/network problem that will 401 egress once the current token expires.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    TRUST_SWEEP_NOT_ATTEMPTED = 4017, Auth, Actionable, "trust-sweep-not-attempted", "1.6.0", true,
        "Scheduled trust sweep could not be attempted (registration not contacted) — RETIRED",
        "RETIRED. Nothing emits this code: the trust book demotes a drifted counterparty and clears it without logging a code.",
        "Nothing emits this code.";

    /// RETIRED: nothing emits it, and no anomaly breaker counts a failed contact. The number is kept so an operator's old logs stay resolvable.
    TRUST_SWEEP_CONTACT_FAILED = 4018, Auth, Actionable, "trust-sweep-contact-failed", "1.6.0", true,
        "Scheduled trust sweep could not authenticate the upstream (failed contact recorded) — RETIRED",
        "RETIRED. Nothing emits this code, and no anomaly breaker counts a failed contact toward suspension (there is none). A registration stops serving only on a drift or an operator's suspension.",
        "Nothing emits this code.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    TRUST_UPSTREAM_DRIFTED = 4019, Auth, Actionable, "trust-upstream-drifted", "1.6.0", true,
        "Upstream drifted from the approved pin (registration demoted) — RETIRED",
        "RETIRED. Nothing emits this code: the trust book demotes a drifted counterparty and clears it without logging a code.",
        "Nothing emits this code.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    TRUST_RECOVERY_HELD = 4020, Auth, BenignRecurring, "trust-recovery-held", "1.6.0", true,
        "Clean trust observation held (recovery backoff not yet elapsed) — RETIRED",
        "RETIRED. Nothing emits this code: the trust book demotes a drifted counterparty and clears it without logging a code.",
        "Nothing emits this code.";

    /// RETIRED: no anomaly breaker suspends a trust registration (the one that was to raise this was never armed and is deleted). The number is kept so an operator's old logs stay resolvable.
    TRUST_REGISTRATION_SUSPENDED = 4021, Auth, Actionable, "trust-registration-suspended", "1.6.0", true,
        "Anomaly breaker suspended a trust registration — RETIRED",
        "RETIRED. Nothing emits this code: no anomaly breaker suspends a trust registration. The one breaker that was to raise it was never armed (no configuration set its thresholds) and is deleted, so a registration stops serving only on a drift or an operator's suspension.",
        "Nothing emits this code.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    TRUST_SWEEP_PANICKED = 4022, Auth, Actionable, "trust-sweep-panicked", "1.6.0", true,
        "Scheduled trust sweep panicked (job continues) — RETIRED",
        "RETIRED. Nothing emits this code: the trust book demotes a drifted counterparty and clears it without logging a code.",
        "Nothing emits this code.";

    /// oauth_as expired-record sweep failed; retried on the next tick. Warn-once (latched, transition-only).
    OAUTH_AS_SWEEP_FAILED = 4023, Auth, BenignRecurring, "oauth-as-sweep-failed", "1.6.0", false,
        "oauth_as expired-record sweep failed (retrying next tick)",
        "The oauth_as authorization-server sweep of expired records failed for a tick — typically a transient store hiccup — so busbar retries on the next tick. Expired records simply linger until a sweep succeeds. Warned once on entry to the failing state; recurrence logs at debug so a persistent store problem cannot spam.",
        "None if it clears on the next tick. Sustained failures indicate an oauth_as store problem worth investigating; expired records accumulate until a sweep succeeds.";

    /// HMAC-SHA256 init failed during request signing — RETIRED: request signing left the host, and no plugin raises this code. The number is kept so a log line from a pre-release build still resolves.
    REQUEST_SIGNING_HMAC_INIT_FAILED = 4024, Auth, Actionable, "request-signing-hmac-init-failed", "1.6.0", true,
        "Request-signing HMAC-SHA256 init failed — RETIRED",
        "RETIRED. Initializing HMAC-SHA256 for per-request egress signing failed, which was documented as unreachable (HMAC-SHA256 accepts a key of any length). Request signing is no longer the host's, and nothing raises this code.",
        "Nothing emits this code.";

    /// oauth_as has no configured signing_key, so an EPHEMERAL ES256 key was generated at boot. Lives in `appbuild.rs`, but the subject is auth & identity (token signing), so it is a 4000 code.
    OAUTH_AS_EPHEMERAL_SIGNING_KEY = 4025, Auth, Actionable, "oauth-as-ephemeral-signing-key", "1.6.0", false,
        "oauth_as generated an ephemeral ES256 signing key (tokens die on restart)",
        "The oauth_as authorization server has no `signing_key` configured, so busbar generated an EPHEMERAL ES256 key at boot. Every token this deployment issues is signed with that in-memory key and stops verifying the moment the process restarts, because a new key is generated on the next boot. Acceptable only for a trial or local development.",
        "Set `oauth_as.signing_key` to a durable key reference before relying on issued tokens across restarts. Until then, every restart invalidates all outstanding oauth_as tokens.";

    /// A routing-policy hook errored; the pool's `on_error` fallback was applied. Warn-once (latched).
    ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK = 5005, Proxy, Actionable, "routing-policy-failed-on-error-fallback", "1.6.0", false,
        "Routing policy failed; on_error fallback applied",
        "A routing-policy hook returned an ERROR while deciding a request, so busbar applied the pool's configured `on_error` fallback. A hook binary that is down, crashing, or returning garbage degrades every request in the pool to the fallback. Warned once per fault window; continued failures log at debug.",
        "Fix the routing-policy hook — check that its process is running, reachable, and returning a valid decision. The pool serves via `on_error` until it recovers.";

    /// A routing-policy hook exceeded its deadline; the `on_error` fallback was applied. Warn-once.
    ROUTING_POLICY_DEADLINE_EXCEEDED = 5006, Proxy, Actionable, "routing-policy-deadline-exceeded", "1.6.0", false,
        "Routing policy deadline exceeded; on_error fallback applied",
        "A routing-policy hook did not answer within the seam's hard wall-clock deadline, so busbar applied the pool's `on_error` fallback. A slow hook adds latency to every request in the pool. Warned once per fault window; continued timeouts log at debug.",
        "Investigate why the routing-policy hook is slow (overload, blocking I/O, an undersized deadline). Tune the hook or raise its configured timeout if the latency is legitimate.";

    /// An `on_error` fallback hook answered for a failed gate — a recovery signal.
    ON_ERROR_FALLBACK_ANSWERED = 5007, Proxy, BenignRecurring, "on-error-fallback-answered", "1.6.0", false,
        "on_error fallback hook answered for the failed gate",
        "After a routing gate failed, one of its configured `on_error` fallback hooks answered and decided the request. This is a RECOVERY signal: the fallback chain did its job.",
        "None — informational. The paired gate-failure diagnostic (BUSBAR-5005/5006) names the primary hook to fix.";

    /// An `on_error` fallback hook itself failed; the chain continued. Warn-once (latched).
    ON_ERROR_FALLBACK_HOOK_FAILED = 5008, Proxy, Actionable, "on-error-fallback-hook-failed", "1.6.0", false,
        "on_error fallback hook failed; continuing down the chain",
        "An `on_error` fallback hook itself returned an error, so busbar continued down the fallback chain to the next link (or the reserved terminal). The fallback chain meant to cover a broken primary is itself partly broken. Warned once per fault window.",
        "Fix the failing fallback hook. The request is still served by a later chain link or the terminal policy, but the chain has less depth than configured.";

    /// An `on_error` fallback hook exceeded its deadline; the chain continued. Warn-once (latched).
    ON_ERROR_FALLBACK_DEADLINE_EXCEEDED = 5009, Proxy, Actionable, "on-error-fallback-deadline-exceeded", "1.6.0", false,
        "on_error fallback hook deadline exceeded; continuing down the chain",
        "An `on_error` fallback hook exceeded its deadline, so busbar continued down the fallback chain. Warned once per fault window; continued timeouts log at debug.",
        "Investigate why the fallback hook is slow, or raise its timeout if the latency is expected. The chain still resolves via a later link or the terminal policy.";

    /// A decision-gate hook rejected the request. Normal policy enforcement.
    DECISION_GATE_REJECTED = 5019, Proxy, BenignRecurring, "decision-gate-rejected", "1.6.0", false,
        "Decision gate rejected the request",
        "A decision-gate hook rejected the request; busbar returns the gate's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.",
        "None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.";

    /// A decision gate's restrict left no eligible lane; on_empty weighted escape.
    DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE = 5020, Proxy, BenignRecurring, "decision-gate-restrict-weighted-escape", "1.6.0", false,
        "Decision gate restrict left no eligible lane; on_empty: weighted escape",
        "A decision gate's restrict left no eligible lane, and its `on_empty` policy is `weighted`, so busbar skips that restriction and falls back to weighted selection across the full pool. Normal advisory-restrict behavior.",
        "None — self-heals per request. If the restriction should be enforced strictly, set its `on_empty` to reject.";

    /// A decision gate's restrict left no eligible lane; on_empty reject (fail-closed).
    DECISION_GATE_RESTRICT_REJECT = 5021, Proxy, BenignRecurring, "decision-gate-restrict-reject", "1.6.0", false,
        "Decision gate restrict left no eligible lane (on_empty: reject)",
        "A decision gate's restrict left no eligible lane and its `on_empty` policy is reject (fail-closed), so busbar rejects the request rather than route to an ineligible lane. This is the correct compliance behavior.",
        "None — self-heals per request; the counters carry the volume. If rejections are unexpected, review the pool membership tags against the restrict's required tags.";

    /// A routing-policy hook rejected the request. Normal policy enforcement.
    ROUTING_POLICY_REJECTED = 5022, Proxy, BenignRecurring, "routing-policy-rejected", "1.6.0", false,
        "Routing policy rejected the request",
        "A routing-policy hook rejected the request; busbar returns the policy's clamped status and sanitized message in the client's native envelope. Normal policy enforcement.",
        "None — self-heals per request; the ROUTE_POLICY rejection counters carry the volume.";

    /// A routing policy's restrict left no eligible lane; on_empty weighted escape.
    ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE = 5023, Proxy, BenignRecurring, "routing-policy-restrict-weighted-escape", "1.6.0", false,
        "Routing policy restrict left no eligible lane; on_empty: weighted escape",
        "A routing policy's restrict left no eligible lane and its `on_empty` is `weighted`, so busbar escapes to full-pool weighted selection. Normal advisory-restrict behavior.",
        "None — self-heals per request. Set `on_empty` to reject if the restriction must be enforced strictly.";

    /// A routing policy's restrict left no eligible lane; on_empty reject (fail-closed).
    ROUTING_POLICY_RESTRICT_REJECT = 5024, Proxy, BenignRecurring, "routing-policy-restrict-reject", "1.6.0", false,
        "Routing policy restrict left no eligible lane (on_empty: reject)",
        "A routing policy's restrict left no eligible lane and its `on_empty` is reject (fail-closed), so busbar rejects the request rather than route to an ineligible upstream. Correct compliance behavior.",
        "None — self-heals per request. If unexpected, review pool membership tags against the restrict's required tags.";

    /// A lane's breaker is hard-down on its fresh logical trip. Warn-once (latched).
    LANE_HARD_DOWN = 5026, Proxy, BenignRecurring, "lane-hard-down", "1.6.0", false,
        "Lane hard-down (breaker trip)",
        "A lane's circuit breaker is hard-down (tripped) and this is the FRESH logical trip, so busbar fails over and stops routing to the lane until its cooldown allows a recovery probe. Recurring still-down probes log at debug. Emitted once per logical trip.",
        "Traffic fails over automatically. Investigate the named upstream's health if a lane stays hard-down.";

    USAGE_TAP_DECODE_FAILED in busbar_contract::diagnostic;

    /// The host's metrics recorder failed to install at boot; /metrics will be empty.
    METRICS_RECORDER_INSTALL_FAILED = 5032, Proxy, Actionable, "metrics-recorder-install-failed", "1.6.0", false,
        "Metrics recorder install failed; /metrics will be empty",
        "The host's metrics recorder failed to install at boot, so the /metrics endpoint will be empty for the life of the process. busbar continues serving proxy traffic, but is blind to metrics.",
        "Investigate the boot error (often a duplicate recorder install or a conflicting exporter). Restart busbar after resolving it; /metrics stays empty until then.";

    /// The metrics maintenance (drain) thread failed to spawn at boot.
    METRICS_MAINTENANCE_THREAD_SPAWN_FAILED = 5033, Proxy, Actionable, "metrics-maintenance-thread-spawn-failed", "1.6.0", false,
        "Could not spawn the metrics maintenance thread (observations drain on scrape only)",
        "busbar could not spawn the metrics maintenance (drain) thread at boot, so buffered metric observations now drain only when /metrics is scraped instead of on a timer. Metrics are still correct but may lag between scrapes.",
        "Investigate the thread-spawn failure (typically OS thread/resource exhaustion). Metrics remain available on scrape; restart after resolving the resource limit for timely draining.";

    /// A /metrics scrape could not list virtual keys; per-key gauges skipped this scrape.
    METRICS_SCRAPE_LIST_KEYS_FAILED = 5034, Proxy, BenignRecurring, "metrics-scrape-list-keys-failed", "1.6.0", false,
        "Metrics scrape: failed to list virtual keys (per-key gauges skipped)",
        "A /metrics scrape could not list virtual keys from the governance store (a transient store hiccup), so it skips the per-key spend/token gauges for this scrape. Other gauges still refresh.",
        "None — self-heals on the next scrape once the store responds. Sustained failures indicate a governance-store problem worth investigating.";

    /// Virtual-key count exceeds the per-key gauge limit; gauges truncated. Warn-once (latched).
    METRICS_KEY_GAUGE_LIMIT_EXCEEDED = 5035, Proxy, Actionable, "metrics-key-gauge-limit-exceeded", "1.6.0", false,
        "Metrics scrape: virtual-key count exceeds the per-key gauge limit (truncating)",
        "The number of virtual keys exceeds the per-key gauge limit (`metrics.key_gauge_limit`), so busbar emits gauges for only the first `limit` keys to bound the exposition's cardinality and scrape-path DB load. Some keys have no per-key series. Warned once until the count drops back under the limit.",
        "Raise `metrics.key_gauge_limit` if you need per-key series for all keys and can afford the cardinality, or reduce the number of active virtual keys. Aggregate group gauges are unaffected.";

    /// A /metrics scrape could not read one key's usage; that key's gauges skipped this scrape.
    METRICS_SCRAPE_KEY_USAGE_READ_FAILED = 5036, Proxy, BenignRecurring, "metrics-scrape-key-usage-read-failed", "1.6.0", false,
        "Metrics scrape: usage read failed; skipping key",
        "During a /metrics scrape, reading one virtual key's usage from the store failed, so busbar skips that key's gauges for this scrape and continues with the rest. Per-key, per-scrape.",
        "None — self-heals on the next scrape. A high volume across keys points to a governance-store problem.";

    /// A /metrics scrape could not read a group ledger bucket; that bucket skipped this scrape.
    METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED = 5037, Proxy, BenignRecurring, "metrics-scrape-group-ledger-read-failed", "1.6.0", false,
        "Metrics scrape: group ledger read failed; skipping bucket",
        "During a /metrics scrape, reading a group budget bucket's ledger from the store failed, so busbar skips that bucket's gauges for this scrape and continues. Per-bucket, per-scrape.",
        "None — self-heals on the next scrape. Sustained failures indicate a governance-store problem.";

    /// A plugin fetch missed on reload; busbar kept the current on-disk artifact. Boot/reload notice. Lives in `appbuild.rs`, but the subject is the plugin loader, so it is a 6000 code.
    PLUGINS_FETCH_RELOAD_MISS = 6001, Plugins, Actionable, "plugins-fetch-reload-miss", "1.6.0", false,
        "plugins.fetch missed on reload (keeping the current artifact)",
        "During a reload, fetching a pinned plugin artifact missed (the source did not return a usable download for the pinned spec), so busbar kept the artifact already on disk and continued the reload. The running plugin is unchanged; the intended refresh did not land.",
        "Check the plugin source (registry/URL) and the pinned spec for the named artifact — a transient fetch miss self-heals on the next reload, a persistent one means the pin no longer resolves. busbar keeps serving the current artifact until a fetch succeeds.";

    /// A plugin is present in the directory but not loaded because the trust policy skips it. Lives in `preflight.rs`, but the subject is plugin trust, so it is a 6000 code.
    PLUGIN_SKIPPED_TRUST_POLICY = 6002, Plugins, Actionable, "plugin-skipped-trust-policy", "1.6.0", false,
        "Plugin present but NOT loaded (skipped by trust policy)",
        "A plugin artifact is present in the plugins directory but was NOT loaded because the configured trust policy skipped it (unsigned, an untrusted publisher, or a failed signature/floor check). busbar fails closed: an untrusted plugin is left inert rather than loaded. Emitted once per skipped plugin at boot.",
        "If the plugin should load, sign it with a trusted publisher key or add that publisher to `plugins.trust` (the log names the plugin, file, and reason). If the skip is intended, remove the artifact from the directory to silence the notice.";

    /// A plugin was loaded but its signature is UNVERIFIED, permitted by an explicit plugins.trust opt-in. Lives in `preflight.rs`, but the subject is plugin trust, so it is a 6000 code.
    PLUGIN_LOADED_UNVERIFIED = 6003, Plugins, Actionable, "plugin-loaded-unverified", "1.6.0", false,
        "Plugin loaded UNVERIFIED (permitted by an explicit plugins.trust opt-in)",
        "A plugin was loaded even though its signature is UNVERIFIED — its code is running unauthenticated, permitted only because an explicit `plugins.trust` opt-in (`allow_unsigned`/`allow_third_party`) let it through. Security-relevant: unverified plugin code runs in-process with busbar's privileges. Emitted once per such plugin at boot.",
        "Prefer a signed artifact from a trusted publisher and remove the `plugins.trust` opt-in once you no longer need it. If running unverified is a deliberate, understood choice (e.g. a locally-built plugin), the opt-in is what keeps it explicit.";

    /// The RAM (ephemeral) store was resolved while a STATEFUL plane (one carrying per-task state) is configured, so in-flight plane task state is dropped on restart.
    STATEFUL_PLANE_EPHEMERAL_STORE = 7030, Plane, Actionable, "stateful-plane-ephemeral-store", "1.6.0", false,
        "Stateful plane on the in-memory store — plane task state is lost on restart",
        "busbar resolved the in-memory (ephemeral) store while a STATEFUL plane is configured — a plane subject (a tool, an agent, or a pool of them). Such planes carry per-task state that lives only in RAM with this store, so it is DROPPED on restart: a task that was mid-flight when the process restarts will break on its next request. Stateless planes are deliberately NOT warned — a restart costs them nothing, so warning there would be noise. This is a WARN, not a boot refusal: a durable store is opt-in and RAM is the convenience default.",
        "Configure a durable store plugin so plane task state survives a restart. No action is needed if losing in-flight task state on restart is acceptable for this deployment.";

    /// A revocation denylist re-sync is still outstanding from an earlier window; store hasn't answered.
    REVOCATION_RESYNC_OUTSTANDING = 8001, Governance, Actionable, "revocation-resync-outstanding", "1.6.0", false,
        "Revocation denylist re-sync still outstanding from an earlier window",
        "A revocation-denylist re-sync launched in an earlier window has not returned — the governance store has not answered for at least a full sync window — so busbar keeps serving the last-known revocations and does not start a second overlapping read. A peer's revoke may not be visible on this node until the store recovers. The CAS bound rate-limits this warning to once per window.",
        "Investigate the governance store's health and latency. Revocations already known stay enforced (fail-closed); the risk is a NEW revoke made elsewhere not yet reaching this node. Re-sync resumes automatically once the store answers.";

    /// A revocation denylist re-sync store read returned an error; the prior set is kept (fail-closed).
    REVOCATION_RESYNC_FAILED = 8002, Governance, Actionable, "revocation-resync-failed", "1.6.0", false,
        "Revocation denylist re-sync failed (keeping the previously-known revocations)",
        "A revocation-denylist re-sync read from the governance store returned an error, so busbar keeps the previously-known revocations in place (fail-closed: a store blip never widens access) and leaves the set marked stale so the next window retries. A peer's revoke may not be visible on this node until a later sync succeeds.",
        "Investigate the governance store — a transient error self-heals on the next window's retry; sustained failures mean the store is unreachable and cross-node revocations are not propagating.";

    /// A principal id collides with a reserved bucket namespace (group:/vk_); no synthetic key minted.
    GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION = 8003, Governance, BenignRecurring, "governance-key-reserved-namespace-collision", "1.6.0", false,
        "Refused to synthesize a governance key (principal id collides with a reserved namespace)",
        "A principal id (attacker-influenceable at the IdP) starts with a reserved ledger-bucket prefix (`group:` or `vk_`), which would alias a group's or a real virtual key's ledger and rate bucket. busbar fails closed and synthesizes NO key for that principal rather than mint a colliding bucket. This is a per-request, caller-side signal, not an operator problem, so it is emitted at debug.",
        "None — self-heals; the principal is correctly refused data-plane access. If a legitimate identity is being rejected, its IdP subject must be reshaped to avoid the reserved `group:` and `vk_` prefixes.";

    /// An unrecognized limit-window word (corrupt/foreign store row); enforced as all-time ('total').
    LIMIT_WINDOW_UNRECOGNIZED = 8004, Governance, Actionable, "limit-window-unrecognized", "1.6.0", false,
        "Unrecognized limit window (enforcing as all-time 'total')",
        "A limit's window word was not recognized — it can only arise from a corrupt or foreign store row, since config parse rejects unknown windows. busbar fails SAFE and enforces the limit as the all-time ('total') window, the tightest enforcement, never wider, and surfaces the value so the corruption is visible instead of silent.",
        "Inspect the governance store row for the named window value — it was written by something other than a validated config load. Enforcement is safe (all-time) in the meantime; correct the row so the intended window applies.";

    /// refresh_self: tombstone of the prior binding failed AND the rollback failed — two live bindings.
    REFRESH_SELF_INCONSISTENT_BINDING = 8005, Governance, Actionable, "refresh-self-inconsistent-binding", "1.6.0", false,
        "Self-serve refresh left an inconsistent binding (tombstone AND rollback both failed)",
        "During a self-serve key refresh, tombstoning the prior binding failed and the compensating rollback of the newly-minted binding ALSO failed, so the subject may now have TWO live bindings in the store for one identity. busbar exhausted its best-effort recovery and surfaces the inconsistent state for inspection. Rare.",
        "Inspect the governance store for the named subject — it may hold two live bindings (old_id and new_id). Tombstone whichever is not intended so the subject has exactly one valid credential.";

    /// refresh_self: cache reconcile failed after the store tombstone; prior binding evicted surgically.
    REFRESH_SELF_CACHE_REFRESH_FAILED = 8006, Governance, Actionable, "refresh-self-cache-refresh-failed", "1.6.0", false,
        "Self-serve refresh: cache reconcile failed after tombstoning the prior binding",
        "During a self-serve key refresh, the store tombstone of the prior binding committed but the follow-up cache reconcile (a store round-trip) failed. busbar evicted the prior binding directly from the cache so its old token stops verifying immediately; the store is consistent, but the rest of the cache may be stale until the next successful refresh.",
        "Investigate the governance store's reachability — the durable state is correct and the old credential no longer verifies. The cache self-heals on the next successful reconcile; sustained failures mean the store is unhealthy.";

    /// A group was missing at accrual; tokens were ledgered to the key bucket only (self-degrading).
    ACCRUAL_GROUP_MISSING = 8007, Governance, BenignRecurring, "accrual-group-missing", "1.6.0", false,
        "Group missing at accrual (tokens ledgered to the key bucket only)",
        "A group referenced by a key was gone by the time usage was accrued (the group was deleted between admission and accrual), so busbar degrades to ledgering the tokens on the key's own bucket only rather than lose them. The request was already admitted and served; nothing is lost. This is a per-request, self-degrading path, so it is emitted at debug.",
        "None — self-heals; tokens are preserved on the key bucket. Frequent occurrence for one key means a group is being deleted out from under active keys; reconcile the key's group assignment.";

    /// Metering flush had key(s) fail to persist this tick; already aggregated to one warn per tick.
    METERING_FLUSH_PARTIAL_FAILURE = 8008, Governance, Actionable, "metering-flush-partial-failure", "1.6.0", false,
        "Metering flush: some keys failed to persist this tick (retained for retry)",
        "A metering flush tick could not persist one or more keys' usage deltas to the store. busbar retains the failed deltas and retries them on the next tick, so no usage is lost. This is already collapsed to ONE aggregate warning per tick (per-key detail is at debug), so it fires at a human cadence, not per key.",
        "Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Usage is retained and re-tried, so billing is not lost, only delayed.";

    /// Metering write-behind accumulator hit its cap; a new cell was coalesced into an overflow sentinel.
    METERING_PENDING_OVERFLOW_COALESCED = 8019, Governance, Actionable, "metering-pending-overflow-coalesced", "1.6.0", false,
        "Metering accumulator at cap: a cell was coalesced into an overflow sentinel",
        "The write-behind metering accumulator (pending_metering) reached its cap while a NEW (key_id, bucket, model, provider) cell arrived — a sustained governance-store outage with diverse keys/models, where every flush re-queues the failed cells while new ones keep arriving. Rather than grow without bound OR silently drop billable usage, busbar COALESCES the arriving cell's counts into a per-bucket overflow sentinel: the day's token and request TOTALS are preserved, only their per-key/model/provider ATTRIBUTION is collapsed. Each coalesce also increments busbar_metering_pending_coalesced_total. The warning is emitted at most once per minute and names how many cells were coalesced since the previous line; the counter carries the running total.",
        "Restore the governance store — the accumulator overflows only under a sustained write outage. Usage is not lost (totals are retained under the overflow sentinel key), but once the store recovers the retained deltas flush and normal per-key attribution resumes. A steadily climbing coalesced counter means the outage has outlasted the cap.";

    /// delete_key: tombstone committed and key evicted, but the full cache reconcile failed.
    DELETE_KEY_CACHE_RECONCILE_FAILED = 8009, Governance, Actionable, "delete-key-cache-reconcile-failed", "1.6.0", false,
        "delete_key: tombstone committed and key evicted, but cache reconcile failed",
        "An admin key deletion committed the tombstone in the store and evicted the deleted key from the in-memory caches (it no longer authenticates), but the follow-up full cache reconcile failed. The deletion is durable and the key is dead; only OTHER cache entries may be stale until the next successful refresh. Rare admin path.",
        "Investigate the governance store's reachability — the deletion itself is complete and safe. The cache self-heals on the next successful refresh; sustained failures indicate an unhealthy store.";

    /// rotate_key: new generation committed and key evicted, but cache reconcile failed; new secret lost.
    ROTATE_KEY_CACHE_RECONCILE_FAILED = 8010, Governance, Actionable, "rotate-key-cache-reconcile-failed", "1.6.0", false,
        "rotate_key: new generation committed, but cache reconcile failed (new secret not returned)",
        "An admin key rotation committed the new generation in the store — so the PREVIOUS credential is permanently dead — and evicted the key from the caches, but the follow-up cache reconcile failed, so the freshly-minted secret could not be returned to the admin. The rotation IS durable; the new secret is simply lost from this response. Rare admin path.",
        "Re-rotate the key to obtain a fresh secret — the previous credential is already dead and will not come back. Investigate the governance store's reachability, which is why the reconcile failed.";

    /// Budget flush had bucket(s) fail to persist this tick; already aggregated to one warn per tick.
    BUDGET_FLUSH_PARTIAL_FAILURE = 8011, Governance, Actionable, "budget-flush-partial-failure", "1.6.0", false,
        "Budget flush: some buckets failed to persist this tick (re-marked dirty for retry)",
        "A budget flush tick could not persist one or more group-budget buckets to the store. busbar re-marks those buckets dirty and retries them on the next tick, so no spend is lost. This is already collapsed to ONE aggregate warning per tick (per-bucket detail is at debug), so it fires at a human cadence, not per bucket.",
        "Investigate the governance store if the failure count stays non-zero across ticks — a transient store hiccup self-heals on the next flush. Spend is retained and re-tried, so budgets are not lost, only delayed.";

    /// --safe-mode boot: the config overlay was quarantined; running on base config.yaml alone.
    SAFE_MODE_OVERLAY_QUARANTINED = 8012, Governance, Actionable, "safe-mode-overlay-quarantined", "1.6.0", false,
        "SAFE MODE: config overlay not merged (running on base config.yaml alone)",
        "busbar was booted with `--safe-mode`, so the persisted config overlay (API-registered hooks) was NOT merged and busbar is running on the operator-owned base config.yaml alone. This is the intentional escape hatch for an applied hook that harms traffic and re-applies itself every boot. The overlay file is untouched, not deleted.",
        "This is an operator-requested state. Repair or remove the offending overlay entry, then boot WITHOUT `--safe-mode` to re-apply the overlay. Until then, API-registered hooks are not in effect.";

    /// RETIRED before 1.6.0 shipped, superseded by [`PROVIDER_API_KEY_UNRESOLVABLE`]: the degrade this code described no longer exists. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened and what replaced it.
    PROVIDER_API_KEY_UNRESOLVED = 8013, Governance, Actionable, "provider-api-key-unresolved", "1.6.0", true,
        "Provider api_key did not resolve (degraded to an empty key) — RETIRED, see BUSBAR-8020",
        "RETIRED. A provider's `api_key` secret reference did not resolve at boot, so busbar degraded that provider to an empty key and started the lane anyway. 1.6.0 removed that degrade: an `api_key` that does not resolve now REFUSES BOOT (BUSBAR-8020), and an upstream that genuinely takes no credential is declared with `api_key: none`.",
        "Nothing emits this code. See BUSBAR-8020.";

    /// A provider api_key SecretRef did not resolve; boot refuses.
    PROVIDER_API_KEY_UNRESOLVABLE = 8020, Governance, Fatal, "provider-api-key-unresolvable", "1.6.0", false,
        "Provider api_key did not resolve (boot refuses)",
        "A provider's `api_key` secret reference could not be resolved — an unset environment variable, a missing or empty file, an unknown module, or a secret plugin that failed — so busbar refuses to start. It does not fall back to an empty credential: that lane could never authenticate, would report healthy, would be skipped by the health prober (no key, no probe), and would answer every request routed to it with a 401 from the upstream. The diagnostic names the provider and the reference (`env:VAR`, `file:/path`), never the value.",
        "Fix the reference so it resolves (set the variable, mount the file, install and trust the secret plugin), or — if this upstream genuinely takes NO credential, such as a local ollama or vLLM — declare that explicitly with `api_key: none`, which starts the lane with no credential and sends no auth header. `--validate` reports the same refusal before you deploy.";

    /// A unit's one line carried a class its plane never declared.
    METER_CLASS_UNDECLARED = 8022, Governance, Actionable, "meter-class-undeclared", "1.6.0", false,
        "A unit reported a usage class its plane never declared (the line is refused, not billed)",
        "A unit's drained usage report named a class that no installed plane declares as billable, no configured `units:` entry names, and is not one of the reserved four. The unit's one line is still written with every count, but its money is REFUSED rather than priced: a class nobody declared is never billed at zero and never dropped. Every read of the balance the line sits on refuses until it is explained.",
        "The plane that served the unit reported a class outside its declaration, which is a plugin defect: upgrade or fix the plane so it declares every class it reports, or configure the class under the lane's `units:` if it is an operator-priced open class.";

    /// auth.chain is empty (open relay) — emitted at error so RUST_LOG=error cannot mask it.
    OPEN_RELAY_NO_AUTH = 8014, Governance, Actionable, "open-relay-no-auth", "1.6.0", false,
        "auth.chain is empty — OPEN RELAY (every request admitted unauthenticated)",
        "The auth chain is empty (either explicitly, or because the `auth:` block is absent and serde-defaults to none), so every data-plane request is admitted unauthenticated — an OPEN RELAY forwarding anyone's traffic on your upstream credentials. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr so the state cannot be masked by log configuration. Acceptable only for local development.",
        "Configure `auth.chain` (a `keys` verifier and/or an auth plugin) before exposing busbar to any untrusted network. This is the same open-relay condition as BUSBAR-4004, surfaced at boot.";

    /// A stored recoverable credential opens under neither at-rest key, so it does not authenticate.
    CREDENTIAL_AT_REST_UNOPENABLE = 8023, Governance, Actionable, "credential-at-rest-unopenable", "1.6.0", false,
        "A stored recoverable credential opens under neither at-rest key (it does not authenticate)",
        "A recoverable credential (a signed-request secret) is stored sealed under an at-rest key whose kid matches neither credentials.at_rest.key nor credentials.at_rest.previous on this node, or its row was altered. It answers as an unknown credential: requests signed with it are refused. The refusal is audited once per kid.",
        "Configure the key with the named kid as credentials.at_rest.previous (or as key) on every node that shares the store, and reload. A credential whose key is lost cannot be recovered: re-mint it.";

    /// Recoverable credentials still need re-sealing under the current at-rest key.
    CREDENTIAL_AT_REST_REWRAP_PENDING = 8024, Governance, Actionable, "credential-at-rest-rewrap-pending", "1.6.0", false,
        "Recoverable credentials are not yet re-sealed under the current at-rest key",
        "A boot or reload re-seals every stored recoverable credential sealed under credentials.at_rest.previous (or stored in the clear before 1.6.0) under credentials.at_rest.key. Some rows were not re-sealed on this pass: another node held their claim, the store keeps no claims, or the store refused the write. They still authenticate under the key they were sealed under.",
        "Keep credentials.at_rest.previous configured until a boot or reload re-seals them all (no further warning). If it persists on a single node, check that the store supports single-use claims and accepts credential writes.";

    /// A recoverable credential written before 1.6.0 is stored in the clear.
    CREDENTIAL_AT_REST_LEGACY_PLAIN = 8025, Governance, Actionable, "credential-at-rest-legacy-plain", "1.6.0", false,
        "A recoverable credential written before 1.6.0 is stored in the clear",
        "A recoverable credential (a signed-request secret) minted by 1.5.5 is stored as v1:plain. It still authenticates. A boot or reload with credentials.at_rest.key configured re-seals it under that key.",
        "Configure credentials.at_rest.key (a secret reference resolving to 32 random bytes) and reload; the row is re-sealed and no longer stored in the clear.";

    /// A store settings SecretRef does not resolve at boot; restart-to-apply, so it WILL fail next restart.
    STORE_SECRET_REF_UNRESOLVED = 8015, Governance, Actionable, "store-secret-ref-unresolved", "1.6.0", false,
        "Store settings hold a secret reference that does not resolve here",
        "A governance-store `settings` value holds a secret reference that does not resolve on this boot. busbar warns rather than fails, because the store is restart-to-apply and staging a ref whose secret the orchestrator mounts on the next deploy is a legitimate workflow. But if the secret is still absent at the next restart, THAT restart will fail in resolve_settings before serving.",
        "Ensure the named store secret reference resolves before the next restart. If you are staging it for an upcoming deploy, no action now; otherwise fix the reference so the next restart does not die resolving it.";

    /// The in-memory (ephemeral) governance store was selected; keys/usage/ledgers reset on restart.
    GOVERNANCE_STORE_EPHEMERAL = 8016, Governance, Actionable, "governance-store-ephemeral", "1.6.0", false,
        "Governance store is in-memory (ephemeral) — state resets on restart",
        "busbar selected the in-memory (ephemeral) governance store, so virtual keys, groups' usage, and ledgers live only in RAM and are LOST on restart. This is the default when no durable store plugin is configured — fine for a trial or local development, but not for anything that must retain keys or spend across restarts.",
        "Configure a durable governance store plugin for persistence if keys, usage, or budgets must survive a restart. No action is needed for ephemeral/dev use.";

    /// Durable store is configured with keys but keys-in-chain is off; durable keys are inert.
    DURABLE_KEYS_INERT = 8017, Governance, Actionable, "durable-keys-inert", "1.6.0", false,
        "Durable keys are inert (keys exist but `keys` is not in the running auth chain)",
        "A durable governance store holds virtual keys, but the running auth chain does not include the `keys` verifier, so those keys enforce nothing — every request bypasses key-based governance. Emitted at ERROR (not warn, which RUST_LOG=error would suppress) and unconditionally on stderr, the same pattern as the open-relay banner, so the inert state cannot be masked by log configuration.",
        "Add `keys` to `auth.chain` so the durable keys actually gate traffic, or remove the keys if key-based governance is not intended. Until then, minted keys are dead weight.";

    /// The durable audit log could not be READ at boot (a store hiccup); busbar starts on an empty ring.
    BOOT_AUDIT_RESTORE_READ_FAILED = 9001, Boot, Actionable, "boot-audit-restore-read-failed", "1.6.0", false,
        "Durable audit log could not be read at boot (starting with an empty ring)",
        "busbar could not READ the durable audit log from the governance store at boot — a store hiccup, not a chain-verification failure — so it started with an empty in-memory audit ring. This is deliberately distinct from BUSBAR-2043 (chain verification failed): here the bytes could not be read at all, so there is no tamper signal, just a store that did not answer.",
        "Investigate the governance store's reachability at boot. If the store recovers, restart so the durable history is restored into the ring; a transient hiccup needs no action beyond confirming the store is healthy.";

    /// The ONE-TIME legacy-audit-table → `plane_records` migration could not be completed at boot (a store write hiccup); the durable seam has not yet taken over the pre-existing audit history.
    BOOT_AUDIT_MIGRATE_FAILED = 9012, Boot, Actionable, "boot-audit-migrate-failed", "1.6.0", false,
        "Legacy audit table could not be migrated into the durable journal seam at boot",
        "busbar found audit history in the legacy durable table but could not copy it into the neutral `plane_records` the durable audit seam now reads at boot — a store read/write hiccup, not a chain-verification failure. The migration is IDEMPOTENT and is retried on the next boot, so the pre-existing history reappears once the store is healthy; until then the seam-backed audit read (`GET /audit`) reflects only records written since this boot.",
        "Investigate the governance store's write path at boot (the same store the audit log persists to). Once it accepts writes, restart so the one-time migration completes and the durable history is restored into the seam; a transient hiccup needs no action beyond confirming the store is healthy.";

    /// The TLS accept loop is failing persistently (fd exhaustion?); busbar backs off. Backoff-latched.
    TLS_ACCEPT_PERSISTENT_FAILURE = 9002, Boot, Actionable, "tls-accept-persistent-failure", "1.6.0", false,
        "TLS accept loop failing persistently (backing off)",
        "A TLS listener's accept loop is failing persistently — commonly file-descriptor exhaustion — so busbar backs off before retrying rather than spin hot on the error. On unix each of the N data-plane workers runs its own accept loop, so the warning can fire from one worker or from several at once. The warning is already rate-limited by the backoff delay, so each loop fires at a human cadence, not per failed accept.",
        "Investigate the accept failure — most often the process fd limit (raise `ulimit -n` / the systemd `LimitNOFILE`) or a resource leak holding sockets open. Each listener keeps retrying with backoff and recovers on its own once accepts succeed.";

    /// The telemetry bank's slot table is full; further label sets fall back to the metrics macros. Warn-once.
    TELEMETRY_SLOT_TABLE_FULL = 9003, Boot, BenignRecurring, "telemetry-slot-table-full", "1.6.0", false,
        "Telemetry slot table full (further label sets fall back to the metrics macros)",
        "The telemetry bank's pre-registered slot table reached its cap, so further label sets fall back to the ordinary metrics macros instead of a reserved slot — correct, just slower on that path. Warned ONCE per table (a latch), never per registration, so it cannot spam.",
        "None — self-heals; the fallback path is correct. If a deployment legitimately needs more distinct label sets than the slot cap, that cap is a build-time bound; the metrics remain accurate via the fallback in the meantime.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    PLANE_TASK_CHAIN_VERIFY_FAILED = 2041, Audit, Actionable, "plane-task-chain-verify-failed", "1.6.0", true,
        "Per-task provenance chain failed hash-chain verification on restore (tamper) — RETIRED",
        "RETIRED. Nothing emits this code: the engine keeps no plane task store.",
        "Nothing emits this code.";

    PLANE_CALLLOG_CHAIN_VERIFY_FAILED = 2042, Audit, Actionable, "plane-calllog-chain-verify-failed", "1.6.0", true,
        "Plane per-call records failed hash-chain verification on restore (tamper evidence) — RETIRED",
        "RETIRED. A principal's persisted plane per-call records were read at boot but do NOT verify against their own hash chain, which is tamper evidence. They are still restored and the chain resumes from the broken tail, because refusing here would convert a detection control into a deletion primitive — anyone able to write to the store could delete a caller's history by corrupting one record.",
        "Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.";

    PLANE_AUDITLOG_CHAIN_VERIFY_FAILED = 2043, Audit, Actionable, "plane-auditlog-chain-verify-failed", "1.6.0", false,
        "Admin audit records failed hash-chain verification on restore (tamper evidence)",
        "The persisted admin audit records were read at boot through the durable journal seam but do NOT verify against their own hash chain, which is tamper evidence. They are still restored and the chain resumes from the broken tail, because refusing here would convert a detection control into a deletion primitive — anyone able to write to the store could delete audit history by corrupting one record.",
        "Treat the durable governance store as compromised until explained: capture it for forensic review before it is overwritten, then restore from a trusted backup once the cause is understood.";

    PLANE_JOURNAL_RESUME_CHAIN_BROKEN = 2048, Audit, Actionable, "plane-journal-resume-chain-broken", "1.6.0", false,
        "A plane journal scope failed hash-chain verification on resume (tamper evidence)",
        "A plane journal scope that had been evicted from the in-memory cache was read back from               the durable store to take its next record, and the persisted tail does NOT verify               against its own hash chain, which is tamper evidence surfaced at runtime rather than at               boot. The chain resumes from the broken tail and the write is not refused, because               refusing here would convert a detection control into a deletion primitive.",
        "Treat the durable governance store as compromised until explained: capture it for              forensic review before it is overwritten, then restore from a trusted backup once the              cause is understood.";

    PLANE_AUDITLOG_WRITE_FAILED = 2044, Audit, Actionable, "plane-auditlog-write-failed", "1.6.0", false,
        "Admin audit record could not be written through the durable journal seam (evidence lost)",
        "The admin audit record could NOT be written through the durable journal seam, so this mutation is being served but its evidence is being lost on that path. The chain position is unchanged, so the chain stays contiguous — what is missing is this one record, not the ones after it. This can recur per mutation during a store outage, so it warns on the transition into the failing state and holds subsequent occurrences at debug.",
        "Restore the durable governance store's write path. Once writes succeed again the latch resets and a future outage re-warns.";

    PLANE_CALLLOG_ROW_UNREADABLE = 2045, Audit, Actionable, "plane-calllog-row-unreadable", "1.6.0", true,
        "Persisted plane per-call record could not be decoded on restore (skipped, not dropped) — RETIRED",
        "RETIRED. A principal's persisted plane per-call record could not be decoded at boot — a body from a store format no released build wrote, or a corrupt row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole rehydrate (which would drop every OTHER principal's working set), but the skip is reported here so a silently lost evidence row is never invisible. Usually an engine-version mismatch or a corrupt store.",
        "Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.";

    PLANE_JOURNAL_ROW_UNREADABLE = 2046, Audit, Actionable, "plane-journal-row-unreadable", "1.6.0", false,
        "Persisted journal record could not be reframed on restore (skipped, not dropped)",
        "A scoped journal record could not be reframed at boot — a body from a store format no released build wrote, or a corrupt row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole rehydrate (which would drop every OTHER scope's working set), but the skip is reported here so a silently lost evidence row is never invisible. Usually an engine-version mismatch or a corrupt store.",
        "Note the scope. If many rows are unreadable, suspect a store format mismatch after an upgrade or downgrade; capture the durable governance store for review.";

    PLANE_AUDIT_ROW_UNREADABLE = 2047, Audit, Actionable, "plane-audit-row-unreadable", "1.6.0", false,
        "Persisted admin audit record could not be decoded on restore (skipped, not dropped)",
        "A persisted admin audit record could not be decoded at boot on the neutral `plane_records` path — a body from a store format no released build wrote, or a corrupt or tampered row. It is COUNTED and SKIPPED per-record rather than allowed to abort the whole restore, but the skip is reported here so a silently lost evidence row on this tamper-evidence surface is never invisible. On the admin audit log an undecodable row may be tamper evidence, not merely a format mismatch.",
        "Treat the durable governance store as suspect: if rows are unreadable on a store a released build wrote, capture it for forensic review before it is overwritten and restore from a trusted backup once the cause is understood.";

    /// An egress bearer credential contains bytes invalid for a header value: the auth plugin that presents it omits the header and raises this code on each request it meets. An actionable warn line, as it was before the code existed; the catalogue never demotes it to debug.
    PROTO_AUTH_INVALID_HEADER_BYTES = 7087, Plane, Actionable, "proto-auth-invalid-header-bytes", "1.6.0", false,
        "Egress credential has invalid header bytes (auth header omitted)",
        "An egress authorization credential contains bytes that are not valid in an HTTP header (e.g. an ASCII control character), so the Authorization header is omitted entirely rather than sent malformed — the upstream will reject the request with 401. The key itself is never logged, only the protocol name. It is raised on each request that would have carried the header.",
        "Fix the misconfigured lane's credential — the configured secret contains invalid header bytes. The protocol name in the log line locates the lane.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    PLANE_TASK_ROW_UNREADABLE = 7089, Plane, Actionable, "plane-task-row-unreadable", "1.6.0", true,
        "Persisted plane task row could not be read back (not resumable) — RETIRED",
        "RETIRED. Nothing emits this code: the engine keeps no plane task store.",
        "Nothing emits this code.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    PLANE_SSRF_CALLBACK_AT_STORE = 7090, Plane, Actionable, "plane-ssrf-callback-at-store", "1.6.0", true,
        "SSRF-refused push callback reached the task store (dropped) — RETIRED",
        "RETIRED. Nothing emits this code: the engine keeps no plane task store.",
        "Nothing emits this code.";

    APPROVAL_LEDGER_UNREACHABLE_REFUSED = 7091, Plane, Actionable, "approval-ledger-unreachable-refused", "1.6.0", true,
        "Spent-approval ledger unreachable — redemption refused — RETIRED",
        "RETIRED. The shared spent-approval ledger could not be reached, so an approval redemption was REFUSED: a ledger that cannot say whether an approval was already spent must not be read as saying it was not (a double-spend on a money-moving tool is the defect the gate exists to stop).",
        "Nothing emits this code. A one-time approval is redeemed through the host's records.claim service.";

    PLANE_CALLLOG_EMPTY_CHAIN = 7092, Plane, Actionable, "plane-calllog-empty-chain", "1.6.0", true,
        "Durable plane call log enumerates a principal with NO records — RETIRED",
        "RETIRED. The durable plane call log named a principal and then produced no records for it, so its chain is reopened at seq 1 and the discrepancy is reported rather than skipped. The verifier alone cannot distinguish this from a caller's evidence being deleted wholesale.",
        "Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.";

    PLANE_CALLLOG_WRITE_FAILED = 7093, Plane, Actionable, "plane-calllog-write-failed", "1.6.0", true,
        "Durable plane per-call record could not be written (evidence lost) — RETIRED",
        "RETIRED. The durable plane per-call record could NOT be written, so this call is being served but its evidence is being lost. The chain position is unchanged, so the chain stays contiguous — what is missing is this one record, not the ones after it. This can recur per request during a store outage, so it warns on the transition into the failing state and holds subsequent occurrences at debug.",
        "Nothing emits this code. The per-call log is a plane's declared chained record kind, appended and resumed by the host's generic journal; a chain that does not verify from its stored tail is BUSBAR-2048.";

    PLANE_DEMOTION_WRITE_FAILED = 7094, Plane, Actionable, "plane-demotion-write-failed", "1.6.0", false,
        "Durable plane demotion record could not be written",
        "The durable plane demotion record could NOT be written, so this upstream is demoted only in the current process and a restart will re-open it until the next sweep looks again. Usually a durable store-write outage.",
        "Restore the durable governance store's write path so demotions persist across restarts.";

    PLANE_DEMOTION_CLEAR_FAILED = 7095, Plane, Actionable, "plane-demotion-clear-failed", "1.6.0", false,
        "Durable plane demotion record could not be cleared",
        "The durable plane demotion record for an upstream could NOT be cleared even though it is serving again in the current process, so a restart would re-establish a quarantine the operator has already worked. Usually a durable store-write outage.",
        "Restore the durable governance store's write path so a cleared demotion does not reappear after a restart.";

    PLANE_DEMOTIONS_UNREAD = 7096, Plane, Actionable, "plane-demotions-unread", "1.6.0", false,
        "Durable plane demotion records could not be read at boot",
        "The durable plane demotion records or the operator's trust decisions could NOT be read when a plane instance was admitted, so the instance was refused rather than re-open an upstream this deployment demoted or stand over a revoke it cannot see. Usually a durable store-read outage.",
        "Restore the durable governance store's read path and restart so persisted demotions are re-applied before a listener binds.";

    /// A plane instance declares a record kind the kernel keeps its own records under; the instance is refused at its admit.
    PLANE_RECORD_KIND_RESERVED = 7106, Plane, Actionable, "plane-record-kind-reserved", "1.6.0", false,
        "A plane declares a record kind the kernel keeps its own records under (the plane is refused)",
        "A plane's Statement declares a record kind that the kernel keeps its own records under (`ticket`, where a minted ticket's record is kept). A plane's declared kind names the rows its retention rule governs, so admitting it would let that plane purge the kernel's records under its own rule. busbar refuses the plane instance at its admit, so the boot (or the reload) that would open it fails, naming the instance and the kind. Nothing of the instance is registered.",
        "Use a plane build that does not declare a kernel record kind: rename the plane's record kind (it is the plugin author's word, in its Statement's record kinds) and rebuild. There is no configuration override; the kernel's kinds are never shared.";

    /// An admin `plane_record_write` named a record kind the kernel keeps its own records under; the write is refused.
    PLANE_RECORD_WRITE_KERNEL_KIND = 7107, Plane, Actionable, "plane-record-write-kernel-kind", "1.6.0", false,
        "An admin plane record write named a kernel record kind (the write is refused)",
        "`POST /api/v1/admin/plane-record-write` named a record kind the kernel keeps its own records under (`audit`, `usage_residual`, `demotion`, `trust_decision` or `ticket`). A plane may declare one of these (plane-mcp declares `demotion`), but the rows under it are the kernel's own, for example its durable demotion record of a quarantined upstream, and no write made in a plane's name may alter them. busbar answers `403 forbidden` naming the kind, writes nothing, and seals the refusal on the administrative audit ring as `rejected`.",
        "Do not write kernel records through the plane record verb. To lift a quarantine, approve the counterparty with `POST /api/v1/admin/trust/approve`, which clears its durable demotion. Write a plane's own records under a kind that is not the kernel's.";

    TRUST_VERIFY_REFUSED_ON_DRIFT = 7097, Plane, BenignRecurring, "trust-verify-refused-on-drift", "1.6.0", true,
        "Verify-on-call refused a call because the upstream's advertised surface drifted — RETIRED",
        "RETIRED. Nothing emits this code: the verify-on-call gate that refused a drifted call is deleted (Q128 p8#3); a registration whose upstream drifted is demoted by the trust book.",
        "Nothing emits this code.";

    TRUST_VERIFY_UNREACHABLE = 7098, Plane, Actionable, "trust-verify-unreachable", "1.6.0", true,
        "Verify-on-call could not reach an upstream to re-verify, and refused fail-closed — RETIRED",
        "RETIRED. Nothing emits this code: the verify-on-call gate that re-fetched a stale observation is deleted (Q128 p8#3).",
        "Nothing emits this code.";

    /// RETIRED before 1.6.0 shipped: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    PLANE_TASK_ABANDON_UNRECORDED = 7099, Plane, Actionable, "plane-task-abandon-unrecorded", "1.6.0", true,
        "Abandoned plane task could not be transitioned to canceled (durable store write failed) — RETIRED",
        "RETIRED. Nothing emits this code: the engine keeps no plane task store.",
        "Nothing emits this code.";

    /// `entitlement.check` named a scope kind the calling plane did not declare; the answer is NOT_ENTITLED.
    ENTITLEMENT_UNDECLARED_SCOPE_KIND = 8021, Governance, BenignRecurring, "entitlement-undeclared-scope-kind", "1.6.0", false,
        "An entitlement check named a scope kind its plane did not declare",
        "A plane asked whether the unit's principal is entitled to a target whose scope kind is not among the scope kinds the plane's tail declares. The kernel answers NOT_ENTITLED without consulting the principal's grants.",
        "Declare the scope kind in the plane's tail, or correct the target the plane asks about.";

    ADMIN_STORE_OPERATION_FAILED = 1006, Durability, Actionable, "admin-store-operation-failed", "1.6.0", false,
        "Admin store operation failed (generic 500; store detail logged server-side)",
        "An admin API CRUD or read operation against the governance/durable store returned an error, so busbar answers the admin request with a generic 500. The store's own error (which may embed SQL fragments or backend paths) is logged server-side only — the response body carries no store internals. The `operation` field names which call failed.",
        "Investigate the durable/governance store's health and reachability for the named operation. A transient store hiccup self-heals on retry; sustained failures mean the store backend is unhealthy and admin mutations/reads cannot complete.";

    ADMIN_STORE_TASK_JOIN_FAILED = 1007, Durability, Actionable, "admin-store-task-join-failed", "1.6.0", false,
        "Admin store blocking task failed to join (cancelled or panicked)",
        "An admin store operation ran on a `spawn_blocking` task that failed to join — the blocking store closure was cancelled or panicked — so busbar maps it to a generic 500 rather than let a JoinError propagate as an unwrap on the request path. The blocking store closures do not panic in normal operation.",
        "Investigate the logged operation and store backend — a panic in a blocking store closure is a bug or a resource failure. Capture the error and file a bug if it recurs; the request was safely failed, not mis-served.";

    GROUP_DELETE_KEY_READ_FAILED = 1008, Durability, Actionable, "group-delete-key-read-failed", "1.6.0", false,
        "Group delete could not read keys to check bindings (admin 500)",
        "Deleting a group requires a full key scan to count how many keys are still bound to it, and that store read failed, so busbar answers the admin delete with a generic 500 rather than delete a group with unknown live bindings. No group state was changed.",
        "Investigate the governance store's reachability — the key scan could not complete. Retry the delete once the store is healthy; a transient read error self-heals.";

    USAGE_BLOCKING_TASK_JOIN_FAILED = 1009, Durability, Actionable, "usage-blocking-task-join-failed", "1.6.0", false,
        "Admin /usage blocking task failed to join (cancelled or panicked)",
        "The admin /usage read ran on a `spawn_blocking` task that failed to join (cancelled or panicked), so busbar answers the request with a generic 500. Distinct from a store error returned by the read itself (BUSBAR-1006): here the blocking task did not complete at all.",
        "Investigate the logged context and store backend — a blocking-task panic is a bug or a resource failure. Capture the error and file a bug if it recurs; the request was safely failed.";

    ADMIN_AUTH_CHAIN_EMPTY = 4026, Auth, Actionable, "admin-auth-chain-empty", "1.6.0", false,
        "admin_auth chain is EMPTY (open, anonymous, full-authority dev posture)",
        "An EMPTY admin_auth chain was seen: the admin API's open dev posture admits every admin request anonymously with FULL authority. The live `PUT /api/v1/admin/admin-auth` applies an empty chain as 1.5.5 did, with this warning, and the open posture is then live until the chain is set again.",
        "Leave `admin_auth` empty ONLY for local development. To opt into the open posture, set `admin_auth: []` in config.yaml and restart. Otherwise configure a non-empty chain (an admin credential entry, or an admin module) before exposing the admin API to any untrusted network.";

    ADMIN_CREATEKEY_MALFORMED_BODY = 4027, Auth, BenignRecurring, "admin-createkey-malformed-body", "1.6.0", false,
        "create_key request body failed to parse (client 400)",
        "A create_key request body did not parse as valid JSON, so busbar returns a generic 400. The body carries secrets (an AWS secret_access_key, the bearer being minted), so only its byte length is logged, never the raw error or an input fragment. This is a CLIENT-side bad request, not an operator problem, so it is emitted at debug.",
        "None — self-heals; the client must send well-formed JSON. Persistent volume from one caller indicates a broken client worth fixing, but it is not a busbar fault.";

    CREATEKEY_UNKNOWN_POOL = 4028, Auth, BenignRecurring, "createkey-unknown-pool", "1.6.0", false,
        "create_key allowed_pools names an unconfigured pool (key still created)",
        "A create_key request listed an `allowed_pools` entry that names no configured pool — a likely typo. The key is still created (the entry activates if the pool is configured later), so this is a non-fatal advisory. It is a per-request, caller-side signal, so it is emitted at debug.",
        "None required — the key was created. If the pool name was a typo, correct it or configure the named pool so the allowed_pools entry takes effect.";

    ADMIN_UPDATEKEY_MALFORMED_BODY = 4029, Auth, BenignRecurring, "admin-updatekey-malformed-body", "1.6.0", false,
        "update_key request body failed to parse (client 400)",
        "An update_key request body did not parse as valid JSON, so busbar returns a generic 400, logging only the body's byte length (never the raw serde error or an input fragment). Mirror of BUSBAR-4027 for the update path. This is a CLIENT-side bad request, so it is emitted at debug.",
        "None — self-heals; the client must send well-formed JSON. Persistent volume from one caller indicates a broken client worth fixing.";

    PLANE_BREAKER_TRIPPED = 5038, Proxy, Actionable, "plane-breaker-tripped", "1.6.0", false,
        "Plane breaker tripped (upstream target failing; dispatches fast-fail)",
        "A plane target's circuit breaker transitioned Closed→Open because the upstream target is failing, so further dispatches fast-fail until the half-open probe recovers it. Names the specific target (every plane target shares one degenerate lane, so without this the operator would not learn WHICH server is down). Emitted once per logical trip, not per failure.",
        "Investigate the named plane target's health (the tool, agent, or server it fronts). Traffic to it fast-fails until the breaker's half-open probe finds it healthy again.";

    PLANE_BREAKER_HARD_DOWN = 5039, Proxy, Actionable, "plane-breaker-hard-down", "1.6.0", false,
        "Plane breaker tripped hard-down (definitive auth/billing failure; sticky cooldown)",
        "A plane target answered a DEFINITIVE failure (auth/billing), so busbar trips its breaker hard-down: dispatches fast-fail for a sticky cooldown rather than keep retrying a target that will keep rejecting. Emitted per hard-down disposition for the named target.",
        "Fix the named target's credentials or billing/quota with its provider — a hard-down is a definitive rejection, not a transient blip. It recovers via the half-open probe once the underlying auth/billing fault is resolved.";

    LANE_HARD_DOWN_ALL_CELLS = 5040, Proxy, Actionable, "lane-hard-down-all-cells", "1.6.0", false,
        "Lane hard-down across all cells (sticky cooldown; recovers via half-open probe)",
        "A lane was recorded hard-down across ALL its per-pool cells at once (the all-cells variant of BUSBAR-5026) — every pool's view of the lane is tripped Open with a sticky cooldown. The lane is RECOVERABLE via the half-open probe (it is not marked dead), so it re-admits once a probe succeeds.",
        "Investigate the named upstream/model lane's health — a hard-down across all cells means a definitive lane-wide fault. Traffic fails over automatically; the lane recovers via the half-open probe once the upstream is healthy.";

    /// RETIRED before 1.6.0 shipped: the kernel's own breaker state machine that raised this code is deleted and the kernel runs on the one breaker, which logs nothing. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    BREAKER_UNEXPECTED_STATE_CLASSIFY = 5041, Proxy, Actionable, "breaker-unexpected-state-classify", "1.6.0", true,
        "Unexpected breaker state on classify (fail-safe: deny admission) — RETIRED",
        "RETIRED. The breaker classify path read a cell state that is not one of the three valid encodings (Closed/Open/HalfOpen). This is IMPOSSIBLE under the atomic-sentinel invariant, so reaching it means a real invariant break or memory corruption. busbar fails SAFE — treats the cell as never-elapsing Open so admission is denied — rather than panic the dispatching task. Warned once per process; recurrence logs at debug.",
        "Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.";

    /// RETIRED before 1.6.0 shipped: the kernel's own breaker state machine that raised this code is deleted and the kernel runs on the one breaker, which logs nothing. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    BREAKER_UNEXPECTED_STATE_PROBE = 5042, Proxy, Actionable, "breaker-unexpected-state-probe", "1.6.0", true,
        "Unexpected breaker state on probe acquisition (fail-safe: refuse) — RETIRED",
        "RETIRED. The breaker probe-acquisition path read an unexpected cell state (not Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar refuses the probe acquisition (admits nobody) rather than panic the dispatching task. Same invariant-break family as BUSBAR-5041. Warned once per process; recurrence logs at debug.",
        "Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.";

    /// RETIRED before 1.6.0 shipped: the kernel's own breaker state machine that raised this code is deleted and the kernel runs on the one breaker, which logs nothing. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    BREAKER_UNEXPECTED_STATE_READ = 5043, Proxy, Actionable, "breaker-unexpected-state-read", "1.6.0", true,
        "Unexpected breaker state on state read (reporting Closed) — RETIRED",
        "RETIRED. A breaker cell state read (a total, side-effect-free projection) found an unexpected encoding. Impossible under the atomic-sentinel invariant; busbar reports the benign Closed default rather than panic, keeping the read total for any encoding. Same family as BUSBAR-5041. Warned once per process; recurrence logs at debug.",
        "Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.";

    /// RETIRED before 1.6.0 shipped: the kernel's own breaker state machine that raised this code is deleted and the kernel runs on the one breaker, which logs nothing. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    BREAKER_UNEXPECTED_STATE_RECORD_FAILURE = 5044, Proxy, Actionable, "breaker-unexpected-state-record-failure", "1.6.0", true,
        "Unexpected breaker state in record_failure (no-op) — RETIRED",
        "RETIRED. The breaker failure-recording path read an unexpected cell state (not Closed/Open/HalfOpen). Impossible under the atomic-sentinel invariant; busbar treats it as a no-op (like the already-Open case) rather than panic the task. Same family as BUSBAR-5041. Warned once per process; recurrence logs at debug.",
        "Nothing emits this code. The one breaker keeps its cell state behind a lock and answers an unreachable encoding silently, with the same fail-safe result.";

    PLUGINS_DIR_FINGERPRINT_FAILED = 6004, Plugins, BenignRecurring, "plugins-dir-fingerprint-failed", "1.6.0", false,
        "Cannot fingerprint the plugins dir (bypassing the catalog cache)",
        "A real I/O error (not a missing directory) meant the plugins directory could not be fingerprinted, so its content-hash freshness signal cannot be trusted and busbar bypasses the catalog cache for this read, falling through to the real scan. Self-healing: it clears once the directory is readable. Warned once on entry to the failing state; recurrence logs at debug.",
        "Investigate the plugins directory's readability (permissions, a stale/hung mount). The catalog read still works via the direct scan; the cache re-engages once the directory fingerprints cleanly again.";

    PLUGIN_CATALOG_SCAN_GATE_TIMEOUT = 6005, Plugins, Actionable, "plugin-catalog-scan-gate-timeout", "1.6.0", false,
        "Plugin catalog scan gate not acquired within the wait bound (retryable 503)",
        "A plugin catalog scan could not acquire the scan gate within its bounded wait, which signals a PRIOR scan is not returning — typically a stale or hung plugins_dir mount. busbar answers with a retryable Unavailable (503) rather than hang this request behind the wedged scan.",
        "Investigate the plugins_dir mount — a hung scan usually means the directory's filesystem is stalled (e.g. an unresponsive network mount). Resolve the mount; the gate frees once the prior scan returns or is unwedged.";

    PLUGIN_CATALOG_BLOCKING_TASK_FAILED = 6006, Plugins, Actionable, "plugin-catalog-blocking-task-failed", "1.6.0", false,
        "Plugin catalog blocking task failed to join (fail-soft to the compiled-in row)",
        "The plugin catalog store scan ran on a `spawn_blocking` task that failed to join (cancelled or panicked). busbar fails SOFT to the always-true compiled-in catalog row rather than a 500 — this is just a plugin CATALOG read — the same posture it takes on an unparseable plugins_cfg. Rare.",
        "Investigate the logged context if it recurs — a blocking-task join failure on the catalog read is unusual. The catalog is served fail-soft in the meantime, so the admin read still returns.";

    PLUGIN_ROLLBACK_PIN_PERSIST_FAILED = 6007, Plugins, Actionable, "plugin-rollback-pin-persist-failed", "1.6.0", false,
        "Plugin rollback could not persist the version pin (nothing swapped, fail-closed)",
        "A plugin rollback tried to persist the lowered version pin to the config overlay and the write failed, so busbar FAILS CLOSED and swaps nothing — the running engine still serves the current plugin. Persisting the pin is the whole point of the rollback: a swallowed failure would swap the live engine while disk still carried the rolled-forward state, so a restart would silently re-upgrade.",
        "Investigate the config overlay's writability (the log names the plugin). Fix the overlay path/permissions and re-issue the rollback; nothing was changed, so it is safe to retry.";

    PLUGIN_ROLLBACK_REVERT_FAILED = 6008, Plugins, Actionable, "plugin-rollback-revert-failed", "1.6.0", false,
        "Plugin rollback rebuild failed AND reverting the version pin failed (disk out of sync)",
        "A plugin rollback's rebuild failed AFTER the lowered pin was persisted, and the compensating revert of that pin ALSO failed, so disk now carries the rolled-forward pin while the running engine still serves the prior plugin. A restart would honor the stale on-disk pin and contradict the running engine. Loud because disk and the live engine now disagree.",
        "Fix the config overlay so the version pin matches the plugin the running engine serves BEFORE restarting (the log names the plugin and both errors). Until then a restart would come up in a state the running engine rejected.";

    /// `--print-metadata-blocklist` could not read/parse config, so it printed the built-in denylist only.
    CLI_METADATA_BLOCKLIST_CONFIG_UNREADABLE = 3014, Config, Actionable, "cli-metadata-blocklist-config-unreadable", "1.6.0", false,
        "--print-metadata-blocklist printed the built-in denylist only (config unreadable)",
        "`busbar --print-metadata-blocklist` could not parse or env-interpolate config.yaml, so it printed the HARDCODED cloud-metadata denylist ALONE and skipped the operator's `security.blocked_metadata_hosts` additions. The list shown is therefore INCOMPLETE — it omits whatever the config would have added — even though the running gateway (once it boots on a valid config) would enforce the full union.",
        "Run `busbar` (or `busbar --validate`) normally to see the precise parse/interpolation error, fix config.yaml, then re-run the flag to see the full effective denylist. The error itself is not echoed here because it could quote a config value.";

    /// `--validate` found config.yaml/providers.yaml invalid (load, resolve, semantic, or secret phase).
    CLI_VALIDATE_CONFIG_INVALID = 3015, Config, Actionable, "cli-validate-config-invalid", "1.6.0", false,
        "--validate rejected the config (load, resolve, semantic, or secret-resolution failure)",
        "`busbar --validate` ran the exact load → resolve → semantic-validate → strict-secret pipeline boot runs and the config did NOT pass at one of those phases, so it exits non-zero. Because `--validate` mirrors boot, this same config would fail to boot the gateway. The specific phase and offending entries are printed alongside this code.",
        "Fix the reported errors in config.yaml / providers.yaml (a parse/structure error, a cross-reference the resolver rejected, a semantic-validation failure, or an unset required secret) and re-run `--validate` until it reports `ok`.";

    /// `--list-plugins` could not read config, so it inventoried using the default plugins block.
    CLI_LIST_PLUGINS_CONFIG_UNREADABLE = 3016, Config, Actionable, "cli-list-plugins-config-unreadable", "1.6.0", false,
        "--list-plugins fell back to the default plugins block (config unreadable)",
        "`busbar --list-plugins` could not read/parse config.yaml, so it inventoried the plugins directory using the DEFAULT `plugins:` block (default dir and trust policy) rather than the deployment's configured one. The inventory shown may not reflect the directory, trust policy, or store selection the running gateway would actually use.",
        "This is informational and best-effort pre-deployment. To inventory against the real config, fix config.yaml so it parses (run `busbar --validate` to see the error) and re-run `--list-plugins`.";

    /// GET /config/settings read the overlay while unreadable/corrupt and reported NO root overrides.
    CONFIG_SETTINGS_OVERLAY_UNREADABLE = 3017, Config, Actionable, "config-settings-overlay-unreadable", "1.6.0", false,
        "Config-settings read found the overlay unreadable/corrupt (reported no root overrides)",
        "A `GET /config/settings` read found the persisted config overlay present but unreadable/corrupt, so it returned an EMPTY set of root overrides. Nothing is mutated, but the response cannot be distinguished from a genuine \"no overrides set\" — the operator's stored single-value overrides may exist on disk yet be absent from this answer.",
        "Fix or remove the corrupt overlay file to restore durable reads (see BUSBAR-3005 for the boot-time counterpart). Until then this endpoint under-reports the stored root settings.";

    /// GET /config/settings read the overlay written by a NEWER busbar and reported NO root overrides.
    CONFIG_SETTINGS_OVERLAY_VERSION_TOO_NEW = 3018, Config, Actionable, "config-settings-overlay-version-too-new", "1.6.0", false,
        "Config-settings read found a newer-busbar overlay (reported no root overrides)",
        "A `GET /config/settings` read found the config overlay was written by a NEWER busbar than this binary, so — rather than misrepresent fields it cannot parse — it returned an EMPTY set of root overrides. The response cannot be distinguished from a genuine \"no overrides set\", so stored overrides may exist yet be absent from this answer.",
        "Read config settings from a busbar at least as new as the one that wrote the overlay, or roll the overlay back to a version this binary understands (see BUSBAR-3006 for the boot-time counterpart).";

    /// The spawn_blocking task backing GET /config/settings panicked or the runtime is shutting down.
    CONFIG_SETTINGS_READ_TASK_JOIN_FAILED = 3019, Config, Actionable, "config-settings-read-task-join-failed", "1.6.0", false,
        "Config-settings overlay read task failed to join (500 rather than a fabricated 200)",
        "The blocking task that reads the config overlay for `GET /config/settings` failed to join — it panicked, or the runtime is shutting down — so busbar returns 500 rather than a fabricated empty-settings 200 that would misreport \"no overrides set\" when the read never completed. A panic here is a bug.",
        "Retry the request; a shutdown-race clears on its own. A repeatable failure is a panic in the overlay read path — capture the logged join error and file a bug.";

    /// The nuclear `allow_all_metadata` is set: the cloud-metadata SSRF guard is OFF. Security posture.
    METADATA_PROTECTION_DISABLED = 5045, Proxy, Actionable, "metadata-protection-disabled", "1.6.0", false,
        "Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set)",
        "The deployment set the nuclear `allow_all_metadata` escape hatch, so busbar's cloud-metadata SSRF guard is OFF and EVERY cloud-metadata endpoint (e.g. 169.254.169.254, the GCP/Azure metadata hosts) is reachable through the proxy. That is a security-relevant degradation: a crafted upstream URL or a compromised plugin can reach the instance's credential endpoint. Emitted once at boot.",
        "Remove `allow_all_metadata` unless a specific, understood need requires it. If metadata access is genuinely needed, scope it with `security.blocked_metadata_hosts` instead of disabling the guard wholesale (`--print-metadata-blocklist` shows the effective list).";

    /// `--validate`'s plugin pre-flight (the exact pipeline boot runs) failed. Plugin-trust subject.
    CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED = 6009, Plugins, Actionable, "cli-validate-plugin-preflight-failed", "1.6.0", false,
        "--validate plugin pre-flight failed (structure, trust, conflict, or store resolution)",
        "`busbar --validate` ran the same plugin pre-flight boot runs — consistency, trust-policy resolution, the three-phase scan of every tarball (structural → trust → conflict), and store resolution — and it FAILED. Because this is the boot pipeline (manifest-only, no dlopen), the same plugin set would fail the plugin half of boot.",
        "Fix the reported plugin problem: a malformed manifest, a signature/trust-policy rejection, an ABI-floor or version-floor violation, a name/alias conflict, or an unresolvable `store.module`. Re-run `--validate` until it reports `ok`.";

    /// `--list-plugins` could not build a trust policy from `plugins.trust` — the config is invalid.
    CLI_LIST_PLUGINS_TRUST_INVALID = 6010, Plugins, Actionable, "cli-list-plugins-trust-invalid", "1.6.0", false,
        "--list-plugins could not build a trust policy (plugins.trust is invalid)",
        "`busbar --list-plugins` could not compile a trust policy from the `plugins.trust` block (e.g. an unparsable trust anchor or a malformed policy), so it cannot compute per-tarball signature verdicts and exits non-zero. The running gateway would reject this same `plugins.trust` at boot.",
        "Fix the `plugins.trust` block (the logged error names the problem), then re-run `--list-plugins` or `--validate`.";

    /// The persisted first-party anti-downgrade floor could not be READ, so the node boots with none.
    PLUGIN_FIRSTPARTY_FLOOR_UNREADABLE = 6011, Plugins, Actionable, "plugin-firstparty-floor-unreadable", "1.6.0", false,
        "First-party anti-downgrade floor unreadable (booting with NO first-party floor)",
        "The persisted per-plugin-name high-water marks — the automatic first-party anti-downgrade floor — could not be read or were not valid, so busbar booted with NO first-party floor. Security-relevant: while the floor is absent, a validly-signed but OLD first-party artifact planted in the plugins directory would load without being refused as a downgrade. The floor re-establishes itself as plugins load successfully. busbar fails SOFT here on purpose: refusing the boot would let anyone able to corrupt one file take the node down.",
        "Check the data directory is readable and that `plugin-highwater.json` beneath it is intact (the log names the path and the exact problem). Deleting the file is safe — the floor rebuilds from the next successful load — but it does re-open the replay window until it does.";

    /// The first-party anti-downgrade floor could not be PERSISTED; it still applies to this process.
    PLUGIN_FIRSTPARTY_FLOOR_UNWRITABLE = 6012, Plugins, Actionable, "plugin-firstparty-floor-unwritable", "1.6.0", false,
        "First-party anti-downgrade floor could not be persisted (it will not survive a restart)",
        "busbar raised the per-plugin-name high-water marks — the automatic first-party anti-downgrade floor — but could not write them to the data directory. The floor still applies to THIS process; it will not survive a restart, so the replay window reopens at the next boot until a load re-establishes it.",
        "Make the configured data directory writable (the log names the underlying I/O error). A node that cannot write its data directory usually has a larger problem than this notice.";

    /// A group `/usage` read could not derive a bucket's usage from the governance store. Read-path fault.
    GROUP_USAGE_READ_FAILED = 8018, Governance, Actionable, "group-usage-read-failed", "1.6.0", false,
        "Group usage read failed (could not derive a bucket's usage from the governance store)",
        "An admin group `/usage` read could not derive a bucket's usage from the governance store (a store read error while computing enforcement-matched spend), so the request returns 500 rather than a partial or understated usage view. No governance state is mutated; the read simply could not complete for the named group/bucket.",
        "Investigate the governance store's health for the logged group and bucket (reachability, the underlying store error). The condition is a read-path fault; usage reads recover once the store answers.";

    /// A boot-time fatal error: the binary printed a one-line reason and exited non-zero (`die`).
    BOOT_FATAL_ERROR = 9007, Boot, Fatal, "boot-fatal-error", "1.6.0", false,
        "Boot refused (fatal misconfiguration or startup error; process exits non-zero)",
        "The binary hit a fatal startup condition — a misconfiguration or other boot-time failure the process cannot serve past — so it printed a single-line reason to stderr and exited non-zero rather than a Rust panic backtrace. The specific reason is printed alongside this code. This is a deliberate refusal, not a crash.",
        "Read the printed reason, fix the underlying config/environment problem, and restart. `busbar --validate` reproduces most boot refusals without binding a listener.";

    /// An explicitly-set worker-thread count (env or config) is not a positive integer; default used.
    WORKER_THREADS_INVALID = 9008, Boot, Actionable, "worker-threads-invalid", "1.6.0", false,
        "Configured worker-thread count is invalid (ignored; default used)",
        "An explicitly-set data-plane worker count — `TOKIO_WORKER_THREADS`/`advanced.worker_threads` — is not a positive integer (e.g. `0`, or non-numeric), so busbar IGNORES it and boots on the default worker count (one per core). The operator's intended worker count is NOT in effect. Emitted pre-tracing, to stderr, at boot.",
        "Set the data-plane worker count to a positive integer (at least 1) or remove it to accept the default. The gateway runs, but on the default worker count, not the value provided.";

    /// A shutdown-signal handler could not be installed; that signal will not trigger graceful drain.
    SHUTDOWN_SIGNAL_HANDLER_INSTALL_FAILED = 9009, Boot, Actionable, "shutdown-signal-handler-install-failed", "1.6.0", false,
        "Shutdown-signal handler not installed (that signal won't trigger graceful drain)",
        "A graceful-shutdown signal handler (SIGINT/ctrl_c, SIGTERM on unix, or CTRL_CLOSE/CTRL_SHUTDOWN on Windows) failed to register. busbar fails soft — that one branch parks forever so the others still trigger the drain — but a stop delivered ONLY via the failed signal will kill the process without draining in-flight requests.",
        "Investigate the logged registration error (an unusual sandbox or signal-handling environment). Other shutdown signals still drain; if the affected signal is your deployment's stop path, restart in an environment where it can register.";

    /// The jemalloc idle-purge fallback could not start; a fully idle process may hold freed RSS.
    JEMALLOC_IDLE_PURGE_FALLBACK_UNAVAILABLE = 9010, Boot, Actionable, "jemalloc-idle-purge-fallback-unavailable", "1.6.0", false,
        "jemalloc idle-purge fallback unavailable (idle RSS may not return to the OS)",
        "The fallback idle-purge helper (for targets where jemalloc's background purge threads are compiled out, e.g. static-musl or macOS) could not start — its worker thread failed to spawn, or it could not read `opt.dirty_decay_ms`. A fully IDLE process may therefore hold freed-but-unpurged dirty pages and its RSS can ratchet at the last burst's peak until traffic resumes. Request behavior is unaffected.",
        "Usually benign — RSS is reclaimed the moment traffic resumes, and under load the helper does nothing. If steady idle RSS on a musl/macOS build matters, investigate the logged spawn/mallctl error; the gateway serves normally regardless.";

    /// `--generate-signing-key` could not obtain OS entropy to mint an ed25519 key.
    SIGNING_KEY_GENERATION_FAILED = 9011, Boot, Actionable, "signing-key-generation-failed", "1.6.0", false,
        "--generate-signing-key could not mint a key (OS entropy source unavailable)",
        "`busbar --generate-signing-key` could not mint a fresh ed25519 signing secret because the OS entropy source was unavailable, so it printed nothing and exited non-zero. No key was generated and nothing was written.",
        "Retry on a host with a working RNG (`/dev/urandom` / `getrandom`). A persistent failure points at a broken or blocked entropy source in the environment.";
}

/// The page text (template + example) of every templated code the host knows: the catalog's own
/// [`TEXTS`] and the contract-owned codes the catalog re-exports.
pub fn all_texts() -> Vec<busbar_contract::diagnostic::ErrorText> {
    TEXTS
        .iter()
        .chain(busbar_contract::diagnostic::CONTRACT_TEXTS)
        .copied()
        .collect()
}

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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

/// Where every code's docs page lives: `<base>BUSBAR-NNNN`.
pub const ERROR_DOCS_BASE: &str = "https://getbusbar.com/docs/1.6/errors/";

/// A message a user or operator reads under `diag`: `BUSBAR-NNNN: <detail>. See <docs page>`.
/// The same shape `Diagnostic::coded` renders on the operator-error-codes registry.
pub fn coded(diag: &Diagnostic, detail: impl std::fmt::Display) -> String {
    let banner = diag.banner();
    format!("{banner}: {detail}. See {ERROR_DOCS_BASE}{banner}")
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
