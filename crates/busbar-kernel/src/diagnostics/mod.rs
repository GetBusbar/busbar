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
///
/// OPERATOR MESSAGES. An entry an operator reads as a message (a config refusal, a CLI error, a
/// migration warning) continues `=> constructor(placeholder, ..) "template"`, optionally followed
/// by `, example "<what triggers it>"` and `, detail "<the template filled in for it>"`. The
/// template has a `{name}` per argument and no trailing period; the constructor is the const's name
/// in lower case and lists the template's placeholders in order of first appearance. It becomes
/// `coded::<constructor>(..)`, which formats exactly that template (the compiler checks every
/// placeholder against the arguments) and renders `BUSBAR-NNNN: <text>. See <docs page>`; its
/// text and example land in [`TEXTS`] for the code's docs page. Call sites never spell a code, a
/// link or the template: they call the constructor.
macro_rules! diagnostics {
    ($($(#[$meta:meta])* $name:ident
        $(= $code:literal, $class:ident, $severity:ident, $slug:literal, $since:literal,
            $retired:literal, $title:literal, $summary:literal, $action:literal
            $(=> $ctor:ident($($arg:ident),*) $text:literal
                $(, example $example:literal)? $(, detail $detail:literal)?)?)?
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

        /// Typed constructors for the templated codes: `coded::<const name in lower case>(..)`
        /// builds the code's operator message from its catalog template.
        pub mod coded {
            $($($(
                #[doc = concat!(
                    "Builds the operator message of [`super::",
                    stringify!($name),
                    "`] from its catalog template."
                )]
                #[cold]
                #[must_use]
                pub fn $ctor($($arg: impl ::core::fmt::Display),*)
                    -> ::busbar_contract::diagnostic::Coded {
                    super::$name.coded(::core::format_args!($text $(, $arg = $arg)*))
                }
            )?)?)*
        }

        /// The page text of every templated host code, in the table's order.
        pub static TEXTS: &[::busbar_contract::diagnostic::ErrorText] = &[$($($(
            ::busbar_contract::diagnostic::ErrorText {
                code: $code,
                text: $text,
                example: concat!("" $(, $example)?),
                example_detail: concat!("" $(, $detail)?),
            },
        )?)?)*];
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
        "RETIRED. Serving no longer applies deprecated operational environment overrides. Move the provider, worker and upstream HTTP settings they set into config.yaml; old file-overlay selection is read only by the one-time upgrade boot.",
        "Run the 1.6 migration before serving, review and validate its output, then remove the retired variables from launchers. See docs/migration-1.6.md. See BUSBAR-3029.";

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

    /// An `advanced.allow_destinations` entry names a cloud-metadata destination, which no configuration admits.
    CONFIG_DESTINATION_NAMES_METADATA = 3134, Config, Fatal, "config-destination-names-metadata", "1.6.0", false,
        "An allowlist entry names a cloud-metadata destination",
        "An `advanced.allow_destinations` entry is a cloud-metadata host name (such as `metadata.google.internal`), a metadata address (such as `169.254.169.254`, `fd00:ec2::254` or an IPv6 link-local address), or a /32 or /128 network equal to one. Cloud metadata is refused for every outbound connection, in every egress class, and no configuration admits it, so the entry is refused at startup rather than silently ignored. A wider network that merely covers a metadata address (such as `169.254.0.0/16`) loads, and still never admits the metadata address.",
        "Remove the entry named in the message. A workload that needs cloud credentials uses workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file, never the instance metadata endpoint.";

    /// A retired 1.5.5 cloud-metadata carve-out key is set; no configuration admits cloud metadata.
    CONFIG_METADATA_CARVE_OUT_RETIRED = 3136, Config, Fatal, "config-metadata-carve-out-retired", "1.6.0", false,
        "A retired cloud-metadata carve-out key is set",
        "The configuration sets `security.allow_metadata_hosts`, `security.allow_all_metadata: true` or a provider's `allow_metadata_hosts`. In 1.6.0 cloud metadata is refused for every outbound connection, in every egress class, and no configuration admits it, so these 1.5.5 carve-outs are retired. The configuration is refused rather than read with the carve-out ignored. `security.blocked_metadata_hosts` still extends the denylist.",
        "Remove the keys. A workload that needs cloud credentials uses workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file, never the instance metadata endpoint.";

    /// The migration retired a registration's `allow_private` and listed exactly its hosts in `advanced.allow_destinations`.
    MIGRATE_PRIVATE_REACH_TO_ALLOWLIST = 3410, Config, Actionable, "migrate-private-reach-to-allowlist", "1.6.0", false,
        "A registration's allow_private was replaced by exact advanced.allow_destinations entries",
        "An MCP server (`tools.<server>`) or A2A agent (`agents.<agent>`) set the retired `allow_private`. The migration removed the key and listed exactly the hosts that registration dials in `advanced.allow_destinations` (never a wildcard or a network, never a cloud-metadata host). A plaintext `http://` registration to a non-loopback host is refused at 1.6.0: the planes admit `http://` to loopback only.",
        "Review the listed hosts. Move a non-loopback `http://` registration to `https://`; per-destination plaintext arrives after 1.6.0.";

    /// The migration removed a retired 1.5.5 cloud-metadata carve-out key.
    MIGRATE_METADATA_CARVE_OUT_REMOVED = 3411, Config, Actionable, "migrate-metadata-carve-out-removed", "1.6.0", false,
        "A retired cloud-metadata carve-out key was removed",
        "The migration removed `security.allow_metadata_hosts`, `security.allow_all_metadata` or a provider's `allow_metadata_hosts`, naming each removed entry. 1.6.0 refuses cloud metadata for every outbound connection and no configuration admits it; a destination the carve-out reached is now refused.",
        "If a removed entry reached an instance credential endpoint, move that workload to workload-identity federation (IRSA, AKS workload identity, GKE workload identity federation) through a projected token file.";

    /// A plugin declares a retired ABI value or need shape; the plugin or need is refused.
    PLUGIN_DECLARES_RETIRED_ABI_VALUE = 6017, Plugins, Fatal, "plugin-declares-retired-abi-value", "1.6.0", false,
        "A plugin declares a retired ABI value",
        "A plugin's Statement or need uses something the 1.6.0 ABI retired: the plane trust role `TRUST_PRIVATE_REACH` (4), or an operator-infrastructure need over a framed transport (`http`, `grpc`) that names no config-declared target (`target_from`). The operator-infrastructure class is a property of a target the operator configured, never a plugin's choice. The plugin (for a trust role) or the need is refused, naming what it declared. A carrier need (`tcp`, `unix`) without a declared target is deprecated and refused from 1.7.0.",
        "Upgrade the plugin to a release built against busbar 1.6.0. A plugin author drops the retired role, and declares `target_from` on an operator-infrastructure need.";

    /// A plugin call broke an ABI rule and was refused; flagged once per instance and audited.
    PLUGIN_CALL_REFUSED_ABI_RULE = 6014, Plugins, Actionable, "plugin-call-refused-abi-rule", "1.6.0", false,
        "A plugin call was refused by an ABI rule",
        "A plugin asked for something the ABI does not allow: `dest.judge` under the operator-infrastructure egress class (content-named hosts are judged in the default or open-web class), or a mid-stream upgrade offering a name that is not the dialled host (only a dial to an IP literal may offer another name). The call is refused; the first refusal per instance is logged and audited.",
        "Upgrade the plugin to a release built against busbar 1.6.0, or report the plugin to its author.";

    /// A plugin used a deprecated ABI value that is still honoured; flagged once per instance and audited.
    PLUGIN_USES_DEPRECATED_ABI_VALUE = 6015, Plugins, Actionable, "plugin-uses-deprecated-abi-value", "1.6.0", false,
        "A plugin used a deprecated ABI value (refused from 1.7.0)",
        "A plugin secured an operator-infrastructure connection with `UPGRADE_VERIFY_OFF`, so the far end's certificate is not verified (postgres `sslmode=prefer`, valkey `#insecure`). The value is honoured in 1.6.x, deprecated, and refused from 1.7.0. The first use per instance is logged and audited.",
        "Configure the server with a certificate the plugin can verify (`sslmode=require` or `verify-full`, `rediss://` without `#insecure`); the core trust store for private CAs arrives after 1.6.0.";

    /// A plane registration sets the retired `allow_private`; the one private-address policy is `advanced.allow_destinations`.
    CONFIG_PRIVATE_REACH_RETIRED = 3135, Config, Fatal, "config-private-reach-retired", "1.6.0", false,
        "A registration still carries the retired per-registration private-address switch",
        "A plane registration (an MCP server under `tools:`, an A2A agent under `agents:`) sets `allow_private`. 1.6.0 has one private-address policy for every outbound connection, `advanced.block_private_addresses` with `advanced.allow_destinations`; a per-registration switch that lifted it for one plugin is retired. The configuration is refused, naming the registration, rather than read with the switch ignored or applied.",
        "Delete `allow_private` and add the host (or its address) to `advanced.allow_destinations`. A cloud-metadata address stays refused whatever is listed.";

    /// A provider URL names a private or loopback host the destination guard refuses (1.5.5 upgrade).
    CONFIG_PROVIDER_DESTINATION_REFUSED = 3025, Config, Actionable, "config-provider-destination-refused", "1.6.0", false,
        "A provider URL names a private or loopback host the destination guard refuses",
        "A provider's `base_url` or `token_url` names a private or loopback address (an RFC 1918, loopback, link-local, CGNAT or unique-local literal, or the `localhost` name), and `advanced.block_private_addresses` is on (the default) and `advanced.allow_destinations` does not name it. The destination guard refuses every request to it, so the provider would fail on its first request rather than at startup. 1.5.5 had no such guard. Emitted once per URL at config load, naming the provider, the key and the host.",
        "Add exactly that host to `advanced.allow_destinations`, or point the provider at a public address. Turning `block_private_addresses` off also admits it, and every other private address with it.";

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

    /// An auth plugin states the operator credential but is not first-party; nothing references it.
    CONFIG_OPERATOR_INERT = 3030, Config, Actionable, "config-operator-inert", "1.6.0", false,
        "An auth plugin states the operator credential but is not first-party (ignored)",
        "An admitted auth plugin states the operator credential, but it is not first-party (not signed by a busbar release key), so it never becomes the operator credential. Nothing in the configuration references it, so it is ignored and the boot continues; each boot also writes an auth.operator.inert audit row naming it.",
        "Remove the plugin from plugins.dir, or narrow plugins.trust so it is not admitted. To make a plugin the operator credential, install the first-party operator credential plugin.";

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

    CONFIG_RESERVED_NAME in busbar_contract::diagnostic;

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

    /// --ignore-overlay boot: the config overlay was not merged; running on base config.yaml/providers.yaml alone.
    OVERLAY_IGNORED = 8012, Governance, Actionable, "safe-mode-overlay-quarantined", "1.6.0", false,
        "IGNORE OVERLAY: config overlay not merged (running on base config alone)",
        "busbar was booted with `--ignore-overlay`, so the persisted config overlay (API-registered hooks) was NOT merged and busbar is running on the operator-owned base config.yaml/providers.yaml alone. This is the intentional escape hatch for an applied hook that harms traffic and re-applies itself every boot. The overlay in the Store is untouched, not deleted. `GET /api/v1/admin/info` reports `overlay_ignored: true`.",
        "Operator-requested state. Repair or remove the offending overlay entry, then boot WITHOUT `--ignore-overlay`. An admin reload, apply or config write in this process re-merges the Store overlay and persists to it.";

    /// RETIRED before 1.6.0 shipped, superseded by [`PROVIDER_API_KEY_UNRESOLVABLE`]: the degrade this code described no longer exists. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened and what replaced it.
    PROVIDER_API_KEY_UNRESOLVED = 8013, Governance, Actionable, "provider-api-key-unresolved", "1.6.0", true,
        "Provider api_key did not resolve (degraded to an empty key) — RETIRED, see BUSBAR-8020",
        "RETIRED. A provider's `api_key` secret reference did not resolve at boot, so busbar degraded that provider to an empty key and started the lane anyway. 1.6.0 removed that degrade: an `api_key` that does not resolve now REFUSES BOOT (BUSBAR-8020), and an upstream that genuinely takes no credential is declared with `api_key: none`.",
        "Nothing emits this code. See BUSBAR-8020.";

    /// A provider api_key SecretRef did not resolve; boot refuses.
    PROVIDER_API_KEY_UNRESOLVABLE = 8020, Governance, Fatal, "provider-api-key-unresolvable", "1.6.0", false,
        "Provider api_key did not resolve (boot refuses)",
        "A provider's `api_key` secret reference could not be resolved — an unset environment variable, a missing file, a value or file that is empty or whitespace-only, an unknown module, or a secret plugin that failed — so busbar refuses to start. It does not fall back to an empty credential: that lane could never authenticate, would report healthy, would be skipped by the health prober (no key, no probe), and would answer every request routed to it with a 401 from the upstream. The diagnostic names the provider and the secret module (`secret module 'busbar-secret-env'`), never the value.",
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

    /// A plane member's upstream credential could not be refreshed; the held value is kept until its lease ends.
    UPSTREAM_CREDENTIAL_REFRESH_FAILED = 8026, Governance, Actionable, "upstream-credential-refresh-failed", "1.6.0", false,
        "A plane member's upstream credential could not be refreshed",
        "busbar renews each plane member's upstream_credential off the request path, at half its lease_ttl_ms (at most every five minutes). A renewal failed: the source could not be read (cause resolve: unavailable, internal fault, an empty or non-text value), or the value changed and the auth plugin refused the new one (cause reopen, at ERROR). The value already held is still presented until its lease ends, and the renewal is retried with a jittered backoff. Reported on the first failure, then at most once a minute per member (also after the lease has ended); members on the same source within that minute are counted in its others field. Each report is audited as upstream_credential.refresh, degraded. An A2A member whose lease ends meanwhile has its hops refused as BUSBAR-7013.",
        "Check the source the reference field names (the file, the environment variable or the secret module) and the error field. For cause reopen, the value at the source is one the auth plugin cannot present (for example a header value with illegal characters): correct it at the source. The next successful refresh logs that it refreshed again and is audited as applied.";

    /// A plane member's upstream credential is no longer presented: its lease ended unrenewed, or its source confirmed it revoked.
    UPSTREAM_CREDENTIAL_LAPSED = 8027, Governance, Actionable, "upstream-credential-lapsed", "1.6.0", false,
        "A plane member's upstream credential lapsed or was revoked at its source",
        "A plane member's upstream credential is no longer presented, so every hop on the member is refused (credential_unavailable; for an A2A member, BUSBAR-7013). Cause lease-expired: its lease_ttl_ms ran out with no successful refresh (reported when the lease ends, whether or not a hop arrives). Cause revoked-at-source: the source answered not-found or permission-denied twice, one second apart, so busbar dropped the credential at once instead of riding out an outage. Reported once per lapse and audited as upstream_credential.refresh, rejected. Refreshes continue; the first that succeeds presents the credential again.",
        "For revoked-at-source, this is expected after deleting the secret or removing busbar's access to it; restore it to resume. For lease-expired, see the BUSBAR-8026 lines for the member: they name the source and the error. A longer lease_ttl_ms rides out longer outages; a shorter one revokes faster.";

    /// A plugin instance's own rotated credential could not be applied; the running instance is kept.
    PLUGIN_CREDENTIAL_ROTATION_FAILED = 8028, Governance, Actionable, "plugin-credential-rotation-failed", "1.6.0", false,
        "A plugin's rotated credential could not be applied",
        "busbar re-reads the secret references a secret or auth plugin instance was opened with every 30 seconds. When one changed (a rotated token file, for example a workload-identity token), busbar hands the new material to the plugin's refresh, or, for a plugin with no refresh, opens a new instance from the same plugin artifact and swaps it in. This failed: the reference could not be re-read (cause unresolvable), the plugin refused the new material (cause refused, at ERROR), or the new instance did not open (cause reopen-failed, at ERROR). The running instance and the credentials it holds are kept and the change is retried on the next poll. Reported at most once a minute per instance and audited as plugin.credential.rotate, degraded; a later success is audited as applied.",
        "Check the reference and the error field. For refused or reopen-failed, the plugin rejected the rotated material: fix it at the source. If the old material expires first, the plugin's own calls fail until the new material is accepted.";

    PLUGIN_TICK_FAILED in busbar_contract::diagnostic;

    /// A store settings SecretRef does not resolve at boot; restart-to-apply, so it WILL fail next restart.
    STORE_SECRET_REF_UNRESOLVED = 8015, Governance, Actionable, "store-secret-ref-unresolved", "1.6.0", false,
        "Store settings hold a secret reference that does not resolve here",
        "A governance-store `settings` value holds a secret reference that does not resolve on this boot. busbar warns rather than fails, because the store is restart-to-apply and staging a ref whose secret the orchestrator mounts on the next deploy is a legitimate workflow. But if the secret is still absent at the next restart, THAT restart will fail in resolve_settings before serving.",
        "Ensure the named store secret reference resolves before the next restart. If you are staging it for an upcoming deploy, no action now; otherwise fix the reference so the next restart does not die resolving it.";

    /// The in-memory (ephemeral) governance store was selected; keys/usage/ledgers and admin config changes reset on restart.
    GOVERNANCE_STORE_EPHEMERAL = 8016, Governance, Actionable, "governance-store-ephemeral", "1.6.0", false,
        "Governance store is in-memory (ephemeral) — state resets on restart",
        "busbar selected the in-memory (ephemeral) governance store, so virtual keys, groups' usage, and ledgers live only in RAM and are LOST on restart. This is the default when no durable store plugin is configured — fine for a trial or local development, but not for anything that must retain keys or spend across restarts. Admin-API config changes are held in the same RAM: live ones apply until restart; restart-only ones (including creating or replacing an exporter) are refused, because the restart would discard them.",
        "Configure a durable governance store plugin for persistence if keys, usage, or budgets must survive a restart. No action is needed for ephemeral/dev use. To change a restart-only setting or add an exporter, edit config.yaml and restart.";

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

    SELF_MINT_HELD = 4043, Auth, BenignRecurring, "self-mint-held", "1.6.0", false,
        "Self-serve sign-in or refresh refused: the subject's key is on hold",
        "A self-serve sign-in (POST /auth/token or the hosted login) or a Refresh was refused because the subject's key is on hold: an administrator disabled it, an administrator revoked it, it was issued through a different identity provider, or the subject itself is held by a principal transition. Nothing is written: the key is not re-enabled, no sibling key is minted, and its old tokens stay dead. The caller gets a 403 that names the reason, and the admin audit log records `self_serve.mint` as `rejected` on `key:<id>#<reason>` (or `subject:<subject>#on_hold`). This is a client-side state, so it is emitted at debug.",
        "Nothing, if the hold is intended. To let the user back in: for a disabled key, PATCH /api/v1/admin/keys/{id} with `enabled: true` (the same key comes back and its earlier tokens work again). For a revoked key, or a key issued through another provider, DELETE /api/v1/admin/keys/{id}: the next sign-in issues a new key with a new id, and every old token stays dead. A revoked key is never re-enabled.";

    REVOKED_KEY_REENABLE_REFUSED = 4044, Auth, BenignRecurring, "revoked-key-reenable-refused", "1.6.0", false,
        "Admin request to re-enable a revoked key refused (revoked is terminal)",
        "A PATCH /api/v1/admin/keys/{id} asked for `enabled: true` on a revoked key. Revoked is terminal: no admin request, sign-in or refresh ever re-enables a revoked key. The request is answered 409 `conflict` with this code, nothing is written, and the admin audit log records `key.patch` as `rejected`. This is a client-side request, so it is emitted at debug.",
        "Leave the key revoked. To give a self-serve user a working key again, DELETE the revoked key: their next sign-in issues a new key with a new id. For an admin-minted key, mint a new one.";

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

    /// `--list-plugins` refused: the config file exists but could not be read, parsed or env-substituted (no inventory against the default plugins block).
    CLI_LIST_PLUGINS_CONFIG_UNREADABLE = 3016, Config, Actionable, "cli-list-plugins-config-unreadable", "1.6.0", false,
        "--list-plugins refused a config that exists but is not readable",
        "`busbar --list-plugins` found a config file at the resolved path that could not be read, parsed or env-substituted, so it refuses (exit 1) rather than inventory the DEFAULT `plugins:` block (default dir and trust policy), which would describe a directory other than the one the deployment configures. The default block is used only when no config file exists at that path (a bare inventory).",
        "Fix config.yaml so it parses (run `busbar --validate` to see the error) and re-run `--list-plugins`, or point `--config` at the right file.";

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

    /// RETIRED in 1.6.0: `allow_all_metadata` is refused (BUSBAR-3136), so the cloud-metadata guard is never off.
    METADATA_PROTECTION_DISABLED = 5045, Proxy, Actionable, "metadata-protection-disabled", "1.6.0", true,
        "Cloud-metadata SSRF protection DISABLED (allow_all_metadata is set) — RETIRED",
        "RETIRED. Nothing emits this code: 1.6.0 refuses `security.allow_all_metadata` at startup (BUSBAR-3136), and cloud metadata is refused for every outbound connection, so the guard can no longer be disabled.",
        "Nothing emits this code. See BUSBAR-3136.";

    /// A unit the provider answered settled without billing its final stated usage. Money: reconcile.
    PLANE_USAGE_UNREAD = 5046, Proxy, Actionable, "plane-usage-unread", "1.6.0", false,
        "Provider usage not read (a unit settled without billing its final stated usage)",
        "A unit the provider answered settled without billing its final stated usage; `reason` names the ReasonCode that ended it (deadline, drain/reload, unpriced, over-budget, far cut, body cap, plane fault, destination unreachable, client gone before fold). The unit's ledger line bills the last usage report busbar accepted, and its terminal checkpoint record carries the same `unread` reason. Emitted once per affected unit, with an audit row under the same slug.",
        "Reconcile the line against the provider's usage report: the provider may have charged more than the line bills.";

    /// A pool's ordering policy made no choice while no member has a known routing cost; the walk is SWRR. Warn-once per policy@pool.
    ROUTING_POLICY_ABSTAINED_UNPRICED = 5050, Proxy, Actionable, "routing-policy-abstained-unpriced", "1.6.0", false,
        "Routing policy made no choice and no member has a known routing cost",
        "The pool's ordering policy made no choice and no member has a known routing cost; the pool uses weighted round-robin. Gates never report this. Warned once per policy and pool until the policy ranks that pool again.",
        "If the policy ranks by cost, price every member's lane in rate_card; a named hook also needs `signals: [candidate_route_cost]`.";

    /// `--validate`'s plugin pre-flight (the exact pipeline boot runs) failed. Plugin-trust subject.
    CLI_VALIDATE_PLUGIN_PREFLIGHT_FAILED = 6009, Plugins, Actionable, "cli-validate-plugin-preflight-failed", "1.6.0", false,
        "--validate plugin pre-flight failed (structure, trust, conflict, or store resolution)",
        "`busbar --validate` ran the same plugin pre-flight boot runs — consistency, trust-policy resolution, the three-phase scan of every tarball (structural → trust → conflict), and store resolution — and it FAILED. Because this is the boot pipeline (manifest-only, no dlopen), the same plugin set would fail the plugin half of boot.",
        "Fix the reported plugin problem: a malformed manifest, a signature/trust-policy rejection, an ABI-floor or version-floor violation, a name/alias conflict, or a `store.module` that names no installed store plugin (the published binary links no store: install a plugin of kind `store` and select it by its name). Re-run `--validate` until it reports `ok`.";

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

    /// Plugin-supplied text over its cap was cut. Fields and caps: a hook reject message (`reject_message`, 300), a metric `help` (`metric_help`, 200), `label` (`metric_label`, 64), `unit` (`metric_unit`, 16) or label value (`metric_label_value`, 64), and a plugin diagnostic message (`diag_message`, 300) or field value (`diag_field`, 64). The `plugin` field is the configured hook instance name for a reject or a hook status read, and the plugin module name for a metric or diagnostic a plugin reported. `busbar_plugin_text_cut_total{plugin,field}` counts over-cap values received in plugin and hook replies (counted at parse, including values in metrics later refused).
    PLUGIN_TEXT_CUT = 6013, Plugins, Actionable, "plugin-text-cut", "1.6.0", false,
        "Plugin-supplied text exceeded its cap and was cut",
        "A plugin or hook sent text longer than its documented cap: a hook reject message, a metric help, label, unit or label value, or a plugin diagnostic message or field. busbar kept the first `cap` sanitised characters exactly as 1.5.5 did, with nothing appended (for a reject whose kept text is all whitespace, clients see the default reject message instead). This warning fires once per plugin and field for the life of the process; `busbar_plugin_text_cut_total{plugin,field}` counts over-cap values received in plugin and hook replies (counted at parse, including values in metrics later refused).",
        "Shorten the named plugin's text for the named field to within the cap; the log gives the cap and the text's length after sanitising (control and format characters removed).";

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

    CLI_UNRECOGNIZED_ARGUMENT = 9101, Boot, Fatal, "cli-unrecognized-argument", "1.6.0", false,
        "The command line names an argument busbar does not know",
        "busbar was started with an argument that is neither a flag it accepts nor the value of one. Nothing ran; the process exited with the usage status (2).",
        "Check the spelling against `busbar --help`. Configuration is not passed on the command line: put settings in config.yaml and point busbar at it with `--config <path>`."
        => cli_unrecognized_argument(argument) "unrecognized argument '{argument}'; try 'busbar --help'",
        example "busbar --valdiate",
        detail "unrecognized argument '--valdiate'; try 'busbar --help'";

    CLI_INVALID_ARGUMENTS = 9102, Boot, Fatal, "cli-invalid-arguments", "1.6.0", false,
        "A command's arguments do not fit together",
        "A command-line command (a principal transition) was given arguments it cannot act on: a missing companion flag, a conflicting pair, or a malformed value. The text after the code names which. Nothing ran; the process exited with the usage status (2).",
        "Fix the arguments the message names; `busbar --help` lists every command with its flags."
        => cli_invalid_arguments(reason) "{reason}; try 'busbar --help'",
        example "busbar --principal-transition",
        detail "principal transition flags require explicit values; try 'busbar --help'";

    CLI_FLAG_REQUIRES_VALUE = 9103, Boot, Fatal, "cli-flag-requires-value", "1.6.0", false,
        "A command-line flag is missing its value",
        "A flag that takes a value (such as `--config <path>` or `--providers <path>`) was the last argument, so it has nothing to read. Nothing ran; the process exited with the usage status (2).",
        "Give the flag its value, for example `busbar --config /etc/busbar/config.yaml --validate`."
        => cli_flag_requires_value(flag) "{flag} requires a value; try 'busbar --help'",
        example "busbar --validate --config",
        detail "--config requires a value; try 'busbar --help'";

    /// A plane claims bytes on a transport protocol that no installed or admitted transport provides.
    COMPOSITION_TRANSPORT_UNPROVIDED = 9201, Boot, Fatal, "composition-transport-unprovided", "1.6.0", false,
        "A plane needs a transport protocol that no installed transport provides",
        "A plane serves on a transport protocol (the admin plane serves on `http`, for example). Busbar itself provides no transport: every protocol comes from a plugin of kind `transport`, linked into the build or installed in `plugins.dir` and admitted at boot. No installed or admitted transport provides the protocol the message names, so the plane could never receive a request, and busbar refused to start rather than serve without it. This describes the deployment's installed plugins, not a fault in the binary. Nothing was served; the process exited with status 2.",
        "Install a transport plugin that provides the protocol the message names (a signed plugin of kind `transport` in `plugins.dir`), then restart. `busbar --list-plugins` lists the installed plugins and whether each one was admitted."
        => composition_transport_unprovided(plane, transport) "plane `{plane}` needs a transport of kind `transport` that provides the protocol `{transport}`, and none is installed or admitted; install a transport plugin that provides `{transport}`",
        example "busbar --config /etc/busbar/config.yaml",
        detail "plane `admin` needs a transport of kind `transport` that provides the protocol `http`, and none is installed or admitted; install a transport plugin that provides `http`";

    /// RETIRED in 1.6.0: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    MIGRATE_PATH_MISSING = 3401, Config, Fatal, "migrate-path-missing", "1.6.0", true,
        "The retired migration command was given no file to migrate — RETIRED",
        "RETIRED. Nothing emits this code: the retired migration command is gone in 1.6.0; the first boot of a 1.5.5 config migrates it in place and keeps a `config.yaml.1.5.5` backup beside it. The number is kept so a log line from a pre-release build still resolves to this page.",
        "Nothing emits this code. Start busbar on the 1.5.5 config.yaml; the boot migrates it. See docs/migration-1.6.md.";

    /// RETIRED in 1.6.0: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    MIGRATE_SOURCE_UNREADABLE = 3402, Config, Fatal, "migrate-source-unreadable", "1.6.0", true,
        "The retired migration command could not read the file it was given — RETIRED",
        "RETIRED. Nothing emits this code: the retired migration command is gone in 1.6.0; the first boot of a 1.5.5 config migrates it in place and keeps a `config.yaml.1.5.5` backup beside it. The number is kept so a log line from a pre-release build still resolves to this page.",
        "Nothing emits this code. Start busbar on the 1.5.5 config.yaml; the boot migrates it. See docs/migration-1.6.md.";

    /// RETIRED in 1.6.0: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    MIGRATE_LAUNCH_DIRECTORY = 3403, Config, Fatal, "migrate-launch-directory", "1.6.0", true,
        "The retired migration command could not resolve its working directory — RETIRED",
        "RETIRED. Nothing emits this code: the retired migration command is gone in 1.6.0; the first boot of a 1.5.5 config migrates it in place and keeps a `config.yaml.1.5.5` backup beside it. The number is kept so a log line from a pre-release build still resolves to this page.",
        "Nothing emits this code. Start busbar on the 1.5.5 config.yaml; the boot migrates it. See docs/migration-1.6.md.";

    /// RETIRED in 1.6.0: nothing emits it. The number is kept so a log line from a pre-release build still resolves to an entry that says what happened.
    MIGRATE_FAILED = 3404, Config, Fatal, "migrate-failed", "1.6.0", true,
        "The retired migration command refused the file — RETIRED",
        "RETIRED. Nothing emits this code: the retired migration command is gone in 1.6.0; the first boot of a 1.5.5 config migrates it in place and keeps a `config.yaml.1.5.5` backup beside it. The number is kept so a log line from a pre-release build still resolves to this page.",
        "Nothing emits this code. Start busbar on the 1.5.5 config.yaml; the boot migrates it. See docs/migration-1.6.md.";

    MIGRATE_REFRESH_TTL_MEANING_CHANGED = 3405, Config, Actionable, "migrate-refresh-ttl-meaning-changed", "1.6.0", false,
        "Migration carried refresh_ttl over to verify_ttl, whose meaning differs",
        "1.5's `refresh_ttl` was a background sweep cadence (default 6h). Its replacement `verify_ttl` is the longest a cached tool listing may be served before a `tools/call` re-verifies the upstream live (default 5s). The migration carried your value over unchanged, which can leave a long drift-serving window on the request path.",
        "Review the migrated `verify_ttl`: a few seconds is the default, `0` is strict-live, and a large value is an explicit security downgrade."
        => migrate_refresh_ttl_meaning_changed(entry, value) "{entry}.refresh_ttl -> verify_ttl (value `{value}` carried over). The meaning CHANGED: `refresh_ttl` was a background sweep cadence (default 6h); `verify_ttl` is the MAX staleness before a `tools/call` re-verifies the upstream live (default 5s). Your value is now a drift-serving window on the request path — reconsider it: a few seconds is the new default, `0` is strict-live, and a large value is an explicit security downgrade",
        example "mcp_servers:\n  search:\n    refresh_ttl: 6h",
        detail "mcp_servers.search.refresh_ttl -> verify_ttl (value `6h` carried over). The meaning CHANGED: `refresh_ttl` was a background sweep cadence (default 6h); `verify_ttl` is the MAX staleness before a `tools/call` re-verifies the upstream live (default 5s). Your value is now a drift-serving window on the request path — reconsider it: a few seconds is the new default, `0` is strict-live, and a large value is an explicit security downgrade";

    MIGRATE_ADMIN_SCOPE_WIDENED = 3406, Config, Actionable, "migrate-admin-scope-widened", "1.6.0", false,
        "Migration widened a retired delegated admin scope to full",
        "1.5.2 retired the delegated admin scopes. An auth chain entry or role binding that granted one is migrated to `full`, the nearest scope that keeps every call it allowed working, which may be broader than intended.",
        "Review the named entry and tighten it to `read-only` if `full` is too broad."
        => migrate_admin_scope_widened(entry, old) "{entry}: {old} -> full (the delegated {old} scope is retired in 1.5.2; tighten to read-only if full is too broad)",
        example "auth:\n  admin_auth:\n    - oidc: { max_admin_scope: keys }",
        detail "auth.admin_auth entry 'oidc' max_admin_scope: keys -> full (the delegated keys scope is retired in 1.5.2; tighten to read-only if full is too broad)";

    MIGRATE_EMPTY_ALLOWED_POOLS_FLIPPED = 3407, Config, Actionable, "migrate-empty-allowed-pools-flipped", "1.6.0", false,
        "An empty allowed_pools list now means no pools",
        "Before 1.5.0 an empty `allowed_pools: []` on a role binding meant every pool; since 1.5.0 it means no pool. The migration keeps the list as written, so the role now reaches nothing.",
        "If the role should reach every pool, delete the `allowed_pools` line (omitted means all). If it should reach none, keep `[]`."
        => migrate_empty_allowed_pools_flipped(module, role) "auth.role_bindings.{module}.{role}.allowed_pools: [] - the MEANING of an empty list FLIPPED in 1.5.0: it used to mean ALL pools, it now means NO pools. If this role should reach every pool, DELETE the allowed_pools line (omitted = all); if it should reach none, keep []",
        example "auth:\n  role_bindings:\n    oidc:\n      engineers: { allowed_pools: [] }",
        detail "auth.role_bindings.oidc.engineers.allowed_pools: [] - the MEANING of an empty list FLIPPED in 1.5.0: it used to mean ALL pools, it now means NO pools. If this role should reach every pool, DELETE the allowed_pools line (omitted = all); if it should reach none, keep []";

    MIGRATE_UNGOVERNED_BINDING_ADDED = 3408, Config, Actionable, "migrate-ungoverned-binding-added", "1.6.0", false,
        "Migration added a binding that keeps 1.5.5's ungoverned access",
        "1.5.5 admitted a principal its identity provider recognised even when no role binding granted it anything; 1.6.0 refuses such a principal (401). To keep a migrated deployment serving the same callers, the migration wrote an empty binding for them: every pool, no group, no budget.",
        "Tighten the named binding (allowed_pools, a group with limits) or remove it to refuse those principals."
        => migrate_ungoverned_binding_added(provider, role, who) "auth.role_bindings.{provider}.\"{role}\" was written by the migration to keep 1.5.5's access: {who} is admitted on every pool with no budget, as 1.5.5 admitted them. Tighten it (allowed_pools, a group with limits) or remove it to refuse them",
        example "auth:\n  auth_chain: [oidc]",
        detail "auth.role_bindings.oidc.\"*\" was written by the migration to keep 1.5.5's access: every principal it identifies is admitted on every pool with no budget, as 1.5.5 admitted them. Tighten it (allowed_pools, a group with limits) or remove it to refuse them";

    MIGRATE_WORKER_THREADS_IGNORED = 3409, Config, Actionable, "migrate-worker-threads-ignored", "1.6.0", false,
        "BUSBAR_WORKER_THREADS was not a positive integer and was not captured",
        "The migration captures the old launcher's BUSBAR_WORKER_THREADS into `advanced.worker_threads`. Its value was not a positive integer, which the old launcher also ignored, so nothing was captured and the configured worker count (or TOKIO_WORKER_THREADS) still applies.",
        "Set `advanced.worker_threads` in the migrated config if you meant to pin the worker count, and remove BUSBAR_WORKER_THREADS from the launcher."
        => migrate_worker_threads_ignored() "BUSBAR_WORKER_THREADS is not a positive integer; ignored as in the old launcher; configured workers and the TOKIO_WORKER_THREADS fallback are preserved",
        example "BUSBAR_WORKER_THREADS=auto busbar",
        detail "BUSBAR_WORKER_THREADS is not a positive integer; ignored as in the old launcher; configured workers and the TOKIO_WORKER_THREADS fallback are preserved";

    CONFIG_MODEL_INVALID = 3102, Config, Fatal, "config-model-invalid", "1.6.0", false,
        "A model definition is invalid",
        "An entry under `models:` names a provider that is not defined, or sets a per-model value outside its range: `default_max_tokens`, `max_concurrent` or `max_requests` of 0, an `attempt_timeout_ms` of 0 or above the 30-year ceiling, an empty `upstream_model`, or a `context_max` that two pools declare differently. The message names the model and the field.",
        "Fix the named field under `models.<name>:`: point `provider:` at a provider defined in providers.yaml or `providers:`, use a positive value, or omit the field to take its default. Then run `busbar --validate`."
        => config_model_invalid(detail) "{detail}",
        example "models:\n  gpt-4o:\n    provider: openia     # typo: no such provider",
        detail "model 'gpt-4o' references unknown provider 'openia'";

    CONFIG_NAME_RESERVED_ROUTE = 3103, Config, Fatal, "config-name-reserved-route", "1.6.0", false,
        "A model, pool or provider is named after a reserved route prefix",
        "Models, pools and providers are reachable at `/<name>/...`. The names `admin` and the native-API root are routed to the operator admin surface before any model, pool or provider route, so an entry with one of those names could never be reached by a client and would bypass its own governance.",
        "Rename the model, pool or provider the message names, and update every reference to it."
        => config_name_reserved_route(detail) "{detail}",
        example "pools:\n  admin:\n    members: [gpt-4o]",
        detail "pool name 'admin' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it";

    CONFIG_NAME_CONFLICT = 3104, Config, Fatal, "config-name-conflict", "1.6.0", false,
        "A pool shares its name with a provider or a model",
        "Pools, providers and models share one route namespace (`/<name>/...`), so a pool may not take the name of a provider or a model: one of the two would be unreachable.",
        "Rename the pool (or the provider or model) so every name is distinct, and update the references to it."
        => config_name_conflict(detail) "{detail}",
        example "models:\n  fast: { provider: openai }\npools:\n  fast: { members: [fast] }",
        detail "pool name 'fast' conflicts with model name 'fast'; pools and models must have distinct names";

    CONFIG_POOL_MEMBERS_INVALID = 3105, Config, Fatal, "config-pool-members-invalid", "1.6.0", false,
        "A pool's member list is invalid",
        "A pool has no members, a member's `weight` is 0, a member's `attempt_timeout_ms` is 0 or above the 30-year ceiling, or a member names a model that is not defined (or whose provider is not). A pool with no routable member answers every request with a misleading 503.",
        "Fix the member the message names under `pools.<pool>.members:`: name a model defined under `models:`, use a weight of at least 1 and a positive timeout, or remove the pool."
        => config_pool_members_invalid(detail) "{detail}",
        example "pools:\n  default:\n    members: [gpt-4o, claude-sonet]   # typo",
        detail "pool 'default' references unknown model 'claude-sonet'";

    CONFIG_POOL_FAILOVER_INVALID = 3106, Config, Fatal, "config-pool-failover-invalid", "1.6.0", false,
        "A pool's failover block is invalid",
        "`failover.timeout_secs` is 0 (every request would 503 before its first attempt) or above 24 hours, or `failover.exclusions` names something that is not a member of the pool (so it benches nothing).",
        "Set `failover.timeout_secs` between 1 and 86400 and list only the pool's own members under `failover.exclusions`."
        => config_pool_failover_invalid(detail) "{detail}",
        example "pools:\n  default:\n    members: [gpt-4o]\n    failover: { timeout_secs: 0 }",
        detail "pool 'default' failover.timeout_secs must be >= 1; a 0 budget rejects the primary attempt before it runs (every request 503s)";

    CONFIG_POOL_ON_EXHAUSTED_INVALID = 3107, Config, Fatal, "config-pool-on-exhausted-invalid", "1.6.0", false,
        "A pool's on_exhausted block is invalid",
        "`on_exhausted` names a fallback pool that does not exist or the pool itself, or its `queue.max_ms` is 0 or longer than the pool's whole failover budget. Such a setting never engages: the pool 503s exactly as if it had no fallback.",
        "Point `on_exhausted.fallback_pool` at a different, defined pool, and keep `queue.max_ms` above 0 and at or below the failover budget (or raise `failover.timeout_secs`)."
        => config_pool_on_exhausted_invalid(detail) "{detail}",
        example "pools:\n  primary:\n    members: [gpt-4o]\n    on_exhausted: { fallback_pool: backup }   # no such pool",
        detail "pool 'primary' on_exhausted references unknown fallback pool 'backup'";

    CONFIG_POOL_AFFINITY_INVALID = 3108, Config, Fatal, "config-pool-affinity-invalid", "1.6.0", false,
        "A pool's affinity header name is invalid",
        "`affinity.header_name` must be a valid, non-empty, ASCII HTTP field-name of at most 64 characters; anything else would silently disable session affinity.",
        "Set `affinity.header_name` to a plain header name such as `x-session-id`, or remove the affinity block."
        => config_pool_affinity_invalid(detail) "{detail}",
        example "pools:\n  chat:\n    members: [gpt-4o]\n    affinity: { mode: header, header_name: \"\" }",
        detail "pool 'chat' affinity.header_name must not be empty (an empty HTTP header field-name silently disables session affinity)";

    CONFIG_POOL_FALLBACK_CYCLE = 3109, Config, Fatal, "config-pool-fallback-cycle", "1.6.0", false,
        "Pools' on_exhausted fallbacks form a cycle",
        "Following `on_exhausted.fallback_pool` from pool to pool leads back to a pool already visited. The runtime loop guard would cut the ring on re-entry, so every pool in it 503s instead of degrading.",
        "Break the cycle the message prints: point one pool at a pool outside the ring, or remove its `on_exhausted`."
        => config_pool_fallback_cycle(detail) "{detail}",
        example "pools:\n  a: { members: [m1], on_exhausted: { fallback_pool: b } }\n  b: { members: [m2], on_exhausted: { fallback_pool: a } }",
        detail "fallback_pool cycle detected: a -> b -> a; on_exhausted fallback chains must not loop — the runtime loop guard terminates a cycle on re-entry, so every pool in the ring 503s instead of degrading. Break the cycle (point one pool at a non-looping pool or remove its on_exhausted)";

    CONFIG_POOL_BREAKER_INVALID = 3110, Config, Fatal, "config-pool-breaker-invalid", "1.6.0", false,
        "A pool's circuit-breaker settings are invalid",
        "A `breaker:` value is out of range: a cooldown of 0 (which re-admits a tripped backend at once), `max_cooldown_secs` below `base_cooldown_secs`, a trip `min_requests`, `window_secs` or `consecutive_n` of 0, or an error-rate `threshold` outside (0.0, 1.0].",
        "Fix the field the message names under `pools.<pool>.breaker:`; docs/circuit-breaker.md gives every default."
        => config_pool_breaker_invalid(detail) "{detail}",
        example "pools:\n  default:\n    members: [gpt-4o]\n    breaker: { base_cooldown_secs: 0 }",
        detail "pool 'default' breaker base_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off";

    CONFIG_POOL_HOOKS_INVALID = 3111, Config, Fatal, "config-pool-hooks-invalid", "1.6.0", false,
        "A pool's hook list is invalid",
        "A pool's `hooks:` list names a hook that is not defined under top-level `hooks:`, names a tap (only a gate can influence routing), or names a built-in ranking strategy this binary was built without.",
        "Define the hook under top-level `hooks:`, use a gate, or name a strategy this build carries (`busbar --help` lists the build's features)."
        => config_pool_hooks_invalid(detail) "{detail}",
        example "pools:\n  default:\n    members: [gpt-4o]\n    hooks: [pii-scrub]   # not defined under hooks:",
        detail "pool 'default' references unknown hook 'pii-scrub'; define it under top-level `hooks:`";

    CONFIG_HOOK_INVALID = 3112, Config, Fatal, "config-hook-invalid", "1.6.0", false,
        "A hook definition is invalid",
        "An entry under top-level `hooks:` (or `global_hooks:`) cannot work as written: it names no plugin, a tap asks to rewrite or to be the default ordering, it takes a reserved name, more than one hook is the default, its timeout is out of range, or its `on_error` chain names an unknown fallback, a tap, an absent ranking strategy or loops.",
        "Fix the hook the message names: set `module:` to a `kind: hook` plugin, use `kind: gate` where it must decide, rename it off reserved words, and end every `on_error` chain on nothing, weighted, reject, first or a ranking strategy."
        => config_hook_invalid(detail) "{detail}",
        example "hooks:\n  audit-tap:\n    module: audit\n    kind: tap\n    prompt: rw",
        detail "hook 'audit-tap' is a tap with `prompt: rw`, but only a gate can rewrite (a tap never replies). Use `kind: gate`, or lower to `prompt: ro`";

    CONFIG_AUTH_POLICY_INVALID = 3113, Config, Fatal, "config-auth-policy-invalid", "1.6.0", false,
        "An auth policy or key lifetime setting is invalid",
        "A setting under `auth:` that governs minted keys cannot hold: a duration that does not parse, a default TTL above the maximum, a per-role mint ceiling wider than the deployment-wide policy, a delegated admin scope that does not parse, or a browser-login method without a `public_url:` to build its redirect URLs.",
        "Fix the named setting: durations are written like `30d` or `12h`, per-role ceilings must stay within `auth.policy`, and a browser login needs top-level `public_url: https://<busbar-host>`."
        => config_auth_policy_invalid(detail) "{detail}",
        example "auth:\n  policy: { default_ttl: 90d, max_ttl: 30d }",
        detail "auth.policy.default_ttl ('90d', 7776000s) exceeds auth.policy.max_ttl ('30d', 2592000s); the default a mint falls back to cannot be longer than the ceiling";

    CONFIG_ROLE_BINDING_INVALID = 3114, Config, Fatal, "config-role-binding-invalid", "1.6.0", false,
        "A role binding is invalid",
        "An entry under `auth.role_bindings` names a module that is in neither auth chain, a role that shadows the reserved operator principal, an unknown admin scope or admin verb, a grant kind no installed plane declares, or a group that does not exist. A binding like that grants nothing, or grants something other than what it says.",
        "Fix the binding the message names; the message prints the exact YAML to add where a module or group is missing."
        => config_role_binding_invalid(detail) "{detail}",
        example "auth:\n  role_bindings:\n    oidc:\n      engineers: { group: eng }   # no group `eng`",
        detail "role_bindings.oidc.engineers names group 'eng', which does not exist.\nPaste this under groups and set its limits:\n\n  eng:\n    limits:\n      - { requests: 0, per: minute }\n";

    CONFIG_AUTH_CHAIN_INVALID = 3115, Config, Fatal, "config-auth-chain-invalid", "1.6.0", false,
        "The auth chain cannot authenticate as configured",
        "The data-plane or admin auth chain is incomplete: it names a module that was removed, it verifies busbar-signed keys without an `auth.signing_key` or without any way to mint one, an operator token sits on a module that is not the operator provider, or the operator token has no answer. Busbar refuses rather than start with an auth surface that admits the wrong callers or none.",
        "Follow the message: generate a signing key with `busbar --generate-signing-key` and reference it from `auth.signing_key`, name `keys` or an IdP plugin in `auth.chain`, and keep the operator token on the operator provider."
        => config_auth_chain_invalid(detail) "{detail}",
        example "auth:\n  chain: [keys]          # no signing_key",
        detail "auth.signing_key is required for signed-token auth (auth.chain names the built-in `keys` verifier), but none is set - and busbar no longer auto-generates one. Generate a key with `busbar --generate-signing-key`, then set auth.signing_key to a secret reference for it (a shorthand an admitted secret module declares, or `{ module: …, settings: … }`; a SHARED secret across nodes for a fleet)";

    CONFIG_PLANE_OPEN_TO_ANONYMOUS = 3116, Config, Fatal, "config-plane-open-to-anonymous", "1.6.0", false,
        "A plane is configured while the data-plane auth chain is empty",
        "A plane section (tools, agents and the like) is configured but `auth.chain` is empty, so the plane would serve anonymous callers with wildcard grants over every registered subject, and outbound credentials would have no inbound grant to bind to.",
        "Close the data-plane chain (`auth: { chain: [keys] }` or an IdP auth plugin), or remove the plane block if this deployment does not serve it."
        => config_plane_open_to_anonymous(detail) "{detail}",
        example "tools:\n  search: { url: https://mcp.example.com }\n# no auth.chain",
        detail "`tools:` is configured but auth.chain is empty, which serves the MCP endpoint to ANONYMOUS callers — and a request that carries no key is never narrowed by one, so it runs with WILDCARD grants over every registered subject on that plane. It also leaves `upstream::authorise` with no inbound grant to bind busbar's outbound credentials to. Close the data-plane chain (`auth: { chain: [keys] }`, or an IdP auth plugin), or remove the `tools:` block if this deployment is not a MCP endpoint";

    CONFIG_SETTING_OUT_OF_RANGE = 3117, Config, Fatal, "config-setting-out-of-range", "1.6.0", false,
        "A global limit or timing setting is out of range",
        "A value under `limits:`, `health:`, `routing:` or `advanced:` is outside what busbar can run with: a timeout or interval of 0 (which fails or disables the thing it bounds), a size below its floor or above its ceiling, a duration above the 30-year ceiling the runtime's clock arithmetic can hold, or reasoning-effort budgets that are zero or not ascending.",
        "Set the named key within the range the message states, or omit it to take the default; docs/configuration.md lists every default."
        => config_setting_out_of_range(detail) "{detail}",
        example "limits:\n  upstream_request_timeout_secs: 0",
        detail "limits.upstream_request_timeout_secs must be >= 1 (0 would time out every upstream call instantly)";

    CONFIG_RATE_CARD_INVALID = 3118, Config, Fatal, "config-rate-card-invalid", "1.6.0", false,
        "A rate card or fee is invalid",
        "A rate card or fee cannot be priced as written: a rate that is negative, not finite or implausibly large, a unit or class the plane does not declare or count, a reserved class priced by name, a card entry for a model that is not defined, or a negative per-request fee.",
        "Fix the named entry: price only the units and classes the plane declares, keep rates finite and non-negative, and name only defined models."
        => config_rate_card_invalid(detail) "{detail}",
        example "rate_card:\n  gpt-5: { input_utok: 1.25 }   # no model gpt-5",
        detail "rate_card names model 'gpt-5', which is not defined under models:";

    CONFIG_GROUP_INVALID = 3119, Config, Fatal, "config-group-invalid", "1.6.0", false,
        "A group's limits are invalid",
        "A group under `groups:` sets a limit of 0, which rejects every request through the group instead of bounding it.",
        "Use a positive limit, or remove the limit to leave that dimension unbounded."
        => config_group_invalid(detail) "{detail}",
        example "groups:\n  eng:\n    limits:\n      - { requests: 0, per: minute }",
        detail "groups.eng has a `requests` limit of 0, which rejects every request through the group from the first admission; set a positive amount, or set `enabled: false` to freeze the group explicitly";

    CONFIG_STORE_INVALID = 3120, Config, Fatal, "config-store-invalid", "1.6.0", false,
        "The store block is missing or names no module",
        "Busbar keeps keys, budgets, audit and configuration overlays in the store named by top-level `store:`. The block is missing or its `module:` is empty. 1.6.0 has no default store: a 1.5.5 config.yaml with no `store:` block ran on the store built into 1.5.5, and the one-time upgrade writes that block into it, so a config.yaml stamped `config_version: 1` must name its store itself.",
        "Add `store: { module: <store plugin> }` (for example `sqlite` with a `db_path` setting). For what 1.5.5 did with no block (state kept in RAM, lost on restart), name the in-memory store."
        => config_store_invalid(detail) "{detail}",
        example "store:\n  module: \"\"",
        detail "store.module must be non-empty; name the configured Store plugin";

    CONFIG_SECRET_REFERENCE_INVALID = 3121, Config, Fatal, "config-secret-reference-invalid", "1.6.0", false,
        "A secret reference or secret module setting is invalid",
        "A secret is referenced in a way busbar cannot resolve safely: `none` where a credential is required, a reference form the setting does not accept, a shorthand no admitted secret module declares, or module-level settings on a secret module linked into this build that takes none.",
        "Write the canonical `{ module: <secret module>, settings: {...} }` reference, or a shorthand an admitted secret module declares (`busbar --list-plugins` shows them)."
        => config_secret_reference_invalid(detail) "{detail}",
        example "auth:\n  signing_key: { vault-path: signing }   # no admitted secret module declares `vault-path`",
        detail "auth.signing_key: `{vault-path: …}` is a secret shorthand, and no admitted secret module declares `vault-path`. Install a signed `kind: secret` module that declares `vault-path` into plugins.dir and admit it (plugins.enabled, plugins.trust), or write the canonical `{ module: <secret module>, settings: { … } }` reference. `busbar --list-plugins` shows what was admitted";

    CONFIG_METADATA_HOST_ENTRY_INVALID = 3122, Config, Fatal, "config-metadata-host-entry-invalid", "1.6.0", false,
        "A metadata host list entry can never match",
        "`security.blocked_metadata_hosts` and `security.allow_metadata_hosts` are matched by exact IP or hostname. An entry with a CIDR (`/`) or one that maps to no host would silently never match, leaving the protection it was meant to add (or remove) a no-op.",
        "List exact IPs or hostnames, for example `169.254.169.254`, not `169.254.0.0/16`."
        => config_metadata_host_entry_invalid(detail) "{detail}",
        example "security:\n  blocked_metadata_hosts: [169.254.0.0/16]",
        detail "security.blocked_metadata_hosts entry '169.254.0.0/16' contains '/' (CIDR is not supported here): these lists are matched by EXACT IP or hostname, so a CIDR/slash entry silently never matches and is a no-op. List exact IPs/hostnames instead (e.g. '169.254.169.254', not '169.254.0.0/16')";

    CONFIG_PROVIDER_INVALID = 3123, Config, Fatal, "config-provider-invalid", "1.6.0", false,
        "A provider definition is invalid",
        "A provider's settings cannot work: a health interval or timeout of 0 or above its ceiling, an `error_map` class that does not exist, a `path` or `path_base` that does not begin with `/`, or an option the provider's protocol does not take.",
        "Fix the field the message names under `providers.<name>:`; docs/providers.md documents every provider field."
        => config_provider_invalid(detail) "{detail}",
        example "providers:\n  openai:\n    base_url: https://api.openai.com\n    path: v1/chat/completions",
        detail "provider 'openai' path 'v1/chat/completions' must begin with '/': a path override is appended to base_url verbatim, so a path that does not start with '/' fuses into the host (e.g. base_url + 'v1/chat/completions') and can redirect signed traffic to an attacker-controlled host";

    CONFIG_PROVIDER_DESTINATION_BLOCKED = 3124, Config, Fatal, "config-provider-destination-blocked", "1.6.0", false,
        "A provider URL targets a blocked cloud-metadata host",
        "A provider's `base_url`, `base_url` + `path`, `base_url` + `path_base` or `token_url` resolves to a cloud-metadata (IMDS) endpoint on `security.blocked_metadata_hosts`. Busbar would send credentials there, so it refuses the configuration.",
        "Point the provider at its real API host. If the host is deliberately reachable, list it under `security.allow_metadata_hosts`."
        => config_provider_destination_blocked(detail) "{detail}",
        example "providers:\n  internal:\n    base_url: http://169.254.169.254",
        detail "provider 'internal' base_url 'http://169.254.169.254' targets a blocked cloud-metadata host '169.254.169.254' (cloud-metadata/IMDS endpoints are denied; ...)";

    CONFIG_PROVIDER_CREDENTIAL_INVALID = 3125, Config, Fatal, "config-provider-credential-invalid", "1.6.0", false,
        "A provider's credential cannot be used as configured",
        "A provider's outbound credential is invalid for its auth style: the referenced secret does not parse (a service-account key, a signing key), required auth settings are missing, or the settings contradict the style. The message names the provider, the style and the secret's source, never its value.",
        "Fix the secret the message points at (its secret module source) or the provider's auth settings, then run `busbar --validate`."
        => config_provider_credential_invalid(detail) "{detail}",
        example "providers:\n  vertex:\n    auth: jwt-bearer\n    api_key: { module: <secret module>, settings: { … } }   # not a service-account JSON",
        detail "provider 'vertex' jwt-bearer credential (from secret module '<secret module>') is invalid: service-account key is not JSON";

    CONFIG_PROVIDER_PROTOCOL_UNKNOWN = 3126, Config, Fatal, "config-provider-protocol-unknown", "1.6.0", false,
        "A provider names a protocol this build does not speak",
        "A provider's `protocol:` is not one this binary carries: it is misspelled, or the build has no plane that speaks it.",
        "Use one of the protocols the message lists, or run a build that carries the plane for it."
        => config_provider_protocol_unknown(detail) "{detail}",
        example "providers:\n  claude:\n    protocol: antropic",
        detail "provider 'claude' has unknown protocol 'antropic': must be one of: anthropic, bedrock, cohere, gemini, openai, responses";

    CONFIG_PLANE_POOL_INVALID = 3127, Config, Fatal, "config-plane-pool-invalid", "1.6.0", false,
        "A plane section's failover pool is invalid",
        "A failover pool inside a plane section (`tools.pools`, `agents.pools`, ...) cannot fail over as written: it has fewer than two members or more than the breaker's lane table holds, it shares its name with a registration, it names a member twice, a member belongs to another plane or is not defined, a member sits in two pools, or a `repeatable:` entry is empty.",
        "Fix the pool the message names: list two or more distinct members defined in the same plane section, give the pool its own name, and keep each registration in at most one pool."
        => config_plane_pool_invalid(detail) "{detail}",
        example "tools:\n  pools:\n    search: { members: [brave] }",
        detail "tools.search: a failover pool needs at least TWO members (it has 1). A pool with one member has nowhere to fail over to, so it changes nothing; remove it or add the second registration";

    CONFIG_PROVIDER_REFERENCE_UNKNOWN = 3128, Config, Fatal, "config-provider-reference-unknown", "1.6.0", false,
        "A reference names a provider that is not defined or speaks the wrong protocol",
        "config.yaml (or a plane section) names a provider that providers.yaml and `providers:` do not define, or one whose protocol the referencing plane does not speak.",
        "Define the provider, fix the spelling, or point the reference at a provider of the right protocol; the message lists the valid choices."
        => config_provider_reference_unknown(detail) "{detail}",
        example "models:\n  gpt-4o: { provider: openai-eu }   # not in providers.yaml",
        detail "provider 'openai-eu' referenced in config.yaml not found in providers.yaml";

    CONFIG_SECTION_INVALID = 3129, Config, Fatal, "config-section-invalid", "1.6.0", false,
        "A configuration section is not valid for this build",
        "A top-level section does not parse into its shape, its registry fails its own checks, or it configures a plane (such as `oauth_as:`) whose implementation this binary does not link. The message names the section and the reason.",
        "Fix the section as the message describes, or remove a section this build does not carry."
        => config_section_invalid(detail) "{detail}",
        example "oauth_as:\n  issuer: https://busbar.example.com",
        detail "oauth_as: configured, but the authorization-server plane (busbar-core-oauth2) is not linked into this binary";

    CONFIG_ADMIN_LISTENER_EXPOSED = 3130, Config, Fatal, "config-admin-listener-exposed", "1.6.0", false,
        "The admin listener is network-exposed without mTLS",
        "`admin_listen` binds a non-loopback address but `admin_tls.client_ca` is unset, so the admin plane would accept connections from the network without client certificates.",
        "Set `admin_tls.client_ca` to require client certificates, or bind `admin_listen` to a loopback address."
        => config_admin_listener_exposed(detail) "{detail}",
        example "admin_listen: 0.0.0.0:9090",
        detail "admin_listen '0.0.0.0:9090' is network-exposed but the admin plane has no mTLS (admin_tls.client_ca is unset). Require client certificates by supplying admin_tls.client_ca, bind admin_listen to loopback, or set admin_require_mtls: false to deliberately run a token-only admin plane (e.g. behind a mesh)";

    CONFIG_EXPORT_INVALID = 3131, Config, Fatal, "config-export-invalid", "1.6.0", false,
        "An export sink definition is invalid",
        "An entry under `export:` cannot deliver what it promises: an unknown module, settings the module refuses, a stream or field that does not exist, has no producer or that the module cannot carry, a duplicate, an empty list, a pinned field left out, or `durable: true` that this release does not implement.",
        "Fix the sink the message names; the message lists the valid streams and fields. docs/export.md documents every stream."
        => config_export_invalid(detail) "{detail}",
        example "export:\n  siem:\n    module: otlp\n    streams: [audit]",
        detail "export.siem.streams: `audit` is NOT a stream — it was a use case, not a data type";

    CONFIG_DESTINATION_REFUSED = 3132, Config, Fatal, "config-destination-refused", "1.6.0", false,
        "An outbound destination is refused by the egress policy",
        "A configured outbound URL (an upstream, a token endpoint, a sink) is not one busbar will send to: it is malformed, uses plaintext for a public host, or targets a blocked cloud-metadata host.",
        "Use an `https://` URL for a public host, fix the URL the message names, or list a deliberately reachable metadata host under `security.allow_metadata_hosts`."
        => config_destination_refused(detail) "{detail}",
        example "providers:\n  remote: { base_url: http://api.example.com }",
        detail "provider 'remote' base_url must use a secure connection for a public host; plaintext is permitted only for a private/loopback local-model upstream";

    /// The admin API error envelope's `diag` for `error.code = not_found`.
    ADMIN_NOT_FOUND = 8101, Governance, Actionable, "admin-not-found", "1.6.0", false,
        "The admin resource named in the request does not exist",
        "The path names a resource (a key, a group, a hook, an exporter, a plugin) that this deployment does not have, or one that cannot exist in its current mode (a key read with governance disabled). The response's `message` names the missing thing.",
        "List the collection (for example `GET /api/v1/admin/keys`) to find the right name or id, or create the resource first.";

    /// The admin API error envelope's `diag` for `error.code = unauthorized`.
    ADMIN_UNAUTHORIZED = 8102, Governance, Actionable, "admin-unauthorized", "1.6.0", false,
        "The admin request carries no valid admin credential",
        "The request reached `/api/v1/admin` without a credential the `admin_auth:` chain accepts: no `Authorization: Bearer` or `x-admin-token` header, an unknown or expired token, or a key that is not an admin credential (`invalid_api_key`).",
        "Send the operator admin token (or a credential your admin auth plugin accepts) in `Authorization: Bearer <token>` or `x-admin-token`. docs/admin-api.md covers the auth chain.";

    /// The admin API error envelope's `diag` for `error.code = method_not_allowed`.
    ADMIN_METHOD_NOT_ALLOWED = 8103, Governance, Actionable, "admin-method-not-allowed", "1.6.0", false,
        "The admin path does not take this HTTP method",
        "The path exists on the admin surface, but not with the method the request used (for example a `DELETE` on a read-only collection).",
        "Use a method the path documents; the OpenAPI document at /docs/api/ lists every path and method.";

    /// The admin API error envelope's `diag` for `error.code = forbidden`.
    ADMIN_FORBIDDEN = 8104, Governance, Actionable, "admin-forbidden", "1.6.0", false,
        "The admin credential's scope does not cover this call",
        "The caller authenticated, but its admin scope (read-only, or a role binding's verb list) does not include this operation. The message names the scope that would have sufficed.",
        "Call with a credential whose scope covers the operation, or widen the role binding's `admin_scope` or `verbs`.";

    /// The admin API error envelope's `diag` for `error.code = invalid_request`.
    ADMIN_INVALID_REQUEST = 8105, Governance, Actionable, "admin-invalid-request", "1.6.0", false,
        "The admin request is malformed or fails validation",
        "The request body or its parameters are not what the operation takes: a malformed JSON body, an unknown or missing field, a value out of range, or a configuration change that fails the same validation `busbar --validate` runs. The message says which.",
        "Fix the request as the message describes; the OpenAPI document at /docs/api/ gives each operation's schema.";

    /// The admin API error envelope's `diag` for `error.code = version_conflict`.
    ADMIN_VERSION_CONFLICT = 8106, Governance, Actionable, "admin-version-conflict", "1.6.0", false,
        "The If-Match version is stale",
        "The request's `If-Match` names a version of the resource that is no longer current: someone else changed it after you read it. This is retryable.",
        "Re-read the resource, re-apply your change to the current version, and retry with the new `ETag`.";

    /// The admin API error envelope's `diag` for `error.code = conflict`.
    ADMIN_CONFLICT = 8107, Governance, Actionable, "admin-conflict", "1.6.0", false,
        "The admin request contradicts the server's state",
        "The request cannot apply to the current state and a retry will not change that: governance is disabled, a base-defined hook cannot be removed, a grant is immutable, a duplicate already exists, or an idempotency key is still in flight. The message says which.",
        "Change the request (or the state it depends on) as the message describes; this is not a transient error.";

    /// The admin API error envelope's `diag` for `error.code = rate_limited`.
    ADMIN_RATE_LIMITED = 8108, Governance, Actionable, "admin-rate-limited", "1.6.0", false,
        "The admin mutation rate limit is exhausted",
        "The caller has used its per-minute budget of admin mutations. Reads are not limited.",
        "Wait for the window the `retry-after` header gives (at most a minute) and retry; batch changes where the API allows.";

    /// The admin API error envelope's `diag` for `error.code = internal`.
    ADMIN_INTERNAL = 8109, Governance, Actionable, "admin-internal", "1.6.0", false,
        "The admin call failed inside busbar",
        "An internal failure (a store or plugin error) stopped the call. The response never carries the cause, which may be sensitive; the server log carries it under its own code.",
        "Check the busbar log at the time of the call for the error line and its code, then retry once the cause is fixed.";

    /// The admin API error envelope's `diag` for `error.code = unavailable`.
    ADMIN_UNAVAILABLE = 8110, Governance, Actionable, "admin-unavailable", "1.6.0", false,
        "The admin call could not complete within its bound",
        "An operation that is normally fast could not start or finish in time (for example the plugin catalog scan), or no administrative surface is mounted on this listener. The call was abandoned rather than left to hang.",
        "Retry after a short wait. If it persists, check the server log and the store's health.";

    /// The admin API error envelope's `diag` for `error.code = unpriced_class`.
    ADMIN_UNPRICED_CLASS = 8111, Governance, Actionable, "admin-unpriced-class", "1.6.0", false,
        "A usage read names a class the rate card does not price",
        "A usage query asked for a class the rate card in force does not price, so there is no amount to report for it.",
        "Price the class on the plane's rate card, or drop it from the query.";

    /// The admin API error envelope's `diag` for `error.code = request_too_large`.
    ADMIN_REQUEST_TOO_LARGE = 8112, Governance, Actionable, "admin-request-too-large", "1.6.0", false,
        "The admin request body exceeds the configured limit",
        "The request body is larger than the admin surface accepts.",
        "Send a smaller body (split a bulk change into several requests), or raise the configured admin body limit.";

    /// The admin API error envelope's `diag` for `error.code = (any other)`.
    ADMIN_REQUEST_REFUSED = 8199, Governance, Actionable, "admin-request-refused", "1.6.0", false,
        "The admin request was refused",
        "The admin surface refused the request for a reason the `error.code` field names. This code covers refusals without a more specific admin code.",
        "Read `error.code` and `error.message` in the response; docs/admin-api.md lists every error code.";

    /// One source spent its budget of refused admin credentials; it is answered 429 until the window passes.
    ADMIN_AUTH_THROTTLED_SOURCE = 4038, Auth, BenignRecurring, "admin-auth-throttled-source", "1.6.0", false,
        "Admin door: a source's refused-credential budget is spent",
        "A source presented `auth.login_limits.admin.max_failures` admin credentials that were refused inside the window. Further admin requests from it get 429 `rate_limited` (BUSBAR-8108) with the real Retry-After, before any credential is judged. Requests that present no credential are never counted. Logged at warn and audited (`admin.auth_throttled`) once per source and window.",
        "Check who is guessing the admin credential from that source. Use a long random operator token (see BUSBAR-4042).";

    /// The configured operator token is shorter than 32 bytes.
    ADMIN_OPERATOR_TOKEN_SHORT = 4042, Auth, Actionable, "admin-operator-token-short", "1.6.0", false,
        "Operator token is shorter than 32 bytes",
        "The admin operator token is operator-chosen and compared by digest, so its entropy is the only thing between an online guesser and the admin API. A token shorter than 32 bytes is warned at every boot and reload in 1.6 and will be refused in 1.7.",
        "Replace it with at least 32 random bytes (for example `openssl rand -hex 32`).";

    /// A DPoP-bound token or DPoP presentation was refused (RFC 9449). Emitted per refusal by `auth::dpop`, never with the token.
    AUTH_SENDER_CONSTRAINT_REFUSED = 4032, Auth, Actionable, "auth-sender-constraint-refused", "1.6.0", false,
        "Sender-constrained (DPoP) credential refused",
        "A DPoP-bound token or DPoP presentation was refused because its sender constraint was not met or cannot be verified here",
        "Have the client present a DPoP proof (with `oauth_as` configured) or an unbound token; if the IdP binds tokens for bearer-only clients, change the IdP client";

    /// A login-limits setting is out of range or malformed; boot refuses.
    CONFIG_LOGIN_LIMITS_INVALID = 3133, Config, Fatal, "config-login-limits-invalid", "1.6.0", false,
        "A login attempt limit setting is invalid",
        "A key of `auth.login_limits`, a provider's `browser_login.max_failures` or `browser_login.failure_window`, `advanced.trusted_proxies` or `advanced.forwarded_header` is out of range or does not parse, so busbar refuses the config rather than run with a limit nobody chose. Counts are 1..=100 (per account) or at least 1, windows 1m..=24h, `per_account.max_failures` may not exceed `per_source.max_failures`, every trusted proxy is an IP or a CIDR, and the forwarded header is `x-forwarded-for` or `forwarded`.",
        "Fix the key the message names.";

    /// A first-start owner made no progress write for longer than its step budget.
    FIRST_START_SLOW_STEP = 9016, Boot, Actionable, "first-start-slow-step", "1.6.0", false,
        "First start step slower than its budget (waiters may take over)",
        "A first-start owner went longer than the step budget (45 s, plus 35 s for a step that runs inside a plane's READY) between two progress writes. Waiting replicas take over after 90 s without progress, so a gap near that window risks retiring a live owner. The line names the step and the gap.",
        "Find what made the step slow (plugin load or open, driver build, the store, an import page) and make it faster. A single replica is not at risk; several replicas sharing the store are.";

    /// This process retired a first-start owner whose progress rows did not change for the stall window and took over its first start.
    FIRST_START_TAKEOVER = 9014, Boot, Actionable, "first-start-takeover", "1.6.0", false,
        "Took over a stalled first start (the previous owner is retired)",
        "An unpublished first start of this dataset was owned by another writer whose progress rows stayed byte-for-byte unchanged for the whole stall window (90 s plus 35 s per plane already done), so this process retired that writer and now owns the first start. Logged only when the takeover Register applied. The line names the dataset, the previous and new writer ids, the stall, the window and the observed digest. The previous owner, if still alive, is fenced and fails boot asking for reconciliation.",
        "Find out why the previous owner stopped: it crashed, was killed, or hung past its own deadlines (a plugin READY, an unavailable store). No action is needed for the dataset; this process finishes first start.";

    /// A first-start takeover was attempted but its outcome is unknown or it was refused; boot refuses.
    FIRST_START_TAKEOVER_UNCONFIRMED = 9015, Boot, Actionable, "first-start-takeover-unconfirmed", "1.6.0", false,
        "First-start takeover not confirmed (outcome unknown or refused)",
        "This process tried to take over a stalled first start, but the store did not confirm it: either the outcome is unknown (the previous writer may or may not have been retired) or the store refused it with no effect. Nothing claims the takeover happened; boot then refuses with the store admission error that follows this line.",
        "Check the store's health and restart. The next start reads the dataset as it is: it waits on the owner, or takes over at once if the earlier takeover did apply.";

    /// One account has been throttled in more than four consecutive failure windows: a targeted account.
    LOGIN_ACCOUNT_THROTTLE_SUSTAINED = 4041, Auth, Actionable, "login-account-throttle-sustained", "1.6.0", false,
        "An account has been throttled for more than four consecutive windows",
        "Someone keeps spending one account's failure budget, window after window. busbar keeps refusing (inside busbar only; the directory is protected), but the real user cannot sign in either. The log carries the account's key fingerprint, never the name. Warned once per window while it lasts.",
        "Treat it as a security event: find the sources in the audit log and block them upstream. Tell the user; consider a trusted network path for them.";

    /// A credential sign-in or admin request came from a source busbar cannot identify; per-source limits do not apply to it.
    LOGIN_CLIENT_ADDRESS_UNKNOWN = 4036, Auth, Actionable, "login-client-address-unknown", "1.6.0", false,
        "Client address unknown: per-source login limits skipped",
        "busbar could not tell who sent a request: the server has no socket peer (an embedded server), a trusted proxy forwarded an unparseable hop, or a private or loopback peer sent `X-Forwarded-For` or `Forwarded` while `advanced.trusted_proxies` is empty, which means an ingress sits in front of busbar and every user would otherwise share one bucket. Per-source limits are skipped for such requests; the per-account limiter still applies. Warned once, then at debug.",
        "List the ingress or load balancer addresses in `advanced.trusted_proxies` (and set `advanced.forwarded_header` if it sends `Forwarded`).";

    /// Credential sign-in failures on this node passed the global alarm threshold; per-source limits are tightened.
    LOGIN_GLOBAL_ALARM = 4034, Auth, Actionable, "login-global-alarm", "1.6.0", false,
        "Credential sign-in failures passed the global alarm threshold",
        "More than `auth.login_limits.global.max_failures_per_minute` credential sign-in failures happened on this node in one minute: the shape of a distributed password spray. busbar does not refuse everyone; while the alarm holds it cuts each source's failure ceiling to a quarter and its submission rate to a third, and records `auth.login_alarm`. Warned once per trip; the clear is logged at info.",
        "Investigate the spray (sources, targeted accounts in the audit log). Put a WAF rate limit in front of `POST /auth/token` if it persists.";

    /// A login limiter is disabled by config.
    LOGIN_LIMITER_DISABLED = 4037, Auth, Actionable, "login-limiter-disabled", "1.6.0", false,
        "A login attempt limiter is disabled",
        "`auth.login_limits.per_source.enabled` or `auth.login_limits.global.enabled` is false. That is allowed for a site whose WAF already does this, and logged at every boot and reload so it is never silent. The per-account limiter cannot be disabled.",
        "Re-enable it, or confirm that a WAF in front of busbar rate-limits `POST /auth/token`.";

    /// Credential sign-in is refused because no auth.signing_key is configured to key the login limiter.
    LOGIN_LIMITER_NO_KEY = 4039, Auth, Actionable, "login-limiter-no-key", "1.6.0", false,
        "Credential sign-in refused: no signing key to key the login limiter",
        "The per-account limiter keys accounts with an HMAC derived from `auth.signing_key`, so every node computes the same key over the shared store. No signing key is configured, so busbar refuses each credential sign-in with 503 and does not call the plugin; it never falls back to a per-node random key, which would split the budget silently. Such a deployment cannot issue keys either. Warned once, then at debug.",
        "Configure `auth.signing_key` (`busbar --generate-signing-key`).";

    /// The login attempt limiter could not reach the core store; credential sign-ins are refused (503) without calling the plugin.
    LOGIN_LIMITER_STORE_UNAVAILABLE = 4035, Auth, Actionable, "login-limiter-store-unavailable", "1.6.0", false,
        "Login attempt limiter cannot reach the core store (sign-ins refused)",
        "The per-account limiter keeps its counts in the core store so they hold fleet-wide. The store failed, was absent, or a compare-and-swap could not settle, so busbar fails closed: every credential sign-in answers 503 \"Couldn't reach your provider\" with Retry-After and the login plugin is not called (a sign-in could not finish anyway: issuing the key writes to the same store). Warned on entering the state and logged on recovery.",
        "Restore the core store (`store:`). Sign-ins resume on their own once it answers.";

    /// A credential method's identity provider failed repeatedly; sign-ins to it are answered 503 for a short time without calling it.
    LOGIN_PROVIDER_BREAKER_OPEN = 4040, Auth, Actionable, "login-provider-breaker-open", "1.6.0", false,
        "Credential method held open after repeated provider outages",
        "The login plugin answered `Outage` (directory or IdP unreachable) five times within a minute. busbar answers sign-ins for that method with 503 \"Couldn't reach your provider\" and Retry-After: 30 for 30 seconds, without calling the plugin and without counting the attempts against anyone, so an outage does not throttle every user. Warned each time it opens.",
        "Restore the directory or identity provider the method uses.";

    /// A credential sign-in was refused because its account's failure ceiling is reached.
    LOGIN_THROTTLED_ACCOUNT = 4045, Auth, BenignRecurring, "login-throttled-account", "1.6.0", false,
        "Credential sign-in throttled: the account's failure ceiling is reached",
        "A hosted credential sign-in (`POST /auth/token` with a login cookie) named an account that already has `max_failures` failed attempts inside its failure window, counted fleet-wide in the core store and keyed on an HMAC of the normalised account name (never the name). busbar answered 429 \"Too many sign-in attempts\" with Retry-After and did NOT call the login plugin, so the directory saw no bind. The first refusal per account and window is logged at warn and audited (`auth.login_throttled`); later ones log at debug.",
        "None for a single burst: it expires on its own. Repeated refusals for one account are a targeted attack or a user who forgot a password: see BUSBAR-4041. Keep `browser_login.max_failures` x ceil(directory reset window / failure window) below the directory's lockout threshold.";

    /// A credential sign-in was refused because its source address spent its failure or submission budget.
    LOGIN_THROTTLED_SOURCE = 4033, Auth, BenignRecurring, "login-throttled-source", "1.6.0", false,
        "Credential sign-in throttled: the client's source spent its budget",
        "One client source (an IPv4 address, or an IPv6 /64 with /48 and /32 aggregates) exceeded the per-source failure ceiling or the submission rate inside the window, typically one client spraying many usernames. busbar answered 429 with Retry-After without calling the login plugin. The first refusal per source and window is logged at warn and audited; later ones log at debug.",
        "None for a single client. If every user arrives from one address (an ingress or load balancer), configure `advanced.trusted_proxies` so busbar sees the real client address.";

    STORE_COMMIT_FENCED_IN_DOUBT = 1011, Durability, Actionable, "store-commit-fenced-in-doubt", "1.6.0", false,
        "A store commit whose earlier send may have applied was fenced on retry",
        "A slotted commit lost its reply, and its retry found the writer's epoch no longer admitted (the writer was closed, which also deleted its slot rows). Whether the earlier send applied cannot be decided automatically, so the operation is held for reconciliation instead of being assumed either way.",
        "Reconcile the named operation against the store's records before reusing its effects. This follows a writer closure (recovery adoption or shutdown) while a commit was in doubt.";

    STORE_INFLIGHT_EXHAUSTED = 1010, Durability, Actionable, "store-inflight-exhausted", "1.6.0", false,
        "Store in-flight queue exhausted: new store writes are refused until slots free up",
        "Every pending-operation slot of this writer is held, so new store commits answer Overloaded and money-path arrivals are refused with DurabilityUnavailable. Emitted when exhaustion starts and again when it ends, with the in_doubt, resolved_uncollected and reconcile counts of the held slots.",
        "store unreachable or slow (in_doubt); a domain not collecting answers (resolved_uncollected, a bug); operator reconciliation pending (reconcile). See the busbar_store_slots gauge.";

    STORE_SELF_FENCED_AMBIGUOUS = 1013, Durability, Actionable, "store-self-fenced-ambiguous", "1.6.0", false,
        "A self-fenced store commit's readback could not decide whether it applied",
        "An administrative commit that can apply at most once lost its reply, and the readback of its witness and predicates could not prove it applied or prove it never will (a record moved past both values, a domain predicate could return to its expected value, or the store refused a predicate that holds). It is held for reconciliation instead of being assumed.",
        "Reconcile the named administrative step (boot registration, writer transition, first start or migration step) against the store before retrying it.";

    STORE_SLOT_INVARIANT = 1012, Durability, Actionable, "store-slot-invariant", "1.6.0", false,
        "A live store commit was answered STALE: the slot queue invariant was broken",
        "The store reported that a later sequence of this commit's slot was already evaluated. A live attempt holds its slot, so this means the slot was leased twice or the store's slot row is wrong. Nothing was applied by this send; an in-doubt attempt is held for reconciliation.",
        "This is a bug in the slot facade or the store plugin. Capture the log line (writer, slot) and file a bug; reconcile any held operation.";

    STORE_TIME_GUARD_INCONSISTENT = 1014, Durability, Actionable, "store-time-guard-inconsistent", "1.6.0", false,
        "The store answered an inconsistent time-guard failure",
        "The store reported a time-guard failure whose observation came from another clock authority, or whose time the commit's guard permits, or for a commit with no guard. That is a store fault; retrying would replay the same recorded verdict, so the operation is held for reconciliation.",
        "Check the store plugin and its clock authority. Capture the log line (store, writer, slot, observed authority and time, the guard) and reconcile the held operation.";

    /// A 1.5.5 file overlay holds settings this Store has not imported; serving refuses to start (fatal).
    CONFIG_LEGACY_OVERLAY_NOT_IMPORTED = 3027, Config, Fatal, "config-legacy-overlay-not-imported", "1.6.0", false,
        "A 1.5.5 file overlay holds settings this Store has not imported (boot refuses to start)",
        "The overlay file a 1.5.5 deployment read and wrote (config.overlay.file, BUSBAR_CONFIG_OVERLAY, or busbar-overlay.json beside config.yaml) holds admin-API settings, and this Store has no import receipt for it. 1.6 serving never reads file overlays, so starting would silently drop those settings, security hooks and groups included; serving REFUSES to start instead. The message names the file and how it was selected, never its settings. In --safe-mode it is a warning and the boot continues.",
        "Follow the remedy the message gives for this Store. The upgrade boot folds a 1.5.5 overlay into config.yaml; a config.yaml that is already migrated no longer reads it. Re-apply the settings you still want through the admin API (on a durable Store), keeping a copy of the file first. Moving the file away without a copy abandons the settings deliberately.";

    /// A 1.5.5 overlay selector, BUSBAR_CONFIG_OVERLAY or overlay file that loses nothing is not read.
    CONFIG_LEGACY_OVERLAY_NOT_READ = 3028, Config, Actionable, "config-legacy-overlay-not-read", "1.6.0", false,
        "A 1.5.5 overlay selector, variable or file is not read (nothing to import)",
        "The deployment still carries a 1.5.5 file-overlay input that 1.6 serving does not read: a config.overlay selector or BUSBAR_CONFIG_OVERLAY naming a file that does not exist, an overlay file that holds no settings, a file whose settings this Store has already imported, or a file beside a locked config (which 1.5.5 ignored too). Nothing is lost, so the boot continues; the message names the file and how it was selected.",
        "Remove the leftover input: delete the imported or empty overlay file, and remove BUSBAR_CONFIG_OVERLAY from the launcher. Remove `config.overlay` from config.yaml. See docs/migration-1.6.md.";

    /// A `plaintext: true` destination entry names a wildcard or a CIDR.
    CONFIG_PLAINTEXT_ENTRY_NOT_EXACT = 3144, Config, Fatal, "config-plaintext-entry-not-exact", "1.6.0", false,
        "A plaintext destination entry is not an exact host or IP",
        "`plaintext: true` on an `advanced.tls.destinations` entry is accepted only on an exact host name or an exact IP. A wildcard or a CIDR would admit cleartext to destinations nobody named.",
        "Write one entry per host or IP that must be reached in clear.";

    /// An outbound proxy is configured: the guard judges names, and addresses where they resolve locally.
    CONFIG_PROXY_DELEGATES_ADDRESS_CHECK = 3149, Config, BenignRecurring, "config-proxy-delegates-address-check", "1.6.0", false,
        "Outbound connections go through a proxy",
        "HTTP(S)_PROXY / ALL_PROXY is set. busbar judges every target's name, and when the name resolves locally it judges every address it answers and refuses a private or metadata answer even behind the proxy. A name that does not resolve locally is reached through the proxy's own resolution, so the address check is delegated to the proxy for it. One line at boot (proxy endpoint redacted, NO_PROXY) and one audit record. Trust anchors are selected by the target, never by the proxy hop.",
        "Nothing, if the proxy is yours. Make sure the proxy enforces your egress policy for names it resolves.";

    /// One accepted `advanced.tls` trust anchor, or the base set loaded, with its fingerprint (info).
    CONFIG_TLS_ANCHOR_ACCEPTED = 3138, Config, BenignRecurring, "config-tls-anchor-accepted", "1.6.0", false,
        "An advanced.tls trust anchor was accepted",
        "Logged once at boot for each operator trust anchor busbar accepted (SHA-256 of the DER certificate, subject, issuer, notAfter, and the scope: `global` or the destination entry), and once for the base set (`roots`: its count and a SHA-256 over the sorted set, and the bundle path for `system`). Each accepted anchor also writes one `config.tls_trust_anchor` audit record.",
        "Nothing to do. Compare the fingerprints with the CAs you intended to trust.";

    /// An `advanced.tls` trust anchor expires within 30 days.
    CONFIG_TLS_ANCHOR_EXPIRING = 3139, Config, Actionable, "config-tls-anchor-expiring", "1.6.0", false,
        "An advanced.tls trust anchor expires within 30 days",
        "An operator trust anchor's notAfter is within 30 days. The warning is logged at boot and repeated once a day by the hourly trust-store sweep. When the anchor expires, the sweep withdraws it from new connections (BUSBAR-5048) and the next boot refuses it (BUSBAR-3137).",
        "Rotate the CA: list the new CA beside the old one, restart, then remove the old one once every server presents a chain to the new CA.";

    /// An `advanced.tls` trust anchor fails boot validation.
    CONFIG_TLS_ANCHOR_INVALID = 3137, Config, Fatal, "config-tls-anchor-invalid", "1.6.0", false,
        "An advanced.tls trust anchor is not a usable CA",
        "A trust anchor listed under `advanced.tls.trust_anchors` or `advanced.tls.destinations[].trust_anchors` was refused at boot: it could not be read, does not parse as PEM, holds no certificate or holds a private key, is not an X.509 v3 CA (`basicConstraints CA:TRUE`, and `keyCertSign` when `keyUsage` is present), is not yet valid (more than five minutes before `notBefore`) or has expired, or rustls does not accept it. busbar refuses to boot rather than open connections with a trust set the operator did not intend. The line names the key, the index, the source (file, env or inline) and the destination it scopes; never the certificate bytes.",
        "List the CA that issued the server's certificate (not the server's own certificate), as a PEM file, environment variable or inline PEM. Rotate an expired CA before restarting. A self-signed server certificate (`CA:FALSE`) is not a trust anchor: issue the server a certificate from a CA you control and list that CA.";

    /// `roots: system` dropped certificates from the OS bundle (expired, not a CA, unreadable).
    CONFIG_TLS_BASE_ROOTS_DROPPED = 3147, Config, Actionable, "config-tls-base-roots-dropped", "1.6.0", false,
        "System CA bundle entries were not used",
        "With `advanced.tls.roots: system`, certificates in the operating system's CA bundle that are expired, are not CA certificates, or do not parse are not used as trust anchors. One warning at boot carries the count and the first reason. Operating-system bundles routinely carry such entries, so the boot continues.",
        "Usually nothing. If a CA you rely on is in the count, update the base image's ca-certificates package or list the CA under `advanced.tls.trust_anchors`.";

    /// An `advanced.tls.destinations` entry is malformed (match, pin, client identity or shape).
    CONFIG_TLS_DESTINATION_INVALID = 3148, Config, Fatal, "config-tls-destination-invalid", "1.6.0", false,
        "An advanced.tls destination entry is invalid",
        "An `advanced.tls.destinations` entry was refused at boot: its `match` is not a host, `*.domain`, IP or CIDR; a `pin_spki_sha256` is not `sha256/<base64>` of 32 bytes; its `client_identity` certificate or key cannot be read or do not belong together; or a `plaintext: true` entry also lists TLS settings. The line names the index and the key, never key material.",
        "Correct the entry. Client identity keys are read by core from a file or environment variable and are never handed to a plugin.";

    /// No trust anchor applies: `roots: none` with nothing listed, or an empty system bundle.
    CONFIG_TLS_TRUST_EMPTY = 3140, Config, Fatal, "config-tls-trust-empty", "1.6.0", false,
        "No trust anchor applies to a TLS destination",
        "`advanced.tls.roots: system` found no usable certificate in the operating system's CA bundle (refused at boot), or `advanced.tls.roots: none` is set and a TLS dial matched neither a global trust anchor nor a destination entry listing one (the dial is refused; a pinned destination is refused the same way, never a panic). busbar never opens a TLS connection it cannot verify.",
        "Install the distribution's ca-certificates package or set SSL_CERT_FILE for `roots: system`; with `roots: none`, list the CA under `advanced.tls.trust_anchors` or a matching `advanced.tls.destinations` entry; or use `roots: bundled` (the default).";

    /// An `advanced.tls.destinations` wildcard covers a single label.
    CONFIG_WILDCARD_OVER_PUBLIC_SUFFIX = 3145, Config, Fatal, "config-wildcard-over-public-suffix", "1.6.0", false,
        "A destination wildcard is too wide",
        "An `advanced.tls.destinations` `match` is a wildcard over a single label (for example `*.com` or `*.internal`), which would scope the entry's CAs, pins or identity to names nobody named. Public-suffix-list wildcards (for example `*.co.uk`) are not detected in 1.6.0.",
        "Name the domain you own: `*.corp.example.com`.";

    /// A used config word, section or style is declared differently by what admission (or the
    /// Store's plugin version pins) gives than by the grammar the configuration was read under.
    CONFIG_GRAMMAR_CHANGED = 3170, Config, Fatal, "config-grammar-changed", "1.6.0", false,
        "A configuration word, section or style changed its owner after it was read",
        "The configuration was read under the grammar its admitted modules declared at that moment. A secret shorthand word, a core grammar role, a plane section or an outbound auth style the configuration uses is declared differently by what admission now gives (plugins.dir changed after the read), or by the Store's plugin version pins at boot, or would be at the next start after a pin. Busbar refuses rather than read a value under one declaration and resolve it under another: a reload or apply is refused and the running generation keeps serving, a boot exits, and a pin is not written. The message names the item and both owners with their files. A module upgraded with an equal declaration never refuses, and an item the configuration does not use never refuses.",
        "Reload (or restart) to read the configuration again. At boot, make config.yaml's plugins: block admit the same module, write the canonical `{ module: ..., settings: ... }` reference, or start once with --ignore-overlay and remove the pin with POST /api/v1/admin/plugins/rollback.";

    /// An outbound dial was refused (destination guard, plaintext rule or trust store).
    EGRESS_DIAL_REFUSED = 5051, Proxy, BenignRecurring, "egress-dial-refused", "1.6.0", false,
        "An outbound dial was refused",
        "busbar refused an outbound connection: the destination guard refused the host or an address it answered, plaintext was not admitted to it (BUSBAR-3141), or no trust anchor applies (BUSBAR-3140). The line carries the verdict, the class, the host, the owning plugin and need; it is rate-limited per host and reason, and each refusal writes one `egress.dial_refused` audit record.",
        "If the destination is intended, add it to `advanced.allow_destinations` (private hosts), use TLS, or list its CA under `advanced.tls`.";

    /// An `advanced.tls` trust anchor expired at runtime and was withdrawn.
    EGRESS_TLS_ANCHOR_EXPIRED_WITHDRAWN = 5048, Proxy, Actionable, "egress-tls-anchor-expired-withdrawn", "1.6.0", false,
        "An expired trust anchor was withdrawn",
        "The hourly trust-store sweep found an operator trust anchor past its notAfter and withdrew it from new connections (audited as `egress.tls_anchor_withdrawn`). A dial whose matching destination entry has no anchor left is refused. Connections already open are unaffected.",
        "Rotate the CA, list the new one, and restart.";

    /// An `advanced.tls` anchor file changed on disk since boot.
    EGRESS_TLS_ANCHOR_FILE_CHANGED = 5049, Proxy, Actionable, "egress-tls-anchor-file-changed", "1.6.0", false,
        "A trust anchor file changed; restart to apply",
        "The hourly trust-store sweep found that a trust anchor file's contents differ from what busbar loaded at boot (for example cert-manager trust-manager rotated the bundle). The trust store is boot-time, so the change is not applied until restart. Logged once per change and audited as `egress.tls_anchor_file_changed`.",
        "Restart busbar to apply the new anchors (validate first).";

    /// An outbound TLS handshake failed certificate or key-pin verification.
    EGRESS_TLS_VERIFICATION_FAILED = 5047, Proxy, Actionable, "egress-tls-verification-failed", "1.6.0", false,
        "An outbound TLS connection failed verification",
        "The far end's certificate did not verify: unknown issuer, wrong host name, expired, or a key that is not the pinned one. The line and the `egress.tls_verification_failed` audit record carry the dialled host, the `advanced.tls.destinations` entries that matched, the fingerprints of the operator anchors in force, and the reason; never the certificate body. busbar never skips verification.",
        "List the CA that issued the server's certificate under `advanced.tls.destinations` for that host (or `trust_anchors` for a corporate root), fix the server's certificate, or update the pin.";

    /// A process that owned an unpublished first start could not retire its writer on exit; the next start waits the stall window.
    FIRST_START_EXIT_RETIRE_FAILED = 9018, Boot, Actionable, "first-start-exit-retire-failed", "1.6.0", false,
        "First start not handed over on exit (the next start waits)",
        "This process owned an unpublished first start and exited, but retiring its writer row did not complete within the exit budget (5 s), was refused, or its outcome is unknown. The next start of this dataset waits up to the named window before it takes over, as after a crash.",
        "Check the store's health. Keep the next start running for at least the named window so it can take over; restarting it early resets the wait.";

    /// A process that owned an unpublished first start retired its own writer on exit, so the next start takes over at once.
    FIRST_START_EXIT_RETIRED = 9017, Boot, Actionable, "first-start-exit-retired", "1.6.0", false,
        "First start handed over on exit (writer retired)",
        "This process owned an unpublished first start and exited before publishing it (a boot refusal, a signal, or a one-shot command), so it retired its own writer row on the way out. The birth record is unchanged; the next start of this dataset, here or on another replica, takes over at once with no wait.",
        "None for the hand-over. Fix the reason the process exited, which is printed just before this line.";

    /// A waiting process sees another writer's unpublished first start of the same dataset and waits for it.
    FIRST_START_WAITING = 9013, Boot, Actionable, "first-start-waiting", "1.6.0", false,
        "Waiting on another writer's first start of this dataset (no listener bound yet)",
        "Another process owns this dataset's first start and has not published it, and its progress rows (birth record, writer row, R0 progress row) changed within the stall window, so this process waits instead of retiring it. It binds no listener while it waits. The line names the owner's writer id, how long ago its progress last changed and when this process takes over if nothing changes. A restart resets the wait.",
        "Let it wait: it is admitted once the owner publishes, or takes over once the owner stops making progress for the window. Do not stop or restart it before the named takeover time; give the supervisor a startup budget of at least 200 + 105 x P seconds (P = conditional-records planes), see docs/operations.md First start with several replicas.";

    /// The shutdown drain ended without retiring the writer (deadline, undrained custody, or a refused retirement).
    SHUTDOWN_DRAIN_INCOMPLETE = 9019, Boot, Actionable, "shutdown-drain-incomplete", "1.6.0", false,
        "Shutdown drain incomplete (the writer was not retired; exit 75 or 70)",
        "The process stopped serving but did not retire its store writer: the drain budget ran out or a second signal arrived (cause=deadline), requests, governed units or persistence were still unsettled at their cut (cause=undrained), or the store refused the retirement (cause=retire_refused). Nothing in flight was cancelled. The exit status is 75 when every completed request's spend is in durable custody (running streams were cut) and 70 when some completed spend is not; each unsettled item is printed on stderr. The writer stays open until its lease lapses and the next start closes it.",
        "Read the cause and the stderr lists. For cause=deadline on a slow store, raise the drain budget or fix the store's latency. A 70 exit lists the unpersisted spend as evidence: correct it through the audited admin correction path once the store is back.";

    /// Some completed spend was not in durable custody at a non-retired exit.
    SHUTDOWN_SPEND_UNPERSISTED = 9020, Boot, Actionable, "shutdown-spend-unpersisted", "1.6.0", false,
        "Completed spend not in durable custody at exit (exit 70)",
        "At a shutdown that could not retire the writer, at least one finished request's spend (a terminal unit checkpoint, a budget cell, a metering count or a correction) was not persisted, or its write was still unconfirmed. Each item is printed on stderr with its identity and amounts, as evidence; busbar never imports it on the next start, because an import can double-spend.",
        "Restore the store, then reconcile the listed items through the audited admin correction path. Find why the drain could not persist them (store outage or latency at shutdown).";

    /// Governed admission is refused while the gateway drains or the settlement backlog is at its cap.
    GOVERNED_ADMISSION_PAUSED = 8030, Governance, Actionable, "governed-admission-paused", "1.6.0", false,
        "Governed admission paused (draining, or finished requests await settlement)",
        "New governed requests are refused with a 503: either the gateway is shutting down (cause=drain, reason drain, retry on another instance) or the number of finished governed requests whose spend still awaits settlement in the store reached its cap (cause=custody_full, reason durability_unavailable, Retry-After 1). Running requests and streams are never refused, and every refusal is audited on its unit. Logged once per episode; an Info line follows when the backlog falls below 90% of the cap.",
        "For custody_full, check the store's latency and throughput: settlement is slower than governed arrival. For drain, route traffic to another instance until this one restarts.";

    /// A writer that never retired was closed, but its shutdown.drain_incomplete record could not be queued.
    SHUTDOWN_DRAIN_INCOMPLETE_UNRECORDED = 9021, Boot, Actionable, "shutdown-drain-incomplete-unrecorded", "1.6.0", false,
        "A closed writer's shutdown.drain_incomplete record could not be queued (retried)",
        "This process closed the store writer of a previous process that never retired (a successor on the same host, a recovery adopter, or the start-up expired-lease pass), but the admin audit queue refused its shutdown.drain_incomplete record: the queue was full or no entropy was available. The record is kept, named here with the writer's epoch, id, node and host, retried every second until it is queued and confirmed, and printed at exit if it is still refused. No later process records this writer.",
        "Check the admin audit store's health: the queue is full because its appends do not complete. The record is retried on its own; if this process exits first, its stderr carries the writer's identity as the only evidence.";

    /// A writer lease or host assignment row did not decode; the expired-writer pass never closes it.
    EXPIRED_WRITER_ROW_INVALID = 9022, Boot, Actionable, "expired-writer-row-invalid", "1.6.0", false,
        "A writer lease or host assignment row does not decode (never closed)",
        "The start-up pass that closes writers whose lease expired at least one lease TTL ago found a writer lease or host assignment row it cannot decode. It never closes or deletes such a row; it reports it once per start with the row's key.",
        "Inspect the named key in the store's node schema. A row written by another tool or a damaged store needs operator repair; busbar leaves it in place.";

    /// The expired-writer pass could not close a writer, or delete a closed writer's lease row.
    EXPIRED_WRITER_CLOSE_FAILED = 9023, Boot, Actionable, "expired-writer-close-failed", "1.6.0", false,
        "An expired writer was not closed (the next start retries)",
        "The start-up pass that closes writers whose lease expired at least one lease TTL ago could not close the named writer, could not delete a closed writer's lease row, or could not scan the node schema, usually because the store did not answer. The writer stays open and the next start of any gateway on this store retries.",
        "Check the store's health. Nothing is lost: the writer is closed, and its shutdown.drain_incomplete record written, by a later start.";

    /// More expired writers remain than one start closes.
    EXPIRED_WRITERS_REMAINING = 9024, Boot, Actionable, "expired-writers-remaining", "1.6.0", false,
        "More expired writers remain than one start closes (the next start continues)",
        "The start-up pass closes at most 256 expired writers per start, so its cost stays bounded. More remained; the next start of any gateway on this store continues with them.",
        "None if starts continue. Many expired writers point at many processes that did not retire: check why shutdowns are not completing.";

    /// A retired 1.5.x launch environment variable is set; 1.6 ignores it.
    RETIRED_ENV_VAR_IGNORED = 3029, Config, Actionable, "retired-env-var-ignored", "1.6.0", false,
        "A retired launch environment variable is set and IGNORED",
        "busbar 1.6 no longer reads BUSBAR_PROVIDERS, BUSBAR_WORKER_THREADS, BUSBAR_UPSTREAM_HTTP1_ONLY or BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE. A set one has NO effect: the config key (or its default) is in force. Emitted pre-tracing, to stderr, at boot and by --validate.",
        "Write the value into config.yaml, validate, then remove the variable from the launcher.";
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
