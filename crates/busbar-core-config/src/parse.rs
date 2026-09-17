// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral config-parsing helpers, relocated out of `admin::`/`admin::v1::contract` (1.6.0
//! de-vocab): both are consumed by `config_validate` and `config::named_map` (boot/validate-time
//! config checks), not the admin HTTP API. Byte-identical rename: only the Rust binding path
//! moves — every parsed VALUE and error-message TEXT is unchanged.

/// The `<n><unit>` duration parser lives in the neutral substrate (`busbar_substrate::duration`) so
/// the plane crates name it without reaching into busbar-core; re-exported here so every
/// `crate::config::parse::parse_duration_secs` caller is unchanged.
pub use busbar_substrate::duration::parse_duration_secs;

use busbar_contract::authz::Scope;

/// THE ONE `max_admin_scope:` CEILING-TOKEN CHECK, with the one error message. `subject` is the
/// human path of the site that carries the token (`auth chain entry 'ad'`,
/// `identity-providers.corp-ad`) — everything else is identical, because the accepted-value list
/// must be.
///
/// ADMIN-WORDED (the error text names `max_admin_scope`/`admin_scope`/`admin authority`
/// verbatim — WIRE-PINNED, byte-frozen) despite living on this neutral config surface, unlike the
/// generic `Scope`/`Grants` lattice it builds on (`busbar_contract::authz`). `Scope::parse` itself
/// is the only part this borrows from the neutral contract.
///
/// Both surfaces that can introduce a ceiling call THIS: `config_validate`'s chain-entry rule
/// (boot / `--validate`) and the admin named-map write path (`NamedMapSection::parse_def`). They
/// used to disagree — the API accepted any string (the write path only ran the `serde`
/// type-check, and `Option<String>` accepts every string), persisted it, answered 200, and the
/// gateway then refused to BOOT on the next restart with "unknown max_admin_scope". A successful
/// admin write that leaves the deployment unbootable is the failure mode a second copy of the
/// accepted-value list buys you; there is now only one copy.
pub fn parse_ceiling(subject: &str, token: &str) -> Result<Scope, String> {
    Scope::parse(token).ok_or_else(|| {
        format!(
            "{subject} has unknown max_admin_scope '{token}': expected read-only or full. \
             There is no `none`: omit the key for the most restrictive default \
             (`{}`), and to grant NO admin authority through this identity source grant no \
             `admin_scope` under its `role_bindings:` — the ceiling caps what a grant can \
             reach, it cannot express the absence of one.",
            busbar_substrate::config::auth::DEFAULT_MAX_ADMIN_SCOPE
        )
    })
}
