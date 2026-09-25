//! The admin surface's own declarations: its closed verb table, its one claim, and the frozen
//! error envelope every refusal on that surface is written in.
//!
//! ## What this module is
//!
//! The closed table of 66 operations the 1.5.5 admin API tag defines (mechanically extracted into
//! `generated::verb_table_1_5_5`, 49 paths, 34 read-only and 32 full) plus the 13 additional 1.6.0
//! money-governance verbs the design names by name (`verify`, `plane_facts`, `plane_record_write`,
//! `chain_break`, `store_restore`, `reseal_epoch_floor`, `set_overdraft_ceiling`,
//! `set_dispute_max_age`, `commit_upgrade`, `resolve_dispute`, `resolve_slice`, `adjust`,
//! `amend_rate_history`), the 5 1.6.0
//! ledger views (the read-only `/api/v1/admin/ledger/*` surface) and the 3 1.6.0 audit-chain reads
//! (the read-only `/api/v1/admin/audit/{head,range,keys}` surface an outside verifier pulls the
//! signed chain through). Every one of those operations is a `KernelVerb` destination this table
//! names; none of them is EXECUTED here.
//! [`verbs::resolve`] is how the composition root's admin mount asks which row a method and path
//! name, and [`refusal::envelope_of`] is the one place the wire shape of an admin error is written.
//!
//! ## What this module is NOT — there is no plane entry face here
//!
//! **A `Plane` is how TRAFFIC enters the dispatch loop, and the admin surface serves operators, not
//! traffic (#83 def 11).** Admin is not a plugin and there is no `control` plugin kind (#3/#5): it
//! is a compiled-in cleanliness crate with a one-way dependency on the kernel, off the hot path.
//! So this module implements no `Plane`, and nothing decodes an admin frame here.
//!
//! An admin request arrives on the administrative listener (`admin_listen`), is matched against
//! [`verbs::resolve`] by the root's admin mount, and walks the kernel's loop as the ADMIN UNITS —
//! `crates/busbar/src/root/units_admin`, which owns the decode, authenticate, verify, approve,
//! admit, route, meter and audit steps for that walk and renders every answer through
//! [`refusal::envelope_of`]. Every fact the removed face used to state about a unit (which resource
//! an operation touches, which kernel verb it is a destination for, what it cost, what the audit
//! chain records) is stated there, on the admin path, rather than inherited by pretending an
//! operator's request is somebody's traffic.
//!
//! What this module still declares about the admin surface — [`meta`]'s `PlaneMeta` row and
//! [`claims::CLAIMS`] — is DATA: the key the surface is registered under, the one path pattern it
//! answers for, and the operation/content classes its units seal under. A declaration is not an
//! entry face; nothing dispatches through it. It is not dead weight either: the claim is what makes
//! a second plane claiming `/api/v1/admin/*` on `http` a BOOT REFUSAL rather than a race decided at
//! the first request (`root::registry::seal` -> `seal_claims`).
//!
//! **And there is no `SessionPlane` half.** The one claim is plain HTTP request/response — the
//! registry requires `SessionPlane` only when a claimed transport declares itself session-shaped,
//! and `http` does not — so there is no session for a fact to attach to and nothing here caches a
//! credential across requests. `meta`'s empty `SESSION_FACTS` and `claims`'s note both point here
//! for that reason.
//!
//! ## What this module is NOT, continued — an explicit scope boundary
//!
//! The design's admin section pins the closed 66+18+5+3 table AND separately names five 1.5.5
//! surfaces that live outside it, each pinned by its own handler rather than by this table: the
//! self-serve token exchange (`POST /auth/token` and its browser-facing `GET` twin), the
//! governance-scoped model listings (`GET /v1/models`, `/v1beta/models`), `/stats`, the
//! unconditional-bypass `/healthz`, and the conditionally-present `/metrics` / `/metrics/hooks`.
//! **This table declares NONE of them.** They are not admin verbs in the sense this table declares
//! them, they carry their own auth posture (several bypass admin auth entirely), and reaching them
//! here would blur exactly the line the design draws. Treat their absence here as a boundary, not a
//! gap — the root's admin mount hands any path this table does not declare straight to the surface
//! that already answers it.
//!
//! ## And no governance, no secrets
//!
//! There is no dual-control arithmetic, no scope decision and no ledger arithmetic in this module.
//! The scope unit is what compares a resource against a principal's held grant. Every "mints via
//! `SecretOnce`" note in the design's admin row belongs to the verb execution, never to this
//! table: a `SecretOnce` placeholder that appeared in this module's own logic would be a defect,
//! not a feature.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod generated;
pub mod meta;
pub mod refusal;
#[cfg(test)]
mod tests;
pub mod verbs;

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The admin surface, as the registry names it.
///
/// A NAME AND A DECLARATION, NOT AN ENTRY FACE. It carries [`Plugin`] (so the boot registry can
/// hold it under one key) and `meta`'s `PlaneMeta` row (so the claim table can read what the
/// surface answers for), and it carries no `Plane`: a `Plane` is how TRAFFIC enters the dispatch
/// loop, and this surface serves operators on their own listener. See the module doc comment.
///
/// No fields, and none it could grow: everything it answers is a constant of the closed table, and
/// nothing about one operator's request outlives that request here. The zero-size test in `tests`
/// asserts that structurally rather than by comment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdminPlane;

impl AdminPlane {
    /// A new handle on the admin surface. There is nothing to configure: see
    /// `meta::CONFIG_SCHEMA`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Plugin for AdminPlane {
    fn key(&self) -> &'static str {
        <Self as busbar_contract::plane::PlaneMeta>::KEY
    }

    fn kind(&self) -> Kind {
        Kind::Plane
    }

    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}
