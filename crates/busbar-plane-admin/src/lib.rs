//! busbar-plane-admin — the HTTP codec for busbar's own admin surface.
//!
//! ## What this crate is
//!
//! One implementation of the plugin contract's plane kind, for the closed table of 66 operations the
//! 1.5.5 admin API tag defines (mechanically extracted into `generated::verb_table_1_5_5`, 49
//! paths, 34 read-only and 32 full) plus the 17 additional 1.6.0 money-governance verbs the design
//! names by name (`verify`, `plane_facts`, `plane_record_write`, `set_operator_key`, `set_escrow`,
//! `chain_break`, `store_restore`, `reseal_epoch_floor`, `set_dual_control`, `set_overdraft_ceiling`,
//! `set_dispute_max_age`, `commit_upgrade`, `resolve_dispute`, `resolve_slice`, `adjust`,
//! `export_keyset`, `approve`), and the 5 1.6.0 ledger views (the read-only
//! `/api/v1/admin/ledger/*` surface). Every one of those operations is a `KernelVerb` destination this
//! plane names; none of them is EXECUTED here. `busbar-unit-verbs`, on the far side of the kernel
//! from this plane, holds the admin credential and mints every one-time secret this surface ever
//! reveals (a rotated key, an exported keyset); this crate never sees one.
//!
//! ## What this crate is NOT — an explicit scope boundary
//!
//! The design's admin section pins the closed 66+17+5 table AND separately names five 1.5.5 surfaces
//! that live outside it, each pinned by its own handler rather than by this table: the self-serve
//! token exchange (`POST /auth/token` and its browser-facing `GET` twin), the governance-scoped
//! model listings (`GET /v1/models`, `/v1beta/models`), `/stats`, the unconditional-bypass
//! `/healthz`, and the conditionally-present `/metrics` / `/metrics/hooks`. **This plane decodes
//! NONE of them.** They are not admin verbs in the sense this crate's table declares them, they carry
//! their own auth posture (several bypass admin auth entirely), and reaching them here would blur
//! exactly the line the design draws. A future plane or a future claim on this same crate may take
//! them on; until then, treat their absence here as a boundary, not a gap.
//!
//! This plane also never dials an upstream (see `codec::AdminPlane`'s `route`, which always answers
//! an empty plan) and never opens a `SessionPlane` half: its one claim is plain HTTP request/response
//! ([`claims::CLAIMS`]), and the registry only requires `SessionPlane` when a claimed transport
//! declares itself session-shaped. `http` here does not.
//!
//! ## What this crate is not, continued: no governance, no secrets
//!
//! There is no dual-control arithmetic, no scope decision and no ledger arithmetic in this crate.
//! `approve` states which resource an operation touches; the scope unit is what compares that against
//! a principal's held grant. Every "mints via `SecretOnce`" note in the design's admin row belongs to
//! `busbar-unit-verbs`, never to this codec: this plane renders whatever bytes the verb execution
//! produced, and a `SecretOnce` placeholder that appeared in this crate's own logic would be a defect,
//! not a feature.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod codec;
pub mod generated;
pub mod meta;
pub mod refusal;
#[cfg(test)]
mod tests;
pub mod verbs;

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};

/// The admin plane.
///
/// No fields: every one of this plane's answers is a pure function of its inputs (the verb table,
/// the frame bytes, the unit) and of nothing this plane owns across calls. The purity/determinism
/// tests in `codec::tests` and the closed-loop table test both rely on that being literally true —
/// a plane that held state here would fail them the same way a plane that performed I/O would.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdminPlane;

impl AdminPlane {
    /// A new admin plane. There is nothing to configure: see `meta::CONFIG_SCHEMA`.
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
