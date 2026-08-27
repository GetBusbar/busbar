// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE TRUST VERB SURFACE on the admin API, written ONCE and parameterised by plane — the
//! CORE-side half of the neutral seam whose plane-facing half is [`busbar_substrate::admin_verbs`].
//!
//! Every plane that fronts a registered upstream owes an operator the same three things, in the same
//! order: resolve the registration or refuse with a `404`, GO AND LOOK at the upstream, and record
//! what was found in the audit trail whatever it turned out to be. That sequence is
//! [`busbar_substrate::admin_verbs::connect_reply`], neutral and written once; this file is what stays
//! CORE about it: the audit record (the frozen `<kind>.<verb>` on `<kind>:<name>`), and the boundary
//! that maps the neutral [`busbar_substrate::admin_verbs::PlaneVerbError`] back onto the frozen
//! [`AdminError`] the JSON envelope speaks.
//!
//! ## What the plane supplies, and what it may not
//!
//! [`PlaneTrust`] (relocated to the substrate) is three items: which plane this is, how to resolve one
//! registration, and how to look at it. Everything else — the refusal wording, the audit resource, the
//! ordering of the audit record against the answer, the envelope — belongs to this file and the core
//! adapter, and a plane cannot restate it.
//!
//! The plane's IDENTITY STRINGS are not restated either: the `404` noun and the audit resource kind
//! come from the plane decl's `subject_noun` and `audit_kind`. There is no `match` on the plane in this
//! file, and adding one would mean the parameterisation had failed.
//!
//! ## THE 404 IS ONE RULE because the alternative is an existence oracle
//!
//! A registration present in the catalogue and absent from config — or the reverse — is not a state a
//! config generation can produce. Both planes therefore answer a missing EITHER half with the same
//! not-found rather than two answers a caller could tell apart, and
//! [`busbar_substrate::admin_verbs::registered`] is where that is decided once; the not-found WORDING is
//! reconstructed here, in [`to_admin_error`], from the plane decl.

use crate::admin::v1::contract::AdminError;

/// Re-export the relocated resolve/look seam so `crate::admin::planeverbs::{PlaneTrust, PlaneVerbError,
/// registered}` keeps resolving for the in-core (a2a) callers and the shared `connect` bound.
pub use busbar_substrate::admin_verbs::{registered, PlaneTrust, PlaneVerbError};

/// RECORD ONE PLANE TRUST VERB in the audit trail.
///
/// The action word and the resource are DERIVED from the plane and the verb rather than spelled out
/// per plane, so a new verb cannot invent a spelling and a new plane cannot invent a naming scheme.
/// The shape is the established one: `<kind>.<verb>` acting on `<kind>:<name>`.
pub(crate) fn audit(
    plane: &'static str,
    verb: &str,
    name: &str,
    outcome: &'static str,
    principal: &crate::auth::AuthPrincipal,
) {
    let audit_kind = crate::plane::plane_decl(plane).audit_kind;
    crate::admin::audit::AUDIT.record_by(
        &format!("{audit_kind}.{verb}"),
        &format!("{audit_kind}:{name}"),
        outcome,
        principal.actor_id(),
    );
}

/// THE BOUNDARY: map the neutral [`PlaneVerbError`] a plane's `resolve`/`look` produced back onto the
/// frozen [`AdminError`] the JSON envelope speaks. `NotFound` has no wording of its own — the frozen
/// `"<subject_noun> `<name>`"` phrasing is reconstructed HERE from the plane decl, so it stays in one
/// place and reads identically on every plane. `Validation` carries its human message verbatim;
/// `Internal`'s diagnostic string is dropped (the wire message is core's generic one).
pub(crate) fn to_admin_error(plane: &'static str, name: &str, err: PlaneVerbError) -> AdminError {
    match err {
        PlaneVerbError::NotFound => AdminError::not_found(format!(
            "{} `{name}`",
            crate::plane::plane_decl(plane).subject_noun
        )),
        PlaneVerbError::Validation(msg) => AdminError::Validation(msg),
        PlaneVerbError::Internal(_) => AdminError::Internal,
    }
}

#[cfg(test)]
#[path = "tests/planeverbs_tests.rs"]
mod planeverbs_tests;
