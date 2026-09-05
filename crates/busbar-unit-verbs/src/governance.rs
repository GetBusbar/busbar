// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The governance seam: the trait the integrator binds to the concrete key/group/hook/plugin/etc.
//! record store (1.5.5's `GovState` and its neighbours in `busbar-core`).
//!
//! This crate names three kinds of governance calls:
//!
//! - [`Governance::group_exists`] / [`Governance::actual_parent`] — read-only, used by
//!   [`crate::mint::plan_mint_group`] before a mint.
//! - [`Governance::provision_group`], [`Governance::mint_key`], [`Governance::rotate_key`] — the
//!   three mutations behind the semantics this crate ports IN FULL (mint's group plan, rotate's
//!   scoping, both under the idempotency cache).
//! - [`Governance::execute_legacy`] / [`Governance::execute_new_verb`] — `// contract:` catch-alls
//!   for every OTHER legacy operation (config, hooks, plugins, export, identity-providers, audit,
//!   info, usage, admin-auth, pools, providers, restart, signing-key rotate, overlay — 60 of the 66
//!   legacy verbs are reached only through these two calls) and every new verb's actual effect
//!   (once posture admits it). `Verbs::execute` (in `crate::verbs`) already enforces scope, rate
//!   limit, idempotency (where applicable) and posture BEFORE reaching either catch-all, so what
//!   lands here is already an admitted call — the catch-all's only job is the verb's own domain
//!   effect. `request`/`response` are opaque bytes because this crate carries no serializer (see
//!   the crate doc): the codec's own wire types pass through unchanged.

use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use crate::verb::KernelVerb;
use busbar_caps::AdminToken;

/// A governance-layer error, mapped to a [`Refusal`] by [`GovernanceError::into_refusal`] rather
/// than exposed to the caller directly — the same fail-closed shape 1.5.5's admin handlers use
/// (`internal_error`/`join_error`): a store failure never echoes its cause past this boundary,
/// because several governance calls carry secrets.
#[derive(Debug)]
pub enum GovernanceError {
    /// The named resource does not exist.
    NotFound,
    /// The request conflicts with existing state.
    Conflict,
    /// The request failed validation.
    Validation,
    /// The underlying store failed; details are for the integrator's own logs only.
    Store,
}

impl GovernanceError {
    /// Map to the stable [`Refusal`] shape.
    pub fn into_refusal(self) -> Refusal {
        let reason = match self {
            GovernanceError::NotFound => ReasonCode::NotFound,
            GovernanceError::Conflict => ReasonCode::Conflict,
            GovernanceError::Validation => ReasonCode::Validation,
            GovernanceError::Store => ReasonCode::StoreError,
        };
        Refusal::new(RefusalStep::Verify, reason)
    }
}

/// A freshly minted or rotated key's once-shown material, as far as this crate's own logic needs to
/// see it (the secret text itself is never a plain `String` here — see
/// [`crate::verbs::Verbs::create_key`] for how it is wrapped in a [`busbar_caps::SecretOnce`] before
/// leaving this crate).
pub struct MintedKey {
    /// The key's id.
    pub id: String,
    /// The plaintext secret/token, shown exactly once.
    pub secret: String,
    /// Unix-seconds expiry, when the credential shape carries one.
    pub expires_at: Option<u64>,
}

/// The three rotate outcomes 1.5.5 distinguishes: not found (404), refused because the key is
/// tombstoned (revoked-and-deleted keys never rotate), or a fresh credential.
pub enum RotateOutcome {
    /// No key with this id exists.
    NotFound,
    /// The key exists but is tombstoned; rotation is refused.
    Tombstoned,
    /// Rotation succeeded; the new credential is shown exactly once.
    Rotated(MintedKey),
}

/// The governance seam.
pub trait Governance {
    /// Does a group with this exact name exist? `// contract:` — the integrator's cost-model group
    /// registry.
    fn group_exists(&self, name: &str) -> bool;

    /// An EXISTING group's actual parent (only called when [`Governance::group_exists`] holds for
    /// `name`). `// contract:`.
    fn actual_parent(&self, name: &str) -> Option<String>;

    /// Provision a new leaf group under `parent` (already known to exist), inheriting limits from
    /// the nearest-ancestor `child_default`. `// contract:` — the integrator's
    /// `build_with_group`-shaped validate-then-swap.
    fn provision_group(&self, admin: &AdminToken, group: &str, parent: &str) -> Result<(), GovernanceError>;

    /// Mint a fresh virtual key, optionally bound to `group` (already planned to exist by the time
    /// this is called — see [`crate::mint::plan_mint_group`]). `// contract:` — the integrator's
    /// key-cap check plus the actual credential mint.
    fn mint_key(&self, admin: &AdminToken, group: Option<&str>) -> Result<MintedKey, GovernanceError>;

    /// Rotate an existing key's credential in place (same id, budgets, usage; the previous
    /// credential stops authenticating immediately). `// contract:` — the integrator's
    /// check-then-act under its own existence-serializing lock (1.5.5's `EXISTENCE_GATE`).
    fn rotate_key(&self, admin: &AdminToken, id: &str) -> Result<RotateOutcome, GovernanceError>;

    /// `// contract:` every OTHER legacy verb's actual effect (60 of the 66 — everything but
    /// create/rotate key, whose SEMANTICS this crate ports directly). `Verbs::execute` has already
    /// checked scope, rate class and (for the two replayable ops) idempotency by the time a call
    /// reaches here; this call's only job is the verb's own domain effect over already-admitted
    /// input.
    fn execute_legacy(
        &self,
        verb: KernelVerb,
        admin: &AdminToken,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError>;

    /// `// contract:` the actual effect of a new 1.6.0 verb, once
    /// [`crate::posture::check_new_verb_admission`] has already admitted it (operator gate, then
    /// dual control). `Verbs::execute` never calls this for a refused verb.
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        admin: &AdminToken,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError>;
}
