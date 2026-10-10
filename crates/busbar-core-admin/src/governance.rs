// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The governance seam: the trait the integrator binds to the concrete key/group/hook/plugin/etc.
//! record store (1.5.5's `GovState` and its neighbours in `busbar-core`).
//!
//! This crate names these governance calls:
//!
//! - [`Governance::execute_legacy`] / [`Governance::execute_new_verb`] — `// contract:` catch-alls
//!   for every legacy operation but the two key mints (config, hooks, plugins, export,
//!   identity-providers, audit, info, usage, admin-auth, pools, providers, restart, signing-key
//!   rotate, overlay) and every new verb's actual effect
//!   (once posture admits it). `Verbs::execute` (in `crate::verbs`) already enforces scope, rate
//!   limit and posture BEFORE reaching either catch-all, so what
//!   lands here is already an admitted call — the catch-all's only job is the verb's own domain
//!   effect. `request`/`response` are opaque bytes because this crate carries no serializer (see
//!   the crate doc): the codec's own wire types pass through unchanged.

use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use crate::verb::KernelVerb;
use busbar_contract::caps::{AdminVerb, Grant};

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

/// The governance seam.
pub trait Governance {
    /// `// contract:` every legacy verb's actual effect but the two key mints (answered by the served
    /// handlers in `crate::keys`). `Verbs::execute` has already checked scope and rate class by the
    /// time a call reaches here; this call's only job is the verb's own domain effect over already-admitted
    /// input.
    fn execute_legacy(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError>;

    /// `// contract:` the actual effect of a new 1.6.0 verb, once
    /// [`crate::posture::check_new_verb_admission`] has already admitted it (operator gate, then
    /// dual control). `Verbs::execute` never calls this for a refused verb.
    ///
    /// `operator` is the resolved [`crate::posture::OperatorState`] the admission was checked
    /// against, carried through so a verb whose effect is verified against the sealed operator key
    /// (D38 `amend_rate_history`) can read the key material without a second policy read. A verb
    /// whose effect needs no key ignores it; the gate above has already guaranteed it is
    /// [`crate::posture::OperatorState::Set`] for every irreducible verb.
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
        operator: crate::posture::OperatorState,
    ) -> Result<Vec<u8>, GovernanceError>;

    /// `// contract:` the answer to one of the five 1.6.0 ledger views
    /// ([`crate::verb::LEDGER_VERBS`]), once `Verbs::execute` has checked its scope. A view reads
    /// figures the ledger already holds and mutates nothing, which is why it has a seam of its own
    /// rather than sharing [`Governance::execute_new_verb`]: that method's callers have passed a
    /// posture check this one deliberately has not, and folding a read into it would make the two
    /// indistinguishable to an implementor.
    ///
    /// The default answers `NotFound`, which is the truthful answer for an integrator that has not
    /// bound a ledger: there is no ledger behind the view, so there are no figures to serve, and
    /// inventing zeros would be a reconciliation that reports as balanced because nothing was ever
    /// read. It is also what keeps this addition additive — an existing implementor compiles
    /// unchanged and serves nothing it does not have.
    ///
    /// # Errors
    ///
    /// The view could not be answered. The default returns [`GovernanceError::NotFound`].
    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        let (_, _, _) = (verb, admin, request);
        Err(GovernanceError::NotFound)
    }

    /// `// contract:` the answer to one of the three 1.6.0 audit-chain reads
    /// ([`crate::verb::AUDIT_VERBS`]), once `Verbs::execute` has checked its scope.
    ///
    /// A seam of its own for the same reason [`Governance::execute_ledger_read`] is one, and for one
    /// more. The same reason first: these three are READS — they mutate nothing, so there is no
    /// maker-checker step for dual control to interpose and no ceremony a read has to wait for, and
    /// folding them into [`Governance::execute_new_verb`] would make a posture-gated mutation and an
    /// ungated read indistinguishable to an implementor. The one more: what they read is not what
    /// the ledger holds. The ledger seam answers with money; this one answers with the chain — where
    /// it is, what is in a window of it, and which public keys signed it — and an integrator that
    /// has bound one has not thereby bound the other.
    ///
    /// PULL, NEVER PUSH. The node ANSWERS through this seam. Nothing behind it opens an outbound
    /// connection, holds a cloud credential or phones anybody: that is what lets an airgapped
    /// operator `curl` their own evidence, and it is why counter-signing is somebody else's product.
    ///
    /// The default answers `NotFound`, which is the truthful answer for an integrator that has bound
    /// no chain: there is no chain behind the read, so there is no head to report, and answering
    /// with an empty one would be this seam claiming a node had sealed nothing when in fact nobody
    /// had asked it. `docs/design/BUSBAR-1.6.0.md:2079` — A GAP AND A FAILURE MUST NEVER BE THE SAME
    /// OUTPUT — is exactly that distinction: an unbound chain and an empty chain are different
    /// facts and must not be one answer. It is also what keeps this addition additive: an existing
    /// implementor compiles unchanged and serves nothing it does not have.
    ///
    /// # Errors
    ///
    /// The read could not be answered. The default returns [`GovernanceError::NotFound`].
    fn execute_audit_read(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        let (_, _, _) = (verb, admin, request);
        Err(GovernanceError::NotFound)
    }
}
