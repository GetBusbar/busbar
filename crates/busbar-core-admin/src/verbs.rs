// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Verbs` — the one entry point the admin codec calls: `execute(KernelVerb, &Grant<AdminVerb>)`, plus
//! the call context every verb needs (who is calling, what scope they were granted, the current
//! time, and the extra fields the verbs read).
//!
//! What happens before a verb's own effect, for EVERY verb, in this order:
//!
//! 1. **Scope.** `granted.allows(required_scope(verb))` — refused `Unauthorized` otherwise. Scope
//!    is resolved from [`crate::verb::LEGACY_VERBS`] for a legacy verb; the new verbs and the
//!    named surfaces are `Full`-scoped mutations and reads respectively by construction (a `Get*`
//!    surface is a read, everything else in that group is a mutation the calling context must
//!    already be authorized for by the time it reaches this crate — the admin plane's own auth
//!    middleware, which this crate does not run).
//! 2. **Rate limit.** [`crate::rate::MutationClass::for_verb`] then
//!    [`crate::rate::MutationLimiter::check`] — refused `RateLimited` otherwise. Reads never reach
//!    the limiter at all (their class is `Forbidden`, i.e. never checked). The limiter is the one
//!    the composition root built for the life of the node and handed to [`Verbs::new`], so the
//!    window outlives the request; and it spends only the new verbs (see [`Verbs::admit`] for why
//!    a legacy verb's budget is not spent here).
//! 3. **Nothing else.** There is no posture step: the admin API is dumb (#77(9) OWNER-LOCKED,
//!    `docs/design/BUSBAR-1.6.0.md` l.2279) — no verb carries dual control, escrow or operator
//!    signatures, and each verb is a plain scoped verb authorized by the token's grant. The five
//!    ledger views ([`crate::verb::LEDGER_VERBS`]) reach
//!    [`crate::governance::Governance::execute_ledger_read`], the three audit-chain reads
//!    ([`crate::verb::AUDIT_VERBS`]) reach [`crate::governance::Governance::execute_audit_read`],
//!    and every other new verb reaches [`crate::governance::Governance::execute_new_verb`], each
//!    having passed exactly the same scope and rate checks.
//! 4. **Idempotency** is not a step of this executor. The two replayable mutations, `POST /keys`
//!    and `POST /keys/{id}/rotate`, are answered by the served handlers in [`crate::keys`] behind
//!    the kernel's mutation limiter, against the node's one process-lifetime
//!    [`crate::idempotency::IdempotencyCache`]; [`Verbs::execute`] refuses both verbs.
//!
//! Only once all of that has admitted the call does anything reach [`crate::governance::Governance`]
//! or [`busbar_kernel_seams::verb_store::Store`]. That holds for the two disaster-recovery verbs too: their effect
//! lands on the store rather than on governance, but they are new verbs like any other, so they
//! reach the store only through [`Verbs::chain_break`] and [`Verbs::store_restore`], each of which
//! runs the same admission first. The bound store is
//! not handed out — a caller holding it could have run either with none of the checks,
//! and nothing in the type system would have asked it not to.

use crate::governance::{Governance, GovernanceError};
use crate::rate::{ConfigClassRule, MutationClass, MutationLimiter, RateCheck};
use crate::refusal::{store_error_into_refusal, ReasonCode, Refusal, RefusalStep};
use crate::verb::{KernelVerb, VerbScope, AUDIT_VERBS, LEDGER_VERBS, NEW_VERBS};
use busbar_contract::caps::{AdminVerb, Grant};
use busbar_kernel_seams::verb_store::Store;
use std::sync::Arc;

pub fn required_scope(verb: KernelVerb) -> VerbScope {
    crate::verb::row_of(verb).map_or(VerbScope::Full, |row| row.scope)
}

pub struct Verbs<G: Governance, S: Store + ?Sized> {
    governance: G,

    store: Option<Arc<S>>,
    config_class_rules: &'static [ConfigClassRule],

    limiter: Arc<MutationLimiter>,
}

impl<G: Governance, S: Store + ?Sized> Verbs<G, S> {
    pub fn new(
        governance: G,
        store: Option<Arc<S>>,
        config_class_rules: &'static [ConfigClassRule],
        limiter: Arc<MutationLimiter>,
    ) -> Self {
        Verbs {
            governance,
            store,
            config_class_rules,
            limiter,
        }
    }

    fn admit(
        &self,
        verb: KernelVerb,
        actor: &str,
        granted: VerbScope,
        now: u64,
    ) -> Result<MutationClass, Refusal> {
        if !granted.allows(required_scope(verb)) {
            return Err(Refusal::new(RefusalStep::Admit, ReasonCode::Unauthorized));
        }
        let class = MutationClass::for_verb(verb, self.config_class_rules);
        if class == MutationClass::Forbidden || !NEW_VERBS.contains(&verb) {
            return Ok(class);
        }
        match self.limiter.check(actor, class, now) {
            RateCheck::Admitted => Ok(class),
            RateCheck::Denied { .. } => {
                Err(Refusal::new(RefusalStep::Admit, ReasonCode::RateLimited))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
        request: &[u8],
    ) -> Result<G::Answer, Refusal> {
        if verb == KernelVerb::PostKeys || verb == KernelVerb::PostKeysIdRotate {
            return Err(Refusal::new(RefusalStep::Admit, ReasonCode::Internal));
        }
        self.admit(verb, actor, granted, now)?;

        if LEDGER_VERBS.contains(&verb) {
            return self
                .governance
                .execute_ledger_read(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }

        if AUDIT_VERBS.contains(&verb) {
            return self
                .governance
                .execute_audit_read(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        if NEW_VERBS.contains(&verb) {
            return self
                .governance
                .execute_new_verb(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        self.governance
            .execute_legacy(verb, admin, request)
            .map_err(GovernanceError::into_refusal)
    }

    #[cfg(test)]
    fn store_for_test(&self) -> &S {
        self.store.as_deref().expect("these tests bind a store")
    }

    fn bound_store(&self) -> Result<&S, busbar_kernel_seams::verb_store::StoreError> {
        self.store
            .as_deref()
            .ok_or(busbar_kernel_seams::verb_store::StoreError::Failed)
    }

    pub fn chain_break(
        &self,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
    ) -> Result<(), Refusal> {
        self.admit(KernelVerb::ChainBreak, actor, granted, now)?;
        self.bound_store()
            .and_then(|store| store.chain_break(admin))
            .map_err(store_error_into_refusal)
    }

    pub fn store_restore(
        &self,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
        backup_ref: &str,
    ) -> Result<(), Refusal> {
        self.admit(KernelVerb::StoreRestore, actor, granted, now)?;
        self.bound_store()
            .and_then(|store| store.store_restore(admin, backup_ref))
            .map_err(store_error_into_refusal)
    }
}

#[cfg(test)]
#[path = "tests/verbs_tests.rs"]
mod tests;
