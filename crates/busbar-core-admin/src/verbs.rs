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
//! or [`busbar_contract::verb_store::Store`]. That holds for the three disaster-recovery verbs too: their effect
//! lands on the store rather than on governance, but they are new verbs like any other, so they
//! reach the store only through [`Verbs::chain_break`], [`Verbs::store_restore`] and
//! [`Verbs::reseal_epoch_floor`], each of which runs the same admission first. The bound store is
//! not handed out — a caller holding it could have run any of the three with none of the checks,
//! and nothing in the type system would have asked it not to.

use crate::governance::{Governance, GovernanceError};
use crate::rate::{ConfigClassRule, MutationClass, MutationLimiter, RateCheck};
use crate::refusal::{store_error_into_refusal, ReasonCode, Refusal, RefusalStep};
use crate::verb::{KernelVerb, VerbScope, AUDIT_VERBS, LEDGER_VERBS, NEW_VERBS};
use busbar_contract::caps::{AdminVerb, Grant};
use busbar_contract::verb_store::Store;
use std::sync::Arc;

/// Resolve the scope a [`KernelVerb`] requires: the scope its row in [`crate::verb::TABLE`]
/// carries (1.5.5's method rule: reads and the two dry-run POSTs are `ReadOnly`, every mutation is
/// `Full`; the ledger views and audit-chain reads are `GET`s, so `ReadOnly`; a named surface is
/// `ReadOnly` only so this stays total and is never routed through `Verbs::execute`). A verb with
/// no row asks for `Full`.
pub fn required_scope(verb: KernelVerb) -> VerbScope {
    crate::verb::row_of(verb).map_or(VerbScope::Full, |row| row.scope)
}

/// `Verbs` — the closed kernel-verb executor. Generic over the seams the integrator binds: the
/// [`Governance`] and [`Store`] record-store adapters. `config_class_rules` is data rather than a
/// third type parameter — a `&'static` table has no behaviour to seal behind a trait.
pub struct Verbs<G: Governance, S: Store + ?Sized> {
    governance: G,
    /// The node's store, shared with the composition that built it; `None` on a node with no
    /// configured store, where each disaster-recovery verb is refused as a store failure.
    store: Option<Arc<S>>,
    config_class_rules: &'static [ConfigClassRule],
    /// The node's mutation limiter: built ONCE by the composition root and shared by every `Verbs`
    /// it builds. A `Verbs` lives for one request, so a limiter it built for itself saw an empty
    /// window on every call and never refused anything.
    limiter: Arc<MutationLimiter>,
}

impl<G: Governance, S: Store + ?Sized> Verbs<G, S> {
    /// Build a fresh executor over the bound seams. `config_class_rules` is the composition
    /// root's sealed class table (see [`crate::rate::CONFIG_CLASS_RULES`] for the 1.5.5-parity
    /// default); `limiter` is mandatory: it is the node's, built once for the life of the process,
    /// and there is no per-executor default that could stand in for it — a limiter born with the
    /// request forgets every attempt before the next one.
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

    /// The scope + rate-limit gate every verb runs through. Returns the [`MutationClass`] on
    /// success, so a caller that must also check idempotency doesn't re-derive it.
    ///
    /// ONE REQUEST, ONE LIMITER. A legacy verb (every verb with a [`LEGACY_VERBS`] row, the two
    /// mint verbs among them) is answered by the 1.5.5 surface it always was, and that surface
    /// spends the principal's mutation budget itself, in front of the handler, exactly as 1.5.5
    /// did. Spending it here as well would count one request twice and refuse at half the budget
    /// 1.5.5 granted. So this limiter spends exactly the verbs no legacy surface answers — the new
    /// verbs ([`NEW_VERBS`]), whose effects land on the store, the journal and the kernel's books
    /// and meet no other limiter on their way.
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
            // Never rate-limited here: a read, or a legacy verb whose own surface spends its budget.
            return Ok(class);
        }
        match self.limiter.check(actor, class, now) {
            RateCheck::Admitted => Ok(class),
            RateCheck::Denied { .. } => {
                Err(Refusal::new(RefusalStep::Admit, ReasonCode::RateLimited))
            }
        }
    }

    /// The generic dispatcher: every legacy operation but the two key mints, the new verbs, and
    /// nothing else. `PostKeys` and `PostKeysIdRotate` are refused here rather
    /// than served, because this path carries none of the replay machinery the served handlers in
    /// [`crate::keys`] answer them with.
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
        // The two minting verbs are REFUSED here, in every build, rather than asserted against in
        // one of them. This path has no replay cache: routed through it, a mint reaches the legacy
        // catch-all and a retry inside the idempotency window mints a second admin credential the
        // client never asked for and will never see. A `debug_assert` said so in a debug build and
        // said nothing in a release binary, which is the build where a miswired caller ships.
        if verb == KernelVerb::PostKeys || verb == KernelVerb::PostKeysIdRotate {
            return Err(Refusal::new(RefusalStep::Admit, ReasonCode::Internal));
        }
        self.admit(verb, actor, granted, now)?;
        // A ledger view is answered BEFORE the new-verb branch, by its own read seam. What it
        // reaches is the same `admit` above every other verb reaches, so its scope and its rate
        // class are decided by the same two lines that decide every other verb's.
        if LEDGER_VERBS.contains(&verb) {
            return self
                .governance
                .execute_ledger_read(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        // An audit-chain read is answered here for the same reason a ledger view is, one branch
        // above, by its own read seam. Without this branch the three verbs RESOLVED — they are in
        // the closed table, they carry a scope and a rate class — and then fell past both this arm
        // and the new-verb one into the legacy catch-all, where a
        // router that never had those paths answered a 404. A verb that resolves and then refuses is
        // the worst of the three possible states: the table says the surface exists and the surface
        // says it does not.
        if AUDIT_VERBS.contains(&verb) {
            return self
                .governance
                .execute_audit_read(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        if NEW_VERBS.contains(&verb) {
            // A plain scoped verb (#77(9)): the token's grant, checked in `admit` above, is the
            // whole of its authorization. No operator key, signature or second approver is asked.
            return self
                .governance
                .execute_new_verb(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        self.governance
            .execute_legacy(verb, admin, request)
            .map_err(GovernanceError::into_refusal)
    }

    /// The bound store, for this crate's own tests to observe what did and did not reach it.
    /// `cfg(test)` so it is not a way for a caller to route around the gates below.
    #[cfg(test)]
    fn store_for_test(&self) -> &S {
        self.store.as_deref().expect("these tests bind a store")
    }

    /// The bound store, or the refusal a node with none answers: there is nothing for the verb to
    /// reach, so it fails as a store failure rather than succeeding over nothing.
    fn bound_store(&self) -> Result<&S, busbar_contract::verb_store::StoreError> {
        self.store
            .as_deref()
            .ok_or(busbar_contract::verb_store::StoreError::Failed)
    }

    /// `chain_break` — deliberately break the journal chain. Admitted through
    /// [`Verbs::admit`] and only then handed to the store.
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

    /// `store_restore` — restore the store from a named backup. Admitted through
    /// [`Verbs::admit`] and only then handed to the store, which refuses it when it has
    /// no restore operation (the configured store never has one: restores happen off-node, row 187).
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

    /// `reseal_epoch_floor` — reseal the epoch floor after a chain break or restore. Admitted
    /// through [`Verbs::admit`] and only then handed to the store.
    pub fn reseal_epoch_floor(
        &self,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
    ) -> Result<(), Refusal> {
        self.admit(KernelVerb::ResealEpochFloor, actor, granted, now)?;
        self.bound_store()
            .and_then(|store| store.reseal_epoch_floor(admin))
            .map_err(store_error_into_refusal)
    }
}

#[cfg(test)]
#[path = "tests/verbs_tests.rs"]
mod tests;
