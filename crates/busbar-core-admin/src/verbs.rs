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
//! 3. **Posture** (new verbs only). [`crate::posture::check_new_verb_admission`]. The five ledger
//!    views ([`crate::verb::LEDGER_VERBS`]) are answered BEFORE this step and never reach it: a view
//!    reads figures the ledger already holds, so there is no mutation for dual control to check and
//!    no ceremony for it to wait on. They reach [`crate::governance::Governance::execute_ledger_read`]
//!    instead, having passed exactly the same scope and rate checks as everything above. The three
//!    audit-chain reads ([`crate::verb::AUDIT_VERBS`]) are answered on the same rung, one branch
//!    later, through [`crate::governance::Governance::execute_audit_read`], for the same reason and
//!    with the same checks run first.
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
use crate::posture::{ApprovalState, PostureCtx};
use crate::rate::{ConfigClassRule, MutationClass, MutationLimiter, RateCheck};
use crate::refusal::{store_error_into_refusal, ReasonCode, Refusal, RefusalStep};
use crate::verb::{
    KernelVerb, VerbScope, AUDIT_VERBS, LEDGER_VERBS, LEGACY_VERBS, NEW_VERBS, READ_ONLY_NEW_VERBS,
};
use busbar_contract::caps::{AdminVerb, Grant};
use busbar_contract::verb_store::Store;
use std::sync::Arc;

/// Resolve the scope a [`KernelVerb`] requires. Legacy verbs read [`LEGACY_VERBS`]; fifteen of the
/// new money-governance verbs are `Full` (they mutate state or read privileged material) and the two
/// the document binds as `GET` ([`READ_ONLY_NEW_VERBS`]) are `ReadOnly`, by exactly 1.5.5's own
/// method rule; the five ledger views and the three audit-chain reads
/// ([`crate::verb::AUDIT_VERBS`]) are `ReadOnly` (the 1.6.0 additions that only look); the named
/// surfaces split by their own nature (`Get*` reads, the two
/// `/auth/token` methods are their own thing and never checked against this two-rung scope model at
/// all — see the module doc on why `Verbs::execute` is not the caller for them).
pub fn required_scope(verb: KernelVerb) -> VerbScope {
    if let Some(row) = LEGACY_VERBS.iter().find(|r| r.verb == verb) {
        return row.scope;
    }
    // Checked before the group as a whole, because these two are members of it: `verify` and
    // `plane_facts` are bound `GET`, and 1.5.5's rule is that a `GET` asks for `read-only`. Asking
    // `full` of them refuses the operator whose credential was only ever meant to look.
    if READ_ONLY_NEW_VERBS.contains(&verb) {
        return VerbScope::ReadOnly;
    }
    if NEW_VERBS.contains(&verb) {
        return VerbScope::Full;
    }
    // The five ledger views are reads, and are answered here rather than by the fallthrough below
    // so that the scope is a decision this function MAKES about them. The fallthrough happens to
    // land on the same rung, and that coincidence is exactly why it must not be relied on: a
    // read-only view and an unrecognised verb would then be indistinguishable, and the day the
    // fallthrough is tightened to `Full` — the safe direction for an unknown — every ledger view
    // would silently start demanding a full-scope credential.
    if LEDGER_VERBS.contains(&verb) {
        return VerbScope::ReadOnly;
    }
    // The three audit-chain reads, answered here for the same reason as the ledger views: the rung
    // must be a decision this function MAKES, not a coincidence of where the fallthrough lands. A
    // chain read is the one surface whose whole point is that somebody who does not trust the node
    // can check it, so it asks for the same rung as `GET /audit` has since 1.5.5 and no more.
    if crate::verb::AUDIT_VERBS.contains(&verb) {
        return VerbScope::ReadOnly;
    }
    // Named surfaces: every `Get*` is a read; `PostAuthToken`/`GetAuthToken` are exempt from this
    // model entirely (see module doc) and are given `ReadOnly` here only so `required_scope` stays
    // total — a caller must not route either through `Verbs::execute`.
    VerbScope::ReadOnly
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

    /// The generic dispatcher: every legacy operation but the two key mints, the new verbs
    /// (posture-gated), and nothing else. `PostKeys` and `PostKeysIdRotate` are refused here rather
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
        posture: Option<PostureCtx>,
        approval: ApprovalState,
        request: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        // The two minting verbs are REFUSED here, in every build, rather than asserted against in
        // one of them. This path has no replay cache: routed through it, a mint reaches the legacy
        // catch-all and a retry inside the idempotency window mints a second admin credential the
        // client never asked for and will never see. A `debug_assert` said so in a debug build and
        // said nothing in a release binary, which is the build where a miswired caller ships.
        if verb == KernelVerb::PostKeys || verb == KernelVerb::PostKeysIdRotate {
            return Err(Refusal::new(RefusalStep::Admit, ReasonCode::Internal));
        }
        self.admit(verb, actor, granted, now)?;
        // A ledger view is answered BEFORE the new-verb branch, and the ordering is the whole of
        // its posture: it never reaches `check_new_verb_admission`, because there is no mutation
        // for dual control to check and no ceremony a read has to wait for. What it does reach is
        // the same `admit` above every other verb reaches, so its scope and its rate class are
        // decided by the same two lines that decide every other verb's.
        if LEDGER_VERBS.contains(&verb) {
            return self
                .governance
                .execute_ledger_read(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        // An audit-chain read is answered here for the same reason a ledger view is, one branch
        // above: it never reaches `check_new_verb_admission`, because there is no mutation for dual
        // control to check and no ceremony a read has to wait for. Without this branch the three
        // verbs RESOLVED — they are in the closed table, they carry a scope and a rate class — and
        // then fell past both this arm and the posture-gated one into the legacy catch-all, where a
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
            // A posture-gated verb whose posture the caller did not resolve is REFUSED, not
            // unwrapped. "A new verb always arrives with one" is a claim about a call site, and a
            // miswired caller — or a verb added to the gated set on one side only — would otherwise
            // turn an admin request into a downed process at the point where the gate was supposed
            // to protect something.
            let Some(ctx) = posture else {
                return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
            };
            crate::posture::check_new_verb_admission(verb, ctx, approval)?;
            return self
                .governance
                .execute_new_verb(verb, admin, request, ctx.operator)
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

    /// The gate the three disaster-recovery verbs run through before they reach the store.
    ///
    /// Identical to what [`Verbs::execute`] runs for any other new verb — scope, rate class, then
    /// the operator ceremony and dual control — because these three are new verbs; the only thing
    /// that makes them different is that their effect lands on [`Store`] rather than
    /// [`Governance`], and where an effect lands is not a reason to be admitted differently. A
    /// posture the caller did not resolve is REFUSED rather than unwrapped, for the same reason it
    /// is in `execute`: a miswired caller must not turn the gate protecting a chain break into a
    /// downed process.
    fn admit_recovery_verb(
        &self,
        verb: KernelVerb,
        actor: &str,
        granted: VerbScope,
        now: u64,
        posture: Option<PostureCtx>,
        approval: ApprovalState,
    ) -> Result<(), Refusal> {
        self.admit(verb, actor, granted, now)?;
        let Some(ctx) = posture else {
            return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
        };
        crate::posture::check_new_verb_admission(verb, ctx, approval)
    }

    /// `chain_break` — deliberately break the journal chain. Admitted through
    /// [`Verbs::admit_recovery_verb`] and only then handed to the store.
    pub fn chain_break(
        &self,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
        posture: Option<PostureCtx>,
        approval: ApprovalState,
    ) -> Result<(), Refusal> {
        self.admit_recovery_verb(
            KernelVerb::ChainBreak,
            actor,
            granted,
            now,
            posture,
            approval,
        )?;
        self.bound_store()
            .and_then(|store| store.chain_break(admin))
            .map_err(store_error_into_refusal)
    }

    /// `store_restore` — restore the store from a named backup. Admitted through
    /// [`Verbs::admit_recovery_verb`] and only then handed to the store.
    #[allow(clippy::too_many_arguments)]
    pub fn store_restore(
        &self,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
        posture: Option<PostureCtx>,
        approval: ApprovalState,
        backup_ref: &str,
    ) -> Result<(), Refusal> {
        self.admit_recovery_verb(
            KernelVerb::StoreRestore,
            actor,
            granted,
            now,
            posture,
            approval,
        )?;
        self.bound_store()
            .and_then(|store| store.store_restore(admin, backup_ref))
            .map_err(store_error_into_refusal)
    }

    /// `reseal_epoch_floor` — reseal the epoch floor after a chain break or restore. Admitted
    /// through [`Verbs::admit_recovery_verb`] and only then handed to the store.
    pub fn reseal_epoch_floor(
        &self,
        admin: &Grant<AdminVerb>,
        actor: &str,
        granted: VerbScope,
        now: u64,
        posture: Option<PostureCtx>,
        approval: ApprovalState,
    ) -> Result<(), Refusal> {
        self.admit_recovery_verb(
            KernelVerb::ResealEpochFloor,
            actor,
            granted,
            now,
            posture,
            approval,
        )?;
        self.bound_store()
            .and_then(|store| store.reseal_epoch_floor(admin))
            .map_err(store_error_into_refusal)
    }
}

#[cfg(test)]
#[path = "tests/verbs_tests.rs"]
mod tests;
