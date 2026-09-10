// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEP 2 — WHERE THE UNIT MAY GO: the three pre-admission guards, in the one order they may run in.
//!
//! This is today's `destination_guard` — the LLM plane's `verify_destination` hook
//! (`native_ingress.rs`'s `GauntletPlane::verify_destination`, which calls
//! `EngineHost::destination_guard`) — expressed as the loop's verify step. Nothing about the
//! DECISION moves: the same three checks, in the same order, over the same reads, raising the same
//! two refusals.
//!
//! ## The order is the invariant
//!
//! 1. **the requested pool's allow-list** — the key names `allowed_pools` and this is not one of
//!    them;
//! 2. **every fallback pool reachable from it** — the requested pool's ACL covers only the FIRST
//!    pool, and the fallback dispatch never re-checks the key, so a key restricted to pool A could
//!    otherwise be served by pool B through A's `on_exhausted`. The walk carries the same
//!    visited-set guard the dispatch itself carries, so the two cannot diverge on a cycle;
//! 3. **the fail-closed unpriced-model gate** — with a rate card PRESENT, a name that is neither a
//!    configured pool nor a configured by-model lane and that the card does not price cannot be
//!    billed, so it is refused rather than served.
//!
//! Every one of the three can refuse, and all three run BEFORE the door charges. That is the whole
//! reason they are one step rather than three checks scattered over the path: a refusal after a
//! charge is a caller billed for a request that went nowhere, and refunding afterwards does not make
//! the ledger honest again.
//!
//! ## What is deliberately NOT here
//!
//! Candidate resolution and the model-miss 404. They stay AFTER the door, in the route step, exactly
//! where `native_ingress`'s `drive` has them today — a model miss is a CHARGED 404 that finishes
//! through the admitted tail. Moving resolution up here would turn it into an uncharged one and
//! change the request counts. Verify is the guards and nothing else.
//!
//! ## Named, not rendered
//!
//! A refusal here is a [`VerifyRefusal`]: a status, a kind word, and a message. It is not a
//! response. The audit step is the one place in this directory that turns a named refusal into
//! bytes, which is what keeps every terminal on this plane on one path — and what lets this file
//! carry no HTTP vocabulary beyond the two kind constants the live doors already spell.

use busbar_caps::{
    Decision, PrincipalId, ReasonCode, Refusal, UnitToken, VerifiedDestination, Verify,
};
use busbar_substrate::plane_host::{CostHandle, EngineHost, EngineTablesView};

use crate::unit::audit::RefusalOutcome;

/// The closed refusal set of this step: two refusals, and there is no third.
///
/// They are kept apart rather than collapsed because they are different answers to different
/// questions and they carry different statuses. A pool the caller may not reach is settled before
/// pricing is asked about at all; a name with no configured rate is a bad request, not an exhausted
/// budget. Collapsing them would make two refusals indistinguishable to anything reading the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyRefusal {
    /// The caller's key may not reach the pool it named, or a fallback pool reachable from it.
    ///
    /// One refusal for both, on purpose: a denial must be indistinguishable from outside whether it
    /// tripped on the requested pool or on a pool it would only have reached under exhaustion.
    NotAuthorized,
    /// A rate card is present and the name the caller supplied has no configured rate.
    NoRate {
        /// The name, as the caller spelled it — it appears in the message.
        name: String,
    },
}

impl VerifyRefusal {
    /// The status this refusal carries on the wire.
    ///
    /// Vendor-faithful and never 402: a pool the key may not reach is a permission answer, and an
    /// unbillable name is a bad request. No real provider answers either with a payment status, and
    /// emitting one would be a busbar tell.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            VerifyRefusal::NotAuthorized => 403,
            VerifyRefusal::NoRate { .. } => 400,
        }
    }

    /// The dialect-shaped kind word, read from the same bank the live doors read it from rather
    /// than respelled here.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            VerifyRefusal::NotAuthorized => busbar_substrate::proxy::KIND_PERMISSION,
            VerifyRefusal::NoRate { .. } => busbar_substrate::proxy::KIND_INVALID_REQUEST,
        }
    }

    /// The caller-facing message, verbatim.
    ///
    /// The permission copy is vendor-plausible and names NOTHING of the operator's: not the key id,
    /// not the pool, not a word of governance vocabulary — a native vendor 403 never does, and the
    /// key id and pool go to the operator's own diagnostics instead (see [`verify`]).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            VerifyRefusal::NotAuthorized => {
                "Your API key does not have permission to access this resource.".to_string()
            }
            VerifyRefusal::NoRate { name } => format!("no configured rate for model '{name}'"),
        }
    }

    /// THE NAMED OUTCOME — the three parts of this refusal as the one value the terminal renders.
    ///
    /// The twin of `ArrivalRefusal::outcome` and `DecodeRefusal::outcome`, and it exists for the
    /// same reason: a caller that assembles the status, the kind word and the message itself is a
    /// caller that could assemble a different three, and then two places decide what a refusal
    /// looks like. Assembling them here means the step names its outcome and the audit step renders
    /// it, which is one place each.
    #[must_use]
    pub fn outcome(&self) -> RefusalOutcome {
        RefusalOutcome::new(
            axum::http::StatusCode::from_u16(self.status())
                .expect("the two statuses this step names are statuses the doors emit"),
            self.kind(),
            self.message(),
        )
    }

    /// The reason code the record files this refusal under.
    #[must_use]
    pub fn reason(&self) -> ReasonCode {
        match self {
            VerifyRefusal::NotAuthorized => ReasonCode::PoolNotPermitted,
            VerifyRefusal::NoRate { .. } => ReasonCode::NoRate,
        }
    }
}

/// Everything the three guards read about the deployment's pools and the caller's key.
///
/// A view rather than a snapshot: the live guards read these off the running app on the request
/// path, and copying them into a struct first would be a second reading that can disagree with the
/// one the door then charges against.
pub trait PoolView {
    /// Whether the caller presented a key at all. With no key every guard below is inert — that is
    /// the ungoverned posture, and it is one boolean rather than three absent checks.
    fn has_key(&self) -> bool;

    /// Whether the key names a pool restriction at all. `false` means it names none and admits
    /// every pool, so guard two has nothing to walk; an explicit EMPTY list is a restriction that
    /// denies everything, which is a different thing and is why this is not "is the list non-empty".
    fn key_is_scoped(&self) -> bool;

    /// Whether the key may use one pool.
    fn pool_allowed(&self, pool: &str) -> bool;

    /// The pool this one falls over to when it exhausts, where its exhaustion policy names one.
    /// `None` when the policy stays inside this pool, or the pool is not configured at all.
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;

    /// Whether the name refers to a configured pool or a configured by-model lane. Either is priced
    /// by construction — boot refuses a card that does not cover them — so only an arbitrary
    /// caller-supplied name can reach the third guard.
    fn is_configured(&self, name: &str) -> bool;

    /// Whether a rate card is present at all.
    fn pricing_enabled(&self) -> bool;

    /// Whether a present card leaves this name unpriced.
    fn is_unpriced(&self, name: &str) -> bool;
}

/// Guard one: the requested pool's allow-list. Inert with no key.
fn pool_authorized(view: &dyn PoolView, pool: &str) -> Option<VerifyRefusal> {
    (view.has_key() && !view.pool_allowed(pool)).then_some(VerifyRefusal::NotAuthorized)
}

/// Guard two: every fallback pool the request could reach if the requested one exhausts.
///
/// Multi-level (A→B→C) and possibly cyclic (A→B→A), so the walk carries a visited set and stops for
/// the same reason the dispatch stops. A denial is the SAME refusal guard one raises.
fn fallback_pools_authorized(view: &dyn PoolView, pool: &str) -> Option<VerifyRefusal> {
    if !view.has_key() || !view.key_is_scoped() {
        return None;
    }
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current = pool.to_string();
    loop {
        if !visited.insert(current.clone()) {
            return None;
        }
        let next = view.on_exhausted_fallback(&current)?;
        if let Some(refusal) = pool_authorized(view, &next) {
            return Some(refusal);
        }
        current = next;
    }
}

/// Guard three: with a card present, every governed request must resolve to a priced destination.
///
/// Costs one boolean when no card is configured, and a single borrowed probe otherwise.
fn priced(view: &dyn PoolView, name: &str) -> Option<VerifyRefusal> {
    (view.has_key()
        && view.pricing_enabled()
        && !view.is_configured(name)
        && view.is_unpriced(name))
    .then(|| VerifyRefusal::NoRate {
        name: name.to_string(),
    })
}

/// The three guards, in their fixed order. Named separately from [`verify`] so the ORDER can be
/// checked without a token in hand, and so the composition root can ask the same question at a
/// boot-time dry run.
pub fn destination_guard(view: &dyn PoolView, pool: &str) -> Result<(), VerifyRefusal> {
    if let Some(r) = pool_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = fallback_pools_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = priced(view, pool) {
        return Err(r);
    }
    Ok(())
}

/// WHAT THE STEP ANSWERS WITH: the decision the loop reads, and the named refusal that produced it.
///
/// The two travel together because they are two readings of one answer for two different readers.
/// The [`Decision`] is the kernel's: it carries the reason code and the retry hint, in the neutral
/// vocabulary every step's decision is written in, and it must stay free of any dialect's status
/// numbers and sentences — a `Refusal` that carried a wire triple would put HTTP into the one type
/// every plane's every step shares. The [`VerifyRefusal`] is the terminal's: it is the same refusal
/// as the step named it, and it is what [`VerifyRefusal::outcome`] renders from.
///
/// Carrying it here is what keeps the guards read ONCE. The alternative — handing back a decision
/// alone and letting the driver re-run [`destination_guard`] to recover the triple — reads the same
/// deployment twice, and two reads of one fact are two answers waiting to disagree: a key revoked
/// between them, or a fallback edge re-read after a config swap, and the record says one thing while
/// the client is told another. `refusal` is `Some` exactly when the decision refused.
#[must_use = "a decision that is not returned to the loop silently skips the step"]
pub struct Verified {
    /// The loop's answer: proceed with the sealed destination set, or refuse at this step.
    pub decision: Decision<Verify>,
    /// The refusal as this step named it, present exactly when `decision` refused.
    pub refusal: Option<VerifyRefusal>,
}

/// THE DEPLOYMENT, as the guards read it on a live node.
///
/// The production [`PoolView`]: every answer below is read off the running deployment through a
/// neutral seam, so the step's three guards see what the shipped pre-admission guard sees. It reads
/// the key's ACL off the key row itself, the fallback edges and the configured names through the
/// engine's own tables projection, and the two pricing questions through the host's cost seam —
/// never through a rendered response, which is what the shipped `EngineHost::destination_guard`
/// hands back and what makes that call unusable as a view (a finished response answers "what does
/// the client see", not "may this key reach this pool").
///
/// The cost handle is minted once per view rather than per question: it is one `Arc` bump, and
/// minting it twice inside one unit would be two handles onto one model.
pub struct HostPoolView<'a> {
    host: &'a dyn EngineHost,
    tables: &'a dyn EngineTablesView,
    key: Option<&'a busbar_contract::store::VirtualKey>,
    cost: CostHandle,
}

impl<'a> HostPoolView<'a> {
    /// Open a view over one deployment for one request.
    ///
    /// `key` is the resolved key row this request presented, or `None` for the ungoverned posture,
    /// in which case every guard below is inert — exactly as the shipped guard is.
    pub fn new(
        host: &'a dyn EngineHost,
        tables: &'a dyn EngineTablesView,
        key: Option<&'a busbar_contract::store::VirtualKey>,
    ) -> Self {
        let cost = host.cost();
        HostPoolView {
            host,
            tables,
            key,
            cost,
        }
    }
}

impl PoolView for HostPoolView<'_> {
    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn key_is_scoped(&self) -> bool {
        // An OMITTED grant admits every scope; an explicit list — empty or not — is a restriction.
        // The shipped fallback walk asks the same question of the same field.
        self.key.is_some_and(|k| k.allowed_scopes.is_some())
    }

    fn pool_allowed(&self, pool: &str) -> bool {
        // The key row's own encoding of its ACL, not a second reading of it.
        self.key.is_none_or(|k| k.scope_allowed("pool", pool))
    }

    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.tables.on_exhausted_fallback(pool)
    }

    fn is_configured(&self, name: &str) -> bool {
        // Two probes, one per half of the destination space, and neither builds a projection: this
        // question is asked once per request and the scrape seam's `pools()` is not a request-path
        // read. The order is the resolution order the Route step's own candidate lookup uses — pool
        // first, bare model second — so "configured" here and "routable" there cannot disagree
        // about which half a name belongs to.
        self.tables.pool_exists(name) || self.tables.model_index(name).is_some()
    }

    fn pricing_enabled(&self) -> bool {
        self.host.cost_pricing_enabled(&self.cost)
    }

    fn is_unpriced(&self, name: &str) -> bool {
        self.host.cost_model_unpriced(&self.cost, name)
    }
}

/// Where this unit may go.
///
/// The guards run first and can refuse; what survives is the destination set the trust unit sealed,
/// carried forward unchanged. The plane's contribution at this step is the guards — it does not seal
/// destinations, because a plane that could seal its own destinations could seal one it was not
/// allowed to reach.
///
/// The one arm that surprises people is the empty one. An all-excluded pool does NOT refuse here: it
/// proceeds, and the door draws and RETAINS the slot, exactly as the shipped behaviour charged
/// before its exhaustion answer. Refusing here would move the charge, and moving a charge is not a
/// refactor.
pub fn verify(
    token: &UnitToken<Verify>,
    view: &dyn PoolView,
    pool: &str,
    principal: &PrincipalId,
    destinations: Vec<VerifiedDestination>,
) -> Verified {
    match destination_guard(view, pool) {
        Ok(()) => Verified {
            decision: Decision::proceed(token, destinations),
            refusal: None,
        },
        Err(refusal) => {
            // The operator's own diagnostics, which are where the key id and the pool go precisely
            // because the caller-facing body must not name either. The two lines are the live
            // doors' own, one per guard family.
            match &refusal {
                VerifyRefusal::NotAuthorized => {
                    tracing::info!(key_id = %principal, pool = %pool, "governance: key not authorized for pool");
                }
                VerifyRefusal::NoRate { name } => {
                    tracing::info!(model = %name, "governance: no configured rate for model; rejecting (rate_card is authoritative and complete)");
                }
            }
            Verified {
                decision: Decision::refuse(token, Refusal::new(refusal.reason())),
                refusal: Some(refusal),
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/verify.rs"]
mod tests;
