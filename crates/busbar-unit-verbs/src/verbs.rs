// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Verbs` — the one entry point the admin codec calls: `execute(KernelVerb, &AdminToken)`, plus
//! the call context every verb needs (who is calling, what scope they were granted, the current
//! time, and — for the two replayable legacy operations and the mint/rotate arguments this crate
//! ports semantics for — the extra fields those specific verbs read).
//!
//! What happens before a verb's own effect, for EVERY verb, in this order:
//!
//! 1. **Scope.** `granted.allows(required_scope(verb))` — refused `Unauthorized` otherwise. Scope
//!    is resolved from [`crate::verb::LEGACY_VERBS`] for a legacy verb; the 17 new verbs and the
//!    named surfaces are `Full`-scoped mutations and reads respectively by construction (a `Get*`
//!    surface is a read, everything else in that group is a mutation the calling context must
//!    already be authorized for by the time it reaches this crate — the admin plane's own auth
//!    middleware, which this crate does not run).
//! 2. **Rate limit.** [`crate::rate::MutationClass::for_verb`] then
//!    [`crate::rate::MutationLimiter::check`] — refused `RateLimited` otherwise. Reads never reach
//!    the limiter at all (their class is `Forbidden`, i.e. never checked).
//! 3. **Posture** (new verbs only). [`crate::posture::check_new_verb_admission`].
//! 4. **Idempotency** (the two legacy replayable mutations only, `create_key`/`rotate_key`,
//!    reached through their own dedicated methods rather than the generic [`Verbs::execute`] — see
//!    their doc comments for why they are not folded into the generic dispatch).
//!
//! Only once all of that has admitted the call does anything reach [`crate::governance::Governance`]
//! or [`crate::store::Store`].

use crate::governance::{Governance, GovernanceError, RotateOutcome};
use crate::idempotency::{IdempotencyCache, Probe, ReplayEncoder};
use crate::mint::{plan_mint_group, GroupLookup, MintPlan};
use crate::posture::{ApprovalState, PostureCtx};
use crate::rate::{ConfigClassRule, MutationClass, MutationLimiter, RateCheck};
use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use crate::store::Store;
use crate::verb::{KernelVerb, VerbScope, LEGACY_VERBS, NEW_VERBS};
use busbar_caps::{AdminToken, SecretOnce, UnitKey};

/// CG-39: the nonce seam. This crate has no CSPRNG dependency of its own, so the 128-bit nonce a
/// [`SecretOnce`] is bound to — the thing that proves exactly one occurrence of the minted secret
/// at its declared target location — must come from the composition root's own entropy (the secret
/// plugin's CSPRNG). Deliberately has **no** `Default` impl and
/// no derivable placeholder: a mandatory seam, bound once at [`Verbs::new`], never silently
/// defaulted to something predictable (a derivable nonce is security-shaped — it must never reach a
/// release binary).
pub trait NonceSource {
    /// Fill `buf` with 128 bits of nonce material for exactly one mint. Called once per
    /// [`SecretOnce`]; two calls must not return the same bytes (the property the CSPRNG, not this
    /// trait, is responsible for).
    fn fill(&self, buf: &mut [u8; 16]);
}

/// The longest a group/parent name may be. `// contract:` in spirit (1.5.5 pins this in
/// `busbar-core::admin::v1::service::MAX_GROUP_NAME_LEN`), kept as a plain constant here because
/// the architecture document does not name it as a dual-controlled default and a mismatch would
/// only ever be too strict, never a security gap.
pub const MAX_GROUP_NAME_LEN: usize = 253;

/// The outcome of a verb call that minted or rotated a credential: the once-shown secret is a
/// [`SecretOnce`] placeholder, never a plain string, so nothing downstream of this crate can hold
/// or log the real material without going through the one capability built to carry it.
#[derive(Debug)]
pub struct MintedKeyOutcome {
    /// The key's id.
    pub id: String,
    /// The once-shown secret placeholder.
    pub secret: SecretOnce,
    /// Unix-seconds expiry, when the credential shape carries one.
    pub expires_at: Option<u64>,
}

/// The result of [`Verbs::create_key`]/[`Verbs::rotate_key`]: either a fresh mint/rotation, or the
/// verbatim replay of a previous call's response for the same idempotency key. CG-40: a replay
/// carries no [`MintedKeyOutcome`] at all — there is no decode step that could reconstruct (and
/// thereby re-mint) a fresh [`SecretOnce`]; `body` is exactly the bytes the encoder produced for the
/// original call, byte-for-byte, for as long as the idempotency window is open.
#[derive(Debug)]
pub enum MintOutcome {
    /// A fresh mint or rotation. `body` is [`ReplayEncoder::encode`]'s output over `outcome` — the
    /// exact bytes cached for any future replay of this idempotency key.
    Minted {
        /// The freshly minted or rotated capability.
        outcome: MintedKeyOutcome,
        /// The encoded response body, as cached for replay.
        body: Vec<u8>,
    },
    /// A replay: the previously encoded response body, verbatim. No secret was minted or rotated on
    /// this call.
    Replayed {
        /// The exact bytes committed by the original call.
        body: Vec<u8>,
    },
}

impl MintOutcome {
    /// The response body to send: the fresh encoding on a mint, the cached bytes verbatim on a
    /// replay — the two cases a caller building an HTTP response must treat identically.
    pub fn body(&self) -> &[u8] {
        match self {
            MintOutcome::Minted { body, .. } => body,
            MintOutcome::Replayed { body } => body,
        }
    }

    /// Whether this outcome is a replay (no fresh secret was minted).
    pub fn is_replay(&self) -> bool {
        matches!(self, MintOutcome::Replayed { .. })
    }

    /// The freshly minted or rotated capability, or `None` for a replay — a replay never carries
    /// one (CG-40: there is no decode step that could reconstruct, and thereby re-mint, a fresh
    /// `SecretOnce`).
    pub fn minted_outcome(&self) -> Option<&MintedKeyOutcome> {
        match self {
            MintOutcome::Minted { outcome, .. } => Some(outcome),
            MintOutcome::Replayed { .. } => None,
        }
    }
}

/// Resolve the scope a [`KernelVerb`] requires. Legacy verbs read [`LEGACY_VERBS`]; the 17 new
/// verbs are `Full` (every one of them mutates state or reads privileged material — there is no
/// read-only new verb); the named surfaces split by their own nature (`Get*` reads, the two
/// `/auth/token` methods are their own thing and never checked against this two-rung scope model at
/// all — see the module doc on why `Verbs::execute` is not the caller for them).
pub fn required_scope(verb: KernelVerb) -> VerbScope {
    if let Some(row) = LEGACY_VERBS.iter().find(|r| r.verb == verb) {
        return row.scope;
    }
    if NEW_VERBS.contains(&verb) {
        return VerbScope::Full;
    }
    // Named surfaces: every `Get*` is a read; `PostAuthToken`/`GetAuthToken` are exempt from this
    // model entirely (see module doc) and are given `ReadOnly` here only so `required_scope` stays
    // total — a caller must not route either through `Verbs::execute`.
    VerbScope::ReadOnly
}

/// `Verbs` — the closed kernel-verb executor. Generic over the seams the integrator binds: the
/// [`Governance`] and [`Store`] record-store adapters, the [`NonceSource`] the secret plugin lends
/// (CG-39), and the [`ReplayEncoder`] the admin plane's own writer implements (CG-40).
/// `config_class_rules` (CG-38) is data rather than a fifth type parameter — a `&'static` table has
/// no behaviour to seal behind a trait.
pub struct Verbs<G: Governance, S: Store, N: NonceSource, E: ReplayEncoder<MintedKeyOutcome>> {
    governance: G,
    store: S,
    nonce_source: N,
    replay_encoder: E,
    config_class_rules: &'static [ConfigClassRule],
    create_key_cache: IdempotencyCache<Vec<u8>>,
    rotate_key_cache: IdempotencyCache<Vec<u8>>,
    limiter: MutationLimiter,
}

impl<G: Governance, S: Store, N: NonceSource, E: ReplayEncoder<MintedKeyOutcome>>
    Verbs<G, S, N, E>
{
    /// Build a fresh executor over the four bound seams. `config_class_rules` is the composition
    /// root's sealed CG-38 table (see [`crate::rate::CONFIG_CLASS_RULES`] for the 1.5.5-parity
    /// default); `nonce_source` and `replay_encoder` are mandatory — there is no `Default` for
    /// either, so a caller cannot silently construct a `Verbs` with a predictable nonce or a
    /// re-minting replay path.
    pub fn new(
        governance: G,
        store: S,
        nonce_source: N,
        replay_encoder: E,
        config_class_rules: &'static [ConfigClassRule],
    ) -> Self {
        Verbs {
            governance,
            store,
            nonce_source,
            replay_encoder,
            config_class_rules,
            create_key_cache: IdempotencyCache::new(),
            rotate_key_cache: IdempotencyCache::new(),
            limiter: MutationLimiter::new(),
        }
    }

    /// The scope + rate-limit gate every verb runs through. Returns the [`MutationClass`] on
    /// success, so a caller that must also check idempotency doesn't re-derive it.
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
        if class == MutationClass::Forbidden {
            // Never rate-limited (a read, or a verb this limiter does not shape).
            return Ok(class);
        }
        match self.limiter.check(actor, class, now) {
            RateCheck::Admitted => Ok(class),
            RateCheck::Denied { .. } => {
                Err(Refusal::new(RefusalStep::Admit, ReasonCode::RateLimited))
            }
        }
    }

    /// CG-39: mint a [`SecretOnce`] whose nonce comes from the bound [`NonceSource`] — never a
    /// value derivable from the unit key or the secret's own shape.
    fn to_secret_once(
        &self,
        admin: &AdminToken,
        unit: UnitKey,
        minted: crate::governance::MintedKey,
        target: &str,
    ) -> MintedKeyOutcome {
        let mut buf = [0u8; 16];
        self.nonce_source.fill(&mut buf);
        let nonce = u128::from_be_bytes(buf);
        MintedKeyOutcome {
            id: minted.id,
            secret: SecretOnce::mint(admin, nonce, unit, target),
            expires_at: minted.expires_at,
        }
    }

    /// `POST /api/v1/admin/keys` — mint a virtual key. Ported in full: the idempotency probe/
    /// reservation (per-actor, `Idempotency-Key` header value, 600 s TTL, no body hash — a retry
    /// with the same key but a different body still replays the first response, exactly as 1.5.5),
    /// then [`plan_mint_group`]'s existence-only parent check, then the governance mint itself.
    ///
    /// Not folded into [`Verbs::execute`]'s generic dispatch because it is one of the two 1.5.5
    /// operations with its OWN ported replay cache and its own multi-step plan — exactly the two
    /// operations the architecture document calls out by name in the holds/keys/recovery section.
    ///
    /// Eight positional arguments rather than a bundled call-context struct: every one of them is
    /// a distinct thing the ported logic reads by name (see the doc above), and a bundling struct
    /// would only move the same count one level out without changing what a caller has to supply.
    #[allow(clippy::too_many_arguments)]
    pub fn create_key(
        &self,
        admin: &AdminToken,
        actor: &str,
        granted: VerbScope,
        now: u64,
        unit: UnitKey,
        idempotency_key: Option<&str>,
        group: Option<&str>,
        parent: Option<&str>,
    ) -> Result<MintOutcome, Refusal> {
        self.admit(KernelVerb::PostKeys, actor, granted, now)?;
        if group.is_none() && parent.is_some() {
            return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
        }
        let ck = idempotency_key.map(|k| (actor.to_string(), k.to_string()));
        let reservation = match ck.clone() {
            None => None,
            Some(key) => match self.create_key_cache.probe(key, now) {
                Probe::NoKey => None,
                Probe::Replay(body) => return Ok(MintOutcome::Replayed { body }),
                Probe::InFlight => {
                    return Err(Refusal::new(
                        RefusalStep::Admit,
                        ReasonCode::IdempotencyInFlight,
                    ))
                }
                Probe::Reserved(r) => Some(r),
            },
        };

        let plan = plan_mint_group(
            &GovernanceGroupLookup(&self.governance),
            group,
            parent,
            MAX_GROUP_NAME_LEN,
        );
        let plan = match plan {
            Ok(p) => p,
            Err(e) => {
                if let Some(r) = reservation {
                    r.clear();
                }
                return Err(e);
            }
        };
        if let MintPlan::ProvisionLeaf { parent } = &plan {
            if let Err(e) = self
                .governance
                .provision_group(admin, group.unwrap(), parent)
            {
                if let Some(r) = reservation {
                    r.clear();
                }
                return Err(e.into_refusal());
            }
        }
        match self.governance.mint_key(admin, group) {
            Ok(minted) => {
                let outcome = self.to_secret_once(admin, unit, minted, "response.secret");
                let body = self.replay_encoder.encode(&outcome);
                if let Some(r) = reservation {
                    r.commit(body.clone(), now);
                }
                Ok(MintOutcome::Minted { outcome, body })
            }
            Err(e) => {
                if let Some(r) = reservation {
                    r.clear();
                }
                Err(e.into_refusal())
            }
        }
    }

    /// `POST /api/v1/admin/keys/{id}/rotate` — ported in full: same idempotency mechanics as
    /// [`Verbs::create_key`], SCOPED to `(actor, "rotate:{id}:{k}")` rather than `(actor, k)` — the
    /// architecture document's note that a create and a rotate sharing a header value must never
    /// replay each other.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_key(
        &self,
        admin: &AdminToken,
        actor: &str,
        granted: VerbScope,
        now: u64,
        unit: UnitKey,
        idempotency_key: Option<&str>,
        id: &str,
    ) -> Result<MintOutcome, Refusal> {
        self.admit(KernelVerb::PostKeysIdRotate, actor, granted, now)?;
        let ck = idempotency_key.map(|k| (actor.to_string(), format!("rotate:{id}:{k}")));
        let reservation = match ck {
            None => None,
            Some(key) => match self.rotate_key_cache.probe(key, now) {
                Probe::NoKey => None,
                Probe::Replay(body) => return Ok(MintOutcome::Replayed { body }),
                Probe::InFlight => {
                    return Err(Refusal::new(
                        RefusalStep::Admit,
                        ReasonCode::IdempotencyInFlight,
                    ))
                }
                Probe::Reserved(r) => Some(r),
            },
        };
        match self.governance.rotate_key(admin, id) {
            Ok(RotateOutcome::NotFound) => {
                if let Some(r) = reservation {
                    r.clear();
                }
                Err(Refusal::new(RefusalStep::Verify, ReasonCode::NotFound))
            }
            Ok(RotateOutcome::Tombstoned) => {
                if let Some(r) = reservation {
                    r.clear();
                }
                Err(Refusal::new(RefusalStep::Verify, ReasonCode::Conflict))
            }
            Ok(RotateOutcome::Rotated(minted)) => {
                let outcome = self.to_secret_once(admin, unit, minted, "response.token");
                let body = self.replay_encoder.encode(&outcome);
                if let Some(r) = reservation {
                    r.commit(body.clone(), now);
                }
                Ok(MintOutcome::Minted { outcome, body })
            }
            Err(e) => {
                if let Some(r) = reservation {
                    r.clear();
                }
                Err(e.into_refusal())
            }
        }
    }

    /// The generic dispatcher for every other verb: every legacy operation but the two above, the
    /// 17 new verbs (posture-gated), and nothing else — a caller for `PostKeys`/`PostKeysIdRotate`
    /// or a named surface must use the dedicated method / must not call this crate at all.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        verb: KernelVerb,
        admin: &AdminToken,
        actor: &str,
        granted: VerbScope,
        now: u64,
        posture: Option<PostureCtx>,
        approval: ApprovalState,
        request: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        debug_assert!(
            verb != KernelVerb::PostKeys && verb != KernelVerb::PostKeysIdRotate,
            "create_key/rotate_key have dedicated methods with their own idempotency handling"
        );
        self.admit(verb, actor, granted, now)?;
        if NEW_VERBS.contains(&verb) {
            let ctx = posture.expect("a new verb must be called with a resolved PostureCtx");
            crate::posture::check_new_verb_admission(verb, ctx, approval)?;
            return self
                .governance
                .execute_new_verb(verb, admin, request)
                .map_err(GovernanceError::into_refusal);
        }
        self.governance
            .execute_legacy(verb, admin, request)
            .map_err(GovernanceError::into_refusal)
    }

    /// Read access to the bound store seam, for the disaster-recovery verbs
    /// (`chain_break`/`store_restore`/`reseal_epoch_floor`) that a caller runs directly rather than
    /// through [`Verbs::execute`] — they are irreducible-set verbs whose effect is a store
    /// operation, not a governance one, and the posture check that gates them
    /// ([`crate::posture::check_operator_gate`]) is the caller's responsibility exactly as it is
    /// for every other new verb.
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// Adapts [`Governance`] to [`GroupLookup`] so [`plan_mint_group`] can be called without this crate
/// naming a second copy of the group-tree query surface.
struct GovernanceGroupLookup<'a, G: Governance>(&'a G);

impl<'a, G: Governance> GroupLookup for GovernanceGroupLookup<'a, G> {
    fn group_exists(&self, name: &str) -> bool {
        self.0.group_exists(name)
    }
    fn actual_parent(&self, name: &str) -> Option<String> {
        self.0.actual_parent(name)
    }
}

#[cfg(test)]
#[path = "tests/verbs_tests.rs"]
mod tests;
