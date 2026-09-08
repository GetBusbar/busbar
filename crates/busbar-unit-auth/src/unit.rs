// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: the unit the loop calls at the authenticate step.

use busbar_caps::{Authenticate, Authenticated, Decision, ReasonCode, Refusal, Unit, UnitToken};

use crate::cache::CredentialCache;
use crate::chain::{AuthChain, ChainVerdict, KeyVerifier, RevocationView};
use crate::challenge::Challenge;
use crate::principal::Principal;

/// Everything the unit is given about one authentication.
pub struct AuthRequest<'a> {
    /// The credential the carriers presented, if any.
    pub candidate: Option<&'a str>,
    /// The scheme the claim declared, narrowed by the plane. A plane may only narrow WITHIN the
    /// claim's declared alternatives; narrowing to something the claim never declared is refused,
    /// because a plane that could invent a scheme could choose the weakest one.
    pub scheme: Option<&'a str>,
    /// The alternatives the claim declared.
    pub declared_schemes: &'a [&'a str],
    /// The audience this plane requires of a signed token. `None` on the residual plane, which
    /// rejects any token that carries one.
    pub expected_aud: Option<&'a str>,
    /// Whether this is a handshake unit — the only shape a challenge may be answered in.
    pub in_handshake: bool,
    /// The wall clock, in seconds.
    pub now: u64,
    /// Whether this is a NEW unit, and therefore whether the revocation set applies.
    pub new_unit: bool,
}

/// Everything the loop hands this unit at the authenticate step.
///
/// One struct rather than five arguments, because [`Unit::Input`] is the shape every sibling of the
/// kind declares its inputs in — the five arguments are still the five arguments, moved to where
/// the trait can name them.
pub struct AuthInput<'a> {
    /// The request as [`Auth::resolve`] reads it.
    pub req: &'a AuthRequest<'a>,
    /// The credential cache, where the deployment has one.
    pub cache: Option<&'a CredentialCache>,
    /// The built-in signed-key arm, where the deployment has one.
    pub keys: Option<&'a dyn KeyVerifier>,
    /// The revocation set the kernel derives from the journal tail.
    pub revocations: Option<&'a dyn RevocationView>,
    /// The challenge the scheme wants to ask, inside a handshake unit only.
    pub pending: Option<Challenge>,
}

/// The auth unit OWNS the authenticate step: it answers with a sealed `Decision<Authenticate>`.
///
/// A pure delegation to [`Auth::resolve`] — the rule is unchanged, and the trait is the shape the
/// rule is now reachable through.
impl Unit for Auth {
    type Step = Authenticate;
    type Input<'a> = AuthInput<'a>;
    type Answer<'a> = Decision<Authenticate>;
    const OWNS_ITS_STEP: bool = true;

    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<Authenticate>,
        input: AuthInput<'a>,
    ) -> Decision<Authenticate> {
        self.resolve(
            input.req,
            input.cache,
            input.keys,
            input.revocations,
            input.pending,
            token,
        )
    }
}

/// The authenticate unit.
pub struct Auth {
    chain: AuthChain,
}

impl Auth {
    /// Build the unit over a resolved chain.
    pub fn new(chain: AuthChain) -> Self {
        Auth { chain }
    }

    /// The chain behind this unit, for reporting.
    pub fn chain(&self) -> &AuthChain {
        &self.chain
    }

    /// Resolve who is calling.
    ///
    /// The order of the checks is the order of the reasons they can refuse for, and it is fixed:
    ///
    /// 1. The plane's narrowing is checked FIRST, before any credential is looked at. A plane that
    ///    narrowed outside the claim's declared alternatives has already broken the contract, and no
    ///    answer computed under a scheme the claim never offered is worth having.
    /// 2. The chain runs. An open door yields the anonymous principal — which is an admission, not a
    ///    refusal, and renders its actor id as the plain word.
    /// 3. Revocation gates a NEW unit's IDENTIFICATION only. A unit already in flight is not
    ///    asked, and neither is a walk that identified nobody — there is no identity for a
    ///    revocation to withdraw, and answering one anyway would tell an unauthenticated caller
    ///    whether the string they presented was ever a credential.
    ///
    /// The challenge argument is what the scheme wants to ask; supplying one outside a handshake
    /// unit is not an error the caller can make usefully, so it is ignored there and the chain's own
    /// verdict stands.
    pub fn resolve(
        &self,
        req: &AuthRequest<'_>,
        cache: Option<&CredentialCache>,
        keys: Option<&dyn KeyVerifier>,
        revocations: Option<&dyn RevocationView>,
        pending: Option<Challenge>,
        token: &UnitToken<Authenticate>,
    ) -> Decision<Authenticate> {
        // 1. The plane may only narrow within what the claim declared.
        if let Some(scheme) = req.scheme {
            if !req.declared_schemes.contains(&scheme) {
                return Decision::refuse(token, Refusal::new(ReasonCode::SchemeNotDeclared));
            }
        }

        // 2. A scheme that needs one more round says so, and only inside a handshake unit. An
        //    exhausted exchange ends the unit rather than continuing to talk.
        if let Some(challenge) = pending {
            if req.in_handshake {
                if challenge.exhausted() {
                    return Decision::refuse(token, Refusal::new(ReasonCode::ChallengeExhausted));
                }
                return Decision::proceed(token, Authenticated::Challenge((&challenge).into()));
            }
        }

        // 3. The chain.
        let verdict =
            self.chain
                .run_chain_cached(req.candidate, cache, keys, req.now, req.expected_aud);

        // 4. Revocation gates NEW units only, and only an identification. A revocation is a
        //    statement about a credential the chain resolved to somebody; applied to whatever
        //    string arrived it answers two questions nobody asked. It tells an unauthenticated
        //    caller which of two refusals they earned — `Revoked` where the set names the string,
        //    `Unauthenticated` where it does not — which is a probe for "was this ever a real
        //    credential", answered before anything has authenticated. And on the open front door,
        //    where no chain is authenticating anyone, it would turn the anonymous admit into a
        //    refusal on the strength of a string nothing verified. `AuthChain::
        //    run_chain_for_new_unit` has always collapsed both to its one `Denied`; this is the
        //    same rule spelled where the reason code exists to be told apart.
        if req.new_unit && matches!(verdict, ChainVerdict::Identified { .. }) {
            if let (Some(r), Some(cred)) = (revocations, req.candidate) {
                if r.is_revoked(cred) {
                    return Decision::refuse(token, Refusal::new(ReasonCode::Revoked));
                }
            }
        }

        match verdict {
            // A module may not SYNTHESIZE an identity in reserved space. The engine's own
            // signed-key arm does not synthesize one: it resolves the key the directory issued, and
            // that key's id is a `vk_` id by construction — the very space the rule reserves. So the
            // check is applied to the arms that can invent an id, and those are exactly the arms
            // that resolved no key: a boxed module's answer type cannot carry one, which is what
            // makes `resolved` the discriminator rather than a provider name a configuration
            // chooses.
            ChainVerdict::Identified {
                principal,
                resolved: None,
                ..
            } if Principal::id_is_reserved(&principal.id) => {
                Decision::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
            }
            ChainVerdict::Identified { principal, .. } => {
                Decision::proceed(token, Authenticated::Principal((&principal).into()))
            }
            // The open front door admits with the anonymous principal: no bucket, and an actor id
            // that reads as the plain word everywhere it is written.
            ChainVerdict::Open => Decision::proceed(
                token,
                Authenticated::Principal((&Principal::anonymous()).into()),
            ),
            ChainVerdict::Denied => {
                Decision::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
            }
        }
    }
}
