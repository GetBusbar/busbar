// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: the unit the loop calls at the authenticate step.

use busbar_caps::{Authenticate, Decision, ReasonCode, Refusal, UnitToken};

use crate::cache::CredentialCache;
use crate::chain::{AuthChain, ChainVerdict, KeyVerifier, RevocationView};
use crate::challenge::Challenge;
use crate::principal::{to_caps_principal, Principal};

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

/// What the unit hands back.
///
/// Two arms, because the loop's own answer type has room for a principal or a refusal and none for
/// a challenge: a challenge is not a decision about this unit, it is a request for one more round
/// before a decision can be made. The kernel delivers it as the handshake unit's delivery leg and
/// asks again when the proof arrives.
// contract: when the kernel's answer type grows a challenge arm, this enum collapses into it.
pub enum Resolved {
    /// The sealed answer for the step.
    Decided(Decision<Authenticate>),
    /// A bounded challenge to deliver before the question can be settled.
    Challenge(Challenge),
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
    /// 3. Revocation gates a NEW unit only. A unit already in flight is not asked.
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
    ) -> Resolved {
        // 1. The plane may only narrow within what the claim declared.
        if let Some(scheme) = req.scheme {
            if !req.declared_schemes.contains(&scheme) {
                return Resolved::Decided(Decision::refuse(
                    token,
                    Refusal::new(ReasonCode::SchemeNotDeclared),
                ));
            }
        }

        // 2. A scheme that needs one more round says so, and only inside a handshake unit. An
        //    exhausted exchange ends the unit rather than continuing to talk.
        if let Some(challenge) = pending {
            if req.in_handshake {
                if challenge.exhausted() {
                    return Resolved::Decided(Decision::refuse(
                        token,
                        Refusal::new(ReasonCode::ChallengeExhausted),
                    ));
                }
                return Resolved::Challenge(challenge);
            }
        }

        // 3. The chain.
        let verdict =
            self.chain
                .run_chain_cached(req.candidate, cache, keys, req.now, req.expected_aud);

        // 4. Revocation gates NEW units only.
        if req.new_unit {
            if let (Some(r), Some(cred)) = (revocations, req.candidate) {
                if r.is_revoked(cred) {
                    return Resolved::Decided(Decision::refuse(
                        token,
                        Refusal::new(ReasonCode::Revoked),
                    ));
                }
            }
        }

        Resolved::Decided(match verdict {
            ChainVerdict::Identified { principal, .. } => {
                // A module may not synthesize an identity in reserved space.
                if Principal::id_is_reserved(&principal.id) {
                    Decision::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
                } else {
                    Decision::proceed(token, to_caps_principal(&principal))
                }
            }
            // The open front door admits with the anonymous principal: no bucket, and an actor id
            // that reads as the plain word everywhere it is written.
            ChainVerdict::Open => {
                Decision::proceed(token, to_caps_principal(&Principal::anonymous()))
            }
            ChainVerdict::Denied => {
                Decision::refuse(token, Refusal::new(ReasonCode::Unauthenticated))
            }
        })
    }
}
