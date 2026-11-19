// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed-ingress verifier of the native path: steps 4 and 2 of a route whose admission is
//! [`Admission::SignedIngress`] (`VerifyBy::Signature`, `BodyAt::BoundedBeforeVerify`).
//!
//! A provider's webhook presents no caller credential. Its sender signs the request, body
//! included, and the route's verifier is the auth instance that reads the signature's header
//! (`busbar-auth-webhook-signature`: HMAC-SHA256 over `id.timestamp.body`, MACed in its parts
//! where the bytes lie, compared in constant time, the timestamp held inside its tolerance, the
//! secret a reference resolved by the secret kind at `open`). This module is what core adds around
//! that verifier, and what makes the class safe to mount:
//!
//! 1. **Bounded before verified.** The route's verifier states the most body bytes its signature
//!    covers; a verifier that states none, or that does not cover the body at all, verifies no
//!    signed route ([`coverage`]). A body over the bound is refused unread by any verifier.
//! 2. **The exact bytes.** The verifier is handed the request as it was received, and the body a
//!    served request is parsed from is the same slice, reachable only through the value a
//!    successful verification returns ([`SignedIngressVerified::body`]). There is no other way
//!    to the bytes: nothing parses a body that was not verified.
//! 3. **Replay refused.** A verified signature is admitted only when its verifier bound it to a
//!    replay claim and that claim is won (one request on any replica). A signature its verifier
//!    did not bind to a claim is refused: a signed route never admits a request that could be
//!    sent twice.
//! 4. **One answer.** A missing signature, a wrong one, a stale timestamp, a changed body and a
//!    replay are the same fact to the admission table ([`Verified::Denied`]: the one 401, same
//!    bytes); the reason goes to the log. A verifier or a replay store that cannot answer is
//!    [`Verified::Unavailable`]: the 503, never a denial.

use std::sync::Arc;

use busbar_plugin_abi::auth::FB_NEEDS_BODY;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::CallCx;

use super::admission_table::{Admission, BodyRead, Facts, Verified, VerifyBy};
use super::native_admin::NativeReplayClaim;
use super::native_chain::{NativeChain, NativePreparedAnswer, PreparedNativeIdentity};
use crate::inbound::request_snapshot::ChargedRequestSnapshot;

/// Whether this module is the verifier of `by`. Written with no catch-all arm.
pub const fn selected_by(by: VerifyBy) -> bool {
    match by {
        VerifyBy::Signature => true,
        VerifyBy::Nobody
        | VerifyBy::Chain
        | VerifyBy::ChainIfPresented
        | VerifyBy::TicketOrChain
        | VerifyBy::AdminChain => false,
    }
}

/// Why a set of auth instances cannot verify a signed route. Each is the operator's
/// configuration or the image's declaration, and each leaves the route unmounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotCovered {
    /// No instance reads the route's signature header.
    NoVerifier,
    /// An instance that would judge the route does not cover the body (no `FB_NEEDS_BODY`): its
    /// answer says nothing about the bytes a signed route serves.
    HeadOnly,
    /// An instance covers the body and states no bound (no `D_BODY_MAX`): how much to read
    /// before verifying is not said, so nothing is read.
    Unbounded,
    /// A stated bound of zero.
    Empty,
}

impl NotCovered {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoVerifier => "no configured auth instance reads this route's signature header",
            Self::HeadOnly => {
                "an auth instance that reads this route's signature header does not cover the body"
            }
            Self::Unbounded => {
                "an auth instance that covers the body states no largest body (D_BODY_MAX)"
            }
            Self::Empty => "an auth instance states a largest body of zero",
        }
    }
}

/// The most body bytes a signed route reads before verifying, from what each instance that
/// judges it declares: its describe facts and its `D_BODY_MAX`. Every instance must cover the
/// body and state its bound; the route's bound is the least of them and never over `cap` (the
/// listener's own body cap).
pub fn coverage(
    members: impl IntoIterator<Item = (u64, Option<u64>)>,
    cap: u64,
) -> Result<u64, NotCovered> {
    let mut bound: Option<u64> = None;
    for (facts, body_max) in members {
        if facts & FB_NEEDS_BODY == 0 {
            return Err(NotCovered::HeadOnly);
        }
        let stated = match body_max {
            None => return Err(NotCovered::Unbounded),
            Some(0) => return Err(NotCovered::Empty),
            Some(stated) => stated,
        };
        bound = Some(bound.map_or(stated, |least| least.min(stated)));
    }
    match bound {
        None => Err(NotCovered::NoVerifier),
        Some(_) if cap == 0 => Err(NotCovered::Empty),
        Some(bound) => Ok(bound.min(cap)),
    }
}

/// A request as it was received: the one source of the bytes that are verified and, after that,
/// parsed.
pub trait Received {
    /// The body, byte for byte as it arrived.
    fn raw_body(&self) -> &[u8];
}

/// How a replay claim ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// The first sighting.
    Won,
    /// Seen before, on this replica or another.
    Replay,
    /// The replay store could not answer.
    Unknown,
}

/// A signature its verifier accepted, before its replay claim.
pub trait Signed: Send + Sync {
    /// Who the sender is recorded as.
    fn subject(&self) -> &str;
    /// The verifier bound this signature to a replay claim.
    fn replay_bound(&self) -> bool;
    /// Claim it. Called once.
    fn claim(&self) -> BoxFut<'_, Claim>;
}

/// What a verifier made of a request.
pub enum Judged<'a> {
    Verified(Box<dyn Signed + 'a>),
    /// No signature this verifier reads is on the head.
    NotSigned,
    /// A signature was presented and refused. The verifier logs why; nothing of it is carried.
    Rejected,
}

/// The verifier could not answer (its instance is down, the call timed out). Not a denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierDown;

/// A signature verifier over requests of type `R`.
pub trait SignatureVerifier<R: ?Sized>: Send + Sync {
    fn verify<'a>(&'a self, request: &'a R) -> BoxFut<'a, Result<Judged<'a>, VerifierDown>>;
}

/// Why a signed request was not admitted. The caller is told none of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedRefused {
    /// The body is longer than the verifier's signature covers. Decided before any verifier ran.
    TooLarge,
    NotSigned,
    /// A wrong signature, a stale timestamp, a changed body: the verifier's refusal.
    BadSignature,
    /// The verifier accepted a signature it bound to no replay claim.
    NoReplayBound,
    Replayed,
    /// The verifier, or the replay store, could not answer.
    Unavailable,
}

impl SignedRefused {
    /// The reason, for the log. It names no secret, no signature and no body.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "the body is longer than the route's verifier signs",
            Self::NotSigned => "no signature the route's verifier reads was presented",
            Self::BadSignature => "the route's verifier refused the signature",
            Self::NoReplayBound => "the verifier bound the signature to no replay claim",
            Self::Replayed => "the signed request was already received",
            Self::Unavailable => "the signature verifier or the replay store could not answer",
        }
    }

    /// What the admission table is told. A body over the bound is step 4's fact; everything else
    /// is step 2's, on a body that was taken.
    pub fn facts(self) -> Facts {
        // Whether a signature was on the head changes the code recorded, never the answer.
        let presented = match self {
            Self::TooLarge | Self::NotSigned => false,
            Self::BadSignature | Self::NoReplayBound | Self::Replayed | Self::Unavailable => true,
        };
        let mut facts = Facts::arrived(presented, false);
        match self {
            Self::TooLarge => facts.body = Some(BodyRead::OverCap),
            Self::Unavailable => {
                facts.body = Some(BodyRead::Taken);
                facts.verified = Some(Verified::Unavailable);
            }
            Self::NotSigned | Self::BadSignature | Self::NoReplayBound | Self::Replayed => {
                facts.body = Some(BodyRead::Taken);
                facts.verified = Some(Verified::Denied);
            }
        }
        facts
    }
}

/// A request whose signature verified over its exact bytes and whose replay claim was won. Only
/// [`NativeSignedIngress::admit`] makes one, and it is the only way to the body.
pub struct SignedIngressVerified<'a> {
    subject: Box<str>,
    body: &'a [u8],
}

impl<'a> SignedIngressVerified<'a> {
    /// Who the sender is recorded as. A signed sender earns no key: no unit is opened for it.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The body that was verified, to be parsed now and not before.
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// What the admission table is told.
    pub fn facts(&self) -> Facts {
        let mut facts = Facts::arrived(true, false);
        facts.body = Some(BodyRead::Taken);
        facts.verified = Some(Verified::Signature);
        facts
    }
}

/// The body never prints.
impl std::fmt::Debug for SignedIngressVerified<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIngressVerified")
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// The signed-ingress verifier of one route: its signature verifier and the bound it reads under.
pub struct NativeSignedIngress<V> {
    verifier: V,
    /// The most body bytes read before verifying ([`coverage`]).
    bound: u64,
}

impl<V> NativeSignedIngress<V> {
    /// `bound`: what [`coverage`] answered for the instances behind `verifier`.
    pub fn new(verifier: V, bound: u64) -> Self {
        Self { verifier, bound }
    }

    /// Whether a route with this admission is this verifier's.
    pub fn serves(admission: Admission) -> bool {
        admission == Admission::SignedIngress
    }

    /// The most body bytes the listener takes for a request on this route. A declared length over
    /// it is refused unread.
    pub fn bound(&self) -> u64 {
        self.bound
    }

    /// Verify `request` and claim its replay key. `Ok` is the only way to its body.
    pub async fn admit<'a, R>(
        &'a self,
        request: &'a R,
    ) -> Result<SignedIngressVerified<'a>, SignedRefused>
    where
        R: Received + ?Sized,
        V: SignatureVerifier<R>,
    {
        let body = request.raw_body();
        let result = self.judge(request, body).await;
        match &result {
            Ok(_) => {}
            Err(SignedRefused::Unavailable) => tracing::warn!(
                reason = SignedRefused::Unavailable.reason(),
                "signed request not judged"
            ),
            Err(refused) => tracing::info!(reason = refused.reason(), "signed request refused"),
        }
        result
    }

    async fn judge<'a, R>(
        &'a self,
        request: &'a R,
        body: &'a [u8],
    ) -> Result<SignedIngressVerified<'a>, SignedRefused>
    where
        R: Received + ?Sized,
        V: SignatureVerifier<R>,
    {
        // Step 4, bounded: no verifier is handed more than it said its signature covers.
        if u64::try_from(body.len()).map_or(true, |len| len > self.bound) {
            return Err(SignedRefused::TooLarge);
        }
        // Step 2: the signature, over the bytes as received.
        let signed = match self.verifier.verify(request).await {
            Err(VerifierDown) => return Err(SignedRefused::Unavailable),
            Ok(Judged::NotSigned) => return Err(SignedRefused::NotSigned),
            Ok(Judged::Rejected) => return Err(SignedRefused::BadSignature),
            Ok(Judged::Verified(signed)) => signed,
        };
        if signed.subject().is_empty() {
            return Err(SignedRefused::BadSignature);
        }
        if !signed.replay_bound() {
            return Err(SignedRefused::NoReplayBound);
        }
        match signed.claim().await {
            Claim::Won => {}
            Claim::Replay => return Err(SignedRefused::Replayed),
            Claim::Unknown => return Err(SignedRefused::Unavailable),
        }
        Ok(SignedIngressVerified {
            subject: signed.subject().into(),
            body,
        })
    }
}

/// A request for the chain verifier: the charged snapshot of the original physical request (its
/// head and the bounded body, as received) and the call it is judged under.
pub struct ChainRequest {
    pub cx: CallCx,
    pub snapshot: Arc<ChargedRequestSnapshot>,
}

impl Received for ChainRequest {
    fn raw_body(&self) -> &[u8] {
        self.snapshot.body()
    }
}

/// The production signature verifier: the auth instances that read the route's signature header,
/// as a native chain. Each instance's `verify` is handed the snapshot's own body
/// ([`ChargedRequestSnapshot::with_auth_input`]), and the replay claim is the one its answer
/// stated, claimed under that instance's namespace.
pub struct ChainSignature {
    chain: Arc<NativeChain>,
}

/// Why a chain cannot be a signed route's verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRefused {
    /// Not a data chain (an admin chain never judges a data route).
    NotData,
    /// The chain names `anonymous`: it would admit a request that presents no signature.
    AdmitsAnonymous,
}

impl ChainSignature {
    /// `chain`: exactly the instances that read the route's signature header, in the operator's
    /// order. A chain that can admit a caller presenting nothing is refused: on a signed route
    /// no signature is never an identity.
    pub fn bind(chain: Arc<NativeChain>) -> Result<Self, ChainRefused> {
        if !chain.is_data() {
            return Err(ChainRefused::NotData);
        }
        if chain.admits_anonymous() {
            return Err(ChainRefused::AdmitsAnonymous);
        }
        Ok(Self { chain })
    }
}

/// A chain's verified identity, as a signature.
struct ChainSigned(Arc<PreparedNativeIdentity>);

impl Signed for ChainSigned {
    fn subject(&self) -> &str {
        self.0.identity().subject()
    }

    fn replay_bound(&self) -> bool {
        self.0.identity().replay().is_some()
    }

    fn claim(&self) -> BoxFut<'_, Claim> {
        Box::pin(async move {
            match self.0.claim_classified().await {
                NativeReplayClaim::Claimed => Claim::Won,
                NativeReplayClaim::Duplicate => Claim::Replay,
                NativeReplayClaim::Unknown(_) => Claim::Unknown,
                // An answer whose claim and cutoff disagree is not a verified signature.
                NativeReplayClaim::Inconsistent => Claim::Replay,
            }
        })
    }
}

impl SignatureVerifier<ChainRequest> for ChainSignature {
    fn verify<'a>(
        &'a self,
        request: &'a ChainRequest,
    ) -> BoxFut<'a, Result<Judged<'a>, VerifierDown>> {
        Box::pin(async move {
            match self
                .chain
                .prepare_snapshot(request.cx, Arc::clone(&request.snapshot))
                .await
            {
                Err(_) => Err(VerifierDown),
                Ok(NativePreparedAnswer::NotMine) => Ok(Judged::NotSigned),
                Ok(NativePreparedAnswer::Rejected | NativePreparedAnswer::Held) => {
                    Ok(Judged::Rejected)
                }
                Ok(NativePreparedAnswer::Identity(prepared)) => {
                    // `bind` refused a chain that admits anonymous; an identity no instance
                    // verified is still never a signature.
                    if prepared.is_anonymous() {
                        return Ok(Judged::Rejected);
                    }
                    Ok(Judged::Verified(Box::new(ChainSigned(prepared))))
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "tests/native_signed_tests.rs"]
mod tests;
