// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One mounted signed route: the completion the listener binds for a plane route whose record
//! admits a signed sender ([`Admission::SignedIngress`]), and the only code that joins the
//! signed-ingress verifier ([`super::native_signed`]) to a physical request.
//!
//! What this file adds to the verifier is custody, and it keeps the verifier's rules whole:
//!
//! - **Mounted only with its whole path.** [`NativeSignedRoute::offered`] is the one decision:
//!   the route's own chain (the opened instances that read its signature header, never the data
//!   chain), every member covering the body and stating its bound, no built-in member, no hook,
//!   the operator's class the route's own. A route that fails any of these is not mounted, and
//!   says why in the operator's words.
//! - **The request judged is the request served.** [`NativeSignedRoute::admit`] takes the
//!   physical request itself, hands the verifier that request's own snapshot (the bytes as
//!   received) and completes or refuses that same request. The verified value never leaves this
//!   function, so no caller can pair one request's proof with another request's body.
//! - **The body is behind the proof.** A served request's bytes are reachable only through the
//!   owner a successful verification made ([`PhysicalUnbilledExecution::signed_request`]). A
//!   refused request's owner has none.
//! - **One answer.** Every refusal is a fact for the admission table ([`SignedUnserved::facts`]):
//!   the one 401 for any denial, 413 for a body over the bound (decided before any verifier ran),
//!   503 when the verifier or the replay store could not answer. The reason is in the log only.

use std::sync::Arc;

use busbar_plugin_abi::plane::AUTH_SIGNED_INGRESS;
use busbar_ports::CallCx;

use super::admission_table::{self, admission_of, Admission, BodyRead, Facts, NotMounted, Offered};
use super::native_chain::NativeChain;
use super::native_data::withheld_carriers;
use super::native_signed::{
    coverage, ChainRefused, ChainRequest, ChainSignature, NativeSignedIngress, NotCovered,
    SignedRefused,
};
use super::route_record::RouteRecord;
use crate::inbound::native::{
    ArrivalRefusal, CompletingPhysicalRequest, PhysicalUnbilledExecution, RouteBinding, RouteTarget,
};
use crate::plane_driver::port::PortSeat;
use crate::plane_driver::port_routes::Mounted;

/// Why a signed route's request is answered by core and not served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedUnserved {
    /// The route's verifier did not admit it ([`NativeSignedIngress::admit`]).
    Refused(SignedRefused),
    /// The request carried trailers: its input refused it before any verifier ran.
    Trailers,
}

impl SignedUnserved {
    /// What the admission table is told. A body fault is step 4's fact, decided with no verifier
    /// run; everything else is the verifier's.
    pub fn facts(self) -> Facts {
        match self {
            Self::Refused(refused) => refused.facts(),
            Self::Trailers => {
                let mut facts = Facts::arrived(false, false);
                facts.body = Some(BodyRead::Trailers);
                facts
            }
        }
    }
}

/// Why a declared signed route is not mounted. Every reason is the operator's configuration or
/// an image's own declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedUnmounted {
    /// The route's record does not admit a signed sender, or it is not declared for the class.
    NotSigned,
    /// The operator chose another class for the route.
    OperatorChoice,
    /// A hook is bound to the route: a signed request opens no unit, so its hooks would have no
    /// admitted request to run under, and a hook-bound route is never served unhooked.
    Hooked,
    /// The route's chain names a built-in member (`anonymous`, `keys`): neither verifies a
    /// sender's signature.
    BuiltIn,
    /// The instances that would judge it do not cover and bound its body.
    Coverage(NotCovered),
    /// The chain cannot be a signature verifier.
    Chain(ChainRefused),
    /// The admission table does not mount it under this configuration.
    Table(NotMounted),
    /// The owners handed to the binding are not this route's own.
    Binding,
}

impl SignedUnmounted {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotSigned => "the route's record does not admit a signed sender",
            Self::OperatorChoice => {
                "the operator's auth choice for this route is not the route's own"
            }
            Self::Hooked => {
                "a signed route with a hook bound is not served: its hooks have no admitted request to run under"
            }
            Self::BuiltIn => {
                "a signed route's verifier is an opened auth instance: its chain names a built-in member"
            }
            Self::Coverage(why) => why.reason(),
            Self::Chain(ChainRefused::NotData) => "a signed route's chain is not a data chain",
            Self::Chain(ChainRefused::AdmitsAnonymous) => {
                "a signed route's chain admits a caller that presents nothing"
            }
            Self::Table(why) => why.reason(),
            Self::Binding => "the signed route's owners are not its own",
        }
    }
}

/// What the plan knows of a signed route before any owner exists.
#[derive(Clone, Copy)]
pub struct SignedOffer<'a> {
    /// A hook is bound to the route.
    pub hooked: bool,
    /// The plane instance's public URL, if the operator configured one.
    pub public_url: Option<&'a str>,
    /// The (describe facts, `D_BODY_MAX`) of each instance of the route's own chain, in chain
    /// order. `None`: the route has no chain of its own (no configured instance reads its
    /// signature header); the data chain is never a signed route's verifier.
    pub members: Option<&'a [(u64, Option<u64>)]>,
    /// The listener's own body cap.
    pub cap: u64,
}

impl std::fmt::Debug for SignedOffer<'_> {
    /// Whether a public URL is configured, never the URL: an operator's URL may carry userinfo
    /// or query material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedOffer")
            .field("hooked", &self.hooked)
            .field("public_url_set", &self.public_url.is_some())
            .field("members", &self.members)
            .field("cap", &self.cap)
            .finish()
    }
}

/// What [`NativeSignedRoute::admit`] made of one request. Either way the owner is the output
/// authority of the answer; only an admitted one leads to the body.
pub enum SignedAnswered {
    /// The signature verified over the exact bytes and its replay claim was won.
    Admitted(PhysicalUnbilledExecution),
    /// Not admitted: core answers `refused` by the table and serves nothing.
    Refused {
        owner: PhysicalUnbilledExecution,
        refused: SignedRefused,
    },
}

/// The signed-ingress completion of one mounted route.
pub struct NativeSignedRoute {
    binding: Arc<RouteBinding>,
    ingress: NativeSignedIngress<ChainSignature>,
    record: RouteRecord,
    /// The route's challenge with the plane instance's public URL written in, at bind.
    challenge: Option<Box<str>>,
    /// The carriers every request on this route withholds from the plane.
    withheld: Arc<[Box<str>]>,
}

impl std::fmt::Debug for NativeSignedRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSignedRoute")
            .field("bound", &self.ingress.bound())
            .finish_non_exhaustive()
    }
}

impl NativeSignedRoute {
    /// Whether `mounted` is a signed route this configuration can serve whole, and the most body
    /// bytes it reads before verifying. The one decision the plan makes about a signed route;
    /// [`Self::bind`] makes it again over the owners it is handed.
    pub fn offered(mounted: &Mounted, offer: SignedOffer<'_>) -> Result<u64, SignedUnmounted> {
        let record = &mounted.record;
        if admission_of(record) != Admission::SignedIngress || mounted.auth != AUTH_SIGNED_INGRESS {
            return Err(SignedUnmounted::NotSigned);
        }
        if mounted.effective != mounted.auth {
            return Err(SignedUnmounted::OperatorChoice);
        }
        if offer.hooked {
            return Err(SignedUnmounted::Hooked);
        }
        let covered = coverage(offer.members.unwrap_or_default().iter().copied(), offer.cap);
        // The table is the judge of whether the class is mounted; the coverage is what it is
        // offered as "a signature verifier is configured for the route".
        let table = admission_table::mounted(
            record,
            Offered {
                verifier_reads_header: covered.is_ok(),
                upgrade_transport: false,
                ticket_store: false,
                signature_verifier: covered.is_ok(),
                challenge_unresolved: record.mounted_challenge(offer.public_url).is_err(),
            },
        );
        match (covered, table) {
            (Err(why), _) => Err(SignedUnmounted::Coverage(why)),
            (Ok(bound), Ok(Admission::SignedIngress)) => Ok(bound),
            (Ok(_), Ok(_)) => Err(SignedUnmounted::NotSigned),
            (Ok(_), Err(why)) => Err(SignedUnmounted::Table(why)),
        }
    }

    /// [`Self::offered`] for a route of `seat`: whether a hook is bound and the seat's public URL
    /// are read from the seat itself.
    pub fn admits(
        seat: &PortSeat,
        mounted: &Mounted,
        members: Option<&[(u64, Option<u64>)]>,
        cap: u64,
    ) -> Result<u64, SignedUnmounted> {
        Self::offered(
            mounted,
            SignedOffer {
                hooked: seat.driver.has_hooks(mounted.route),
                public_url: seat.public_url(),
                members,
                cap,
            },
        )
    }

    /// Bind the route's completion. `chain`: exactly the opened instances named for the route (its
    /// signature header's readers, or the operator's own list), in order. `members`: the same
    /// instances' (describe facts, `D_BODY_MAX`), in the same order.
    pub fn bind(
        seat: &PortSeat,
        binding: Arc<RouteBinding>,
        chain: Arc<NativeChain>,
        members: &[(u64, Option<u64>)],
        cap: u64,
    ) -> Result<Arc<Self>, SignedUnmounted> {
        let RouteTarget::Plane(target) = binding.target() else {
            return Err(SignedUnmounted::NotSigned);
        };
        let mounted = target.mounted();
        let bound = Self::admits(seat, mounted, Some(members), cap)?;
        if chain.admits_keys() {
            return Err(SignedUnmounted::BuiltIn);
        }
        if !seat.driver.caller().same_incarnation(target.caller())
            || !seat
                .driver
                .routes()
                .data
                .iter()
                .any(|route| route == mounted)
            || !chain.matches_names(target.auth_instances())
            || members.len() != target.auth_instances().len()
        {
            return Err(SignedUnmounted::Binding);
        }
        // `offered` refused a challenge that cannot be resolved.
        let Ok(challenge) = mounted.record.mounted_challenge(seat.public_url()) else {
            return Err(SignedUnmounted::Table(
                NotMounted::NoPublicUrlForItsChallenge,
            ));
        };
        let withheld = withheld_carriers(&chain, mounted.cred_header.as_deref());
        let record = mounted.record.clone();
        // A chain that can admit a caller presenting nothing is refused here: on a signed route
        // no signature is never an identity.
        let verifier = ChainSignature::bind(chain).map_err(SignedUnmounted::Chain)?;
        Ok(Arc::new(Self {
            binding,
            ingress: NativeSignedIngress::new(verifier, bound),
            record,
            challenge,
            withheld,
        }))
    }

    /// The route token this completion was bound to.
    pub fn binding(&self) -> &Arc<RouteBinding> {
        &self.binding
    }

    /// The most body bytes read for a request on this route before its signature is judged. A
    /// declared length over it is refused unread.
    pub fn bound(&self) -> u64 {
        self.ingress.bound()
    }

    /// The route's record, as bound.
    pub fn record(&self) -> &RouteRecord {
        &self.record
    }

    /// The `WWW-Authenticate` text of this route's 401, or `None` for core's generic one.
    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }

    /// The carriers every request on this route withholds from the plane: `authorization`, the
    /// signature headers its verifier's instances declare, and the route's own.
    pub fn withheld(&self) -> &Arc<[Box<str>]> {
        &self.withheld
    }

    /// Judge this exact physical request and consume it: verify the signature over its own bytes
    /// as received, claim its replay key, and complete it; or refuse it. `Err`: the request ended
    /// (cancelled, past its deadline, not this route's) and has no answer.
    ///
    /// The body bound is judged first, before any verifier is called. Dropping this future
    /// cancels the request.
    pub async fn admit(
        &self,
        request: CompletingPhysicalRequest,
        cx: CallCx,
    ) -> Result<SignedAnswered, ArrivalRefusal> {
        let binding = request.binding().clone();
        if !Arc::ptr_eq(binding.route(), &self.binding) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        binding.check_live()?;
        // The one snapshot of the original request: the verifier is handed its body, and a
        // served request is parsed from the same bytes.
        let received = ChainRequest {
            cx,
            snapshot: binding.snapshot().map_err(|_| ArrivalRefusal::Capacity)?,
        };
        match self.ingress.admit(&received).await {
            Ok(verified) => Ok(SignedAnswered::Admitted(
                request.complete_signed(&verified)?,
            )),
            Err(refused) => Ok(SignedAnswered::Refused {
                owner: request.refuse_signed(SignedUnserved::Refused(refused))?,
                refused,
            }),
        }
    }

    /// Refuse a request its own input already refused (a body over the listener's cap, request
    /// trailers): no verifier runs, nothing of the body is judged, and core answers `why` by the
    /// table.
    pub fn refuse_unread(
        &self,
        request: CompletingPhysicalRequest,
        why: SignedUnserved,
    ) -> Result<PhysicalUnbilledExecution, ArrivalRefusal> {
        if !Arc::ptr_eq(request.binding().route(), &self.binding) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        request.refuse_signed(why)
    }
}

#[cfg(test)]
#[path = "tests/native_signed_route_tests.rs"]
mod tests;
