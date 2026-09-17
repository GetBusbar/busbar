//! The control kind: a compiled-in served surface (the admin API) that decodes an ingress
//! envelope, says who it is for and what it touches, and encodes a response or a refusal — and
//! NOTHING on the data path.
//!
//! ## Why this is not a plane
//!
//! A [`crate::plane::Plane`] carries the full data-path vocabulary: it dials upstreams
//! (`encode_egress`, `encode_ingress_frame`, `decode_response`), it opens legs (`route`) and it
//! prices a response against a lane (`meter`, `admit`). A control surface does none of that. Its
//! destination is always a `KernelVerb` the kernel executes on the far side of its own verb table;
//! it never dials, never opens a leg, and never meters. So it does not implement `Plane`, and it is
//! not registered on the plane registry — modelling it as a plane meant carrying inert
//! `RoutePlan::default()`/`UsageLocators::default()` steps and an unreachable `encode_egress`, which
//! is exactly the debt the `kind-isolation:control-path` gate exists to refuse (ARCHITECTURE.md 1.4:
//! a control surface is a kind of its own, not a metered plane).
//!
//! ## What a control surface DOES answer
//!
//! Only the entry behaviour: read the inbound envelope ([`ControlSurface::decode_ingress`]), state
//! where the credential is ([`ControlSurface::authenticate`]), where the unit is going
//! ([`ControlSurface::verify`] — a `KernelVerb` destination), what it touches
//! ([`ControlSurface::approve`]), how it ended ([`ControlSurface::audit`]), and render the outbound
//! bytes ([`ControlSurface::encode_response`], [`ControlSurface::encode_refusal`]). Every method is
//! pure over its inputs, exactly as a plane's are; the signatures mirror the plane trait's own so a
//! surface that used to be a plane moves onto this seam without a byte of behaviour changing.

use crate::bounded::ArenaBytes;
use crate::dest::DestinationFacts;
use crate::kinds::CredentialLocator;
use crate::plane::{Ingress, PlaneSessionState, Response, UnitDraft};
use crate::unit::{AuditFacts, Ctx, Refusal, ScopeFacts, Unit, UnitEnd};
use crate::wire::{Decode, Encode, FrameCursor};

/// The control face: a compiled-in served surface's entry behaviour, with no data-path step.
///
/// This is deliberately NOT `Plugin`-bound (a control surface is not loaded over the ABI, DECISIONS
/// #5) and NOT `Plane` (it has no route/meter/egress). It is the trait the composition root registers
/// a control surface through instead of the plane registry.
pub trait ControlSurface {
    /// Read the inbound request envelope. Same contract as a plane's `decode_ingress`: a cursor with
    /// nothing left, or an envelope object that has not closed, is `NeedMore`; a closed envelope that
    /// names no verb is refused.
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode>;

    /// Render one response back to the client. A control surface computes no result of its own — the
    /// bytes are the executing kernel verb's — so this is a pass-through, save for any documented,
    /// pure substitution the surface owns (the admin surface substitutes `openapi.json`'s
    /// `info.version`).
    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;

    /// Render a refusal in this surface's shape. The codec state is borrowed immutably, for the same
    /// reason a plane's `encode_refusal` borrows it: a refusal must not advance codec state.
    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        draft: Option<&UnitDraft<'u>>,
        st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;

    /// Say where the credential is. A control surface never narrows outside the alternatives its
    /// claim declares and never sees the credential itself.
    fn authenticate<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> CredentialLocator;

    /// Say where this unit is going. For a control surface this is always a `KernelVerb` destination —
    /// the kernel dials its own verb table, and that IS the routing, which is why there is no `route`
    /// method here.
    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> DestinationFacts;

    /// Say what resources this unit touches.
    fn approve<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> ScopeFacts;

    /// Say what this unit was and how it ended, for the audit record.
    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, ctx: &Ctx<'u>) -> AuditFacts;
}
