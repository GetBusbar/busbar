//! Where this dialect keeps what the loop asks about, and the four codec methods.
//!
//! ## The row
//!
//! [`LOCATIONS`] is a table of PLACES — where the model is, where the client's response ceiling
//! may be, where the conversation is, where the four metered quantities are reported. Nothing here
//! parses or writes anything; the reading and writing of those places is the plane's, on the other
//! side of the four methods below.
//!
//! Three entries are worth their own sentence, and all three are places this vendor differs from
//! the three dialects carved out before it.
//!
//! The model is in the REQUEST TARGET, not the body. The row names path segment zero — the first
//! variable segment of the pattern its rung-6 claim matched, whose first segment is the model —
//! which is a location form in its own right. It used to be a body pointer, true only because the
//! arrival path had copied a target-carried model into the body before a plane saw the bytes; the
//! location is the value's actual place now.
//!
//! The conversation is at `/contents`, and the ceiling under `/generationConfig`. Neither is a
//! top-level member the other vendors use, which is what makes a shared row impossible.
//!
//! There is NO cache-write pointer. This vendor reports the read-from-cache quantity and nothing
//! about writes, so that class meters "not reported" rather than a number invented for it.
//!
//! ## The four methods
//!
//! Each is the plane's own body, called with the row above. That is the whole implementation. What
//! the crate's battery asserts is that the DELEGATION is to this dialect — that the row the plane is
//! handed is this crate's row and not a neighbour's — because that is the one thing this file could
//! get wrong.

use busbar_contract::bounded::ArenaBytes;
use busbar_contract::dest::{EgressBody, VerifiedDestination};
use busbar_contract::plane::{Ingress, PlaneSessionState, Progress, Response};
use busbar_contract::unit::{Ctx, Unit};
use busbar_contract::wire::{Decode, Encode, FrameCursor};
use busbar_plane_llm::dialect::Dialect as Locations;
use busbar_plane_llm::registry::DialectEntry;

use crate::claims::LADDER;
use crate::Gemini;

/// Where this dialect keeps everything the loop asks about.
pub const LOCATIONS: Locations = Locations {
    name: crate::meta::KEY,
    // The model is in the request target, not the body: the first variable segment of the
    // model-scoped pattern this dialect claims.
    model_location: busbar_contract::grammar::Location::Arrival(
        busbar_contract::grammar::ArrivalLocation::PathSegment(0),
    ),
    max_response_pointers: &["/generationConfig/maxOutputTokens"],
    input_pointer: "/contents",
    tokens_in_pointer: "/usageMetadata/promptTokenCount",
    tokens_out_pointer: "/usageMetadata/candidatesTokenCount",
    cache_read_pointer: Some("/usageMetadata/cachedContentTokenCount"),
    // This vendor reports no written-to-cache quantity.
    cache_write_pointer: None,
    scheme_alt: "api-key",
    egress_scheme: "bearer",
    // This vendor's upstreams accept a request with no ceiling, so the crossing adds none.
    requires_max_response: false,
};

/// This dialect's whole contribution to its plane, as one `const` a composition root seals.
///
/// It is the only thing a boot needs from this crate to make the plane speak `gemini`, and it is
/// DATA: the plane holds a row and a ladder, never a value of [`Gemini`], because holding the value
/// would be the plane naming the dialect.
pub const ENTRY: DialectEntry = DialectEntry {
    locations: LOCATIONS,
    ladder: LADDER,
};

impl busbar_contract::dialect::Dialect for Gemini {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        self.plane().decode_ingress_as(&LOCATIONS, frames, st, ctx)
    }

    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        self.plane().encode_egress_as(&LOCATIONS, u, dest, st, ctx)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        self.plane()
            .decode_response_as(&LOCATIONS, frames, dest, st, ctx)
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        self.plane().encode_response_as(&LOCATIONS, r, st, ctx)
    }
}
