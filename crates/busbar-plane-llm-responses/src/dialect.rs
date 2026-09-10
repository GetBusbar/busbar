//! Where this dialect keeps what the loop asks about, and the four codec methods.
//!
//! ## The row
//!
//! [`LOCATIONS`] is a table of PLACES and nothing else — where the model is, where the client's
//! response ceiling may be, where the conversation is, where the four metered quantities are
//! reported. Nothing here parses or writes anything; the reading and writing of those places is the
//! plane's, on the other side of the four methods below.
//!
//! Three of the places are worth their own sentence, and all three are places this surface differs
//! from the same vendor's older one — which is what makes the two two dialects.
//!
//! The conversation is at `/input`, not `/messages`. That is the priced span, so a row that named
//! the older member would price the whole document or nothing at all.
//!
//! The response ceiling is declared under ONE member name. This surface was introduced with
//! `/max_output_tokens` and has never accepted the older key, so a second pointer would name a place
//! a client of this surface cannot put a value.
//!
//! There IS a cache-write pointer, where the older surface has none. This surface reports the
//! written-to-cache quantity under its own member, so the class meters what the upstream reported
//! rather than not being reported at all.
//!
//! ## The four methods
//!
//! Each is the plane's own body, called with the row above. That is the whole implementation. What
//! the crate's battery asserts is that the DELEGATION is to this dialect — that the row the plane is
//! handed is this crate's row and not a neighbour's — because that is the one thing this file could
//! get wrong, and the neighbour it would most plausibly reach for is the sibling crate that speaks
//! the same vendor's other surface.

use busbar_contract::bounded::ArenaBytes;
use busbar_contract::dest::{EgressBody, VerifiedDestination};
use busbar_contract::plane::{Ingress, PlaneSessionState, Progress, Response};
use busbar_contract::unit::{Ctx, Unit};
use busbar_contract::wire::{Decode, Encode, FrameCursor};
use busbar_plane_llm::dialect::Dialect as Locations;
use busbar_plane_llm::registry::DialectEntry;

use crate::claims::LADDER;
use crate::Responses;

/// Where this dialect keeps everything the loop asks about.
pub const LOCATIONS: Locations = Locations {
    name: crate::meta::KEY,
    model_location: busbar_contract::grammar::Location::Arrival(
        busbar_contract::grammar::ArrivalLocation::FirstFrameJsonPointer("/model"),
    ),
    max_response_pointers: &["/max_output_tokens"],
    input_pointer: "/input",
    tokens_in_pointer: "/usage/input_tokens",
    tokens_out_pointer: "/usage/output_tokens",
    cache_read_pointer: Some("/usage/input_tokens_details/cached_tokens"),
    // This surface DOES report a separate written-to-cache quantity, unlike the same vendor's older
    // one, and it reports it beside the cache-read quantity under the input-token details.
    cache_write_pointer: Some("/usage/input_tokens_details/cache_write_tokens"),
    scheme_alt: "bearer",
    egress_scheme: "bearer",
    // This surface accepts a request with no ceiling, so the crossing adds none.
    requires_max_response: false,
};

/// This dialect's whole contribution to its plane, as one `const` a composition root seals.
///
/// It is the only thing a boot needs from this crate to make the plane speak `responses`, and it is
/// DATA: the plane holds a row and a ladder, never a value of [`Responses`], because holding the
/// value would be the plane naming the dialect.
pub const ENTRY: DialectEntry = DialectEntry {
    locations: LOCATIONS,
    ladder: LADDER,
};

impl busbar_contract::dialect::Dialect for Responses {
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
