//! Where this dialect keeps what the loop asks about, and the four codec methods.
//!
//! ## The row
//!
//! [`LOCATIONS`] is a table of PLACES and one fact — where the model is, where the client's
//! response ceiling may be, where the conversation is, where the four metered quantities are
//! reported, and whether an upstream of this dialect refuses a request that names no ceiling.
//! Nothing here parses or writes anything; the reading and writing of those places is the plane's,
//! on the other side of the four methods below.
//!
//! Two entries are worth their own sentence.
//!
//! The response ceiling is declared under ONE member name, and this dialect REQUIRES it. The
//! vendor's upstreams refuse a request with no `max_tokens`, so the plane's crossing fills one in
//! when the arriving request carried none — and it learns that it must from this row, not from
//! naming this vendor. It is the one `true` among the six, which is why the column exists.
//!
//! Both cache quantities are reported, as siblings under `usage`. The read-from-cache and the
//! written-to-cache counts each have their own member, so both meter classes read a number the
//! upstream reported rather than one being marked "not reported".
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
use crate::Anthropic;

/// Where this dialect keeps everything the loop asks about.
pub const LOCATIONS: Locations = Locations {
    name: crate::meta::KEY,
    model_location: busbar_contract::grammar::Location::Arrival(
        busbar_contract::grammar::ArrivalLocation::FirstFrameJsonPointer("/model"),
    ),
    max_response_pointers: &["/max_tokens"],
    input_pointer: "/messages",
    tokens_in_pointer: "/usage/input_tokens",
    tokens_out_pointer: "/usage/output_tokens",
    cache_read_pointer: Some("/usage/cache_read_input_tokens"),
    cache_write_pointer: Some("/usage/cache_creation_input_tokens"),
    scheme_alt: "api-key",
    egress_scheme: "bearer",
    // The one dialect of the six whose upstreams refuse a request with no ceiling.
    requires_max_response: true,
};

/// This dialect's whole contribution to its plane, as one `const` a composition root seals.
///
/// It is the only thing a boot needs from this crate to make the plane speak `anthropic`, and it
/// is DATA: the plane holds a row and a ladder, never a value of [`Anthropic`], because holding the
/// value would be the plane naming the dialect.
pub const ENTRY: DialectEntry = DialectEntry {
    locations: LOCATIONS,
    ladder: LADDER,
};

impl busbar_contract::dialect::Dialect for Anthropic {
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
