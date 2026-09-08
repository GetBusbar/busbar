//! The dialect kind: a plane's WIRE DIALECT, and the one cross-crate edge the plugin tree carves
//! out by hand.
//!
//! A dialect is the narrowest kind in the tree. It translates bytes to and from its own plane's
//! shape and does nothing else: pure, no input or output, no state outside the session state its
//! plane owns, no transport, no unit, no sibling. It DECLARES its plane, its claims and its
//! locations, and it registers INTO that plane — the plane never names a dialect back, which is
//! what keeps a plane dialect-neutral while its wire surface stays open.
//!
//! WHY THE IR IS NOT AN ASSOCIATED TYPE, since it is the first thing a reader looks for. The kernel
//! holds every plugin behind a pointer, so a dialect's trait has to be object-safe, and an
//! associated type is exactly what object safety forbids. It is also the wrong shape: the semantic
//! IR belongs to the PLANE, by the plugin-tree spec's answer on where the IR lives, and a dialect
//! that named its plane's semantic
//! type in the CONTRACT would put a plane's own vocabulary on the plugin-visible surface. So the
//! seam is the span [`Ir`](crate::bounded::Ir) both halves already share — bytes in, spans out —
//! and the plane's own IR stays where it is owned.
//!
//! Fallibility: the codec methods return [`Decode`] and [`Encode`] on the same terms the plane's
//! do; see [`crate::plane::Plane`] for what a decode failure is and is not.

use crate::bounded::ArenaBytes;
use crate::dest::{EgressBody, VerifiedDestination};
use crate::grammar::{ArrivalLocation, Claim};
use crate::ids::SchemeAlt;
use crate::plane::{Ingress, PlaneSessionState, Progress, Response};
use crate::plugin::Plugin;
use crate::unit::{Ctx, Unit};
use crate::wire::{Decode, Encode, FrameCursor};

/// Everything a dialect declares about itself.
///
/// All of it is a constant, for the reason [`PlaneMeta`](crate::plane::PlaneMeta) gives: the claim
/// ladder is sealed at boot, and a declaration that could vary afterwards would not be the one the
/// boot proved disjoint. A plane's `CLAIMS` is the union of its own and its registered dialects'
/// constants — composition, not configuration, and there is still no selector that resolves a
/// configured string.
pub trait DialectMeta {
    /// The dialect's registry key, unique within its plane.
    const KEY: &'static str;
    /// The registry key of the plane this dialect translates for. The only plane it may name.
    const PLANE: &'static str;
    /// The claims this dialect adds to its plane's ladder.
    const CLAIMS: &'static [Claim];
    /// The arrival forms this dialect can read a credential out of.
    const LOCATIONS: &'static [ArrivalLocation];
    /// The alternative this dialect narrows its plane's claimed scheme to, where it narrows one.
    const SCHEME_ALT: Option<SchemeAlt>;
    /// The egress-auth scheme key an upstream speaking this dialect expects, where there is one.
    const EGRESS_SCHEME: Option<&'static str>;
    /// The content type a streamed response is written under, where this dialect streams.
    const STREAMING_CONTENT_TYPE: Option<&'static str>;
    /// The envelope keys this dialect reads out of a response head.
    const HEAD_KEYS: &'static [&'static str];
    /// The verbs this dialect names on the wire, as its plane's operation classes are reached.
    const VERBS: &'static [&'static str];
    /// Where the metered quantities are found in this dialect's bytes: one JSON pointer per meter
    /// class its plane declares, in that plane's own order.
    ///
    /// The pointers are the dialect's because the LOCATION is dialect-specific and the CLASS is
    /// not: two dialects of one plane meter the same classes out of different places, and a plane
    /// that carried the pointers would carry a per-dialect branch — the one thing a plane may not
    /// have.
    const METER_LOCATORS: &'static [&'static str];
}

/// Translates bytes to and from its own plane's shape.
///
/// Four codec methods, one per direction per side, and nothing else: a dialect has no fact
/// methods, no introspection and no session of its own, because the facts are the plane's reading
/// and the session state is the plane's to own. Every method is pure over its inputs and none may
/// perform input or output.
///
/// # Errors
/// Every method returns [`Decode`] or [`Encode`] when the bytes cannot be expressed in this
/// dialect's shape; the plane then answers as it would for any other unreadable frame.
pub trait Dialect: Plugin + Send + Sync + 'static {
    /// Read inbound bytes into what the plane makes of them.
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode>;

    /// Write the outbound request for one verified destination, in this dialect's shape.
    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode>;

    /// Read bytes coming back from an upstream that speaks this dialect.
    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode>;

    /// Write one response frame back to a client that speaks this dialect.
    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;
}
