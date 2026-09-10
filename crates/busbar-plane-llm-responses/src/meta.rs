//! What this dialect declares about itself.
//!
//! Everything here is a constant, for the reason the plane's own `meta` gives: it is read once at
//! registration and sealed into policy. A dialect that could vary its declarations at run time
//! would make the ladder a boot proved disjoint stop being the ladder in force.

use busbar_contract::dialect::DialectMeta;
use busbar_contract::grammar::{ArrivalLocation, Claim};
use busbar_contract::ids::SchemeAlt;

use crate::claims;
use crate::dialect::LOCATIONS;
use crate::Responses;

/// This dialect's registry key, unique within its plane.
///
/// PUBLIC because the location row names it too, and the two must be one string rather than two
/// spellings that agree today: a row whose `name` and whose `KEY` differed would register under one
/// and resolve under the other, and the plane would answer for a dialect nothing had declared.
pub const KEY: &str = "responses";

/// The verbs this dialect names on the wire.
///
/// ONE, because this dialect claims one surface. The list is what makes the rungs checkable against
/// something: a verb here with no rung is a surface nothing routes to, and a rung with no verb is a
/// surface this crate claims and cannot name in an audit line.
const VERBS: &[&str] = &["responses"];

/// The envelope keys this dialect reads out of a response head.
///
/// They are not the older surface's keys and the difference is not cosmetic: the creation time is
/// `created_at` rather than `created`, and there is a `status` member the older envelope has no
/// equivalent for.
const HEAD_KEYS: &[&str] = &["id", "object", "created_at", "model", "status", "usage"];

/// Where the metered quantities are found, one pointer per meter class the PLANE declares, in the
/// plane's own order.
///
/// The order is load-bearing and it is not this crate's to choose: the plane declares
/// `tokens_in`, `tokens_out`, `cache_read`, `cache_write` in that order, and the locators are read
/// positionally against it. ALL FOUR ARE POINTERS here — this surface reports a written-to-cache
/// quantity under its own member, where the vendor's older surface reports none and declares the
/// empty locator that says "not reported". That difference is one of the reasons the two surfaces
/// are two dialects.
const METER_LOCATORS: &[&str] = &[
    LOCATIONS.tokens_in_pointer,
    LOCATIONS.tokens_out_pointer,
    "/usage/input_tokens_details/cached_tokens",
    "/usage/input_tokens_details/cache_write_tokens",
];

impl DialectMeta for Responses {
    const KEY: &'static str = KEY;
    const PLANE: &'static str = "llm";
    const CLAIMS: &'static [Claim] = claims::CLAIMS;
    /// This surface's clients present a token in the standard authorization header, so the arrival
    /// form is the header and there is nothing vendor-specific about where it is read from.
    const LOCATIONS: &'static [ArrivalLocation] = &[ArrivalLocation::Header("authorization")];
    const SCHEME_ALT: Option<SchemeAlt> = Some(SchemeAlt::new(LOCATIONS.scheme_alt));
    const EGRESS_SCHEME: Option<&'static str> = Some(LOCATIONS.egress_scheme);
    /// Streamed answers arrive on the event-stream framing of the same request.
    const STREAMING_CONTENT_TYPE: Option<&'static str> = Some("text/event-stream");
    const HEAD_KEYS: &'static [&'static str] = HEAD_KEYS;
    const VERBS: &'static [&'static str] = VERBS;
    const METER_LOCATORS: &'static [&'static str] = METER_LOCATORS;
}
