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
use crate::Anthropic;

/// This dialect's registry key, unique within its plane.
///
/// PUBLIC because the location row names it too, and the two must be one string rather than two
/// spellings that agree today: a row whose `name` and whose `KEY` differed would register under one
/// and resolve under the other, and the plane would answer for a dialect nothing had declared.
pub const KEY: &str = "anthropic";

/// The verbs this dialect names on the wire.
///
/// ONE PATH SURFACE, so one verb. Three rungs and one verb is not a shortfall: two of the rungs
/// are HEADER evidence about the client — a version header, a key header — and a header claims
/// every path a request could arrive on rather than naming a surface of its own. The surface those
/// rungs route to is the same one the path rung names, and the list is what makes that checkable:
/// a verb here with no rung is a surface nothing routes to, and a path rung with no verb is a
/// surface this crate claims and cannot name in an audit line.
const VERBS: &[&str] = &["messages"];

/// The envelope keys this dialect reads out of a response head.
///
/// The messages envelope carries its finish under `stop_reason` (with the matched sequence beside
/// it) and its kind under `type`; there is no `object` and no creation time, which is what makes
/// these keys this dialect's and not a neighbour's.
const HEAD_KEYS: &[&str] = &[
    "id",
    "type",
    "role",
    "model",
    "stop_reason",
    "stop_sequence",
    "usage",
];

/// Where the metered quantities are found, one pointer per meter class the PLANE declares, in the
/// plane's own order.
///
/// The order is load-bearing and it is not this crate's to choose: the plane declares
/// `tokens_in`, `tokens_out`, `cache_read`, `cache_write` in that order, and the locators are read
/// positionally against it. ALL FOUR ARE POINTERS here — this vendor reports both the read-from-
/// cache and the written-to-cache quantities as siblings of the two plain counts under `usage`,
/// each under its own member.
const METER_LOCATORS: &[&str] = &[
    LOCATIONS.tokens_in_pointer,
    LOCATIONS.tokens_out_pointer,
    "/usage/cache_read_input_tokens",
    "/usage/cache_creation_input_tokens",
];

impl DialectMeta for Anthropic {
    const KEY: &'static str = KEY;
    const PLANE: &'static str = "llm";
    const CLAIMS: &'static [Claim] = claims::CLAIMS;
    /// This vendor's clients present the key in a header of the vendor's own naming, which is
    /// also rung 4 of the ladder, and its token-bearing clients present it in the standard
    /// authorization header. Both are arrival forms this dialect reads a credential out of, and
    /// the key header is first because it is the form the vendor documents.
    const LOCATIONS: &'static [ArrivalLocation] = &[
        ArrivalLocation::Header("x-api-key"),
        ArrivalLocation::Header("authorization"),
    ];
    const SCHEME_ALT: Option<SchemeAlt> = Some(SchemeAlt::new(LOCATIONS.scheme_alt));
    const EGRESS_SCHEME: Option<&'static str> = Some(LOCATIONS.egress_scheme);
    /// Streamed answers arrive on the event-stream framing of the same request.
    const STREAMING_CONTENT_TYPE: Option<&'static str> = Some("text/event-stream");
    const HEAD_KEYS: &'static [&'static str] = HEAD_KEYS;
    const VERBS: &'static [&'static str] = VERBS;
    const METER_LOCATORS: &'static [&'static str] = METER_LOCATORS;
}
