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
use crate::OpenAi;

/// This dialect's registry key, unique within its plane.
///
/// PUBLIC because the location row names it too, and the two must be one string rather than two
/// spellings that agree today: a row whose `name` and whose `KEY` differed would register under one
/// and resolve under the other, and the plane would answer for a dialect nothing had declared.
pub const KEY: &str = "openai";

/// The verbs this dialect names on the wire.
///
/// One per surface the ladder claims, which is what makes the two lists checkable against each
/// other: a verb here with no rung is a surface nothing routes to, and a rung with no verb is a
/// surface this crate claims and cannot name.
const VERBS: &[&str] = &[
    "chat.completions",
    "embeddings",
    "moderations",
    "images",
    "audio.translations",
];

/// The envelope keys this dialect reads out of a response head.
const HEAD_KEYS: &[&str] = &["id", "model", "object", "created", "usage"];

/// Where the metered quantities are found, one pointer per meter class the PLANE declares, in the
/// plane's own order.
///
/// The order is load-bearing and it is not this crate's to choose: the plane declares
/// `tokens_in`, `tokens_out`, `cache_read`, `cache_write` in that order, and the locators are read
/// positionally against it. The fourth is EMPTY because this dialect reports no separate
/// written-to-cache quantity — an empty locator is "this dialect does not report this class", which
/// is a different statement from a pointer at a member that never arrives, and the difference is
/// whether the class meters nothing or meters zero.
const METER_LOCATORS: &[&str] = &[
    LOCATIONS.tokens_in_pointer,
    LOCATIONS.tokens_out_pointer,
    "/usage/prompt_tokens_details/cached_tokens",
    "",
];

impl DialectMeta for OpenAi {
    const KEY: &'static str = KEY;
    const PLANE: &'static str = "llm";
    const CLAIMS: &'static [Claim] = claims::CLAIMS;
    /// This vendor's clients present a token in the standard authorization header, so the arrival
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
