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
use crate::Gemini;

/// This dialect's registry key, unique within its plane.
///
/// PUBLIC because the location row names it too, and the two must be one string rather than two
/// spellings that agree today: a row whose `name` and whose `KEY` differed would register under one
/// and resolve under the other, and the plane would answer for a dialect nothing had declared.
pub const KEY: &str = "gemini";

/// The verbs this dialect names on the wire.
///
/// One per action suffix the rung-5 claims spell, and `models` for the rung-6 surface those
/// actions are scoped under — the model-scoped path with no action is the vendor's list-and-get
/// surface. The list is what makes the rungs checkable against something: a verb here with no rung
/// is a surface nothing routes to, and a path rung with no verb is a surface this crate claims and
/// cannot name in an audit line.
const VERBS: &[&str] = &[
    "generateContent",
    "streamGenerateContent",
    "embedContent",
    "batchEmbedContents",
    "predict",
    "models",
];

/// The envelope keys this dialect reads out of a response head.
///
/// The answer is a list of `candidates` rather than a message, its metering rides `usageMetadata`
/// rather than `usage`, and the model that answered is `modelVersion` — no `id`, no `object`, no
/// creation time, which is what makes these keys this dialect's and not a neighbour's.
const HEAD_KEYS: &[&str] = &["candidates", "usageMetadata", "modelVersion", "responseId"];

/// Where the metered quantities are found, one pointer per meter class the PLANE declares, in the
/// plane's own order.
///
/// The order is load-bearing and it is not this crate's to choose: the plane declares
/// `tokens_in`, `tokens_out`, `cache_read`, `cache_write` in that order, and the locators are read
/// positionally against it. THREE ARE POINTERS AND THE FOURTH IS EMPTY: this vendor reports the
/// read-from-cache quantity under `usageMetadata` and reports no written-to-cache quantity at all,
/// and the empty string is the declared way of saying "not reported" rather than a pointer that
/// would resolve to nothing.
const METER_LOCATORS: &[&str] = &[
    LOCATIONS.tokens_in_pointer,
    LOCATIONS.tokens_out_pointer,
    "/usageMetadata/cachedContentTokenCount",
    "",
];

impl DialectMeta for Gemini {
    const KEY: &'static str = KEY;
    const PLANE: &'static str = "llm";
    const CLAIMS: &'static [Claim] = claims::CLAIMS;
    /// This vendor's clients present the key in a header of the vendor's own naming, which is
    /// also rung 3 of the ladder, and its token-bearing clients present it in the standard
    /// authorization header. Both are arrival forms this dialect reads a credential out of, and
    /// the key header is first because it is the form the vendor's own SDK sends.
    const LOCATIONS: &'static [ArrivalLocation] = &[
        ArrivalLocation::Header("x-goog-api-key"),
        ArrivalLocation::Header("authorization"),
    ];
    const SCHEME_ALT: Option<SchemeAlt> = Some(SchemeAlt::new(LOCATIONS.scheme_alt));
    const EGRESS_SCHEME: Option<&'static str> = Some(LOCATIONS.egress_scheme);
    /// Streamed answers arrive on the event-stream framing of the same request when the client
    /// asked for it; the vendor's other streaming shape is the plane's framing concern, not a
    /// second content type this dialect declares.
    const STREAMING_CONTENT_TYPE: Option<&'static str> = Some("text/event-stream");
    const HEAD_KEYS: &'static [&'static str] = HEAD_KEYS;
    const VERBS: &'static [&'static str] = VERBS;
    const METER_LOCATORS: &'static [&'static str] = METER_LOCATORS;
}
