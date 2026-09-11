//! The six dialects, and where each one keeps the things the loop asks about.
//!
//! Nothing here parses or writes anything. Each entry is a table of LOCATIONS — where the model
//! name is, where the client's response ceiling is, where the four metered quantities are — and the
//! reading and writing of those places is the codec's job, on the other side of this seam.
//!
//! Two dialects carry the model in the REQUEST TARGET rather than in the body, and they say so:
//! their entry names the path segment it is in, which is a location form in its own right. It used
//! to be a body pointer for all six, because the location grammar had no form for a path segment —
//! so the two path-carried dialects relied on the arrival path having copied the value into the
//! body under the ordinary member name before a plane saw the bytes. The location is the value's
//! actual place now, and nothing has to copy it there first.
//!
//! One dialect accepts the response ceiling under either of two member names. It declares BOTH, in
//! precedence order, because the admit facts carry a bounded list rather than one place and the
//! kernel takes the first that resolves. It used to declare only the older spelling — the one every
//! client of that dialect still sends — which meant a request carrying only the newer one sized its
//! hold off a key the client had not sent.

use busbar_contract::grammar::{ArrivalLocation, Location, SignedOver};
use busbar_contract::ids::SchemeAlt;
use busbar_contract::kinds::{CredentialArrival, CredentialPresentation, CredentialSignature};

/// Where one dialect keeps what the loop asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dialect {
    /// The dialect's registry name, the same string the codec crate answers to.
    pub name: &'static str,
    /// Where the request names the model.
    ///
    /// Four dialects carry it in the body, as a pointer. Two carry it in the request target, as a
    /// segment of the matched path pattern.
    pub model_location: Location,
    /// Where the request may carry the client's own response ceiling, in precedence order.
    ///
    /// One place for five of the six. Two for the dialect that accepts the ceiling under either of
    /// two member names: the older spelling first, because a request that carries both means the
    /// older one, and the newer one second so a request that carries only it is still read.
    pub max_response_pointers: &'static [&'static str],
    /// Where the request carries the conversation itself — the span that is the priced input.
    pub input_pointer: &'static str,
    /// Where the response reports the input quantity that was not served from a cache.
    pub tokens_in_pointer: &'static str,
    /// Where the response reports the produced quantity.
    pub tokens_out_pointer: &'static str,
    /// Where the response reports the input quantity that was served from a cache.
    pub cache_read_pointer: Option<&'static str>,
    /// Where the response reports the input quantity that was written to a cache.
    pub cache_write_pointer: Option<&'static str>,
    /// This dialect's credential SIGNATURE: where its clients carry a credential on the way in,
    /// and how a request to one of its upstreams carries ours on the way out.
    ///
    /// The two units that act on a credential — the authenticate step and the egress-auth step —
    /// read THIS, over the set of dialects the root mounted, and never a dialect's name. A dialect
    /// that is not mounted declares nothing, and its credential shape is therefore unreadable by
    /// absence rather than by a list.
    pub credential: CredentialSignature,
}

/// The top-level member the four body-carrying dialects name the model under.
const MODEL: Location = Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model"));

/// The arrival every scheme-worded credential uses: the authorization header, behind its word.
///
/// The word is the WIRE spelling (`Bearer`), matched case-insensitively on the way in and written
/// verbatim on the way out, so one declaration serves both directions.
const AT_AUTHORIZATION_BEARER: &[CredentialArrival] = &[CredentialArrival {
    at: ArrivalLocation::Header("authorization"),
    prefix: Some("Bearer"),
}];

/// Presenting the credential behind the scheme word in the authorization header.
const AS_AUTHORIZATION_BEARER: CredentialPresentation = CredentialPresentation::Header {
    name: "authorization",
    prefix: Some("Bearer"),
};

/// The path segment the two target-carrying dialects name the model in.
///
/// Index zero in both, and in both for the same reason: the model is the first variable segment of
/// the pattern its claim matched. One vendor's pattern spells that segment as a variable
/// (`model/{id}/invoke`); the other's spells it as the tail of a model-scoped surface
/// (`v1beta/models/{...}`), whose first segment is the model. The location grammar counts both as
/// the pattern's first variable, which is why one index serves both.
const MODEL_IN_PATH: Location = Location::Arrival(ArrivalLocation::PathSegment(0));

/// The table, one row per dialect, in the order the codec crate declares them.
pub const DIALECTS: &[Dialect] = &[
    Dialect {
        name: "anthropic",
        model_location: MODEL,
        max_response_pointers: &["/max_tokens"],
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/input_tokens",
        tokens_out_pointer: "/usage/output_tokens",
        cache_read_pointer: Some("/usage/cache_read_input_tokens"),
        cache_write_pointer: Some("/usage/cache_creation_input_tokens"),
        credential: CredentialSignature {
            alt: SchemeAlt::new("api-key"),
            // In on its own header, verbatim; out behind the scheme word. The two directions are
            // different wire facts and this dialect is the reason they cannot be one field.
            arrivals: &[CredentialArrival {
                at: ArrivalLocation::Header("x-api-key"),
                prefix: None,
            }],
            presentation: AS_AUTHORIZATION_BEARER,
        },
    },
    Dialect {
        name: "openai",
        model_location: MODEL,
        // This dialect accepts a newer spelling as well, and both are declared. The reasoning
        // models of this vendor refuse the older key outright, so a client of one of them sends
        // only the newer; naming just the older was a hold sized off a key that never arrived.
        max_response_pointers: &["/max_tokens", "/max_completion_tokens"],
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/prompt_tokens",
        tokens_out_pointer: "/usage/completion_tokens",
        cache_read_pointer: Some("/usage/prompt_tokens_details/cached_tokens"),
        // This dialect reports no separate written-to-cache quantity.
        cache_write_pointer: None,
        credential: CredentialSignature {
            alt: SchemeAlt::new("bearer"),
            arrivals: AT_AUTHORIZATION_BEARER,
            presentation: AS_AUTHORIZATION_BEARER,
        },
    },
    Dialect {
        name: "gemini",
        // The model is in the request target, not the body.
        model_location: MODEL_IN_PATH,
        max_response_pointers: &["/generationConfig/maxOutputTokens"],
        input_pointer: "/contents",
        tokens_in_pointer: "/usageMetadata/promptTokenCount",
        tokens_out_pointer: "/usageMetadata/candidatesTokenCount",
        cache_read_pointer: Some("/usageMetadata/cachedContentTokenCount"),
        cache_write_pointer: None,
        credential: CredentialSignature {
            alt: SchemeAlt::new("api-key"),
            arrivals: &[CredentialArrival {
                at: ArrivalLocation::Header("x-goog-api-key"),
                prefix: None,
            }],
            presentation: AS_AUTHORIZATION_BEARER,
        },
    },
    Dialect {
        name: "bedrock",
        // The model is in the request target, not the body.
        model_location: MODEL_IN_PATH,
        max_response_pointers: &["/inferenceConfig/maxTokens"],
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/inputTokens",
        tokens_out_pointer: "/usage/outputTokens",
        cache_read_pointer: Some("/usage/cacheReadInputTokens"),
        cache_write_pointer: Some("/usage/cacheWriteInputTokens"),
        credential: CredentialSignature {
            alt: SchemeAlt::new("request-signature"),
            // What arrives is a SIGNATURE over the request, not a credential to lift out of a
            // header — which is why the token ladder must fall THROUGH an authorization header it
            // cannot read as its own, rather than treating one as an absent credential.
            arrivals: &[CredentialArrival {
                at: ArrivalLocation::Signed {
                    over: SignedOver::Both,
                },
                prefix: None,
            }],
            presentation: CredentialPresentation::RequestSignature,
        },
    },
    Dialect {
        name: "responses",
        model_location: MODEL,
        max_response_pointers: &["/max_output_tokens"],
        input_pointer: "/input",
        tokens_in_pointer: "/usage/input_tokens",
        tokens_out_pointer: "/usage/output_tokens",
        cache_read_pointer: Some("/usage/input_tokens_details/cached_tokens"),
        cache_write_pointer: Some("/usage/input_tokens_details/cache_write_tokens"),
        credential: CredentialSignature {
            alt: SchemeAlt::new("bearer"),
            arrivals: AT_AUTHORIZATION_BEARER,
            presentation: AS_AUTHORIZATION_BEARER,
        },
    },
    Dialect {
        name: "cohere",
        model_location: MODEL,
        max_response_pointers: &["/max_tokens"],
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/tokens/input_tokens",
        tokens_out_pointer: "/usage/tokens/output_tokens",
        // This dialect reports no cache accounting at all.
        cache_read_pointer: None,
        cache_write_pointer: None,
        credential: CredentialSignature {
            alt: SchemeAlt::new("bearer"),
            arrivals: AT_AUTHORIZATION_BEARER,
            presentation: AS_AUTHORIZATION_BEARER,
        },
    },
];

/// The row for one dialect, by name.
#[must_use]
pub fn dialect(name: &str) -> Option<&'static Dialect> {
    DIALECTS.iter().find(|d| d.name == name)
}

/// Whether a dialect refuses a request that names no response ceiling.
///
/// Read off the codec crate's own declaration rather than restated here, so the two cannot drift:
/// this is the fact the request writer acts on, asked at its source.
#[must_use]
pub fn requires_max_response(name: &str) -> bool {
    busbar_llm_codec::DECLS
        .iter()
        .find(|d| d.name == name)
        .is_some_and(|d| d.requires_max_tokens)
}
