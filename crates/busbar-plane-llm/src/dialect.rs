//! The six dialects, and where each one keeps the things the loop asks about.
//!
//! Nothing here parses or writes anything. Each entry is a table of LOCATIONS — where the model
//! name is, where the client's response ceiling is, where the four metered quantities are — and the
//! reading and writing of those places is the codec's job, on the other side of this seam.
//!
//! Two locations are honest approximations and say so at the entry:
//!
//! Two dialects carry the model in the request target rather than in the body. The arrival path
//! copies it into the body under the ordinary member name before a plane sees the bytes, so the
//! pointer below is the same one for all six; without that copy there would be no pointer to give,
//! because the location grammar this plane answers in has no form for a path segment.
//!
//! One dialect accepts the response ceiling under either of two member names. A location is one
//! place, so the entry names the older of the two — the one every client of that dialect still
//! sends — and the newer spelling is read by the codec, which sees both.

/// Where one dialect keeps what the loop asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dialect {
    /// The dialect's registry name, the same string the codec crate answers to.
    pub name: &'static str,
    /// Where the request names the model, as a pointer into the request body.
    pub model_pointer: &'static str,
    /// Where the request carries the client's own response ceiling.
    pub max_response_pointer: &'static str,
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
    /// The credential alternative this dialect's clients present.
    pub scheme_alt: &'static str,
    /// The egress-auth scheme that decorates a request to an upstream of this dialect.
    pub egress_scheme: &'static str,
}

/// The top-level member name every dialect's request carries the model under once arrival has
/// copied a path-carried model into the body.
const MODEL: &str = "/model";

/// The table, one row per dialect, in the order the codec crate declares them.
pub const DIALECTS: &[Dialect] = &[
    Dialect {
        name: "anthropic",
        model_pointer: MODEL,
        max_response_pointer: "/max_tokens",
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/input_tokens",
        tokens_out_pointer: "/usage/output_tokens",
        cache_read_pointer: Some("/usage/cache_read_input_tokens"),
        cache_write_pointer: Some("/usage/cache_creation_input_tokens"),
        scheme_alt: "api-key",
        egress_scheme: "bearer",
    },
    Dialect {
        name: "openai",
        model_pointer: MODEL,
        // This dialect accepts a newer spelling as well. One location is one place, so this is the
        // older one; the codec reads whichever the client sent.
        max_response_pointer: "/max_tokens",
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/prompt_tokens",
        tokens_out_pointer: "/usage/completion_tokens",
        cache_read_pointer: Some("/usage/prompt_tokens_details/cached_tokens"),
        // This dialect reports no separate written-to-cache quantity.
        cache_write_pointer: None,
        scheme_alt: "bearer",
        egress_scheme: "bearer",
    },
    Dialect {
        name: "gemini",
        model_pointer: MODEL,
        max_response_pointer: "/generationConfig/maxOutputTokens",
        input_pointer: "/contents",
        tokens_in_pointer: "/usageMetadata/promptTokenCount",
        tokens_out_pointer: "/usageMetadata/candidatesTokenCount",
        cache_read_pointer: Some("/usageMetadata/cachedContentTokenCount"),
        cache_write_pointer: None,
        scheme_alt: "api-key",
        egress_scheme: "bearer",
    },
    Dialect {
        name: "bedrock",
        model_pointer: MODEL,
        max_response_pointer: "/inferenceConfig/maxTokens",
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/inputTokens",
        tokens_out_pointer: "/usage/outputTokens",
        cache_read_pointer: Some("/usage/cacheReadInputTokens"),
        cache_write_pointer: Some("/usage/cacheWriteInputTokens"),
        scheme_alt: "request-signature",
        egress_scheme: "request-signature",
    },
    Dialect {
        name: "responses",
        model_pointer: MODEL,
        max_response_pointer: "/max_output_tokens",
        input_pointer: "/input",
        tokens_in_pointer: "/usage/input_tokens",
        tokens_out_pointer: "/usage/output_tokens",
        cache_read_pointer: Some("/usage/input_tokens_details/cached_tokens"),
        cache_write_pointer: Some("/usage/input_tokens_details/cache_write_tokens"),
        scheme_alt: "bearer",
        egress_scheme: "bearer",
    },
    Dialect {
        name: "cohere",
        model_pointer: MODEL,
        max_response_pointer: "/max_tokens",
        input_pointer: "/messages",
        tokens_in_pointer: "/usage/tokens/input_tokens",
        tokens_out_pointer: "/usage/tokens/output_tokens",
        // This dialect reports no cache accounting at all.
        cache_read_pointer: None,
        cache_write_pointer: None,
        scheme_alt: "bearer",
        egress_scheme: "bearer",
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
    busbar_llm::DECLS
        .iter()
        .find(|d| d.name == name)
        .is_some_and(|d| d.requires_max_tokens)
}
