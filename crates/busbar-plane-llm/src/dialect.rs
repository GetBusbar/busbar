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

use busbar_contract::grammar::{ArrivalLocation, Location};

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
    /// The credential alternative this dialect's clients present.
    pub scheme_alt: &'static str,
    /// The egress-auth scheme that decorates a request to an upstream of this dialect.
    pub egress_scheme: &'static str,
    /// THE DIALECT'S DEFAULT OUTBOUND AUTH STYLE (the design's auth points: a member's style is its
    /// provider's `auth:`, else its plane's default for its dialect; ARCHITECT Q-L1-AUTH (A)): the
    /// style an auth plugin serves, stated in the plane tail's `dialect_auth`.
    pub egress_style: &'static str,
    /// THE DEFAULT STYLE'S PARAMETERS for this dialect, a JSON object (`""`: none), stated in the
    /// plane tail's `dialect_auth.params` and handed the auth plugin's `open_outbound` as its
    /// settings at seal, under the provider's own (ARCHITECT RULING 2026-10-03, Q-L6-AUTHPARAMS).
    /// Its `protocol` is the name the auth plugin's line for a credential it cannot present carries
    /// as that line's `protocol` field — stated where 1.5.5's builder named it (the bearer
    /// dialects and the credential-family one), and nowhere else.
    pub egress_params: &'static str,
    /// The request headers busbar GOVERNS for this dialect (lower-case): its credential headers and
    /// its tenant selectors. A same-dialect route forwards every other client header unchanged; these
    /// never pass, because busbar's upstream credential and configuration replace them (OWNER HARD
    /// RULE 2026-10-02, "BUSBAR IS INVISIBLE TO UPSTREAMS", governed fields (1) and (2)).
    pub governed_headers: &'static [&'static str],
    /// The request URL query parameters busbar GOVERNS for this dialect: its credential parameters.
    /// A same-dialect route forwards every other caller parameter unchanged; these never pass.
    pub governed_query: &'static [&'static str],
    /// The tenant selectors this dialect's far end reads, as `(config key, header)`: busbar sets
    /// each from the provider's config (`organization`, `project`) on every upstream request.
    pub tenant_headers: &'static [(&'static str, &'static str)],
    /// The response headers busbar GOVERNS for this dialect (lower-case): what the far end derives
    /// from busbar's own credential and tenant (the operator's organization or project id). A
    /// same-dialect answer relays every other upstream header; these never reach the caller.
    pub governed_response_headers: &'static [&'static str],
}

/// The top-level member the four body-carrying dialects name the model under.
const MODEL: Location = Location::Arrival(ArrivalLocation::FirstFrameJsonPointer("/model"));

/// The path segment the two target-carrying dialects name the model in.
///
/// Index zero in both, and in both for the same reason: the model is the first variable segment of
/// the pattern its claim matched. One vendor's pattern spells that segment as a variable
/// (`model/{id}/invoke`); the other's spells it as the tail of a model-scoped surface
/// (`v1beta/models/{...}`), whose first segment is the model. The location grammar counts both as
/// the pattern's first variable, which is why one index serves both.
const MODEL_IN_PATH: Location = Location::Arrival(ArrivalLocation::PathSegment(0));

/// What the two dialects of one vendor govern: its credential headers (a bearer, and the key header
/// a re-hosted deployment of it reads) and its two tenant selectors.
/// The tenant selectors of the two dialects of one vendor, by provider config key.
const OPENAI_TENANT: &[(&str, &str)] = &[
    ("organization", "openai-organization"),
    ("project", "openai-project"),
];
/// What the two dialects of one vendor govern on an answer: the operator's tenant ids it echoes.
const OPENAI_GOVERNED_RESPONSE: &[&str] = &["openai-organization", "openai-project"];

const OPENAI_GOVERNED: &[&str] = &[
    "authorization",
    "api-key",
    "openai-organization",
    "openai-project",
];

/// The `api-key` style's parameters for the dialect whose credentials come in families (its
/// codec's `EgressScheme::Static`): an api key presented in `x-api-key` with leading whitespace
/// trimmed, an oauth token as a bearer, the operator's own key in `x-api-key`, a passthrough caller's
/// as a bearer.
pub(crate) const KEY_FAMILY_PARAMS: &str = concat!(
    r#"{"protocol":"anthropic","header":"x-api-key","#,
    r#""families":[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},"#,
    r#"{"prefix":"sk-ant-oat"}],"#,
    r#""own":{"header":"x-api-key"},"passthrough":{}}"#,
);

/// The `sigv4` style's parameters for the signed dialect (its codec's `EgressScheme::SigV4`): the
/// service, the content type the signature covers, and the region read from the provider's host by
/// the codec's rule (`derive_sigv4_region`), else its default with the codec's warning.
pub(crate) const SIGNED_PARAMS: &str = concat!(
    r#"{"service":"bedrock","content_type":"application/json","#,
    r#""region":{"host_label_after":["bedrock-runtime","bedrock-runtime-fips","bedrock","bedrock-fips"],"#,
    r#""default":"us-east-1","#,
    r#""unread":"could not derive AWS region from Bedrock endpoint host; defaulting SigV4 scope to "#,
    r#"us-east-1 (set a bedrock-runtime[-fips].<region>.amazonaws.com host)"}}"#,
);

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
        scheme_alt: "api-key",
        egress_scheme: "bearer",
        egress_style: "api-key",
        egress_params: KEY_FAMILY_PARAMS,
        governed_headers: &["authorization", "x-api-key"],
        governed_query: &[],
        tenant_headers: &[],
        governed_response_headers: &["anthropic-organization-id"],
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
        scheme_alt: "bearer",
        egress_scheme: "bearer",
        egress_style: "bearer",
        egress_params: r#"{"protocol":"openai"}"#,
        governed_headers: OPENAI_GOVERNED,
        governed_query: &[],
        tenant_headers: OPENAI_TENANT,
        governed_response_headers: OPENAI_GOVERNED_RESPONSE,
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
        scheme_alt: "api-key",
        egress_scheme: "bearer",
        egress_style: "x-goog-api-key",
        egress_params: "",
        governed_headers: &["authorization", "x-goog-api-key", "x-goog-user-project"],
        governed_query: &["key"],
        tenant_headers: &[],
        governed_response_headers: &[],
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
        scheme_alt: "request-signature",
        egress_scheme: "request-signature",
        egress_style: "sigv4",
        egress_params: SIGNED_PARAMS,
        governed_headers: &[
            "authorization",
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token",
        ],
        governed_query: &[],
        tenant_headers: &[],
        governed_response_headers: &[],
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
        scheme_alt: "bearer",
        egress_scheme: "bearer",
        egress_style: "bearer",
        egress_params: r#"{"protocol":"responses"}"#,
        governed_headers: OPENAI_GOVERNED,
        governed_query: &[],
        tenant_headers: OPENAI_TENANT,
        governed_response_headers: OPENAI_GOVERNED_RESPONSE,
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
        scheme_alt: "bearer",
        egress_scheme: "bearer",
        egress_style: "bearer",
        egress_params: r#"{"protocol":"cohere"}"#,
        governed_headers: &["authorization"],
        governed_query: &[],
        tenant_headers: &[],
        governed_response_headers: &[],
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
    crate::codec::DECLS
        .iter()
        .find(|d| d.name == name)
        .is_some_and(|d| d.requires_max_tokens)
}
