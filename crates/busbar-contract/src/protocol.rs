// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL-SEAM SHAPES (DECISIONS #83: contract = shapes) — the vocabulary and the traits a

use zeroize::{Zeroize, Zeroizing};

use crate::codec::CodecHost;
use crate::operation::OpVerb;

/// Error `type` for a missing or invalid API key.
pub const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";
/// Error `type` for a malformed / bad-argument request.
pub const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
/// Error `type` for a permission / access-control denial.
pub const ERR_TYPE_PERMISSION: &str = "permission_error";
/// Error `type` for a resource that does not exist.
pub const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
/// Error `type` for a rate-limit / throttle response.
pub const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
/// Error `type` for a transient upstream failure.
pub const ERR_TYPE_SERVER_ERROR: &str = "server_error";
/// Error `type` for a billing-quota exhaustion (HTTP 429).
pub const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Internal kind for an overloaded upstream; a dialect whose wire has no overloaded type maps it to

pub const ERR_TYPE_OVERLOADED: &str = "overloaded_error";
/// Error `type` for a generic upstream/API failure; also the agnostic forward-layer kind

pub const ERR_TYPE_API_ERROR: &str = "api_error";
/// Error `type` for an oversized request (HTTP 413); shared by the forward KIND bank and the

pub const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

/// Agnostic forward kind for a generic upstream/API failure.
pub const KIND_API_ERROR: &str = ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from [`ERR_TYPE_OVERLOADED`] ("overloaded_error", one

pub const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from one dialect's `timeout_error` wire spelling.
pub const KIND_TIMEOUT: &str = "timeout";
/// Transient upstream-failure forward kind (aliases the `server_error` type).
pub const KIND_SERVER_ERROR: &str = ERR_TYPE_SERVER_ERROR;
/// Caller-authentication failure forward kind (aliases the `authentication_error` type).
pub const KIND_AUTHENTICATION: &str = ERR_TYPE_AUTHENTICATION;
/// Caller-permission failure forward kind (aliases the `permission_error` type).
pub const KIND_PERMISSION: &str = ERR_TYPE_PERMISSION;
/// Rate-limit forward kind (aliases the `rate_limit_error` type).
pub const KIND_RATE_LIMIT: &str = ERR_TYPE_RATE_LIMIT;
/// Malformed/invalid-request forward kind (aliases the `invalid_request_error` type).
pub const KIND_INVALID_REQUEST: &str = ERR_TYPE_INVALID_REQUEST;
/// Unknown-model / not-found forward kind (aliases the `not_found_error` type).
pub const KIND_NOT_FOUND: &str = ERR_TYPE_NOT_FOUND;
/// Quota-exhausted forward kind (aliases the `insufficient_quota` type).
pub const KIND_INSUFFICIENT_QUOTA: &str = ERR_TYPE_INSUFFICIENT_QUOTA;
/// Oversized-request forward kind (aliases the `request_too_large` type).
pub const KIND_REQUEST_TOO_LARGE: &str = ERR_TYPE_REQUEST_TOO_LARGE;

/// The failure-DISPOSITION metric-label value for a context-length result — the label a dialect's

pub const DISPOSITION_CONTEXT_LENGTH: &str = crate::upstream::Disposition::ContextLength.label();

/// Provider error-code token emitted when a request exceeds the model's context-window limit.

pub const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST

pub const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for event-stream responses — the `Content-Type` value that

pub const TEXT_EVENT_STREAM: &str = "text/event-stream";

/// Unknown/foreign egress protocol default `User-Agent`: a generic-but-present UA still beats

pub const EGRESS_UA_DEFAULT: &str = "okhttp/4.12.0";

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics

pub const SIGNAL_IR_PARSE: &str = "ir_parse";

/// An IR-level error, currently an alias for [`CanonicalSignal`](crate::upstream::CanonicalSignal)

pub type IrError = crate::upstream::CanonicalSignal;

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a

pub const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

/// The length of the line terminator starting at `i`, or `None` when `i` does not begin one.

fn terminator_len(buf: &[u8], i: usize) -> Option<usize> {
    match buf.get(i)? {
        b'\n' => Some(1),
        b'\r' => match buf.get(i + 1) {
            Some(b'\n') => Some(2),
            Some(_) => Some(1),
            None => None,
        },
        _ => None,
    }
}

/// Find the first event-stream frame terminator (a blank line) in `buf`, returning `(offset,

pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    loop {
        let at = i + memchr::memchr2(b'\r', b'\n', &buf[i..])?;
        let first = terminator_len(buf, at)?;
        if let Some(second) = terminator_len(buf, at + first) {
            return Some((at, first + second));
        }

        i = at + first;
    }
}

/// Split event-stream frame text into lines on the event-stream grammar's own line-terminator rule

pub fn sse_lines(text: &str) -> Vec<&str> {
    sse_line_spans(text.as_bytes())
        .into_iter()
        .map(|(start, end)| &text[start..end])
        .collect()
}

/// The `(start, end)` byte span of each line in `bytes` under the event-stream line-terminator

pub fn sse_line_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match terminator_len(bytes, i) {
            Some(len) => {
                spans.push((start, i));
                i += len;
                start = i;
            }
            None => i += 1,
        }
    }
    if start < bytes.len() {
        spans.push((start, bytes.len()));
    }
    spans
}

/// THE EVENT-STREAM FRAME REASSEMBLER: bytes in, whole frames out, borrowed from the one buffer.
///
/// An event stream does not arrive one frame per chunk: one read can carry three frames, half a
/// frame, or the tail of one and the head of the next. So bytes accumulate here and a frame is
/// yielded only once the blank line that ends it ([`find_frame_terminator`]) has arrived; the frame
/// includes its terminator.
///
/// Linear in the bytes fed, however they are chunked: a scan resumes where the last one stopped
/// (three bytes behind it, as the longest terminator, `\r\n\r\n`, is four), never below the end of
/// the last frame yielded; and the framed prefix is dropped once per [`push`](Self::push), not once
/// per frame. A frame is copied nowhere: [`next_frame`](Self::next_frame) lends it, and
/// [`next_span`](Self::next_span) names it in [`buffer`](Self::buffer), which holds until the next
/// push.
#[derive(Debug, Clone, Default)]
pub struct SseFrames {
    buf: Vec<u8>,
    /// The end of the last frame yielded.
    consumed: usize,
    /// How far into `buf` a scan has looked.
    scanned: usize,
}

/// The longest terminator is four bytes, so a scan resuming three bytes behind the previous end

const TERMINATOR_REWIND: usize = 3;

impl SseFrames {
    /// An empty reassembler.
    #[must_use]
    pub const fn new() -> Self {
        SseFrames {
            buf: Vec::new(),
            consumed: 0,
            scanned: 0,
        }
    }

    /// Add a chunk, first dropping every frame already yielded.
    pub fn push(&mut self, chunk: &[u8]) {
        if self.consumed > 0 {
            let remaining = self.buf.len() - self.consumed;
            self.buf.copy_within(self.consumed.., 0);

            self.buf[remaining..].zeroize();
            self.buf.truncate(remaining);
            self.scanned -= self.consumed;
            self.consumed = 0;
        }
        let required = self
            .buf
            .len()
            .checked_add(chunk.len())
            .expect("SSE buffer length overflow");
        if required > self.buf.capacity() {
            let mut grown = Zeroizing::new(Vec::new());

            grown.reserve(required.max(self.buf.capacity().saturating_mul(2)));
            grown.extend_from_slice(&self.buf);
            self.buf.zeroize();
            self.buf = std::mem::take(&mut *grown);
        }
        self.buf.extend_from_slice(chunk);
    }

    /// The span in [`buffer`](Self::buffer) of the next complete frame (its terminator included),

    pub fn next_span(&mut self) -> Option<std::ops::Range<usize>> {
        let from = self
            .scanned
            .saturating_sub(TERMINATOR_REWIND)
            .max(self.consumed)
            .min(self.buf.len());
        match find_frame_terminator(&self.buf[from..]) {
            Some((at, len)) => {
                let start = self.consumed;
                let end = from + at + len;
                self.consumed = end;
                self.scanned = end;
                Some(start..end)
            }
            None => {
                self.scanned = self.buf.len();
                None
            }
        }
    }

    /// The next complete frame (its terminator included), lent, or `None` until more bytes arrive.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        let span = self.next_span()?;
        self.buf.get(span)
    }

    /// The bytes held since the last [`push`](Self::push) dropped the framed prefix: every span

    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    /// How many bytes are held that no frame yielded yet. A reader bounds this: a far end that

    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len() - self.consumed
    }
}

impl Drop for SseFrames {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// How tightly a protocol CLAIMS an inbound request, for the generic detection fold. A LOWER value
/// binds TIGHTER — it names an earlier rung of the historical detection ladder (a mandatory-unique
/// credential header binds tighter than a path verb, which binds tighter than a bare path suffix).
/// The fold picks the tightest claim across the registered protocols; a tie breaks by registration
/// order. Opaque to core: only the relative order is meaningful, and each protocol owns the rungs
/// it claims. This is the datum that let a hand-ordered `if`-ladder in the kernel become a fold
/// over per-declaration predicates — each dialect's specific header/path sniff now states its own
/// rungs on its declaration's `claims`, and the kernel names no dialect.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClaimStrength(pub u16);

/// The ROUTER detection predicate a protocol supplies: `(fields, path) -> Option<ClaimStrength>`,

pub type ClaimsFn = fn(HeadFields<'_>, &str) -> Option<ClaimStrength>;

/// A request head as a plane receives it: its fields in order, each name and value as bytes (the

pub type HeadFields<'a> = &'a [(&'a [u8], &'a [u8])];

/// The value of the FIRST field in `fields` named `name` (in any case) whose value is a legal header

#[must_use]
pub fn head_field<'a>(fields: HeadFields<'a>, name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, v)| {
            n.eq_ignore_ascii_case(name.as_bytes())
                && v.iter().all(|b| (*b >= 0x20 && *b != 0x7f) || *b == b'\t')
        })
        .map(|(_, v)| *v)
}

/// The RESIDUAL detection predicate a protocol supplies: `path -> Option<ClaimStrength>`, from the

pub type ResidualClaimsFn = fn(&str) -> Option<ClaimStrength>;

/// A protocol's RESPONSE-side vendor-metadata reporter: given a response body, the vendor-scoped

pub type VendorResponseMetadataFn = fn(&serde_json::Value) -> Vec<&'static str>;

/// A streaming JSON-array reframer: consumes a protocol's event-stream response bytes and re-emits

pub trait ArrayStreamFramer: Send {
    /// Feed a chunk of event-stream bytes; return JSON-array bytes for whatever complete frames are

    fn feed(&mut self, chunk: &[u8]) -> Vec<u8>;

    /// Close the array at end-of-stream when this framer sits DOWNSTREAM of a cross-protocol

    fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8>;

    /// Terminate the array with a trailing protocol-shaped SERVER-ERROR element, then the closing `]`.

    fn finish_with_server_error(&mut self, message: &str) -> Vec<u8>;
}

/// **THE 4TH NEUTRAL SEAM.** The per-PROTOCOL computed-codec facade

pub trait DialectCodec: Send + Sync {
    fn probe_body(&self, host: &dyn CodecHost, model: &str) -> Vec<u8>;
    fn apply_rewrite_to_ingress_body(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        messages: &[serde_json::Value],
        tools: &[serde_json::Value],
    ) -> bool;
    fn recover_truncated_usage(&self, tail: &[u8]) -> Option<crate::billing::TokenUsage>;
    fn ingress_response_request_id(
        &self,
        host: &dyn CodecHost,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)>;
    fn write_error(
        &self,
        host: &dyn CodecHost,
        status: u16,
        kind: &str,
        message: &str,
    ) -> serde_json::Value;
    fn requested_candidate_count(&self, body: &serde_json::Value) -> Option<u64>;
    fn write_response_exception(
        &self,
        host: &dyn CodecHost,
        err: &crate::upstream::CanonicalSignal,
    ) -> Option<(String, String)>;
    fn write_error_frame(
        &self,
        host: &dyn CodecHost,
        err: &crate::upstream::CanonicalSignal,
    ) -> Option<(String, serde_json::Value)>;
    fn wants_array_stream(&self, body: &serde_json::Value) -> bool;
    fn inject_response_metrics(&self, value: &mut serde_json::Value, elapsed_ms: Option<u64>);
    /// The head fields this dialect's error response carries beside its body, given the built

    fn error_response_fields(
        &self,
        host: &dyn CodecHost,
        kind: &str,
        envelope: &serde_json::Value,
    ) -> Vec<(String, Vec<u8>)>;
    /// This protocol's upstream-error vocabulary (the reader's `extract_error`), reached by name so

    fn extract_error(&self, status: u16, body: &[u8]) -> crate::upstream::RawUpstreamError;
    /// The dialect's array-stream framer for a JSON-array ingress client, or `None` when this

    fn make_array_stream_framer(&self) -> Option<Box<dyn ArrayStreamFramer>>;
    /// The upstream request path for a (streaming) request against this dialect — the health probe's

    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String;
    /// Install the authoritative lane model into a same-protocol passthrough body if the dialect

    fn rewrite_model_if_needed(&self, body: &mut serde_json::Value, model: &str) -> bool;
    /// Reshape a path-base (URL-model) lane's body for this dialect (e.g. drop the body `model`,

    fn reshape_for_path_base(&self, body: &mut serde_json::Value) -> bool;
}

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that

pub struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `runtime.region-1.example.com`. Borrowed from the lane's
    pub host: &'a str,
    /// URI-encoded request path (no query), e.g. `/model/vendor.model%3A0/invoke`. Borrowed (like
    pub canonical_uri: &'a str,
    /// The exact request body bytes that will be sent.
    pub body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub timestamp_epoch: u64,
    /// The UPSTREAM-credential mode for this request. Lets a writer resolve a credential whose scheme
    pub upstream_creds: crate::config::UpstreamCreds,
}

/// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
/// verification itself stays in the auth layer, which has the governance key lookup and the shared
/// signing helpers. This replaces a reader-vtable predicate that was the same
/// fact answered through a vtable — and answering it through a vtable meant allocating a reader to
/// ask a `&'static` question.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngressAuth {
    /// A bearer token / API key in a header (every protocol but the request-signing one).
    Bearer,
    /// A SigV4 request signature (the request-signing protocol's ingress shape).
    SigV4,
}

/// A protocol's declared egress credential-header builder: the resolved per-request credential

pub type EgressAuthHeaders = fn(&str, &SigningContext) -> Vec<(String, Vec<u8>)>;

/// HOW ONE CREDENTIAL IS PRESENTED on an egress request — which header carries it and in what
/// form. Declared data: the kernel's egress-auth unit reads it and writes the header itself, so the
/// credential never has to pass through the plane that declared it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialHeader {
    /// `authorization: Bearer <credential>`.
    Bearer,
    /// A custom header (`header`, lowercase) carrying the credential verbatim, or with its leading
    /// whitespace trimmed when `trim_start` is set (a configured key whose family was recognized on
    /// its trimmed text is sent as that text).
    Raw {
        /// The lowercase header name.
        header: &'static str,
        /// Whether leading whitespace is trimmed before the credential is sent.
        trim_start: bool,
    },
}

/// ONE ROW OF A CREDENTIAL-FAMILY TABLE: a credential whose text, leading whitespace trimmed, starts
/// with `prefix` belongs to this family and is presented as `presented_as`. The table is how a
/// dialect that accepts two credential families (a static key in one header, an access token as a
/// bearer) states which is which as data rather than as code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CredentialFamily {
    /// The family's credential prefix.
    pub prefix: &'static str,
    /// How a credential of this family is presented.
    pub presented_as: CredentialHeader,
}

/// A PROTOCOL'S DECLARED EGRESS SCHEME — how busbar presents a lane's credential to this protocol's
/// upstream, as data the kernel's egress-auth unit reads. The plane declares WHICH scheme; the
/// kernel holds the credential and writes (or signs) the headers, so no plane receives a secret.
/// Non-credential static headers a dialect always sends (a version header) are not auth: they are
/// declared beside it, in [`ProtocolDecl::static_headers`].
#[derive(Clone, Copy, Debug)]
pub enum EgressScheme {
    /// A static credential, presented by a credential-family table: the first row whose prefix the
    /// credential starts with decides; a credential matching no row is presented by the lane's
    /// credential MODE — `own` for a configured lane key, `passthrough` for a forwarded caller token.
    /// A static scheme is lane-constant: the same credential and mode always present the same bytes.
    Static {
        /// The credential-family table, in precedence order (may be empty).
        families: &'static [CredentialFamily],
        /// How a configured lane key that matches no family is presented.
        own: CredentialHeader,
        /// How a forwarded caller token that matches no family is presented.
        passthrough: CredentialHeader,
    },
    /// A per-request SigV4 signature over the request, the lane credential being
    /// `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`. Never lane-constant: it signs the body, the time and
    /// the path.
    SigV4 {
        /// The service name the signature is scoped to.
        service: &'static str,
        /// THE REGION, as a declared pure function of the upstream host (the endpoint names its
        /// region); `None` when the host names none.
        region_of_host: fn(&str) -> Option<&str>,
        /// The region signed for when `region_of_host` finds none.
        default_region: &'static str,
        /// The request content type, which the signature covers beside the host.
        content_type: &'static str,
    },
}

impl EgressScheme {
    /// `authorization: Bearer <credential>` whatever the credential or mode.
    pub const fn bearer() -> Self {
        Self::Static {
            families: &[],
            own: CredentialHeader::Bearer,
            passthrough: CredentialHeader::Bearer,
        }
    }

    /// The credential verbatim in the custom header `header` whatever the credential or mode.
    pub const fn header(header: &'static str) -> Self {
        let raw = CredentialHeader::Raw {
            header,
            trim_start: false,
        };
        Self::Static {
            families: &[],
            own: raw,
            passthrough: raw,
        }
    }
}

/// EVERYTHING CORE KNOWS ABOUT A PROTOCOL, declared once by the protocol itself.

pub struct ProtocolDecl {
    /// The registry key, and the metrics label. **OPERATOR-VISIBLE:** a protocol name appears in
    pub name: &'static str,

    /// This protocol's NEUTRAL computed-codec facade ([`DialectCodec`]), or `None` for a protocol
    pub codec: Option<&'static dyn DialectCodec>,

    /// The cell that serves one exchange on this protocol. Replaces `handlers::request_handler`'s
    pub handler: Option<&'static dyn crate::codec::RequestHandler>,

    /// THE VERBS this protocol serves — one [`OpVerb`] (`Verb { op, name }`
    pub verbs: &'static [OpVerb],

    /// TOP-LEVEL body keys the pre-materialized path may point-read, DOM-free. The registry unions
    pub head_keys: &'static [&'static str],

    /// The `Content-Type` this protocol's writer emits on a STREAMING response, or `None` for a
    pub streaming_content_type: Option<&'static str>,

    /// The router's array-stream shim key for this protocol (only one dialect has one: a marker
    pub array_stream_shim_key: Option<&'static str>,

    /// This protocol's NATIVE tool-call id prefix, or `None` when it carries no tool id on the wire
    pub native_tool_id_prefix: Option<&'static str>,

    /// Which inbound auth scheme this protocol's clients present.
    pub ingress_auth: IngressAuth,

    /// This protocol's NATIVE egress credential-header builder, or `None` for a protocol whose
    pub egress_auth_headers: Option<EgressAuthHeaders>,

    /// Whether [`Self::egress_auth_headers`]'s output is LANE-CONSTANT: a pure function of the
    pub egress_auth_lane_constant: bool,

    /// This protocol's DECLARED egress scheme, which the kernel's egress-auth unit presents the
    pub egress_scheme: Option<EgressScheme>,

    /// Whether a STREAMING response on this protocol reports token usage only when the request
    pub stream_usage_requires_opt_in: bool,

    /// Replaces `ProtocolWriter::requires_max_tokens()`. Whether this dialect hard-rejects a request
    pub requires_max_tokens: bool,

    /// Replaces `ProtocolWriter::stop_sequence_cap()`. The published cap on stop sequences and the
    pub stop_sequence_cap: Option<(usize, &'static str)>,

    /// Replaces `ProtocolWriter::cache_markers_model_gated()`. Whether this dialect's native cache
    pub cache_markers_model_gated: bool,

    /// Replaces `ProtocolWriter::fills_thought_signature()`. Whether egress fills the
    pub fills_thought_signature: bool,

    /// Replaces `ProtocolWriter::frame_after_message_start()`. A framed wire frame this dialect emits
    pub frame_after_message_start: Option<&'static [u8]>,

    /// Replaces `ProtocolWriter::reshapes_body_at_path_base()` (the PREDICATE only). Whether this
    pub reshapes_body_at_path_base: bool,

    /// Replaces `ProtocolWriter::max_cache_control_breakpoints()`. The maximum `cache_control`
    pub max_cache_control_breakpoints: Option<usize>,

    /// Replaces `ProtocolWriter::quota_exceeded_status()`. The native HTTP status a quota/budget
    pub quota_exceeded_status: u16,

    /// Replaces `ProtocolWriter::ingress_is_eventstream()`. True when this protocol's ingress client
    pub ingress_is_eventstream: bool,

    /// Replaces the writer's former done-terminator method. True when this protocol's streamed
    pub emits_sse_done_terminator: bool,

    /// Replaces `ProtocolWriter::max_citations_per_delta()`. The maximum citations one streamed
    pub max_citations_per_delta: Option<usize>,

    /// Replaces `ProtocolWriter::egress_user_agent()`. The plausible native-SDK `User-Agent` for THIS
    pub egress_user_agent: &'static str,

    /// Replaces `ProtocolWriter::has_model_in_url()`. True when this protocol carries the model in the
    pub has_model_in_url: bool,

    /// Replaces `ProtocolWriter::auth_failure_status_and_kind()`. The HTTP status and error `kind` a
    pub auth_failure_status_and_kind: (u16, &'static str),

    /// Replaces `ProtocolWriter::ingress_relays_amzn_headers()`. True when this protocol's ingress
    pub ingress_relays_amzn_headers: bool,

    /// Replaces `ProtocolWriter::ingress_relayed_response_header_names()`. The upstream response
    pub ingress_relayed_response_header_names: &'static [&'static str],

    /// Replaces `ProtocolWriter::auth_failure_message()`. The vendor-plausible auth-failure wire
    pub auth_failure_message: &'static str,

    /// Replaces `ProtocolWriter::uses_array_stream_shim()`. True when this protocol's ingress
    pub uses_array_stream_shim: bool,

    /// Replaces `ProtocolWriter::has_native_path_not_found()`. True when this protocol has a native
    pub has_native_path_not_found: bool,

    /// Replaces `ProtocolWriter::egress_accept()` (the STREAMING half of it). The native-SDK
    pub egress_stream_accept: &'static str,

    /// This protocol's `GET /v1(beta)/models` (list-models) response ENVELOPE builder, or `None`
    pub models_list_envelope: Option<fn(&[&str]) -> serde_json::Value>,

    /// THE ROUTER detection predicate — how (and how tightly) this protocol claims an inbound
    pub claims: Option<ClaimsFn>,

    /// THE RESIDUAL detection predicate — how (and how tightly) this protocol claims a path from its
    pub residual_claims: Option<ResidualClaimsFn>,

    /// TRUE for the ONE protocol core falls back to when NO dialect claims a request yet a dialect
    pub residual_default: bool,

    /// THE RESPONSE-side vendor-metadata reporter — the fields this protocol's upstream returns that
    pub vendor_response_metadata: Option<VendorResponseMetadataFn>,

    /// THE WIRE-FINGERPRINT HEADERS this dialect declares as SAFE disambiguators of the SHARED
    pub list_models_fingerprint_headers: &'static [&'static str],

    /// THE STATIC EGRESS HEADERS this protocol's upstream request always carries beside its declared
    pub static_headers: &'static [(&'static str, &'static str)],
}

impl ProtocolDecl {
    /// This dialect's router claim on `(path, fields)`: [`ProtocolDecl::claims`] over a request's

    #[must_use]
    pub fn claim_over(&self, path: &str, fields: HeadFields<'_>) -> Option<ClaimStrength> {
        (self.claims?)(fields, path)
    }

    /// A NAME-ONLY DECLARATION: this key, and the neutral zero for every other field.
    ///
    /// The declaration has forty-odd fields and almost every one of them is "no". A caller that
    /// needs a decl in order to exercise a fold over `name`/`has_model_in_url` had to write all
    /// forty out, and two copies of that literal already existed — one here, one on the crate that
    /// holds the fold. Two copies of a struct literal is two places a NEW field has to be added,
    /// and the second one is the one that gets missed.
    ///
    /// So the neutral row is written ONCE, beside the struct whose fields it names, and a caller
    /// states only what is true of its own case:
    ///
    /// ```ignore
    /// static URL_MODEL: ProtocolDecl = ProtocolDecl { has_model_in_url: true, ..ProtocolDecl::named("telex") };
    /// ```
    ///
    /// `const`, so it composes into a `static` without a lock or a lazy cell.
    pub const fn named(name: &'static str) -> Self {
        Self {
            name,
            codec: None,
            handler: None,
            verbs: &[],
            head_keys: &[],
            streaming_content_type: None,
            array_stream_shim_key: None,
            native_tool_id_prefix: None,
            ingress_auth: IngressAuth::Bearer,
            egress_auth_headers: None,
            egress_auth_lane_constant: false,
            egress_scheme: None,
            stream_usage_requires_opt_in: false,
            requires_max_tokens: false,
            stop_sequence_cap: None,
            cache_markers_model_gated: false,
            fills_thought_signature: false,
            frame_after_message_start: None,
            reshapes_body_at_path_base: false,
            max_cache_control_breakpoints: None,
            quota_exceeded_status: 429,
            ingress_is_eventstream: false,
            emits_sse_done_terminator: false,
            max_citations_per_delta: None,
            egress_user_agent: EGRESS_UA_DEFAULT,
            has_model_in_url: false,
            auth_failure_status_and_kind: (401, ERR_TYPE_AUTHENTICATION),
            ingress_relays_amzn_headers: false,
            ingress_relayed_response_header_names: &[],
            auth_failure_message: "authentication failed",
            uses_array_stream_shim: false,
            has_native_path_not_found: false,
            egress_stream_accept: TEXT_EVENT_STREAM,
            models_list_envelope: None,
            claims: None,
            residual_claims: None,
            residual_default: false,
            vendor_response_metadata: None,
            list_models_fingerprint_headers: &[],
            static_headers: &[],
        }
    }

    /// True when this protocol authenticates INBOUND requests with SigV4 rather than a bearer

    pub fn uses_sigv4_ingress_auth(&self) -> bool {
        matches!(self.ingress_auth, IngressAuth::SigV4)
    }

    /// This protocol's neutral computed-codec facade ([`DialectCodec`]) — the 4th seam the

    pub fn dialect(&self) -> Option<&'static dyn DialectCodec> {
        self.codec
    }
}

#[cfg(test)]
#[path = "tests/sse_frames_tests.rs"]
mod sse_frames_tests;
