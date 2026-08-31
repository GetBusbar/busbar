use super::*;

/// extract the host (no scheme, no trailing slash, no userinfo) from a base URL, for SigV4's signed
/// `host` header. base_urls are already trailing-slash-trimmed and carry no path.
///
/// A `base_url` carrying an embedded `user:pass@` userinfo component (accidental misconfiguration)
/// must NOT leak into the signed `host` value: the HTTP stack sends `Host: host.example.com` while
/// SigV4 would otherwise sign `host: user:pass@host.example.com`, producing a signature mismatch
/// (every Bedrock request fails) AND embedding the credential in the signed string (which may surface
/// in request logs/traces). Strip any userinfo (everything up to and including the last `@` in the
/// authority) so the signed host always matches what the HTTP layer transmits.
///
/// Returns the AUTHORITY ONLY (`host[:port]`) — never any path/query/fragment. The HTTP stack always
/// transmits `Host: <authority>` regardless of any path in `base_url`, so a `host` value that
/// included a path (e.g. a misconfigured `https://bedrock.../prefix`) would be signed but never sent,
/// yielding a silent `SignatureDoesNotMatch` on every request. Stripping the path here makes the
/// signed `host` equal to the transmitted `Host` byte-for-byte even if config validation is bypassed.
pub(crate) fn host_from_base(base: &str) -> String {
    let no_scheme = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    // Normalize backslash → forward slash BEFORE locating the authority boundary. The WHATWG URL
    // parser the `url` crate (and thus reqwest) uses treats `\` as an authority/path delimiter
    // exactly like `/`, so reqwest connects to the host that ENDS at the first backslash. Splitting
    // here only on `/?#` (a backslash-blind split, the SAME defect `ssrf_blocked_host` had) would
    // make this function read PAST the backslash: e.g. `https://evil.example.com\@victim.example/`
    // connects to `evil.example.com` on the wire, but a `/?#`-only split yields authority
    // `evil.example.com\@victim.example` whose `rfind('@')` returns `victim.example` — a signed
    // `Host` that DESYNCS from the host actually contacted (SigV4 signs one host, the TCP/TLS layer
    // dials another). Folding `\`→`/` first makes the authority boundary — and the returned signed
    // host — match what reqwest dials, byte-for-byte.
    // Only ALLOCATE the backslash-normalized copy when a backslash is actually present (rare
    // misconfiguration / attack shape). A well-formed base_url has none, so the common request path
    // borrows the input and skips this per-request heap allocation.
    let no_scheme: std::borrow::Cow<str> = if no_scheme.contains('\\') {
        std::borrow::Cow::Owned(no_scheme.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(no_scheme)
    };
    let no_scheme = no_scheme.as_ref();
    // The authority ends at the first `/`, `?`, or `#`; userinfo (if any) precedes the LAST `@`
    // within that authority. Split on the authority boundary first so an `@` appearing later in a
    // path/query (not userinfo) is never mistaken for a userinfo delimiter. Only the authority is
    // returned — the path/query/fragment (`rest`) is intentionally discarded (see doc above).
    let authority_end = no_scheme.find(['/', '?', '#']).unwrap_or(no_scheme.len());
    let authority = &no_scheme[..authority_end];
    match authority.rfind('@') {
        Some(at) => authority[at + 1..].to_string(),
        None => authority.to_string(),
    }
}

/// Produce the path that is BOTH signed (as the SigV4 canonical URI) and sent on the wire, so the
/// two can never diverge. Only the path component (before any `?`) is URI-encoded — reserved chars
/// in a Bedrock modelId such as `:` become `%3A`; the query string (if any) is preserved verbatim
/// (encoding `?`/`=`/`&` would corrupt it). The percent-encoded `%XX` sequences pass through the
/// `url` crate's path parser unchanged, so the transmitted request path equals the signed canonical
/// path byte-for-byte and AWS cannot reject with SignatureDoesNotMatch over a path-encoding mismatch.
pub(crate) fn sign_and_wire_path(url_path: &str) -> String {
    sign_and_wire_path_parts(url_path).0
}

/// Like [`sign_and_wire_path`] but ALSO returns the SigV4 `canonical_uri` (the encoded path with the
/// query stripped) so callers that need both don't re-split the wire path and allocate a SECOND
/// `String` for the canonical URI. On the common no-query path the encoded path IS the canonical URI,
/// so it is reused for both fields and only the wire path is (cheaply) cloned; with a query the wire
/// path is `canonical?query`. Output is byte-identical to the previous split-and-`to_string` form.
/// True when every byte of `path` is SigV4-unreserved (`A-Z a-z 0-9 - _ . ~ /`), i.e.
/// `uri_encode_path` would return it byte-for-byte unchanged. The openai/anthropic/cohere/responses
/// lanes (all `/v1/...` style paths, no reserved chars) hit this; only a Bedrock modelId (carrying a
/// `:` and other reserved chars) fails it. Lets the encode fast path skip the redundant second
/// double-encode scan+allocation without changing any signed byte.
#[inline]
fn path_is_sigv4_unreserved(path: &str) -> bool {
    path.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/')
    })
}

/// One boot-precomputed egress target: the ABSOLUTE wire URL and the SigV4 canonical URI for one
/// `(operation, stream)` on one lane. Both are pure functions of lane-constant config (`base_url`,
/// `path`/`path_base` overrides, `wire_model`, the protocol's path template), so the forward path
/// reads them from the lane instead of composing the path, encoding it, and WHATWG-parsing the URL
/// on every request. The URL is parsed from the FULL composed string exactly once at boot — never
/// via `Url::join`/`set_path`, whose re-encoding can drift from the signed bytes (a Bedrock
/// modelId's `%3A` must survive verbatim; see `sign_and_wire_path_parts`).
#[derive(Clone)]
pub(crate) struct EgressTarget {
    /// The absolute URL as the WHATWG-parsed `url::Url` — TEST-ONLY since the stage-B hyper
    /// cutover: it anchors the byte-differential proof (`egress_target_tests` pins `uri` == `url`
    /// == the reference composition), keeping the old parser in the tree AS the reference the
    /// precomputed `uri` can never silently drift from.
    ///
    /// `#[cfg(test)]`, not resident in a release build: the WHATWG parse still RUNS at boot in
    /// every build (same fail-loud validation, same refusal text — see `build_egress_targets`),
    /// but the parsed value is dropped rather than stored per `(operation, stream)` entry per
    /// lane — a reference only tests read has no business occupying idle RSS.
    #[cfg(test)]
    pub(crate) url: url::Url,
    /// The SAME absolute URL as a pre-parsed `http::Uri` (wave-7 stage A): the hyper-owned egress
    /// client sends this directly, so the per-request WHATWG re-parse reqwest performed at send
    /// time is gone. Clone is refcounted `Bytes` parts — no parse, no copy of the string.
    pub(crate) uri: axum::http::Uri,
    pub(crate) canonical_uri: String,
}

/// Build a lane's egress-target table at boot: every operation the closed vocabulary can dispatch
/// (`Operation::ALL` ∪ the LLM family's seven ∪ the registered declarations' verbs) × stream intent.
/// The composition is byte-identical to the per-request form this replaces: `lane.path` override
/// verbatim, else the protocol `RequestHandler` renders from the same resolved primitives, then the
/// same `sign_and_wire_path_parts` split. A protocol with no registered handler yields an EMPTY
/// table — the request-path lookup miss then takes exactly the old `upstream_path` `None` arm (500,
/// probe released). A URL that does not parse is a boot error (fail loud at apply, not per request).
pub(crate) fn build_egress_targets(
    protocol: &'static str,
    path_override: Option<&str>,
    path_base: Option<&str>,
    wire_model: &str,
    base_url: &str,
) -> Result<std::collections::HashMap<(crate::operation::Operation, bool), EgressTarget>, String> {
    use crate::operation::Operation;
    let mut out = std::collections::HashMap::new();
    let Some(rh) = crate::handlers::request_handler(protocol) else {
        return Ok(out);
    };
    // The seven cross-dialect chat/completion-family operations, kept as a local seed set (a neutral
    // `Operation` list, naming no plane) so the boot table pre-computes an egress target for each even
    // before a protocol's own `ProtocolDecl::verbs` are folded in below. Deduped against
    // `Operation::ALL` and the registered declarations' verbs, so a protocol that declares any of them
    // takes exactly one entry.
    let family_ops: [Operation; 7] = [
        Operation::CHAT,
        Operation::EMBEDDINGS,
        Operation::MODERATION,
        Operation::IMAGE,
        Operation::TRANSCRIPTION,
        Operation::SPEECH,
        Operation::RERANK,
    ];
    let ops = family_ops
        .iter()
        .chain(Operation::ALL.iter())
        .chain(crate::proto::registry::declared_verbs().iter());
    for &op in ops {
        for stream in [false, true] {
            if out.contains_key(&(op, stream)) {
                continue;
            }
            let path = match path_override {
                Some(p) => p.to_string(),
                None => rh.upstream_path(&crate::handlers::EgressCtx {
                    operation: op,
                    model: wire_model,
                    stream,
                    path_base,
                }),
            };
            let (wire_path, canonical_uri) = sign_and_wire_path_parts(&path);
            let composed = format!("{base_url}{wire_path}");
            // The WHATWG parse runs in EVERY build — same boot-time fail-loud validation, same
            // refusal text — but the parsed `Url` is stored only under `cfg(test)`, where it is
            // the byte-differential reference (`egress_target_tests`); see `EgressTarget::url`.
            let url = url::Url::parse(&composed).map_err(|e| {
                format!("egress URL '{composed}' (protocol '{protocol}') does not parse: {e}")
            })?;
            #[cfg(not(test))]
            drop(url);
            let uri: axum::http::Uri = composed.parse().map_err(|e| {
                format!("egress URI '{composed}' (protocol '{protocol}') does not parse: {e}")
            })?;
            out.insert(
                (op, stream),
                EgressTarget {
                    #[cfg(test)]
                    url,
                    uri,
                    canonical_uri,
                },
            );
        }
    }
    Ok(out)
}

pub(crate) fn sign_and_wire_path_parts(url_path: &str) -> (String, String) {
    // The wire path is single-URI-encoded (what actually goes on the request line). The SigV4
    // CANONICAL path is DOUBLE-URI-encoded for every service except S3 (Bedrock included): AWS
    // re-encodes the already-encoded path it receives before recomputing the signature, so the
    // signature must be taken over the double-encoded form. Using the single-encoded path for BOTH
    // (as before) makes any path with an encodable char — every Bedrock model id has a `:` — fail
    // with SignatureDoesNotMatch (403). The signature-blind mock cannot catch this; only a real
    // upstream does, so it was invisible to the harness. For paths with no encodable chars
    // (openai/anthropic `/v1/...`) `uri_encode_path` is a no-op and canonical == wire, unchanged.
    let (path, query) = match url_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url_path, None),
    };
    // Fast path (openai/anthropic/cohere/responses — every non-Bedrock lane, i.e. the throughput
    // hot path): the path holds only SigV4-unreserved bytes, so both `uri_encode_path` passes are
    // identity no-ops (`encoded == path`) and the double-encode `canonical == wire_path == path`.
    // Skip BOTH encode allocations and the second pass; allocate the owned `wire`/`canonical` the
    // callers require exactly once each straight from the borrowed path. Byte-identical output to
    // the always-encode form — `uri_encode_path` provably returns its input unchanged here. Only a
    // path carrying an encodable char (a Bedrock modelId's `:`) takes the full double-encode below.
    if path_is_sigv4_unreserved(path) {
        let wire = match query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        };
        return (wire, path.to_string());
    }
    let wire_path = crate::sigv4::uri_encode_path(path);
    let canonical = crate::sigv4::uri_encode_path(&wire_path); // double-encode (non-S3 SigV4 rule)
    let wire = match query {
        Some(q) => format!("{wire_path}?{q}"),
        None => wire_path,
    };
    (wire, canonical)
}

/// Build outbound auth headers for a lane. Defaults to the protocol's native auth via
/// `sign_request` (bearer for openai/anthropic/responses, `x-goog-api-key` for gemini, per-request
/// SigV4 for bedrock). When the provider declares `auth: api-key` (Azure OpenAI), send an
/// `api-key: <key>` header instead — the deployment and `?api-version=` live in the provider's
/// `path` override, so no new protocol is needed. An un-encodable key yields no auth header (the
/// upstream then rejects with 401, classified by the breaker like any other auth failure).
pub(crate) fn lane_auth_headers(
    lane: &crate::state::Lane,
    key: &str,
    ctx: &crate::proto::SigningContext,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    lane.credential.headers_for(key, ctx)
}

// ─── EGRESS User-Agent strings — RELEASE-CHECKLIST AUDIT SURFACE ──────────────────────────────────
//
// These mirror the `User-Agent` a real first-party SDK emits for each provider's API. They embed
// PINNED SDK VERSION NUMBERS that drift from upstream as those SDKs publish new releases (the OpenAI
// Python SDK alone ships several times per quarter). A backend that logs/filters by UA version can
// eventually observe a frozen, implausible version and separate busbar traffic from native traffic —
// a silent decay of the backend-facing indistinguishability guarantee.
//
// CONTAINMENT (no config/CI feature added here, per the 1.0 hardening scope): every pinned string is
// hoisted into a single named-constant block so the drift hazard lives on ONE auditable surface
// instead of being scattered as inline literals across `egress_user_agent`, and `egress_ua_versions_*`
// tests pin each protocol's UA to its constant so any silent edit/drift trips a test that forces a
// CONSCIOUS update. **RELEASE OBLIGATION:** before each busbar release, re-verify every version below
// against the latest published SDK release (PyPI / Crates.io / etc.) and bump as needed; the test
// guard ensures this block can never change unnoticed.
//
// The per-dialect native-SDK `User-Agent` strings RELOCATED to the LLM plugin: each is stated inline
// on its own `busbar_llm::<dialect>::DECL.egress_user_agent` (a dialect's backend fingerprint is the
// dialect's own vocabulary and must not live in this neutral crate), with the release-time re-verify
// obligation carried in the doc on each decl field. Core reads whichever value the registered decl
// declares through `egress_user_agent(name)` below and names none of them.
// Unknown/foreign egress protocol default UA — the neutral substrate default
// (`busbar_substrate::proxy::EGRESS_UA_DEFAULT`) so a codec-less protocol declaration in a plane
// (`busbar_substrate::proxy::EGRESS_UA_DEFAULT`) so a codec-less protocol declaration in a plane
// crate (`busbar-mcp`) states it as its `ProtocolDecl::egress_user_agent` default without reaching
// into core. Re-exported through `crate::proxy` (see `proxy/mod.rs`) so every `EGRESS_UA_DEFAULT`
// call site here resolves unchanged.

/// Plausible native-SDK `User-Agent` for the chosen EGRESS protocol. reqwest sends NO default
/// User-Agent unless one is set, so without this every proxied upstream request reaches the backend
/// with no UA at all — a trivial backend-side fingerprint distinguishing busbar-proxied traffic from
/// a native vendor SDK (which always sends a recognizable UA). (Backend-facing only; does not affect
/// client indistinguishability.) The version numbers are PINNED and drift over time — see the
/// `EGRESS_UA_*` constant block above for the release-time audit obligation that keeps them current.
///
/// Thin wrapper: dispatches through `ProtocolWriter::egress_user_agent` so the name-match lives in
/// the per-protocol writer, not in this agnostic function. Call sites that already hold a resolved
/// writer (`writer.egress_user_agent()`) bypass this wrapper; it exists for test-code paths that
/// look up by name.
pub(crate) fn egress_user_agent(egress_protocol: &str) -> &'static str {
    crate::proto::decl_for(egress_protocol)
        .map(|d| d.egress_user_agent)
        .unwrap_or(crate::proxy::EGRESS_UA_DEFAULT)
}

/// The `Accept` header a native SDK for `egress_protocol` sends, given the caller's stream intent.
/// `accept` is NOT part of SigV4 SignedHeaders, so adding it never affects a Bedrock signature — but
/// a native SDK ALWAYS sends one, so omitting it is a deterministic backend-side proxy fingerprint
/// (a busbar-proxied request carries none where a native one does). Set to what the real SDK emits so
/// the backend cannot separate busbar traffic from native traffic on this header.
///
/// Thin wrapper: reads the per-protocol logic (Bedrock → eventstream/json; all others →
/// text/event-stream/json) off the protocol DECLARATION (`ProtocolDecl::egress_stream_accept`) rather
/// than allocating a codec to ask a `&'static` constant. The non-streaming value is universally
/// `application/json`. The by-name lookup path (probes, forward-header assembly).
pub(crate) fn egress_accept(egress_protocol: &str, wants_stream: bool) -> &'static str {
    if wants_stream {
        crate::proto::decl_for(egress_protocol)
            .map(|d| d.egress_stream_accept)
            .unwrap_or(TEXT_EVENT_STREAM)
    } else {
        APPLICATION_JSON
    }
}
