// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic egress credentials: which native scheme a key maps to and the headers it is sent as.

use super::*;

/// Which native credential scheme a credential maps to. Anthropic accepts exactly one scheme per
/// request, and a native client presents exactly one: an API-key client sends `x-api-key` and no
/// `authorization`; an OAuth client sends `authorization: Bearer` and no `x-api-key`. Emitting
/// both (the same secret duplicated across two schemes) is a request shape no native client
/// produces — a structural upstream-distinguishability tell — so we classify and emit one.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum AnthropicCredScheme {
    /// Canonical Anthropic API key (`sk-ant-api...`): `x-api-key` only.
    ApiKey,
    /// OAuth access token (`sk-ant-oat...`): `authorization: Bearer` only.
    OAuth,
    /// Shape not recognizable as either Anthropic credential family. busbar cannot tell from the
    /// credential alone whether this is a static API key or a passthrough Bearer token (the mode
    /// is known to proxy engine but not plumbed into this trait method), so it conservatively emits
    /// BOTH headers — preserving the passthrough Bearer round-trip for an opaque caller token
    /// while still presenting `x-api-key` for a non-canonical static key. Real Anthropic
    /// credentials always match `ApiKey`/`OAuth`, so the dual-header fallback never fires for
    /// genuine API-key or OAuth traffic — the path distinguishability is measured on.
    Ambiguous,
}

impl AnthropicWriter {
    /// Classify `key` into its native credential scheme by prefix. Matches on the trimmed key so
    /// surrounding whitespace (a likely config artifact) doesn't misclassify a credential.
    pub(super) fn classify_credential(key: &str) -> AnthropicCredScheme {
        let k = key.trim_start();
        if k.starts_with(CRED_PREFIX_API_KEY) {
            AnthropicCredScheme::ApiKey
        } else if k.starts_with(CRED_PREFIX_OAUTH) {
            AnthropicCredScheme::OAuth
        } else {
            AnthropicCredScheme::Ambiguous
        }
    }

    /// Build the native Anthropic error envelope for a resolved `error.type`.
    ///
    /// Current Anthropic API error bodies carry a top-level `request_id` (`req_...`) alongside the
    /// `error` object. busbar synthesizes this envelope itself (no upstream request to forward), so
    /// we mint one to match the native shape — the SDK doesn't require it to decode the typed
    /// exception, but its absence is a distinguishability tell. Shared by every `write_error` exit
    /// so the status-driven and kind-driven paths emit byte-identical envelopes.
    pub(super) fn error_envelope(error_type: &str, message: &str) -> serde_json::Value {
        Self::error_envelope_with_request_id(error_type, message, &synth_request_id())
    }

    /// The same envelope, with the top-level `request_id` supplied rather than minted.
    ///
    /// This is the form a caller that may not read a random source uses: it builds the id from
    /// entropy it was handed (see [`request_id_from_entropy`]) and passes it in. Both forms produce
    /// the identical document — the only difference is where the id's bytes came from.
    pub fn error_envelope_with_request_id(
        error_type: &str,
        message: &str,
        request_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "type": "error",
            "error": {
                "type": error_type,
                "message": message,
            },
            "request_id": request_id,
        })
    }
}

/// Build Anthropic auth headers for `key`, resolving the credential scheme to native headers.
///
/// Anthropic accepts exactly ONE credential scheme per request, and a native client presents exactly
/// one: an API-key client sends `x-api-key` and NO `authorization`; an OAuth client sends
/// `authorization: Bearer <token>` and NO `x-api-key`. Emitting both (the same secret duplicated
/// across two schemes) is a request shape no native client produces — a structural upstream-
/// distinguishability tell — and, if upstream ever cross-validates the two headers, a latent 401
/// source. So we classify the credential and emit a single scheme.
///
/// The credential family disambiguates the real cases: a static lane key (the configured
/// `sk-ant-api…`) → `x-api-key`; a passthrough OAuth access token (`sk-ant-oat…`) →
/// `authorization: Bearer`. A credential matching NEITHER family is `Ambiguous` — busbar cannot tell
/// from the credential bytes alone whether it is a static key or a forwarded Bearer token. `mode`
/// carries the front-door auth mode from the wire path (`SigningContext.auth_mode`) to break that
/// tie WITHOUT a dual-header tell:
///   * `Some(Passthrough)` → the caller's token, forwarded as `authorization: Bearer` only;
///   * `Some(Token | None)` → a configured lane key, presented as `x-api-key` only;
///   * `None` → the mode-blind primitive (`auth_headers`, no signing ctx): fall back to BOTH headers
///     so neither path silently drops. Real Anthropic credentials always match ApiKey/OAuth, so the
///     dual-header fallback never fires for genuine traffic; the wire path always passes `Some(_)`.
///
/// The `anthropic-version` header is common to all.
///
/// A key with bytes invalid in an HTTP header value (e.g. a stray newline) is OMITTED rather than
/// emitted with an empty value (one diagnostic warning naming the protocol, key bytes never logged)
/// — matching the warn+OMIT policy of the Bearer writers (`proto::bearer_auth_headers`) and the
/// Gemini/Cohere/Responses writers. An empty `x-api-key: ` is both a syntactically invalid header the
/// upstream 401s on AND a fingerprinting tell against well-formed tokens, so we drop just that
/// credential header and keep `anthropic-version`. The worker never panics; the upstream returns a
/// clean 401 the breaker classifies normally. Defense-in-depth; keys should be validated at config
/// load.
pub fn anthropic_auth_headers(
    key: &str,
    creds: Option<busbar_contract::config::UpstreamCreds>,
) -> Vec<(HeaderName, HeaderValue)> {
    // Build a credential header pair, OMITTING it (returning None) when the value carries bytes
    // invalid for an HTTP header value. Never logs the key bytes — only the header name and the fact
    // that they were malformed.
    let safe = |name: &'static str, raw: String| -> Option<(HeaderName, HeaderValue)> {
        match HeaderValue::from_str(&raw) {
            Ok(v) => Some((HeaderName::from_static(name), v)),
            Err(_) => {
                tracing::warn!(
                    protocol = "anthropic",
                    header = name,
                    "auth credential contains bytes invalid for an HTTP header value (e.g. a \
                     trailing newline); omitting the credential header — upstream will return 401, \
                     check the key configuration"
                );
                None
            }
        }
    };
    let x_api_key = || safe(HDR_X_API_KEY, key.to_string());
    // ApiKey-scheme variant of `x-api-key` that strips LEADING whitespace from the configured key.
    // `classify_credential` matches on `key.trim_start()`, so `"  sk-ant-api…"`
    // classifies as `ApiKey` — but the raw `x_api_key` closure above forwards the key VERBATIM,
    // emitting `x-api-key: "  sk-ant-api…"` (a header value with a leading-space artifact the
    // upstream rejects with a 401). Trim the leading whitespace so the emitted header matches the
    // value that was classified. Scope is deliberately narrow: ONLY the canonical configured-key
    // (`ApiKey`) scheme is trimmed here. The OAuth (`authorization: Bearer`) and the Ambiguous
    // passthrough/static fallbacks keep the raw closures below, preserving their byte-for-byte
    // round-trip contract — a forwarded caller token must reach the upstream exactly as presented.
    let x_api_key_trimmed = || safe(HDR_X_API_KEY, key.trim_start().to_string());
    let authorization = || safe(crate::dialect::HDR_AUTHORIZATION, format!("Bearer {key}"));
    let version = (
        HeaderName::from_static(HDR_ANTHROPIC_VERSION),
        HeaderValue::from_static(ANTHROPIC_API_VERSION),
    );
    // Assemble the credential header(s) (each an `Option`, omitted on bad bytes) followed by the
    // always-present `anthropic-version`.
    let assemble =
        |creds: Vec<Option<(HeaderName, HeaderValue)>>| -> Vec<(HeaderName, HeaderValue)> {
            let mut out: Vec<(HeaderName, HeaderValue)> = creds.into_iter().flatten().collect();
            out.push(version.clone());
            out
        };
    match AnthropicWriter::classify_credential(key) {
        // Configured Anthropic API key: native API-key client shape — `x-api-key` only. Use the
        // leading-whitespace-trimmed builder so a configured key with a stray leading space (the
        // value `classify_credential` already matched on its trimmed form) is forwarded clean.
        AnthropicCredScheme::ApiKey => assemble(vec![x_api_key_trimmed()]),
        // OAuth access token / passthrough Bearer token: native OAuth client shape —
        // `authorization: Bearer` only.
        AnthropicCredScheme::OAuth => assemble(vec![authorization()]),
        // Unrecognized shape: the mode resolves it to a single native header on the wire path;
        // the mode-blind primitive falls back to both so neither path silently drops.
        AnthropicCredScheme::Ambiguous => match creds {
            Some(busbar_contract::config::UpstreamCreds::Passthrough) => {
                assemble(vec![authorization()])
            }
            Some(busbar_contract::config::UpstreamCreds::Own) => assemble(vec![x_api_key()]),
            None => assemble(vec![x_api_key(), authorization()]),
        },
    }
}
