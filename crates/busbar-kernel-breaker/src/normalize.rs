// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVED PATH'S UPSTREAM-ERROR NORMALIZER (#83a O1: the error-map rule and the `Retry-After`
//! reading are breaker semantics): Stage 1b of the disposition pipeline, turning a dialect's
//! [`RawUpstreamError`] into the [`CanonicalSignal`] the breaker acts on, and the `Retry-After`
//! header read that bounds a cooldown. Moved verbatim from the retired shared value crate; the one
//! adaptation is that the unrecognized-`error_map` report is the caller's (`unrecognized`), since
//! this unit takes no logging dependency.
//!
//! [`crate::classify`] is this unit's own classifier over its own raw-error record; the two read a
//! status-less error (0) and the obsolete HTTP-date forms differently, so they are not merged here.

use busbar_contract::http;
use busbar_contract::upstream::{CanonicalSignal, RawUpstreamError, StatusClass};

/// The non-standard 529 overload status a provider sends as its server-overloaded signal (distinct
/// from 503); not in the IANA registry.
const HTTP_OVERLOADED: u16 = 529;

/// Parse a `Retry-After` header value. RFC 9110 §10.2.3 defines the field as
/// `delay-seconds / HTTP-date`; BOTH forms are normative and providers send both. Parsing only the
/// integer form silently discards the provider's stated cooldown floor on every date-form response,
/// leaving the breaker to guess.
///
/// `now` is a PARAMETER: a unit reads no clock, so the caller that read the response hands in the
/// instant it read it at (the kernel's `breaker::parse_retry_after` passes the wall clock).
pub fn parse_retry_after(headers: &http::HeaderMap, now: std::time::SystemTime) -> Option<u64> {
    let s = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    // A date already in the past means "retry now", not "retry in a very long time" — hence
    // saturating_duration_since, which floors at zero.
    let at = httpdate::parse_http_date(s).ok()?;
    Some(at.duration_since(now).unwrap_or_default().as_secs())
}

/// Classify a raw upstream error into a canonical signal using an error_map.
/// Stage 1b (provider normalizer): data-driven mapping from raw errors to StatusClass. An operator
/// `error_map` value that names no status class is IGNORED (classification falls through to the
/// HTTP status) and handed to `unrecognized`, the caller's report of the misconfiguration.
pub fn normalize_raw_error(
    raw: &RawUpstreamError,
    error_map: &std::collections::HashMap<String, String>,
    unrecognized: &dyn Fn(&str),
) -> CanonicalSignal {
    // Step 1: a provider error code mapped in error_map refines (overrides) the HTTP-status default.
    let provider_signal = if let Some(ref code) = raw.provider_code {
        if let Some(mapped_class) = error_map.get(code) {
            if let Some(class) = StatusClass::parse(mapped_class) {
                // CLASS guard: context_length must NEVER mask a 5xx upstream
                // outage. An operator error_map mapping a code to `context_length` on a 5xx
                // status would otherwise reclassify a transient outage as no-penalty
                // ContextLength and skip the breaker penalty. Suppress the early return in
                // that one case and fall through to HTTP-status classification so the lane is
                // penalized; every other mapped class returns as before.
                if !(class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)) {
                    return CanonicalSignal {
                        class,
                        provider_signal: Some(code.clone()),
                        retry_after: raw.retry_after_secs,
                    };
                }
            } else {
                // The operator mapped this code to a string that is not a recognized status class
                // (typo such as `rate_limt`). It is silently ignored below; warn so the misconfig
                // is visible instead of a mapping that never takes effect.
                unrecognized(mapped_class);
            }
        }
        // built-in recognition of the canonical context-length code (the operator
        // error_map above overrides — it is checked first and returns early; this is the default
        // when unmapped). The lane is healthy — ContextLength → fail over without penalty.
        //
        // Gated on the PRECISE request-size statuses (400 Bad Request / 413 Payload Too Large): a
        // 5xx is an upstream server failure, never a context-length error — and so is a
        // 200/3xx/auth status that happens to carry a `context_length_exceeded`-ish code — so
        // every other status falls through to the HTTP-status classification below, where the
        // operator error_map can still countermand via the structured-type signal (Step 1b).
        // TIGHTEN (breaker-layer half): the built-in context_length code only ever
        // applies to oversized-request statuses (400 Bad Request / 413 Payload Too Large).
        // The previous `!(500..600)` guard let any non-5xx (e.g. a 200/3xx/auth) carrying a
        // `context_length_exceeded` code masquerade as ContextLength; restrict to the precise
        // request-size set so it can never mask a non-request-size status.
        if code == busbar_contract::protocol::PROVIDER_CODE_CONTEXT_LENGTH
            && (raw.http_status == 400 || raw.http_status == 413)
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(code.clone()),
                retry_after: raw.retry_after_secs,
            };
        }
        // Code not in map or invalid mapping — fall through to HTTP classification
        Some(code.clone())
    } else {
        None
    };

    // Step 1b: the provider's structured error *type* is a second data-driven signal — an operator
    // can map it in error_map just like a code (useful when a provider has no numeric code but a
    // typed `error.type`). The explicit code (above) wins; this refines when the code didn't match.
    if let Some(ref ty) = raw.structured_type {
        // Resolve the mapped class, warning (once) if the operator mapped this type to an
        // unrecognized status-class string — otherwise it is silently ignored and falls through.
        let mapped = error_map.get(ty).and_then(|m| {
            let class = StatusClass::parse(m);
            if class.is_none() {
                unrecognized(m);
            }
            class
        });
        if let Some(class) = mapped {
            // Same CLASS guard as the code path above: a structured-type signal mapped to
            // `context_length` on a 5xx must not mask the upstream outage — fall through to
            // HTTP-status classification so the lane is penalized.
            if !(class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)) {
                return CanonicalSignal {
                    class,
                    provider_signal: provider_signal.or_else(|| Some(ty.clone())),
                    retry_after: raw.retry_after_secs,
                };
            }
        }
    }

    // Step 2: Classify by HTTP status (universal spec; exhaustive match)
    let http_status = raw.http_status;
    let class = if http_status == 401 || http_status == 403 {
        StatusClass::Auth
    } else if http_status == 429 {
        StatusClass::RateLimit
    } else if http_status == 408 {
        StatusClass::Timeout
    } else if http_status == HTTP_OVERLOADED {
        StatusClass::Overloaded
    } else if (500..600).contains(&http_status) {
        StatusClass::ServerError
    } else if (400..500).contains(&http_status) {
        // True 4xx (other than the 401/403/408/429 handled above) — caller's fault.
        StatusClass::ClientError
    } else {
        // Unexpected non-error status (2xx/3xx) reaching the error path — e.g. a misconfigured
        // base_url issuing redirects the client didn't follow. The LANE is not at fault, so we do
        // NOT penalize the breaker; classifying as ClientError → ClientFault relays it verbatim and
        // records nothing. (A 3xx is genuinely not a client error, but ClientFault is the closest
        // "record nothing, relay as-is" disposition; revisit if a benign/Unknown class is added.)
        StatusClass::ClientError
    };

    CanonicalSignal {
        class,
        provider_signal,
        retry_after: raw.retry_after_secs,
    }
}
