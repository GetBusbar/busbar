// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protocol-agnostic classifier for breaker dispositions.
//!
//! Stage 2 of the two-stage disposition pipeline:
//! - Stage 1 (src/proto/): per-protocol normalizer → CanonicalSignal with typed StatusClass
//! - Stage 2 (this module): protocol-agnostic classifier → Disposition
//!
//! Mapping (+ ADR-0002):
//!   RateLimit|Overloaded|ServerError|Timeout|Network → TransientUpstream
//!   Auth|Billing → HardDown
//!   ClientError → ClientFault

/// Anthropic non-standard 529 overload status — not in the IANA registry but
/// documented by Anthropic as their server-overloaded signal (distinct from 503).
const HTTP_OVERLOADED: u16 = 529;

/// Protocol-neutral, dialect-normalized status class.
/// Emitted by Stage 1 normalizer (the per-protocol classifier) in src/proto/.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// Rate limit / slow down — transient, may recover with retry-after
    RateLimit,
    /// Overloaded server — transient
    Overloaded,
    /// Server error (5xx) — transient
    ServerError,
    /// Request timeout — transient
    Timeout,
    /// Network failure — transient
    Network,
    /// Authentication failure (401/403) — hard down, key invalid
    Auth,
    /// Billing / insufficient balance — hard down, account issue
    Billing,
    /// Client error (4xx other than 401/403) — client fault, do not penalize lane
    ClientError,
    /// Request exceeds this model's context window — the LANE is healthy; fail over (ideally to
    /// a larger-context model) WITHOUT penalizing the breaker.
    ContextLength,
}

/// Final disposition that drives the LaneRuntime write path.
/// Per ADR-0002 +:
///   - ClientFault: caller's bad input → relay verbatim, record NOTHING
///   - TransientUpstream: transient failure → cooldown + err counter
///   - HardDown: definitive signal → permanent dead state (with probe recovery)
///   - ContextLength: request too big for this model → fail over, record NOTHING (lane healthy)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    ClientFault,
    TransientUpstream,
    HardDown,
    ContextLength,
}

/// Convert a string to StatusClass. Returns None for unknown values.
pub fn status_class_from_str(s: &str) -> Option<StatusClass> {
    match s {
        "rate_limit" => Some(StatusClass::RateLimit),
        "overloaded" => Some(StatusClass::Overloaded),
        "server_error" => Some(StatusClass::ServerError),
        "timeout" => Some(StatusClass::Timeout),
        "network" => Some(StatusClass::Network),
        "auth" => Some(StatusClass::Auth),
        "billing" => Some(StatusClass::Billing),
        "client_error" => Some(StatusClass::ClientError),
        "context_length" => Some(StatusClass::ContextLength),
        _ => None,
    }
}

/// Warn (once per distinct value) that an operator `error_map` entry maps to a string that is not a
/// recognized StatusClass. Such a value is silently ignored by `normalize_raw_error` — the error
/// then falls through to HTTP-status classification — so without this signal a typo'd mapping (e.g.
/// `rate_limt`) would never take effect and the operator would have no indication why. Deduped via a
/// process-wide set so a misconfiguration on a hot error path logs once, not per request.
fn warn_unrecognized_error_map_value(value: &str) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    // Poisoning is harmless here (the set only dedupes warnings); recover the guard either way.
    let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
    if guard.insert(value.to_string()) {
        crate::diag_warn!(
            crate::diagnostics::CONFIG_ERROR_MAP_CLASS_UNRECOGNIZED,
            error_map_value = value,
            "error_map maps an error to an unrecognized status class; the mapping is IGNORED and \
             classification falls through to HTTP status. Valid classes: rate_limit, overloaded, \
             server_error, timeout, network, auth, billing, client_error, context_length"
        );
    }
}

/// Classify a CanonicalSignal into a disposition.
/// EXHAUSTIVE match on StatusClass — NO `_ =>` allowed.
/// Per ADR-0002: ClientFault never counted; HardDown immediate trip.
pub fn classify(sig: &CanonicalSignal) -> Disposition {
    match sig.class {
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network => Disposition::TransientUpstream,
        StatusClass::Auth | StatusClass::Billing => Disposition::HardDown,
        StatusClass::ClientError => Disposition::ClientFault,
        StatusClass::ContextLength => Disposition::ContextLength,
    }
}

/// Raw upstream error extracted from HTTP response (Stage 1a output).
#[derive(Debug, Clone)]
pub struct RawUpstreamError {
    pub http_status: u16,
    /// Provider-specific error *code* (e.g. a numeric `code` field), checked against `error_map`.
    pub provider_code: Option<String>,
    /// Provider-specific structured error *type* (e.g. a `type`/`error.type` string), checked
    /// against `error_map` as a second signal when the code doesn't match.
    pub structured_type: Option<String>,
    /// Upstream `Retry-After` header value in whole seconds, when present. The per-protocol
    /// `extract_error` methods only see the body (no headers), so the forwarding layer — which has
    /// the response headers — parses and sets this after `extract_error` returns. `normalize_raw_error`
    /// then propagates it into `CanonicalSignal.retry_after` so the cooldown floor is honored.
    pub retry_after_secs: Option<u64>,
}

impl RawUpstreamError {
    /// THE STATUS ALONE, claiming no provider vocabulary — what one outbound attempt reports when
    /// nothing on the path could read its upstream's error shape. It is the most restrictive USEFUL
    /// answer rather than the most restrictive possible one: `classify` still places the failure
    /// from the status, which is strictly better than a non-2xx the breaker never hears about.
    pub fn from_status(status: u16) -> Self {
        Self {
            http_status: status,
            provider_code: None,
            structured_type: None,
            retry_after_secs: None,
        }
    }
}

/// Parse a `Retry-After` header value. RFC 9110 §10.2.3 defines the field as
/// `delay-seconds / HTTP-date`; BOTH forms are normative and providers send both. Parsing only the
/// integer form silently discards the provider's stated cooldown floor on every date-form response,
/// leaving the breaker to guess.
pub fn parse_retry_after(headers: &http::HeaderMap) -> Option<u64> {
    let s = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    // A date already in the past means "retry now", not "retry in a very long time" — hence
    // saturating_duration_since, which floors at zero.
    let at = httpdate::parse_http_date(s).ok()?;
    Some(
        at.duration_since(std::time::SystemTime::now())
            .unwrap_or_default()
            .as_secs(),
    )
}

/// Classify a raw upstream error into a canonical signal using an error_map.
/// Stage 1b (provider normalizer): data-driven mapping from raw errors to StatusClass.
pub fn normalize_raw_error(
    raw: &RawUpstreamError,
    error_map: &std::collections::HashMap<String, String>,
) -> CanonicalSignal {
    // Step 1: a provider error code mapped in error_map refines (overrides) the HTTP-status default.
    let provider_signal = if let Some(ref code) = raw.provider_code {
        if let Some(mapped_class) = error_map.get(code) {
            if let Some(class) = status_class_from_str(mapped_class) {
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
                warn_unrecognized_error_map_value(mapped_class);
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
        if code == crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH
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
            let class = status_class_from_str(m);
            if class.is_none() {
                warn_unrecognized_error_map_value(m);
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

/// Canonical signal emitted by protocol normalizers.
/// Stage 1 output → Stage 2 input.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalSignal {
    pub class: StatusClass,
    pub provider_signal: Option<String>,
    pub retry_after: Option<u64>,
}

#[cfg(test)]
#[path = "tests/breaker_tests.rs"]
mod tests;
