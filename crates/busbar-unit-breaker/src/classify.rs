//! The protocol-agnostic disposition classifier — Stage 2 of the two-stage pipeline that turns an
//! upstream error into the fact the breaker state machine acts on.
//!
//! Moved byte-identical from `busbar-substrate::breaker` (1.5.5's
//! `crates/busbar-substrate/src/breaker.rs`). Stage 1 (per-protocol extraction of a
//! [`RawUpstreamError`] from a response) stays with the wire/dialect code, which is out of scope
//! for this unit; this module starts from the already-extracted raw error.
//!
//! Two call-site adaptations from the source, neither of which changes the classification
//! arithmetic itself:
//! - `parse_retry_after` takes a plain `&str` (the `Retry-After` header VALUE), not an
//!   `axum::http::HeaderMap` — this crate depends on nothing but `busbar-caps`, so it cannot name
//!   `axum`'s header map type. The HTTP-date branch is a hand-rolled RFC 9110 IMF-fixdate parser
//!   (`parse_imf_fixdate`) rather than the `httpdate` crate, for the same reason.
//! - the "operator `error_map` points at an unrecognized class" diagnostic is delivered through an
//!   injectable [`Diagnostics`] sink rather than `tracing::warn!`, since this crate takes no
//!   logging dependency. `// contract:` — a caller wires a real sink (or the kernel's diagnostics
//!   seam, once one exists) in; [`NoopDiagnostics`] preserves today's "silently ignored" behavior
//!   for the return value, which is what the state machine's byte-identical requirement is about.

/// Anthropic's non-standard 529 overload status — not in the IANA registry, but documented by
/// Anthropic as their server-overloaded signal, distinct from 503.
const HTTP_OVERLOADED: u16 = 529;

/// Protocol-neutral, dialect-normalized status class emitted by the (out-of-scope, per-protocol)
/// Stage 1 normalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// Rate limit / slow down — transient, may recover with retry-after.
    RateLimit,
    /// Overloaded server — transient.
    Overloaded,
    /// Server error (5xx) — transient.
    ServerError,
    /// Request timeout — transient.
    Timeout,
    /// Network failure — transient.
    Network,
    /// Authentication failure (401/403) — hard down, key invalid.
    Auth,
    /// Billing / insufficient balance — hard down, account issue.
    Billing,
    /// Client error (4xx other than 401/403) — client fault, do not penalize the lane.
    ClientError,
    /// Request exceeds this destination's context window — the destination is healthy; fail over
    /// (ideally to a larger-context sibling) WITHOUT penalizing the breaker.
    ContextLength,
}

/// The final disposition that drives the breaker's write path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The caller's bad input: relay verbatim, record nothing against the breaker.
    ClientFault,
    /// A transient failure: cooldown + error counter.
    TransientUpstream,
    /// A definitive signal (bad key, billing exhausted): sticky cooldown, recovered by a probe.
    HardDown,
    /// The request was too big for this destination: fail over, record nothing (the lane is
    /// healthy).
    ContextLength,
}

/// Every declared status class paired with its disposition, as data — the table PB-10 names.
/// `classify` is still an exhaustive match (so the compiler catches a class the table forgot), but
/// this array is what the port test below checks the match against, and what a future caller can
/// render/audit without re-deriving it from the match arms.
pub const DISPOSITION_TABLE: &[(StatusClass, Disposition)] = &[
    (StatusClass::RateLimit, Disposition::TransientUpstream),
    (StatusClass::Overloaded, Disposition::TransientUpstream),
    (StatusClass::ServerError, Disposition::TransientUpstream),
    (StatusClass::Timeout, Disposition::TransientUpstream),
    (StatusClass::Network, Disposition::TransientUpstream),
    (StatusClass::Auth, Disposition::HardDown),
    (StatusClass::Billing, Disposition::HardDown),
    (StatusClass::ClientError, Disposition::ClientFault),
    (StatusClass::ContextLength, Disposition::ContextLength),
];

/// Convert a wire token to a [`StatusClass`]. `None` for anything unrecognized (e.g. a typo'd
/// operator `error_map` entry).
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

/// A sink for the one diagnostic this module raises: an operator `error_map` entry names a string
/// that is not a recognized [`StatusClass`]. `// contract:` a real deployment wires this to its own
/// logging/metrics seam; [`NoopDiagnostics`] is the default and matches 1.5.5's behavior for the
/// classification RESULT (the mapping is still silently ignored either way — only the side-channel
/// warning is pluggable here instead of a hardwired `tracing::warn!`).
pub trait Diagnostics {
    /// Called at most once per distinct unrecognized value in a process's lifetime (dedup is the
    /// caller's job in the reference `WarnOnceDiagnostics`, mirroring 1.5.5's warn-once-per-value).
    fn unrecognized_error_map_value(&self, value: &str);
}

/// A [`Diagnostics`] sink that does nothing. The default when a caller has not wired one in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDiagnostics;

impl Diagnostics for NoopDiagnostics {
    fn unrecognized_error_map_value(&self, _value: &str) {}
}

/// A [`Diagnostics`] adapter that forwards each distinct unrecognized value to an inner sink AT
/// MOST ONCE per process lifetime, deduplicating repeat calls for the same value itself so the
/// inner sink (e.g. a real `tracing::warn!`-backed one the composition root binds) never has to.
/// This is PB-98's "warned once and ignored": the classification RESULT is unaffected either way
/// (the mapping is still silently ignored) — only how many times the side-channel warning fires.
pub struct WarnOnceDiagnostics<S: Diagnostics> {
    seen: std::sync::Mutex<std::collections::HashSet<String>>,
    inner: S,
}

impl<S: Diagnostics> WarnOnceDiagnostics<S> {
    /// Wrap `inner`, deduplicating by the exact unrecognized string.
    pub fn new(inner: S) -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::HashSet::new()),
            inner,
        }
    }
}

impl<S: Diagnostics> Diagnostics for WarnOnceDiagnostics<S> {
    fn unrecognized_error_map_value(&self, value: &str) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.insert(value.to_string()) {
            drop(seen);
            self.inner.unrecognized_error_map_value(value);
        }
    }
}

/// A shared [`Diagnostics`] sink is still one: this is what lets a caller keep a handle on the
/// concrete sink (e.g. to assert on it in a test, or to fan it out elsewhere) while also handing
/// an owned value into [`crate::BreakerUnit::with_diagnostics`].
impl<S: Diagnostics + ?Sized> Diagnostics for std::sync::Arc<S> {
    fn unrecognized_error_map_value(&self, value: &str) {
        (**self).unrecognized_error_map_value(value);
    }
}

/// Classify a [`CanonicalSignal`] into a [`Disposition`]. Exhaustive over [`StatusClass`] — no
/// wildcard arm, so a class added to the enum without a table row fails to compile.
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

/// The raw upstream error extracted from a response by the (out-of-scope) per-protocol Stage 1.
#[derive(Debug, Clone)]
pub struct RawUpstreamError {
    /// The HTTP status the upstream returned.
    pub http_status: u16,
    /// A provider-specific error CODE (e.g. a numeric `code` field), checked against `error_map`.
    pub provider_code: Option<String>,
    /// A provider-specific structured error TYPE (e.g. `error.type`), checked against `error_map`
    /// as a second signal when the code doesn't match.
    pub structured_type: Option<String>,
    /// The upstream `Retry-After` value in whole seconds, when present and already parsed by the
    /// caller (see [`parse_retry_after`]).
    pub retry_after_secs: Option<u64>,
}

impl RawUpstreamError {
    /// Build a raw error from the status alone, claiming no provider vocabulary — the most
    /// restrictive USEFUL answer when nothing on the path could read the upstream's error shape.
    pub fn from_status(status: u16) -> Self {
        Self {
            http_status: status,
            provider_code: None,
            structured_type: None,
            retry_after_secs: None,
        }
    }
}

/// The wire literal 1.5.5 and every provider integration recognize for a context-length rejection.
/// Kept here (not owned by a wire/dialect crate) because [`normalize_raw_error`]'s built-in
/// recognition names it directly; a dialect crate importing this constant, rather than
/// hand-copying the literal, is how the spelling stays single-sourced.
pub const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

/// Parse an RFC 9110 §10.2.3 `Retry-After` header VALUE. Both normative forms are accepted:
/// `delay-seconds` (an integer) and an HTTP-date, which floors at 0 when it is already in the past.
pub fn parse_retry_after(value: &str) -> Option<u64> {
    let s = value.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    parse_imf_fixdate_retry_after(s)
}

/// Parse the value as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, the sole HTTP-date form RFC
/// 9110 recommends generating, though obsolete forms are permitted for parsing — this parser
/// accepts only the recommended form, matching every provider observed in practice) and return the
/// whole seconds remaining until it, floored at 0 for a date already in the past.
fn parse_imf_fixdate_retry_after(s: &str) -> Option<u64> {
    // "Www, dd Mon yyyy HH:MM:SS GMT" — fixed-width, so a byte-length check plus field slicing is
    // enough; no general calendar library is warranted for one wire format.
    let bytes = s.as_bytes();
    if bytes.len() != 29 || !s.ends_with(" GMT") {
        return None;
    }
    let day: u64 = s.get(5..7)?.parse().ok()?;
    let month = month_from_abbrev(s.get(8..11)?)?;
    let year: u64 = s.get(12..16)?.parse().ok()?;
    let hour: u64 = s.get(17..19)?.parse().ok()?;
    let minute: u64 = s.get(20..22)?.parse().ok()?;
    let second: u64 = s.get(23..25)?.parse().ok()?;
    if s.as_bytes().get(3) != Some(&b',') || s.as_bytes().get(4) != Some(&b' ') {
        return None;
    }
    let epoch_secs = civil_to_epoch_secs(year, month, day, hour, minute, second)?;
    let now = crate::clock::unix_time_secs();
    Some(epoch_secs.saturating_sub(now))
}

fn month_from_abbrev(m: &str) -> Option<u64> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days-from-civil algorithm (Howard Hinnant's public-domain `civil_from_days` inverse), giving a
/// UTC Unix timestamp for a UTC calendar date and time with no external date/time dependency.
fn civil_to_epoch_secs(year: u64, month: u64, day: u64, hour: u64, minute: u64, second: u64) -> Option<u64> {
    let y = year as i64 - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era * 146_097 + doe - 719_468;
    let days_since_epoch = u64::try_from(days_since_epoch).ok()?;
    Some(days_since_epoch * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Classify a raw upstream error into a [`CanonicalSignal`] using an operator `error_map`. Stage 1b
/// (the provider normalizer): data-driven mapping from raw errors to [`StatusClass`], with a
/// built-in fallback to HTTP-status classification.
pub fn normalize_raw_error(
    raw: &RawUpstreamError,
    error_map: &std::collections::HashMap<String, String>,
    diagnostics: &dyn Diagnostics,
) -> CanonicalSignal {
    // Step 1: a provider error code mapped in error_map refines (overrides) the HTTP-status default.
    let provider_signal = if let Some(ref code) = raw.provider_code {
        if let Some(mapped_class) = error_map.get(code) {
            if let Some(class) = status_class_from_str(mapped_class) {
                // CLASS guard: a mapping to `context_length` on a 5xx must never mask a real
                // upstream outage — suppress the early return and fall through to HTTP
                // classification so the lane is penalized; every other mapped class returns early.
                if !(class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)) {
                    return CanonicalSignal {
                        class,
                        provider_signal: Some(code.clone()),
                        retry_after: raw.retry_after_secs,
                    };
                }
            } else {
                diagnostics.unrecognized_error_map_value(mapped_class);
            }
        }
        // The built-in canonical context-length code, recognized ONLY on the precise
        // oversized-request statuses (400 Bad Request / 413 Payload Too Large) — never a 5xx (an
        // upstream server failure) or any other status that happens to carry the code.
        if code == PROVIDER_CODE_CONTEXT_LENGTH && (raw.http_status == 400 || raw.http_status == 413) {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(code.clone()),
                retry_after: raw.retry_after_secs,
            };
        }
        Some(code.clone())
    } else {
        None
    };

    // Step 1b: the provider's structured error TYPE is a second data-driven signal — the explicit
    // code (above) wins; this refines when the code didn't match.
    if let Some(ref ty) = raw.structured_type {
        let mapped = error_map.get(ty).and_then(|m| {
            let class = status_class_from_str(m);
            if class.is_none() {
                diagnostics.unrecognized_error_map_value(m);
            }
            class
        });
        if let Some(class) = mapped {
            // Same CLASS guard as the code path.
            if !(class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)) {
                return CanonicalSignal {
                    class,
                    provider_signal: provider_signal.or_else(|| Some(ty.clone())),
                    retry_after: raw.retry_after_secs,
                };
            }
        }
    }

    // Step 2: classify by HTTP status (universal spec fallback; exhaustive).
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
        // True 4xx (other than 401/403/408/429 above) — the caller's fault.
        StatusClass::ClientError
    } else {
        // An unexpected non-error status (2xx/3xx) reaching the error path — the destination is not
        // at fault, so record nothing and relay as-is (the closest available disposition).
        StatusClass::ClientError
    };

    CanonicalSignal {
        class,
        provider_signal,
        retry_after: raw.retry_after_secs,
    }
}

/// The canonical signal Stage 1 (out of scope here) hands to [`classify`].
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalSignal {
    /// The normalized status class.
    pub class: StatusClass,
    /// The provider code or structured type that drove the classification, if any (diagnostic
    /// only — never read by `classify`).
    pub provider_signal: Option<String>,
    /// The upstream's requested Retry-After, in seconds, if any.
    pub retry_after: Option<u64>,
}
