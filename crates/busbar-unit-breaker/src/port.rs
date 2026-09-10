// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The disposition-plus-outcome answer the egress unit's `Breaker::classify` port needs, and the
//! pure mapping from a classified upstream error onto it.
//!
//! [`classify`] answers ONLY the disposition (Stage 2 of the two-stage pipeline).
//! The egress port needs one step further: what the classified answer means to THIS unit's own
//! state machine (an [`Outcome`]) and the metric label a caller's dashboard reads. That fold is
//! [`outcome_and_label`] below, ported as data (not as HTTP/telemetry plumbing) from the four-way
//! split in 1.5.5's `classify_error` (`busbar-llm/src/engine/attempt/classify.rs:213-289`):
//! `ClientFault` records nothing and relays; `TransientUpstream` carries the upstream's own
//! `Retry-After` through as the cooldown floor; `HardDown` trips every pool cell for the
//! destination; `ContextLength` records nothing and fails over. [`classify_upstream`] composes that
//! fold with [`crate::classify::normalize_raw_error`] and [`crate::classify::classify`] into the one
//! call a caller needs, and [`crate::BreakerUnit::classify`] is the stateful method that reads the
//! declared per-destination `error_map` and calls it — together the pure function and the method the
//! task asks for.
//!
//! This module takes no dependency beyond [`crate::classify`] and [`crate::Outcome`] — in
//! particular, no `busbar-contract` (this crate's `Cargo.toml` is explicit that `busbar-caps` is the
//! only workspace crate it may name). The egress unit's own `UpstreamStatus` additionally carries
//! the transport's coarse status-class reading (`busbar_contract::StatusClass`); a caller that has
//! that reading folds it into [`UpstreamStatus::code`] itself before calling in — exactly the kind
//! of narrowing an integrator's adapter does, alongside the `DestinationId` width narrowing.
//!
//! What that narrowing may NOT drop is the numbering the status was spelled in: [`UpstreamCode`]
//! restates the transport contract's namespaced status in this crate's own vocabulary, so an
//! integrator hands over `Grpc(14)` and not the bare `14` an HTTP band-check would fail to place.

use crate::classify::{self, Disposition};
use crate::Outcome;

/// The numbering an upstream status was spelled in, carried WITH the number.
///
/// This unit takes no dependency on the transport contract, so it cannot name that contract's
/// `WireStatus` — but the fact the two types carry is the same one, and an integrator's adapter
/// narrows across (exactly as it already does for the destination's width). What matters is that
/// neither side can hand a bare number over: a `14` read against HTTP's bands matches no band at
/// all, and the destination that just said `UNAVAILABLE` would go unrecorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamCode {
    /// An HTTP status. Classified by band, as 1.5.5 classified every upstream.
    Http(u16),
    /// A `grpc-status` code. Classified through [`crate::classify::GRPC_STATUS_TABLE`], which is
    /// gRPC's own numbering and shares nothing with HTTP's but the fact that it is a number.
    Grpc(u8),
}

/// WHY a destination went hard-down — what the upstream said when it went, in the words the
/// previous release recorded lane-wide (`1.5.5's forward path, attempt/classify.rs:306-318`).
///
/// A value, not a string, so it can ride [`crate::Outcome::HardDown`] across a `Copy` seam and
/// still render to the exact text an operator reads off `/stats`. The classifier decides it, the
/// walk hands it to `observe`, and the unit records it — there is no call between those two at
/// which a reason could be recorded any other way, which is why it is on the outcome and not a
/// second verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardDownReason {
    /// The account behind the credential is out of money.
    Billing,
    /// The credential itself was refused.
    Auth(Option<UpstreamCode>),
    /// A definitive refusal the operator's `error_map` classed as hard-down without being either
    /// of the two above.
    Rejected(Option<UpstreamCode>),
}

impl HardDownReason {
    /// The reason for a hard-down classified as `class`, from an answer carrying `code`.
    #[must_use]
    pub fn of(class: classify::StatusClass, code: Option<UpstreamCode>) -> Self {
        match class {
            classify::StatusClass::Billing => Self::Billing,
            classify::StatusClass::Auth => Self::Auth(code),
            _ => Self::Rejected(code),
        }
    }
}

/// The status, spelled the way the reason's text has always spelled it.
struct SpelledCode(Option<UpstreamCode>);

impl std::fmt::Display for SpelledCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(UpstreamCode::Http(code)) => write!(f, "HTTP {code}"),
            Some(UpstreamCode::Grpc(code)) => write!(f, "grpc-status {code}"),
            None => f.write_str("no status"),
        }
    }
}

impl std::fmt::Display for HardDownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Billing => f.write_str("billing / insufficient balance"),
            Self::Auth(code) => write!(f, "auth rejected ({})", SpelledCode(*code)),
            Self::Rejected(code) => write!(f, "request rejected ({})", SpelledCode(*code)),
        }
    }
}

/// WHOSE credential the upstream refused. The ORIGIN of the credential and never the credential:
/// this type holds no bytes at all, which is why it is not one of the named secret carriers that
/// must hand-roll `Debug`, and why its name says `Origin` out loud rather than leaving a reader to
/// check.
///
/// 1.5.5 asks this question on the response path and it changes the answer: a 401/403 against a
/// key the CALLER supplied is that caller's own credential failing, not this destination's, and it
/// is relayed with no breaker penalty at all (`1.5.5's forward path, attempt/classify.rs:203-210`).
/// Without the distinction the same response hard-downs the destination in every pool, so one
/// caller's stale key benches a healthy upstream for everybody else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CredentialOrigin {
    /// The credential busbar itself declared for this destination. A refusal is the destination's.
    #[default]
    Declared,
    /// The caller's own key, relayed unchanged (1.5.5's `UpstreamCreds::Passthrough`).
    Passthrough,
}

/// The upstream answer as this unit classifies it: the numeric status WITH its namespace (`None`
/// when the transport could not put a number on the failure), whose credential was refused, the
/// signals the dialect read out of the response BODY, and the upstream's own requested wait.
///
/// `provider_code` and `structured_type` are the two slots an `error_map` entry is keyed on. They
/// are the dialect's reading of the body — 1.5.5's `extract_error(status, body)`, folded in at
/// `1.5.5's forward path, attempt/classify.rs:214-220` — and they are what makes an operator's rule
/// for `insufficient_quota` a rule about a provider's own vocabulary rather than about an HTTP
/// number. When no code was read, the HTTP status string stands in, because the config grammar
/// accepts a plain status as a key too (`error_map: { "400": client_error }`); that fallback is a
/// FALLBACK and never a replacement, which is the whole difference. A gRPC code is NOT offered as a
/// provider code: those keys are HTTP-status strings by the config grammar, and feeding `14` in
/// would let an operator's rule for HTTP `14` — a status that does not exist — silently claim a
/// gRPC `UNAVAILABLE`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamStatus<'a> {
    /// The upstream's numeric status and the numbering that spelled it, where one is known.
    pub code: Option<UpstreamCode>,
    /// Whose credential this answer refused.
    pub credential: CredentialOrigin,
    /// The provider's own error CODE, as the dialect read it out of the response body.
    pub provider_code: Option<&'a str>,
    /// The provider's structured error TYPE, as the dialect read it out of the response body — the
    /// second signal `normalize_raw_error` checks when the code matched nothing.
    pub structured_type: Option<&'a str>,
    /// The upstream's requested Retry-After, in whole seconds, where it asked for one.
    pub retry_after: Option<u64>,
}

/// What the classifier made of one upstream answer: where the caller sends the request next, what
/// this unit's own state machine should be told, and the metric label for the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    /// Where the caller sends the request next.
    pub disposition: Disposition,
    /// What [`crate::Breaker::observe`] should be told.
    pub outcome: Outcome,
    /// The metric label for this failure.
    pub label: &'static str,
}

/// The metric label literals. These are pinned to the SAME string values as the egress unit's own
/// `ports::disposition` module — the two crates share no dependency to point at one constant, so the
/// values are kept in step by hand, deliberately, rather than through a shared type.
pub mod label {
    /// A transient upstream failure.
    pub const TRANSIENT_UPSTREAM: &str = "transient_upstream";
    /// A definitive signal about the shared destination.
    pub const HARD_DOWN: &str = "hard_down";
    /// The request was too large for this destination's window.
    pub const CONTEXT_LENGTH: &str = "context_length";
    /// The caller's own fault. Never read as a telemetry label by the reference caller (a
    /// `ClientFault` short-circuits before the label is used) but a real value all the same — never
    /// a placeholder a future caller could mistake for "unset".
    pub const CLIENT_FAULT: &str = "client_fault";
}

/// Fold a classified [`Disposition`] into the [`Outcome`] this unit's state machine acts on and the
/// metric label a caller records the failure under. A pure function: no destination, no lock, no
/// clock. `reason` is read on the hard-down arm alone — it is the one arm whose record outlives
/// the call.
#[must_use]
pub fn outcome_and_label(
    disposition: Disposition,
    retry_after: Option<u64>,
    reason: HardDownReason,
) -> (Outcome, &'static str) {
    match disposition {
        // The caller's bad input: the destination is healthy either way, so nothing is recorded —
        // folded together with `ContextLength` below, per `Outcome`'s own doc comment.
        Disposition::ClientFault => (Outcome::RecordNothing, label::CLIENT_FAULT),
        // A transient failure: the upstream's own Retry-After (if any) threads through as the
        // cooldown floor `BreakerCell::compute_cooldown_with_retry_after` reads.
        Disposition::TransientUpstream => (
            Outcome::Transient { retry_after },
            label::TRANSIENT_UPSTREAM,
        ),
        // A definitive signal about the shared destination: every pool cell trips, not just this
        // one — see `BreakerUnit::hard_down_all`, which `BreakerUnit::observe` dispatches
        // `Outcome::HardDown` to.
        Disposition::HardDown => (Outcome::HardDown { reason }, label::HARD_DOWN),
        // Too big for this destination's window: the destination is healthy, record nothing.
        Disposition::ContextLength => (Outcome::RecordNothing, label::CONTEXT_LENGTH),
    }
}

/// Classify one upstream answer against a declared `error_map`, and fold the answer straight
/// through to the [`Outcome`] and label a caller acts on. The pure function
/// [`crate::BreakerUnit::classify`] is implemented over: no lock, no destination, no clock — a
/// caller with its own error-map storage can call this directly.
///
/// `diagnostics` is the sink an unrecognized `error_map` value is reported to: this
/// function no longer hardcodes [`classify::NoopDiagnostics`] internally, so a real sink bound by
/// the composition root actually reaches the classifier. Pass `&classify::NoopDiagnostics` for
/// today's silently-ignored behavior.
#[must_use]
pub fn classify_upstream(
    error_map: &std::collections::HashMap<String, String>,
    status: UpstreamStatus<'_>,
    diagnostics: &dyn classify::Diagnostics,
) -> Classified {
    // Each namespace through its own table. The gRPC leg never enters the HTTP normalizer at all:
    // that normalizer's every branch — the 401/403 arm, the 429 arm, the 5xx band — is a statement
    // about HTTP's numbering, and a gRPC code walking through it lands wherever its digits happen
    // to fall.
    let sig = match status.code {
        Some(UpstreamCode::Grpc(code)) => classify::CanonicalSignal {
            class: classify::grpc_status_class(code),
            provider_signal: None,
            retry_after: status.retry_after,
        },
        http => {
            let http_status = match http {
                Some(UpstreamCode::Http(code)) => Some(code),
                _ => None,
            };
            let raw = classify::RawUpstreamError {
                http_status: http_status.unwrap_or(0),
                // The dialect's reading of the body first, the status string only where there was
                // none. Reversing that order — or dropping the body reading, as this crate did
                // before the equivalence cells named it — silently re-keys every operator rule
                // onto HTTP numbers, and every rule written against a provider's own vocabulary
                // stops firing without saying so.
                provider_code: status
                    .provider_code
                    .map(str::to_string)
                    .or_else(|| http_status.map(|c| c.to_string())),
                structured_type: status.structured_type.map(str::to_string),
                retry_after_secs: status.retry_after,
            };
            classify::normalize_raw_error(&raw, error_map, diagnostics)
        }
    };
    // A passthrough 401/403 is the CALLER's key failing, not busbar's: no breaker penalty, relay.
    // Placed after the signal is built, not before, so the classification a caller reads back is
    // still the one the tables produced — only the DISPOSITION is overridden, and only for the two
    // statuses 1.5.5 exempts. A passthrough 429 is still a transient the breaker records, or a
    // caller could suppress every penalty on this destination by relaying its own key.
    let disposition = if status.credential == CredentialOrigin::Passthrough
        && matches!(status.code, Some(UpstreamCode::Http(401 | 403)))
    {
        Disposition::ClientFault
    } else {
        classify::classify(&sig)
    };
    let (outcome, label) = outcome_and_label(
        disposition,
        sig.retry_after,
        HardDownReason::of(sig.class, status.code),
    );
    Classified {
        disposition,
        outcome,
        label,
    }
}

#[cfg(test)]
#[path = "tests/port.rs"]
mod tests;
