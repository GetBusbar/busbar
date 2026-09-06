//! The 1.5.5 admin error envelope, and the closed `RefusalReason -> code` mapping that renders it.
//!
//! The wire shape is `{"error":{"code":"<code>","message":"<message>"}}`, transcribed from
//! `busbar-core`'s admin contract (`crates/busbar-core/src/admin/v1/contract/mod.rs`'s `AdminError`
//! and `crates/busbar-core/src/admin/v1/json/mod.rs`'s `err_json`), which this crate reads as
//! read-only reference and never depends on.
//!
//! `busbar-core`'s ten `AdminError` variants map to exactly these frozen `code` strings: `not_found`,
//! `unauthorized`, `method_not_allowed`, `forbidden`, `invalid_request`, `version_conflict`,
//! `conflict`, `rate_limited`, `internal`, `unavailable`. The contract crate's `RefusalReason` is a
//! WIDER closed set (twenty variants, general to every plane in the design, not admin-specific), so
//! this mapping is necessarily lossy in one direction: several `RefusalReason`s share one code. Each
//! row below states the reasoning, because a silent many-to-one mapping is exactly the kind of
//! decision a reviewer needs to be able to check without re-deriving it.
//!
//! **The table below is the ratified mapping.** It is not a proposal and not this crate's guess: a
//! client-rendered reason is an opaque code by design, so the lossiness is inherent rather than a
//! defect, and this table is where it is decided. A change to a row is a change to what an operator
//! sees, so it is a change to be argued for here rather than made in passing.
//!
//! | `RefusalReason` | `code` | Why |
//! |---|---|---|
//! | `InFlightCap` | `rate_limited` | the node is momentarily over its concurrency ceiling; a retry-shaped condition, not a data conflict |
//! | `CursorBudget` | `invalid_request` | the request's own bytes exceeded a per-connection reading budget: a property of THIS request |
//! | `CredentialBudget` | `invalid_request` | the presented credential's span would not fit the slab: also a property of this request |
//! | `SessionBudget` | `unavailable` | a node-global ceiling, transient and not the caller's fault |
//! | `BodyTooLarge` | `invalid_request` | the closest existing code to "the body you sent is too large" |
//! | `OpenSlotBusy` | `conflict` | a second open unit contends for one direction's slot: a state conflict on the connection |
//! | `SchemeNotDeclared` | `unauthorized` | the credential could not even be classified into a scheme this claim allows |
//! | `CredentialRejected` | `unauthorized` | the credential did not verify |
//! | `SessionUnbound` | `unauthorized` | a session-carried credential was asked for on a session that caches none |
//! | `Revoked` | `forbidden` | authenticated, but authority was withdrawn |
//! | `ScopeMissing` | `forbidden` | authenticated, under-scoped — the textbook `forbidden` case |
//! | `Vetoed` | `forbidden` | a gate hook said no; the principal may not perform this operation |
//! | `NoDestination` | `not_found` | the verified set is empty: there is nothing to route this unit to |
//! | `OverBudget` | `rate_limited` | a money cap reached; throttling-shaped, not a conflict over state |
//! | `GroupFrozen` | `forbidden` | the principal's group is frozen: authenticated, not currently permitted |
//! | `Unpriced` | `invalid_request` | no price and none allowed: the closest of the ten to "this request cannot be served as shaped" |
//! | `OverdraftCeiling` | `rate_limited` | another money-throttle ceiling, same reasoning as `OverBudget` |
//! | `StaleSlice` | `unavailable` | the node's slice of a bucket window is out of date: transient, node-side |
//! | `DurabilityUnavailable` | `unavailable` | the journal cannot be written: the textbook `unavailable` case |
//! | `TierMismatch` | `internal` | a configuration inconsistency across a bucket chain: not the caller's fault and not a normal request outcome |
//! | `SpillBudget` | `unavailable` | a node-global spill ceiling: transient and node-side, same family as `SessionBudget` |
//! | `ArenaBudget` | `unavailable` | the per-unit arena ran out: a node-side resource, not a property of the request |
//! | `RateLimited` | `rate_limited` | the source is over its arrival rate: the code exists for exactly this |
//! | `DecodeFailed` | `invalid_request` | the bytes could not be read: a property of THIS request |
//! | `ChallengeExhausted` | `unauthorized` | the exchange ran out before authority was established |
//! | `PoolNotPermitted` | `forbidden` | authenticated and not allowed to reach the pool it named |
//! | `NoRate` | `invalid_request` | the name the caller supplied cannot be billed: nothing is wrong with the budget |
//! | `Replayed` | `conflict` | the idempotency key was already used: a state conflict, not a throttle |
//! | `InFlight` | `conflict` | the key belongs to a unit still running: the same conflict, earlier |
//! | `DestinationBudgetExhausted` | `unavailable` | the destination has nothing left to spend: node-side, not the caller's fault |
//! | `BreakerOpen` | `unavailable` | the destination is being protected: transient by construction |
//! | `DestinationUnreachable` | `unavailable` | nothing answered upstream |
//! | `MeterDisputed` | `internal` | two evidence sources disagree: a node-side inconsistency |
//! | `HandoffMismatch` | `internal` | two legs did not agree on what they were doing: not the caller's doing |
//! | `PlanePanic` | `internal` | the textbook `internal` case |
//! | `TaskLost` | `internal` | the unit's task disappeared without an end |
//! | `SecretPlaceholder` | `internal` | a minted secret did not land where it was declared: node-side |
//! | `Stalled` | `unavailable` | no progress inside the deadline: transient |
//! | `Drain` | `unavailable` | the node is going away: the textbook retry-elsewhere case |
//! | `Superseded` | `conflict` | a later unit took this one's place: a conflict over the same state |
//! | `ClientGone` | `conflict` | the caller abandoned the request: a connection-state outcome, same family as `OpenSlotBusy` |
//! | `DeadlineExceeded` | `unavailable` | the unit ran past its maximum duration |
//!
//! Where a `RefusalReason` has no crisp admin-error analog, the row above states the closest
//! reasonable one rather than defaulting silently to `internal`; only `TierMismatch` (a genuine
//! server-side misconfiguration) uses `internal`.
//!
//! Every reason has a row, and the meta-test below walks the closed set to say so: a reason added to
//! the contract without a row here would otherwise reach an operator as whatever the fallback arm
//! happened to be.

use busbar_contract::unit::RefusalReason;

/// The frozen `code` string for one `RefusalReason`, per the table in this module's doc comment.
#[must_use]
pub(crate) fn code_for(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::InFlightCap => "rate_limited",
        RefusalReason::CursorBudget => "invalid_request",
        RefusalReason::CredentialBudget => "invalid_request",
        RefusalReason::SessionBudget => "unavailable",
        RefusalReason::BodyTooLarge => "invalid_request",
        RefusalReason::OpenSlotBusy => "conflict",
        RefusalReason::SchemeNotDeclared => "unauthorized",
        RefusalReason::CredentialRejected => "unauthorized",
        RefusalReason::SessionUnbound => "unauthorized",
        RefusalReason::Revoked => "forbidden",
        RefusalReason::ScopeMissing => "forbidden",
        RefusalReason::Vetoed => "forbidden",
        RefusalReason::NoDestination => "not_found",
        RefusalReason::OverBudget => "rate_limited",
        RefusalReason::GroupFrozen => "forbidden",
        RefusalReason::Unpriced => "invalid_request",
        RefusalReason::OverdraftCeiling => "rate_limited",
        RefusalReason::StaleSlice => "unavailable",
        RefusalReason::DurabilityUnavailable => "unavailable",
        RefusalReason::TierMismatch => "internal",
        RefusalReason::SpillBudget => "unavailable",
        RefusalReason::ArenaBudget => "unavailable",
        RefusalReason::RateLimited => "rate_limited",
        RefusalReason::DecodeFailed => "invalid_request",
        RefusalReason::ChallengeExhausted => "unauthorized",
        RefusalReason::PoolNotPermitted => "forbidden",
        RefusalReason::NoRate => "invalid_request",
        RefusalReason::Replayed => "conflict",
        RefusalReason::InFlight => "conflict",
        RefusalReason::DestinationBudgetExhausted => "unavailable",
        RefusalReason::BreakerOpen => "unavailable",
        RefusalReason::DestinationUnreachable => "unavailable",
        RefusalReason::MeterDisputed => "internal",
        RefusalReason::HandoffMismatch => "internal",
        RefusalReason::PlanePanic => "internal",
        RefusalReason::TaskLost => "internal",
        RefusalReason::SecretPlaceholder => "internal",
        RefusalReason::Stalled => "unavailable",
        RefusalReason::Drain => "unavailable",
        RefusalReason::Superseded => "conflict",
        RefusalReason::ClientGone => "conflict",
        RefusalReason::DeadlineExceeded => "unavailable",
    }
}

/// A short, caller-safe human message for one `RefusalReason`. Never the reason's `Debug` name
/// verbatim on the wire — a client sees prose, not a Rust identifier — but stable enough that a
/// test can assert on it.
#[must_use]
pub(crate) fn message_for(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::InFlightCap => "too many requests in flight",
        RefusalReason::CursorBudget => "request exceeded the read cursor budget",
        RefusalReason::CredentialBudget => "credential span exceeded the credential budget",
        RefusalReason::SessionBudget => "the node's session budget is exhausted",
        RefusalReason::BodyTooLarge => "request body too large",
        RefusalReason::OpenSlotBusy => "an open unit already occupies this slot",
        RefusalReason::SchemeNotDeclared => "credential scheme not declared for this claim",
        RefusalReason::CredentialRejected => "credential rejected",
        RefusalReason::SessionUnbound => "session is not bound",
        RefusalReason::Revoked => "principal's authority was revoked",
        RefusalReason::ScopeMissing => "principal lacks the required scope",
        RefusalReason::Vetoed => "operation vetoed",
        RefusalReason::NoDestination => "no destination available",
        RefusalReason::OverBudget => "principal is over its budget",
        RefusalReason::GroupFrozen => "principal's group is frozen",
        RefusalReason::Unpriced => "operation has no price and none is allowed",
        RefusalReason::OverdraftCeiling => "overdraft ceiling reached",
        RefusalReason::StaleSlice => "the node's bucket slice is stale",
        RefusalReason::DurabilityUnavailable => "the journal is unavailable",
        RefusalReason::TierMismatch => "bucket chain tier mismatch",
        RefusalReason::SpillBudget => "the node's spill budget is exhausted",
        RefusalReason::ArenaBudget => "the unit's working memory is exhausted",
        RefusalReason::RateLimited => "too many requests",
        RefusalReason::DecodeFailed => "the request could not be read",
        RefusalReason::ChallengeExhausted => "the authentication exchange was exhausted",
        RefusalReason::PoolNotPermitted => "principal may not use this pool",
        RefusalReason::NoRate => "the name supplied has no configured rate",
        RefusalReason::Replayed => "this request was already answered",
        RefusalReason::InFlight => "this request is still in flight",
        RefusalReason::DestinationBudgetExhausted => "the destination's request budget is spent",
        RefusalReason::BreakerOpen => "the destination is not accepting requests",
        RefusalReason::DestinationUnreachable => "the destination could not be reached",
        RefusalReason::MeterDisputed => "usage evidence disagrees",
        RefusalReason::HandoffMismatch => "the two legs of this request did not agree",
        RefusalReason::PlanePanic => "the request handler failed",
        RefusalReason::TaskLost => "the request was lost",
        RefusalReason::SecretPlaceholder => "a secret placeholder did not resolve",
        RefusalReason::Stalled => "the request made no progress",
        RefusalReason::Drain => "the node is draining",
        RefusalReason::Superseded => "a later request took this one's place",
        RefusalReason::ClientGone => "the client went away",
        RefusalReason::DeadlineExceeded => "the request ran past its deadline",
    }
}

/// Render the 1.5.5 admin error envelope for one refusal reason.
///
/// Byte-for-byte the shape `busbar-core`'s `err_json` renders: `{"error":{"code":"...",
/// "message":"..."}}`, with no other keys and no trailing whitespace. Built with `format!` rather
/// than a JSON library: the shape is two fixed keys and two string values this module already knows
/// are quote-safe (closed code strings; closed, comma/quote-free prose), so a dependency on a
/// serializer would buy nothing here that hand-formatting does not already give byte-for-byte.
#[must_use]
pub(crate) fn envelope(reason: RefusalReason) -> String {
    format!(
        r#"{{"error":{{"code":"{}","message":"{}"}}}}"#,
        code_for(reason),
        message_for(reason)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_shape_matches_the_1_5_5_error_contract() {
        let rendered = envelope(RefusalReason::ScopeMissing);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed.as_object().unwrap().len(), 1);
        let error = parsed.get("error").expect("error key").as_object().unwrap();
        assert_eq!(error.len(), 2);
        assert_eq!(error["code"], "forbidden");
        assert!(error["message"].is_string());
    }

    #[test]
    fn every_reason_maps_to_one_of_the_ten_frozen_codes() {
        const FROZEN_CODES: &[&str] = &[
            "not_found",
            "unauthorized",
            "method_not_allowed",
            "forbidden",
            "invalid_request",
            "version_conflict",
            "conflict",
            "rate_limited",
            "internal",
            "unavailable",
        ];
        let all = [
            RefusalReason::InFlightCap,
            RefusalReason::CursorBudget,
            RefusalReason::CredentialBudget,
            RefusalReason::SessionBudget,
            RefusalReason::BodyTooLarge,
            RefusalReason::OpenSlotBusy,
            RefusalReason::SchemeNotDeclared,
            RefusalReason::CredentialRejected,
            RefusalReason::SessionUnbound,
            RefusalReason::Revoked,
            RefusalReason::ScopeMissing,
            RefusalReason::Vetoed,
            RefusalReason::NoDestination,
            RefusalReason::OverBudget,
            RefusalReason::GroupFrozen,
            RefusalReason::Unpriced,
            RefusalReason::OverdraftCeiling,
            RefusalReason::StaleSlice,
            RefusalReason::DurabilityUnavailable,
            RefusalReason::TierMismatch,
            RefusalReason::SpillBudget,
            RefusalReason::ArenaBudget,
            RefusalReason::RateLimited,
            RefusalReason::DecodeFailed,
            RefusalReason::ChallengeExhausted,
            RefusalReason::PoolNotPermitted,
            RefusalReason::NoRate,
            RefusalReason::Replayed,
            RefusalReason::InFlight,
            RefusalReason::DestinationBudgetExhausted,
            RefusalReason::BreakerOpen,
            RefusalReason::DestinationUnreachable,
            RefusalReason::MeterDisputed,
            RefusalReason::HandoffMismatch,
            RefusalReason::PlanePanic,
            RefusalReason::TaskLost,
            RefusalReason::SecretPlaceholder,
            RefusalReason::Stalled,
            RefusalReason::Drain,
            RefusalReason::Superseded,
            RefusalReason::ClientGone,
            RefusalReason::DeadlineExceeded,
        ];
        // The whole closed set, not a sample of it: `code_for` matches exhaustively, so a reason
        // added to the contract fails to compile there and this count says the walk saw it too.
        assert_eq!(
            all.len(),
            42,
            "the contract's reason set changed and this walk did not"
        );
        for reason in all {
            assert!(
                FROZEN_CODES.contains(&code_for(reason)),
                "{reason:?} mapped to a code outside the frozen ten"
            );
        }
    }

    /// Every row of the ratified table is what the documentation says AND what the code does.
    ///
    /// The mapping is lossy on purpose and the table is where that is decided, so a row that exists
    /// in code and not in the table is a decision nobody agreed to — and a row in the table that
    /// `code_for` does not render is a promise to an operator that the wire breaks. Both directions
    /// are checked off the same twenty rows: the documented row is read out of this file's own
    /// source, and the rendered code is read out of `code_for` for the very same reason value.
    #[test]
    fn every_ratified_row_is_documented_and_rendered() {
        let source = include_str!("refusal.rs");
        let table = source
            .split("//! | `RefusalReason` | `code` | Why |")
            .nth(1)
            .expect("the ratified table is still in the module header");
        let rows = [
            (RefusalReason::InFlightCap, "rate_limited"),
            (RefusalReason::CursorBudget, "invalid_request"),
            (RefusalReason::CredentialBudget, "invalid_request"),
            (RefusalReason::SessionBudget, "unavailable"),
            (RefusalReason::BodyTooLarge, "invalid_request"),
            (RefusalReason::OpenSlotBusy, "conflict"),
            (RefusalReason::SchemeNotDeclared, "unauthorized"),
            (RefusalReason::CredentialRejected, "unauthorized"),
            (RefusalReason::SessionUnbound, "unauthorized"),
            (RefusalReason::Revoked, "forbidden"),
            (RefusalReason::ScopeMissing, "forbidden"),
            (RefusalReason::Vetoed, "forbidden"),
            (RefusalReason::NoDestination, "not_found"),
            (RefusalReason::OverBudget, "rate_limited"),
            (RefusalReason::GroupFrozen, "forbidden"),
            (RefusalReason::Unpriced, "invalid_request"),
            (RefusalReason::OverdraftCeiling, "rate_limited"),
            (RefusalReason::StaleSlice, "unavailable"),
            (RefusalReason::DurabilityUnavailable, "unavailable"),
            (RefusalReason::TierMismatch, "internal"),
            (RefusalReason::SpillBudget, "unavailable"),
            (RefusalReason::ArenaBudget, "unavailable"),
            (RefusalReason::RateLimited, "rate_limited"),
            (RefusalReason::DecodeFailed, "invalid_request"),
            (RefusalReason::ChallengeExhausted, "unauthorized"),
            (RefusalReason::PoolNotPermitted, "forbidden"),
            (RefusalReason::NoRate, "invalid_request"),
            (RefusalReason::Replayed, "conflict"),
            (RefusalReason::InFlight, "conflict"),
            (RefusalReason::DestinationBudgetExhausted, "unavailable"),
            (RefusalReason::BreakerOpen, "unavailable"),
            (RefusalReason::DestinationUnreachable, "unavailable"),
            (RefusalReason::MeterDisputed, "internal"),
            (RefusalReason::HandoffMismatch, "internal"),
            (RefusalReason::PlanePanic, "internal"),
            (RefusalReason::TaskLost, "internal"),
            (RefusalReason::SecretPlaceholder, "internal"),
            (RefusalReason::Stalled, "unavailable"),
            (RefusalReason::Drain, "unavailable"),
            (RefusalReason::Superseded, "conflict"),
            (RefusalReason::ClientGone, "conflict"),
            (RefusalReason::DeadlineExceeded, "unavailable"),
        ];
        assert_eq!(
            rows.len(),
            42,
            "the contract's reason set changed and this table did not"
        );
        for (reason, code) in rows {
            let row = format!("| `{reason:?}` | `{code}` |");
            assert!(
                table.contains(&row),
                "the ratified table has no row reading {row}"
            );
            assert_eq!(
                code_for(reason),
                code,
                "{reason:?} renders a code the ratified table does not promise"
            );
        }
    }
}
