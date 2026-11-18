// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's already-decided unitless reasons at an exact native route's rendering boundary.

use busbar_contract::caps::ReasonCode;
use busbar_kernel::refusal::ClientRefusal;

/// The client refusal for `reason`. `text` is kept as it is given: a fixed word is lent for the
/// life of the process and a rendered message is moved in, so neither is copied here.
pub(crate) fn client(
    reason: ReasonCode,
    status: u16,
    text: impl Into<std::borrow::Cow<'static, str>>,
) -> ClientRefusal {
    use busbar_plugin_abi::fail::failed::{F_INTERNAL, F_TIMEOUT, F_UNAVAILABLE};
    use busbar_plugin_abi::fail::refused::{
        R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_BUDGET, R_INVALID, R_NOT_TRUSTED, R_NO_ROUTE,
        R_POLICY, R_RATE_LIMITED, R_REPLAYED,
    };
    let code = match reason {
        ReasonCode::OverBudget | ReasonCode::OverdraftCeiling => R_BUDGET,
        ReasonCode::RateLimited | ReasonCode::InFlightCap | ReasonCode::InFlight => R_RATE_LIMITED,
        ReasonCode::SessionUnbound => R_AUTH_REQUIRED,
        ReasonCode::Unauthenticated
        | ReasonCode::SchemeNotDeclared
        | ReasonCode::ChallengeExhausted
        | ReasonCode::Revoked => R_BAD_CREDENTIAL,
        ReasonCode::ScopeDenied
        | ReasonCode::PoolNotPermitted
        | ReasonCode::HookVeto
        | ReasonCode::GroupFrozen => R_POLICY,
        ReasonCode::Untrusted => R_NOT_TRUSTED,
        ReasonCode::Replayed => R_REPLAYED,
        ReasonCode::NoDestination
        | ReasonCode::DestinationBudgetExhausted
        | ReasonCode::BreakerOpen
        | ReasonCode::DestinationUnreachable
        | ReasonCode::CredentialUnavailable => R_NO_ROUTE,
        ReasonCode::Stalled | ReasonCode::DeadlineExceeded => F_TIMEOUT,
        ReasonCode::MeterDisputed
        | ReasonCode::HandoffMismatch
        | ReasonCode::PlanePanic
        | ReasonCode::TaskLost
        | ReasonCode::SecretPlaceholder
        | ReasonCode::Internal => F_INTERNAL,
        ReasonCode::SessionBudget
        | ReasonCode::SpillBudget
        | ReasonCode::ScratchExhausted
        | ReasonCode::OpenSlotBusy
        | ReasonCode::StaleSlice
        | ReasonCode::DurabilityUnavailable
        | ReasonCode::TierMismatch
        | ReasonCode::Drain
        | ReasonCode::ClientGone => F_UNAVAILABLE,
        ReasonCode::CursorBudget
        | ReasonCode::CredentialBudget
        | ReasonCode::BodyTooLarge
        | ReasonCode::DecodeFailed
        | ReasonCode::NoRate
        | ReasonCode::Unpriced
        | ReasonCode::Superseded
        | ReasonCode::MethodNotAllowed => R_INVALID,
    };
    // The actual core request status/text remains authoritative for request-specific decisions
    // (413, NoRate400, upstream availability503). Monetary and replay semantics have native
    // generic defaults; the selected plane alone applies its caller-dialect override.
    let status = match code {
        R_BUDGET => 402,
        R_REPLAYED => 409,
        _ => status,
    };
    ClientRefusal {
        code,
        status,
        text: text.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::fail::refused::{R_BUDGET, R_INVALID, R_NO_ROUTE, R_RATE_LIMITED};

    #[test]
    fn money_capacity_and_root_request_errors_keep_distinct_meanings() {
        let money = client(ReasonCode::OverBudget, 429, "spend cap");
        assert_eq!((money.code, money.status), (R_BUDGET, 402));
        let capacity = client(ReasonCode::RateLimited, 429, "capacity");
        assert_eq!((capacity.code, capacity.status), (R_RATE_LIMITED, 429));
        for (reason, status) in [
            (ReasonCode::DecodeFailed, 400),
            (ReasonCode::BodyTooLarge, 413),
            (ReasonCode::CredentialBudget, 413),
            (ReasonCode::NoRate, 400),
        ] {
            let request = client(reason, status, "core request explanation");
            assert_eq!((request.code, request.status), (R_INVALID, status));
            assert_eq!(request.text, "core request explanation");
        }
        let destination = client(
            ReasonCode::DestinationBudgetExhausted,
            503,
            "destination spent",
        );
        assert_eq!((destination.code, destination.status), (R_NO_ROUTE, 503));
    }
}
