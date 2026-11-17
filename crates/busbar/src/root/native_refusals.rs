// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's already-decided unitless reasons at an exact native route's rendering boundary.

use busbar_contract::caps::ReasonCode;
use busbar_kernel::refusal::ClientRefusal;

pub(crate) fn client(reason: ReasonCode, status: u16, text: &str) -> ClientRefusal {
    let _ = reason;
    ClientRefusal {
        code: busbar_plugin_abi::fail::refused::R_INVALID,
        status,
        text: text.to_owned().into(),
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
        let destination = client(ReasonCode::DestinationBudgetExhausted, 503, "destination spent");
        assert_eq!((destination.code, destination.status), (R_NO_ROUTE, 503));
    }
}
