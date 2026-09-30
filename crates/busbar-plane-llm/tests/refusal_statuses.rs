// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's stated refusal reasons name the reasons they say they name.

use busbar_contract::abi::plane::reason_of;
use busbar_plane_llm::refusal::reason;

#[test]
fn every_stated_reason_code_is_the_reason_it_is_named_for() {
    for (code, spelling) in [
        (reason::UNAUTHENTICATED, "unauthenticated"),
        (reason::OVER_BUDGET, "over_budget"),
        (reason::DESTINATION_UNREACHABLE, "destination_unreachable"),
    ] {
        assert_eq!(
            reason_of(code).map(|r| r.as_str()),
            Some(spelling),
            "code {code}"
        );
    }
}
