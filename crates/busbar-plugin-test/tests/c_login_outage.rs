// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LOGIN-OUTAGE (ABI-MIN3-INTERFACE §14): Login outages render the hosted 503 page with Retry-After (L5 + K8).
//! The auth-github and auth-oidc arms run in their repos.
//!
//! W1-K8B's arm is the one mapping of a login port error onto `LoginOutcome`
//! (`busbar_kernel::auth::login_facts::login_failure`). The pages each outcome renders, and the Retry-After clamp
//! (stated value clamped to 1..=3600, default 5), are hosted_login's unchanged code and goldens
//! (busbar-core-oauth2 tests/hosted_login_tests.rs); the end-to-end arm through a login port is the switch-over's.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_contract::auth::LoginOutcome;
use busbar_kernel::auth::login_facts::login_failure;
use busbar_plugin_abi::auth::{BAD_CREDENTIAL, SECURITY_CHECK};
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_loader::ports::PortError;

fn failed(retry_after_s: Option<u64>) -> PortError {
    PortError::Failed {
        code: 0x10,
        text: "provider unreachable".into(),
        retry_after_s,
        backend_status: Some(503),
        error: None,
    }
}

fn refused(code: u32) -> PortError {
    PortError::Refused {
        code,
        text: "declined".into(),
        error: None,
    }
}

#[test]
fn login_failures_map_to_outage_security_check_and_declined() {
    for stated in [Some(120), Some(9_999), None] {
        assert_eq!(
            login_failure(&failed(stated)),
            LoginOutcome::Outage {
                retry_after_secs: stated
            },
            "FAILED carries the provider's Retry-After as stated; the page clamps it"
        );
    }
    assert_eq!(
        login_failure(&PortError::Call(CallError::Deadline)),
        LoginOutcome::Outage {
            retry_after_secs: None
        }
    );
    assert_eq!(
        login_failure(&PortError::Call(CallError::Quarantined)),
        LoginOutcome::Outage {
            retry_after_secs: None
        }
    );
    assert_eq!(
        login_failure(&refused(SECURITY_CHECK)),
        LoginOutcome::SecurityCheckFailed
    );
    assert_eq!(
        login_failure(&refused(BAD_CREDENTIAL)),
        LoginOutcome::Reject
    );
}

#[test]
#[ignore = "owner: W2-SW-AUTH; re-checked 2026-11-16: the hosted page driven through a login port (draft MR !2481, IF gap in OUTSTANDING section B; the auth port needs the redesign ruled 2026-11-16 ~21:30Z)"]
fn login_outage_pages() {
    todo!("owner: W2-SW-AUTH (C-LOGIN-OUTAGE end-to-end arm)")
}
