// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Charging the image for a once rule core finds (IF §8.6, PLANE-DRIVER.md slice 2): a second or late FORWARD, a
//! to-client item out of place, a USAGE the session may not keep. The loader already handles what its own decode
//! finds as a FAULT (the instance quarantined, `plugin_fault` audited); a break only core can see is handed to the
//! port's one `charge` entry, which does the same. What is core's own doing (a record that did not read back) and
//! what the port already handled (`SessionError::Port`) charges nothing.

use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_loader::ports::plane::PlanePort;

use super::port_session::{SessionError, Violation};

/// The fault a violation is charged as; `None` for a violation that is core's own.
#[must_use]
pub fn fault_of(violation: &Violation) -> Option<FaultReason> {
    match violation {
        Violation::BadRecords => None,
        Violation::SecondForward
        | Violation::LateForward
        | Violation::ForwardOutOfPlace(_)
        | Violation::AfterEnd
        | Violation::Usage(_)
        | Violation::AttemptOutOfPlace(_)
        | Violation::AttemptWithResponse
        | Violation::BadAttempt
        | Violation::BadAudit
        | Violation::UpstreamOutOfPlace(_)
        | Violation::BadExchange
        | Violation::MissingExchange
        | Violation::IntentStorm
        | Violation::BadJudge => Some(FaultReason::OnceRule),
    }
}

/// Charges `port`'s image when `error` is a once rule the plane broke. Answers whether it did.
pub fn charge(port: &dyn PlanePort, error: &SessionError) -> bool {
    let SessionError::Violation(violation) = error else {
        return false;
    };
    let Some(reason) = fault_of(violation) else {
        return false;
    };
    tracing::error!(
        ?violation,
        "a plane broke a once rule: its image is charged"
    );
    port.charge(reason);
    true
}

#[cfg(test)]
#[path = "tests/port_charge_tests.rs"]
mod tests;
