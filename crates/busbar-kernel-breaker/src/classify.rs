// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The breaker's reading of one answer, and the disposition it carries.

/// The transport's fault reading, as the contract owns it.
pub use busbar_contract::transport::wire::WireFault;

/// The disposition, as the contract owns it: what [`classify`] answers.
pub use busbar_contract::upstream::Disposition;

use busbar_contract::upstream::StatusClass;

/// What the breaker knows about one attempt's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// No answer came: the destination refused or reset the connection, or the attempt ended with
    /// nothing read. The kernel's own fact, and a failure OF the destination.
    NoAnswer,
    /// An answer came, and the transport read it so (`None`: it stated no reading).
    Answered(Option<WireFault>),
}

/// The disposition one [`Reading`] carries.
#[must_use]
pub const fn classify(reading: Reading) -> Disposition {
    match reading {
        Reading::NoAnswer => StatusClass::Network.disposition(),
        Reading::Answered(Some(WireFault::Hard)) => Disposition::HardDown,
        Reading::Answered(Some(WireFault::Transient)) => Disposition::TransientUpstream,
        Reading::Answered(Some(WireFault::Caller | WireFault::Healthy) | None) => {
            Disposition::ClientFault
        }
    }
}
