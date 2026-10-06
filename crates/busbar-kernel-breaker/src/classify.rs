// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The breaker's reading of one answer, and the disposition it carries.
//!
//! THE BREAKER READS FACTS, NEVER A WIRE. What an answer means to the destination's health is the
//! transport's to state: a framer reads its own numbering against its own declared fault table and
//! puts the reading on the answer's frame (`FramePiece::fault`, read up as
//! [`WireFault`]). The kernel adds the one fact only it holds — that no answer came at all. This
//! module turns those two into the contract's [`Disposition`]; it holds no code band, no numbering
//! and no vendor's spelling, and it reads no body. What a body means (an operator's error map, a
//! request too large for the window) is the plane's verdict, and reaches the unit as the
//! [`crate::Outcome`] its caller observes.
//!
//! The four readings carry 1.5.5's four arms exactly: a hard reading is the old `HardDown` (every
//! pool's cell trips), a transient one the old `TransientUpstream` (the stated wait floors the
//! cooldown), a caller's or an unstated one the old `ClientFault` (nothing recorded), and no answer
//! at all the old network failure, which is transient.

/// The transport's fault reading, as the contract owns it.
pub use busbar_contract::transport::wire::WireFault;

/// The status class and the disposition, as the contract owns them. The class is kept here under
/// its historical path for the callers that name it beside the disposition.
pub use busbar_contract::upstream::{Disposition, StatusClass};

/// Convert an operator's class token to a [`StatusClass`]. `None` for anything unrecognized.
pub fn status_class_from_str(s: &str) -> Option<StatusClass> {
    StatusClass::parse(s)
}

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
///
/// An answer the transport stated no reading for is the caller's: inventing an outage from an
/// answer nobody read would trip a live destination on a framer that declares no fault table.
#[must_use]
pub const fn classify(reading: Reading) -> Disposition {
    match reading {
        Reading::NoAnswer => StatusClass::Network.disposition(),
        Reading::Answered(Some(WireFault::Hard)) => Disposition::HardDown,
        Reading::Answered(Some(WireFault::Transient)) => Disposition::TransientUpstream,
        Reading::Answered(Some(WireFault::Caller) | None) => Disposition::ClientFault,
    }
}
