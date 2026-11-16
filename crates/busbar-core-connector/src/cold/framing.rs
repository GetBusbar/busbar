// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold text for the framing modules (`compose`, `framer`, `framed_stream`): the refusal and fault
//! text a connection, a framing or a framed stream keeps when it refuses or fails, built out of line.
//! Nothing here runs unless the request path is already refusing or failing.

use std::fmt;

use busbar_contract::abi::mechanism::call::Outcome;

use crate::compose::Failure;
use crate::framer::Refused;

/// An error's own text, kept owned by the failure that carries it.
#[cold]
pub(crate) fn display(e: &dyn fmt::Display) -> String {
    format!("{e}")
}

/// A framer answer refused with `outcome` and the text `args`.
#[cold]
pub(crate) fn refusal(outcome: Outcome, args: fmt::Arguments<'_>) -> Refused {
    Refused {
        outcome,
        error: fmt::format(args),
    }
}

/// A framer answer that broke the contract: a FAULT with the text `args`.
#[cold]
pub(crate) fn fault(args: fmt::Arguments<'_>) -> Refused {
    refusal(Outcome::Fault, args)
}

/// A connection refused, with the text `args`.
#[cold]
pub(crate) fn refused(args: fmt::Arguments<'_>) -> Failure {
    Failure::Refused(fmt::format(args))
}

/// A connection failed, with the text `args`.
#[cold]
pub(crate) fn failed(args: fmt::Arguments<'_>) -> Failure {
    Failure::Failed(fmt::format(args))
}

/// `bytes` that are not UTF-8, as text with each bad sequence replaced (a refusal's text).
#[cold]
pub(crate) fn lossy(bytes: &[u8]) -> String {
    format!("{}", String::from_utf8_lossy(bytes))
}

/// A failed handshake or record: the text connection security keeps (a dialled refusal explained,
/// an accepted one in the stack's own words) and the refusal the connection fails with.
#[cold]
pub(crate) fn tls_failure(e: &rustls::Error, dialled: bool) -> (String, Failure) {
    let text = if dialled {
        crate::tls::explain::handshake_refusal(e)
    } else {
        e.to_string()
    };
    let refusal = Failure::Refused(format!("tls: {text}"));
    (text, refusal)
}
