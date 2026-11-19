// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S ANSWER VALIDATORS, beside the shapes they judge: one pure `check_<op>` per

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::Tail;
use crate::abi::mechanism::check::{fault, listed};
use crate::export_stream::ExportStream;

/// The most routes one export instance may declare.
pub const HARD_MAX_ROUTES: u64 = 64;

/// Validates the export Statement tail's lists, before any entry is read: a count never comes
pub fn check_tail(t: &Tail) -> Result<(), Fault> {
    listed(t.streams, t.streams_len, "tail.streams")?;
    if t.streams_len as u64 > ExportStream::ALL.len() as u64 {
        return Err(fault(Rule::OverMax, "tail.streams_len"));
    }
    listed(t.routes, t.routes_len, "tail.routes")?;
    if t.routes_len as u64 > HARD_MAX_ROUTES {
        return Err(fault(Rule::OverMax, "tail.routes_len"));
    }
    Ok(())
}
