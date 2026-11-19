// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The refusal and diagnostic text of the carrier, the host's I/O, the registry view, the
//! destination judge, the dialled association and the wire rule: built only when a refusal or a
//! failure is answered, out of line.

use std::fmt::Display;
/// The sentence of `value`, spelled only when a refusal or failure is answered.
#[cold]
pub(crate) fn display_text(value: &dyn Display) -> String {
    format!("{value}")
}

/// `prefix` and the sentence of `value`, spelled only when a refusal or failure is answered.
#[cold]
pub(crate) fn prefixed(prefix: &str, value: &dyn Display) -> String {
    format!("{prefix}{value}")
}
