// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared wire bodies, neutral IR outcomes, usage faults and explicit host services.

use crate::bounded::SlabBytes;
use crate::json::Value;

/// An upstream response body a producer could not decode into its operation's IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The payload violates the selected codec's grammar or required shape.
    Malformed(String),
}

/// The translation cap a plane bounds a response's translation at when its settings name none:
/// 32 MiB, the host's own default for an unconfigured `limits.request_body_max_bytes`. The cap a
/// plane enforces is the one the kernel hands it in the settings it is opened and refreshed with
/// (`limits.request_body_max_bytes`), held in the plane's own state. The contract carries only this
/// default: there is no reader to install and no port a codec reads the cap through.
///
/// ```compile_fail
/// // The cap is no host port: a codec reads it from the plane's own settings.
/// let _ = busbar_contract::codec::max_translate_body_bytes();
/// ```
///
/// ```compile_fail
/// busbar_contract::codec::install_translate_cap_reader(|| 0);
/// ```
pub const TRANSLATE_BODY_MAX_BYTES_DEFAULT: usize = 32 * 1024 * 1024;
