// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mandatory opaque persistence primitives and their shared output buffer.
pub mod v4;
use crate::abi::mechanism::decl::abi_struct;
pub use v4::{ABI_VERSION, LAYOUT_FINGERPRINT};
abi_struct! {
    /// A caller-owned initialized byte allocation. Native code never retains this pointer.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct HostBuf {
        /// Null only when capacity is zero.
        pub ptr: *mut u8,
        /// Allocation capacity in bytes.
        pub cap: usize,
    }
}
/// Cancellation cannot prove that a submitted commit did not apply.
pub const CANCEL_UNKNOWN: u32 = 0;
/// Diagnostic for reuse of a logical operation identity with a different body.
pub const DIAG_OPID_CONFLICT: &str = "STORE_OPID_CONFLICT";
/// Caller-side retry give-up horizon still read by five kernel retry owners
/// (host records, governance recovery, ledger correction, exact debt, metering flush).
/// Store COMMIT dedupe no longer depends on it: slot rows never expire.
pub const OP_ID_RETENTION_SECS: u64 = 24 * 60 * 60;
