// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stamp scan, moved from the abi (IF §7.4, §11.1), and the error-code identity grammar (round 34, §50).
//! W0-ABI stub: frozen signatures, `todo!()` bodies; L1 fills it.

use busbar_plugin_abi::stamp::Stamp;

// W0-ABI: the IF names `StampScanErr` (§7.4) but never defines it; the stub aliases it to the three stamp
// refusals it carries (`RefusalCode::{StampMissing, StampAmbiguous, StampMalformed}`, r10 step 3). L1 settles
// the type with the lead designer.
pub type StampScanErr = crate::refusal::RefusalCode;

// `scan` (find exactly one stamp in image bytes and validate every field, r10 step 3); its only callers are
// admit and pack (IF §7.4).
pub fn stamp(image: &[u8]) -> Result<Stamp, StampScanErr> {
    let _ = image;
    todo!()
}

/// Round 34 (PLUGIN-ERROR-CODES §2.2; `scan.rs`, L1). The identity grammar for an image that declares D_ERRORS:
/// the stamp `name` bytes before the first NUL match `^[a-z][a-z0-9-]{0,63}$` and do not end in `-` (so ≤ 64
/// bytes). On a compiled-in image no name rule has run before this (`admit_linked` has no manifest, and the
/// stamp may come from a `CARGO_PKG_NAME` holding `_`), so `Registry::add` calls it on both load paths. The fault
/// names the position or length only, never a byte: `BadChar { byte }` → "bad character at byte N", `Length
/// { len }` → "length L > 64" (also `Empty`, `TrailingDash`). Admission is unchanged: no new `RefusalCode`; an
/// image without D_ERRORS is never checked (a digit-led or `_` name stays valid; it simply has no codes).
pub fn error_identity(name: &[u8; 64]) -> Result<&str, IdentityFault> {
    let _ = name;
    todo!()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFault {
    Empty,
    BadChar { byte: u32 },
    Length { len: u32 },
    TrailingDash,
}

#[cfg(test)]
#[path = "tests/scan_tests.rs"]
mod tests;
