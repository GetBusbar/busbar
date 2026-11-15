// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The mechanism and per-kind ABI numbers and the engine version (IF §7.3). W0-ABI stub: frozen signatures, `todo!()` bodies; A1 fills it.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::types::KindCode;

/// AGREED §4: each number is its 1.5.5 value + 1. Exact match, no ranges. A bump is an owner-signed test edit.
pub const MECHANISM: u32 = 2;
pub const STORE: u32 = 3;
pub const SECRET: u32 = 2;
pub const AUTH: u32 = 3;
pub const HOOK: u32 = 2;
pub const EXPORT: u32 = 3;
pub const PLANE: u32 = 1;
pub const TRANSPORT: u32 = 1;
/// The engine version, which is this crate's package version.
// W0-ABI stub value (this crate's version, 1.6.0, written out); A1 sets it from the package version.
pub const ENGINE: EngineVersion = EngineVersion {
    major: 1,
    minor: 6,
    patch: 0,
    _reserved: 0,
};
#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct EngineVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub _reserved: u16,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AbiVersion {
    pub kind: KindCode,
    pub version: u32,
}
impl AbiVersion {
    pub const fn current(kind: KindCode) -> Self {
        AbiVersion {
            kind,
            version: kind.abi(),
        }
    }
    pub const fn accepts(self, have: u32) -> bool /* == */ {
        have == self.version
    }
}
