// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The mechanism and per-kind ABI numbers and the engine version (IF §7.3).

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
pub const ENGINE: EngineVersion = EngineVersion {
    major: number(env!("CARGO_PKG_VERSION_MAJOR")),
    minor: number(env!("CARGO_PKG_VERSION_MINOR")),
    patch: number(env!("CARGO_PKG_VERSION_PATCH")),
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

/// One version component of the package version as a u16; a non-digit or a value past u16 fails the build.
const fn number(digits: &str) -> u16 {
    let bytes = digits.as_bytes();
    assert!(!bytes.is_empty(), "an empty package version component");
    let mut value: u16 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        assert!(
            digit.is_ascii_digit(),
            "a package version component is decimal"
        );
        value = value * 10 + (digit - b'0') as u16;
        i += 1;
    }
    value
}
