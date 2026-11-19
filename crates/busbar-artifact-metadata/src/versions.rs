// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **Every ABI number, once.** The mechanism and the seven kinds each have exactly one version;
//! every `ABI_VERSION` / `MECHANISM_VERSION` constant elsewhere derives from this file. The seven
//! kind numbers are not kept here: each is busbar-plugin-abi's `versions::abi_of` (the call-shape
//! generation the loader admits and a native stamp carries), so the two can never disagree.
//!
//! A number means only "release generation". Development-time layout drift is the layout
//! fingerprint's job, not a bump here. `ci/abi.pin` holds the kind numbers with their
//! fingerprints.

use busbar_plugin_abi::types::KindCode;

/// One ABI generation. It is only ever equal or not equal: there is no ordering, so no code can
/// accept a range of versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiVersion(u32);

impl AbiVersion {
    /// The version a wire field (a manifest or index row's `abi_version`) states.
    #[must_use]
    pub const fn from_wire(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw wire value; ABI admission compares generations for equality only.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for AbiVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

/// The shared mechanism: v1.5.5 shipped 1 (`plugin-abi/src/lib.rs:71` `TRANSPORT_VERSION`).
pub const MECHANISM: AbiVersion = AbiVersion(2);
/// Store: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const STORE: AbiVersion = kind(KindCode::Store);
/// Secret: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const SECRET: AbiVersion = kind(KindCode::Secret);
/// Auth: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const AUTH: AbiVersion = kind(KindCode::Auth);
/// Hook: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const HOOK: AbiVersion = kind(KindCode::Hook);
/// Export: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const EXPORT: AbiVersion = kind(KindCode::Export);
/// Plane: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const PLANE: AbiVersion = kind(KindCode::Plane);
/// Transport: the call-shape number busbar-plugin-abi sets (`versions::abi_of`).
pub const TRANSPORT: AbiVersion = kind(KindCode::Transport);

/// A kind's one version: busbar-plugin-abi's `versions::abi_of`, the number a native stamp carries
/// and the loader admits. This file keeps no second table of kind numbers.
const fn kind(code: KindCode) -> AbiVersion {
    AbiVersion(busbar_plugin_abi::versions::abi_of(code))
}
