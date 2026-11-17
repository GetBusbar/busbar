// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **Every ABI number, once.** The mechanism and the seven kinds each have exactly one version
//! here; every `ABI_VERSION` / `MECHANISM_VERSION` constant elsewhere derives from this file.
//!
//! A number means only "release generation": each is its v1.5.5 value plus one (plane and
//! transport are new at 1). Development-time layout drift is the layout fingerprint's job, not a
//! bump here. `tests/abi_versions.rs` holds the v1.5.5 baselines, and busbar-release
//! `ci/abi.pin` holds these numbers outside this repository.

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
/// Store: v1.5.5 shipped 2 (`plugin-abi/src/lib.rs:128`).
pub const STORE: AbiVersion = AbiVersion(3);
/// Secret: v1.5.5 shipped 1 (`plugin-abi/src/lib.rs:379`).
pub const SECRET: AbiVersion = AbiVersion(2);
/// Auth: v1.5.5 shipped 2 (`plugin-abi/src/lib.rs:395`).
pub const AUTH: AbiVersion = AbiVersion(3);
/// Hook: v1.5.5 shipped 1 (`plugin-abi/src/hook.rs:38`).
pub const HOOK: AbiVersion = AbiVersion(2);
/// Export: v1.5.5 shipped 2 (`plugin-abi/src/export.rs:36`).
pub const EXPORT: AbiVersion = AbiVersion(3);
/// Plane: new since v1.5.5.
pub const PLANE: AbiVersion = AbiVersion(1);
/// Transport: new since v1.5.5.
pub const TRANSPORT: AbiVersion = AbiVersion(1);
