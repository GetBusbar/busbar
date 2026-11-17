// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// One axis of a hook manifest's declared intent — the SAME `no ⊂ ro ⊂ rw` ladder the operator
/// grant uses, so the core can compare "declared" against "granted" directly. `rw` is meaningful
/// only on the `prompt` axis (identity is never rewritten); on `user` it reads as "at least ro".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeedLevel {
    /// Declares no need for this content (the default).
    #[default]
    No,
    /// Asks to READ this content.
    Ro,
    /// Asks to read AND rewrite (prompt axis only).
    Rw,
}

impl NeedLevel {
    /// Whether the plugin declared it needs to READ this axis (`ro` or `rw`).
    #[must_use]
    pub fn wants_read(self) -> bool {
        !matches!(self, NeedLevel::No)
    }

    /// Whether the plugin declared it needs to REWRITE (prompt axis; `rw`).
    #[must_use]
    pub fn wants_rewrite(self) -> bool {
        matches!(self, NeedLevel::Rw)
    }
}

/// Cryptographic facts retained from the successful admission attempt. Declared publisher
/// names and unverified signature text never populate this proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verification {
    /// Canonical key id of the embedded root that authenticated the keys document.
    pub root: Option<String>,
    /// Canonical key ids of the actual satisfying artifact signers.
    pub signers: Vec<String>,
    /// Authenticated keys-document version, absent for configured bare signatures.
    pub keys_version: Option<u64>,
}
