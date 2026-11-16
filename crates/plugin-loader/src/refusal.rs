// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's one refusal type (IF §4.3). W0-ABI stub: frozen signatures, `todo!()` bodies; L1 fills it.

/// One refusal, printed as r10 §4.1, audited as `plugin.compat` rejected (r10 §4.3), diagnostic BUSBAR-6013
/// unless the code says otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: RefusalCode,
    /// The field or check that failed ("kind_abi", "layout", "crypto", "manifest.version", ...).
    pub field: &'static str,
    /// The verified stamp name once decoded, else the manifest name if it passes valid_name, else None.
    pub plugin: Option<String>,
    pub have: String,
    pub want: String,
    /// https://getbusbar.com/plugins/n/<name>?engine=<x.y.z>&target=<target>, when a name is known.
    pub link: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    Integrity,
    Signature,
    StampMissing,
    StampAmbiguous,
    StampMalformed {
        byte: u32,
        rule: &'static str,
    },
    KindUnknown,
    KindAbi,
    Mechanism,
    Layout,
    Semantic,
    Target,
    EngineRange,
    Crypto,
    ManifestMismatch,
    DoorStampMismatch,
    ImageBounds,
    DescribeInvalid,
    CapUnknown,
    OutOfProcessUnavailable,
    LocalBuild,
    Superseded,
    /// Round 9: a `former_names` word equals another admitted plugin's identity or word (`Registry::add`;
    /// field "former_names", have = the word, want = a word no other admitted plugin answers to).
    NameConflict,
    // Round 28: the publisher-check variant and its 10 codes are deleted (AGREED 118): admit has no such check,
    // and a plugin that refuses on its own terms does so inside its own `open` (§16.183).
}

impl Refusal {
    // "BUSBAR-6013" for every code (round 28)
    pub fn diagnostic(&self) -> &'static str {
        "BUSBAR-6013"
    }
}

impl core::fmt::Display for Refusal {
    // the r10 §4.1 line, byte for byte
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let _ = f;
        todo!()
    }
}

#[cfg(test)]
#[path = "tests/refusal_tests.rs"]
mod tests;
