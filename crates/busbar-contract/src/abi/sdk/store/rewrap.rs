// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Credential envelope maintenance over slot 8's existing keyed extensions and secret record.

use crate::records::CredentialSecret;
use zeroize::Zeroize;

/// Statement capability and input intent. The only supported value is `b"1"`.
pub const INTENT: &str = "busbar.store.credential-rewrap";
/// READY result, under an answer lease: `b"applied"` or `b"conflict"`.
pub const RESULT: &str = "busbar.store.credential-rewrap.result";

/// Deliberately disjoint from ordinary CredentialSecret JSON: an old SDK that ignores the
/// extension cannot decode this as a mint. Both envelope strings are zeroized on drop.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u8,
    pub expected: CredentialSecret,
    pub replacement: String,
}

impl Request {
    #[must_use]
    pub fn new(expected: &CredentialSecret, replacement: &str) -> Self {
        Self {
            version: 1,
            expected: expected.clone(),
            replacement: replacement.to_owned(),
        }
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRewrap")
            .field("version", &self.version)
            .field("expected", &self.expected)
            .field("replacement", &"<redacted>")
            .finish()
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.expected.secret.zeroize();
        self.replacement.zeroize();
    }
}
