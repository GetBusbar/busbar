// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `<scheme> <credential>`: an HTTP `Authorization` value under a scheme the caller names (RFC 9110,

use zeroize::Zeroizing;

use crate::abi::sdk::cred::{Cred, Seal};

impl Cred {
    /// `<scheme> <credential>`, or the bare `<scheme>` when the credential is empty (a scheme that
    pub fn scheme(&self, scheme: impl AsRef<[u8]>) -> Seal {
        let scheme = scheme.as_ref();
        // Exact size in one allocation (`concat`): the wiping buffer never grows (LR-117).
        let v = if self.is_empty() {
            Zeroizing::new(scheme.to_vec())
        } else {
            Zeroizing::new([scheme, b" ", self.wire()].concat())
        };
        self.seal(v)
    }
}

#[cfg(test)]
#[path = "../tests/chip_scheme_tests.rs"]
mod tests;
