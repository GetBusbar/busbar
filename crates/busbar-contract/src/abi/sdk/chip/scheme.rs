// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `<scheme> <credential>`: an HTTP `Authorization` value under a scheme the caller names (RFC 9110,
//! the Authorization field), the general form of [`Cred::bearer`].

use zeroize::Zeroizing;

use crate::abi::sdk::cred::{Cred, Seal};

impl Cred {
    /// `<scheme> <credential>`, or the bare `<scheme>` when the credential is empty (a scheme that
    /// carries no credential, or a caller that registered none). The scheme is written as given;
    /// checking that it is a token is the caller's.
    pub fn scheme(&self, scheme: impl AsRef<[u8]>) -> Seal {
        let scheme = scheme.as_ref();
        let mut v = Zeroizing::new(Vec::with_capacity(scheme.len() + 1 + self.len()));
        v.extend_from_slice(scheme);
        if !self.is_empty() {
            v.push(b' ');
            v.extend_from_slice(self.wire());
        }
        self.seal(v)
    }
}

#[cfg(test)]
#[path = "../tests/chip_scheme_tests.rs"]
mod tests;
