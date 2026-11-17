// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Metadata from the root's admitted image proof, without request or credential authority.

/// A missing digest identifies a compiled linked image, fixed for this process lifetime.
/// Root obtains both values from the same admitted image retained by the actual native seat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaneImageIdentity {
    canonical: Box<str>,
    digest: Option<[u8; 32]>,
}

impl PlaneImageIdentity {
    pub fn new(canonical: Box<str>, digest: Option<[u8; 32]>) -> Result<Self, &'static str> {
        if canonical.is_empty() || canonical.chars().any(char::is_control) {
            return Err("selected route requires the admitted image's canonical identity");
        }
        Ok(Self { canonical, digest })
    }

    pub fn compatible_with(&self, current: &Self) -> bool {
        self == current
    }
}
