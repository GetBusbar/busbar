// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST ON SIGHT, PLANE SIDE: the two shapes every plane that sights an upstream on the kernel's

/// The last contact with an upstream, over what a successful one observed (`O`). `Never` is not a
/// failure: an upstream nobody has looked at, or one approved declaratively, has legitimately never
/// been contacted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Sighting<O> {
    /// Never contacted.
    #[default]
    Never,
    /// The contact, or its verification, failed, with the operator-visible reason.
    Failed(String),
    /// Contacted (and verified, where the plane verifies), and this is what it presented.
    Seen(O),
}

impl<O> Sighting<O> {
    /// What the contact observed, when it succeeded.
    #[must_use]
    pub fn seen(&self) -> Option<&O> {
        match self {
            Self::Seen(o) => Some(o),
            _ => None,
        }
    }

    /// Why the last contact failed, when it did.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed(reason) => Some(reason),
            _ => None,
        }
    }
}

/// THE TRUST VIEW'S STATE WORD, derived on every read from the kernel's verdict and the last
/// sighting, so there is no stored state to go stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing is approved: nothing served.
    Pending,
    /// The approval holds against the last sighting (or nothing was sighted since). Serves.
    Approved,
    /// The last sighting differs from what was approved.
    Quarantined,
    /// The last contact failed.
    Error,
}

impl State {
    /// The wire word a UI branches on.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Approved => "approved",
            State::Quarantined => "quarantined",
            State::Error => "error",
        }
    }
}
