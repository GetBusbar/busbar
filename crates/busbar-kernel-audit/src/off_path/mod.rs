// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT REQUEST-PATH MODULES' OFF-PATH CODE: what they need once per restore, per
//! configuration or per process lifecycle (a journal read back from durable storage, a signing key
//! loaded, a held run copied out for a restore), never per request. It sits outside the
//! request-path marker because it does not run per request; the request path only reads what it
//! built. Each submodule is named for the request-path module it builds for.

pub(crate) mod amend;
pub(crate) mod heads;

impl crate::record::Subject {
    /// A principal named by plain text: a line read back off durable storage, or one a recovery,
    /// an operator or a test states. Its name is made shared text here, once. A unit being sealed
    /// never comes through this: it shares the name its principal already holds.
    #[must_use]
    pub fn principal(id: &str) -> Self {
        Self::PrincipalId(busbar_contract::kept::Text::from(
            std::sync::Arc::<str>::from(id),
        ))
    }
}

/// Text read back off durable storage as shared text: the empty text costs nothing, as an empty
/// `String` did.
pub(crate) fn read_text(text: &str) -> busbar_contract::kept::Text {
    if text.is_empty() {
        busbar_contract::kept::Text::EMPTY
    } else {
        busbar_contract::kept::Text::from(std::sync::Arc::<str>::from(text))
    }
}
pub(crate) mod journal;
pub(crate) mod sign;
