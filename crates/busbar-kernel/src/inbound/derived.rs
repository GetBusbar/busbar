// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT ONE INBOUND UNIT DERIVED FROM ITS ORIGINAL HEAD, KEPT FOR EVERY LATER READER
//! (SINGLE-PATH SP-A1 / SP-AU1).
//!
//! A unit's original head is fixed once its first auth call (or its hand-in) records it, and the
//! unit pins one listener table for its whole life. So the plane admission, the `HeaderMap` and
//! the caller credential read from that head are the same answer every time they are asked for.
//! Each slot here is filled the first time a reader asks and read by reference after that; no
//! reader goes back to the raw head.
//!
//! Every accessor takes the head it derives from, and every caller passes the unit's original:
//! `UnitState::head` during the auth calls, `AdmittedRequest::original` after the claim (which is
//! the same head, or the handed head for a unit minted at hand-in, whose auth calls never ran).
//! A non-peer continuation call resolves its admission on its own stripped head through
//! [`Listener::admission_on`], which is not cached here because its input differs.

use super::{header_map, Head, Listener};
use crate::plane_driver::dispatch::PlaneAdmission;
use busbar_contract::redacted::Secret;
use std::sync::OnceLock;

/// The caller credential read once from the original head's carriers. Both of today's views are
/// kept, so the DPoP difference stays exact.
struct Carried {
    /// The inbound candidate's answer: a DPoP-bound token first (when this node is an OAuth
    /// authorization server), else the first carrier.
    candidate: Option<Secret<String>>,
    /// `extract_client_token`'s answer: the first carrier only.
    token: Option<zeroize::Zeroizing<String>>,
}

/// One unit's derived facts. Shared by the unit and, after the claim, its admitted request.
#[derive(Default)]
pub(crate) struct Derived {
    admission: OnceLock<Option<PlaneAdmission>>,
    headers: OnceLock<axum::http::HeaderMap>,
    carried: OnceLock<Carried>,
}

impl Derived {
    /// The plane admission (audience, resource metadata) for the unit's original head.
    pub(crate) fn admission(
        &self,
        listener: &Listener,
        original: &Head,
    ) -> Option<&PlaneAdmission> {
        self.admission
            .get_or_init(|| listener.admission(original))
            .as_ref()
    }

    /// The unit's original head as an HTTP header map; the one `header_map` build per unit.
    pub(crate) fn headers(&self, original: &Head) -> &axum::http::HeaderMap {
        self.headers.get_or_init(|| header_map(original))
    }

    fn carried(&self, app: &crate::state::App, original: &Head) -> &Carried {
        self.carried.get_or_init(|| {
            busbar_contract::stage_probe::tick(
                busbar_contract::stage_probe::Derive::CredentialExtract,
            );
            let headers = self.headers(original);
            Carried {
                candidate: crate::auth::candidate_of(app, headers),
                token: crate::auth::carried_credential(app.auth.carriers(), headers)
                    .map(zeroize::Zeroizing::new),
            }
        })
    }

    /// The inbound candidate credential (DPoP-preferring).
    pub(crate) fn candidate(
        &self,
        app: &crate::state::App,
        original: &Head,
    ) -> Option<&Secret<String>> {
        self.carried(app, original).candidate.as_ref()
    }

    /// The carried client token (carriers only), as `extract_client_token` reads it.
    pub(crate) fn client_token(&self, app: &crate::state::App, original: &Head) -> Option<&str> {
        self.carried(app, original)
            .token
            .as_deref()
            .map(String::as_str)
    }
}
