// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEP 1 — WHO IS CALLING.
//!
//! On this plane, today, that question is already answered by the time any plane code runs. The
//! HTTP auth middleware runs the configured chain and resolves the one verdict
//! (`busbar_core::auth::resolve_data_plane_identity`) before the request reaches a handler; what it
//! leaves behind is a [`busbar_api::PlaneRequestCtx`] carrying the resolved `Arc<VirtualKey>`, and
//! that context is the only thing the LLM ingress is handed about identity
//! (`native_ingress::operation_ingress_inner`'s `gov` parameter, and everything it threads on).
//!
//! So this step is a READ, not a decision, and saying so plainly is the point of the file. The
//! three shapes the middleware can leave are the three arms below:
//!
//! | the chain said | what the middleware leaves | what this step answers |
//! |---|---|---|
//! | identified, with a resolved or synthesized enforcement key | `gov.key = Some(key)` | `Principal(key.id)` |
//! | the open front door, or governance off | `gov.key = None` | `Principal(anonymous)` |
//! | denied, or a role principal that earned no grant | *the handler is never reached* | — |
//!
//! ## The closed refusal set is EMPTY, and that is a statement about where the 401 lives
//!
//! Every refusal this step could raise — `Unauthenticated`, `Revoked`, `SchemeNotDeclared`,
//! `ChallengeExhausted` — is raised UPSTREAM of the plane today, by the middleware, and rendered by
//! `busbar_core::auth::unauthorized_response`: the vendor-native 401 shaped by the dialect the path
//! resolves to, never a plane-shaped one. A request that reaches this step is a request the chain
//! already admitted, so there is no input to this function that can refuse, and inventing an arm
//! that could would be a SECOND door answering a question the first one already answered —
//! two 401 shapes for one condition.
//!
//! That is why this file renders nothing and refuses nothing. When the challenge round and the
//! revocation re-check move onto this seam, they arrive as `Authenticated::Challenge` and a
//! `Revoked` refusal respectively, and the table above grows a row; until they do, an empty refusal
//! set is the honest description of what the plane's authenticate step does.

use busbar_caps::{Authenticate, Authenticated, Decision, PrincipalId, UnitToken};

/// The actor id an unkeyed request is attributed to.
///
/// READ, never restated: it is what the live attribution accessor answers for the same absence
/// (`busbar_api::AuthPrincipal::actor_id` on a principal-less request), so the plane and the audit
/// row cannot come to different spellings of the anonymous caller. Spelling the word here instead
/// would be a second source for one fact.
fn anonymous_actor_id() -> &'static str {
    busbar_api::AuthPrincipal(None).actor_id()
}

/// Who this unit's caller is, read off the auth middleware's outcome.
///
/// Takes the step's own token and gives back the step's own answer, so this drops straight into the
/// composition root's authenticate seam. It cannot refuse — see the module docs — so the return is
/// always `Decision::proceed`, and the facts are always an established identity: this plane opens
/// no handshake unit, so the challenge arm is unreachable from here rather than unimplemented.
pub fn authenticate(
    token: &UnitToken<Authenticate>,
    gov: &busbar_api::PlaneRequestCtx,
) -> Decision<Authenticate> {
    Decision::proceed(
        token,
        // NO TIER ON THIS LEG, and it is a fact about the leg rather than a default. This is the
        // legacy authenticate step: it reads a governance handle directly and never resolves the
        // key's binding, so there is no tier here to seal. A leg that sealed one it had not
        // resolved would be inventing the caller's tier.
        Authenticated::Principal {
            id: principal_id(gov),
            tier: None,
        },
    )
}

/// The identity the rest of the loop attributes to, as the loop spells identities.
///
/// The keys arm and the open arm in one expression, because they are one expression on the live
/// path too: everything downstream of the middleware reads `gov.key`, treats `Some` as the
/// enforcement key and `None` as ungoverned, and attributes the latter to the anonymous actor.
/// Separated from [`authenticate`] so the mapping can be checked against the live read directly,
/// without a token in hand.
#[must_use]
pub fn principal_id(gov: &busbar_api::PlaneRequestCtx) -> PrincipalId {
    match gov.key() {
        Some(key) => PrincipalId::new(key.id.as_str()),
        None => PrincipalId::new(anonymous_actor_id()),
    }
}

#[cfg(test)]
#[path = "tests/authenticate.rs"]
mod tests;
