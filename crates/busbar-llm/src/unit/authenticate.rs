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
    Decision::proceed(token, Authenticated::Principal(principal_id(gov)))
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
mod tests {
    use super::*;
    use busbar_caps::{KernelSeal, StepName};

    /// A key row carrying only what this step reads. Every other field is what the store's own
    /// default row carries, so the fixture cannot drift from the shape the middleware resolves.
    fn key(id: &str) -> std::sync::Arc<busbar_api::VirtualKey> {
        std::sync::Arc::new(busbar_api::VirtualKey {
            id: id.to_string(),
            enabled: true,
            ..Default::default()
        })
    }

    fn governed(id: &str) -> busbar_api::PlaneRequestCtx {
        busbar_api::PlaneRequestCtx { key: Some(key(id)) }
    }

    fn ungoverned() -> busbar_api::PlaneRequestCtx {
        busbar_api::PlaneRequestCtx { key: None }
    }

    /// IDENTITY — the keys arm. The live path attributes a governed request to the resolved key's
    /// id (`gov.key.as_ref()`, threaded into the usage sink and every accrual on it); the step
    /// answers with the SAME id, on the same input.
    #[test]
    fn the_keys_arm_names_the_resolved_key_and_the_live_read_names_it_too() {
        let seal = KernelSeal::acquire_for_kernel();
        let gov = governed("vk_live_key");

        let live = gov.key().map(|k| k.id.clone()).expect("governed");
        let stepped = super::authenticate(&UnitToken::<Authenticate>::mint(&seal), &gov)
            .into_result(&seal)
            .expect("the plane's authenticate step never refuses");

        let Authenticated::Principal(p) = stepped else {
            panic!("this plane opens no handshake unit, so the challenge arm is unreachable")
        };
        assert_eq!(p.as_str(), live);
        assert_eq!(p.as_str(), "vk_live_key");
    }

    /// IDENTITY — the open arm. With no key the live surfaces attribute to the anonymous actor;
    /// the step answers with the same word, taken from the same accessor rather than retyped.
    #[test]
    fn the_open_arm_names_the_same_anonymous_actor_the_live_attribution_names() {
        let seal = KernelSeal::acquire_for_kernel();
        let gov = ungoverned();

        let live = busbar_api::AuthPrincipal(None).actor_id().to_string();
        let stepped = super::authenticate(&UnitToken::<Authenticate>::mint(&seal), &gov)
            .into_result(&seal)
            .expect("the plane's authenticate step never refuses");

        let Authenticated::Principal(p) = stepped else {
            panic!("this plane opens no handshake unit, so the challenge arm is unreachable")
        };
        assert_eq!(p.as_str(), live);
        assert_eq!(p.as_str(), "anonymous");
    }

    /// THE CLOSED REFUSAL SET IS EMPTY. Not a claim in a comment: over every shape the middleware
    /// can leave behind, the step proceeds. A future arm that refuses here has to change this test,
    /// which is exactly the review the second 401 door deserves.
    #[test]
    fn no_input_the_middleware_can_leave_makes_this_step_refuse() {
        let seal = KernelSeal::acquire_for_kernel();
        for gov in [ungoverned(), governed("vk_a"), governed("group:ops")] {
            let d = super::authenticate(&UnitToken::<Authenticate>::mint(&seal), &gov);
            assert!(
                d.into_result(&seal).is_ok(),
                "the 401 is the middleware's; this step raises none"
            );
        }
    }

    /// The step this file answers is the step the loop asks it, and the answer is stamped with it.
    /// Cheap, and it is what makes a copy-paste of this body into a neighbouring step file fail to
    /// compile rather than mis-stamp a record.
    #[test]
    fn the_answer_is_stamped_with_this_step() {
        assert_eq!(
            <Authenticate as busbar_caps::Step>::NAME,
            StepName::Authenticate
        );
        // A step whose token the kernel keeps to itself is never asked of a unit at all; this one
        // is, which is what makes the file above reachable.
        const { assert!(!<Authenticate as busbar_caps::Step>::KERNEL_OWNED) };
    }
}
