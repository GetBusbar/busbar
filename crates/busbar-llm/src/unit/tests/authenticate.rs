//! Tests for `authenticate.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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

    let Authenticated::Principal { id: p, .. } = stepped else {
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

    let Authenticated::Principal { id: p, .. } = stepped else {
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
