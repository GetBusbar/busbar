//! Tests for `verify.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_caps::{KernelSeal, StepName};

/// A deployment, as the guards see one.
#[derive(Default)]
struct View {
    keyed: bool,
    scopes: Option<Vec<String>>,
    fallbacks: Vec<(String, String)>,
    configured: Vec<String>,
    card: bool,
    priced_names: Vec<String>,
}

impl PoolView for View {
    fn has_key(&self) -> bool {
        self.keyed
    }
    fn key_is_scoped(&self) -> bool {
        self.scopes.is_some()
    }
    fn pool_allowed(&self, pool: &str) -> bool {
        match &self.scopes {
            None => true,
            Some(list) => list.iter().any(|s| s == pool),
        }
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.fallbacks
            .iter()
            .find(|(from, _)| from == pool)
            .map(|(_, to)| to.clone())
    }
    fn is_configured(&self, name: &str) -> bool {
        self.configured.iter().any(|c| c == name)
    }
    fn pricing_enabled(&self) -> bool {
        self.card
    }
    fn is_unpriced(&self, name: &str) -> bool {
        self.card && !self.priced_names.iter().any(|p| p == name)
    }
}

/// The bytes a refusal leaves, built the way the live doors build them. Used only to compare the
/// step's named refusal against the live envelope; nothing in this directory returns one.
fn envelope(status: u16, kind: &str, message: &str) -> (u16, Vec<u8>) {
    let code = axum::http::StatusCode::from_u16(status).expect("a status the doors emit");
    let resp = busbar_substrate::proxy::ingress_error(
        crate::proto_codec::PROTO_OPENAI,
        code,
        kind,
        message,
    );
    let status = resp.status().as_u16();
    let body = futures::executor::block_on(async {
        use http_body_util::BodyExt;
        resp.into_body()
            .collect()
            .await
            .expect("an in-memory error body")
            .to_bytes()
            .to_vec()
    });
    (status, body)
}

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

/// IDENTITY — guard one. The live door answers a pool the key may not reach with
/// `ingress_error(proto, FORBIDDEN, KIND_PERMISSION, "Your API key does not have permission to
/// access this resource.")`. The step names a refusal that renders to the same bytes.
#[test]
fn the_pool_acl_refusal_is_the_live_403_byte_for_byte() {
    let view = View {
        keyed: true,
        scopes: Some(vec!["allowed".into()]),
        ..Default::default()
    };
    let refusal = destination_guard(&view, "denied").expect_err("the key may not reach it");

    let live = envelope(
        403,
        crate::engine::KIND_PERMISSION,
        "Your API key does not have permission to access this resource.",
    );
    let stepped = envelope(refusal.status(), refusal.kind(), &refusal.message());
    assert_eq!(stepped, live);
    assert_eq!(refusal.reason(), ReasonCode::PoolNotPermitted);
}

/// IDENTITY — guard two. A key restricted to A, reaching A, whose `on_exhausted` names B: the
/// live door refuses with the SAME 403 as guard one, so a denial cannot be told from outside
/// whether it tripped on the requested pool or on a fallback. Same bytes here.
#[test]
fn a_fallback_pool_the_key_may_not_reach_is_the_same_403_as_the_requested_one() {
    let view = View {
        keyed: true,
        scopes: Some(vec!["a".into()]),
        fallbacks: vec![("a".into(), "b".into())],
        ..Default::default()
    };
    let refusal = destination_guard(&view, "a").expect_err("a falls over to b, and b is denied");
    assert_eq!(refusal, VerifyRefusal::NotAuthorized);

    let live = envelope(
        403,
        crate::engine::KIND_PERMISSION,
        "Your API key does not have permission to access this resource.",
    );
    assert_eq!(
        envelope(refusal.status(), refusal.kind(), &refusal.message()),
        live
    );
}

/// IDENTITY — guard three. The live door answers an unbillable name with
/// `ingress_error(proto, BAD_REQUEST, KIND_INVALID_REQUEST, "no configured rate for model
/// '<name>'")`, naming the model the caller asked for.
#[test]
fn an_unpriced_name_is_the_live_400_byte_for_byte() {
    let view = View {
        keyed: true,
        card: true,
        priced_names: vec!["gpt-priced".into()],
        ..Default::default()
    };
    let refusal = destination_guard(&view, "made-up").expect_err("a card is present");

    let live = envelope(
        400,
        crate::engine::KIND_INVALID_REQUEST,
        "no configured rate for model 'made-up'",
    );
    assert_eq!(
        envelope(refusal.status(), refusal.kind(), &refusal.message()),
        live
    );
    assert_eq!(refusal.reason(), ReasonCode::NoRate);
}

/// THE ORDER. A deployment that trips guard one AND guard three answers with guard one's
/// refusal — the permission answer is settled before pricing is asked about at all. Reversing
/// the two would tell an unauthorized caller which names this deployment prices.
#[test]
fn the_pool_acl_answers_before_the_pricing_gate_does() {
    let view = View {
        keyed: true,
        scopes: Some(vec!["allowed".into()]),
        card: true,
        ..Default::default()
    };
    assert_eq!(
        destination_guard(&view, "denied-and-unpriced"),
        Err(VerifyRefusal::NotAuthorized)
    );
}

/// A fallback chain that cycles terminates, and on the same reason the dispatch terminates on.
#[test]
fn a_cyclic_fallback_chain_terminates_instead_of_walking_forever() {
    let view = View {
        keyed: true,
        scopes: Some(vec!["a".into(), "b".into()]),
        fallbacks: vec![("a".into(), "b".into()), ("b".into(), "a".into())],
        ..Default::default()
    };
    assert_eq!(destination_guard(&view, "a"), Ok(()));
}

/// With no key every guard is inert — the ungoverned posture, unchanged.
#[test]
fn an_unkeyed_request_passes_every_guard() {
    let view = View {
        card: true,
        ..Default::default()
    };
    assert_eq!(destination_guard(&view, "anything-at-all"), Ok(()));
}

/// A configured pool is priced by construction, so it never reaches the unpriced gate even with
/// a card present and the name absent from the card's own list.
#[test]
fn a_configured_pool_is_never_unpriced() {
    let view = View {
        keyed: true,
        card: true,
        configured: vec!["pool-a".into()],
        ..Default::default()
    };
    assert_eq!(destination_guard(&view, "pool-a"), Ok(()));
}

/// THE EMPTY SET IS NOT A REFUSAL. An all-excluded pool proceeds, and the door draws and retains
/// the slot. Refusing here would move the charge.
#[test]
fn an_empty_destination_set_proceeds_rather_than_refusing() {
    let seal = seal();
    let view = View::default();
    let d = verify(
        &UnitToken::<Verify>::mint(&seal),
        &view,
        "pool-a",
        &PrincipalId::new("vk_x"),
        Vec::new(),
    );
    assert!(d.refusal.is_none(), "proceeding names no refusal");
    assert!(d.decision.into_result(&seal).expect("proceeds").is_empty());
}

/// The step's refusal is stamped with THIS step, so the record says where the unit stopped and
/// a body copied into a neighbouring step file cannot mis-stamp it.
#[test]
fn the_step_stamps_its_refusal_with_verify() {
    let seal = seal();
    let view = View {
        keyed: true,
        scopes: Some(vec!["allowed".into()]),
        ..Default::default()
    };
    let answer = verify(
        &UnitToken::<Verify>::mint(&seal),
        &view,
        "denied",
        &PrincipalId::new("vk_x"),
        Vec::new(),
    );
    // The step's own named refusal rides back with the decision, so the wire triple is read
    // from what the step returned rather than recovered by running the guards a second time.
    assert_eq!(answer.refusal, Some(VerifyRefusal::NotAuthorized));
    let refusal = answer
        .decision
        .into_result(&seal)
        .expect_err("the key may not reach it");
    assert_eq!(refusal.step(), Some(StepName::Verify));
    assert_eq!(refusal.reason(), ReasonCode::PoolNotPermitted);
}

/// THE NAMED OUTCOME renders to the live envelope, and it is the same envelope the three parts
/// rendered separately produce — so moving the assembly onto the value moved no bytes.
#[test]
fn the_named_outcome_renders_the_live_refusal_bytes() {
    for refusal in [
        VerifyRefusal::NotAuthorized,
        VerifyRefusal::NoRate {
            name: "made-up".to_string(),
        },
    ] {
        let outcome = refusal.outcome();
        assert_eq!(outcome.status().as_u16(), refusal.status());
        assert_eq!(outcome.kind(), refusal.kind());
        assert_eq!(outcome.message(), refusal.message());
        assert_eq!(
            envelope(outcome.status().as_u16(), outcome.kind(), outcome.message()),
            envelope(refusal.status(), refusal.kind(), &refusal.message())
        );
    }
}

/// THE CLOSED SET IS TWO. Every refusal this step can raise carries one of exactly two reason
/// codes; a third arm has to change this test.
#[test]
fn the_closed_refusal_set_is_exactly_two_reasons() {
    let all = [
        VerifyRefusal::NotAuthorized,
        VerifyRefusal::NoRate {
            name: "x".to_string(),
        },
    ];
    let reasons: Vec<ReasonCode> = all.iter().map(VerifyRefusal::reason).collect();
    assert_eq!(
        reasons,
        vec![ReasonCode::PoolNotPermitted, ReasonCode::NoRate]
    );
    let statuses: Vec<u16> = all.iter().map(VerifyRefusal::status).collect();
    assert_eq!(statuses, vec![403, 400]);
}

/// ASKING WHETHER A NAME IS CONFIGURED ALLOCATES NOTHING.
///
/// The guard runs on every request, and the question it asks is a membership probe: is this
/// name a pool, or a direct model? `model_index` has always answered its half with one hash
/// probe. The pool half went through `pools()`, which is the COLD scrape projection — it builds
/// a `Vec` of every configured pool AND a `Vec` of member indices per pool, then walks it
/// comparing names — so the cost of a per-request yes/no scaled with the size of the
/// deployment, on a seam whose own header says it is reached at most once per scrape and is
/// free to allocate.
///
/// Measured, not timed: a wall-clock assertion on a laptop measures the laptop. Eight pools, so
/// a projection that allocates per pool cannot hide inside a slack bound, and both answers are
/// exercised — a name that IS a pool and one that is nothing at all — because a probe that
/// allocated only on the miss would still be a per-request allocation.
///
/// ZERO is the contract, the same one the engine's own alloc gate holds: no malloc on hot
/// calls. Do not raise this number to make a change green.
#[test]
fn asking_whether_a_name_is_configured_allocates_nothing() {
    use crate::test_support::{LaneSpec, TestApp};
    use crate::CountingJemalloc;

    crate::testkit::install_test_seams();
    let mut builder = TestApp::new();
    for i in 0..8 {
        builder = builder
            .lane(LaneSpec::new(
                &format!("m{i}"),
                crate::proto_codec::PROTO_OPENAI,
                "http://127.0.0.1:9",
            ))
            .pool(&format!("p{i}"), &[(i, 1)]);
    }
    let app = builder.build();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let view = HostPoolView::new(host.as_ref(), &*rt, None);

    // WARM once outside the window: a first-touch lazy static is a per-process cost, not a
    // per-request one.
    let _ = view.is_configured("p3");

    let _ = CountingJemalloc::reset();
    let hit = view.is_configured("p3");
    let miss = view.is_configured("not-a-name");
    let allocs = CountingJemalloc::count();

    assert!(hit, "p3 is a configured pool");
    assert!(!miss, "nothing by that name is configured");
    assert_eq!(
        allocs, 0,
        "a membership probe on the request path allocates nothing"
    );
}

/// THE OPERATOR'S HALF of the same denial: the diagnostic names the pool the ACL tripped on.
///
/// The caller-facing bytes are the previous test's — one 403, indistinguishable — and this is
/// the fact only the node's own log carries. A key restricted to A reaches A, whose exhaustion
/// policy names B, whose policy names C; the ACL denies B. An operator told "A" would go looking
/// at a pool the key is explicitly allowed to use, and the two edges that are actually
/// misconfigured would appear in no line at all. Guard one still names the pool it was handed,
/// and the pricing guard names no pool because it refuses a name.
#[test]
fn the_fallback_denial_names_the_pool_the_acl_tripped_on() {
    let view = View {
        keyed: true,
        scopes: Some(vec!["a".into(), "c".into()]),
        fallbacks: vec![("a".into(), "b".into()), ("b".into(), "c".into())],
        ..Default::default()
    };
    let (refusal, denied) =
        destination_guard_named(&view, "a").expect_err("a falls over to b, and b is denied");
    assert_eq!(refusal, VerifyRefusal::NotAuthorized);
    assert_eq!(
        denied.as_deref(),
        Some("b"),
        "the fallback edge the key may not take is the one the operator has to fix"
    );

    let direct = View {
        keyed: true,
        scopes: Some(vec!["a".into()]),
        ..Default::default()
    };
    assert_eq!(
        destination_guard_named(&direct, "z")
            .expect_err("z is not on the key's list")
            .1
            .as_deref(),
        Some("z"),
        "guard one names the pool it was handed"
    );

    let unpriced = View {
        keyed: true,
        card: true,
        priced_names: vec!["gpt-priced".into()],
        ..Default::default()
    };
    assert_eq!(
        destination_guard_named(&unpriced, "gpt-unpriced")
            .expect_err("no card entry for that name")
            .1,
        None,
        "the pricing guard refuses a name, not a pool"
    );
}
