// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn list_order_fixes_identity_refusal_and_overload_before_later_answers() {
    let providers = vec!["first".into(), "second".into()];
    let requests = HashSet::new();
    let fixed = |answers: &[Option<Judged>]| fixed_answer_at(answers, &providers, &requests, false);
    assert_eq!(fixed(&[None, Some(Judged::Identity)]), None);
    assert_eq!(
        fixed(&[Some(Judged::Pass), Some(Judged::Identity)]),
        Some(Fixed::Admitted(1))
    );
    assert_eq!(
        fixed(&[Some(Judged::Identity), Some(Judged::Denied)]),
        Some(Fixed::Admitted(0))
    );
    assert_eq!(
        fixed(&[Some(Judged::Denied), Some(Judged::Identity)]),
        Some(Fixed::Denied)
    );
    assert_eq!(
        fixed(&[Some(Judged::Overloaded), Some(Judged::Identity)]),
        Some(Fixed::Overloaded)
    );
    assert_eq!(
        fixed(&[Some(Judged::Pass), Some(Judged::Pass)]),
        Some(Fixed::Denied)
    );
}

#[test]
fn peer_answers_wait_for_a_provider_that_also_owns_request_authentication() {
    let providers = vec!["both".into(), "peer".into()];
    let request_auths = HashSet::from(["both".into()]);
    for first in [Judged::Identity, Judged::Pass] {
        assert_eq!(
            fixed_answer_at(
                &[Some(first), Some(Judged::Identity)],
                &providers,
                &request_auths,
                true
            ),
            None
        );
    }
    assert_eq!(
        fixed_answer_at(
            &[Some(Judged::Denied), Some(Judged::Identity)],
            &providers,
            &request_auths,
            true
        ),
        Some(Fixed::Denied)
    );
    assert_eq!(
        fixed_answer_at(
            &[Some(Judged::Overloaded), Some(Judged::Identity)],
            &providers,
            &request_auths,
            true
        ),
        Some(Fixed::Overloaded)
    );
    assert_eq!(
        fixed_answer_at(
            &[Some(Judged::Pass), Some(Judged::Identity)],
            &providers,
            &HashSet::new(),
            true
        ),
        Some(Fixed::Admitted(1))
    );
}

#[tokio::test]
async fn actual_replay_claim_is_once_per_admission_and_denied_after_exit_or_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let actual = crate::real_store::store();
    let gov = Arc::new(crate::governance::GovState::new(actual.clone(), None).unwrap());
    assert!(gov.attach_store_calls(actual));
    let now = crate::store::now();
    let identity = VerifiedIdentity {
        replay: Some(Box::new(busbar_contract::auth_calls::Replay {
            key: format!("inbound-owner-{}", crate::door::op_id().counter()),
            ttl_secs: 60,
        })),
        ..Default::default()
    };
    let claim = || ReplayAdmission {
        pending: crate::auth::PendingClaim::for_identity(
            "actual-owner-policy",
            &identity,
            Some(gov.clone()),
            now,
        )
        .unwrap(),
        won: tokio::sync::OnceCell::new(),
    };
    let alive = AtomicBool::new(true);
    let replay = claim();
    assert!(claim_request_replay(&alive, Some(&replay), None).await);
    assert!(
        claim_request_replay(&alive, Some(&replay), None).await,
        "one admission reuses its settled claim"
    );
    assert!(
        !claim_request_replay(&alive, Some(&claim()), None).await,
        "a distinct admission cannot claim the same actual Store key"
    );
    alive.store(false, Ordering::Release);
    assert!(
        !claim_request_replay(&alive, Some(&replay), None).await,
        "an exited admission loses even a settled win"
    );
    assert!(!claim_request_replay(&alive, None, None).await);
    alive.store(true, Ordering::Release);
    assert!(claim_request_replay(&alive, None, None).await);
    assert!(
        !claim_request_replay(&alive, Some(&replay), Some(std::time::Instant::now())).await,
        "expired replay admission cannot reuse a settled win"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_deadline_cancels_the_owned_pending_verification_and_leaves_the_reactor_live() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct PendingVerification {
        polled: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }
    impl std::future::Future for PendingVerification {
        type Output = ();
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            self.polled.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingVerification {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    let polled = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let reactor = tokio::spawn(async {
        tokio::task::yield_now().await;
        17
    });
    let result = until_deadline(
        Some(std::time::Instant::now() + std::time::Duration::from_millis(10)),
        PendingVerification {
            polled: polled.clone(),
            dropped: dropped.clone(),
        },
    )
    .await;
    assert!(result.is_none());
    assert!(polled.load(Ordering::SeqCst) > 0);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "the owned pending verification is released exactly once"
    );
    assert_eq!(
        reactor.await.unwrap(),
        17,
        "the same-thread reactor remains live while verification waits"
    );
}

#[test]
fn a_settled_list_never_dispatches_a_later_position_and_an_answer_is_not_repeated() {
    for settled in [Fixed::Admitted(0), Fixed::Denied, Fixed::Overloaded] {
        for answer in [
            None,
            Some(Judged::Pass),
            Some(Judged::Identity),
            Some(Judged::Denied),
            Some(Judged::Overloaded),
        ] {
            assert_eq!(position_work(Some(settled), answer), PositionWork::Finished);
        }
    }
    for answered in [
        Judged::Pass,
        Judged::Identity,
        Judged::Denied,
        Judged::Overloaded,
    ] {
        assert_eq!(position_work(None, Some(answered)), PositionWork::Answered);
    }
    assert_eq!(position_work(None, None), PositionWork::Verify);
}

#[test]
fn continuation_bytes_preserve_the_original_request_except_declared_partial_stripping() {
    let mut original = Head::default();
    original.method = "POST".into();
    original.target = "/v1/messages".into();
    original.fields = vec![
        ("Authorization".into(), b"secret-A".to_vec()),
        ("X-Resource".into(), b"A".to_vec()),
    ];
    original.query = Some("token=a&scope=A&token=b".into());
    let strips = [
        Strip::field("authorization".to_string()),
        Strip::query("token".to_string()),
    ];
    for mutation in [
        "method",
        "path",
        "authority",
        "field",
        "query",
        "credential",
        "added",
    ] {
        let mut changed = original.clone();
        match mutation {
            "method" => changed.method = "PUT".into(),
            "path" => changed.target = "/different".into(),
            "authority" => changed.authority = "other.example".into(),
            "field" => changed.fields[1].1 = b"B".to_vec(),
            "query" => changed.query = Some("token=a&scope=B".into()),
            "credential" => changed.fields[0].1 = b"secret-B".to_vec(),
            "added" => changed.fields.push(("X-Added".into(), b"B".to_vec())),
            _ => unreachable!(),
        }
        assert!(
            !continuation_head(&original, &changed, &strips),
            "{mutation}"
        );
    }
    for form in ["original", "field", "query", "both", "case"] {
        let mut retained = original.clone();
        match form {
            "original" => {}
            "field" => {
                retained.fields.remove(0);
            }
            "query" => retained.query = Some("scope=A&token=b".into()),
            "both" => retained = original.stripped(&strips).unwrap(),
            "case" => {
                retained.fields[0].0 = "authorization".into();
                retained.fields[1].0 = "x-resource".into();
            }
            _ => unreachable!(),
        }
        assert!(continuation_head(&original, &retained, &strips), "{form}");
    }
}

#[test]
fn authenticated_framing_fields_remain_exact_at_the_claim_boundary() {
    let mut original = Head::default();
    original.method = "POST".into();
    original.target = "/v1/messages".into();
    original.fields = vec![
        ("authorization".into(), b"credential".to_vec()),
        ("connection".into(), b"close, x-signed".to_vec()),
        ("content-length".into(), b"3".to_vec()),
        ("x-signed".into(), b"first".to_vec()),
        ("x-signed".into(), b"second".to_vec()),
    ];
    original.query = Some("x=1".into());
    let strips = [Strip::field("authorization".to_string())];
    let admitted = original.stripped(&strips).unwrap();
    for removed in ["connection", "content-length", "x-signed"] {
        let mut changed = admitted.clone();
        changed.fields.retain(|(name, _)| name != removed);
        assert!(
            !continuation_head(&original, &changed, &strips),
            "hand-in may not delete {removed}"
        );
        assert!(
            !same_request(&admitted, &changed),
            "claim may not delete {removed}"
        );
    }
    assert!(continuation_head(&original, &admitted, &strips));
    assert!(same_request(&admitted, &admitted));
    assert!(!still_present(&strips, &admitted));
    assert!(still_present(&strips, &original));
}

#[test]
fn host_admission_keeps_credential_separate_from_the_principal_and_wire_answer() {
    let secret = "opaque-owner-custody-value";
    let identity = VerifiedIdentity {
        subject: "actual-principal".into(),
        name: Some("display".into()),
        groups: vec!["reader".into(), "writer".into()],
        ttl_secs: Some(37),
        credential: Some(Secret::new(secret.to_owned())),
        ..Default::default()
    };
    let (admitted, credential) = admitted_identity("provider".into(), identity, None);
    assert!(admitted.identity.credential.is_none());
    assert_eq!(
        credential.as_ref().unwrap().expose(&crate::seal::lend()),
        secret
    );
    assert!(!format!("{admitted:?}").contains(secret));
    let crate::auth::ChainVerdict::Identified {
        module,
        principal,
        resolved,
    } = admission_verdict(Some(&admitted))
    else {
        panic!("identity remains identified");
    };
    assert_eq!(module, "provider");
    assert_eq!(principal.id, "actual-principal");
    assert_eq!(principal.name.as_deref(), Some("display"));
    assert_eq!(principal.roles, ["reader", "writer"]);
    assert_eq!(principal.ttl_secs, Some(37));
    assert!(resolved.is_none());
    assert!(matches!(
        admission_verdict(None),
        crate::auth::ChainVerdict::Open
    ));
    let answer = inbound_answer(
        Some(Fixed::Admitted(0)),
        UnitRef { id: 1, mac: 2 },
        false,
        &[],
    );
    assert!(!format!("{answer:?}").contains(secret));
}

#[test]
fn verifier_projection_lends_the_original_candidate_and_unrewritten_request_values() {
    let mut head = Head::default();
    head.method = "POST".into();
    head.target = "/v1/messages".into();
    head.authority = "original.example".into();
    head.query = Some("token=first&token=second".into());
    head.fields = vec![
        ("Authorization".into(), b"Bearer candidate".to_vec()),
        ("X-Safe".into(), b"unchanged".to_vec()),
    ];
    let candidate = Secret::new("candidate".to_owned());
    let projected = verify_request(
        &head,
        AuthPoint::HeadBody,
        11,
        13,
        Some(b"exact body"),
        Some(&candidate),
    );
    assert_eq!(
        projected
            .credential
            .as_ref()
            .unwrap()
            .expose(&crate::seal::lend())
            .as_slice(),
        b"candidate"
    );
    assert_eq!(
        projected
            .lines
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["authorization", "x-safe"]
    );
    assert_eq!(
        projected.lines[0].1.expose(&crate::seal::lend()).as_slice(),
        b"Bearer candidate"
    );
    assert_eq!(
        projected.lines[1].1.expose(&crate::seal::lend()).as_slice(),
        b"unchanged"
    );
    assert_eq!(
        (
            projected.method.clone(),
            projected.authority.clone(),
            projected.path.clone(),
            projected.query.clone(),
            projected.body.clone()
        ),
        (
            head.method.clone(),
            head.authority.clone(),
            head.target.clone(),
            head.query.clone(),
            Some(b"exact body".to_vec())
        )
    );
    assert!(verify_request(&head, AuthPoint::Head, 11, 13, None, None)
        .credential
        .is_none());
}
