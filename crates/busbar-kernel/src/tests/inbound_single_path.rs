// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-A1 / SP-AU1: one unit resolves its plane admission, builds its header map and
//! reads its caller credential once, through every auth point and every reader after the claim.
//! Counted by the dev-only stage probes (`busbar_contract::stage_probe`), on the actual inbound
//! host, never on its helpers.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

/// Drive the two-point signed-reader chain to a claimed request and read it the way the data
/// plane and the operator adapter do.
async fn claimed_and_read(k: &Kit, seen: &Arc<Mutex<Vec<Seen>>>) -> Answer {
    let answer = two_points(k, seen).await;
    if answer.flow == FLOW_CONTINUE {
        let head = signed_head().stripped(&answer.strips).unwrap();
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, answer.unit, head.clone()).0,
            FLOW_CONTINUE
        );
        let request = k.inbound.claim_request(OWNER, 1, 1, &head).unwrap();
        let _ = request.plane_admission();
        let _ = request.effect_context();
        let _ = crate::auth::admitted_context(&request).await;
        let _ = request.plane_admission();
    }
    answer
}

#[tokio::test]
async fn plane_admission_and_header_map_derived_once_per_unit_through_the_claim() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);

    let scope = Scope::open();
    let answer = claimed_and_read(&k, &seen).await;

    assert_eq!(answer.flow, FLOW_CONTINUE, "today's verdict is unchanged");
    assert_eq!(
        k.inbound.admitted(answer.unit.id).unwrap().identity.subject,
        "body"
    );
    assert_eq!(
        scope.count(Derive::PlaneAdmission),
        1,
        "the plane admission on the unit's original head is resolved once and carried"
    );
    assert_eq!(
        scope.count(Derive::AdmissionOnHead),
        1,
        "only the continuation point resolves again, on its own head"
    );
    assert_eq!(
        scope.count(Derive::HeaderMap),
        1,
        "one header map per unit across both points, the claim and every reader after it"
    );
    assert_eq!(
        scope.count(Derive::CredentialExtract),
        1,
        "the caller credential is read out of the carriers once per unit"
    );
}

#[tokio::test]
async fn keys_judging_reads_the_carried_admission_and_credential() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let k = mixed(reader, &[head, body]);

    let scope = Scope::open();
    let answer = two_points(&k, &seen).await;

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id),
            expected("body", AuthPoint::HeadBody, answer.unit.id),
        ],
        "every provider still answers in list order before keys judge"
    );
    assert_eq!(scope.count(Derive::PlaneAdmission), 1);
    assert_eq!(scope.count(Derive::AdmissionOnHead), 1);
    assert_eq!(scope.count(Derive::HeaderMap), 1);
    assert_eq!(scope.count(Derive::CredentialExtract), 1);
}

fn refused(k: &Kit, unit: UnitRef) -> Refusal {
    k.inbound
        .refuse(Refuse {
            owner: OWNER,
            generation: GEN,
            unit,
            cause: REFUSE_STOPPED,
            line: 0,
            request: Some(signed_head()),
            conn: 1,
            stream: 1,
            framing: Some(1),
        })
        .expect("refused")
}

#[tokio::test]
async fn a_refused_unit_reads_the_admission_and_credential_its_auth_calls_derived() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let k = mixed(reader, &[head, body]);

    let scope = Scope::open();
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP, "no key is presented, so keys deny");
    let refusal = refused(&k, answer.unit);

    assert_eq!(refusal.status, 401, "today's refusal is unchanged");
    assert_eq!(
        scope.count(Derive::PlaneAdmission),
        1,
        "the refusal reads the admission keys judging already resolved"
    );
    assert_eq!(
        scope.count(Derive::HeaderMap),
        1,
        "the refusal reads the unit's header map, never builds a second"
    );
    assert_eq!(
        scope.count(Derive::CredentialExtract),
        1,
        "the refusal reads the unit's carried credential"
    );
}

#[tokio::test]
async fn a_refusal_with_no_unit_derives_each_input_once() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let k = mixed(reader, &[head, body]);

    let scope = Scope::open();
    let refusal = refused(&k, UnitRef::NONE);

    assert_eq!(refusal.status, 401);
    assert_eq!(scope.count(Derive::PlaneAdmission), 1);
    assert_eq!(scope.count(Derive::HeaderMap), 1);
    assert_eq!(scope.count(Derive::CredentialExtract), 1);
}

#[tokio::test]
async fn a_presented_unit_is_verified_once_and_handed_in_under_one_units_guard() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let k = mixed(reader, &[head, body]);
    let waiting = k
        .call_async(MESSAGES, UnitRef::NONE, POINT_HEAD, signed_head())
        .await
        .unwrap();
    assert_eq!(waiting.flow, FLOW_CONTINUE);

    let scope = Scope::open();
    let (flow, unit) = k.hand_in(MESSAGES, MESSAGES, waiting.unit, signed_head());

    assert_eq!(
        (flow, unit),
        (FLOW_STOP, waiting.unit),
        "today's verdict: the chain has not admitted the unit yet"
    );
    assert_eq!(
        scope.count(Derive::UnitMac),
        1,
        "the kernel checks a presented unit's MAC once per hand-in"
    );
    assert_eq!(
        scope.count(Derive::UnitsLock),
        2,
        "one units guard to verify the ref, one to check and record the hand-in"
    );
}

#[tokio::test]
async fn a_unit_minted_at_hand_in_takes_the_units_lock_twice() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let k = mixed(reader, &[head, body]);

    let scope = Scope::open();
    let (flow, unit) = k.hand_in(MESSAGES, MESSAGES, UnitRef::NONE, signed_head());

    assert_eq!(
        flow, FLOW_STOP,
        "a chain line is not admitted by a bare hand-in"
    );
    assert!(!unit.is_none(), "the hand-in minted its unit");
    assert_eq!(scope.count(Derive::UnitMac), 0, "nothing was presented");
    assert_eq!(
        scope.count(Derive::UnitsLock),
        2,
        "the mint's insert, then one guard to check and record the hand-in"
    );
}

#[tokio::test]
async fn a_stale_unit_is_still_refused_foreign_at_hand_in() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let k = mixed(reader, &[head, body]);
    let waiting = k
        .call_async(MESSAGES, UnitRef::NONE, POINT_HEAD, signed_head())
        .await
        .unwrap();
    let forged = UnitRef {
        mac: waiting.unit.mac ^ 1,
        ..waiting.unit
    };
    let refused = k.inbound.hand_in(HandIn {
        owner: OWNER,
        generation: GEN,
        auth: k.id(MESSAGES),
        unit: forged,
        line: 0,
        conn: 1,
        stream: 1,
        framing: Some(1),
        head: signed_head(),
    });
    assert_eq!(refused, Err(UNIT_FOREIGN));
}

#[tokio::test]
async fn an_admitted_hand_in_scans_for_stripped_credentials_once() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_CONTINUE);
    let handed = signed_head().stripped(&answer.strips).unwrap();

    let scope = Scope::open();
    let (flow, _) = k.hand_in(MESSAGES, MESSAGES, answer.unit, handed);

    assert_eq!(flow, FLOW_CONTINUE, "today's verdict is unchanged");
    assert_eq!(
        scope.count(Derive::StripScan),
        1,
        "core strips its own original once; the handed head equal to it carries nothing stripped"
    );
}

/// One keys-chain unit from its first auth call to its served head. Every head is built fresh by
/// the test, so only the host's own copies are counted.
async fn served_from_fresh_heads(k: &Kit) {
    let waiting = k
        .call_async(MESSAGES, UnitRef::NONE, POINT_HEAD, signed_head())
        .await
        .unwrap();
    assert_eq!(waiting.flow, FLOW_CONTINUE);
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, waiting.unit, signed_head()).0,
        FLOW_STOP
    );
    let answer = k
        .call_async(MESSAGES, waiting.unit, POINT_HEAD_BODY, signed_head())
        .await
        .unwrap();
    assert_eq!(answer.flow, FLOW_CONTINUE);
    let handed = signed_head().stripped(&answer.strips).unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, handed).0,
        FLOW_CONTINUE
    );
    let claimed = signed_head().stripped(&answer.strips).unwrap();
    let request = k.inbound.claim_request(OWNER, 1, 1, &claimed).unwrap();
    let _ = crate::auth::admitted_context(&request).await;
}

#[tokio::test]
async fn a_units_heads_are_shared_from_its_first_auth_call_to_its_served_head() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);

    let scope = Scope::open();
    served_from_fresh_heads(&k).await;

    assert!(
        scope.count(Derive::HeadCopy) <= 2,
        "the unit keeps its original once and the served head is copied once to be stripped; \
         every other reader shares them: {}",
        scope.count(Derive::HeadCopy)
    );
}
