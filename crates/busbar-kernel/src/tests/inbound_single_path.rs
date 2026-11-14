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
