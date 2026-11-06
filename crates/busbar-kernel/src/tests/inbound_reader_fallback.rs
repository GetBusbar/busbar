// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercise the actual inbound host's two-point dispatch, not its decision helpers.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    name: &'static str,
    point: AuthPoint,
    unit: u64,
    body: Option<Vec<u8>>,
}

struct Probe {
    name: &'static str,
    points: AuthPoints,
    answer: Verified,
    faulted: bool,
    pending: bool,
    seen: Arc<Mutex<Vec<Seen>>>,
}

struct Reply {
    answer: Option<VerifyAnswer>,
    faulted: bool,
}
impl Future for Reply {
    type Output = VerifyAnswer;
    fn poll(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.answer
            .take()
            .map_or(std::task::Poll::Pending, std::task::Poll::Ready)
    }
}
impl Verifying for Reply {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.answer.take()
    }
    fn faulted(&self) -> bool {
        self.faulted
    }
}
impl AuthCalls for Probe {
    fn name(&self) -> &str {
        self.name
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        self.points
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.seen.lock().unwrap().push(Seen {
            name: self.name,
            point: request.point,
            unit: request.unit,
            body: request.body.clone(),
        });
        Box::new(Reply {
            answer: (!self.pending).then(|| VerifyAnswer::from(self.answer.clone())),
            faulted: self.faulted,
        })
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

fn probe(
    name: &'static str,
    points: AuthPoints,
    answer: Verified,
    seen: &Arc<Mutex<Vec<Seen>>>,
) -> Arc<Probe> {
    Arc::new(Probe {
        name,
        points,
        answer,
        faulted: false,
        pending: false,
        seen: seen.clone(),
    })
}

fn mixed(reader: Arc<Probe>, providers: &[Arc<Probe>]) -> Kit {
    let gov = signing_gov();
    let mut k = reader_kit(&gov, reader, true);
    let mut listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    let mut names: Vec<_> = providers.iter().map(|p| p.name.to_string()).collect();
    names.push(crate::config::KEYS_MODULE.into());
    let chain = LineAuth::Chain(names, AuthPoints(POINT_HEAD | POINT_HEAD_BODY));
    listener.guests = GuestList::seal(vec![
        line(MESSAGES, METHOD_POST, chain.clone()),
        line(OTHER, METHOD_POST, chain),
        line(HEALTHZ, METHOD_GET, LineAuth::None),
    ])
    .unwrap();
    listener.auths = providers
        .iter()
        .map(|p| (p.name.to_string(), p.clone() as Arc<dyn AuthCalls>))
        .collect();
    let next = Arc::new(AtomicU64::new(100));
    let refused = k.refused.clone();
    k.inbound = Inbound::new(
        Seals {
            mint: Arc::new(move || next.fetch_add(1, Ordering::SeqCst)),
            mac: Arc::new(test_mac),
        },
        Arc::new(|work| {
            tokio::spawn(work);
        }),
        Arc::new(move |r| refused.lock().unwrap().push(r.clone())),
    );
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    k
}

async fn two_points(k: &Kit, seen: &Arc<Mutex<Vec<Seen>>>) -> Answer {
    let head = signed_head();
    let waiting = k
        .call_async(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
        .await
        .unwrap();
    assert_eq!(waiting.flow, FLOW_CONTINUE);
    assert!(
        seen.lock().unwrap().is_empty(),
        "HEAD cannot run ahead of the selected signed reader"
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, waiting.unit, head.clone()).0,
        FLOW_STOP
    );
    let answer = k
        .call_async(MESSAGES, waiting.unit, POINT_HEAD_BODY, head)
        .await
        .unwrap();
    assert_eq!(
        answer.unit, waiting.unit,
        "one unit spans both actual host crossings"
    );
    answer
}

fn expected(name: &'static str, point: AuthPoint, unit: u64) -> Seen {
    Seen {
        name,
        point,
        unit,
        body: (point == AuthPoint::HeadBody).then(|| b"{}".to_vec()),
    }
}

#[tokio::test]
async fn reader_pass_resumes_head_identity_on_the_same_unit_without_lending_the_body() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe(
        "head",
        AuthPoints::HEAD,
        identity("oidc", "credential"),
        &seen,
    );
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Reject, &seen);
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert_eq!(
        k.inbound.admitted(answer.unit.id).unwrap().identity.subject,
        "oidc"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
    let head = signed_head().stripped(&answer.strips).unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, head.clone()).0,
        FLOW_CONTINUE
    );
    assert!(k.inbound.claim_request(OWNER, 1, 1, &head).is_ok());
}

#[tokio::test]
async fn reader_pass_resumes_head_denial_before_any_later_body_identity() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Reject, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("later", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert!(k.inbound.admitted(answer.unit.id).is_none());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
}

#[tokio::test]
async fn reader_and_head_pass_preserve_order_and_deliver_the_body_only_to_the_body_provider() {
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
    assert_eq!(
        k.inbound.admitted(answer.unit.id).unwrap().identity.subject,
        "body"
    );
    let trace = vec![
        expected("reader", AuthPoint::HeadBody, answer.unit.id),
        expected("head", AuthPoint::Head, answer.unit.id),
        expected("body", AuthPoint::HeadBody, answer.unit.id),
    ];
    assert_eq!(*seen.lock().unwrap(), trace);
    let again = k
        .call_async(MESSAGES, answer.unit, POINT_HEAD_BODY, signed_head())
        .await
        .unwrap();
    assert_eq!(again.unit, answer.unit);
    assert_eq!(again.flow, FLOW_CONTINUE);
    assert_eq!(
        *seen.lock().unwrap(),
        trace,
        "answered HEAD providers and settled reader are never repeated"
    );
}

#[tokio::test]
async fn a_final_signed_reader_verdict_still_preempts_head_and_body_providers() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Reject, &seen);
    let head = probe(
        "head",
        AuthPoints::HEAD,
        identity("head", "credential"),
        &seen,
    );
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![expected("reader", AuthPoint::HeadBody, answer.unit.id)]
    );
}

#[tokio::test]
async fn a_faulted_signed_reader_pass_cannot_release_the_head_chain() {
    let seen = Arc::default();
    let mut reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    Arc::get_mut(&mut reader).unwrap().faulted = true;
    let head = probe(
        "head",
        AuthPoints::HEAD,
        identity("head", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![expected("reader", AuthPoint::HeadBody, answer.unit.id)]
    );
}

#[tokio::test]
async fn a_pending_fallback_head_obeys_the_original_operation_deadline_and_cannot_admit() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let mut head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    Arc::get_mut(&mut head).unwrap().pending = true;
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
    let waiting = k
        .inbound
        .auth_call(
            Call {
                owner: OWNER,
                generation: GEN,
                auth: k.id(MESSAGES),
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: 1,
                stream: 1,
                framing: 1,
                head: signed_head(),
                body: None,
                deadline: Some(deadline),
            },
            Box::new(|_| panic!("the body reader has not started")),
        )
        .expect("HEAD reserves the reader synchronously")
        .unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let immediate = k.inbound.auth_call(
        Call {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: waiting.unit,
            point: POINT_HEAD_BODY,
            conn: 1,
            stream: 1,
            framing: 1,
            head: signed_head(),
            body: Some(b"{}".to_vec()),
            deadline: Some(deadline),
        },
        Box::new(move |answer| {
            let _ = sent.send(answer);
        }),
    );
    assert!(
        immediate.is_none(),
        "the real host retains the pending verifier"
    );
    let answer = tokio::time::timeout(std::time::Duration::from_secs(1), received)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(answer.unit, waiting.unit);
    assert!(k.inbound.admitted(answer.unit.id).is_none());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
}

#[tokio::test]
async fn a_faulted_fallback_head_pass_denies_before_the_body_provider() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let mut head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    Arc::get_mut(&mut head).unwrap().faulted = true;
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert!(k.inbound.admitted(answer.unit.id).is_none());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
}
