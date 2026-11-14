// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::tests::{NativeFixture, BUDGET};
use crate::root::durability::{build_on_store, DurabilityConfig};
use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::{FLOW_CONTINUE, FLOW_STOP, REFUSE_STOPPED};
use busbar_contract::caps::{Outcome, ReasonCode, StepName};
use busbar_kernel::inbound::{Call, Refuse};
use busbar_kernel::persistence::journal::RuntimeJournal;
use std::sync::atomic::Ordering;

const GENERATION: u64 = 41;

struct Ingress {
    host: Arc<Inbound>,
    listener: Listener,
    line: u32,
    observed: Arc<Mutex<Vec<busbar_kernel::inbound::RefusedUnit>>>,
    mac_units: Arc<Mutex<Vec<u64>>>,
}

impl Ingress {
    fn new(g: &Governed, routes: &Arc<crate::root::serve::DataRoutes>) -> Self {
        let node = Arc::clone(g.post.node());
        let mint = Arc::clone(&node);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::clone(&observed);
        let mac_units = Arc::new(Mutex::new(Vec::new()));
        let tagged = Arc::clone(&mac_units);
        let host = Inbound::new(
            Seals {
                mint: Arc::new(move || crate::root::inbound::mint_on(&mint)),
                mac: Arc::new(move |tag| {
                    tagged.lock().unwrap().push(tag.unit);
                    crate::root::loader::dispatch::auth_handle::mint_unit_ref(
                        tag.secret,
                        tag.generation,
                        tag.owner,
                        tag.line,
                        tag.unit,
                    )
                    .map(|unit| unit.mac)
                }),
            },
            Arc::new(|future| {
                tokio::spawn(future);
            }),
            Arc::new(move |refused| {
                node.refused_inbound(refused);
                events.lock().unwrap().push(refused.clone());
            }),
        );
        let line = routes
            .guests
            .lines()
            .iter()
            .position(|line| line.route.rung == 0)
            .unwrap() as u32;
        let render = Arc::clone(routes);
        let kinds = Arc::clone(routes);
        let listener = Listener {
            guests: routes.guests.clone(),
            auths: Default::default(),
            body_limit: 4096,
            app: Arc::clone(&g.app),
            door_refusals: Vec::new(),
            ids: (1..=routes.guests.lines().len() as u64).collect(),
            signed_ingress: Arc::new(|_, _| false),
            scope: Some(busbar_kernel::inbound::ListenerScope {
                audit_kind: Some(Arc::new(move |line| kinds.inbound_audit_kind(line))),
                neutral_refuse: Some(Arc::new(move |app, refusal| {
                    render.refuse_line(app, refusal)
                })),
                admission: Arc::new(|_, _| None),
                legacy_fallback: false,
                refuse: None,
            }),
        };
        host.install_at(OWNER, LISTENER, GENERATION, listener.clone())
            .unwrap();
        host.framing_started(OWNER, LISTENER, FRAMING, GENERATION)
            .unwrap();
        Self {
            host,
            listener,
            line,
            observed,
            mac_units,
        }
    }

    async fn authenticate(
        &self,
        stream: u64,
        token: &str,
    ) -> (busbar_kernel::inbound::Answer, Head) {
        self.host
            .grant_stream(OWNER, FRAMING, stream, GENERATION)
            .unwrap();
        let head = Head {
            method: "POST".into(),
            target: "/call/local-counted".into(),
            authority: String::new(),
            query: None,
            fields: vec![(
                "authorization".into(),
                format!("Bearer {token}").into_bytes(),
            )],
        };
        let (done, reply) = tokio::sync::oneshot::channel();
        let immediate = self.host.auth_call(
            Call {
                owner: OWNER,
                generation: GENERATION,
                auth: self.line as u64 + 1,
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: FRAMING,
                stream,
                framing: FRAMING,
                head: head.clone(),
                body: None,
                deadline: None,
            },
            Box::new(move |answer| {
                let _ = done.send(answer);
            }),
        );
        let answer = match immediate {
            Some(answer) => answer,
            None => reply.await.unwrap(),
        }
        .unwrap();
        (answer, head)
    }

    fn claim(
        &self,
        stream: u64,
        answer: &busbar_kernel::inbound::Answer,
        mut head: Head,
    ) -> RequestAdmission {
        assert_eq!(answer.flow, FLOW_CONTINUE);
        head.fields.retain(|(name, _)| {
            !answer
                .strips
                .iter()
                .any(|strip| strip.name.eq_ignore_ascii_case(name))
        });
        let (flow, handed) = self
            .host
            .hand_in(HandIn {
                owner: OWNER,
                generation: GENERATION,
                auth: self.line as u64 + 1,
                unit: answer.unit,
                line: self.line,
                conn: FRAMING,
                stream,
                framing: Some(FRAMING),
                head: head.clone(),
            })
            .unwrap();
        assert_eq!(flow, FLOW_CONTINUE);
        assert_eq!(handed, answer.unit);
        let admission = self
            .host
            .claim_request(OWNER, FRAMING, stream, &head)
            .unwrap();
        assert_eq!(admission.unit_key().get(), answer.unit.id);
        assert_eq!(admission.generation(), GENERATION);
        admission
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_auth_refusals_and_success_keep_one_signed_persisted_identity() {
    let _one = PUBLISHING.lock().await;
    let node_id = busbar_kernel::door::op_id().counter();
    let fixture = NativeFixture::new(node_id).await;
    let lane = fixture.journal.clone();
    let mut durability = fixture.book().await;
    durability.record = busbar_kernel_audit::AuditChain::new()
        .sealing_as(node_id)
        .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[0x71; 32]));
    let book = Arc::new(Mutex::new(durability));
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let g = governed_full(
        "first-auth-audit",
        true,
        None,
        Screen::Nothing,
        Some((Arc::clone(&node), Arc::clone(&book), fixture.core.clone())),
        None,
        false,
    )
    .await;
    let routes = crate::root::serve::door_mounts(
        g.served.clone(),
        || None,
        &[(busbar_kernel::config::KEYS_MODULE.into(), AuthPoints::HEAD)],
        &[],
        &[],
        &[],
    )
    .unwrap()
    .data;
    let ingress = Ingress::new(&g, &routes);

    // A real keys verifier rejects before any teller admission. Its transport refusal seals
    // the ID minted by auth.call, and retrying that same UnitRef cannot seal another record.
    let (rejected, head) = ingress.authenticate(1, "invalid-key").await;
    assert_eq!(rejected.flow, FLOW_STOP);
    let refuse = || Refuse {
        owner: OWNER,
        generation: GENERATION,
        unit: rejected.unit,
        cause: REFUSE_STOPPED,
        line: ingress.line,
        conn: FRAMING,
        stream: 1,
        framing: Some(FRAMING),
        request: Some(head.clone()),
    };
    assert_eq!(ingress.host.refuse(refuse()).unwrap().status, 401);
    assert!(ingress.host.refuse(refuse()).is_err());
    assert_eq!(g.requests().await, 0);
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);

    // Once handed in, cancellation in the shared final authentication gate is still a
    // refusal of the original unit, and dropping all remaining owners cannot duplicate it.
    let (cancelled, head) = ingress.authenticate(2, &g.token).await;
    let admission = ingress.claim(2, &cancelled, head);
    ingress.host.stream_ended(OWNER, FRAMING, 2);
    assert!(busbar_kernel::auth::admitted_context(&admission)
        .await
        .is_err());
    drop(admission);
    assert_eq!(g.requests().await, 0);

    let (good, head) = ingress.authenticate(3, &g.token).await;
    let admission = ingress.claim(3, &good, head);
    let mut replacement = ingress.listener.clone();
    replacement.body_limit = 17;
    replacement.app = Arc::new((*g.app).clone());
    ingress
        .host
        .install_at(OWNER, LISTENER, GENERATION + 1, replacement)
        .unwrap();
    assert_eq!(admission.generation(), GENERATION);
    assert_eq!(admission.body_limit(), 4096);
    let context = busbar_kernel::auth::admitted_context(&admission)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&context.app, &g.app));
    let output = Arc::new(Output::default());
    Arc::clone(&routes)
        .serve_admitted(
            &admission,
            context,
            bytes::Bytes::from_static(b"hello"),
            busbar_contract::abi::host::service::SCHEME_SECURE,
            busbar_kernel::plane_routes::FramedSession::default(),
            Arc::clone(&output),
        )
        .await;
    assert_eq!(output.stated(), Some(200));
    assert_eq!(*output.body.lock().unwrap(), b"hello");
    ingress.host.stream_ended(OWNER, FRAMING, 3);
    drop(admission);
    assert_eq!(g.requests().await, 1);
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);

    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
    let chain = { book.lock().unwrap().chain_at() };
    let persisted = chain.audit_window(1, 3).await.unwrap();
    assert_eq!(persisted.len(), 3);
    assert_eq!(
        persisted
            .iter()
            .map(|record| record.what.unit_key.get())
            .collect::<Vec<_>>(),
        vec![rejected.unit.id, cancelled.unit.id, good.unit.id]
    );
    assert!(matches!(
        persisted[0].outcome.unit_end,
        Outcome::Refused(StepName::Authenticate, ReasonCode::Unauthenticated)
    ));
    assert!(matches!(
        persisted[1].outcome.unit_end,
        Outcome::Refused(..)
    ));
    assert_eq!(persisted[2].outcome.unit_end, Outcome::Completed);
    for record in &persisted[..2] {
        assert!(record.usage.lines.is_empty());
        assert_eq!(record.usage.fee_count, 0);
        assert!(record.controls.hooks_applied.is_empty());
    }
    let keys = crate::root::durability::keyset_of(&book.lock().unwrap().record);
    for record in &persisted {
        busbar_kernel_audit::AuditChain::verify_signature(
            record,
            keys.get(record.key_id.as_deref().unwrap()).unwrap(),
        )
        .unwrap();
    }
    assert!(busbar_kernel_audit::AuditChain::verify_chain(&persisted).is_ok());
    assert_eq!(ingress.observed.lock().unwrap().len(), 2);
    assert!(ingress
        .observed
        .lock()
        .unwrap()
        .iter()
        .all(|event| event.generation == GENERATION));
    let reopened = build_on_store(
        &DurabilityConfig::default(),
        node_id,
        RuntimeJournal::open(fixture.core.clone(), node_id, BUDGET)
            .await
            .unwrap(),
        None,
        BUDGET,
    )
    .await
    .unwrap();
    assert_eq!(reopened.audit_window(1, 3).await, Some(persisted));
}

struct ReplayIdentity(std::sync::atomic::AtomicUsize);
impl ReplayIdentity {
    fn answer(&self) -> busbar_contract::auth_calls::VerifyAnswer {
        use busbar_contract::auth_calls::{
            Replay, Strip, Verified, VerifiedIdentity, VerifyAnswer,
        };
        let index = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let replay = if index == 2 { 1 } else { index };
        VerifyAnswer {
            strips: vec![Strip::field("authorization")],
            ..VerifyAnswer::from(Verified::Identity(VerifiedIdentity {
                subject: "verified-reader".into(),
                groups: vec!["reader".into()],
                replay: Some(Box::new(Replay {
                    key: format!("ingress-audit-replay-{replay}"),
                    ttl_secs: 60,
                })),
                ..Default::default()
            }))
        }
    }
}
struct Answered(Option<busbar_contract::auth_calls::VerifyAnswer>);
impl std::future::Future for Answered {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().unwrap())
    }
}
impl busbar_contract::auth_calls::Verifying for Answered {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.take()
    }
}
impl busbar_contract::auth_calls::AuthCalls for ReplayIdentity {
    fn name(&self) -> &str {
        "audit-reader"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(self.answer())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Answered(Some(self.answer())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dpop_replay_body_and_cancel_refusals_retain_signed_audit_through_store_delay() {
    let _one = PUBLISHING.lock().await;
    let node_id = busbar_kernel::door::op_id().counter();
    let fixture = NativeFixture::new(node_id).await;
    let slots = &fixture.faults;
    let lane = fixture.journal.clone();
    let mut durability = fixture.book().await;
    durability.record = busbar_kernel_audit::AuditChain::new()
        .sealing_as(node_id)
        .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[0x72; 32]));
    let book = Arc::new(Mutex::new(durability));
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let mut g = governed_full(
        "postauth-audit",
        false,
        None,
        Screen::Nothing,
        Some((Arc::clone(&node), Arc::clone(&book), fixture.core.clone())),
        None,
        false,
    )
    .await;
    let mut app = (*g.app).clone();
    app.oauth_as = Some(Arc::new(())); // Bearer cnf rejection needs no AS plugin call.
    app.role_bindings
        .entry("audit-reader".into())
        .or_default()
        .entry("reader".into())
        .or_default();
    g.app = Arc::new(app);
    let routes = crate::root::serve::door_mounts(
        g.served.clone(),
        || None,
        &[("audit-reader".into(), AuthPoints::HEAD)],
        &[],
        &[],
        &[],
    )
    .unwrap()
    .data;
    let mut ingress = Ingress::new(&g, &routes);
    ingress.listener.auths.insert(
        "audit-reader".into(),
        Arc::new(ReplayIdentity(Default::default())),
    );
    // Reinstall before opening streams: the host calls this verifier itself and retains its
    // identity. Transport answers still contain only flow, UnitRef and strips.
    ingress
        .host
        .install_at(OWNER, LISTENER, GENERATION, ingress.listener.clone())
        .unwrap();

    use base64::Engine as _;
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"cnf":{"jkt":"bound"}}"#);
    let (dpop, head) = ingress
        .authenticate(1, &format!("e30.{payload}.c2ln"))
        .await;
    let admission = ingress.claim(1, &dpop, head);
    assert!(matches!(
        busbar_kernel::auth::admitted_context(&admission).await,
        Err(busbar_kernel::auth::AdmittedRefusal::SenderConstraint)
    ));
    ingress.host.stream_ended(OWNER, FRAMING, 1);
    drop(admission);

    let (body, head) = ingress.authenticate(2, "unbound").await;
    let admission = ingress.claim(2, &body, head);
    assert!(busbar_kernel::auth::admitted_context(&admission)
        .await
        .is_ok());
    assert_eq!(
        crate::root::listener::framed::serve_admitted_body_test(
            Arc::clone(&routes),
            admission,
            vec![Ok(bytes::Bytes::from(vec![0; 4097]))]
        )
        .await,
        Some(413)
    );
    ingress.host.stream_ended(OWNER, FRAMING, 2);

    let (replay, head) = ingress.authenticate(3, "unbound").await;
    let admission = ingress.claim(3, &replay, head);
    assert!(matches!(
        busbar_kernel::auth::admitted_context(&admission).await,
        Err(busbar_kernel::auth::AdmittedRefusal::Identity(
            busbar_kernel::auth::IdentityRefusal::Denied
        ))
    ));
    ingress.host.stream_ended(OWNER, FRAMING, 3);
    drop(admission);

    let (cancel, head) = ingress.authenticate(4, "unbound").await;
    let admission = ingress.claim(4, &cancel, head);
    ingress.host.stream_ended(OWNER, FRAMING, 4);
    drop(admission);

    let (malformed, head) = ingress.authenticate(5, "unbound").await;
    let admission = ingress.claim(5, &malformed, head);
    // Win the replay before pausing Store: body collection then exercises the actual
    // production refusal path while the fixed-record writer has pending Store custody.
    assert!(busbar_kernel::auth::admitted_context(&admission)
        .await
        .is_ok());
    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
    slots.pause(true);
    assert_eq!(
        crate::root::listener::framed::serve_admitted_body_test(
            Arc::clone(&routes),
            admission,
            vec![Err("decoded stream failed")]
        )
        .await,
        Some(400)
    );
    ingress.host.stream_ended(OWNER, FRAMING, 5);
    assert!(
        lane.pending_records() > 0,
        "the one sealed record retains pending Store custody"
    );
    assert_eq!(ingress.observed.lock().unwrap().len(), 5);
    slots.lose_acks.store(true, Ordering::Release);
    slots.pause(false);
    assert!(node.retry_held_journal().await.is_err());
    assert!(
        lane.pending_records() > 0,
        "lost acknowledgements retain exact original custody"
    );
    slots.lose_acks.store(false, Ordering::Release);
    node.retry_held_journal().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lane.pending_records(), 0);

    let mut ungranted = ingress.listener.clone();
    let mut app = (*ungranted.app).clone();
    app.role_bindings.clear();
    ungranted.app = Arc::new(app);
    ingress
        .host
        .install_at(OWNER, LISTENER, GENERATION, ungranted)
        .unwrap();
    let (scope, head) = ingress.authenticate(6, "unbound").await;
    let admission = ingress.claim(6, &scope, head);
    assert!(matches!(
        busbar_kernel::auth::admitted_context(&admission).await,
        Err(busbar_kernel::auth::AdmittedRefusal::Identity(
            busbar_kernel::auth::IdentityRefusal::NoGrant
        ))
    ));
    ingress.host.stream_ended(OWNER, FRAMING, 6);
    drop(admission);
    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ingress.observed.lock().unwrap().len(), 6);
    assert_eq!(g.requests().await, 0);
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
    let chain = { book.lock().unwrap().chain_at() };
    let persisted = chain.audit_window(1, 6).await.unwrap();
    assert_eq!(
        persisted
            .iter()
            .map(|record| record.what.unit_key.get())
            .collect::<Vec<_>>(),
        vec![
            dpop.unit.id,
            body.unit.id,
            replay.unit.id,
            cancel.unit.id,
            malformed.unit.id,
            scope.unit.id,
        ]
    );
    for (record, reason) in persisted.iter().zip([
        ReasonCode::Unauthenticated,
        ReasonCode::BodyTooLarge,
        ReasonCode::Unauthenticated,
        ReasonCode::ClientGone,
        ReasonCode::DecodeFailed,
        ReasonCode::ScopeDenied,
    ]) {
        assert!(matches!(record.outcome.unit_end, Outcome::Refused(_, actual) if actual == reason));
        assert!(record.usage.lines.is_empty());
        assert_eq!(record.usage.fee_count, 0);
    }
    assert!(matches!(
        persisted[5].outcome.unit_end,
        Outcome::Refused(StepName::Approve, ReasonCode::ScopeDenied)
    ));
    let keys = crate::root::durability::keyset_of(&book.lock().unwrap().record);
    for record in &persisted {
        busbar_kernel_audit::AuditChain::verify_signature(
            record,
            keys.get(record.key_id.as_deref().unwrap()).unwrap(),
        )
        .unwrap();
    }
    assert!(busbar_kernel_audit::AuditChain::verify_chain(&persisted).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_audit_store_lane_stops_first_auth_minting_before_any_unit_tag() {
    let _one = PUBLISHING.lock().await;
    let node_id = busbar_kernel::door::op_id().counter();
    let fixture = NativeFixture::new(node_id).await;
    let slots = &fixture.faults;
    let lane = RuntimeJournal::open(
        fixture.core.clone(),
        node_id,
        busbar_kernel::persistence::journal::BufferBudget {
            records: 1,
            bytes: BUDGET.bytes,
        },
    )
    .await
    .unwrap();
    let book = Arc::new(Mutex::new(
        build_on_store(
            &DurabilityConfig::default(),
            node_id,
            lane.clone(),
            None,
            BUDGET,
        )
        .await
        .unwrap(),
    ));
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let g = governed_full(
        "bounded-inbound-audit",
        true,
        None,
        Screen::Nothing,
        Some((Arc::clone(&node), Arc::clone(&book), fixture.core.clone())),
        None,
        false,
    )
    .await;
    let routes = crate::root::serve::door_mounts(
        g.served.clone(),
        || None,
        &[(busbar_kernel::config::KEYS_MODULE.into(), AuthPoints::HEAD)],
        &[],
        &[],
        &[],
    )
    .unwrap()
    .data;
    let ingress = Ingress::new(&g, &routes);
    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
    let (rejected, head) = ingress.authenticate(1, "invalid-key").await;
    assert_eq!(rejected.flow, FLOW_STOP);
    slots.pause(true);
    ingress
        .host
        .refuse(Refuse {
            owner: OWNER,
            generation: GENERATION,
            unit: rejected.unit,
            cause: REFUSE_STOPPED,
            line: ingress.line,
            conn: FRAMING,
            stream: 1,
            framing: Some(FRAMING),
            request: Some(head.clone()),
        })
        .unwrap();
    assert_eq!(lane.pending_records(), 1);
    assert!(node.journal_refusal().is_some());
    // Verification also recomputes the MAC; a full lane must add no tag at all.
    let before_blocked = ingress.mac_units.lock().unwrap().clone();
    assert!(!before_blocked.is_empty());
    assert!(before_blocked.iter().all(|id| *id == rejected.unit.id));
    for stream in 2..=9 {
        ingress
            .host
            .grant_stream(OWNER, FRAMING, stream, GENERATION)
            .unwrap();
        let (done, reply) = tokio::sync::oneshot::channel();
        let immediate = ingress.host.auth_call(
            Call {
                owner: OWNER,
                generation: GENERATION,
                auth: ingress.line as u64 + 1,
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: FRAMING,
                stream,
                framing: FRAMING,
                head: head.clone(),
                body: None,
                deadline: None,
            },
            Box::new(move |answer| {
                let _ = done.send(answer);
            }),
        );
        let answer = match immediate {
            Some(answer) => answer,
            None => reply.await.unwrap(),
        };
        assert_eq!(answer, Err(busbar_kernel::inbound::UNIT_UNMINTED));
    }
    assert_eq!(*ingress.mac_units.lock().unwrap(), before_blocked);
    assert!(
        ingress.host.unit_secret(OWNER, 0).is_none(),
        "zero is never an accepted unit"
    );
    assert_eq!(ingress.observed.lock().unwrap().len(), 1);
    assert_eq!(book.lock().unwrap().audit_records.len(), 1);
    assert_eq!(
        lane.pending_records(),
        1,
        "refusals cannot grow debt behind a full audit lane"
    );
    assert_eq!(g.requests().await, 0);
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
    slots.pause(false);
    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
    assert!(node.journal_refusal().is_none());
    let (next, _) = ingress.authenticate(10, "invalid-key").await;
    assert_ne!(next.unit.id, 0);
    assert_ne!(next.unit.id, rejected.unit.id);
    let after_drain = ingress.mac_units.lock().unwrap().clone();
    assert_eq!(&after_drain[..before_blocked.len()], &before_blocked);
    let new_tags = &after_drain[before_blocked.len()..];
    assert!(!new_tags.is_empty());
    assert!(new_tags.iter().all(|id| *id == next.unit.id));
    ingress.host.stream_ended(OWNER, FRAMING, 10);
    tokio::time::timeout(std::time::Duration::from_secs(5), lane.flush())
        .await
        .unwrap()
        .unwrap();
}

/// The ops of one whole answer on the HTTP door: a head stating exactly one `content-length`
/// equal to the body it opens (and no chunking), the whole body, then the stream's empty end.
/// No `Refuse` may follow, so nothing can cut a stated length short. Returns status and body.
fn whole_answer(wire: &[crate::root::listener::framed::WireOp]) -> (u32, bytes::Bytes) {
    use crate::root::listener::framed::WireOp;
    let [WireOp::Head {
        status,
        fields,
        end: false,
    }, WireOp::Data { bytes, end: false }, WireOp::Data {
        bytes: last,
        end: true,
    }] = wire
    else {
        panic!("not head, whole body, empty end: {wire:?}");
    };
    assert!(last.is_empty(), "nothing after the whole body: {wire:?}");
    let block = String::from_utf8_lossy(fields).to_ascii_lowercase();
    let lines: Vec<&str> = block
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("content-length:"))
            .copied()
            .collect::<Vec<_>>(),
        [format!("content-length: {}", bytes.len()).as_str()],
        "the head states the whole body's length once: {lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.starts_with("transfer-encoding:")),
        "a whole answer is not chunked: {lines:?}"
    );
    (*status, bytes.clone())
}

#[tokio::test]
async fn unmetered_completion_states_its_length() {
    let _one = PUBLISHING.lock().await;
    let g = governed("unmetered-completion-length", false).await;
    let mut served = g.served.clone();
    // The third claim serves the plane's protected-resource document: an unmetered completion.
    let snapshot = &mut served.planes[0].snapshot;
    snapshot.claims[2].verb = "GET".into();
    snapshot.audience = Some("https://resource.test".into());
    snapshot.resource_metadata = Some("https://resource.test/framed".into());
    let routes = crate::root::serve::door_mounts(served, || None, &[], &[], &[], &[])
        .unwrap()
        .data;
    let head = Head {
        method: "GET".into(),
        target: "/framed".into(),
        authority: String::new(),
        query: None,
        fields: Vec::new(),
    };
    let (_host, admission) = super::admission(Arc::clone(&g.app), routes.guests.clone(), &head);
    let wire =
        crate::root::listener::framed::serve_admitted_wire_test(routes, admission, Vec::new())
            .await;
    let (status, body) = whole_answer(&wire);
    assert_eq!(status, 200);
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["resource"], "https://resource.test");
    assert_eq!(g.money.open_units(), 0);
}

#[tokio::test]
async fn pre_flight_refusal_render_has_no_trailing_refuse() {
    let _one = PUBLISHING.lock().await;
    let g = governed_full(
        "pre-flight-refusal-length",
        true,
        Some(1),
        Screen::Nothing,
        None,
        None,
        false,
    )
    .await;
    let routes = crate::root::serve::door_mounts(
        g.served.clone(),
        || None,
        &[(busbar_kernel::config::KEYS_MODULE.into(), AuthPoints::HEAD)],
        &[],
        &[],
        &[],
    )
    .unwrap()
    .data;
    let ingress = Ingress::new(&g, &routes);
    let serve = |stream: u64| {
        let routes = Arc::clone(&routes);
        let ingress = &ingress;
        let token = g.token.clone();
        async move {
            let (answer, head) = ingress.authenticate(stream, &token).await;
            let admission = ingress.claim(stream, &answer, head);
            let wire = crate::root::listener::framed::serve_admitted_wire_test(
                routes,
                admission,
                vec![Ok(bytes::Bytes::from_static(b"ping"))],
            )
            .await;
            ingress.host.stream_ended(OWNER, FRAMING, stream);
            wire
        }
    };
    // The one-request budget admits the first call; the second is refused before any egress.
    let first = serve(1).await;
    assert!(
        matches!(
            first.first(),
            Some(crate::root::listener::framed::WireOp::Head { status: 200, .. })
        ),
        "the budget admits one call: {first:?}"
    );
    assert_eq!(g.requests().await, 1);
    let refused = serve(2).await;
    let (status, body) = whole_answer(&refused);
    assert_eq!(status, 429, "{refused:?}");
    assert!(
        body.starts_with(b"refused:429:"),
        "{:?}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(g.requests().await, 1, "the refused call charged nothing");
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
}
