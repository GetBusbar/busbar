// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::FLOW_CONTINUE;
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::{AuthCalls, Verified, VerifiedIdentity, VerifyAnswer};
use busbar_contract::caps::{Outcome, ReasonCode, StepName};
use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
use std::sync::Mutex;
use tower::ServiceExt;

const PATH: &str = "/api/v1/admin/keys";
const PROVIDER: &str = "first-auth-admin";
const FRAMING: u64 = 74;

struct Identity;
impl AuthCalls for Identity {
    fn name(&self) -> &str {
        PROVIDER
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, _: &busbar_contract::auth_calls::VerifyRequest) -> Option<VerifyAnswer> {
        Some(VerifyAnswer {
            strips: vec![busbar_contract::auth_calls::Strip::field("authorization")],
            ..VerifyAnswer::from(Verified::Identity(VerifiedIdentity {
                subject: "first-auth-reader".into(),
                groups: vec!["reader".into()],
                ..Default::default()
            }))
        })
    }
    fn verify(
        &self,
        request: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Answered(self.verify_now(&request)))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

struct Answered(Option<VerifyAnswer>);
impl std::future::Future for Answered {
    type Output = VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().unwrap())
    }
}
impl busbar_contract::auth_calls::Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

async fn admitted(
    host: &Arc<Inbound>,
    listener: &kin::Listener,
    stream: u64,
    method: &str,
    deadline: Option<std::time::Instant>,
) -> kin::RequestAdmission {
    host.grant_stream(OWNER, FRAMING, stream, GEN).unwrap();
    let mut head = kin::Head {
        method: method.into(),
        target: PATH.into(),
        authority: String::new(),
        query: None,
        fields: vec![(
            "authorization".into(),
            b"Bearer stripped-first-auth-proof".to_vec(),
        )],
    };
    let answer = host
        .auth_call(
            kin::Call {
                owner: OWNER,
                generation: GEN,
                auth: listener.ids[0],
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: FRAMING,
                stream,
                framing: FRAMING,
                head: head.clone(),
                body: None,
                deadline,
            },
            Box::new(|_| panic!("immediate fixture")),
        )
        .unwrap()
        .unwrap();
    assert_eq!(answer.flow, FLOW_CONTINUE);
    head.fields.clear();
    let (_, unit) = host
        .hand_in(kin::HandIn {
            owner: OWNER,
            generation: GEN,
            auth: listener.ids[0],
            unit: answer.unit,
            line: 0,
            conn: FRAMING,
            stream,
            framing: Some(FRAMING),
            head: head.clone(),
        })
        .unwrap();
    let admission = host.claim_request(OWNER, FRAMING, stream, &head).unwrap();
    assert_eq!(admission.unit_key().get(), unit.id);
    assert_eq!(admission.deadline(), deadline);
    admission
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_first_auth_identity_survives_reload_and_seals_once_without_charges() {
    let (original, _, _) = app(false);
    let mut pinned = (*original).clone();
    pinned.role_bindings = serde_json::from_value(serde_json::json!({
        (PROVIDER): {"reader": {"admin_scope": "read-only"}}
    }))
    .unwrap();
    let pinned = Arc::new(pinned);
    let slots = crate::root::store_double::RecordSlots::new();
    let lane =
        crate::root::durability::JournalLane::start(slots.calls(), "operator-identity").unwrap();
    let node_id = busbar_kernel::door::op_id().counter();
    let mut durability =
        crate::root::durability::build_on_store(&Default::default(), node_id, lane.clone(), None)
            .unwrap();
    durability.record = busbar_kernel_audit::AuditChain::new()
        .sealing_as(node_id)
        .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[0x73; 32]));
    let book = Arc::new(Mutex::new(durability));
    let node = Arc::new(crate::root::plane_node::Node::new());
    node.bind_book(Arc::clone(&book));
    let mint = Arc::clone(&node);
    let refused = Arc::clone(&node);
    let host = Inbound::new(
        kin::Seals {
            mint: Arc::new(move || mint.mint().get()),
            mac: Arc::new(|tag| Some(tag.unit ^ tag.secret[0])),
        },
        Arc::new(|future| {
            tokio::spawn(future);
        }),
        Arc::new(move |event| refused.refused_inbound(event)),
    );
    let listener = kin::Listener {
        guests: GuestList::seal(vec![Line {
            route: Route {
                methods: METHOD_GET | METHOD_POST,
                path_form: PATH_EXACT,
                path: PATH.into(),
                fields: Vec::new(),
                rung: 0,
            },
            claimant: Claimant::Clean("admin".into()),
            dialect: 0,
            auth: LineAuth::Chain(vec![PROVIDER.into()], AuthPoints::HEAD),
            upgrade: None,
            offered: AuthPoints::HEAD,
        }])
        .unwrap(),
        auths: std::collections::HashMap::from([(
            PROVIDER.into(),
            Arc::new(Identity) as Arc<dyn AuthCalls>,
        )]),
        body_limit: 4096,
        app: Arc::clone(&pinned),
        door_refusals: Vec::new(),
        ids: vec![auth_handle::next_ref_id(RefSpace::Line)],
        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    };
    host.install_at(OWNER, 1, GEN, listener.clone()).unwrap();
    host.framing_started(OWNER, 1, FRAMING, GEN).unwrap();
    let good = admitted(&host, &listener, 1, "GET", None).await;
    let denied = admitted(&host, &listener, 2, "POST", None).await;
    let cancelled = admitted(&host, &listener, 3, "GET", None).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
    let expired = admitted(&host, &listener, 4, "GET", Some(deadline)).await;
    host.stream_ended(OWNER, FRAMING, 3);
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    let mut replacement = (*pinned).clone();
    replacement.role_bindings.clear();
    let replacement = Arc::new(replacement);
    let mut replaced = listener.clone();
    replaced.app = Arc::clone(&replacement);
    host.install_at(OWNER, 1, GEN + 1, replaced).unwrap();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(replacement));
    let inner = busbar_kernel::router::build_admin_router_on(&handle, 4096, false);
    let held = Arc::clone(&book);
    let router = crate::root::units_admin::mount(
        inner,
        crate::root::kernel::new_kernel(),
        4096,
        move |dispatch| {
            crate::root::kernel::ProductionUnits::admin_only_sharing(
                dispatch,
                Arc::new(|_| panic!("an admitted operator must never authenticate again")),
                held,
                None,
            )
        },
    );
    let ids = [
        good.unit_key(),
        denied.unit_key(),
        cancelled.unit_key(),
        expired.unit_key(),
    ];
    for (admission, method, status) in [
        (good, "GET", 200),
        (denied, "POST", 403),
        (cancelled, "GET", 503),
        (expired, "GET", 503),
    ] {
        assert_eq!(admission.generation(), GEN);
        assert!(Arc::ptr_eq(&admission.app(), &pinned));
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(PATH)
                    .extension(admission.clone())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert!(
            !admission.begin_execution(),
            "the operation already owns its terminal record"
        );
    }
    assert!(lane.drain(std::time::Duration::from_secs(5)));
    let records = book.lock().unwrap().chain_at().audit_window(1, 4).unwrap();
    assert_eq!(records.len(), 4);
    for (record, id) in records.iter().zip(ids) {
        assert_eq!(record.what.unit_key, id);
        assert_eq!(
            record.subject,
            busbar_kernel_audit::Subject::PrincipalId("first-auth-reader".into())
        );
        assert!(record.usage.lines.is_empty());
        assert_eq!(record.usage.fee_count, 0);
    }
    assert_eq!(records[0].outcome.unit_end, Outcome::Completed);
    assert_eq!(
        records[1].outcome.unit_end,
        Outcome::Refused(StepName::Approve, ReasonCode::ScopeDenied)
    );
    assert_eq!(
        records[2].outcome.unit_end,
        Outcome::Refused(StepName::Arrival, ReasonCode::ClientGone)
    );
    assert_eq!(
        records[3].outcome.unit_end,
        Outcome::Refused(StepName::Arrival, ReasonCode::DeadlineExceeded)
    );
    let keys = crate::root::durability::keyset_of(&book.lock().unwrap().record);
    for record in &records {
        busbar_kernel_audit::AuditChain::verify_signature(
            record,
            keys.get(record.key_id.as_deref().unwrap()).unwrap(),
        )
        .unwrap();
    }
    assert!(busbar_kernel_audit::AuditChain::verify_chain(&records).is_ok());
    let reopened = crate::root::durability::build_on_store(
        &Default::default(),
        node_id,
        crate::root::durability::JournalLane::start(slots.calls(), "operator-identity-reopen")
            .unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(reopened.audit_window(1, 4), Some(records));
}
