// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::transport::route::{METHOD_GET, PATH_EXACT};
use busbar_kernel::guest::{Line, Route};
use busbar_kernel::inbound::{HandIn, Head, Inbound, Listener, RequestAdmission, Seals};

const OWNER: u64 = 71;
const LISTENER: u64 = 73;
const FRAMING: u64 = 79;
const STREAM: u64 = 83;

async fn listener(upgrade: Option<&str>, generation: u64) -> Listener {
    let app = projection_boundary_app(topology(), vec![], generation).await;
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: "/live".into(),
            fields: vec![],
            rung: 0,
        },
        claimant: Claimant::Plane("fixture".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: upgrade.map(str::to_owned),
        offered: AuthPoints::HEAD,
    }])
    .unwrap();
    Listener {
        guests,
        auths: Default::default(),
        body_limit: 1024,
        app,
        door_refusals: vec![],
        ids: vec![1],
        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    }
}

async fn admitted(
    upgrade: Option<&str>,
    deadline: Option<std::time::Instant>,
) -> (Arc<Inbound>, RequestAdmission) {
    let next = Arc::new(std::sync::atomic::AtomicU64::new(100));
    let inbound = Inbound::new(
        Seals {
            mint: Arc::new(move || next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)),
            mac: Arc::new(|tag| {
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
        Arc::new(|_| {}),
    );
    inbound
        .install_at(OWNER, LISTENER, 1, listener(upgrade, 1).await)
        .unwrap();
    inbound
        .framing_started(OWNER, LISTENER, FRAMING, 1)
        .unwrap();
    inbound.grant_stream(OWNER, FRAMING, STREAM, 1).unwrap();
    let head = Head {
        method: "GET".into(),
        target: "/live".into(),
        authority: "listener.test".into(),
        query: None,
        fields: vec![],
    };
    let (flow, _) = inbound
        .hand_in_with_deadline(
            HandIn {
                owner: OWNER,
                generation: 1,
                auth: 1,
                unit: UnitRef::NONE,
                line: 0,
                conn: FRAMING,
                stream: STREAM,
                framing: Some(FRAMING),
                head: head.clone(),
            },
            deadline,
        )
        .unwrap();
    assert_eq!(flow, busbar_contract::abi::host::service::FLOW_CONTINUE);
    let admission = inbound
        .claim_request(OWNER, FRAMING, STREAM, &head)
        .unwrap();
    (inbound, admission)
}

#[tokio::test]
async fn upgrade_authority_uses_the_exact_admitted_route_and_is_consumed_once() {
    let (_inbound, admission) = admitted(Some("fixture-session"), None).await;
    let permit = admission.upgrade_permit().unwrap();
    let copy = permit.clone();
    assert!(permit
        .consume(&admission, OWNER + 1, FRAMING, STREAM)
        .is_none());
    assert!(permit
        .consume(&admission, OWNER, FRAMING + 1, STREAM)
        .is_none());
    assert!(permit
        .consume(&admission, OWNER, FRAMING, STREAM + 1)
        .is_none());
    assert_eq!(
        permit.consume(&admission, OWNER, FRAMING, STREAM),
        Some("fixture-session")
    );
    assert!(copy.consume(&admission, OWNER, FRAMING, STREAM).is_none());
    let (_plain, ordinary) = admitted(None, None).await;
    assert!(ordinary.upgrade_permit().is_none());
}

#[tokio::test]
async fn another_request_with_identical_numeric_handles_cannot_use_an_upgrade_permit() {
    let (_first_inbound, first) = admitted(Some("fixture-session"), None).await;
    let (_second_inbound, second) = admitted(Some("fixture-session"), None).await;
    let permit = first.upgrade_permit().unwrap();
    assert!(permit.consume(&second, OWNER, FRAMING, STREAM).is_none());
    assert_eq!(
        permit.consume(&first, OWNER, FRAMING, STREAM),
        Some("fixture-session")
    );
}

#[tokio::test]
async fn expired_or_retired_request_cannot_authorize_an_upgrade() {
    let (_inbound, expired) =
        admitted(Some("fixture-session"), Some(std::time::Instant::now())).await;
    assert!(expired
        .upgrade_permit()
        .unwrap()
        .consume(&expired, OWNER, FRAMING, STREAM)
        .is_none());
    for connection_ended in [false, true] {
        let (inbound, retired) = admitted(Some("fixture-session"), None).await;
        let permit = retired.upgrade_permit().unwrap();
        if connection_ended {
            inbound.framing_ended(FRAMING);
        } else {
            inbound.stream_ended(OWNER, FRAMING, STREAM);
        }
        assert!(permit.consume(&retired, OWNER, FRAMING, STREAM).is_none());
    }
}

#[tokio::test]
async fn an_admitted_upgrade_retains_its_exact_claim_across_listener_reload() {
    let (inbound, admitted) = admitted(Some("old-session"), None).await;
    let permit = admitted.upgrade_permit().unwrap();
    for generation in 2..=4 {
        inbound
            .install_at(
                OWNER,
                LISTENER,
                generation,
                listener(Some("new-session"), generation).await,
            )
            .unwrap();
    }
    inbound.retire_before(4);
    assert!(inbound.specs_at(OWNER, LISTENER, 1).is_none());
    assert_eq!(
        permit.consume(&admitted, OWNER, FRAMING, STREAM),
        Some("old-session"),
        "reload cannot retarget authority already issued to a live request"
    );
}
