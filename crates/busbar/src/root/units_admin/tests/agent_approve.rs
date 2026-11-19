// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /api/v1/admin/agents/{name}/approve`, END TO END over the mounted admin chain (PROOF-076):
//! no credential and a wrong credential are refused before any trust code runs; a read-only
//! credential is refused (approving needs the operator); the operator approves the agent's card at
//! the fingerprint `connect` reported, and nothing else; every request leaves exactly one audit row.

use std::sync::Arc;

/// The agent the A2A plane instance `a2a` registers, and the card fingerprint `connect` reported.
const INSTANCE: &str = "a2a";
const AGENT: &str = "billing";
const FINGERPRINT: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const CHANGED: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

const THE_OPERATORS_CREDENTIAL: &str = "agent-approve-operator-token";
const A_READERS_CREDENTIAL: &str = "agent-approve-reader-token";
/// Principals of this file's own, so the audit rows it counts are its own.
const THE_OPERATOR: &str = "agent-approve-operator";
const A_READER: &str = "agent-approve-reader";

/// The item the A2A plane sights an agent's card under.
const CARD: &str = "card";

const PATH: &str = "/api/v1/admin/agents/billing/approve";

struct ADirectoryThatMintedIt;

impl busbar_kernel_identity::RevocationView for ADirectoryThatMintedIt {
    fn is_revoked(&self, _credential: &str) -> bool {
        false
    }
}

fn a_door() -> crate::root::units_admin::AdminDoorFn {
    use busbar_contract::auth::Principal;
    use busbar_contract::authz::{Grants, Scope};
    use busbar_kernel::auth::AdminDoor;
    crate::root::units_admin::door_of(|credential| match credential {
        Some(THE_OPERATORS_CREDENTIAL) => {
            AdminDoor::Identified(Principal::from_id(THE_OPERATOR), Grants::of(Scope::Full))
        }
        Some(A_READERS_CREDENTIAL) => {
            AdminDoor::Identified(Principal::from_id(A_READER), Grants::of(Scope::ReadOnly))
        }
        _ => AdminDoor::Denied,
    })
}

/// A bound-custody kernel admitting the agent `billing` at the A2A instance `a2a`, its card sighted
/// at [`FINGERPRINT`] the way `connect` sights it (the agent and its `card` item).
async fn a_kernel_that_sighted_the_card() -> Arc<busbar_kernel::host_services::KernelServices> {
    use busbar_contract::services::{Caller, HostServices, Ran};
    use busbar_kernel::host_services::InstanceFacts;
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;
    let kernel = Arc::new(crate::root::units_admin::bound::bound_tests::bound_kernel().await);
    kernel
        .admit(
            &INSTANCE.into(),
            InstanceFacts {
                trust: vec![(
                    AGENT.to_string(),
                    TrustEntry {
                        pin: None,
                        policy: Policy {
                            ttl_ms: 0,
                            recovery_backoff_ms: 0,
                        },
                        approved: Default::default(),
                    },
                )],
                ..InstanceFacts::default()
            },
        )
        .await
        .expect("admitted");
    let caller = Caller::for_test(
        Arc::from(INSTANCE),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    let (sent, settled) = tokio::sync::oneshot::channel();
    if let Ran::Later = kernel.trust_sight(
        &caller,
        AGENT,
        FINGERPRINT,
        Box::new(move |stored| {
            let _ = sent.send(stored);
        }),
    ) {
        settled.await.expect("the agent's sighting settles");
    }
    let (sent, settled) = tokio::sync::oneshot::channel();
    if let Ran::Later = kernel.trust_sight_item(
        &caller,
        AGENT,
        CARD,
        FINGERPRINT,
        Box::new(move |stored| {
            let _ = sent.send(stored);
        }),
    ) {
        settled.await.expect("the card's sighting settles");
    }
    kernel
}

/// The admin units mounted behind [`a_door`] with `trust` as the serving kernel's trust book, over a
/// surface that serves nothing of its own: every answer this file reads is the units' own.
async fn a_node(trust: Arc<busbar_kernel::host_services::KernelServices>) -> axum::Router {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    busbar_kernel::audit::auditlog::ensure_global_audit_stream_registered().await;
    let bare = axum::Router::new().fallback(axum::routing::any(|| async {
        axum::http::StatusCode::NOT_FOUND
    }));
    let fixture = crate::root::durability::tests::NativeFixture::new(7).await;
    let held = Arc::new(std::sync::Mutex::new(fixture.book().await));
    crate::root::units_admin::mount(
        bare,
        crate::root::kernel::new_kernel(),
        1 << 20,
        move |dispatch| {
            let mut units = crate::root::kernel::ProductionUnits::admin_only_sharing(
                dispatch,
                a_door(),
                held,
                None,
            )
            .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                ADirectoryThatMintedIt,
            )));
            units.admin.trust = Some(trust);
            units
        },
    )
}

async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: &str,
    credential: Option<&str>,
) -> (u16, serde_json::Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder().method(method).uri(path);
    if let Some(credential) = credential {
        request = request.header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {credential}"),
        );
    }
    let request = request
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("the request builds");
    let response = router
        .clone()
        .oneshot(crate::root::units_admin::charged_http_for_test(request).await)
        .await
        .expect("the mounted router answers");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer's body is readable");
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::Value::from(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

fn approving(fingerprint: &str) -> String {
    format!(r#"{{"fingerprint":"{fingerprint}"}}"#)
}

/// The `(action, outcome)` audit rows `principal` holds for the two actions an agent approval may
/// write (the kernel's typed `trust_approve` and the route's own `agent_approve`), newest first.
async fn rows_of(principal: &str) -> Vec<(String, String)> {
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .expect("the audit rows settle");
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, busbar_kernel::audit_ring::MAX_AUDIT_ENTRIES, None, None)
        .into_iter()
        .filter(|row| {
            row.principal == principal
                && matches!(row.action.as_str(), "agent_approve" | "trust_approve")
        })
        .map(|row| (row.action, row.outcome))
        .collect()
}

fn the_card_is_served(kernel: &busbar_kernel::host_services::KernelServices) -> bool {
    kernel
        .trust_judge(
            INSTANCE,
            &busbar_kernel::trust::book::TrustFacts {
                counterparty: AGENT,
                item: Some(CARD),
                digest: Some(FINGERPRINT),
            },
        )
        .is_ok()
}

#[tokio::test]
async fn agent_approve_refuses_no_token_and_a_wrong_token() {
    let _one = crate::root::PUBLISHING.lock().await;
    let kernel = a_kernel_that_sighted_the_card().await;
    let node = a_node(Arc::clone(&kernel)).await;
    let before = kernel.trust_rows();
    for credential in [None, Some("not-a-credential-this-node-minted")] {
        let (status, body) = send(&node, "POST", PATH, &approving(FINGERPRINT), credential).await;
        assert_eq!(status, 401, "{credential:?} is refused: {body:?}");
        assert_eq!(
            kernel.trust_rows(),
            before,
            "{credential:?}: nothing changes"
        );
        assert!(
            !the_card_is_served(&kernel),
            "{credential:?}: nothing approved"
        );
    }
}

#[tokio::test]
async fn agent_approve_needs_the_operator() {
    let _one = crate::root::PUBLISHING.lock().await;
    let kernel = a_kernel_that_sighted_the_card().await;
    let node = a_node(Arc::clone(&kernel)).await;
    let before = kernel.trust_rows();
    let rows_before = rows_of(A_READER).await;
    let (status, body) = send(
        &node,
        "POST",
        PATH,
        &approving(FINGERPRINT),
        Some(A_READERS_CREDENTIAL),
    )
    .await;
    assert_eq!(
        status, 403,
        "a read-only credential may not approve: {body:?}"
    );
    assert_eq!(kernel.trust_rows(), before, "nothing changes");
    assert!(!the_card_is_served(&kernel), "nothing approved");
    let rows = rows_of(A_READER).await;
    assert_eq!(
        rows.len() - rows_before.len(),
        1,
        "the refusal is one audit row: {rows:?}"
    );
    assert_eq!(
        rows[0],
        ("agent_approve".to_string(), "rejected".to_string())
    );
}

#[tokio::test]
async fn agent_approve_locks_the_card_at_the_reviewed_fingerprint_with_one_audit_row() {
    let _one = crate::root::PUBLISHING.lock().await;
    let kernel = a_kernel_that_sighted_the_card().await;
    let node = a_node(Arc::clone(&kernel)).await;
    let op = Some(THE_OPERATORS_CREDENTIAL);
    assert!(
        !the_card_is_served(&kernel),
        "a sighted card serves only once approved"
    );

    // Refused before the trust book: one route row each, nothing decided.
    let rows_before = rows_of(THE_OPERATOR).await;
    for (path, body, status) in [
        (PATH, "not json".to_string(), 400),
        (PATH, r#"{"fingerprint":"abc"}"#.to_string(), 400),
        (
            PATH,
            format!(r#"{{"fingerprint":"{FINGERPRINT}","force":true}}"#),
            400,
        ),
        (
            "/api/v1/admin/agents/stranger/approve",
            approving(FINGERPRINT),
            404,
        ),
    ] {
        let (got, answer) = send(&node, "POST", path, &body, op).await;
        assert_eq!(got, status, "{path} {body}: {answer:?}");
        assert!(!the_card_is_served(&kernel), "{body}: nothing approved");
    }
    let rows = rows_of(THE_OPERATOR).await;
    assert_eq!(
        rows.len() - rows_before.len(),
        4,
        "one row per refusal: {rows:?}"
    );
    assert!(
        rows[..4]
            .iter()
            .all(|(action, outcome)| action == "agent_approve" && outcome == "rejected"),
        "{rows:?}"
    );

    // A fingerprint other than the card's current one is stale: the trust book refuses it.
    let rows_before = rows_of(THE_OPERATOR).await;
    let (status, answer) = send(&node, "POST", PATH, &approving(CHANGED), op).await;
    assert_eq!(status, 409, "a stale review is refused: {answer:?}");
    assert!(
        !the_card_is_served(&kernel),
        "a stale review approves nothing"
    );
    let rows = rows_of(THE_OPERATOR).await;
    assert_eq!(rows.len() - rows_before.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0],
        ("trust_approve".to_string(), "rejected".to_string())
    );

    // The reviewed fingerprint: the card is approved there, and only the kernel's row is written.
    let rows_before = rows_of(THE_OPERATOR).await;
    let (status, answer) = send(&node, "POST", PATH, &approving(FINGERPRINT), op).await;
    assert_eq!(status, 200, "{answer:?}");
    assert_eq!(answer["agent"].as_str(), Some(AGENT));
    assert_eq!(answer["key"].as_str(), Some("a2a/billing/card"));
    assert_eq!(answer["fingerprint"].as_str(), Some(FINGERPRINT));
    assert_eq!(answer["state"].as_str(), Some("approved"));
    assert!(the_card_is_served(&kernel), "the approved card serves");
    let rows = rows_of(THE_OPERATOR).await;
    assert_eq!(
        rows.len() - rows_before.len(),
        1,
        "exactly one audit row: {rows:?}"
    );
    assert_eq!(
        rows[0],
        ("trust_approve".to_string(), "applied".to_string())
    );
    assert!(
        kernel
            .trust_rows()
            .iter()
            .filter(|row| row.key() != "a2a/billing/card")
            .all(|row| row.approved.is_none()),
        "only the card was approved"
    );
}
