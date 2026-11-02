// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RefreshDoor {
    drops: u64,
    fails: bool,
    calls: AtomicUsize,
}

impl RefreshDoor {
    fn new(drops: u64, fails: bool) -> Arc<Self> {
        Arc::new(Self {
            drops,
            fails,
            calls: AtomicUsize::new(0),
        })
    }
}

impl busbar_contract::auth_calls::AuthCalls for RefreshDoor {
    fn name(&self) -> &str {
        "refresh-test"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Passed)
    }
    fn refresh(&self) -> Result<u64, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fails {
            Err("private-refresh-error-token".into())
        } else {
            Ok(self.drops)
        }
    }
}

async fn flush(
    app: Arc<busbar_kernel::state::App>,
    actor: &str,
    module: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let body = module.map_or_else(Vec::new, |name| {
        serde_json::to_vec(&serde_json::json!({"module": name})).unwrap()
    });
    let response = crate::v1::json::flush_credential_cache(
        axum::extract::State(Arc::new(busbar_kernel::state::AppHandle::new(app))),
        axum::Extension(busbar_kernel::auth::AuthPrincipal(Some(
            busbar_kernel::auth::Principal::from_id(actor.to_string()),
        ))),
        axum::body::Bytes::from(body),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("private-refresh-error-token"));
    (status, serde_json::from_slice(&body).unwrap())
}

fn audit_outcomes(actor: &str) -> Vec<String> {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, audit_ring::MAX_AUDIT_ENTRIES, None, None)
        .into_iter()
        .filter(|entry| entry.action == "auth.cache_flush" && entry.principal == actor)
        .map(|entry| entry.outcome)
        .collect()
}

async fn accepted_audit(
    observation: busbar_kernel::audit::auditlog::AcceptedAdminAudit,
) -> audit_ring::AuditEntry {
    tokio::time::timeout(std::time::Duration::from_secs(5), observation.accepted())
        .await
        .expect("the credential flush audit must be published")
        .expect("the accepted audit observer remains registered")
}

#[tokio::test]
async fn a_failed_admin_or_data_refresh_is_not_a_successful_flush() {
    for (actor, admin_fails) in [("flush-error-admin", true), ("flush-error-data", false)] {
        let admin = RefreshDoor::new(3, admin_fails);
        let later_admin = RefreshDoor::new(7, false);
        let data = RefreshDoor::new(5, !admin_fails);
        let later_data = RefreshDoor::new(11, false);
        let auth = busbar_kernel::auth::AuthMiddleware::from_doors_for_test(vec![
            ("data".into(), data.clone()),
            ("later-data".into(), later_data.clone()),
        ]);
        let app = crate::new_test_app()
            .auth(Arc::new(auth))
            .admin_door("a-admin", admin.clone())
            .admin_door("z-later-admin", later_admin.clone())
            .build();
        let audit = busbar_kernel::audit::auditlog::observe_accepted_admin_entry(
            "auth.cache_flush",
            "*",
            actor,
        );
        let (status, body) = flush(app, actor, None).await;
        assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal");
        assert!(
            body.get("flushed").is_none(),
            "partial progress is not a successful flush"
        );
        for door in [&admin, &later_admin, &data, &later_data] {
            assert_eq!(
                door.calls.load(Ordering::SeqCst),
                1,
                "every selected module is attempted"
            );
        }
        assert_eq!(
            accepted_audit(audit).await.outcome,
            audit_ring::OUTCOME_REJECTED
        );
        assert_eq!(audit_outcomes(actor), vec![audit_ring::OUTCOME_REJECTED]);
    }
}

#[tokio::test]
async fn a_filtered_flush_sums_both_chains_without_refreshing_other_modules() {
    let admin = RefreshDoor::new(3, false);
    let data = RefreshDoor::new(5, false);
    let omitted_admin = RefreshDoor::new(0, true);
    let omitted_data = RefreshDoor::new(0, true);
    let auth = busbar_kernel::auth::AuthMiddleware::from_doors_for_test(vec![
        ("target".into(), data.clone()),
        ("omitted".into(), omitted_data.clone()),
    ]);
    let app = crate::new_test_app()
        .auth(Arc::new(auth))
        .admin_door("target", admin.clone())
        .admin_door("omitted", omitted_admin.clone())
        .build();
    let audit = busbar_kernel::audit::auditlog::observe_accepted_admin_entry(
        "auth.cache_flush",
        "target",
        "flush-filtered",
    );
    let (status, body) = flush(app.clone(), "flush-filtered", Some("target")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["flushed"], 8);
    assert_eq!(
        accepted_audit(audit).await.outcome,
        audit_ring::OUTCOME_APPLIED
    );
    assert_eq!(
        audit_outcomes("flush-filtered"),
        vec![audit_ring::OUTCOME_APPLIED]
    );
    for door in [&admin, &data] {
        assert_eq!(door.calls.load(Ordering::SeqCst), 1);
    }
    for door in [&omitted_admin, &omitted_data] {
        assert_eq!(door.calls.load(Ordering::SeqCst), 0);
    }
    let (status, body) = flush(app, "flush-absent", Some("not-configured")).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["flushed"], 0);
}
