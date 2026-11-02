// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::credential_flush_response;
use busbar_kernel::audit_ring;
use std::sync::Mutex;

static ACCEPTED: Mutex<Option<tokio::sync::mpsc::UnboundedSender<audit_ring::AuditEntry>>> =
    Mutex::new(None);

fn accepted(entry: &audit_ring::AuditEntry) {
    if entry.action == "auth.cache_flush" && entry.principal.starts_with("flush-projection:") {
        if let Some(sender) = &*ACCEPTED.lock().unwrap() {
            let _ = sender.send(entry.clone());
        }
    }
}

#[tokio::test]
async fn completed_refresh_answers_project_truthful_status_body_and_audit() {
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    *ACCEPTED.lock().unwrap() = Some(sender);
    busbar_kernel::audit::auditlog::install_accepted_entry_test_hook(accepted);
    for (actor, result, module, status, outcome) in [
        (
            "flush-projection:admin-refused",
            Err("private-refresh-error-token".into()),
            None,
            500,
            audit_ring::OUTCOME_REJECTED,
        ),
        (
            "flush-projection:data-refused",
            Err("private-refresh-error-token".into()),
            None,
            500,
            audit_ring::OUTCOME_REJECTED,
        ),
        (
            "flush-projection:filtered",
            Ok(8),
            Some("target"),
            200,
            audit_ring::OUTCOME_APPLIED,
        ),
        (
            "flush-projection:absent",
            Ok(0),
            Some("not-configured"),
            200,
            audit_ring::OUTCOME_APPLIED,
        ),
    ] {
        let response = credential_flush_response(result, module, actor);
        assert_eq!(response.status().as_u16(), status);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private-refresh-error-token"));
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if status == 500 {
            assert_eq!(body["error"]["code"], "internal");
            assert!(
                body.get("flushed").is_none(),
                "partial progress is not a successful flush"
            );
        } else {
            assert_eq!(
                body["flushed"],
                if module == Some("target") { 8 } else { 0 }
            );
        }
        let row = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.principal, actor);
        assert_eq!(row.resource, module.unwrap_or("*"));
        assert_eq!(row.outcome, outcome);
    }
    *ACCEPTED.lock().unwrap() = None;
}
