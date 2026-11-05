// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn credential_applied_response_and_restart_receipt_are_machine_readable() {
    for operation in ["key.rotate", "key.patch", "key.delete"] {
        let response = applied_mutation(operation, "key:public-id");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc["error"]["code"], "mutation_applied");
        assert_eq!(doc["effect"], "applied");
        assert_eq!(doc["operation"], operation);
        assert_eq!(doc["resource"], "key:public-id");
        assert_eq!(doc["credential_recoverable"], false);
        assert!(doc.get("token").is_none());
    }
    let response = claim_refused(
        KeyAudit::Mutation {
            verb: "key.rotate",
            resource: "key:public-id",
            actor: "actor",
        },
        Refused::Applied("key:public-id".into()),
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["effect"], "applied");
    assert_eq!(doc["recovery"], "rotate_with_new_action");
    assert_eq!(doc["resource"], "key:public-id");
}
