// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The skill a request matches on a held card, and the refusal of one it does not fit, in the
//! served engine's words (`busbar-a2a` `registry::judge`, `receive::admit`).

use serde_json::json;

use super::*;

fn card() -> Value {
    json!({
        "name": "Planner",
        "capabilities": { "streaming": false, "pushNotifications": true },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            { "id": "summarize", "outputModes": ["application/json"] },
            { "id": "plan" },
        ],
    })
}

fn send(params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": params })
}

#[test]
fn a_named_skill_the_card_declares_is_the_match() {
    let shape = TaskShape::of(&send(json!({ "metadata": { "skill": "plan" } })));
    assert_eq!(fit(&card(), &shape), Ok(Some("plan".into())));
}

#[test]
fn a_request_naming_no_skill_matches_none() {
    assert_eq!(fit(&card(), &TaskShape::of(&send(json!({})))), Ok(None));
}

#[test]
fn a_skills_own_modes_override_the_cards_defaults() {
    let wants_json = send(json!({ "metadata": { "skill": "summarize" },
        "configuration": { "acceptedOutputModes": ["application/json"] } }));
    assert_eq!(
        fit(&card(), &TaskShape::of(&wants_json)),
        Ok(Some("summarize".into()))
    );
    let wants_json_from_plan = send(json!({ "metadata": { "skill": "plan" },
        "configuration": { "acceptedOutputModes": ["application/json"] } }));
    assert_eq!(
        fit(&card(), &TaskShape::of(&wants_json_from_plan)),
        Err(Unfit::ModesIncompatible)
    );
}

#[test]
fn an_unfit_request_is_refused_403_in_the_engines_exclusion_words() {
    let undeclared = TaskShape::of(&send(json!({ "metadata": { "skill": "fly" } })));
    let unfit = fit(&card(), &undeclared).unwrap_err();
    assert_eq!(unfit, Unfit::SkillNotDeclared("fly".into()));
    let stream = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/stream", "params": {} });
    assert_eq!(
        fit(&card(), &TaskShape::of(&stream)),
        Err(Unfit::CapabilityNotDeclared("streaming"))
    );
    assert_eq!(
        fit(&json!([1]), &TaskShape::default()),
        Err(Unfit::Unreadable(Unreadable::NotAnObject))
    );
    let refused = refusal(&unfit);
    assert_eq!(
        refused.envelope(),
        json!({ "jsonrpc": "2.0", "id": null, "error": {
            "code": -32004, "message": "SkillNotDeclared(\"fly\")",
            "data": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org", "reason": "UNSUPPORTED_OPERATION" }] } })
    );
    assert_eq!(refused.status, 403);
    assert_eq!(
        refusal(&Unfit::CapabilityNotDeclared("streaming")).message,
        "CapabilityNotDeclared(\"streaming\")"
    );
    assert_eq!(
        refusal(&Unfit::Unreadable(Unreadable::NotAnObject)).message,
        "Unreadable(NotAnObject)"
    );
}

#[test]
fn the_shape_reads_every_spelling_of_a_stream_and_a_push_callback() {
    for method in [
        "message/stream",
        "SendStreamingMessage",
        "tasks/resubscribe",
        "SubscribeToTask",
    ] {
        assert!(
            TaskShape::of(&json!({ "method": method })).requires_stream,
            "{method}"
        );
    }
    assert!(!TaskShape::of(&json!({ "method": "SendMessage" })).requires_stream);
    for at in [
        json!({ "pushNotificationConfig": {} }),
        json!({ "taskPushNotificationConfig": {} }),
        json!({ "taskPushNotificationConfig": { "pushNotificationConfig": {} } }),
    ] {
        let shape = TaskShape::of(&json!({ "params": { "configuration": at } }));
        assert!(shape.requires_push_notifications);
    }
}
