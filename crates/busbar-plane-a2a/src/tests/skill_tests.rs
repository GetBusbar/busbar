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

#[test]
fn an_agent_with_no_held_card_is_refused_by_the_catalogue_s_name() {
    assert_eq!(refusal(&Unfit::NoCachedCard).message, "NoCachedCard");
    assert_eq!(refusal(&Unfit::NoCachedCard).status, 403);
}

// ── the engine's catalogue fitness cells (`busbar-a2a` `catalogue_tests.rs`), on the fit ─────────

/// A card with `skills` and `capabilities`, its default modes JSON both ways.
fn a_card(skills: Value, capabilities: Value) -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "agent",
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": capabilities,
        "skills": skills,
    })
}

/// The planner streams and takes no push; the researcher takes push and does not stream.
fn planner() -> Value {
    a_card(
        json!([{ "id": "plan", "name": "Plan" }, { "id": "summarize", "name": "Summarize" }]),
        json!({ "streaming": true, "pushNotifications": false }),
    )
}

fn researcher() -> Value {
    a_card(
        json!([{ "id": "research", "name": "Research" }]),
        json!({ "streaming": false, "pushNotifications": true }),
    )
}

/// A protocol capability the task requires and the card does not declare excludes the agent, on
/// each of the two capabilities; a card that declares it fits.
#[test]
fn a_required_protocol_capability_the_card_does_not_declare_excludes_the_agent() {
    let streams = TaskShape {
        requires_stream: true,
        ..Default::default()
    };
    assert_eq!(fit(&planner(), &streams), Ok(None), "it declares streaming");
    assert_eq!(
        fit(&researcher(), &streams),
        Err(Unfit::CapabilityNotDeclared("streaming"))
    );
    let push = TaskShape {
        requires_push_notifications: true,
        ..Default::default()
    };
    assert_eq!(fit(&researcher(), &push), Ok(None), "it declares push");
    assert_eq!(
        fit(&planner(), &push),
        Err(Unfit::CapabilityNotDeclared("pushNotifications"))
    );
}

/// The caller must be able to send what the agent accepts AND read what it produces: an input-mode
/// mismatch and an output-mode mismatch each exclude it, and modes compatible both ways fit.
#[test]
fn modes_must_be_compatible_in_both_directions() {
    let sends_audio = TaskShape {
        input_modes: vec!["audio/wav".to_string()],
        ..Default::default()
    };
    assert_eq!(fit(&planner(), &sends_audio), Err(Unfit::ModesIncompatible));
    let wants_pdf = TaskShape {
        output_modes: vec!["application/pdf".to_string()],
        ..Default::default()
    };
    assert_eq!(fit(&planner(), &wants_pdf), Err(Unfit::ModesIncompatible));
    let json_both_ways = TaskShape {
        input_modes: vec!["application/json".to_string()],
        output_modes: vec!["application/json".to_string()],
        ..Default::default()
    };
    assert_eq!(fit(&planner(), &json_both_ways), Ok(None));
}

/// CONTENT-BLINDNESS BY CONSTRUCTION: the shape the fit reads holds typed metadata only. An
/// exhaustive destructure with no `..`, so a field for prose cannot arrive without this failing to
/// compile.
#[test]
fn the_task_shape_carries_no_channel_for_prose() {
    let TaskShape {
        skill,
        requires_stream,
        requires_push_notifications,
        input_modes,
        output_modes,
    } = TaskShape::default();
    assert!(skill.is_none());
    assert!(!requires_stream && !requires_push_notifications);
    assert!(input_modes.is_empty() && output_modes.is_empty());
}
