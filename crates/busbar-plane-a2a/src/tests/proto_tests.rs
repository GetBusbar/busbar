// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The generated messages and the SDK model's rules over them (`pbconv`'s round trip, ported).

use super::*;

/// The service name is the vendored descriptor's own.
#[test]
fn the_service_name_is_the_descriptors() {
    let proto = include_str!("../../proto/a2a.proto");
    let (package, service) = SERVICE_NAME.rsplit_once('.').expect("package.Service");
    assert!(proto.contains(&format!("package {package};")));
    assert!(proto.contains(&format!("service {service} {{")));
}

/// An enum value the model does not know is its unspecified one; a known one stands.
#[test]
fn an_unknown_enum_value_is_clamped() {
    let mut m = pb::Message {
        role: 99,
        ..Default::default()
    };
    m.normal().unwrap();
    assert_eq!(m.role, pb::Role::Unspecified as i32);
    let mut m = pb::Message {
        role: pb::Role::Agent as i32,
        ..Default::default()
    };
    m.normal().unwrap();
    assert_eq!(m.role, pb::Role::Agent as i32);
    let mut s = pb::TaskStatus {
        state: 77,
        ..Default::default()
    };
    s.normal().unwrap();
    assert_eq!(s.state, pb::TaskState::Unspecified as i32);
}

/// A part with no content is an empty text; a value that is not finite is `null`.
#[test]
fn a_contentless_part_is_empty_text_and_a_non_finite_number_is_null() {
    let mut p = pb::Part::default();
    p.normal().unwrap();
    assert_eq!(p.content, Some(pb::part::Content::Text(String::new())));
    let mut p = pb::Part {
        content: Some(pb::part::Content::Data(Value {
            kind: Some(Kind::NumberValue(f64::NAN)),
        })),
        ..Default::default()
    };
    p.normal().unwrap();
    assert_eq!(
        p.content,
        Some(pb::part::Content::Data(Value {
            kind: Some(Kind::NullValue(0))
        }))
    );
}

/// A task with no status has the unspecified one; an unrepresentable timestamp is dropped.
#[test]
fn a_statusless_task_and_an_unrepresentable_timestamp() {
    let mut t = pb::Task::default();
    t.normal().unwrap();
    assert_eq!(t.status, Some(pb::TaskStatus::default()));
    let mut s = pb::TaskStatus {
        timestamp: Some(Timestamp {
            seconds: 0,
            nanos: -1,
        }),
        ..Default::default()
    };
    s.normal().unwrap();
    assert_eq!(s.timestamp, None);
    let mut s = pb::TaskStatus {
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 5,
        }),
        ..Default::default()
    };
    s.normal().unwrap();
    assert!(s.timestamp.is_some());
}

/// A non-positive page size is none.
#[test]
fn a_non_positive_page_size_is_none() {
    let mut r = pb::ListTasksRequest {
        page_size: Some(0),
        ..Default::default()
    };
    r.normal().unwrap();
    assert_eq!(r.page_size, None);
    let mut r = pb::ListTasksRequest {
        page_size: Some(5),
        ..Default::default()
    };
    r.normal().unwrap();
    assert_eq!(r.page_size, Some(5));
}

/// An answer with no payload is refused, in the SDK's words.
#[test]
fn an_answer_with_no_payload_is_refused() {
    assert_eq!(
        pb::SendMessageResponse::default()
            .normal()
            .unwrap_err()
            .to_string(),
        "ProtoJSON payload missing required data for SendMessageResponse"
    );
    assert_eq!(
        pb::StreamResponse::default().normal(),
        Err(MissingPayload("StreamResponse"))
    );
}

/// The card: a gRPC interface's URL loses `http://`; a scheme-less security scheme is dropped; an
/// OAuth2 scheme with no flow gets the empty client-credentials one; no capabilities is empty ones.
#[test]
fn the_card_follows_the_models_rules() {
    let mut card = pb::AgentCard {
        supported_interfaces: vec![
            pb::AgentInterface {
                url: "http://h:1".into(),
                protocol_binding: "grpc".into(),
                ..Default::default()
            },
            pb::AgentInterface {
                url: "http://h:2".into(),
                protocol_binding: "JSONRPC".into(),
                ..Default::default()
            },
        ],
        security_schemes: [
            ("none".to_string(), pb::SecurityScheme { scheme: None }),
            (
                "oauth".to_string(),
                pb::SecurityScheme {
                    scheme: Some(pb::security_scheme::Scheme::Oauth2SecurityScheme(
                        pb::OAuth2SecurityScheme::default(),
                    )),
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    card.normal().unwrap();
    assert_eq!(card.supported_interfaces[0].url, "h:1");
    assert_eq!(card.supported_interfaces[1].url, "http://h:2");
    assert!(!card.security_schemes.contains_key("none"));
    let Some(pb::security_scheme::Scheme::Oauth2SecurityScheme(oa)) =
        &card.security_schemes["oauth"].scheme
    else {
        panic!("the oauth scheme stays");
    };
    assert!(matches!(
        oa.flows.as_ref().and_then(|f| f.flow.as_ref()),
        Some(pb::o_auth_flows::Flow::ClientCredentials(_))
    ));
    assert_eq!(card.capabilities, Some(pb::AgentCapabilities::default()));
}

/// A JSON `null` for a repeated member reads as empty (the generated serde's patch).
#[test]
fn a_null_repeated_member_reads_as_empty() {
    let task: pb::Task =
        serde_json::from_value(serde_json::json!({ "id": "t", "contextId": "c", "history": null }))
            .expect("null history reads");
    assert!(task.history.is_empty());
}
