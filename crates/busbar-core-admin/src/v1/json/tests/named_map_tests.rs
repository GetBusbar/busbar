// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::named_map::NamedMapSection;

fn refusal(section: NamedMapSection) -> String {
    match validate_definition(section, "x", &serde_json::json!("not an object")) {
        Err(AdminError::Validation(m)) => m,
        other => panic!("a non-object definition is refused: {other:?}"),
    }
}

#[test]
fn a_non_object_definition_is_refused_in_1_5_5_words() {
    assert_eq!(
        refusal(NamedMapSection::IdentityProviders),
        format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            NamedMapSection::IdentityProviders.singular()
        )
    );
    assert_eq!(
        refusal(NamedMapSection::Export),
        format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            NamedMapSection::Export.singular()
        )
    );
}

#[test]
fn export_restart_metadata_is_additive_to_the_stored_definition_and_live_settings() {
    let def: busbar_kernel::config::ExportDefCfg =
        serde_json::from_value(serde_json::json!({"module": "neutral-sink"})).unwrap();
    let view = || crate::v1::named_def_views::export_def_view("sink", &def);
    let live = serde_json::to_value(MutatedDefView::new(view(), vec![], vec![], vec![])).unwrap();
    assert_eq!(live, serde_json::to_value(view()).unwrap());
    let pending = serde_json::to_value(MutatedDefView::new(
        view(),
        vec![],
        vec![],
        vec!["export.sink".into()],
    ))
    .unwrap();
    assert_eq!(pending["name"], live["name"]);
    assert_eq!(pending["module"], live["module"]);
    assert_eq!(
        pending["reload_to_apply"],
        serde_json::json!(["export.sink"])
    );
    let note = pending["note"].as_str().unwrap();
    assert!(note.contains("boot-opened sinks"), "{note}");
    assert!(note.contains("Settings refreshes"), "{note}");
    assert!(note.contains("still apply live"), "{note}");
}

#[tokio::test]
async fn an_export_removal_pending_restart_returns_the_existing_metadata_pair() {
    let pending = removal_response(vec![], vec![], vec!["export.sink".into()]);
    assert_eq!(pending.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(pending.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["reload_to_apply"], serde_json::json!(["export.sink"]));
    assert!(body["note"].as_str().unwrap().contains("RESTART"));
    assert_eq!(body.as_object().unwrap().len(), 2);
    let live = removal_response(vec![], vec![], vec![]);
    assert_eq!(live.status(), StatusCode::NO_CONTENT);
    assert!(axum::body::to_bytes(live.into_body(), usize::MAX)
        .await
        .unwrap()
        .is_empty());
}

#[cfg(feature = "openapi-schema")]
#[test]
fn export_removal_schema_describes_both_live_and_restart_pending_answers() {
    let ops = openapi_paths();
    let (_, route) = ops
        .iter()
        .find(|(path, _)| path.ends_with("/export/{name}"))
        .unwrap();
    let responses = &route["delete"][super::super::RESPONSES_KEY];
    assert!(responses.get("204").is_some());
    assert!(responses["200"]["description"]
        .as_str()
        .unwrap()
        .contains("reload_to_apply"));
}
