// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::named_map::NamedMapSection;

#[test]
fn named_settings_edit_preserves_omitted_secrets_and_distinguishes_removal_from_null() {
    let req: NamedSettingsReq = serde_json::from_value(serde_json::json!({
        "edit": {"set": {"timeout": 20, "nullable": null}, "remove": ["obsolete"]}
    }))
    .unwrap();
    let Mutation::EditSettings(edit) = req.into_mutation().unwrap() else {
        panic!("explicit edit mode must not become replacement");
    };
    let original = serde_json::json!({
        "timeout": 10,
        "credential": {"file": "/private/operator-token"},
        "opaque": {"unknown_secret": "retained"},
        "obsolete": true
    })
    .as_object()
    .unwrap()
    .clone();
    let edited = edit.apply(original.into()).unwrap();
    let edited = serde_json::to_value(edited.authoring(&busbar_kernel::seal::acquire())).unwrap();
    let edited = edited.as_object().unwrap();
    assert_eq!(edited["timeout"], 20);
    assert_eq!(
        edited["credential"],
        serde_json::json!({"file": "/private/operator-token"})
    );
    assert_eq!(
        edited["opaque"],
        serde_json::json!({"unknown_secret": "retained"})
    );
    assert_eq!(edited.get("nullable"), Some(&serde_json::Value::Null));
    assert!(!edited.contains_key("obsolete"));
}

#[test]
fn named_settings_modes_are_exclusive_and_legacy_replacement_stays_exact() {
    for body in [
        serde_json::json!({}),
        serde_json::json!({"settings": {}, "edit": {}}),
    ] {
        let req: NamedSettingsReq = serde_json::from_value(body).unwrap();
        assert!(req.into_mutation().is_err());
    }
    for body in [
        serde_json::json!({"settings": null, "edit": {}}),
        serde_json::json!({"settings": {}, "edit": null}),
        serde_json::json!({"edit": {"sets": {"typo": 1}}}),
    ] {
        assert!(serde_json::from_value::<NamedSettingsReq>(body).is_err());
    }
    let req: NamedSettingsReq =
        serde_json::from_value(serde_json::json!({"settings": {}})).unwrap();
    assert!(
        matches!(req.into_mutation().unwrap(), Mutation::Settings(settings) if settings.is_empty())
    );
    let req: NamedSettingsReq = serde_json::from_value(serde_json::json!({
        "edit": {"set": {"secret": "do-not-report"}, "remove": ["secret"]}
    }))
    .unwrap();
    let Mutation::EditSettings(edit) = req.into_mutation().unwrap() else {
        unreachable!()
    };
    let error = edit.validate().unwrap_err();
    assert!(!format!("{error:?}").contains("do-not-report"));
}

#[test]
fn named_configured_settings_are_allowlisted_and_never_claim_runtime_acknowledgement() {
    let settings = serde_json::json!({"timeout": 12, "credential": "never-return-this"})
        .as_object()
        .unwrap()
        .clone();
    let settings = settings.into();
    let public = |_: &str| ["timeout".to_owned()].into_iter().collect();
    for (pending, state) in [(false, "configured"), (true, "restart_pending")] {
        let view = serde_json::to_value(configured_settings(
            42, "module", &settings, pending, &public,
        ))
        .unwrap();
        assert_eq!(view["config_version"], 42);
        assert_eq!(view["source"], "installed_configuration");
        assert_eq!(view["state"], state);
        assert_eq!(view["settings_public"], serde_json::json!({"timeout": 12}));
        assert!(!view.to_string().contains("never-return-this"));
        assert!(view.get("applied").is_none());
    }
    let view = serde_json::to_value(configured_settings(7, "unknown", &settings, false, &|_| {
        Default::default()
    }))
    .unwrap();
    assert_eq!(view["settings_public"], serde_json::json!({}));
}

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
