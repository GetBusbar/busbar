use super::*;
use busbar_contract::plane::PlaneMeta;

#[test]
fn key_matches_the_plugin_key() {
    assert_eq!(<DecisionPlane as PlaneMeta>::KEY, "decision");
}

#[test]
fn one_meter_class_declared_for_billable_decisions() {
    let classes = <DecisionPlane as PlaneMeta>::METER_CLASSES;
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0].key, CLASS_DECISION);
    assert_eq!(
        classes[0].direction,
        busbar_contract::ids::ClassDirection::Response
    );
    assert_eq!(classes[0].default_divisor, 1);
}

#[test]
fn op_classes_are_the_ops_module_table() {
    assert_eq!(<DecisionPlane as PlaneMeta>::OP_CLASSES, ops::OP_CLASSES);
}

#[test]
fn no_introspection_verb_is_declared() {
    assert!(<DecisionPlane as PlaneMeta>::INTROSPECTION_VERBS.is_empty());
}

#[test]
fn neither_interrupt_nor_pacing_fact_is_declared() {
    assert_eq!(<DecisionPlane as PlaneMeta>::INTERRUPT_FACT, None);
    assert_eq!(<DecisionPlane as PlaneMeta>::EGRESS_PACING_FACT, None);
}

#[test]
fn config_schema_is_well_formed_json_naming_models_and_the_reserved_pair() {
    let schema: serde_json::Value =
        serde_json::from_str(<DecisionPlane as PlaneMeta>::CONFIG_SCHEMA)
            .expect("the config schema is valid JSON");
    let props = schema["properties"].as_object().expect("has properties");
    assert!(props.contains_key("models"));
    assert!(props.contains_key("hooks"));
    assert!(props.contains_key("upstream_credentials"));
    // Never a `state` or `answers` property anywhere in the schema string — the schema describes
    // busbar's OWN config shape, not jev's wire shape, so neither word belongs here at all.
    let raw = <DecisionPlane as PlaneMeta>::CONFIG_SCHEMA;
    assert!(!raw.contains("\"state\""));
    assert!(!raw.contains("\"answers\""));
}

/// The field names `ModelCfg` accepts, read off the type itself: `deny_unknown_fields` answers an
/// unknown member by listing every field it does know, so the list is the type's, not a copy.
fn model_cfg_fields() -> std::collections::BTreeSet<String> {
    let err = serde_json::from_str::<busbar_contract::config::ModelCfg>(
        r#"{"provider":"p","__not_a_model_cfg_field__":0}"#,
    )
    .expect_err("an unknown member is refused");
    let text = err.to_string();
    let (_, listed) = text
        .split_once("expected one of ")
        .unwrap_or_else(|| panic!("serde names the accepted fields: {text}"));
    listed
        .split(',')
        .filter_map(|part| part.split('`').nth(1))
        .map(str::to_owned)
        .collect()
}

/// Item 400. The model entry `CONFIG_SCHEMA` describes is `ModelCfg`, member for member: the same
/// property set, and the same required set (`ModelCfg` refuses a model with no `provider` and
/// accepts one with nothing else). A field added to, renamed in or removed from either side is red.
#[test]
fn config_schema_model_entry_is_model_cfg_field_for_field() {
    let schema: serde_json::Value =
        serde_json::from_str(<DecisionPlane as PlaneMeta>::CONFIG_SCHEMA).expect("valid JSON");
    let entry = &schema["properties"]["models"]["additionalProperties"];
    let declared: std::collections::BTreeSet<String> = entry["properties"]
        .as_object()
        .expect("the model entry declares its properties")
        .keys()
        .cloned()
        .collect();
    let accepted = model_cfg_fields();
    assert_eq!(
        accepted.len(),
        8,
        "the probe read ModelCfg's list: {accepted:?}"
    );
    assert_eq!(declared, accepted);
    assert_eq!(
        entry["additionalProperties"],
        serde_json::Value::Bool(false)
    );

    let required: Vec<&str> = entry["required"]
        .as_array()
        .expect("the model entry names what it requires")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(required, ["provider"]);
    assert!(serde_json::from_str::<busbar_contract::config::ModelCfg>("{}").is_err());
    assert!(
        serde_json::from_str::<busbar_contract::config::ModelCfg>(r#"{"provider":"p"}"#).is_ok()
    );
}
