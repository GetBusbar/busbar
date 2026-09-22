use super::*;
use busbar_contract::plane::PlaneMeta;

#[test]
fn key_matches_the_plugin_key() {
    assert_eq!(<DecisionPlane as PlaneMeta>::KEY, "decision");
}

#[test]
fn key_matches_registry_decl_key() {
    assert_eq!(
        <DecisionPlane as PlaneMeta>::KEY,
        crate::registry::PLANE_DECL.key
    );
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
