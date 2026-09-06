//! Tests for `meta.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{CONFIG_SCHEMA, INTROSPECTION_VERBS, METER_CLASSES};
use crate::McpPlane;
use busbar_contract::ids::MeterClassId;
use busbar_contract::plane::PlaneMeta;

/// The registry key is the codec's own.
#[test]
fn the_key_is_the_codecs_own() {
    assert_eq!(McpPlane::KEY, busbar_mcp_codec::PLANE_KEY);
}

/// The design's plane table gives this protocol exactly these two classes.
#[test]
fn the_declared_classes_are_the_two() {
    let keys: Vec<&str> = METER_CLASSES.iter().map(|c| c.key.as_str()).collect();
    assert_eq!(keys, vec!["tool_calls", "bytes"]);
}

/// No kernel-reserved class is declared here.
#[test]
fn no_kernel_reserved_class_is_declared() {
    for reserved in ["requests", "fee", "count", "session_seconds", "tokens"] {
        assert!(
            !METER_CLASSES
                .iter()
                .any(|c| c.key == MeterClassId::new(reserved)),
            "the plane declares the kernel's own class {reserved}"
        );
    }
}

/// Every declared class carries a family and a divisor that can size a hold.
#[test]
fn every_class_can_size_a_hold() {
    for class in METER_CLASSES {
        assert!(!class.family.is_empty(), "{} has no family", class.key);
        assert!(class.default_divisor > 0, "{} divides by zero", class.key);
    }
}

/// The two classes are in different families, so a cap over one does not count the other.
#[test]
fn the_two_classes_do_not_share_a_family() {
    assert_ne!(METER_CLASSES[0].family, METER_CLASSES[1].family);
}

/// The declared verb is a read-only projection and no more.
#[test]
fn the_verbs_are_read_only() {
    for mutating in ["connect", "approve", "install", "promote"] {
        assert!(
            !INTROSPECTION_VERBS.iter().any(|v| v.as_str() == mutating),
            "the plane declares the mutating verb {mutating}"
        );
    }
}

/// The configuration schema is a document, and it names the member the codec requires.
#[test]
fn the_configuration_schema_is_a_document() {
    let parsed: serde_json::Value =
        serde_json::from_str(CONFIG_SCHEMA).expect("the schema is a document");
    assert!(parsed["properties"].get("canonical_uri").is_some());
    assert_eq!(parsed["required"], serde_json::json!(["canonical_uri"]));
}

/// Every declared operation class is produced by something the decode step can reach.
///
/// Most classes come from a method of the vocabulary. Two do not, and each is named here rather
/// than allowed through a bound that cannot fail: a notice is a message with no identifier, and
/// the discovery fetch is named by its TARGET because it carries no document to name it in.
#[test]
fn every_class_is_reachable_from_the_vocabulary() {
    for op in McpPlane::OP_CLASSES {
        let from_a_method = crate::ops::METHODS.iter().any(|m| m.op == *op);
        let from_a_notice = *op == crate::ops::OP_NOTIFICATION;
        let from_the_target = *op == crate::ops::OP_METADATA;
        assert!(
            from_a_method || from_a_notice || from_the_target,
            "{op} is declared but nothing produces it"
        );
    }
}

/// Every declared list is a SET: nothing declared twice, nothing declared empty.
///
/// This used to compare each list to itself, which is true of any two reads of anything and so
/// could not fail. What is worth asserting is what the registry needs to be true of a list it
/// seals at boot: a repeated key would be one declaration silently standing for two, and an
/// empty key would be a class, schema or fact nothing can name.
#[test]
fn every_declared_list_is_a_set() {
    fn no_repeats<T: PartialEq + core::fmt::Debug>(what: &str, items: &[T]) {
        for (i, item) in items.iter().enumerate() {
            assert!(!items[..i].contains(item), "{what} declares {item:?} twice");
        }
    }
    no_repeats("the class list", McpPlane::OP_CLASSES);
    no_repeats("the record list", McpPlane::RECORD_SCHEMAS);
    no_repeats("the session-fact list", McpPlane::SESSION_FACTS);
    no_repeats("the content-fact list", McpPlane::CONTENT_FACTS);
    no_repeats("the verb list", McpPlane::INTROSPECTION_VERBS);
    no_repeats(
        "the meter-class list",
        &METER_CLASSES.iter().map(|c| c.key).collect::<Vec<_>>(),
    );
    for key in McpPlane::SESSION_FACTS
        .iter()
        .chain(McpPlane::CONTENT_FACTS)
    {
        assert!(!key.is_empty(), "a fact key is declared as the empty name");
    }
    for op in McpPlane::OP_CLASSES {
        assert!(
            !op.as_str().is_empty(),
            "a class is declared as the empty name"
        );
    }
    assert!(
        !McpPlane::CLAIMS.is_empty(),
        "a plane that claims nothing takes no bytes"
    );
}
