//! Tests for `meta.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{CONFIG_SCHEMA, INTROSPECTION_VERBS, METER_CLASSES};
use crate::A2aPlane;
use busbar_contract::ids::MeterClassId;
use busbar_contract::plane::PlaneMeta;

/// The registry key is the codec's own.
#[test]
fn the_key_is_the_codecs_own() {
    assert_eq!(A2aPlane::KEY, busbar_a2a_codec::PLANE_KEY);
}

/// No kernel-reserved class is declared here.
///
/// The kernel declares these itself and the registry refuses them from a plane, so declaring one
/// would be a boot refusal rather than a subtle bug — but a boot refusal discovered at boot is
/// still discovered later than one discovered here.
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

/// The declared verbs are read-only projections and no more.
///
/// The codec's two mutating admin operations are deliberately absent; this asserts they stay
/// absent, because a mutating verb declared here would be a plane taking an action.
#[test]
fn the_verbs_are_read_only() {
    for mutating in ["connect", "approve", "suspend", "resume"] {
        assert!(
            !INTROSPECTION_VERBS.iter().any(|v| v.as_str() == mutating),
            "the plane declares the mutating verb {mutating}"
        );
    }
}

/// The configuration schema is a document, and it names the two members the codec requires.
#[test]
fn the_configuration_schema_is_a_document() {
    let parsed: serde_json::Value =
        serde_json::from_str(CONFIG_SCHEMA).expect("the schema is a document");
    let props = &parsed["additionalProperties"]["properties"];
    assert!(props.get("url").is_some());
    assert!(props.get("pin").is_some());
    assert_eq!(
        parsed["additionalProperties"]["required"],
        serde_json::json!(["url", "pin"])
    );
}

/// The configuration schema names the section the codec reads, and no other.
#[test]
fn the_configuration_section_is_the_codecs_own() {
    assert_eq!(busbar_a2a_codec::CONFIG_SECTION, "agents");
}

/// Every declared operation class is named by at least one method of the vocabulary.
///
/// A class no method produces would be a price nothing can be charged at.
#[test]
fn every_class_is_reachable_from_the_vocabulary() {
    for op in A2aPlane::OP_CLASSES {
        let from_a_method = crate::ops::METHODS.iter().any(|m| m.op == *op);
        let provider_initiated = *op == crate::ops::OP_PUSH_EVENT;
        assert!(
            from_a_method || provider_initiated,
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
    no_repeats("the class list", A2aPlane::OP_CLASSES);
    no_repeats("the record list", A2aPlane::RECORD_SCHEMAS);
    no_repeats("the session-fact list", A2aPlane::SESSION_FACTS);
    no_repeats("the content-fact list", A2aPlane::CONTENT_FACTS);
    no_repeats("the verb list", A2aPlane::INTROSPECTION_VERBS);
    no_repeats(
        "the meter-class list",
        &METER_CLASSES.iter().map(|c| c.key).collect::<Vec<_>>(),
    );
    for key in A2aPlane::SESSION_FACTS
        .iter()
        .chain(A2aPlane::CONTENT_FACTS)
    {
        assert!(!key.is_empty(), "a fact key is declared as the empty name");
    }
    for op in A2aPlane::OP_CLASSES {
        assert!(
            !op.as_str().is_empty(),
            "a class is declared as the empty name"
        );
    }
    assert!(
        !A2aPlane::CLAIMS.is_empty(),
        "a plane that claims nothing takes no bytes"
    );
}
