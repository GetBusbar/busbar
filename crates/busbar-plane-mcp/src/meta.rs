//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. A plane that could vary its own declarations at run time would make the claims a
//! boot proved non-overlapping stop being the claims in force.

use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::PlaneMeta;

use crate::{claims, facts, ops, records, McpPlane};

/// The family the count-shaped class rolls up into.
const COUNT_FAMILY: &str = "count";

/// The family the byte-shaped class rolls up into.
const BYTE_FAMILY: &str = "byte";

/// The two classes this plane meters.
///
/// A tool call is FLAT-metered, which is what the codec already does: it posts one attributed
/// request event per round, with no quantity attached. So the call class divides by one and counts
/// calls, and a rate card that wants to charge per call has a key to hang a price on. The byte class
/// is the second axis the design's plane table names, and it is what makes a very large argument or
/// a very large answer cost more than a small one on a deployment that wants it to.
///
/// One observation worth recording rather than smoothing over: the codec today posts a quantity of
/// zero for its request event, so a deployment that priced the call class would be pricing something
/// the codec does not currently report a number for. That is a gap between what the design's table
/// declares and what the engine beside the codec measures, and closing it is a change to the
/// metering side rather than to this adapter.
const METER_CLASSES: &[MeterClassDecl] = &[
    MeterClassDecl {
        key: MeterClassId::new("tool_calls"),
        family: COUNT_FAMILY,
        // Sized from the answer: a call has been made once it has been answered, and a call that
        // never reached a server is not a call this node made.
        direction: ClassDirection::Response,
        default_divisor: 1,
    },
    MeterClassDecl {
        key: MeterClassId::new("bytes"),
        family: BYTE_FAMILY,
        // Sized from the ingress-derived estimate, and settled from what the metering step read.
        direction: ClassDirection::Input,
        default_divisor: 1,
    },
];

/// The class key a completed call is counted under.
pub const CLASS_TOOL_CALLS: MeterClassId = MeterClassId::new("tool_calls");

/// The class key the bytes an exchange moved are counted under.
pub const CLASS_BYTES: MeterClassId = MeterClassId::new("bytes");

/// The read-only verb that lists the registered servers.
pub const VERB_TOOLS: AdminVerbId = AdminVerbId::new("tools");

/// The read-only verb that answers for the ONE registration the subject names.
pub const VERB_SERVER: AdminVerbId = AdminVerbId::new("server");

/// The verbs this plane answers.
///
/// Two, and which two is the point. The codec answers a projection over every registration and a
/// projection over the ONE registration a request names; the introspection verb now carries a
/// subject, so both are expressible and both are declared. The per-name one used to be declared
/// nowhere, because a verb identifier and a context said WHICH plane but never WHICH server, and a
/// key per registration is not available to a plane whose verb key set is closed at registration.
///
/// What is still NOT a verb of this plane is anything that changes something: the codec's operation
/// that re-contacts a server and re-pins it is the kernel's own record-write verb, reached with this
/// plane's record schemas, and the plane contributes the shape rather than the action. Liveness is
/// not here either, for a different reason — a plane holds a registration table and no runtime
/// state, so a health answer would be a guess wearing a fact's clothes.
const INTROSPECTION_VERBS: &[AdminVerbId] = &[VERB_TOOLS, VERB_SERVER];

/// The schema of this plane's own configuration block.
///
/// Two blocks, in fact, and that is the codec's shape rather than this crate's: an address block
/// naming what this deployment IS, and a registry block naming the servers it fronts. Nothing here
/// is a credential — the credential members name a REFERENCE that the secret plugin resolves, and
/// this plane never sees what is behind one — and nothing here is a price.
const CONFIG_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "canonical_uri": { "type": "string" },
    "authorization_servers": { "type": "array", "items": { "type": "string" } },
    "scopes_supported": { "type": "array", "items": { "type": "string" } },
    "allowed_origins": { "type": "array", "items": { "type": "string" } },
    "servers": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "url": { "type": "string" },
          "command": { "type": "string" },
          "args": { "type": "array", "items": { "type": "string" } },
          "pin": { "type": "object" },
          "verify_ttl": { "type": "string" },
          "timeout": { "type": "string" },
          "tools_allow": { "type": "object" },
          "prompts_allow": { "type": "object" },
          "resources_allow": { "type": "object" },
          "transport": { "type": "string" },
          "grants": { "type": "object" },
          "roots": { "type": "array" },
          "sampling": { "type": "object" },
          "allow_private": { "type": "boolean" },
          "upstream_credentials": { "type": "object" },
          "hooks": { "type": "array", "items": { "type": "string" } }
        },
        "required": ["pin"]
      }
    }
  },
  "required": ["canonical_uri"]
}"#;

impl PlaneMeta for McpPlane {
    const KEY: &'static str = "mcp";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = claims::CLAIMS;
    const OP_CLASSES: &'static [OpClassId] = ops::OP_CLASSES;
    const METER_CLASSES: &'static [MeterClassDecl] = METER_CLASSES;
    const SESSION_FACTS: &'static [&'static str] = facts::SESSION_FACTS;
    const CONTENT_FACTS: &'static [&'static str] = facts::CONTENT_FACTS;
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = records::RECORD_SCHEMAS;
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = INTROSPECTION_VERBS;
    // The specification names a cancellation notice, and this protocol's own dispatch does NOT act
    // on one today: it is not in the codec's method table, and a notice obliges no answer. So no
    // interrupt fact is declared, because declaring one would make the kernel supersede open units
    // on a frame the codec has never superseded anything on — a behaviour change, which is exactly
    // what this crate is not allowed to make.
    const INTERRUPT_FACT: Option<&'static str> = None;
    // Nothing paces this plane's write path. Events are written as fast as they are produced, which
    // is what the codec does and what this crate must not change.
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}

#[cfg(test)]
mod tests {
    use super::{INTROSPECTION_VERBS, CONFIG_SCHEMA, METER_CLASSES};
    use crate::McpPlane;
    use busbar_contract::ids::MeterClassId;
    use busbar_contract::plane::PlaneMeta;

    /// The registry key is the codec's own.
    #[test]
    fn the_key_is_the_codecs_own() {
        assert_eq!(McpPlane::KEY, busbar_mcp::PLANE_DECL.key);
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

    /// Every declared operation class is named by at least one method of the vocabulary.
    #[test]
    fn every_class_is_reachable_from_the_vocabulary() {
        for op in McpPlane::OP_CLASSES {
            let from_a_method = crate::ops::METHODS.iter().any(|m| m.op == *op);
            let from_a_notice = *op == crate::ops::OP_NOTIFICATION;
            assert!(
                from_a_method || from_a_notice,
                "{op} is declared but nothing produces it"
            );
        }
    }

    /// The declarations are the same every time they are read.
    #[test]
    fn the_declarations_do_not_vary() {
        assert_eq!(McpPlane::CLAIMS, McpPlane::CLAIMS);
        assert_eq!(McpPlane::OP_CLASSES, McpPlane::OP_CLASSES);
        assert_eq!(McpPlane::RECORD_SCHEMAS, McpPlane::RECORD_SCHEMAS);
        assert_eq!(McpPlane::SESSION_FACTS, McpPlane::SESSION_FACTS);
        assert_eq!(McpPlane::CONTENT_FACTS, McpPlane::CONTENT_FACTS);
    }
}
