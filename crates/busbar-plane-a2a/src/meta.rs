//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. A plane that could vary its own declarations at run time would make the claims a
//! boot proved non-overlapping stop being the claims in force.

use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::PlaneMeta;

use crate::{claims, facts, ops, records, A2aPlane};

/// The family the byte-shaped class rolls up into.
///
/// A rate card may price the class and may change its divisor; it may never move it to another
/// family, because a cap written over the family would then be counting something else.
const BYTE_FAMILY: &str = "byte";

/// The class this plane meters.
///
/// ONE class, named for what it counts. The design's plane table gives this protocol exactly one
/// class and calls it bytes, and that is what is declared: a unit of this plane is one exchange with
/// an agent, and what an exchange costs is what it moved.
///
/// The direction says where the ESTIMATE comes from — the ingress-derived figure, which the
/// admission step reads off the span the admit facts point at. The SETTLEMENT comes from what the
/// metering step read off the answer. Estimate from one side, settle from the other, is the same
/// shape every class in every plane has; it is only unusual here because the class's name mentions
/// a direction and the class itself does not.
///
/// One observation worth recording rather than smoothing over: a single byte class cannot separate
/// what a caller sent from what an agent returned, so a deployment that wanted to price those
/// differently cannot express it. That is a property of the declared vocabulary, not of this
/// adapter, and changing it is a design decision rather than a code change here.
const METER_CLASSES: &[MeterClassDecl] = &[MeterClassDecl {
    key: MeterClassId::new("bytes"),
    family: BYTE_FAMILY,
    direction: ClassDirection::Input,
    // A byte is a byte: the class's own quantity is the quantity, so nothing is divided.
    default_divisor: 1,
}];

/// The class key the metering step reports under.
pub const CLASS_BYTES: MeterClassId = MeterClassId::new("bytes");

/// The read-only verb that lists the agents this node fronts.
pub const VERB_AGENTS: AdminVerbId = AdminVerbId::new("agents");

/// The read-only verb that answers for the ONE agent the subject names.
pub const VERB_AGENT: AdminVerbId = AdminVerbId::new("agent");

/// The verbs this plane answers.
///
/// Two, and which two is the point. The codec answers a projection over every agent and a projection
/// over the ONE agent a request names; the introspection verb now carries a subject, so both are
/// expressible and both are declared. The per-name one used to be declared nowhere, because a verb
/// identifier and a context said WHICH plane but never WHICH agent, and a key per agent is not
/// available to a plane whose verb key set is closed at registration.
///
/// The codec's two OTHER admin operations — the one that re-contacts an agent and re-pins it, and
/// the one that records an operator's approval — CHANGE something, so they are not verbs of this
/// plane either: a mutating plane admin operation is the kernel's own record-write verb, reached
/// with the plane's record schemas, and the plane contributes the shape rather than the action.
const INTROSPECTION_VERBS: &[AdminVerbId] = &[VERB_AGENTS, VERB_AGENT];

/// The schema of this plane's own configuration block.
///
/// This is the shape the codec already parses, one level deep: a map from agent name to that
/// agent's definition, plus the two reserved members that apply to every agent. Nothing here is a
/// credential — the credential members name a REFERENCE that the secret plugin resolves, and this
/// plane never sees what is behind one — and nothing here is a price.
const CONFIG_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "url": { "type": "string" },
      "pin": { "type": "object" },
      "client_identity": { "type": "object" },
      "reverify_ttl": { "type": "string" },
      "recovery_backoff": { "type": "string" },
      "protocol_version": { "type": "string" },
      "allow_private": { "type": "boolean" },
      "upstream_credentials": { "type": "object" },
      "upstream_credential": { "type": "object" },
      "egress_scopes": { "type": "array", "items": { "type": "string" } },
      "hooks": { "type": "array", "items": { "type": "string" } }
    },
    "required": ["url", "pin"]
  },
  "properties": {
    "hooks": { "type": "array", "items": { "type": "string" } },
    "upstream_credentials": { "type": "object" }
  }
}"#;

impl PlaneMeta for A2aPlane {
    const KEY: &'static str = "a2a";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = claims::CLAIMS;
    const OP_CLASSES: &'static [OpClassId] = ops::OP_CLASSES;
    const METER_CLASSES: &'static [MeterClassDecl] = METER_CLASSES;
    const SESSION_FACTS: &'static [&'static str] = facts::SESSION_FACTS;
    const CONTENT_FACTS: &'static [&'static str] = facts::CONTENT_FACTS;
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = records::RECORD_SCHEMAS;
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = INTROSPECTION_VERBS;
    // This protocol has no frame that supersedes an open one. Asking for a task to stop is its own
    // request, with its own identifier and its own answer, so it is a UNIT rather than an interrupt;
    // declaring an interrupt fact here would make the kernel look for a fact that never arrives.
    const INTERRUPT_FACT: Option<&'static str> = None;
    // Nothing paces this plane's write path. The event stream is written as fast as the answer
    // arrives, which is what the existing codec does and what this crate must not change.
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}

#[cfg(test)]
mod tests {
    use super::{CONFIG_SCHEMA, INTROSPECTION_VERBS, METER_CLASSES};
    use crate::A2aPlane;
    use busbar_contract::ids::MeterClassId;
    use busbar_contract::plane::PlaneMeta;

    /// The registry key is the codec's own.
    #[test]
    fn the_key_is_the_codecs_own() {
        assert_eq!(A2aPlane::KEY, busbar_a2a::PLANE_DECL.key);
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
        assert_eq!(busbar_a2a::PLANE_DECL.config_section, "agents");
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

    /// The declarations are the same every time they are read.
    #[test]
    fn the_declarations_do_not_vary() {
        assert_eq!(A2aPlane::CLAIMS.len(), A2aPlane::CLAIMS.len());
        assert_eq!(A2aPlane::OP_CLASSES, A2aPlane::OP_CLASSES);
        assert_eq!(A2aPlane::RECORD_SCHEMAS, A2aPlane::RECORD_SCHEMAS);
        assert_eq!(A2aPlane::SESSION_FACTS, A2aPlane::SESSION_FACTS);
        assert_eq!(A2aPlane::CONTENT_FACTS, A2aPlane::CONTENT_FACTS);
    }
}
