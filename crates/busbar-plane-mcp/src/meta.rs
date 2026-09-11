//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. A plane that could vary its own declarations at run time would make the claims a
//! boot proved non-overlapping stop being the claims in force.

use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::PlaneMeta;
use busbar_contract::wire::StatusAt;

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
        unit_noun: "call",
        family: COUNT_FAMILY,
        // Sized from the answer: a call has been made once it has been answered, and a call that
        // never reached a server is not a call this node made.
        direction: ClassDirection::Response,
        default_divisor: 1,
    },
    MeterClassDecl {
        key: MeterClassId::new("bytes"),
        unit_noun: "byte",
        family: BYTE_FAMILY,
        // Sized from the ANSWER, because the answer is what the metering step measures: the one
        // quantity this plane reports under this class is the length of the document it just read
        // back. The class used to declare itself sized from the request instead, which is a hold
        // taken over one side of the exchange and settled from the other — and a rate card reading
        // the declaration would have been pricing a caller's request at the size of a server's
        // answer to it.
        direction: ClassDirection::Response,
        default_divisor: 1,
    },
];

/// The class key a completed call is counted under.
pub const CLASS_TOOL_CALLS: MeterClassId = MeterClassId::new("tool_calls");

/// The class key the bytes an exchange moved are counted under.
pub const CLASS_BYTES: MeterClassId = MeterClassId::new("bytes");

/// The plane a sampling request is answered by, one level down.
///
/// Declared here, once, and not read from configuration: a nested destination is what the VERIFY
/// step seals and what the ROUTE step then dials, and the two must be the same destination or the
/// unit routes somewhere it was never verified for. Naming it in one constant is what makes them
/// the same by construction rather than by two authors agreeing.
pub const SAMPLING_PLANE: &str = "llm";

/// The operation class a sampling request is answered as on [`SAMPLING_PLANE`]. Half of the same
/// pair, for the same reason.
pub const SAMPLING_OP: OpClassId = OpClassId::new("chat");

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
    // WHERE THIS DIALECT REPORTS THE STATUS OF A UNIT. A JSON-RPC exchange says whether it was
    // answered on the FIRST frame that comes back — the reply document, or the first event of a
    // tool call's stream — and both bindings of this protocol agree about that, which is why one
    // declaration covers both transports this plane claims: where the status is reported is a fact
    // about the dialect, and the wire is only how the frame gets there. A tool call that dies
    // part-way through its stream contradicts a first frame that already said otherwise, and that
    // contradiction is the kernel's to settle, not this plane's to hide.
    const STATUS_LEG: Option<StatusAt> = Some(StatusAt::FirstFrame);
    /// A TOOL CALL IS THE SERVER'S WORK, and this plane is not the server. It relays a call to the
    /// tool host that answers it, so a call with no destination reached nothing and bought nothing.
    const CHARGEABLE_LOCAL: bool = false;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}

#[cfg(test)]
#[path = "tests/meta.rs"]
mod tests;
