//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. A plane that could vary its own declarations at run time would make the claims a
//! boot proved non-overlapping stop being the claims in force.

use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::PlaneMeta;

use crate::claims;
use crate::LlmPlane;

/// The family every token-shaped meter class rolls up into.
///
/// A card may price a class and may change its divisor; it may never move a class to another
/// family, because a cap written over the family would then be counting something else.
const TOKEN_FAMILY: &str = "token";

/// The family the count-shaped non-chat classes roll up into.
const COUNT_FAMILY: &str = "count";

/// The family the duration-shaped non-chat classes roll up into.
const DURATION_FAMILY: &str = "duration";

/// Bytes per token, as the default divisor.
///
/// This exists so a class cap works with no rate card configured at all. It is deliberately the
/// coarse, widely-used approximation rather than a per-dialect refinement: the divisor sizes a HOLD,
/// and the metering step settles against what the upstream actually reported.
const BYTES_PER_TOKEN: u32 = 4;

/// The four token classes, plus the non-chat classes the previous release billed.
///
/// The four are the ones every dialect reports, read through the codec's own normalization rather
/// than off a raw pointer: the dialects that report a cached count inside their prompt total have
/// already had it subtracted by the time the value reaches here, so the four partition the input
/// bytes without double-counting. The rest are the classes the previous release billed for the
/// non-chat operations, declared so that none of them is refused as unpriced.
///
/// The aggregate token class is deliberately ABSENT. It is declared by the kernel, not by a plane,
/// and the registry refuses it from one.
const METER_CLASSES: &[MeterClassDecl] = &[
    MeterClassDecl {
        key: MeterClassId::new("tokens_in"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("tokens_out"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("cache_read"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::CacheRead,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: MeterClassId::new("cache_write"),
        family: TOKEN_FAMILY,
        direction: ClassDirection::CacheWrite,
        default_divisor: BYTES_PER_TOKEN,
    },
    // The non-chat classes. A flat-billed operation still declares a class, because "billed at a
    // flat rate" and "has no meter class" settle differently: the first posts one, the second is
    // refused as unpriced.
    MeterClassDecl {
        key: MeterClassId::new("images"),
        family: COUNT_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: 1,
    },
    MeterClassDecl {
        key: MeterClassId::new("characters"),
        family: COUNT_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: 1,
    },
    MeterClassDecl {
        key: MeterClassId::new("audio_seconds"),
        family: DURATION_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: 1,
    },
    MeterClassDecl {
        key: MeterClassId::new("flat"),
        family: COUNT_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: 1,
    },
];

/// The operation classes a unit of this plane can be.
///
/// These are the classes that PRICE a unit, so the list is the one the previous release billed
/// against and no wider. The draft names one at the decode step and the audit step is checked
/// against it.
const OP_CLASSES: &[OpClassId] = &[
    OpClassId::new("chat"),
    OpClassId::new("embeddings"),
    OpClassId::new("moderation"),
    OpClassId::new("image"),
    OpClassId::new("transcription"),
    OpClassId::new("speech"),
    OpClassId::new("rerank"),
];

/// The fact key under which the decode step reports which dialect it read.
pub const FACT_DIALECT: &str = "dialect";

/// The fact key under which the decode step reports the model the request named.
pub const FACT_MODEL: &str = "model";

/// The fact key under which the decode step reports whether a streamed answer was asked for.
pub const FACT_STREAM: &str = "stream";

/// The fact key under which the decode step reports the operation it resolved.
pub const FACT_OPERATION: &str = "operation";

/// The fact key under which the decode step reports the response ceiling the client asked for.
pub const FACT_MAX_RESPONSE: &str = "max_response";

/// The fact key under which the response side records which dialect the bytes arrived in.
///
/// This exists because the unit a plane is handed at the encode step carries no facts of its own,
/// so the one thing the response encoder must know — which dialect wrote these bytes — has to
/// travel on the response it is encoding.
pub const FACT_SOURCE_DIALECT: &str = "source_dialect";

/// The fact key under which the response side records whether a frame was a whole answer or one
/// event of a streamed one.
pub const FACT_FRAME_KIND: &str = "frame_kind";

/// The fact key under which the response side reports the reason the upstream stopped.
pub const FACT_FINISH_REASON: &str = "finish_reason";

/// The fact key under which the response side reports the model the upstream answered as.
pub const FACT_RESPONSE_MODEL: &str = "response_model";

/// The fact key under which the response side reports how many tool calls the answer carried.
pub const FACT_TOOL_CALLS: &str = "tool_calls";

/// The fact key under which the response side reports the upstream's own identifier for the answer.
pub const FACT_RESPONSE_ID: &str = "response_id";

/// The session fact keys this plane writes.
///
/// The dialect and the model are session facts because a session that changed either mid-stream
/// would be a different priced thing, and the kernel needs to be able to see that from the outside.
const SESSION_FACTS: &[&str] = &[
    FACT_DIALECT,
    FACT_MODEL,
    FACT_STREAM,
    FACT_OPERATION,
    FACT_MAX_RESPONSE,
    FACT_SOURCE_DIALECT,
    FACT_FRAME_KIND,
];

/// The content fact keys this plane produces.
///
/// This is what the export path receives today: what the answer was for, what it ended as, and what
/// it named — never the content itself, and never a credential.
const CONTENT_FACTS: &[&str] = &[
    FACT_RESPONSE_MODEL,
    FACT_FINISH_REASON,
    FACT_TOOL_CALLS,
    FACT_RESPONSE_ID,
];

/// The read-only introspection verb that lists the dialects this plane speaks.
pub const VERB_DIALECTS: AdminVerbId = AdminVerbId::new("dialects");

/// The read-only introspection verb that lists the detection ladder, rung by rung.
pub const VERB_LADDER: AdminVerbId = AdminVerbId::new("ladder");

/// The verbs this plane answers.
const ADMIN_VERBS: &[AdminVerbId] = &[VERB_DIALECTS, VERB_LADDER];

/// The schema of this plane's own configuration block.
///
/// The lanes and the upstreams a claim may name are configuration, and so is the optional
/// idempotency location. Nothing here is a credential and nothing here is a price.
const CONFIG_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "lanes": { "type": "array", "items": { "type": "string" } },
    "default_dialect": { "type": "string" },
    "idempotency_header": { "type": "string" }
  }
}"#;

impl PlaneMeta for LlmPlane {
    const KEY: &'static str = "llm";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = claims::CLAIMS;
    const OP_CLASSES: &'static [OpClassId] = OP_CLASSES;
    const METER_CLASSES: &'static [MeterClassDecl] = METER_CLASSES;
    const SESSION_FACTS: &'static [&'static str] = SESSION_FACTS;
    const CONTENT_FACTS: &'static [&'static str] = CONTENT_FACTS;
    // This plane keeps no kernel-held durable records: everything it knows about a unit is on the
    // unit, and the answer to "what happened" is the journal's, not a second store of this plane's.
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = &[];
    const ADMIN_VERBS: &'static [AdminVerbId] = ADMIN_VERBS;
    // No dialect here has a frame that supersedes the open one, and none paces the write path: a
    // request-and-answer dialect has neither, and declaring one would make the kernel look for a
    // fact that never arrives.
    const INTERRUPT_FACT: Option<&'static str> = None;
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}
