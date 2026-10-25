//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. A plane that could vary its own declarations at run time would make the claims a
//! boot proved non-overlapping stop being the claims in force.

use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::{PlaneMeta, ServedOpClass, TOKEN_FAMILY};

use crate::claims;
use crate::plane_door::TOKEN_CLASSES;
use crate::LlmPlane;

/// Bytes per token, as the default divisor.
///
/// This exists so a class cap works with no rate card configured at all. It is deliberately the
/// coarse, widely-used approximation rather than a per-dialect refinement: the divisor sizes a HOLD,
/// and the metering step settles against what the upstream actually reported.
const BYTES_PER_TOKEN: u32 = 4;

/// The four token classes: every class this plane reports, and no other.
///
/// The four are the ones every dialect reports, read through the codec's own normalization rather
/// than off a raw pointer: the dialects that report a cached count inside their prompt total have
/// already had it subtracted by the time the value reaches here, so the four partition the input
/// bytes without double-counting.
///
/// ONE DECLARATION, ONE SOURCE (ARCHITECT, `$` meter classes: "Money is ledger x ratecard, so there
/// must be ONE declaration and one source"). The door's billable classes
/// ([`crate::plane_door::TOKEN_CLASSES`], the classes the dispatcher checks a reported count against)
/// are the source; every key and family below is READ from them, never spelled here. They are
/// 1.5.5's own names, byte for byte: the `rate_card:` tiers (`input_utok`, `output_utok`,
/// `cache_read_utok`, `cache_write_utok`), the ledger's `TierTokens { input, output, cache_read,
/// cache_write }` and the spend metrics' `tier` label. This list used to spell its own keys
/// (`tokens_in`, `tokens_out`), names no card prices and no ledger tier carries; a count emitted under
/// one of them could only post unpriced or be refused.
///
/// THE LIST IS WHAT THE METERING STEP EMITS, exactly. A declaration is an invitation to a rate card:
/// an operator who sees a class here prices it, and a class the card prices but the plane never
/// reports posts no line at all — not a zero line, no line — so the invoice is silently short by
/// whatever that class was worth and nothing anywhere says so. Four count-shaped and duration-shaped
/// classes used to sit below the four token ones for the non-chat operations, and not one of them
/// was ever emitted: this plane reads its quantities through the codec's own usage figures, which
/// carry token counts and nothing else — no image count, no character count, no audio duration — so
/// the three that named a count or a duration could never be read here. The fourth named a flat
/// per-request charge, which the rate card already posts by itself as its own `fee` line whatever a
/// plane declares; a second spelling of it here could only ever bill the same request twice or
/// nothing.
///
/// A non-chat operation that should carry a price gets a class here when the plane can read its
/// quantity, and the reading comes first. The op class list below is unaffected: a unit is priced by
/// the class it is, and the token classes price the ones this plane can actually read.
///
/// The aggregate token class is deliberately ABSENT. It is declared by the kernel, not by a plane,
/// and the registry refuses it from one.
/// The class keys the metering step reports under.
///
/// EXPORTED BECAUSE THE CLASS LABEL IS WHAT SELECTS A UNIT PRICE, and a second spelling of one is a
/// count emitted under a class no card can name — silently unpriced, or a boot refusal under
/// #77(5), and in neither case anything that points at the line that misspelled it. Each const is
/// the door's billable class at its index, so the class a count is emitted under, the class this
/// plane declares and the class the door states are one value the compiler checks.
pub const CLASS_INPUT: MeterClassId = MeterClassId::new(TOKEN_CLASSES[0]);
/// See [`CLASS_INPUT`].
pub const CLASS_OUTPUT: MeterClassId = MeterClassId::new(TOKEN_CLASSES[1]);
/// See [`CLASS_INPUT`].
pub const CLASS_CACHE_READ: MeterClassId = MeterClassId::new(TOKEN_CLASSES[2]);
/// See [`CLASS_INPUT`].
pub const CLASS_CACHE_WRITE: MeterClassId = MeterClassId::new(TOKEN_CLASSES[3]);

const METER_CLASSES: &[MeterClassDecl] = &[
    MeterClassDecl {
        key: CLASS_INPUT,
        family: TOKEN_FAMILY,
        direction: ClassDirection::Input,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: CLASS_OUTPUT,
        family: TOKEN_FAMILY,
        direction: ClassDirection::Response,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: CLASS_CACHE_READ,
        family: TOKEN_FAMILY,
        direction: ClassDirection::CacheRead,
        default_divisor: BYTES_PER_TOKEN,
    },
    MeterClassDecl {
        key: CLASS_CACHE_WRITE,
        family: TOKEN_FAMILY,
        direction: ClassDirection::CacheWrite,
        default_divisor: BYTES_PER_TOKEN,
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

/// The TRANSPORT fact key carrying how long the upstream took, in milliseconds.
///
/// One dialect stamps an elapsed figure into the answer's metrics, and the reference path has one
/// to stamp because the thing that made the call measured it. A plane cannot measure it: it holds
/// no connection and reads no clock but the one the context hands it, and a clock reading at encode
/// time is not an elapsed time. So the figure arrives the way every other thing a plane cannot
/// observe arrives — as a fact the transport published. With the fact absent the plane stamps
/// nothing, which is what it did before this key existed.
pub const TRANSPORT_FACT_ELAPSED_MS: &str = "elapsed_ms";

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
const INTROSPECTION_VERBS: &[AdminVerbId] = &[VERB_DIALECTS, VERB_LADDER];

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

/// [`HELP_TAGLINE`]'s text, spelled once for it and for [`CLI_HELP_TEXT`].
macro_rules! help_tagline {
    () => {
        "native-protocol LLM gateway"
    };
}

/// The one-line description `busbar --help` opens with (`busbar <version> — <this>`), byte for byte
/// as the binary has always printed it (shadow-oracle cells `cli__--help` / `cli__-h`). It names
/// this plane, so this plane owns it (#47/#49) and the composition root reads it from here.
pub const HELP_TAGLINE: &str = help_tagline!();

/// [`HELP_ENDPOINTS`]'s text, spelled once for it and for [`CLI_HELP_TEXT`].
macro_rules! help_endpoints {
    () => {
        "    POST /<model>/v1/messages              Anthropic-format ingress (single model)
    POST /<pool>/v1/messages               route to a configured pool
    POST /<provider>/<model>/v1/messages   ad-hoc direct route
    POST /v1/chat/completions              OpenAI-format ingress
    POST /v2/chat                          Cohere-format ingress
    POST /v1/responses                     Responses-API ingress
    POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1)
    POST /v1beta/models/<model>:<action>   Gemini-format ingress
    POST /model/<modelId>/converse         Bedrock Converse ingress
    POST /model/<modelId>/converse-stream  Bedrock Converse streaming ingress
    GET  /v1/models  /v1beta/models        list models (answers in the caller's dialect)"
    };
}

/// This plane's lines in the `ENDPOINTS` block of `busbar --help` — the doors its dialects answer
/// on — byte for byte as the binary has always printed them (shadow-oracle cells `cli__--help` /
/// `cli__-h`). They name this plane's dialects, so this plane owns them (#47/#49); no trailing
/// newline, the root splices them between two lines it owns.
pub const HELP_ENDPOINTS: &str = help_endpoints!();

/// This plane's rows of `busbar --help`, as the composition root's CLI-help axis reads them:
/// `("tagline", …)` the one-line description the help opens with, `("endpoint", …)` its rows of the
/// `ENDPOINTS` block.
pub const CLI_HELP: &[(&str, &str)] = &[("tagline", HELP_TAGLINE), ("endpoint", HELP_ENDPOINTS)];

/// THE SAME ROWS AS THE DOOR'S TAIL STATES THEM (`PlaneTail::cli_help`), in the contract's grammar
/// (`busbar_contract::abi::plane::cli_help`): the tagline row, then the `ENDPOINTS` row. The host
/// reads them off the door, so a dropped-in build of this plane prints the same help as a linked one.
pub const CLI_HELP_TEXT: &str = concat!(
    "\u{1e}tagline\u{1f}",
    help_tagline!(),
    "\u{1e}endpoint\u{1f}",
    help_endpoints!()
);

/// The operation class this plane serves ONE LEVEL DOWN, to another plane's unit that names only the
/// class it needs, and the display name a refusal naming this plane reads — byte for byte the word
/// the binary has always printed where it names this plane (#47/#49: this plane owns it).
pub const SERVED_OP_CLASSES: &[ServedOpClass] = &[ServedOpClass {
    op: OpClassId::new("chat"),
    name: "LLM",
}];

/// THE PROVIDER KEYS THIS PLANE OWNS, per form of a `providers:` entry (row 155 B1c, ARCHITECT
/// ruling "Option A"): the descriptor this plane states in its Statement's extensions under
/// `busbar_contract::provider_keys::EXT_PROVIDER_KEYS`, in the contract's neutral shape vocabulary,
/// so the kernel parses an entry without holding one of these names.
///
/// Each form's keys are in the order of the previous release's frozen grammar for that form (the
/// catalog definition, the operator deployment, the whole resolved entry), with the kernel's own keys
/// left out; each says whether it must be written, and each form whether it refuses a key it does not
/// name. A test holds every form to the frozen grammar, key by key. Read by nothing yet: the kernel
/// keeps it at its door fold.
pub const PROVIDER_KEYS: &str = r#"{
  "catalog": {
    "deny_unknown": false,
    "keys": [
      {"name": "protocol", "shape": "str", "required": true},
      {"name": "error_map", "shape": "str-map", "required": false},
      {"name": "organization", "shape": "str", "required": false},
      {"name": "project", "shape": "str", "required": false},
      {"name": "max_output_key", "shape": {"one-of": ["max_tokens", "max_completion_tokens"]}, "required": false},
      {"name": "anthropic_adaptive_thinking", "shape": "bool", "required": false},
      {"name": "native_structured_output", "shape": "bool", "required": false},
      {"name": "model_capabilities", "shape": {"list": {"table": {
        "deny_unknown": true,
        "keys": [
          {"name": "models", "shape": {"list": "str"}, "required": true},
          {"name": "max_output_key", "shape": {"one-of": ["max_tokens", "max_completion_tokens"]}, "required": false},
          {"name": "anthropic_adaptive_thinking", "shape": "bool", "required": false},
          {"name": "native_structured_output", "shape": "bool", "required": false},
          {"name": "reasoning_none", "shape": "bool", "required": false},
          {"name": "thinking_always_on", "shape": "bool", "required": false}
        ]
      }}}, "required": false}
    ]
  },
  "deployment": {
    "deny_unknown": true,
    "keys": [
      {"name": "protocol", "shape": "str", "required": false},
      {"name": "error_map", "shape": "str-map", "required": false},
      {"name": "organization", "shape": "str", "required": false},
      {"name": "project", "shape": "str", "required": false},
      {"name": "max_output_key", "shape": {"one-of": ["max_tokens", "max_completion_tokens"]}, "required": false},
      {"name": "anthropic_adaptive_thinking", "shape": "bool", "required": false},
      {"name": "native_structured_output", "shape": "bool", "required": false},
      {"name": "model_capabilities", "shape": {"list": {"table": {
        "deny_unknown": true,
        "keys": [
          {"name": "models", "shape": {"list": "str"}, "required": true},
          {"name": "max_output_key", "shape": {"one-of": ["max_tokens", "max_completion_tokens"]}, "required": false},
          {"name": "anthropic_adaptive_thinking", "shape": "bool", "required": false},
          {"name": "native_structured_output", "shape": "bool", "required": false},
          {"name": "reasoning_none", "shape": "bool", "required": false},
          {"name": "thinking_always_on", "shape": "bool", "required": false}
        ]
      }}}, "required": false}
    ]
  },
  "entry": {
    "deny_unknown": true,
    "keys": [
      {"name": "protocol", "shape": "str", "required": false},
      {"name": "error_map", "shape": "str-map", "required": true},
      {"name": "organization", "shape": "str", "required": false},
      {"name": "project", "shape": "str", "required": false},
      {"name": "max_output_key", "shape": {"one-of": ["max_tokens", "max_completion_tokens"]}, "required": false},
      {"name": "anthropic_adaptive_thinking", "shape": "bool", "required": false},
      {"name": "native_structured_output", "shape": "bool", "required": false},
      {"name": "model_capabilities", "shape": {"list": {"table": {
        "deny_unknown": true,
        "keys": [
          {"name": "models", "shape": {"list": "str"}, "required": true},
          {"name": "max_output_key", "shape": {"one-of": ["max_tokens", "max_completion_tokens"]}, "required": false},
          {"name": "anthropic_adaptive_thinking", "shape": "bool", "required": false},
          {"name": "native_structured_output", "shape": "bool", "required": false},
          {"name": "reasoning_none", "shape": "bool", "required": false},
          {"name": "thinking_always_on", "shape": "bool", "required": false}
        ]
      }}}, "required": false}
    ]
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
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = INTROSPECTION_VERBS;
    // No dialect here has a frame that supersedes the open one, and none paces the write path: a
    // request-and-answer dialect has neither, and declaring one would make the kernel look for a
    // fact that never arrives.
    const INTERRUPT_FACT: Option<&'static str> = None;
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}
