//! What this plane declares about itself, through the contract's own `PlaneMeta` trait.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy. This is the contract's own trait, which `plane.rs`'s `impl Plane for DecisionPlane`
//! is checked against regardless of whether anything outside this crate has been told the plane
//! exists. It is the ONLY declaration this crate makes about itself: the kernel-shaped `PlaneDecl`
//! constant that used to sit beside it in `registry.rs` is gone — it was a generation-1 registration
//! nothing ever read, and carrying it cost this plugin crate a `busbar-kernel` dependency the
//! dep-wall forbids.

use busbar_contract::grammar::Claim;
use busbar_contract::ids::{
    AdminVerbId, ClassDirection, MeterClassDecl, MeterClassId, OpClassId, RecordSchemaId,
};
use busbar_contract::plane::PlaneMeta;

use crate::{claims, facts, ops, records, DecisionPlane};

/// The family the billable-decision class rolls up into.
const DECISION_FAMILY: &str = "decision";

/// The class key jev meters under.
///
/// ONE class, priced on the provider's own success billing. The signed design's C-3 rules
/// "billable-success fee gated kernel-side, `units_decision` twin of `units_mcp`" — this plane's
/// job is the twin of `busbar-plane-mcp`'s own metering surface: a locator naming the class and the
/// quantity this codec already read off a SUCCESS response, direction `Response` because the
/// quantity is sized from what the provider answered, never from what the caller asked. A 4xx
/// answer (the provider blamed the request) has nothing extractable under this class — see
/// `plane.rs::meter` and the `billable_success_only` test.
pub const CLASS_DECISION: MeterClassId = MeterClassId::new("decision");

/// The meter classes this plane declares.
const METER_CLASSES: &[MeterClassDecl] = &[MeterClassDecl {
    key: CLASS_DECISION,
    family: DECISION_FAMILY,
    direction: ClassDirection::Response,
    // The provider's own usage unit is the quantity; nothing here divides it further.
    default_divisor: 1,
}];

/// The schema of this plane's own configuration block.
///
/// One level deep: a map from busbar-facing model name to that model's definition (`provider`
/// required, `upstream_model` optional — the shape `busbar_contract::config::ModelCfg`
/// already parses, see `config.rs`), plus the two reserved members every model-serving section
/// carries. Nothing here is a credential and nothing here is a price.
const CONFIG_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "models": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "provider": { "type": "string" },
          "upstream_model": { "type": "string" },
          "max_requests": { "type": "integer" },
          "max_concurrent": { "type": "integer" },
          "default_max_tokens": { "type": "integer" },
          "attempt_timeout_ms": { "type": "integer" },
          "reasoning": { "type": "boolean" },
          "prompt_caching": { "type": "boolean" }
        },
        "required": ["provider"]
      }
    },
    "hooks": { "type": "array", "items": { "type": "string" } },
    "upstream_credentials": { "type": "string", "enum": ["own", "passthrough"] }
  }
}"#;

impl PlaneMeta for DecisionPlane {
    const KEY: &'static str = "decision";
    const CLAIMS: &'static [Claim] = claims::CLAIMS;
    const OP_CLASSES: &'static [OpClassId] = ops::OP_CLASSES;
    const METER_CLASSES: &'static [MeterClassDecl] = METER_CLASSES;
    const SESSION_FACTS: &'static [&'static str] = facts::SESSION_FACTS;
    const CONTENT_FACTS: &'static [&'static str] = facts::CONTENT_FACTS;
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = records::RECORD_SCHEMAS;
    // jev has no introspection verb of its own today — the provider set is a plain config read,
    // not a live catalogue with state worth projecting (unlike A2A's configured-agent list).
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = &[];
    // jev's answers are single request/response pairs; nothing supersedes an open one.
    const INTERRUPT_FACT: Option<&'static str> = None;
    // Nothing paces jev's write path — no streamed answer to pace.
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}

#[cfg(test)]
#[path = "tests/meta.rs"]
mod tests;
