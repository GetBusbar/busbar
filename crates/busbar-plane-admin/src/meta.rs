//! What this plane declares about itself.
//!
//! Everything here is a constant, because everything here is read once at registration and sealed
//! into policy — the same rule every `PlaneMeta` impl in this workspace states.

use busbar_contract::ids::{AdminVerbId, MeterClassDecl, OpClassId, RecordSchemaId};
use busbar_contract::plane::PlaneMeta;

use crate::claims;
use crate::verbs::{OP_READ, OP_WRITE};
use crate::AdminPlane;

/// The two operation classes a unit of this plane can be: a read that reaches nothing but the
/// journal, and a mutation. See [`crate::verbs::OP_READ`]/[`crate::verbs::OP_WRITE`] for why the
/// closed 66+17 table collapses to two classes rather than one per verb: pricing is uniform across
/// the whole admin surface (a flat, kernel-reserved `count` class — see `METER_CLASSES` below), so
/// the only thing an operation class needs to preserve here is the design's own `ReadOnly`/`Full`
/// split, for the audit step's dispute check to mean something.
const OP_CLASSES: &[OpClassId] = &[OP_READ, OP_WRITE];

/// This plane declares NO meter classes of its own.
///
/// The design's admin row prices every verb under `count`, and `count` — along with `requests`,
/// `fee` and `session_seconds` — is named as a KERNEL-RESERVED meter class, declared by the kernel
/// itself with direction `Kernel`, and "the registry refuses them from any plane" that tries to
/// declare one. An admin plane that declared `count` here would therefore be refused at boot; the
/// correct declaration is the empty one, matching every evidence read (`read_*`) being "pinned at 0
/// and never refused for budget" — the admin surface's own reads included.
const METER_CLASSES: &[MeterClassDecl] = &[];

/// The session fact keys this plane writes: none. The admin claim is plain HTTP request/response,
/// never a session transport (see the module doc comment below for why `SessionPlane` is not
/// implemented), so there is no session for a fact to attach to.
const SESSION_FACTS: &[&str] = &[];

/// The fact key under which `content_facts` reports which verb a response answered.
pub(crate) const FACT_VERB: &str = "verb";

/// The content fact keys this plane produces: which verb ran. Never a credential, never the mutation
/// payload itself — content facts are evidence for the export path, and the design is explicit that
/// a minted secret's placeholder never appears there; this plane mints no secrets at all (see the
/// crate-root doc comment on the `SecretOnce` boundary) so there is nothing further to withhold.
const CONTENT_FACTS: &[&str] = &[FACT_VERB];

/// This plane's own read-only introspection verbs: none.
///
/// The constant used to be called `ADMIN_VERBS`, which collided in name with this crate's own
/// 66+17-row `KernelVerb` table -- the admin SURFACE itself, not a plane's self-description of it.
/// Two different things wearing one name had already confused an implementer, so the small
/// per-plane set every plane may answer through `plane_facts` (the `llm` plane's `dialects` and
/// `ladder`, this protocol's per-name projections) is called what it is.
///
/// Declaring this plane's OWN introspection verb as, say, `verb_table` (a verb that dumps the 66+17
/// rows) was considered and rejected: the closed table is already fully public in this crate's
/// `generated` module and in the pinned openapi fixture, so a further meta-verb would be a second
/// copy of the same 83 rows rather than new information. Empty is the honest answer for a plane
/// that IS the admin surface and therefore needs no verb ABOUT itself.
const INTROSPECTION_VERBS: &[AdminVerbId] = &[];

/// This plane's configuration schema: an empty object.
///
/// The admin surface's claim (one prefix, one credential scheme) needs no operator-configured
/// knob distinct from the credential and scope machinery `busbar-unit-verbs`/the scope unit already
/// own; there is no lane to name, no upstream to configure, and no secret ref a plane config could
/// smuggle in.
const CONFIG_SCHEMA: &str = r#"{"type":"object","additionalProperties":false,"properties":{}}"#;

impl PlaneMeta for AdminPlane {
    const KEY: &'static str = "admin";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = claims::CLAIMS;
    const OP_CLASSES: &'static [OpClassId] = OP_CLASSES;
    const METER_CLASSES: &'static [MeterClassDecl] = METER_CLASSES;
    const SESSION_FACTS: &'static [&'static str] = SESSION_FACTS;
    const CONTENT_FACTS: &'static [&'static str] = CONTENT_FACTS;
    // This plane keeps no kernel-held durable records of its own: the design's admin row lists no
    // Records for this plane (mutating plane-record writes are the `plane_record_write` KERNEL VERB,
    // executed by `busbar-unit-verbs` against ANOTHER plane's declared schema — never this plane's).
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = &[];
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = INTROSPECTION_VERBS;
    // No admin frame ever supersedes an open one (there is no open unit to supersede: every admin
    // unit is `OneShot`), and nothing on this plane paces an outbound write path (this plane never
    // writes to an upstream at all — see `route`/`encode_egress`).
    const INTERRUPT_FACT: Option<&'static str> = None;
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = CONFIG_SCHEMA;
}
