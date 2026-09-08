//! The plane's durable state, expressed as record legs rather than as a store this crate holds.
//!
//! A plane performs no input and no output. Everything it needs to remember across units is a
//! KERNEL-HELD record, reached only through a leg of the route plan, verified by the trust unit and
//! journaled like any other reach. So this module declares the schema and the operations, the same
//! shape `busbar-plane-a2a/src/records.rs` and `busbar-plane-mcp/src/records.rs` declare theirs in.
//!
//! ## The one schema, and where its name comes from
//!
//! `busbar-voice`'s own connection-lifetime session state
//! (`busbar-voice/src/runtime/scope.rs:24 VOICE_SESSION_KIND`) is already durable — it is written
//! through [`busbar_substrate::plane::handle_engine::DurableHandleEngine`] and rehydrated on boot —
//! and its own module doc names the record kind it is stamped under: `"voice_session"`. This module
//! declares the same identifier as a [`RecordSchemaId`], so the one place a plane crate can name
//! what a session record is called agrees with the one place `busbar-voice` already writes it.
//!
//! ## The conversion table
//!
//! | what `runtime/scope.rs` does today | what it becomes |
//! |---|---|
//! | `SessionScope::open` mints a row and its durable handle | a `voice_session` leg, operation `put` |
//! | `SessionScope::bump_turn`/`set_rtc_call_id`/`settle_terminal` mutate the open row | a `voice_session` leg, operation `put` |
//! | `SessionScope::get` reads the row back | a `voice_session` leg, operation `get` |
//! | `rehydrate_sessions` rebuilds the working set from every retained row at boot | a `voice_session` leg, operation `scan` |
//! | `SessionScope::close` evicts a settled row past its retention window | a `voice_session` leg, operation `delete` |

use busbar_contract::ids::RecordSchemaId;

/// The connection-lifetime session rows this plane's duplex sessions are durable under.
///
/// The literal string is `busbar-voice`'s own `VOICE_SESSION_KIND`
/// (`busbar-voice/src/runtime/scope.rs:24`), copied rather than imported: this crate depends on
/// `busbar-voice-codec` for its dialect codecs and IR types, never on `busbar-voice` itself (see the
/// crate root doc comment's dependency-seam note), so there is no path to the constant to import. A
/// test pins the two spellings against each other.
pub const SCHEMA_VOICE_SESSION: RecordSchemaId = RecordSchemaId::new("voice_session");

/// The record schemas this plane keeps kernel-held durable records under.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[SCHEMA_VOICE_SESSION];

/// Read one record back by key.
pub const OP_GET: &str = "get";

/// Write one record, replacing any earlier one under the same key.
pub const OP_PUT: &str = "put";

/// Read every record of a schema under one parent.
pub const OP_SCAN: &str = "scan";

/// Remove one record.
pub const OP_DELETE: &str = "delete";

/// Every operation any of this plane's schemas declares.
pub const OPERATIONS: &[&str] = &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE];

/// Which operations one schema declares.
///
/// A leg naming an operation its schema does not declare is refused by the trust unit, so the
/// answer has to be a declaration rather than a convention.
#[must_use]
pub fn operations_for(schema: RecordSchemaId) -> &'static [&'static str] {
    match schema.as_str() {
        s if s == SCHEMA_VOICE_SESSION.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE],
        _ => &[],
    }
}

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
