//! This plane's durable state — which is none.
//!
//! MCP and A2A keep kernel-held records because their exchanges are stateful across calls: a tool
//! catalogue, a task and its event history, a push-notification pin. jev is neither: each of its
//! two operations is a single request/response pair against a provider/account-scoped upstream, the
//! provider's `/v1/models` answer is never cached (the design's C-6 ruling is explicit — no busbar
//! catalogue synthesis, the provider's list is relayed as-is on every call), and `systemone` mints
//! no busbar-side identifier a later call would need to look back up. So this plane declares no
//! record schemas and `plane.rs::route` names no record leg — every leg it returns is a hop to the
//! configured provider.
//!
//! This is a real design choice, not an omission: if a future decision vendor's dialect needed
//! durable state (a multi-turn decision session, say), that vendor's dialect would declare the
//! schema it needs here, exactly as A2A declares its four.

use busbar_contract::ids::RecordSchemaId;

/// The record schemas this plane keeps kernel-held durable records under — empty, see the module
/// note.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[];

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
