//! The plane's durable state, expressed as record legs rather than as a store this crate holds.
//!
//! A plane performs no input and no output. Everything it needs to remember across units is a
//! KERNEL-HELD record, reached only through a leg of the route plan, verified by the trust unit and
//! journaled like any other reach. So this module declares the schemas and the operations, and the
//! routing method turns each of the codec's present-day reaches into one of them.
//!
//! ## The conversion table
//!
//! The existing codec reaches state in twelve places. Written out in full, because "the store reads
//! became legs" is the kind of sentence that is true of ten out of twelve.
//!
//! | what the codec does today | what it becomes |
//! |---|---|
//! | reads the demotion rows at boot to un-advertise a quarantined tool | a `demotion` leg, operation `scan` |
//! | records a demotion, or clears one, when a server is re-contacted | a `demotion` leg, operation `put` or `delete` |
//! | reads the call log back for one caller | a `call` leg, operation `scan` |
//! | appends a call record for what a caller asked for and got | a `call` leg, operation `append` |
//! | spends a one-time approval, exactly once, so a retry cannot re-spend it | an `approval` leg, operation `redeem` |
//! | builds the tool catalogue from configuration on every apply | a `catalogue` leg, operation `scan`, so the catalogue survives a restart with the approvals it was approved under |
//! | resolves one tool, prompt or resource through the catalogue | a `catalogue` leg, operation `get` |
//! | reads a server's registration to decide how to reach it | a `settings` leg, operation `get` |
//! | keeps the per-caller roots generation in memory, so a restart forgets it | a `settings` leg, operation `put` |
//! | keeps the long-running tasks in a process-local map | a `task` leg, so a restart no longer loses a task a caller is waiting on |
//! | keeps a subscription's cursor in memory for the life of one stream | stays in memory: a subscription IS the life of one stream, and a stream does not survive a restart |
//! | keeps the sampling spend in a process-local counter | an `approval` leg, because a spend that a restart forgets is a cap that a restart lifts |
//!
//! And the reaches that are NOT records, because they were never this plane's to hold:
//!
//! | what the codec does today | where it goes |
//! |---|---|
//! | charges a meter, once per round | the metering step's locators |
//! | writes an audit row | the audit step's facts |
//! | asks a breaker whether to proceed, and settles it | the breaker unit |
//! | asks governance whether the caller may spend | the admission unit |
//! | fires a gate hook, or a rewrite hook | the hook seats |
//! | asks the engine to synthesize a completion for an upstream's request | a nested unit of the other plane, reached as a nested destination |
//! | resolves a credential for an outbound hop | the egress-auth unit; the plane names the scheme and never sees the secret |
//!
//! ## Two of the schemas are the codec's own names
//!
//! The call and demotion schemas take their identifiers from the codec's own record kinds, so there
//! is one answer to "what is this record called" rather than two that agree today. The other four
//! name state the codec keeps in memory or derives from configuration, and therefore forgets on
//! restart; declaring them here is what makes that forgetting visible.

use busbar_contract::ids::RecordSchemaId;

/// The call log: what each caller asked for, and what they got.
pub const SCHEMA_CALL: RecordSchemaId = RecordSchemaId::new(busbar_mcp_codec::record::KIND_CALL);

/// The quarantine rows: which servers are not being advertised, and why.
pub const SCHEMA_DEMOTION: RecordSchemaId =
    RecordSchemaId::new(busbar_mcp_codec::record::KIND_DEMOTION);

/// The tool catalogue: what each registered server was observed to offer.
pub const SCHEMA_CATALOGUE: RecordSchemaId = RecordSchemaId::new("catalogue");

/// The approvals: the one-time grants a retry must not be able to re-spend.
pub const SCHEMA_APPROVAL: RecordSchemaId = RecordSchemaId::new("approval");

/// The settings: each registered server's own configuration as it was applied.
pub const SCHEMA_SETTINGS: RecordSchemaId = RecordSchemaId::new("settings");

/// The long-running tasks a caller may come back for.
pub const SCHEMA_TASK: RecordSchemaId = RecordSchemaId::new("task");

/// The record schemas this plane keeps kernel-held durable records under.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[
    SCHEMA_CALL,
    SCHEMA_DEMOTION,
    SCHEMA_CATALOGUE,
    SCHEMA_APPROVAL,
    SCHEMA_SETTINGS,
    SCHEMA_TASK,
];

/// Read one record back by key.
pub const OP_GET: &str = "get";

/// Write one record, replacing any earlier one under the same key.
pub const OP_PUT: &str = "put";

/// Read every record of a schema under one parent.
pub const OP_SCAN: &str = "scan";

/// Add one record to a schema's append-only side.
pub const OP_APPEND: &str = "append";

/// Remove one record.
pub const OP_DELETE: &str = "delete";

/// Spend a one-time grant, exactly once, and say whether this caller is the one who spent it.
pub const OP_REDEEM: &str = "redeem";

/// Every operation any of this plane's schemas declares.
pub const OPERATIONS: &[&str] = &[OP_GET, OP_PUT, OP_SCAN, OP_APPEND, OP_DELETE, OP_REDEEM];

/// Which operations one schema declares.
///
/// A leg naming an operation its schema does not declare is refused by the trust unit, so the answer
/// has to be a declaration rather than a convention.
#[must_use]
pub fn operations_for(schema: RecordSchemaId) -> &'static [&'static str] {
    match schema.as_str() {
        // The call log is append-and-read. It is the answer to "what happened", and an answer whose
        // middle can be replaced is not an answer.
        s if s == SCHEMA_CALL.as_str() => &[OP_APPEND, OP_SCAN],
        s if s == SCHEMA_DEMOTION.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE],
        s if s == SCHEMA_CATALOGUE.as_str() => &[OP_GET, OP_PUT, OP_SCAN],
        // An approval is spent, never read and then spent: the two-step version is the race the
        // redeem operation exists to close.
        s if s == SCHEMA_APPROVAL.as_str() => &[OP_PUT, OP_REDEEM],
        s if s == SCHEMA_SETTINGS.as_str() => &[OP_GET, OP_PUT, OP_SCAN],
        s if s == SCHEMA_TASK.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE],
        _ => &[],
    }
}

// ── THE CALL RECORD'S OWN BYTES ─────────────────────────────────────────────────────────────────
//
// A plane declares its record, and a record is a schema plus the bytes one instance of it frames
// to. The schema is above; the bytes are here. Nothing else in the tree may spell them: the digest
// a deployed store sealed is over exactly this byte stream, so a second speller is a second answer
// to "what happened" waiting for one of them to be edited.

/// THE CALL RECORD'S PRE-FRAMED CONTENT SUFFIX: the chained fields AFTER the chain's own prelude.
///
/// Seven fields, length-prefixed — `len:u64-be ⧺ bytes`, an integer carried as its eight big-endian
/// bytes in one such field — in the order `ts, server, tool, outcome, reason, tool_digest,
/// pin_generation`. Every field self-delimits, so the prelude and this suffix byte-concatenate with
/// no separator and the concatenation is the digest input.
///
/// The request id is DELIBERATELY ABSENT. It is a join key, it is legitimately empty on every path
/// with no inbound request, and a field that is sometimes absent must not be able to make an
/// otherwise-intact chain unverifiable.
///
/// A pure function of seven scalars: it names no store, no host and no engine, which is what lets
/// the record be the plane's while the chain around it belongs to the audit unit.
#[must_use]
pub fn call_suffix(
    ts: u64,
    server: &str,
    tool: &str,
    outcome: &str,
    reason: &str,
    tool_digest: &str,
    pin_generation: u64,
) -> Vec<u8> {
    fn text(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u64).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    fn num(out: &mut Vec<u8>, v: u64) {
        let b = v.to_be_bytes();
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&b);
    }
    let mut out = Vec::new();
    num(&mut out, ts);
    text(&mut out, server);
    text(&mut out, tool);
    text(&mut out, outcome);
    text(&mut out, reason);
    text(&mut out, tool_digest);
    num(&mut out, pin_generation);
    out
}

/// The seven fields of one call record, read back out of its suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFields {
    /// Unix seconds the call was recorded at.
    pub ts: u64,
    /// Which registered server the call was routed to.
    pub server: String,
    /// Which tool was asked for.
    pub tool: String,
    /// The stable outcome token.
    pub outcome: String,
    /// The stable reason token, empty where the outcome needs none.
    pub reason: String,
    /// The digest of the tool definition the call was admitted against.
    pub tool_digest: String,
    /// Which pin generation was in force.
    pub pin_generation: u64,
}

/// Read one call suffix back into its seven fields — the exact inverse of [`call_suffix`].
///
/// Fails CLOSED on a truncated or oversized field rather than reading past the buffer: this decodes
/// bytes a store handed back, and a store is exactly the thing that may have been tampered with.
#[must_use]
pub fn parse_call_suffix(content: &[u8]) -> Option<CallFields> {
    fn take<'a>(content: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
        let end = off.checked_add(8)?;
        if end > content.len() {
            return None;
        }
        let len = u64::from_be_bytes(content[*off..end].try_into().ok()?) as usize;
        let field_end = end.checked_add(len)?;
        if field_end > content.len() {
            return None;
        }
        *off = field_end;
        Some(&content[end..field_end])
    }
    fn num(content: &[u8], off: &mut usize) -> Option<u64> {
        let b: [u8; 8] = take(content, off)?.try_into().ok()?;
        Some(u64::from_be_bytes(b))
    }
    fn text(content: &[u8], off: &mut usize) -> Option<String> {
        Some(String::from_utf8_lossy(take(content, off)?).into_owned())
    }
    let mut off = 0usize;
    Some(CallFields {
        ts: num(content, &mut off)?,
        server: text(content, &mut off)?,
        tool: text(content, &mut off)?,
        outcome: text(content, &mut off)?,
        reason: text(content, &mut off)?,
        tool_digest: text(content, &mut off)?,
        pin_generation: num(content, &mut off)?,
    })
}

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
