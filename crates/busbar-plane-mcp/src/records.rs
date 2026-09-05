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
pub const SCHEMA_DEMOTION: RecordSchemaId = RecordSchemaId::new(busbar_mcp_codec::record::KIND_DEMOTION);

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

#[cfg(test)]
mod tests {
    use super::{
        operations_for, OPERATIONS, RECORD_SCHEMAS, SCHEMA_APPROVAL, SCHEMA_CALL, SCHEMA_DEMOTION,
    };

    /// The two durable schemas carry the codec's own record kind names.
    ///
    /// If the codec renames a kind, this goes red rather than the plane quietly writing records
    /// under a name nothing reads back.
    #[test]
    fn the_durable_schemas_are_the_codecs_own_kinds() {
        assert_eq!(SCHEMA_CALL.as_str(), busbar_mcp_codec::record::KIND_CALL);
        assert_eq!(SCHEMA_DEMOTION.as_str(), busbar_mcp_codec::record::KIND_DEMOTION);
    }

    /// Every schema declares at least one operation, and every operation it declares is a known one.
    #[test]
    fn every_schema_declares_known_operations() {
        for schema in RECORD_SCHEMAS {
            let ops = operations_for(*schema);
            assert!(!ops.is_empty(), "{schema} declares no operation");
            for op in ops {
                assert!(OPERATIONS.contains(op), "{schema} declares unknown op {op}");
            }
        }
    }

    /// A schema this plane does not declare has no operations at all.
    #[test]
    fn an_undeclared_schema_declares_nothing() {
        let stranger = busbar_contract::ids::RecordSchemaId::new("ledger");
        assert!(operations_for(stranger).is_empty());
    }

    /// The call log cannot be overwritten or deleted.
    #[test]
    fn the_call_log_cannot_be_rewritten() {
        let ops = operations_for(SCHEMA_CALL);
        assert!(!ops.contains(&super::OP_PUT));
        assert!(!ops.contains(&super::OP_DELETE));
    }

    /// An approval is spent atomically, never read and then spent.
    ///
    /// A read followed by a write is two units of time in which a second caller can spend the same
    /// grant. Declaring no read at all is what makes that impossible to write by accident.
    #[test]
    fn an_approval_is_spent_atomically() {
        let ops = operations_for(SCHEMA_APPROVAL);
        assert!(ops.contains(&super::OP_REDEEM));
        assert!(!ops.contains(&super::OP_GET));
        assert!(!ops.contains(&super::OP_SCAN));
    }

    /// No schema name is repeated.
    #[test]
    fn no_schema_is_declared_twice() {
        for (i, schema) in RECORD_SCHEMAS.iter().enumerate() {
            assert!(
                !RECORD_SCHEMAS[..i].iter().any(|s| s == schema),
                "{schema} is declared twice"
            );
        }
    }
}
