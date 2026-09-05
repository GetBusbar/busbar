//! The plane's durable state, expressed as record legs rather than as a store this crate holds.
//!
//! A plane performs no input and no output. Everything it needs to remember across units is a
//! KERNEL-HELD record, reached only through a leg of the route plan, verified by the trust unit and
//! journaled like any other reach. So this module declares the schemas and the operations, and the
//! routing method turns each of the codec's present-day direct store touches into one of them.
//!
//! ## The conversion table
//!
//! The existing codec reaches durable and process-local state in nine places. Each becomes a leg
//! here, or a fact, or it belongs to a unit and leaves the plane entirely. Written out in full,
//! because "the store reads became legs" is the kind of sentence that is true of eight out of nine.
//!
//! | what the codec does today | what it becomes |
//! |---|---|
//! | writes a task row when a message opens one | a `tasks` leg, operation `put` |
//! | writes a task row when the task changes state | a `tasks` leg, operation `put` |
//! | reads one task row back, scoped to the caller | a `tasks` leg, operation `get` |
//! | lists the task rows a caller may see | a `tasks` leg, operation `scan` |
//! | appends an event row as a task advances | a `task_event` leg, operation `append` |
//! | reads a task's event rows back | a `task_event` leg, operation `scan` |
//! | sets or clears a task's callback address | a `push_config` leg, operation `put` or `delete` |
//! | keeps the caller's push configurations in a process-local map | a `push_config` leg, so a restart no longer forgets them |
//! | keeps a callback's pinned address in a process-local map | a `pin` leg, for the same reason |
//! | keeps a mapping from the identifier this node minted to the one the agent minted | a `tasks` `get`; the mapping is a member of the row, not a second store |
//! | redeems a one-time callback token | a `push_config` leg, operation `redeem` |
//!
//! And the five reaches that are NOT records, because they were never this plane's to hold:
//!
//! | what the codec does today | where it goes |
//! |---|---|
//! | charges a meter | the metering step's locators |
//! | writes an audit row | the audit step's facts |
//! | asks a breaker whether to proceed | the breaker unit |
//! | asks governance whether the caller may spend | the admission unit |
//! | resolves a credential for an outbound hop | the egress-auth unit; the plane names the scheme and never sees the secret |
//!
//! ## Two of the four schemas are the codec's own names
//!
//! The task and task-event schemas take their identifiers from the codec's own record kinds, so
//! there is one answer to "what is this record called" rather than two that agree today. The other
//! two name state the codec keeps in memory today and therefore forgets on restart; declaring them
//! here is what makes that forgetting visible.

use busbar_contract::ids::RecordSchemaId;

/// The task rows: one per governed exchange this node is tracking.
pub const SCHEMA_TASK: RecordSchemaId = RecordSchemaId::new(busbar_a2a::record::KIND_TASK);

/// The task event rows: the hash-linked history behind each task.
pub const SCHEMA_TASK_EVENT: RecordSchemaId =
    RecordSchemaId::new(busbar_a2a::record::KIND_TASK_EVENT);

/// The push-notification configurations a caller registered against a task.
pub const SCHEMA_PUSH_CONFIG: RecordSchemaId = RecordSchemaId::new("push_config");

/// The pinned callback addresses a delivery is allowed to reach.
pub const SCHEMA_PIN: RecordSchemaId = RecordSchemaId::new("pin");

/// The record schemas this plane keeps kernel-held durable records under.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[
    SCHEMA_TASK,
    SCHEMA_TASK_EVENT,
    SCHEMA_PUSH_CONFIG,
    SCHEMA_PIN,
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

/// Spend a one-time token, exactly once, and say whether this caller is the one who spent it.
pub const OP_REDEEM: &str = "redeem";

/// Every operation any of this plane's schemas declares.
pub const OPERATIONS: &[&str] = &[OP_GET, OP_PUT, OP_SCAN, OP_APPEND, OP_DELETE, OP_REDEEM];

/// Which operations one schema declares.
///
/// A leg naming an operation its schema does not declare is refused by the trust unit, so the
/// answer has to be a declaration rather than a convention.
#[must_use]
pub fn operations_for(schema: RecordSchemaId) -> &'static [&'static str] {
    match schema.as_str() {
        s if s == SCHEMA_TASK.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE],
        s if s == SCHEMA_TASK_EVENT.as_str() => &[OP_APPEND, OP_SCAN],
        s if s == SCHEMA_PUSH_CONFIG.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE, OP_REDEEM],
        s if s == SCHEMA_PIN.as_str() => &[OP_GET, OP_PUT, OP_DELETE],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::{operations_for, OPERATIONS, RECORD_SCHEMAS, SCHEMA_TASK, SCHEMA_TASK_EVENT};

    /// The two durable schemas carry the codec's own record kind names.
    ///
    /// If the codec renames a kind, this goes red rather than the plane quietly writing records
    /// under a name nothing reads back.
    #[test]
    fn the_durable_schemas_are_the_codecs_own_kinds() {
        assert_eq!(SCHEMA_TASK.as_str(), busbar_a2a::record::KIND_TASK);
        assert_eq!(
            SCHEMA_TASK_EVENT.as_str(),
            busbar_a2a::record::KIND_TASK_EVENT
        );
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

    /// The append-only history is append-and-read, never overwritten.
    ///
    /// The event rows are hash-linked, and a chain whose middle can be replaced is not a chain.
    #[test]
    fn the_history_cannot_be_overwritten() {
        let ops = operations_for(SCHEMA_TASK_EVENT);
        assert!(!ops.contains(&super::OP_PUT));
        assert!(!ops.contains(&super::OP_DELETE));
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
