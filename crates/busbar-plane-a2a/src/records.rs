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
//! | remembers what the backend calls a task busbar minted its own id for | an `idmap` leg, operation `put` |
//! | resolves the backend's id for a task, scoped to the caller who owns it | an `idmap` leg, operation `get` |
//! | authorises a callback token | a `push_config` leg, operation `verify_live`, and a `revoke` leg once the task is terminal |
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
//! ## Two of the five schemas are the codec's own names
//!
//! The task and task-event schemas take their identifiers from the codec's own record kinds, so
//! there is one answer to "what is this record called" rather than two that agree today. The other
//! three name state the codec keeps in memory today and therefore forgets on restart; declaring them
//! here is what makes that forgetting visible.
//!
//! ## `idmap` is process-local today, and its own header says so
//!
//! `crate::idmap` (`busbar-a2a/src/a2a/idmap.rs:27-30`) states its own limitation: "this mapping is
//! PROCESS-LOCAL and does not survive a restart. The durable place for it is…". This schema is that
//! durable place, declared. It carries no `scan` and no `delete`: the process-local table is
//! bounded and evicts oldest-first rather than ever being asked to drop one entry, and there is no
//! caller that lists every mapping rather than resolving one busbar-minted id at a time.

use busbar_contract::ids::RecordSchemaId;

/// The task rows: one per governed exchange this node is tracking.
pub const SCHEMA_TASK: RecordSchemaId = RecordSchemaId::new(busbar_a2a_codec::record::KIND_TASK);

/// The task event rows: the hash-linked history behind each task.
pub const SCHEMA_TASK_EVENT: RecordSchemaId =
    RecordSchemaId::new(busbar_a2a_codec::record::KIND_TASK_EVENT);

/// The push-notification configurations a caller registered against a task.
pub const SCHEMA_PUSH_CONFIG: RecordSchemaId = RecordSchemaId::new("push_config");

/// The pinned callback addresses a delivery is allowed to reach.
pub const SCHEMA_PIN: RecordSchemaId = RecordSchemaId::new("pin");

/// The busbar-minted task id → the backend's own task id, so the mapping `crate::idmap` keeps
/// process-local today survives a restart. See `busbar-a2a/src/a2a/idmap.rs:27-30`.
pub const SCHEMA_IDMAP: RecordSchemaId = RecordSchemaId::new("idmap");

/// The record schemas this plane keeps kernel-held durable records under.
pub const RECORD_SCHEMAS: &[RecordSchemaId] = &[
    SCHEMA_TASK,
    SCHEMA_TASK_EVENT,
    SCHEMA_PUSH_CONFIG,
    SCHEMA_PIN,
    SCHEMA_IDMAP,
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

/// Ask whether a callback token is STILL LIVE, and spend nothing asking.
///
/// The verb a push callback is authorised by, and deliberately not a `redeem`. The token busbar
/// registers with a backend names ONE TASK and is presented once per state that task moves through —
/// `working`, then `input-required`, then `completed` — so it is a capability that lasts as long as
/// the work does, not a one-time nonce. A `redeem` gets that wrong twice over: spent on the first
/// callback it refuses the rest of an honest sequence, and answered `true` every time it accepts a
/// captured one forever.
///
/// LIVE means all three of: the configuration is still there, the task it names has not reached a
/// terminal state, and the task's deadline has not passed. The moment any of those stops holding the
/// token is dead and every later callback carrying it is refused.
pub const OP_VERIFY_LIVE: &str = "verify_live";

/// Revoke a callback token, so nothing presenting it is authorised again.
///
/// Its own operation rather than a `delete`, because the two say different things to an operator
/// reading the plan: a `delete` is the caller withdrawing a configuration it registered, and this is
/// busbar retiring a capability whose task has finished. They happen at different moments for
/// different reasons, and folding them together would make the revocation invisible in the one place
/// the push-event plan is read.
pub const OP_REVOKE: &str = "revoke";

/// Every operation any of this plane's schemas declares.
pub const OPERATIONS: &[&str] = &[
    OP_GET,
    OP_PUT,
    OP_SCAN,
    OP_APPEND,
    OP_DELETE,
    OP_VERIFY_LIVE,
    OP_REVOKE,
];

/// Which operations one schema declares.
///
/// A leg naming an operation its schema does not declare is refused by the trust unit, so the
/// answer has to be a declaration rather than a convention.
#[must_use]
pub fn operations_for(schema: RecordSchemaId) -> &'static [&'static str] {
    match schema.as_str() {
        s if s == SCHEMA_TASK.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_DELETE],
        s if s == SCHEMA_TASK_EVENT.as_str() => &[OP_APPEND, OP_SCAN],
        s if s == SCHEMA_PUSH_CONFIG.as_str() => &[
            OP_GET,
            OP_PUT,
            OP_SCAN,
            OP_DELETE,
            OP_VERIFY_LIVE,
            OP_REVOKE,
        ],
        s if s == SCHEMA_PIN.as_str() => &[OP_GET, OP_PUT, OP_DELETE],
        // No `scan`, no `delete`: see this module's doc comment on why.
        s if s == SCHEMA_IDMAP.as_str() => &[OP_GET, OP_PUT],
        _ => &[],
    }
}

#[cfg(test)]
#[path = "tests/records.rs"]
mod tests;
