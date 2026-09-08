//! Tests for `records.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{
    operations_for, OPERATIONS, RECORD_SCHEMAS, SCHEMA_IDMAP, SCHEMA_TASK, SCHEMA_TASK_EVENT,
};

/// The two durable schemas carry the codec's own record kind names.
///
/// If the codec renames a kind, this goes red rather than the plane quietly writing records
/// under a name nothing reads back.
#[test]
fn the_durable_schemas_are_the_codecs_own_kinds() {
    assert_eq!(SCHEMA_TASK.as_str(), busbar_a2a_codec::record::KIND_TASK);
    assert_eq!(
        SCHEMA_TASK_EVENT.as_str(),
        busbar_a2a_codec::record::KIND_TASK_EVENT
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

/// `idmap` is a lookup and a remember, and never a scan or a delete.
///
/// The process-local table it durabilises is bounded and evicts oldest-first on its own; nothing
/// asks it to drop one entry or list every entry it holds.
#[test]
fn idmap_has_no_scan_and_no_delete() {
    let ops = operations_for(SCHEMA_IDMAP);
    assert!(ops.contains(&super::OP_GET));
    assert!(ops.contains(&super::OP_PUT));
    assert!(!ops.contains(&super::OP_SCAN));
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
