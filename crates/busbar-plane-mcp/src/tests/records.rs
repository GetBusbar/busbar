//! Tests for `records.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{
    operations_for, OPERATIONS, RECORD_SCHEMAS, SCHEMA_APPROVAL, SCHEMA_CALL, SCHEMA_DEMOTION,
};
use busbar_mcp_codec::record::{KIND_CALL, KIND_DEMOTION};

/// The two durable schemas carry the codec's own record kind names.
///
/// If the codec renames a kind, this goes red rather than the plane quietly writing records
/// under a name nothing reads back.
#[test]
fn the_durable_schemas_are_the_codecs_own_kinds() {
    assert_eq!(SCHEMA_CALL.as_str(), KIND_CALL);
    assert_eq!(SCHEMA_DEMOTION.as_str(), KIND_DEMOTION);
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
