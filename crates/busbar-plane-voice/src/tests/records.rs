//! Tests for `records.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{operations_for, OPERATIONS, RECORD_SCHEMAS, SCHEMA_VOICE_SESSION};

/// The one durable schema's literal spelling agrees with `busbar-voice`'s own record kind.
///
/// `busbar-voice/src/runtime/scope.rs:24` names `VOICE_SESSION_KIND = "voice_session"` but keeps it
/// private, so this pins the spelling as a literal rather than importing a constant this crate has
/// no dependency path to. If the two ever disagree, this is where it goes red.
#[test]
fn the_durable_schema_matches_busbar_voices_own_session_kind() {
    assert_eq!(SCHEMA_VOICE_SESSION.as_str(), "voice_session");
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

/// The session row supports the full read/write/list/evict cycle `runtime/scope.rs`'s own methods
/// need: `open`/`bump_turn`/`set_rtc_call_id`/`settle_terminal` (`put`), `get` (`get`),
/// `rehydrate_sessions` (`scan`), and `close` past the retention window (`delete`).
#[test]
fn the_voice_session_schema_supports_the_full_lifecycle() {
    let ops = operations_for(SCHEMA_VOICE_SESSION);
    assert!(ops.contains(&super::OP_GET));
    assert!(ops.contains(&super::OP_PUT));
    assert!(ops.contains(&super::OP_SCAN));
    assert!(ops.contains(&super::OP_DELETE));
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
