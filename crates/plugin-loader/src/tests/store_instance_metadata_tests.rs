// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::abi::mechanism::call::{BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::sdk::store::metadata;

#[test]
fn legacy_open_and_instance_specific_memory_or_durable_answers_are_distinct() {
    assert_eq!(
        instance_ephemeral(lifecycle::blob(&[], BLOB_ABSENT, 0)),
        Ok(None)
    );
    let memory = metadata::encode(true);
    let durable = metadata::encode(false);
    assert_eq!(
        instance_ephemeral(lifecycle::blob(&memory, BLOB_OCTETS, 0)),
        Ok(Some(true))
    );
    assert_eq!(
        instance_ephemeral(lifecycle::blob(&durable, BLOB_OCTETS, 0)),
        Ok(Some(false))
    );
    assert!(instance_ephemeral(lifecycle::blob(&memory, BLOB_JSON, 0)).is_err());
}

#[test]
fn invalid_open_metadata_ranges_are_refused_before_reading_them() {
    let bytes = metadata::encode(true);
    let mut blob = lifecycle::blob(&bytes, BLOB_OCTETS, 0);
    blob.ptr = std::ptr::null();
    assert!(instance_ephemeral(blob).is_err());
    blob.ptr = bytes.as_ptr();
    blob.len = usize::MAX;
    assert!(instance_ephemeral(blob).is_err());
}

use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts, MARK_EPHEMERAL};
use busbar_contract::abi::store::Ops;
use std::sync::OnceLock;

extern "C" fn open_without_instance_metadata(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    output: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    // SAFETY: forward the original live OPEN frames to the retained real SQLite image.
    unsafe {
        let ops = &*crate::actual_store::door().ops().cast::<Ops>();
        let answer = ops.head.open.expect("actual SQLite OPEN")(instance, input, output);
        if answer == busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Ready) {
            // Model a fixed backend's absent optional metadata; retain its genuine lease so
            // the loader still releases the original answer through the actual Store.
            (*output.cast::<OpenOut>()).head.extensions = lifecycle::blob(&[], BLOB_ABSENT, 0);
        }
        answer
    }
}

fn metadata_door(slot: &OnceLock<usize>, ephemeral: bool, omit_metadata: bool) -> &'static Door {
    let address = *slot.get_or_init(|| {
        let actual = *crate::actual_store::door();
        // SAFETY: actual_store retains the validated immutable descriptor and operation table.
        let (mut statement, mut ops) = unsafe {
            (
                *actual.statement(),
                actual.ops().cast::<Ops>().read_unaligned(),
            )
        };
        if ephemeral {
            statement.marks |= MARK_EPHEMERAL;
        } else {
            statement.marks &= !MARK_EPHEMERAL;
        }
        if omit_metadata {
            ops.head.open = Some(open_without_instance_metadata);
        }
        let statement = Box::leak(Box::new(statement));
        let ops = Box::leak(Box::new(ops));
        // SAFETY: only the static durability declaration and optional metadata projection
        // differ; retained genuine SQLite operations own the instance and all its behavior.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                statement,
                ops: std::ptr::from_ref(ops).cast(),
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: this immutable descriptor and its data are retained permanently above.
    unsafe { &*(address as *const Door) }
}

extern "C" fn static_durable() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    metadata_door(&SLOT, false, true)
}
extern "C" fn static_ephemeral() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    metadata_door(&SLOT, true, true)
}
extern "C" fn ephemeral_statement_with_instance_metadata() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    metadata_door(&SLOT, true, false)
}

fn open_metadata_store(door: DoorFn, settings: &[u8]) -> LoadedStore {
    use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, LinkedRow, NoSink};
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_linked::<Store>(
        &LinkedRow::of(door).expect("the Store declaration validates"),
        Bind {
            instance: "store-durability-metadata".into(),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the actual Store operations load");
    LoadedStore::open(plugin, dispatcher, settings, crate::actual_store::mint)
        .expect("the actual SQLite Store opens")
}

#[test]
fn fixed_store_durability_uses_the_retained_statement_when_open_metadata_is_absent() {
    for (door, expected) in [(static_durable as DoorFn, false), (static_ephemeral, true)] {
        let store = open_metadata_store(door, &crate::actual_store::settings());
        assert_eq!(store.ephemeral, None, "no per-open durability was supplied");
        assert_eq!(store.facts.ephemeral, expected);
        assert_eq!(StoreCalls::ephemeral(&store), Some(expected));
        RecordStore::add_denylist(&store, "durability-check", "test").unwrap();
        assert_eq!(
            RecordStore::list_denylist(&store).unwrap(),
            ["durability-check"]
        );
    }
}

#[test]
fn opened_instance_durability_overrides_the_statement_in_both_directions() {
    let memory = open_metadata_store(crate::actual_store::door, br#"{"db_path":":memory:"}"#);
    assert!(!memory.facts.ephemeral);
    assert_eq!(memory.ephemeral, Some(true));
    assert_eq!(StoreCalls::ephemeral(&memory), Some(true));

    let durable = open_metadata_store(
        ephemeral_statement_with_instance_metadata,
        &crate::actual_store::settings(),
    );
    assert!(durable.facts.ephemeral);
    assert_eq!(durable.ephemeral, Some(false));
    assert_eq!(StoreCalls::ephemeral(&durable), Some(false));
}
