// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Kind, LinkedRow, NoSink, Plugin,
};
use busbar_contract::abi::mechanism::{
    call::Outcome,
    door::{Door, DoorFn},
    rendering,
};
use std::sync::{Arc, OnceLock};

macro_rules! renamed {
    ($name:ident, $original:path) => {
        extern "C" fn $name() -> &'static Door {
            static SLOT: OnceLock<usize> = OnceLock::new();
            let address = *SLOT.get_or_init(|| {
                let original = $original();
                // SAFETY: the neutral SDK descriptor has static, valid metadata.
                let mut statement = unsafe { *original.statement() };
                statement.name = busbar_contract::abi::sdk::door::abi_str(concat!(
                    "substitute-",
                    stringify!($name)
                ));
                let mut parts = original.parts();
                parts.statement = Box::leak(Box::new(statement));
                // SAFETY: only the diagnostic implementation name changes; the complete
                // validated SDK operation table and all other declarations remain static.
                Box::into_raw(Box::new(unsafe { Door::__from_parts(parts) })) as usize
            });
            // SAFETY: the immutable descriptor is permanently owned by SLOT.
            unsafe { &*(address as *const Door) }
        }
    };
}
renamed!(store, crate::neutral_store::door);
renamed!(secret, crate::neutral_secret::door);
renamed!(auth, crate::neutral_auth::door);
renamed!(
    hook,
    crate::hook_door_conformance_tests::hook_door_plugin::conforming::door
);
renamed!(export, crate::neutral_export::door);
renamed!(transport, crate::neutral_transport::door);
renamed!(plane, crate::neutral_plane::door);

fn compare<K: Kind>(original: DoorFn, substitute: DoorFn, run: impl Fn(&Plugin<K>) -> Vec<String>) {
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let rows = [
        LinkedRow::of(original).unwrap(),
        LinkedRow::of(substitute).unwrap(),
    ];
    let mut declared = rendering::read(&rows[0].statement).unwrap();
    let renamed = rendering::read(&rows[1].statement).unwrap();
    assert_ne!(declared.name, renamed.name);
    declared.name.clone_from(&renamed.name);
    assert_eq!(
        declared, renamed,
        "all admitted capabilities survive implementation rename"
    );
    let load = |row: &LinkedRow| {
        load_linked::<K>(
            row,
            Bind {
                instance: Arc::from("configured-instance"),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Probe,
            },
        )
        .unwrap()
    };
    let a = load(&rows[0]);
    let b = load(&rows[1]);
    assert_ne!(a.name(), b.name());
    assert_eq!(a.kind(), b.kind());
    assert_eq!(a.max_inflight(), b.max_inflight());
    assert_eq!(a.declared_needs(), b.declared_needs());
    assert_eq!(a.secret_refs(), b.secret_refs());
    assert_eq!(a.reference_fields(), b.reference_fields());
    let (caller_a, caller_b) = (a.service_caller().unwrap(), b.service_caller().unwrap());
    assert_eq!(caller_a.namespace(), caller_b.namespace());
    assert_eq!(caller_a.kind(), caller_b.kind());
    assert!(!caller_a.same_incarnation(&caller_b));
    assert_eq!(
        run(&a),
        run(&b),
        "the renamed implementation has the same lifecycle behavior"
    );
}

fn lifecycle<K: Kind>(plugin: &Plugin<K>) -> Vec<String> {
    lifecycle_with_settings(plugin, b"{}")
}

fn lifecycle_with_settings<K: Kind>(plugin: &Plugin<K>, settings: &[u8]) -> Vec<String> {
    use crate::door_both_ways::{close, line, open};
    let opened = open(plugin, settings);
    assert_eq!(opened.outcome, Outcome::Ready);
    assert!(plugin.is_open());
    let closed = close(plugin);
    assert_eq!(closed.outcome, Outcome::Ready);
    vec![line("open", &opened), line("close", &closed)]
}

#[test]
fn renaming_neutral_implementations_preserves_every_kind_capability_and_lifecycle() {
    use crate::dispatch::kinds::{
        auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store_v4::StoreV4,
        transport::Transport,
    };
    compare::<StoreV4>(crate::neutral_store::door, store, lifecycle);
    compare::<Secret>(crate::neutral_secret::door, secret, lifecycle);
    compare::<Auth>(crate::neutral_auth::door, auth, lifecycle);
    compare::<Hook>(
        crate::hook_door_conformance_tests::hook_door_plugin::conforming::door,
        hook,
        |plugin| lifecycle_with_settings(plugin, br#"{"reject_over_messages":3}"#),
    );
    compare::<Export>(crate::neutral_export::door, export, lifecycle);
    compare::<Transport>(crate::neutral_transport::door, transport, lifecycle);
    compare::<Plane>(crate::neutral_plane::door, plane, |plugin| {
        let snapshot =
            crate::dispatch::kinds::plane::open_door(plugin, b"{}", b"{}", None).unwrap();
        assert_eq!(snapshot.generation, 1);
        assert_eq!(crate::door_both_ways::close(plugin).outcome, Outcome::Ready);
        vec![format!("{snapshot:?}")]
    });
}
