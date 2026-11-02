// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::transport::TransportSettings;

use crate::root::linked::linked_transport;
use crate::root::registry::{compose, Dropped};
use busbar_core_connector::doors::{row_facts, stated_row, RowFacts};

#[allow(unsafe_code)]
extern "C" fn misnamed_tcp() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    use busbar_contract::abi::sdk::door::abi_str;

    let actual = busbar_transport_tcp::door();
    // SAFETY: the actual linked TCP product owns this immutable, process-lifetime Statement.
    let statement = unsafe { *actual.statement() };
    let statement = Box::leak(Box::new(Statement {
        name: abi_str("tcp-misnamed"),
        ..statement
    }));
    let mut parts = actual.parts();
    parts.statement = statement;
    // SAFETY: only the name's valid static string changes. Every list, tail and operation
    // pointer remains the actual TCP product's process-lifetime data and implementation.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(parts).__with_migrate(actual.migrate())
    }))
}

#[test]
fn a_door_root_row_links_with_the_key_layers_and_session_its_statement_states() {
    let row = linked_transport!(busbar_transport_tcp::door);
    assert_eq!((row.key)(), "tcp", "the key is the door's own claim");
    assert!(
        (row.composes_over)().is_empty(),
        "the layers are the tail's: none"
    );
    assert_eq!(
        row_facts(busbar_transport_tcp::door),
        RowFacts {
            key: "tcp",
            composes_over: Vec::new(),
            session: true,
        },
        "the session is the claim row's"
    );
    let built = compose(&[row], Dropped::NONE, &TransportSettings::default())
        .expect("the door-root row composes");
    let keys: Vec<&str> = built.iter().map(|(r, _)| r.key).collect();
    assert_eq!(keys, ["tcp"], "the fold registers it under its key");
    assert_eq!(
        built[0].1.key(),
        "tcp",
        "the boot's admission of its door answers the same key"
    );

    let framer = linked_transport!(busbar_transport_http::door::door);
    let stated = row_facts(busbar_transport_http::door::door);
    assert_eq!((framer.key)(), "http");
    assert_eq!((framer.composes_over)(), stated.composes_over);
    assert!(!stated.session, "the actual HTTP claim carries no session");
    let built = compose(&[row, framer], Dropped::NONE, &TransportSettings::default())
        .expect("the actual carrier and framer compose");
    assert!(built
        .iter()
        .any(|(registered, wire)| registered.key == "tcp" && wire.key() == "tcp"));
    assert!(built
        .iter()
        .any(|(registered, wire)| registered.key == "http" && wire.key() == "http"));
}

#[test]
fn a_door_whose_own_claim_is_not_its_statement_name_is_refused_at_boot() {
    let actual = busbar_transport_tcp::door();
    let mutated = misnamed_tcp();
    assert_eq!(stated_row(busbar_transport_tcp::door).unwrap().key, "tcp");
    let original = actual.parts();
    let restated = mutated.parts();
    assert_eq!(restated.magic, original.magic);
    assert_eq!(restated.mechanism_version, original.mechanism_version);
    assert_eq!(restated.size, original.size);
    assert_eq!(restated.kind, original.kind);
    assert_eq!(restated.kind_abi, original.kind_abi);
    assert_eq!(restated.ops, original.ops);
    assert_eq!(
        restated.ready.map(|op| op as usize),
        original.ready.map(|op| op as usize)
    );
    assert_eq!(restated.layout, original.layout);
    assert_eq!(
        mutated.migrate().map(|op| op as usize),
        actual.migrate().map(|op| op as usize)
    );
    let mut original = busbar_contract::abi::mechanism::rendering::read(
        &crate::root::loader::dispatch::rendering_of(busbar_transport_tcp::door).unwrap(),
    )
    .unwrap();
    original.name = "tcp-misnamed".into();
    let restated = busbar_contract::abi::mechanism::rendering::read(
        &crate::root::loader::dispatch::rendering_of(misnamed_tcp).unwrap(),
    )
    .unwrap();
    assert_eq!(
        restated, original,
        "only the real TCP product's name is faulted"
    );
    let refused = stated_row(misnamed_tcp).expect_err("a misnamed door is refused");
    assert!(
        refused.contains("`tcp-misnamed`") && refused.contains("`tcp`"),
        "the refusal names both spellings: {refused}"
    );
    let row = linked_transport!(misnamed_tcp);
    let boot = std::panic::catch_unwind(|| {
        compose(&[row], Dropped::NONE, &TransportSettings::default()).map(|built| built.len())
    })
    .expect_err("the boot is refused");
    let said = boot
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| boot.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default();
    assert!(
        said.contains("a linked transport door is refused") && said.contains(&refused),
        "the boot refusal is the reader's: {said}"
    );
}

#[test]
fn every_linked_transport_row_is_keyed_by_its_doors_statement() {
    let stated: Vec<RowFacts> = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .map(|(key, door)| {
            let stated = stated_row(*door).unwrap_or_else(|e| panic!("`{key}`: {e}"));
            assert_eq!(
                stated.key, *key,
                "the connector keys `{key}` by its door's Statement"
            );
            stated
        })
        .collect();
    let rows: Vec<(&str, Vec<&str>)> = crate::LINKED
        .transports
        .iter()
        .map(|t| ((t.key)(), (t.composes_over)().to_vec()))
        .collect();
    assert_eq!(
        stated
            .into_iter()
            .map(|f| (f.key, f.composes_over))
            .collect::<Vec<_>>(),
        rows,
        "each linked row is keyed and layered by its door's Statement"
    );
}
