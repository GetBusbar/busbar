// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::transport::TransportSettings;

use crate::root::linked::linked_transport;
use crate::root::registry::{compose, Dropped};
use busbar_core_connector::doors::{row_facts, stated_row, RowFacts};

use busbar_test_kit::root_door_fixtures::{layered, misnamed};

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

    let layered = linked_transport!(layered::door);
    assert_eq!((layered.key)(), "door-root-layered");
    assert_eq!((layered.composes_over)(), ["door-root-under"]);
    assert!(
        !row_facts(layered::door).session,
        "its claim row carries no session"
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
    let refused = stated_row(misnamed::door).expect_err("a misnamed door is refused");
    assert!(
        refused.contains("`door-root-named`") && refused.contains("`door-root-claimed`"),
        "the refusal names both spellings: {refused}"
    );
    let row = linked_transport!(misnamed::door);
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
