// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LINKED TRANSPORT ROW IS ITS BARE `door` (coordinator ruling (b), row 159): a door-root crate's
//! only public item is `door` (`BUSBAR-1.6.0.md` A.1, l.3560), and a linked row holds that door and
//! reaches the same `'static` table a dropped-in copy does (l.3561). So the row's key, the layers it
//! composes over and whether it carries a session are read off the door's Statement (A.2,
//! l.3564-3577: the name, the claims, the kind tail), never off a constant the crate exports beside
//! `door`. The fixtures here are door-root crates in miniature: each module's only public item is
//! `door`; it exports no `KEY`, `COMPOSES_OVER` or `SESSION`.

use busbar_contract::transport::TransportSettings;

use crate::root::doors::{row_facts, stated_row, RowFacts};
use crate::root::linked::linked_transport;
use crate::root::registry::{compose, Dropped};
// The door-root crates in miniature, built in the loader's test fixtures: the root holds no door
// macro (status row 195).
use busbar_plugin_loader::root_door_fixtures::{layered, misnamed, wire};

/// GREEN: A DOOR-ROOT ROW LINKS WITH THE KEY, LAYERS AND SESSION ITS STATEMENT STATES. The row is
/// built by the macro the generated linked table expands for every `transport` row, from the bare
/// `door` and nothing else; the boot seal's fold builds it (its door admitted, opened and admitted
/// to be served) and registers it under the key the Statement states. RED without the mechanism:
/// the row would need the crate's `KEY` and `COMPOSES_OVER`, which a door-root crate does not have.
#[test]
fn a_door_root_row_links_with_the_key_layers_and_session_its_statement_states() {
    let row = linked_transport!(wire::door);
    assert_eq!(
        (row.key)(),
        "door-root-wire",
        "the key is the door's own claim"
    );
    assert!(
        (row.composes_over)().is_empty(),
        "the layers are the tail's: none"
    );
    assert_eq!(
        row_facts(wire::door),
        RowFacts {
            key: "door-root-wire",
            composes_over: Vec::new(),
            session: true,
        },
        "the session is the claim row's"
    );
    let built = compose(&[row], Dropped::NONE, &TransportSettings::default())
        .expect("the door-root row composes");
    let keys: Vec<&str> = built.iter().map(|(r, _)| r.key).collect();
    assert_eq!(
        keys,
        ["door-root-wire"],
        "the fold registers it under its key"
    );
    assert_eq!(
        built[0].1.key(),
        "door-root-wire",
        "the boot's admission of its door answers the same key"
    );

    // What a door states is read, never defaulted: a tail that names a layer, and a claim row that
    // carries no session.
    let layered = linked_transport!(layered::door);
    assert_eq!((layered.key)(), "door-root-layered");
    assert_eq!((layered.composes_over)(), ["door-root-under"]);
    assert!(
        !row_facts(layered::door).session,
        "its claim row carries no session"
    );
}

/// RED: A DOOR WHOSE OWN CLAIM IS NOT ITS STATEMENT'S NAME IS REFUSED AT BOOT. The reader refuses it
/// naming both spellings, and the boot seal's fold over a row of it does not register it: the
/// boot is refused with the reader's words.
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

/// EVERY ROW THIS BUILD LINKS, door-root or `linked`-module alike, reads its key off its door's
/// Statement through the one reader: each linked transport door states its own claim as its name,
/// and the linked table's rows are keyed and layered, in order, by what those doors state.
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
