// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A LINKED ROW STATES IS READ OFF ITS DOOR (BUSBAR-1.6.0.md, the door-only gate: a linked row
//! names its crate's `door` and nothing else; ARCHITECT ruling: the root reads `declares`, alias
//! and the rest off the door's Statement). A store row's key and `ephemeral`, an export row's name
//! and alias, and every door's `declares` section come off the door; a `linked-declares` or
//! `linked-alias` row answers only for a door that does not state its own yet.

use super::*;

/// EVERY `linked-declares` AND `linked-alias` ROW NAMES A DOOR THAT STATES NONE: a door that states
/// its `declares` (`EXT_DECLARES`) or its module alias (`REWRITE_ALIAS`) is read off its Statement
/// and never off its row, so a row left beside it is a second spelling of one fact. RED: a row
/// naming the fallback plane's `DECLARES` again, whose door states its own.
#[test]
fn every_declares_and_alias_row_names_a_door_that_states_none() {
    let states_none = |door, what: &str| {
        let read = stated(door).expect("a linked door states itself");
        let declares = stated_declares(&read).expect("its `declares` reads");
        assert!(
            declares.is_none(),
            "linked {what} '{}' states its own `declares` on its Statement: drop its \
             `linked-declares` row",
            read.name
        );
        read
    };
    for (door, _) in crate::LINKED.secret_declares {
        states_none(*door, "secret");
    }
    for (_, door, _) in crate::LINKED.plane_door_declares {
        states_none(*door, "plane");
    }
    for d in crate::LINKED.export_doors {
        let read = stated(d.door).expect("a linked export door states itself");
        if d.declares.is_some() {
            states_none(d.door, "export");
        }
        assert!(
            d.alias.is_none() || stated_alias(&read).is_none(),
            "linked export '{}' states its own module alias: drop its `linked-alias` row",
            read.name
        );
    }
}

/// A DOOR THAT STATES ITS `declares` IS READ OFF ITS STATEMENT, NOT A ROW: the fallback plane's
/// door states its section (`EXT_DECLARES`), so the root reads exactly that section for it, and a
/// planted `linked-declares` row for the same door is not read. RED: a root that reads only the
/// rows (the plane's catalogue codes leave the catalogue once its row is dropped).
#[cfg(linked_section_pools)]
#[test]
fn a_plane_door_stating_its_declares_is_read_off_its_statement() {
    let (door, read) = crate::LINKED
        .plane_doors
        .iter()
        .map(|door| {
            (
                *door,
                stated(*door).expect("a linked plane door states itself"),
            )
        })
        .find(|(_, read)| read.sections.iter().any(|(name, _)| name == "pools"))
        .expect("the plane that declares `pools` is linked");
    let own = stated_declares(&read)
        .expect("its `declares` reads")
        .expect("the door states its `declares` section");
    serde_json::from_str::<serde_json::Value>(&own).expect("the stated section is JSON");
    let planted = Linked {
        plane_door_declares: vec![("planted-row", door, r#"{"planted":true}"#)].leak(),
        ..crate::LINKED
    };
    let read_back = plane_declares(&planted).expect("the linked plane doors state");
    let row = read_back
        .iter()
        .find(|d| d.name == read.name)
        .expect("the door's section is read");
    assert_eq!(
        row.json, own,
        "the Statement's section, never the planted row's"
    );
    assert_eq!(row.plugin, read.name, "named by its Statement");
}

/// THE STORE ROW IS READ OFF ITS DOOR: its key is the door's Statement `name` and its `ephemeral` the
/// Statement's `MARK_EPHEMERAL`, and its canonical name is its packaging row's (its key when it has
/// none). The linked memory store answers the key a migrated 1.5.x config names, ephemeral, under
/// its canonical name.
#[test]
fn the_linked_store_row_is_read_off_its_door() {
    let doors = crate::LINKED.stores.doors();
    let rows = linked_stores(doors).expect("the linked stores state");
    assert_eq!(rows.len(), doors.len(), "one row per door");
    let named = |rows: &[busbar_kernel::preflight::LinkedStore]| -> Vec<(String, bool, String)> {
        let row =
            |r: &busbar_kernel::preflight::LinkedStore| (r.0.to_string(), r.1, r.3.to_string());
        rows.iter().map(row).collect()
    };
    assert_eq!(
        named(&crate::LINKED.stores[..]),
        named(&rows),
        "the axis reads its rows the same way"
    );
    for (row, linked) in rows.iter().zip(doors) {
        let read = stated(linked.door).expect("a linked store states itself");
        assert_eq!(row.0, read.name, "its key is its Statement name");
        assert_eq!(
            row.1,
            read.marks & busbar_contract::abi::mechanism::door::MARK_EPHEMERAL != 0,
            "its `ephemeral` is its Statement's mark"
        );
        assert_eq!(row.3, linked.canonical.unwrap_or(row.0));
    }
    let memory = rows
        .iter()
        .find(|r| r.0 == busbar_kernel::config::sections::MIGRATED_STORE_MODULE)
        .expect("the build links the store a migrated config names");
    assert!(memory.1, "the memory store is ephemeral");
    assert_ne!(
        memory.3, memory.0,
        "its canonical name is its manifest name, not its key"
    );
}

/// AN EXPORT ROW'S ALIAS IS READ OFF ITS DOOR: a door that states `REWRITE_ALIAS` answers that alias
/// whatever its row says; a door that states none answers its row's; a door with neither is refused,
/// naming it.
#[cfg(linked_axis_export_doors)]
#[test]
fn an_export_rows_alias_is_read_off_its_door() {
    for d in crate::LINKED.export_doors {
        let read = stated(d.door).expect("a linked export door states itself");
        let planted = LinkedDoorExport {
            alias: Some("planted-alias"),
            ..*d
        };
        let bare = LinkedDoorExport { alias: None, ..*d };
        match stated_alias(&read) {
            Some(own) => {
                assert_eq!(planted.alias().as_deref(), Ok(own.as_str()));
                assert_eq!(bare.alias().as_deref(), Ok(own.as_str()));
            }
            None => {
                assert_eq!(planted.alias().as_deref(), Ok("planted-alias"));
                let refused = bare.alias().expect_err("no alias stated anywhere");
                assert!(refused.contains(&read.name), "{refused}");
            }
        }
    }
}
