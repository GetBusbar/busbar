// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DOOR-ROOT ROW OF EVERY KIND boots with the facts its door's Statement states (status row 195).
//! The subjects are this build's own linked doors, one per axis, each read as a door-root row reads
//! it: by its `door` alone, every fact off its Statement. Where the build links the same crate as a
//! TRANSITIONAL row (its `linked` items), the door-root reading states the same facts its items do,
//! so a crate converging on door-root registers exactly as it registered before. RED: a door whose
//! Statement is not the kind its row's axis registers, or is not named as its row names it, refuses
//! the boot, naming both.

use busbar_contract::abi::mechanism::door::DoorFn;

use super::{check, declared, stated, store_row, DoorRoot};

/// A door-root row of `door` on `axis`, stating `name` for it where its axis names one.
fn row(axis: &'static str, door: DoorFn, name: Option<&'static str>) -> DoorRoot {
    DoorRoot {
        row: "door-root-subject",
        axis,
        door,
        name,
    }
}

/// GREEN: A DOOR-ROOT STORE ROW is the row its crate's `STORE` states: its key (its Statement name),
/// whether it is ephemeral (`MARK_EPHEMERAL`), its door, and its canonical name. The default store
/// is a required dependency, so every build links one.
#[test]
fn a_door_root_store_row_states_what_its_store_constant_states() {
    let &(key, ephemeral, door, canonical) = crate::LINKED
        .stores
        .first()
        .expect("every build links its default store");
    assert_eq!(
        check(&[row("stores", door, Some(key))]),
        Ok(()),
        "the store's door states itself a store, named its key"
    );
    let (read_key, read_ephemeral, _, read_canonical) = store_row(door, canonical);
    assert_eq!(
        (read_key, read_ephemeral, read_canonical),
        (key, ephemeral, canonical),
        "the Statement states the key and the ephemeral mark the crate's STORE states"
    );
}

/// GREEN: A DOOR-ROOT SECRET ROW reads its door alone; its `declares`, where its Statement states
/// one, is what the secret axis is handed beside it. The env and file sources are required
/// dependencies, so every build links them.
#[test]
fn a_door_root_secret_row_boots_off_its_door() {
    let doors = crate::LINKED.secrets;
    assert!(!doors.is_empty(), "every build links its secret sources");
    let rows: Vec<DoorRoot> = doors
        .iter()
        .map(|door| row("secret-doors", *door, None))
        .collect();
    assert_eq!(check(&rows), Ok(()));
    for (_, door, json) in declared(&rows, "secret-doors") {
        assert_eq!(
            stated(door).expect("it states itself").declares,
            Some(json),
            "the declares handed beside a door is the one its Statement states"
        );
        serde_json::from_str::<serde_json::Value>(json).expect("a declares document is JSON");
    }
}

/// GREEN: A DOOR-ROOT TRANSPORT ROW: its door states the transport kind, and its own claim as its
/// name. Every build links a transport door.
#[test]
fn a_door_root_transport_row_boots_off_its_door() {
    let (key, door) = *crate::LINKED_TRANSPORT_DOORS
        .first()
        .expect("every build links a transport door");
    assert_eq!(check(&[row("transport", door, None)]), Ok(()));
    assert_eq!(stated(door).expect("it states itself").name, key);
}

/// GREEN: A DOOR-ROOT AUTH ROW: its door states the auth kind and is named as its row's canonical
/// name (`linked-canonical`, else its key), the name its signed tarball's manifest states.
#[cfg(linked_axis_auths)]
#[test]
fn a_door_root_auth_row_is_named_its_canonical_name() {
    let rows: Vec<DoorRoot> = crate::LINKED
        .auths
        .iter()
        .map(|(_, canonical, door)| row("auths", *door, Some(*canonical)))
        .collect();
    assert!(!rows.is_empty(), "the auth axis is linked");
    assert_eq!(check(&rows), Ok(()));
}

/// GREEN: A DOOR-ROOT EXPORT ROW is the row its crate's `NAME` and `ALIAS` state: its Statement's
/// name and its first `REWRITE_ALIAS`; its `declares`, where its Statement states one, is its own.
#[cfg(linked_axis_export_doors)]
#[test]
fn a_door_root_export_row_states_what_its_constants_state() {
    for linked in crate::LINKED.export_doors.iter() {
        assert_eq!(check(&[row("export-doors", linked.door, None)]), Ok(()));
        let read = super::export_row(linked.door);
        assert_eq!(
            (read.name, read.alias),
            (linked.name, linked.alias),
            "the Statement states the name and alias the crate's constants state"
        );
        if let Some(json) = stated(linked.door).expect("it states itself").declares {
            assert_eq!(read.declares, json);
        }
    }
}

/// GREEN: A DOOR-ROOT HOOK ROW reads its door alone.
#[cfg(linked_axis_hooks)]
#[test]
fn a_door_root_hook_row_boots_off_its_door() {
    let rows: Vec<DoorRoot> = crate::LINKED
        .hook_doors
        .iter()
        .map(|door| row("hooks", *door, None))
        .collect();
    assert!(!rows.is_empty(), "the hook axis is linked");
    assert_eq!(check(&rows), Ok(()));
}

/// GREEN: A DOOR-ROOT PLANE DOOR ROW reads its door alone; its `declares`, where its Statement
/// states one, joins the plane doors' declared metadata (`root::linked::plane_door_declares`).
#[cfg(linked_axis_plane_door)]
#[test]
fn a_door_root_plane_door_row_boots_off_its_door() {
    let rows: Vec<DoorRoot> = crate::LINKED
        .plane_doors
        .iter()
        .map(|door| row("plane-door", *door, None))
        .collect();
    assert!(!rows.is_empty(), "the plane door axis is linked");
    assert_eq!(check(&rows), Ok(()));
    for (_, door, json) in declared(&rows, "plane-door") {
        assert_eq!(stated(door).expect("it states itself").declares, Some(json));
    }
}

/// RED: A DOOR WHOSE STATEMENT IS NOT ITS AXIS'S KIND refuses the boot: a secret source's door on
/// the store axis is refused, naming the axis and both kinds.
#[test]
fn a_door_on_another_kinds_axis_is_refused() {
    let door = crate::LINKED.secrets[0];
    let refused = check(&[row("stores", door, None)]).expect_err("a secret door is no store");
    assert!(
        refused.contains("`stores`") && refused.contains("kind 1") && refused.contains("kind 2"),
        "{refused}"
    );
}

/// RED: A DOOR NOT NAMED AS ITS ROW NAMES IT refuses the boot: a store row naming a key its door's
/// Statement does not state is refused, naming both.
#[test]
fn a_door_named_otherwise_than_its_row_is_refused() {
    let door = crate::LINKED.stores[0].2;
    let refused = check(&[row("stores", door, Some("door-root-not-its-name"))])
        .expect_err("the row and the Statement disagree");
    assert!(
        refused.contains("`door-root-not-its-name`")
            && refused.contains(&format!("`{}`", crate::LINKED.stores[0].0)),
        "{refused}"
    );
}

/// RED: A ROW ON AN AXIS NO DOOR-ROOT ROW REGISTERS ON is refused (the generator refuses it first,
/// `linked_gen::check_door_root`; this is the boot's own guard).
#[test]
fn a_door_root_row_on_a_kernel_typed_axis_is_refused() {
    let door = crate::LINKED.secrets[0];
    let refused = check(&[row("protocols", door, None)]).expect_err("no door-root axis");
    assert!(refused.contains("`protocols`"), "{refused}");
}
