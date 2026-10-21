// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DOOR-ROOT ROW OF EVERY KIND states, off its door's Statement, what its crate's transitional
//! items state today (status row 195). The subjects are this build's own linked doors, one per axis,
//! read as a door-root row reads them: by the door alone. Each fact a door-root row reads is held
//! against the constant the same crate's transitional row reads (its `STORE`, its `NAME` and
//! `ALIAS`, its `declares` document), never against itself, so a crate converging on door-root
//! registers exactly as it registered before. RED: a door whose Statement is not the kind its row's
//! axis registers, is not named as its row names it, or sits on an axis no door-root row may name,
//! refuses the boot, naming both; and a crate the loader does not link is refused in the loader's
//! words.

use std::sync::OnceLock;

use busbar_contract::abi::mechanism::door::DoorFn;

use super::{check, check_statements, read, store_row, DoorRoot, Stated};

/// The cells the rows below read their doors into, one per row: a test owns its own range.
static CELLS: [OnceLock<Stated>; 64] = [const { OnceLock::new() }; 64];

/// A door-root row of `door` on `axis`, read into cell `at`, stating `name` where its axis names
/// one.
fn row(at: usize, axis: &'static str, door: DoorFn, name: Option<&'static str>) -> DoorRoot {
    DoorRoot {
        row: "door-root-subject",
        axis,
        door,
        facts: &CELLS[at],
        name,
    }
}

/// The JSON `text` states.
fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("a declares document is JSON")
}

/// GREEN: A DOOR-ROOT STORE ROW states what its crate's `STORE` states: its key (its Statement name)
/// and whether it is ephemeral (`MARK_EPHEMERAL`); its canonical name is its row's. The default
/// store is a required dependency, so every build links one.
#[test]
fn a_door_root_store_row_states_what_its_store_constant_states() {
    let &(key, ephemeral, door, canonical) = crate::LINKED
        .stores
        .first()
        .expect("every build links its default store");
    assert_eq!(
        check_statements(&[row(0, "stores", door, Some(key))]),
        Ok(())
    );
    let (read_key, read_ephemeral, _, read_canonical) = store_row(&CELLS[1], door, canonical);
    assert_eq!(
        (read_key, read_ephemeral, read_canonical),
        (key, ephemeral, canonical),
        "the Statement states the key and the ephemeral mark the crate's STORE states"
    );
}

/// GREEN: EVERY LINKED SECRET AND PLANE DOOR whose crate states a `declares` document by constant
/// (`linked-declares`): where its door's Statement states one too, the two are the same JSON; a
/// door-root row reads only the Statement's. Every door-root row on either axis states one wherever
/// its axis reads it.
#[test]
fn a_door_root_declares_is_the_document_its_crate_declares() {
    let pairs: Vec<(DoorFn, &str)> = crate::LINKED
        .secret_declares
        .iter()
        .copied()
        .chain(
            crate::LINKED
                .plane_door_declares
                .iter()
                .map(|(_, door, text)| (*door, *text)),
        )
        .collect();
    assert!(
        !pairs.is_empty(),
        "the build links a door with a declared document"
    );
    for (door, constant) in pairs {
        let stated = read(door).expect("the door states itself");
        if let Some(document) = &stated.declares {
            assert_eq!(
                json(document),
                json(constant),
                "`{}` states another `declares` than its crate's constant",
                stated.name
            );
        }
    }
    for root in crate::LINKED
        .door_roots
        .iter()
        .filter(|r| r.axis == "secret-doors" || r.axis == "plane-door")
    {
        let stated = root.stated().expect("a door-root door states itself");
        if let Some(document) = &stated.declares {
            json(document);
        }
    }
}

/// GREEN: A DOOR-ROOT TRANSPORT ROW: its door states the transport kind, and its own claim as its
/// name, which is the key the connector's table holds. Every build links a transport door.
#[test]
fn a_door_root_transport_row_boots_off_its_door() {
    let (key, door) = *crate::LINKED_TRANSPORT_DOORS
        .first()
        .expect("every build links a transport door");
    assert_eq!(check_statements(&[row(2, "transport", door, None)]), Ok(()));
    assert_eq!(read(door).expect("it states itself").name, key);
}

/// GREEN: A DOOR-ROOT AUTH ROW: its door states the auth kind and is named as its row's canonical
/// name (`linked-canonical`, else its key), the name its signed tarball's manifest states.
#[cfg(linked_axis_auths)]
#[test]
fn a_door_root_auth_row_is_named_its_canonical_name() {
    let rows: Vec<DoorRoot> = crate::LINKED
        .auths
        .iter()
        .enumerate()
        .map(|(n, (_, canonical, door))| row(8 + n, "auths", *door, Some(*canonical)))
        .collect();
    assert!(!rows.is_empty(), "the auth axis is linked");
    assert!(rows.len() <= 8, "the auth rows fit their cells");
    assert_eq!(check_statements(&rows), Ok(()));
}

/// GREEN: A DOOR-ROOT EXPORT ROW states what its crate's `NAME`, `ALIAS` and `DECLARES` state: its
/// Statement's name, its ONE `REWRITE_ALIAS`, and, where it states a `declares` document, the same
/// JSON as the constant.
#[cfg(linked_axis_export_doors)]
#[test]
fn a_door_root_export_row_states_what_its_constants_state() {
    for linked in crate::LINKED.export_doors.iter() {
        let stated = read(linked.door).expect("it states itself");
        assert_eq!(
            (stated.name.as_str(), stated.aliases.as_slice()),
            (linked.name, [linked.alias.to_owned()].as_slice()),
            "the Statement states the name and the one alias the crate's constants state"
        );
        if let Some(document) = &stated.declares {
            assert_eq!(json(document), json(linked.declares), "`{}`", linked.name);
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
        .enumerate()
        .map(|(n, door)| row(16 + n, "hooks", *door, None))
        .collect();
    assert!(!rows.is_empty(), "the hook axis is linked");
    assert!(rows.len() <= 8, "the hook rows fit their cells");
    assert_eq!(check_statements(&rows), Ok(()));
}

/// GREEN: A DOOR-ROOT PLANE DOOR ROW reads its door alone.
#[cfg(linked_axis_plane_door)]
#[test]
fn a_door_root_plane_door_row_boots_off_its_door() {
    let rows: Vec<DoorRoot> = crate::LINKED
        .plane_doors
        .iter()
        .enumerate()
        .map(|(n, door)| row(24 + n, "plane-door", *door, None))
        .collect();
    assert!(!rows.is_empty(), "the plane door axis is linked");
    assert!(rows.len() <= 8, "the plane door rows fit their cells");
    assert_eq!(check_statements(&rows), Ok(()));
}

/// GREEN: THIS BUILD'S OWN DOOR-ROOT ROWS boot: each crate's door admitted by the loader
/// (`open_linked`, the `dlopen` path's checks) and its Statement agreeing with its row.
#[test]
fn this_builds_door_root_rows_are_admitted_and_agree_with_their_rows() {
    let rows = crate::LINKED.door_roots;
    assert!(!rows.is_empty(), "this build links a door-root crate");
    assert_eq!(check(rows), Ok(()));
    for root in rows {
        assert!(
            crate::root::loader::linked::linked().contains(&root.row),
            "`{}` is linked through the loader's door-root table",
            root.row
        );
    }
}

/// RED: A DOOR WHOSE STATEMENT IS NOT ITS AXIS'S KIND refuses the boot: a secret source's door on
/// the store axis is refused, naming the axis and both kinds.
#[test]
fn a_door_on_another_kinds_axis_is_refused() {
    let door = crate::LINKED.secrets[0];
    let refused =
        check_statements(&[row(32, "stores", door, None)]).expect_err("a secret door is no store");
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
    let refused = check_statements(&[row(33, "stores", door, Some("door-root-not-its-name"))])
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
    let refused =
        check_statements(&[row(34, "protocols", door, None)]).expect_err("no door-root axis");
    assert!(refused.contains("`protocols`"), "{refused}");
}

/// RED: A ROW NAMING A CRATE THE LOADER DOES NOT LINK is refused at boot with the loader's words.
#[test]
fn a_door_root_row_the_loader_does_not_link_is_refused() {
    let refused = check(&[DoorRoot {
        row: "door-root-not-linked",
        ..row(35, "secret-doors", crate::LINKED.secrets[0], None)
    }])
    .expect_err("the loader links no such crate");
    assert!(
        refused.contains("plugin 'door-root-not-linked'") && refused.contains("no door-root crate"),
        "{refused}"
    );
}
