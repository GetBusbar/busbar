// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR-ROOT ROWS (status row 195; `BUSBAR-1.6.0.md` Part 4 A.1, l.3560: every kind's logic
//! crate has `fn door()` as its only public item; l.3561: a linked row holds the same `door` pointer
//! and reaches the same `'static` table a dropped-in copy does).
//!
//! A linked row is DOOR-ROOT when the manifest's `[package.metadata.busbar.door-root]` table names
//! its crate's `door` (`src/linked_gen.rs`): the generated table reads that `door` and nothing else
//! of the crate's, and every fact the row's axis needs is read here, off the door's Statement (A.2,
//! l.3564-3577), by the loader's one validation ([`LinkedRow::of`]) and the one rendering reader
//! (`rendering::read`), the reader a dropped-in copy's signed Statement is read by:
//!
//! * every row: its kind, which must be its axis's kind;
//! * a transport row: its key, layers and session (`crate::root::doors::row_facts`);
//! * an auth row: its Statement name, which must be the canonical name the manifest states for it;
//! * a store row: its key (its name, or the name the manifest states, which must be its name) and
//!   whether it is ephemeral (`MARK_EPHEMERAL`);
//! * an export row: its name and its alias (its `REWRITE_ALIAS`), and its `declares`;
//! * a secret or plane door row: its `declares` (`EXT_DECLARES`, #1399).
//!
//! A row whose crate is not in the table is TRANSITIONAL: it keeps the reads it has today (its
//! `linked` items), so a fleet that has not converged on door-root still links. The transitional arm
//! exists only for that convergence; it is no home for a kernel-typed item (Part 2 #2: a plugin talks
//! only over the ABI), and a door-root row may name no axis that reads one (`src/linked_gen.rs`
//! refuses it). Its removal is row 195's last step.
//!
//! [`LinkedRow::of`]: crate::root::loader::dispatch::LinkedRow::of

use std::sync::{Mutex, PoisonError};

use busbar_contract::abi::mechanism::door::{DoorFn, MARK_EPHEMERAL, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::KindCode;

use crate::root::linked::LinkedDoorExport;

/// What a door-root row's door states, read once off its Statement and held for the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stated {
    /// Its kind's number (`KindCode`).
    pub kind: u32,
    /// Its Statement name.
    pub name: &'static str,
    /// The other names config may call it by (its `REWRITE_ALIAS` rewrites), in order.
    pub aliases: Vec<&'static str>,
    /// Whether what it holds is lost on restart (`MARK_EPHEMERAL`).
    pub ephemeral: bool,
    /// The `declares` document its extensions state (`EXT_DECLARES`); `None` when they state none.
    pub declares: Option<&'static str>,
}

/// Every door read so far, by its address: a door is read once, and what it states is held for the
/// process (a linked door's Statement is `'static`; so is what is read off it).
static READ: Mutex<Vec<(usize, &'static Stated)>> = Mutex::new(Vec::new());

/// What `door` states.
///
/// # Errors
///
/// The loader refuses the door or its Statement, its rendering does not read back, or its
/// `declares` document is not UTF-8.
pub fn stated(door: DoorFn) -> Result<&'static Stated, String> {
    let at = door as usize;
    if let Some((_, stated)) = READ
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .find(|(a, _)| *a == at)
    {
        return Ok(stated);
    }
    let row = crate::root::loader::dispatch::LinkedRow::of(door).map_err(|e| e.to_string())?;
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).map_err(|e| {
        format!(
            "its Statement rendering does not read back at byte {}",
            e.at
        )
    })?;
    let declares = busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes)
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .map(|text| &*Box::leak(text.to_owned().into_boxed_str()))
                .map_err(|_| format!("`{}`'s `declares` document is not UTF-8", read.name))
        })
        .transpose()?;
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let stated: &'static Stated = Box::leak(Box::new(Stated {
        kind: read.kind,
        aliases: read
            .rewrites
            .into_iter()
            .filter(|(class, _, _)| *class == REWRITE_ALIAS)
            .map(|(_, from, _)| leak(from))
            .collect(),
        ephemeral: read.marks & MARK_EPHEMERAL != 0,
        declares,
        name: leak(read.name),
    }));
    let mut held = READ.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, first)) = held.iter().find(|(a, _)| *a == at) {
        return Ok(first);
    }
    held.push((at, stated));
    Ok(stated)
}

/// What `door` states, as a boot reads it.
///
/// # Panics
///
/// The build's own door is refused ([`stated`]): the binary was built with a broken plugin, which
/// no configuration can repair, so the boot is refused.
#[must_use]
pub fn stated_or_refused(door: DoorFn) -> &'static Stated {
    stated(door).unwrap_or_else(|e| panic!("a linked door is refused: {e}"))
}

/// ONE DOOR-ROOT ROW, as the generated table states it: the manifest row, the axis it registers on,
/// its door, and the name the manifest states for it where its axis names one (an auth row's
/// canonical name, a store's key), which its Statement must state.
#[derive(Debug, Clone, Copy)]
pub struct DoorRoot {
    /// The manifest row (its crate, as every refusal names it).
    pub row: &'static str,
    /// The axis it registers on (`linked-axes`).
    pub axis: &'static str,
    /// Its door.
    pub door: DoorFn,
    /// The name the manifest states for it, which its Statement must state.
    pub name: Option<&'static str>,
}

/// The kind each door-root axis registers.
fn kind_of(axis: &str) -> Option<KindCode> {
    Some(match axis {
        "transport" | "transport-door" | "connector-door" => KindCode::Transport,
        "plane-door" => KindCode::Plane,
        "secret-doors" => KindCode::Secret,
        "auths" => KindCode::Auth,
        "export-doors" => KindCode::Export,
        "stores" => KindCode::Store,
        "hooks" => KindCode::Hook,
        _ => return None,
    })
}

/// THE BOOT'S CHECK OF EVERY DOOR-ROOT ROW: each door's Statement is read, and it must be the kind
/// its axis registers, state the name its row states, and state what its axis reads (a transport
/// its own claim as its name, an export its alias).
///
/// # Errors
///
/// The first row whose door is refused or whose Statement disagrees with its row, naming both.
pub fn check(rows: &[DoorRoot]) -> Result<(), String> {
    for row in rows {
        let stated = stated(row.door).map_err(|e| format!("plugin '{}': {e}", row.row))?;
        let want = kind_of(row.axis).ok_or_else(|| {
            format!(
                "plugin '{}': `{}` is no axis a door-root row registers on",
                row.row, row.axis
            )
        })?;
        if stated.kind != want as u32 {
            return Err(format!(
                "plugin '{}': its row registers it on the `{}` axis (kind {}), but its door's \
                 Statement states kind {}",
                row.row, row.axis, want as u32, stated.kind
            ));
        }
        if let Some(name) = row.name {
            if stated.name != name {
                return Err(format!(
                    "plugin '{}': its row names it `{name}`, but its door's Statement is named `{}`",
                    row.row, stated.name
                ));
            }
        }
        match want {
            KindCode::Transport => {
                crate::root::doors::stated_row(row.door)
                    .map_err(|e| format!("plugin '{}': {e}", row.row))?;
            }
            KindCode::Export if stated.aliases.is_empty() => {
                return Err(format!(
                    "plugin '{}': its door's Statement states no alias (`REWRITE_ALIAS`), the \
                     module name an `export:` instance names it by",
                    row.row
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The `(row, door, declares)` of every door-root row on `axis` whose door states a `declares`
/// document: what the transitional arm reads off a `linked-declares` row, read off the Statement.
#[must_use]
pub fn declared(rows: &[DoorRoot], axis: &str) -> Vec<(&'static str, DoorFn, &'static str)> {
    rows.iter()
        .filter(|row| row.axis == axis)
        .filter_map(|row| {
            stated_or_refused(row.door)
                .declares
                .map(|json| (row.row, row.door, json))
        })
        .collect()
}

/// A door-root STORE row: its key (its Statement name), whether it is ephemeral, its door, and the
/// canonical name its row states (`linked-canonical`, else its crate's package name).
#[must_use]
pub fn store_row(door: DoorFn, canonical: &'static str) -> busbar_kernel::preflight::LinkedStore {
    let stated = stated_or_refused(door);
    (stated.name, stated.ephemeral, door, canonical)
}

/// A door-root EXPORT row: its name, its alias (its first `REWRITE_ALIAS`) and its `declares`
/// (`{}` when it states none), each its Statement's, and its door.
///
/// # Panics
///
/// The door is refused, or states no alias ([`check`] refuses the boot on either first).
#[must_use]
pub fn export_row(door: DoorFn) -> LinkedDoorExport {
    let stated = stated_or_refused(door);
    LinkedDoorExport {
        name: stated.name,
        alias: stated.aliases.first().copied().unwrap_or_else(|| {
            panic!(
                "a linked door is refused: `{}` states no alias",
                stated.name
            )
        }),
        declares: stated.declares.unwrap_or("{}"),
        door,
    }
}

#[cfg(test)]
#[path = "tests/door_root.rs"]
mod tests;
