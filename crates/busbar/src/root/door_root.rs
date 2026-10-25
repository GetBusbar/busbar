// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR-ROOT ROWS (status row 195; `BUSBAR-1.6.0.md` Part 4 A.1, l.3560: every kind's logic
//! crate has `fn door()` as its only public item; l.3561: a linked row holds the same `door` pointer
//! and reaches the same `'static` table a dropped-in copy does; coordinator ruling (a), l.272-274:
//! this root is `forbid(unsafe_code)`, and the loader holds the one `unsafe` entry).
//!
//! A DOOR-ROOT crate is the one this crate's `[package.metadata.busbar.door-root]` table names
//! (ARCHITECT ruling, row 195: the root generates the linked table and alone depends on the plugin
//! crates; the loader names none). The generated table reads its `door` alone and hands it to the
//! loader's safe entry (`crate::root::loader::dispatch::admit_linked`: `open_linked`, the `dlopen`
//! path's own checks beside the loader's one reviewed `unsafe`); the tables hold a forwarder of the
//! admitted door (`src/linked_gen.rs`), and every fact a row's axis needs is read here, off that door's Statement
//! (A.2, l.3564-3577), through the loader's validation ([`LinkedRow::of`]) and the one rendering
//! reader (`rendering::read`), the reader a dropped-in copy's signed Statement is read by:
//!
//! * every row: its kind, which must be its axis's kind;
//! * a transport row: its key, layers and session (`crate::root::doors::row_facts`);
//! * an auth row: its Statement name, which must be the registry key its row states (`linked-name`);
//! * a store row: its key (its Statement name, which must be the `linked-name` its row states, if
//!   any) and whether it is ephemeral (`MARK_EPHEMERAL`); its canonical name is its row's
//!   (`linked-canonical`, else its crate's package name: the Statement has no home for it);
//! * an export row: its name, its one alias (`REWRITE_ALIAS`) and its `declares` (`EXT_DECLARES`);
//! * a secret or plane door row: its `declares` (`EXT_DECLARES`), which it must state.
//!
//! What a door states is read ONCE into its row's own `static` cell (a `OnceLock<Stated>` the
//! generated table declares beside the forwarder) and borrowed from there for the process.
//!
//! A crate not in the table is TRANSITIONAL: it keeps the reads it has today (its `linked` items),
//! so a fleet that has not converged on door-root still links. The transitional arm exists only for
//! that convergence; it is no home for a kernel-typed item (Part 2 #2), and a door-root row may name
//! no axis that reads one (`src/linked_gen.rs` refuses it). Its removal is row 195's last step.
//!
//! [`LinkedRow::of`]: crate::root::loader::dispatch::LinkedRow::of

use std::sync::OnceLock;

use busbar_contract::abi::mechanism::door::{DoorFn, MARK_EPHEMERAL, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::KindCode;

use crate::root::linked::LinkedDoorExport;

/// What a door states, as its rows read it: owned, held in its row's cell for the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stated {
    /// Its kind's number (`KindCode`).
    pub kind: u32,
    /// Its Statement name.
    pub name: String,
    /// The other names config may call it by (its `REWRITE_ALIAS` rewrites), in order.
    pub aliases: Vec<String>,
    /// Whether what it holds is lost on restart (`MARK_EPHEMERAL`).
    pub ephemeral: bool,
    /// The `declares` document its extensions state (`EXT_DECLARES`); `None` when they state none.
    pub declares: Option<String>,
}

/// What `door` states, read off its Statement.
///
/// # Errors
///
/// The loader refuses the door or its Statement, its rendering does not read back, its extensions
/// blob is not whole entries, or its `declares` document is not JSON.
pub fn read(door: DoorFn) -> Result<Stated, String> {
    let row = crate::root::loader::dispatch::LinkedRow::of(door).map_err(|e| e.to_string())?;
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).map_err(|e| {
        format!(
            "its Statement rendering does not read back at byte {}",
            e.at
        )
    })?;
    let blob = &read.extensions.bytes;
    // Every entry whole: a blob whose entries do not add up to its length is malformed, never
    // read past (a reader would stop at the cut and miss what follows).
    let whole: usize = busbar_contract::abi::mechanism::extensions::entries(blob)
        .map(|(k, v)| 2 + k.len() + 4 + v.len())
        .sum();
    if whole != blob.len() {
        return Err(format!(
            "`{}`'s Statement extensions are malformed: {} of {} bytes are whole entries",
            read.name,
            whole,
            blob.len()
        ));
    }
    let declares = busbar_contract::abi::mechanism::extensions::declares(blob)
        .map(|bytes| {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| format!("`{}`'s `declares` document is not UTF-8", read.name))?;
            serde_json::from_str::<serde_json::Value>(text)
                .map_err(|e| format!("`{}`'s `declares` document is not JSON: {e}", read.name))?;
            Ok::<_, String>(text.to_owned())
        })
        .transpose()?;
    Ok(Stated {
        kind: read.kind,
        aliases: read
            .rewrites
            .into_iter()
            .filter(|(class, _, _)| *class == REWRITE_ALIAS)
            .map(|(_, from, _)| from)
            .collect(),
        ephemeral: read.marks & MARK_EPHEMERAL != 0,
        declares,
        name: read.name,
    })
}

/// What `door` states, read once into `cell`.
///
/// # Errors
///
/// As [`read`], the first time.
pub fn stated(cell: &'static OnceLock<Stated>, door: DoorFn) -> Result<&'static Stated, String> {
    if let Some(stated) = cell.get() {
        return Ok(stated);
    }
    let read = read(door)?;
    Ok(cell.get_or_init(|| read))
}

/// [`stated`], as a boot reads it.
///
/// # Panics
///
/// The build's own door is refused: the binary was built with a broken plugin, which no
/// configuration can repair ([`check_door_roots`] refuses the boot on it first, exit 2).
#[must_use]
pub fn stated_or_refused(cell: &'static OnceLock<Stated>, door: DoorFn) -> &'static Stated {
    stated(cell, door).unwrap_or_else(|e| panic!("a linked door is refused: {e}"))
}

/// ONE DOOR-ROOT ROW, as the generated table states it: the crate, the axis it registers on, the
/// forwarder of its admitted door, its cell, and the name its row states where its axis names one
/// (an auth row's or a store's `linked-name`), which its Statement must state.
#[derive(Debug, Clone, Copy)]
pub struct DoorRoot {
    /// The crate (as the loader's table and every refusal name it).
    pub row: &'static str,
    /// The axis it registers on (`linked-axes`).
    pub axis: &'static str,
    /// Its door: the forwarder of the door the loader admitted.
    pub door: DoorFn,
    /// The cell its door's Statement is read into, once.
    pub facts: &'static OnceLock<Stated>,
    /// The loader's refusal of its door (`admit_linked`, read once), or `None`: admitted.
    pub admission: fn() -> Option<String>,
    /// The name its row states, which its Statement must state.
    pub name: Option<&'static str>,
}

impl DoorRoot {
    /// What its door states.
    ///
    /// # Errors
    ///
    /// As [`read`].
    pub fn stated(&self) -> Result<&'static Stated, String> {
        stated(self.facts, self.door)
    }
}

/// The kinds whose rows carry a `declares` document (a secret's disk need, a plane's and an
/// export's metric families, diagnostics and answers): a door-root row of one states it on its
/// Statement (`EXT_DECLARES`, #1399).
fn declares_kind(kind: KindCode) -> bool {
    matches!(kind, KindCode::Secret | KindCode::Plane | KindCode::Export)
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
        // The hook axis is spelled as the hook kind's root key, read off the one list.
        _ if axis == busbar_contract::plugin::Kind::Hook.root() => KindCode::Hook,
        _ => return None,
    })
}

/// THE BOOT'S CHECK OF EVERY DOOR-ROOT ROW (`main.rs` runs it before anything registers): its
/// crate's door admitted by the loader (`admit_linked`: `open_linked`, the `dlopen` path's checks,
/// and the same refusal word for word), then [`check_statements`].
///
/// # Errors
///
/// The first row the loader refuses, with the loader's refusal, or [`check_statements`]' refusal.
pub fn check(rows: &[DoorRoot]) -> Result<(), String> {
    for row in rows {
        if let Some(refused) = (row.admission)() {
            return Err(format!("plugin '{}': {refused}", row.row));
        }
    }
    check_statements(rows)
}

/// EACH DOOR-ROOT ROW'S DOOR AGAINST ITS ROW: each door's Statement is read, and it must be the
/// kind its axis registers, state the name its row states, and state what its axis reads (a
/// transport its own claim as its name; an export one alias and a `declares` document).
///
/// # Errors
///
/// The first row whose door is refused or whose Statement disagrees with its row, naming both.
pub fn check_statements(rows: &[DoorRoot]) -> Result<(), String> {
    for row in rows {
        let stated = row
            .stated()
            .map_err(|e| format!("plugin '{}': {e}", row.row))?;
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
            KindCode::Export if stated.aliases.len() != 1 => {
                return Err(format!(
                    "plugin '{}': its door's Statement states {} aliases (`REWRITE_ALIAS`); an \
                     export states exactly one, the module name an `export:` instance names it by",
                    row.row,
                    stated.aliases.len()
                ));
            }
            _ => {}
        }
        // A KIND THAT CARRIES A `declares` DOCUMENT states it on a door-root row's Statement, the
        // one place it is read: never read as an empty one.
        if declares_kind(want) && stated.declares.is_none() {
            return Err(format!(
                "plugin '{}': its row registers it on the `{}` axis, whose kind carries a \
                 `declares` document, but its door's Statement states none (`EXT_DECLARES`)",
                row.row, row.axis
            ));
        }
    }
    Ok(())
}

/// THE BOOT'S DOOR-ROOT STEP: [`check`] over the build's door-root rows, refusing the boot (exit 2)
/// with its words.
pub fn check_door_roots(rows: &[DoorRoot]) {
    if let Err(refusal) = check(rows) {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    }
}

/// The `(row, door, declares)` of every door-root row on `axis` whose door states a `declares`
/// document: what the transitional arm reads off a `linked-declares` row, read off the Statement.
#[must_use]
pub fn declared(rows: &[DoorRoot], axis: &str) -> Vec<(&'static str, DoorFn, &'static str)> {
    rows.iter()
        .filter(|row| row.axis == axis)
        .filter_map(|row| {
            stated_or_refused(row.facts, row.door)
                .declares
                .as_deref()
                .map(|json| (row.row, row.door, json))
        })
        .collect()
}

/// A door-root STORE row: its key (its Statement name), whether it is ephemeral, its door, and the
/// canonical name its row states (`linked-canonical`, else its crate's package name).
#[must_use]
pub fn store_row(
    facts: &'static OnceLock<Stated>,
    door: DoorFn,
    canonical: &'static str,
) -> busbar_kernel::preflight::LinkedStore {
    let stated = stated_or_refused(facts, door);
    (stated.name.as_str(), stated.ephemeral, door, canonical)
}

/// A door-root EXPORT row: its name, its one alias and its `declares`, each its Statement's, and
/// its door.
///
/// # Panics
///
/// The door is refused, or states other than one alias or no `declares` ([`check_door_roots`]
/// refuses the boot on each first).
#[must_use]
pub fn export_row(facts: &'static OnceLock<Stated>, door: DoorFn) -> LinkedDoorExport {
    let stated = stated_or_refused(facts, door);
    let [alias] = stated.aliases.as_slice() else {
        panic!(
            "a linked door is refused: `{}` states {} aliases, not one",
            stated.name,
            stated.aliases.len()
        );
    };
    LinkedDoorExport {
        name: stated.name.as_str(),
        alias: alias.as_str(),
        declares: stated.declares.as_deref().unwrap_or_else(|| {
            panic!(
                "a linked door is refused: `{}` states no `declares` document",
                stated.name
            )
        }),
        door,
    }
}

#[cfg(test)]
#[path = "tests/door_root.rs"]
mod tests;
