// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S SIDE OF THE DOOR'S OPTIONAL `migrate` (`busbar_contract::abi::mechanism::lifecycle`,
//! MIGRATE; owner ruling 2026-10-27: each plugin migrates its own settings section).
//!
//! `busbar --migrate-config` hands each configured plugin's current build its settings section as
//! the operator wrote it and the busbar version the configuration came from, and reads back the
//! plugin's [`Migrated`]: the new section, its report lines and the needs it raises against keys
//! core owns. The call is made with no instance and no ticket (it may not pend), on a permanent FFI
//! worker, through the door's tail: a door that states no `migrate` is not called, and its section
//! passes through unchanged ([`migrate_door`] answers `None`).

use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot, ValidateIn};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::sdk::migrate::{read_answer, Migrated};

/// How many bytes the host lends a plugin's `migrate` for its answer.
pub const ANSWER_CAP: usize = 4 * 1024 * 1024;

/// Call `door`'s `migrate` on `settings` (the plugin's section as written; `null` for none), from
/// the busbar version `from`. `None` when the door states no `migrate`.
///
/// # Errors
/// The door is refused by the host's door checks, or the plugin's `migrate` refused (its reason),
/// faulted, or answered something that is not a migration.
pub fn migrate_door(
    door: RawDoorFn,
    settings: &serde_json::Value,
    from: &str,
) -> Result<Option<Migrated>, String> {
    let p = super::load::enter_door(door);
    super::load::validate_any(p).map_err(|e| e.to_string())?;
    // SAFETY: `validate_any` admitted `p`: a non-NULL `'static` door readable through its stated
    // size; `read_migrate` reads the tail only when that size covers it.
    let Some(op) = (unsafe { Door::read_migrate(p) }) else {
        return Ok(None);
    };
    let section = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
    let mut answer = vec![0u8; ANSWER_CAP];
    let mut head = super::in_head();
    head.size = size_of::<ValidateIn>() as u32;
    head.op = slot::MIGRATE;
    head.extensions = Blob {
        ptr: from.as_ptr(),
        len: from.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let input = ValidateIn {
        head,
        settings: Blob {
            ptr: section.as_ptr(),
            len: section.len(),
            fmt: BLOB_JSON,
            flags: 0,
        },
        err_buf: answer.as_mut_ptr(),
        err_cap: answer.len(),
    };
    let mut out = super::out_head();
    let called = crate::ffi_thread::on_plugin_thread(|| {
        // The door's admitted `migrate`, called with no instance on a frame the host owns for the
        // whole call: `input` and what it lends (`section`, `from`, `answer`) outlive it, and `out`
        // is a whole `OutHead`.
        op(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
    })
    .map_err(|_| "its migrate panicked".to_string())?;
    let outcome = called.outcome();
    let named = out.error;
    let lent = answer.as_ptr();
    let bytes = if named.ptr.is_null() || named.len == 0 {
        &[][..]
    } else if named.ptr == lent && named.len <= answer.len() {
        &answer[..named.len]
    } else {
        return Err("its migrate named an answer outside the host's buffer".to_string());
    };
    read_answer(outcome, bytes).map(Some)
}

/// [`migrate_door`] over a dropped-in plugin's VERIFIED library bytes (the bytes its signed
/// manifest's `sha256` names): staged by the loader's one staging path, opened, its door's `migrate`
/// called, and the library closed again on the plugin thread. `display` labels a refusal.
///
/// # Errors
/// The library does not load or exports no door, or [`migrate_door`]'s.
pub fn migrate_library(
    bytes: &[u8],
    display: &str,
    settings: &serde_json::Value,
    from: &str,
) -> Result<Option<Migrated>, String> {
    let (lib, staged) = crate::stage::load_library_from_bytes(bytes, display)?;
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; `lib` is held open until the
    // call below has returned.
    let door = unsafe {
        lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
            .map(|s| *s)
    };
    let answered = match door {
        Ok(door) => migrate_door(door, settings, from),
        Err(e) => Err(format!("{display}: no door: {e}")),
    };
    crate::dlclose_on_worker(lib);
    drop(staged);
    answered
}

#[cfg(test)]
#[path = "../tests/migrate_door_tests.rs"]
mod tests;
