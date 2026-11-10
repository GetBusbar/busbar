// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot, ValidateIn};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::sdk::migrate::{read_answer, MigrationAnswer};

pub const ANSWER_CAP: usize = 4 * 1024 * 1024;

pub fn migrate_door(
    door: RawDoorFn,
    settings: &serde_json::Value,
    from: &str,
) -> Result<Option<MigrationAnswer>, String> {
    settings_migration(door, settings, from, false)
}

/// Cold reference discovery for a registered plane without selecting it for ordinary migration.
pub fn migrate_references_door(
    door: RawDoorFn,
    settings: &serde_json::Value,
    from: &str,
) -> Result<Option<MigrationAnswer>, String> {
    settings_migration(door, settings, from, true)
}

fn settings_migration(
    door: RawDoorFn,
    settings: &serde_json::Value,
    from: &str,
    references: bool,
) -> Result<Option<MigrationAnswer>, String> {
    let section = zeroize::Zeroizing::new(serde_json::to_vec(settings).map_err(|e| e.to_string())?);
    let Some((outcome, answer)) = call_migration(door, &section, BLOB_JSON, from, references)?
    else {
        return Ok(None);
    };
    read_answer(outcome, &answer).map(Some)
}

/// Lend a resolved credential to its auth owner's cold migration entry.
/// Neither secret bytes nor owner refusal text escape through diagnostic strings.
pub fn migrate_credential_door(
    door: RawDoorFn,
    credential: &busbar_contract::Secret<String>,
    from: &str,
    seal: &dyn busbar_contract::plugin::KernelSeal,
) -> Result<busbar_contract::abi::sdk::migrate::CredentialMigration, String> {
    let refused = || "credential owner could not migrate the original reference".to_owned();
    let Some((outcome, answer)) = call_migration(
        door,
        credential.expose(seal).as_bytes(),
        BLOB_OCTETS,
        from,
        false,
    )
    .map_err(|_| refused())?
    else {
        return Err(refused());
    };
    if outcome != busbar_contract::abi::mechanism::call::Outcome::Ready {
        return Err(refused());
    }
    serde_json::from_slice(&answer).map_err(|_| refused())
}

type MigrationWireAnswer = (
    busbar_contract::abi::mechanism::call::Outcome,
    zeroize::Zeroizing<Vec<u8>>,
);

fn call_migration(
    door: RawDoorFn,
    section: &[u8],
    format: u32,
    from: &str,
    references: bool,
) -> Result<Option<MigrationWireAnswer>, String> {
    let p = super::load::enter_door(door);
    let admitted = super::load::validate_any(p).map_err(|e| e.to_string())?;
    if format == BLOB_OCTETS && admitted.kind != busbar_contract::abi::mechanism::KindCode::Auth {
        return Err("credential migration requires an auth owner".into());
    }
    // SAFETY: `validate_any` admitted `p`: a non-NULL `'static` door readable through its stated
    // size; `read_migrate` reads the tail only when that size covers it.
    let Some(op) = (unsafe { Door::read_migrate(p) }) else {
        return Ok(None);
    };
    let mut answer = zeroize::Zeroizing::new(vec![0u8; ANSWER_CAP]);
    let mut head = super::in_head();
    head.size = size_of::<ValidateIn>() as u32;
    head.op = slot::MIGRATE;
    head.extensions = Blob {
        ptr: from.as_ptr(),
        len: from.len(),
        fmt: BLOB_OCTETS,
        flags: if references {
            busbar_contract::abi::sdk::migrate::REFERENCE_DISCOVERY
        } else {
            0
        },
    };
    let input = ValidateIn {
        head,
        settings: Blob {
            ptr: section.as_ptr(),
            len: section.len(),
            fmt: format,
            flags: if format == BLOB_OCTETS {
                busbar_contract::abi::mechanism::call::BLOB_SECRET
            } else {
                0
            },
        },
        err_buf: answer.as_mut_ptr(),
        err_cap: answer.len(),
    };
    let mut out = super::out_head();
    let called = crate::ffi_thread::on_plugin_thread(|| {
        // SAFETY: the door's admitted `migrate`, called with no instance on a frame the host owns for the
        // whole call: `input` and what it lends (`section`, `from`, `answer`) outlive it, and `out`
        // is a whole `OutHead`.
        unsafe {
            op(
                std::ptr::null_mut(),
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
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
    Ok(Some((outcome, zeroize::Zeroizing::new(bytes.to_vec()))))
}

/// Pure current-settings validation after a cold migration, before the host emits configuration.
/// The plugin gets no instance. Refusal details are deliberately not copied into migration logs.
pub fn validate_migrated_door(door: RawDoorFn, settings: &serde_json::Value) -> Result<(), String> {
    use busbar_contract::abi::mechanism::call::Outcome;
    let p = super::load::enter_door(door);
    let admitted =
        super::load::validate_any(p).map_err(|_| "current migration plugin admission failed")?;
    let op = admitted.slots[slot::VALIDATE as usize];
    let section = zeroize::Zeroizing::new(
        serde_json::to_vec(settings).map_err(|_| "cannot encode migrated settings")?,
    );
    let mut answer = zeroize::Zeroizing::new(vec![0u8; ANSWER_CAP]);
    let mut head = super::in_head();
    head.size = size_of::<ValidateIn>() as u32;
    head.op = slot::VALIDATE;
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
        // SAFETY: admission checked this lifecycle slot; VALIDATE is pure and receives no
        // instance. All input/output buffers remain live for the complete native call.
        unsafe {
            op(
                std::ptr::null_mut(),
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
    })
    .map_err(|_| "current plugin validation panicked")?;
    if called.outcome() == Outcome::Ready {
        Ok(())
    } else {
        Err("current plugin validation refused migrated settings".into())
    }
}

pub fn validate_migrated_library(
    bytes: &[u8],
    display: &str,
    settings: &serde_json::Value,
) -> Result<(), String> {
    let (lib, staged) = crate::stage::load_library_from_bytes(bytes, display)?;
    // SAFETY: the admitted library stays open for the complete call; DOOR_SYMBOL has RawDoorFn ABI.
    let door = unsafe {
        lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
            .map(|symbol| *symbol)
    };
    let result = match door {
        Ok(door) => validate_migrated_door(door, settings),
        Err(_) => Err("current migration plugin has no door".into()),
    };
    crate::dlclose_on_worker(lib);
    drop(staged);
    result
}

pub fn migrate_library(
    bytes: &[u8],
    display: &str,
    settings: &serde_json::Value,
    from: &str,
) -> Result<Option<MigrationAnswer>, String> {
    settings_migration_library(bytes, display, settings, from, false)
}

/// Loaded-image counterpart of reference discovery.
pub fn migrate_references_library(
    bytes: &[u8],
    display: &str,
    settings: &serde_json::Value,
    from: &str,
) -> Result<Option<MigrationAnswer>, String> {
    settings_migration_library(bytes, display, settings, from, true)
}

fn settings_migration_library(
    bytes: &[u8],
    display: &str,
    settings: &serde_json::Value,
    from: &str,
    references: bool,
) -> Result<Option<MigrationAnswer>, String> {
    let (lib, staged) = crate::stage::load_library_from_bytes(bytes, display)?;
    // SAFETY: `DOOR_SYMBOL` is typed `RawDoorFn` by the mechanism; `lib` is held open until the
    // call below has returned.
    let door = unsafe {
        lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
            .map(|s| *s)
    };
    let answered = match door {
        Ok(door) => settings_migration(door, settings, from, references),
        Err(e) => Err(format!("{display}: no door: {e}")),
    };
    crate::dlclose_on_worker(lib);
    drop(staged);
    answered
}

#[cfg(test)]
#[path = "../tests/migrate_door_tests.rs"]
mod tests;

/// Credential counterpart of `migrate_library`; the loaded image stays live through the call.
pub fn migrate_credential_library(
    bytes: &[u8],
    display: &str,
    credential: &busbar_contract::Secret<String>,
    from: &str,
    seal: &dyn busbar_contract::plugin::KernelSeal,
) -> Result<busbar_contract::abi::sdk::migrate::CredentialMigration, String> {
    let (lib, staged) = crate::stage::load_library_from_bytes(bytes, display)?;
    // SAFETY: the image remains loaded through the admitted migration call.
    let door = unsafe {
        lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
            .map(|symbol| *symbol)
    };
    let result = match door {
        Ok(door) => migrate_credential_door(door, credential, from, seal),
        Err(_) => Err("credential owner has no migration door".into()),
    };
    crate::dlclose_on_worker(lib);
    drop(staged);
    result
}
