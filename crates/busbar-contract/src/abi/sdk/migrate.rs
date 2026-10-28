// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN MIGRATES ITS OWN SETTINGS (owner ruling 2026-10-27): the door's optional `migrate`
//! (`abi::mechanism::lifecycle`, MIGRATE), once for every kind.
//!
//! `busbar --migrate-config` migrates core's own keys and nothing inside a plugin's settings
//! section. For each configured plugin it loads the plugin's current build and calls this entry with
//! the section as the operator wrote it and the busbar version the configuration came from. The
//! plugin answers the new section, one report line per change (what changed and why), and the needs
//! it raises against keys core owns. Core applies only those needs, prints every report line under
//! the plugin's name, and writes the new section. A renamed key, a removed key, a new required key,
//! a default that keeps the old behaviour: each is the plugin's to write here.
//!
//! A plugin states it on its door with [`Migrator`] over its own [`Migrate`]:
//!
//! ```ignore
//! struct Mine;
//! impl busbar_contract::abi::sdk::migrate::Migrate for Mine {
//!     fn migrate(settings: serde_json::Value, from: &str) -> Migrated { /* ... */ }
//! }
//! busbar_contract::plugin_door! {
//!     ops: busbar_contract::abi::secret::Ops,
//!     statement: busbar_contract::abi::sdk::door::statement("mine", "1.6.0", 4),
//!     lifecycle: life(Life),
//!     migrate: busbar_contract::abi::sdk::migrate::Migrator<Mine>,
//!     kind_ops: { resolve: Resolve },
//! }
//! ```

use std::ffi::c_void;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use crate::abi::mechanism::lifecycle::ValidateIn;
use crate::abi::sdk::door::Slot;

/// A need a plugin's migration raises against a key core owns. Core applies exactly these, to its
/// own keys only, and nothing else of the plugin's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MigrateNeed {
    /// The plugin dials this host, which the destination guard refuses by default (a private or
    /// loopback address, or a name that resolves to one) and which the plugin reached on the
    /// version the configuration came from: core adds exactly this host to
    /// `advanced.allow_destinations`.
    AllowDestination(String),
}

/// A plugin's migrated settings section: the new section, a report line per change, and the needs
/// it raises against core's keys. The answer `migrate` writes, as one JSON object.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migrated {
    /// The settings section as it reads now. Core writes it in place of the old one.
    pub settings: serde_json::Value,
    /// One line per change, each saying what changed and why. Core prints each under the plugin's
    /// name.
    #[serde(default)]
    pub report: Vec<String>,
    /// What the plugin needs of keys core owns.
    #[serde(default)]
    pub needs: Vec<MigrateNeed>,
}

impl Migrated {
    /// `settings` unchanged: nothing to report, nothing needed.
    #[must_use]
    pub fn unchanged(settings: serde_json::Value) -> Self {
        Self {
            settings,
            ..Self::default()
        }
    }
}

/// A plugin's own migration of its settings section.
pub trait Migrate {
    /// Migrate `settings` (the section as the operator wrote it; `null` when it wrote none) from
    /// the busbar version `from` (`"1.5.5"`, or `""` when the configuration does not say). Pure: it
    /// reads nothing but its arguments and writes nothing.
    fn migrate(settings: serde_json::Value, from: &str) -> Migrated;
}

/// THE `migrate` SLOT over a plugin's [`Migrate`]: reads the section and the version the host lent,
/// calls `M`, and writes the answer as JSON into the host's buffer, naming it in `head.error`.
/// Settings that are not JSON, or an answer larger than the buffer, are REFUSED with the reason
/// written the same way (when it fits).
#[derive(Debug)]
pub struct Migrator<M>(PhantomData<M>);

impl<M: Migrate> Slot for Migrator<M> {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, input: &ValidateIn, out: &mut OutHead) -> Outcome {
        // SAFETY: the host lent `settings`, `head.extensions` and `err_buf` (`err_cap` bytes,
        // writable) for this call, as the MIGRATE op states (`abi::mechanism::lifecycle`).
        let (settings, from) = unsafe {
            (
                lent(input.settings.ptr, input.settings.len),
                lent(input.head.extensions.ptr, input.head.extensions.len),
            )
        };
        let (outcome, answer) = match parse(settings) {
            Ok(section) => {
                let from = String::from_utf8_lossy(from);
                let migrated = M::migrate(section, &from);
                match serde_json::to_vec(&migrated) {
                    Ok(bytes) => (Outcome::Ready, bytes),
                    Err(e) => (Outcome::Refused, format!("migrate: {e}").into_bytes()),
                }
            }
            Err(e) => (Outcome::Refused, e.into_bytes()),
        };
        if input.err_buf.is_null() || answer.len() > input.err_cap {
            return Outcome::Refused;
        }
        // SAFETY: `err_buf` holds `err_cap >= answer.len()` writable bytes the host lent for the
        // call, and `answer` is this call's own, so the two do not overlap.
        unsafe { std::ptr::copy_nonoverlapping(answer.as_ptr(), input.err_buf, answer.len()) };
        out.error = AbiStr {
            ptr: input.err_buf,
            len: answer.len(),
        };
        outcome
    }
}

/// The settings section as JSON: `null` when the host lent none.
fn parse(settings: &[u8]) -> Result<serde_json::Value, String> {
    if settings.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(settings).map_err(|e| format!("migrate: the settings are not JSON: {e}"))
}

/// `len` bytes at `p`, or none for a NULL `p` or a zero `len`.
///
/// # Safety
/// A non-NULL `p` points at `len` readable bytes, valid for the call.
unsafe fn lent<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// The answer a door's `migrate` named, read back by the HOST: the plugin's [`Migrated`], or the
/// reason it gave.
///
/// # Errors
/// The plugin did not answer READY (its reason), or answered something that is not a [`Migrated`].
pub fn read_answer(outcome: Outcome, answer: &[u8]) -> Result<Migrated, String> {
    let text = String::from_utf8_lossy(answer);
    match outcome {
        Outcome::Ready => serde_json::from_slice(answer)
            .map_err(|e| format!("its migrate answered something that is not a migration: {e}")),
        o if text.is_empty() => Err(format!("its migrate answered {o:?}")),
        _ => Err(text.into_owned()),
    }
}

#[cfg(test)]
#[path = "tests/migrate_tests.rs"]
mod tests;
