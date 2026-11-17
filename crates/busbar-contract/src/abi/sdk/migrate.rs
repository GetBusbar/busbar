// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plugin migrates its own settings through the door's optional `migrate` entry
//! (`abi::mechanism::lifecycle`, MIGRATE), once for every kind.
//!
//! The boot's migration migrates core's own keys and nothing inside a plugin's settings
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

use crate::plugin::KindMarker;
use std::ffi::c_void;
use std::marker::PhantomData;

use crate::secure::{SecureString, SecureVec};
use serde::{Deserialize, Serialize};

use crate::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use crate::abi::mechanism::lifecycle::ValidateIn;
use crate::abi::sdk::door::RawSlot;

/// Reserved read-only plane-envelope section containing generic source provenance.
/// Entries are keyed by consumed section; owners retain this section unchanged.
pub const SOURCE_DOCUMENTS: &str = "$migration_sources";
/// MIGRATE extension flag for cold reference discovery, without selecting the plane.
pub const REFERENCE_DISCOVERY: u32 = 1 << 31;

/// Original source documents for an owner to interpret its own precedence rules.
#[derive(Clone, Serialize, Deserialize)]
pub struct SourceDocuments {
    /// Original authored deployment section, or null if absent.
    pub authored: serde_json::Value,
    /// Original catalog section, or null if unavailable.
    pub catalog: serde_json::Value,
}

impl std::fmt::Debug for SourceDocuments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceDocuments([REDACTED])")
    }
}
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
    /// The plugin dials this host and reached it on the version the configuration came from, but
    /// cannot tell whether it is private: `migrate` reads nothing but its arguments, so it cannot
    /// resolve a name. Core resolves it at migrate time and judges every answer with the
    /// destination guard's own predicates (`crate::net`). It adds exactly this host to
    /// `advanced.allow_destinations` only when every answer is private or loopback and none is
    /// cloud metadata. Core prints a line for every decision, added or not, naming what the host
    /// resolved to.
    AllowDestinationIfPrivate(String),
    /// Externalize the historical literal secret at this nonempty path relative to
    /// `Migrated.settings`. The plugin leaves the string in that slot; core writes its exact
    /// UTF-8 bytes to a private migration artifact and replaces the slot with a SecretRef.
    /// The need and report must never contain the secret value. Core validates the path and
    /// refuses unsafe artifact creation before writing the migrated configuration.
    ExternalizeSecret { path: Vec<String> },
    /// The owner cannot decide safely without additional original source evidence.
    /// The reason must contain no secret values.
    Review { path: Vec<String>, reason: String },
}

/// A plugin's migrated settings section: the new section, a report line per change, and the needs
/// it raises against core's keys. The answer `migrate` writes, as one JSON object.
///
/// The section is held in the same wiping, opaque custody as the host's [`MigrationAnswer`]:
/// the owner finishes editing its `serde_json::Value` and then seals it here with
/// [`Migrated::new`] or [`Migrated::unchanged`]. Nothing reads or serializes the sealed section
/// except the `migrate` slot's own wire encoder; a test holding the dev-only kernel seal reads it
/// back through [`MigrationAnswer::from`] and [`MigrationAnswer::authoring`]. `Debug` names no
/// setting.
///
/// ```compile_fail
/// fn inspect(answer: busbar_contract::abi::sdk::migrate::Migrated) {
///     let _ = answer.settings;
/// }
/// ```
/// ```compile_fail
/// fn serialize(answer: busbar_contract::abi::sdk::migrate::Migrated) {
///     let _ = serde_json::to_value(answer);
/// }
/// ```
/// ```compile_fail
/// let _: busbar_contract::abi::sdk::migrate::Migrated = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq)]
pub struct Migrated {
    /// The settings section as it reads now. Core writes it in place of the old one.
    settings: crate::plugin_settings::Tree,
    /// One line per change, each saying what changed and why. Core prints each under the plugin's
    /// name. Report lines must not contain secret values.
    pub report: Vec<String>,
    /// What the plugin needs of keys core owns.
    pub needs: Vec<MigrateNeed>,
}

impl Default for Migrated {
    /// A `null` section, nothing to report, nothing needed.
    fn default() -> Self {
        Self::unchanged(serde_json::Value::Null)
    }
}

impl std::fmt::Debug for Migrated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Migrated")
            .field("settings", &"[REDACTED]")
            .field("report", &self.report)
            .field("needs", &self.needs)
            .finish()
    }
}

impl Migrated {
    /// Seal the owner's migrated `settings` with its report lines and needs.
    #[must_use]
    pub fn new(settings: serde_json::Value, report: Vec<String>, needs: Vec<MigrateNeed>) -> Self {
        Self {
            settings: crate::plugin_settings::Tree(settings),
            report,
            needs,
        }
    }

    /// `settings` unchanged: nothing to report, nothing needed.
    #[must_use]
    pub fn unchanged(settings: serde_json::Value) -> Self {
        Self::new(settings, Vec::new(), Vec::new())
    }

    /// The `migrate` slot's answer bytes, `{"settings": .., "report": [..], "needs": [..]}`,
    /// written into guarded custody.
    pub(crate) fn wire(&self) -> Result<crate::Secret<Vec<u8>>, serde_json::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            settings: &'a serde_json::Value,
            report: &'a [String],
            needs: &'a [MigrateNeed],
        }
        crate::plugin_settings::encode_guarded(&Wire {
            settings: &self.settings.0,
            report: &self.report,
            needs: &self.needs,
        })
    }
}

/// The host's custody of a migration answer. Settings retain their exact JSON shape,
/// including `null`, but cannot be inspected or serialized without kernel authority.
/// The owner's [`Migrated`] remains the construction API on the plugin side.
///
/// ```compile_fail
/// fn inspect(answer: busbar_contract::abi::sdk::migrate::MigrationAnswer) {
///     let _ = answer.settings;
/// }
/// ```
/// ```compile_fail
/// fn serialize(answer: busbar_contract::abi::sdk::migrate::MigrationAnswer) {
///     let _ = serde_json::to_value(answer);
/// }
/// ```
#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationAnswer {
    settings: crate::plugin_settings::Tree,
    /// Owner-authored report lines; these must not contain secret values.
    #[serde(default)]
    pub report: Vec<String>,
    /// Explicit migration needs against host-owned configuration.
    #[serde(default)]
    pub needs: Vec<MigrateNeed>,
}

impl std::fmt::Debug for MigrationAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationAnswer")
            .field("settings", &"[REDACTED]")
            .field("report_count", &self.report.len())
            .field("need_count", &self.needs.len())
            .finish()
    }
}

impl From<Migrated> for MigrationAnswer {
    fn from(migrated: Migrated) -> Self {
        Self {
            settings: migrated.settings,
            report: migrated.report,
            needs: migrated.needs,
        }
    }
}

impl MigrationAnswer {
    /// Borrow the settings document for authorized migration write-back.
    /// A transport grant or generic sealed credential borrow cannot author documents.
    ///
    /// ```compile_fail
    /// fn read(answer: &busbar_contract::abi::sdk::migrate::MigrationAnswer,
    ///         seal: &dyn busbar_contract::plugin::KernelSeal) {
    ///     let _ = answer.authoring(seal);
    /// }
    /// ```
    pub fn authoring<'a>(&'a self, _seal: &'a crate::caps::KernelSeal) -> MigrationAuthoring<'a> {
        MigrationAuthoring { answer: self }
    }

    /// Encode the settings for a receiving kind while retaining guarded byte custody.
    pub fn encode(&self) -> Result<crate::Secret<Vec<u8>>, serde_json::Error> {
        self.settings.encode()
    }
}

/// Borrowed settings document issued by [`MigrationAnswer::authoring`].
#[derive(Debug)]
pub struct MigrationAuthoring<'a> {
    answer: &'a MigrationAnswer,
}

impl Serialize for MigrationAuthoring<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.answer.settings.0.serialize(serializer)
    }
}

/// A plugin's own migration of its settings section.
pub trait Migrate {
    /// Kind whose settings are being migrated.
    type Kind: crate::plugin::KindMarker;
    /// Migrate `settings` (the section as the operator wrote it; `null` when it wrote none) from
    fn migrate(settings: serde_json::Value, from: &str) -> Migrated;
    /// Discover credential migration needs in borrowed sections without selecting this plane.
    /// Default owners have no reference discovery. The host ignores settings edits and other needs.
    fn migrate_references(settings: serde_json::Value, _from: &str) -> Migrated {
        Migrated::unchanged(settings)
    }
}

/// THE `migrate` SLOT over a plugin's [`Migrate`]: reads the section and the version the host lent,
/// calls `M`, and writes the answer as JSON into the host's buffer, naming it in `head.error`.
/// Settings that are not JSON, or an answer larger than the buffer, are REFUSED with the reason
/// written the same way (when it fits).
#[derive(Debug)]
pub struct Migrator<M>(PhantomData<M>);

impl<M: Migrate> RawSlot for Migrator<M> {
    type Kind = M::Kind;
    type In = ValidateIn;
    type Out = OutHead;
    unsafe fn call(_: *mut c_void, input: &ValidateIn, out: &mut OutHead) -> Outcome {
        // SAFETY: the host lent `settings`, `head.extensions` and `err_buf` (`err_cap` bytes,
        // writable) for this call, as the MIGRATE op states (`abi::mechanism::lifecycle`).
        let (settings, from) = unsafe {
            (
                lent(input.settings.ptr, input.settings.len),
                lent(input.head.extensions.ptr, input.head.extensions.len),
            )
        };
        // An octet (credential) input is not a settings section: the credential conversion
        // channel is retired (MIGRATE-ON-BOOT r41 §A4: the deferred style binding and the owner's own open
        // replace it).
        if input.settings.fmt == crate::abi::mechanism::call::BLOB_OCTETS {
            return Outcome::Refused;
        }
        let (outcome, answer) = {
            match parse(settings) {
                Ok(section) => {
                    let from = String::from_utf8_lossy(from);
                    let migrated = if input.head.extensions.flags & REFERENCE_DISCOVERY != 0 {
                        M::migrate_references(section, &from)
                    } else {
                        M::migrate(section, &from)
                    };
                    match migrated.wire() {
                        Ok(mut bytes) => (
                            Outcome::Ready,
                            SecureVec::from(std::mem::take(&mut bytes.0)),
                        ),
                        Err(e) => (
                            Outcome::Refused,
                            SecureString::from_args(format_args!("migrate: {e}")).into_bytes(),
                        ),
                    }
                }
                Err(e) => (Outcome::Refused, SecureVec::from(e.into_bytes())),
            }
        };

        let (outcome, answer) = if answer.len() > input.err_cap {
            (
                Outcome::Refused,
                b"migrate: the answer is larger than the host buffer".as_slice(),
            )
        } else {
            (outcome, answer.as_slice())
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

/// Read a door's answer into host custody without exposing the owner's settings.
/// Cold, and pinned so the migrate-size job finds it (MIGRATE-ON-BOOT §7 †).
#[cold]
#[inline(never)]
pub fn read_answer(outcome: Outcome, answer: &[u8]) -> Result<MigrationAnswer, String> {
    match outcome {
        Outcome::Ready => serde_json::from_slice(answer)
            .map_err(|_| "its migrate answered something that is not a migration".to_owned()),
        o if answer.is_empty() => Err(format!("its migrate answered {o:?}")),
        _ => Err(String::from_utf8_lossy(answer).into_owned()),
    }
}

#[cfg(test)]
#[path = "tests/migrate_tests.rs"]
mod tests;
