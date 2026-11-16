// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::secret_calls`: the secret axis's refusal text, and its boot- and
//! config-time work (loading an instance, matching a configured module to its candidate, loading
//! its checker).

use std::fmt::{Arguments, Display};
use std::sync::{Arc, PoisonError};

use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS, BLOB_SECRET};
use busbar_contract::abi::mechanism::rendering::Unreadable;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::plugin::KernelSeal;
use busbar_contract::redacted::Secret as SecretValue;
use busbar_contract::secret::SecretRefused;
use busbar_contract::secure::SecureVec;

use crate::boot::Candidate;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::lifecycle::blob;
use crate::dispatch::Plugin;
use crate::secret_calls::{CheckerKey, SecretRows};

/// Config transaction: a copy of the live dropped-in set, put back if the transaction publishes
/// nothing.
#[cold]
pub(crate) fn dropped_copy(rows: &SecretRows) -> Vec<Candidate> {
    rows.dropped
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Config transaction: whether the live dropped-in set is `snapshot`, module for module: name,
/// version, Statement, archive file and the library bytes its signed manifest names.
#[cold]
pub(crate) fn same_set(live: &[Candidate], snapshot: &[Candidate]) -> bool {
    fn image(c: &Candidate) -> Option<(&str, &Arc<Vec<u8>>)> {
        match &c.origin {
            crate::boot::Origin::Dropped { file, bytes } => Some((file.as_str(), bytes)),
            crate::boot::Origin::Linked(_) => None,
        }
    }
    let same = |a: &Candidate, b: &Candidate| {
        a.name == b.name
            && a.version == b.version
            && a.stated == b.stated
            && match (image(a), image(b)) {
                (Some((file_a, bytes_a)), Some((file_b, bytes_b))) => {
                    file_a == file_b && (Arc::ptr_eq(bytes_a, bytes_b) || bytes_a == bytes_b)
                }
                _ => false,
            }
    };
    live.len() == snapshot.len() && live.iter().zip(snapshot).all(|(a, b)| same(a, b))
}

/// Boot: names the secret module that could not be loaded.
#[cold]
pub(crate) fn load_refused(name: &str, e: &dyn Display) -> String {
    format!("secret module '{name}' could not be loaded: {e}")
}

/// Boot: the label a loaded secret instance keeps.
#[cold]
pub(crate) fn instance_label(label: &str) -> Arc<str> {
    Arc::from(label)
}

/// Config: a secret module's instance label, named when config opens or checks it.
#[cold]
pub(crate) fn label(module: &str) -> String {
    format!("secrets.{module}")
}

/// Config: lists why the secret module refused a reference at config time.
#[cold]
pub(crate) fn check_failed(name: &str, text: &[u8]) -> Vec<String> {
    if busbar_contract::abi::mechanism::lifecycle::check_validate_refusal(text).is_err() {
        return vec![format!(
            "secret module '{name}' refused the reference without saying why"
        )];
    }
    String::from_utf8_lossy(text)
        .split('\n')
        .map(str::to_string)
        .collect()
}

/// Config: a secret module answered its check with an outcome a check never answers.
#[cold]
pub(crate) fn check_answered(name: &str, o: Outcome) -> Vec<String> {
    vec![format!(
        "secret module '{name}' answered {o:?} to check the reference"
    )]
}

/// Error: a refusal whose text is formatted here, on the refusal path only.
#[cold]
pub(crate) fn refused_fmt(error_kind: u32, text: Arguments<'_>) -> SecretRefused {
    SecretRefused {
        error_kind,
        text: format!("{text}"),
    }
}

/// Error: the plugin's own refusal text of a refused resolve, or the fallback.
#[cold]
pub(crate) fn answer_text(error: Option<&[u8]>, fallback: Arguments<'_>) -> String {
    match error.filter(|e| !e.is_empty()) {
        Some(e) => String::from_utf8_lossy(e).into_owned(),
        None => format!("{fallback}"),
    }
}

/// Config: an open on a dispatcher the host lent no seal cannot reveal the lent material.
#[cold]
pub(crate) fn open_unsealed(name: &str) -> String {
    format!(
        "plugin '{name}' open failed: its secret material is revealed only on a \
             dispatcher the host lent its seal"
    )
}

/// Config: an open found no ticket to cross on.
#[cold]
pub(crate) fn open_without_ticket(name: &str) -> String {
    format!("plugin '{name}' open failed: no ticket to open it on")
}

/// Config: an open did not complete within its wait.
#[cold]
pub(crate) fn open_timed_out(name: &str, wait_secs: u64) -> String {
    format!("secret module '{name}' did not complete its open within {wait_secs} s")
}

/// Config: the host-owned copies of the material an instance is opened over, kept for the open.
#[cold]
pub(crate) fn lent_material<S: KernelSeal + ?Sized>(
    secrets: &[SecretValue<Vec<u8>>],
    seal: &S,
) -> Vec<SecureVec> {
    let mut owned = Vec::with_capacity(secrets.len());
    owned.extend(
        secrets
            .iter()
            .map(|s| SecureVec::from(s.expose(seal).as_slice())),
    );
    owned
}

/// Re-lend: the secret blobs a `refresh` frame lends, over the re-resolved material.
#[cold]
pub(crate) fn secret_blobs<S: KernelSeal + ?Sized>(
    secrets: &[SecretValue<Vec<u8>>],
    seal: &S,
) -> Vec<Blob> {
    secrets
        .iter()
        .map(|s| blob(s.expose(seal), BLOB_OCTETS, BLOB_SECRET))
        .collect()
}

/// Config: a disk-lane resolve runs at config time only, off this thread: the module name and the
/// settings it moves there.
#[cold]
pub(crate) fn lane_copies(name: &str, settings: &[u8]) -> (String, Vec<u8>) {
    (name.to_string(), settings.to_vec())
}

/// Config: a secret module's settings did not encode.
#[cold]
pub(crate) fn encode_refused(e: &dyn Display) -> String {
    e.to_string()
}

/// Boot: a linked secret's declares section did not read.
#[cold]
pub(crate) fn declares_unread(name: &str, e: &dyn Display) -> String {
    format!("linked secret '{name}': its declares section: {e}")
}

/// Boot: a linked door of another kind was offered as a secret.
#[cold]
pub(crate) fn not_a_secret_door(name: &str, kind: KindCode) -> String {
    format!("`{name}` is a {kind:?} door, not a secret one")
}

/// Config: a secret module's Statement did not read back.
#[cold]
pub(crate) fn statement_unread(name: &str, e: &Unreadable) -> String {
    format!(
        "secret module '{}': its Statement does not read back (byte {}: {})",
        name, e.at, e.what
    )
}

/// Config: names a configured secret module no plugin answers to.
#[cold]
pub(crate) fn unanswered(module: &str) -> String {
    format!("no secret module answers to '{module}'")
}

/// Config: a secret reference's settings did not render for checking.
#[cold]
pub(crate) fn unencodable_settings() -> Vec<String> {
    vec!["cannot encode source settings".to_owned()]
}

/// Config: checking a secret reference needs the host settings seal.
#[cold]
pub(crate) fn unsealed_check() -> Vec<String> {
    vec!["source validation requires the host settings seal".to_owned()]
}

/// Config: the module name a re-lending instance keeps.
#[cold]
pub(crate) fn module_name(module: &str) -> String {
    module.to_owned()
}

impl SecretRows {
    /// Boot: the linked row a linked secret's declares section belongs to, matched once at link
    /// time.
    #[cold]
    pub(crate) fn declared_row(&mut self, name: &str) -> Result<&mut Candidate, String> {
        self.linked
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or_else(|| format!("linked secret '{name}' declares, but no linked row is it"))
    }

    /// Boot: the linked candidates followed by the offered secrets, checked together once.
    #[cold]
    pub(crate) fn with_linked(&self, secrets: &[Candidate]) -> Vec<Candidate> {
        self.linked
            .iter()
            .cloned()
            .chain(secrets.iter().cloned())
            .collect()
    }

    /// Config: every candidate, linked then dropped, gathered when config reads the sugars.
    #[cold]
    pub(crate) fn all_candidates(&self) -> Vec<Candidate> {
        self.linked
            .iter()
            .cloned()
            .chain(
                self.dropped
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .cloned(),
            )
            .collect()
    }

    /// Config: the candidate a configured secret module names, linked first, then dropped.
    #[cold]
    pub(crate) fn find_candidate(&self, module: &str) -> Option<Candidate> {
        if let Some(c) = self.linked.iter().find(|c| c.answers(module)) {
            return Some(c.clone());
        }
        let dropped = self.dropped.read().unwrap_or_else(PoisonError::into_inner);
        dropped.iter().find(|c| c.answers(module)).cloned()
    }

    /// Config: whether config names a linked secret module.
    #[cold]
    pub(crate) fn answers_linked(&self, module: &str) -> bool {
        self.linked.iter().any(|c| c.answers(module))
    }

    /// Config: the linked candidate a shared secret module names, matched when config opens it.
    #[cold]
    pub(crate) fn linked_candidate(&self, module: &str) -> Result<&Candidate, String> {
        self.linked
            .iter()
            .find(|c| c.answers(module))
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))
    }

    /// Config: a secret module's checker, loaded once per registry generation.
    #[cold]
    pub(crate) fn checker(&self, module: &str) -> Result<Option<Arc<Plugin<Secret>>>, String> {
        let (key, candidate, generation) = {
            let dropped = self.dropped.read().unwrap_or_else(PoisonError::into_inner);
            let checkers = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
            let Some((key, candidate)) = self
                .linked
                .iter()
                .enumerate()
                .find(|(_, c)| c.answers(module))
                .map(|(i, c)| (CheckerKey::Linked(i), c))
                .or_else(|| {
                    dropped
                        .iter()
                        .enumerate()
                        .find(|(_, c)| c.answers(module))
                        .map(|(i, c)| (CheckerKey::Dropped(i), c))
                })
            else {
                return Ok(None);
            };
            if let Some(plugin) = checkers.plugins.get(&key) {
                return Ok(Some(Arc::clone(plugin)));
            }
            (key, candidate.clone(), Arc::clone(&checkers.generation))
        };

        let check_label = format!("{}.check", label(module));
        let loaded = Arc::new(self.load(&candidate, &check_label)?);
        let plugin = {
            let mut checkers = self.checkers.lock().unwrap_or_else(PoisonError::into_inner);
            if Arc::ptr_eq(&generation, &checkers.generation) {
                Arc::clone(
                    checkers
                        .plugins
                        .entry(key)
                        .or_insert_with(|| Arc::clone(&loaded)),
                )
            } else {
                Arc::clone(&loaded)
            }
        };
        Ok(Some(plugin))
    }
}
