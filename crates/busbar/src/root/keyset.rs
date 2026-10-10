// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEPLOYMENT KEYSET: where the one ed25519 key that signs the audit chain AND the ledger's
//! checkpoints comes from (spec #82(a); OWNER Q71(3) one keyset; BUSBAR-1.6.0.md THE DESIGN, §2 and PB-13;
//! architect ruling 2026-09-26 "#82(a) key source", flagged to the owner as Q78).
//!
//! ## The rule, as ruled
//!
//! - The keyset is MINTED at the first boot's `Bootstrap`: a fresh ed25519 seed from the OS CSPRNG.
//! - It is SEALED IN THE STORE: the configured store's v3 record slots keep it once for the
//!   deployment (`durability::KEYSET_SCHEMA`; ARCHITECT 2026-10-07 H3 ruling, follow-up). With no
//!   `data_dir` the first boot mints it, keeps it in the store, and seals its fingerprint in a
//!   `Bootstrap` record; every later boot, and every other node on that store, reads it back, so
//!   `/admin/verify` verifies a chain a predecessor signed. A chain whose `Bootstrap` names a
//!   fingerprint the store does not yield refuses [`KeysetError::StoreMissing`].
//! - With no store and no `data_dir` (no deployment boots so: a configuration names its store), the
//!   keyset is NODE-LOCAL AND EPHEMERAL (PB-13): minted per process, never written anywhere.
//! - With `data_dir` written, [`KEYSET_FILE`] under it (mode 0600) is a LOCAL CACHE of the
//!   deployment keyset, and the first boot journals a `Bootstrap` record sealing its fingerprint.
//!   [`KeysetMissing`] fires ONLY when `data_dir` is set, a `Bootstrap` is on the chain, and
//!   neither the file nor the store yields the fingerprint that `Bootstrap` sealed.
//! - There is NO off-node import/export CLI: the owner cut `export_keyset`, so an import would have
//!   no source.

use std::path::{Path, PathBuf};

use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_kernel::registry::{bootstrap, BootstrapVerdict};
use busbar_kernel_audit::{AuditSigningKey, AuditVerifyingKey};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, RecordClass};

use crate::root::durability::Durability;

/// The keyset cache's file name under `data_dir`. One 64-hex-character ed25519 seed, mode 0600.
pub const KEYSET_FILE: &str = "deployment-keyset";

/// The fingerprint a `Bootstrap` seals: SHA-256 over the public key's 32 bytes. The key identifier
/// a signed record names is this digest's first eight bytes, so the two can never disagree.
#[must_use]
pub fn fingerprint_of(key: &AuditVerifyingKey) -> [u8; 32] {
    let raw = hex::decode(key.public_key_hex()).unwrap_or_default();
    busbar_kernel_ledger::digest::sha256(&raw)
}

/// [`fingerprint_of`] a signing key's public half.
#[must_use]
pub fn fingerprint_of_signer(key: &AuditSigningKey) -> [u8; 32] {
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex())
        .expect("a signing key's own public half is a valid key");
    fingerprint_of(&public)
}

/// Where this node's keyset came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetSource {
    /// No `data_dir`: minted for this process only, written nowhere (PB-13).
    Ephemeral,
    /// First boot with `data_dir`: minted, cached to the file, and its fingerprint sealed by a
    /// `Bootstrap` record on the journal.
    Minted {
        /// The keyset cache file written.
        file: PathBuf,
    },
    /// A later boot with `data_dir`: the file yielded the fingerprint the `Bootstrap` sealed.
    Cached {
        /// The keyset cache file read.
        file: PathBuf,
    },
    /// No `data_dir`: the deployment keyset the configured store keeps (minted into it on the
    /// first boot of the deployment).
    Stored,
}

/// Why a boot could not bind the deployment keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetError {
    /// `data_dir` is set, a `Bootstrap` is on the chain, and neither the keyset file nor the store
    /// yields the fingerprint it sealed.
    Missing(KeysetMissing),
    /// The keyset file could not be read or written.
    Io {
        /// The keyset file.
        file: PathBuf,
        /// What the filesystem said.
        why: String,
    },
    /// The `Bootstrap` record could not be made durable.
    Unsealed {
        /// The journal step that lost the write.
        step: &'static str,
    },
    /// The OS CSPRNG gave no bytes, so no key could be minted.
    NoEntropy,
    /// No `data_dir`: a `Bootstrap` is on the chain the store kept, and the store does not yield
    /// the keyset whose fingerprint it sealed.
    StoreMissing {
        /// The fingerprint the `Bootstrap` record sealed.
        fingerprint: [u8; 32],
    },
    /// The configured store would not read or keep the deployment keyset.
    Store(String),
}

/// THE REFUSAL: this deployment was bootstrapped with a keyset this node cannot produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetMissing {
    /// The configured data directory.
    pub data_dir: PathBuf,
    /// The fingerprint the `Bootstrap` record sealed.
    pub fingerprint: [u8; 32],
}

impl std::fmt::Display for KeysetMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeysetMissing: the journal under {dir} holds a Bootstrap sealing keyset fingerprint \
             {fp}, and neither the keyset file {file} nor the configured store yields that \
             fingerprint. Restore this node's data_dir (the keyset file beside its journal), or \
             boot against a store that holds the deployment keyset",
            dir = self.data_dir.display(),
            fp = hex::encode(self.fingerprint),
            file = self.data_dir.join(KEYSET_FILE).display(),
        )
    }
}

impl std::fmt::Display for KeysetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeysetError::Missing(missing) => missing.fmt(f),
            KeysetError::Io { file, why } => write!(
                f,
                "the deployment keyset file {} could not be used: {why}",
                file.display()
            ),
            KeysetError::Unsealed { step } => write!(
                f,
                "the journal could not make the deployment keyset's Bootstrap record durable at \
                 step {step}"
            ),
            KeysetError::NoEntropy => f.write_str(
                "the operating system's random source gave no bytes, so the deployment keyset \
                 could not be minted",
            ),
            KeysetError::StoreMissing { fingerprint } => write!(
                f,
                "KeysetMissing: the journal the configured store keeps holds a Bootstrap sealing \
                 keyset fingerprint {}, and the store does not yield that fingerprint. Restore \
                 the store's deployment keyset, or boot against a store that holds it",
                hex::encode(fingerprint)
            ),
            KeysetError::Store(why) => write!(f, "the deployment keyset: {why}"),
        }
    }
}

/// A `Bootstrap` record's body: the sealed fingerprint, then the key identifier for a reader.
#[must_use]
pub fn bootstrap_body(fingerprint: &[u8; 32], key_id: &str) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.bytes(fingerprint).text(key_id);
    body.finish()
}

/// The fingerprint a `Bootstrap` record's body seals, or `None` for a body that is not one.
#[must_use]
pub fn bootstrap_fingerprint(body: &[u8]) -> Option<[u8; 32]> {
    BodyReader::new(body).bytes()?.try_into().ok()
}

/// Mint a fresh keyset: 32 bytes from the OS CSPRNG, as the 64-hex-character text the cache file
/// holds. The raw bytes are overwritten before this returns.
fn mint_seed_hex() -> Result<String, KeysetError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| KeysetError::NoEntropy)?;
    let text = hex::encode(seed);
    seed.fill(0);
    std::hint::black_box(&seed);
    Ok(text)
}

/// Read the keyset cache file: `Ok(None)` when there is none.
fn read_cached(file: &Path) -> Result<Option<AuditSigningKey>, KeysetError> {
    match std::fs::read_to_string(file) {
        Ok(text) => AuditSigningKey::from_hex_seed(&text)
            .map(Some)
            .map_err(|e| KeysetError::Io {
                file: file.to_path_buf(),
                why: format!("it does not hold a keyset: {e}"),
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KeysetError::Io {
            file: file.to_path_buf(),
            why: e.to_string(),
        }),
    }
}

/// The fingerprint the newest `Bootstrap` on the chain sealed, if any. A chain that will not read
/// back yields none: the journal's own finding already names that, and a Bootstrap nobody can read
/// is not one this node can be refused over.
fn sealed_fingerprint(durability: &Durability) -> Option<[u8; 32]> {
    let records = durability.journal.replay().ok()?.ok()?;
    records
        .iter()
        .filter(|r| r.class == RecordClass::Bootstrap)
        .max_by_key(|r| r.node_seq)
        .and_then(|r| bootstrap_fingerprint(&r.body))
}

fn sign_with(durability: &mut Durability, key: AuditSigningKey) {
    durability.record = std::mem::take(&mut durability.record).signing_with(key);
}

/// BIND THE DEPLOYMENT KEYSET to this node's audit chain, so every record it seals and every
/// checkpoint the ledger seals from here on is signed with it (#82(a): at seal time, in-process).
///
/// Called by the boot BEFORE the opening is sealed, so the migration's checkpoint 0 is signed too.
/// `data_dir` is the directory the journal was opened in, or `None` for a memory-buffered node.
///
/// # Errors
///
/// [`KeysetError::Missing`] under the one condition the ruling names; otherwise a keyset file this
/// node could not read or write, a `Bootstrap` the journal could not make durable, or no entropy.
/// With `data_dir` unset there is no error but [`KeysetError::NoEntropy`].
pub fn bind(
    durability: &mut Durability,
    data_dir: Option<&Path>,
    token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<KeysetSource, KeysetError> {
    let store = durability
        .lane()
        .map(crate::root::durability::JournalLane::calls);
    let Some(dir) = data_dir else {
        if let Some(calls) = store {
            return bind_in_store(durability, calls.as_ref(), token, at, now);
        }
        let key = AuditSigningKey::from_hex_seed(&mint_seed_hex()?)
            .expect("a freshly minted seed is 64 hex characters");
        sign_with(durability, key);
        return Ok(KeysetSource::Ephemeral);
    };
    let file = dir.join(KEYSET_FILE);
    let prior = sealed_fingerprint(durability);
    let cached = match (prior, read_cached(&file)) {
        // A sealed Bootstrap and a file that cannot be read are the refusal, not an I/O fault: the
        // file does not yield the fingerprint, and the store holds no keyset.
        (Some(fingerprint), Err(_)) => {
            return Err(KeysetError::Missing(KeysetMissing {
                data_dir: dir.to_path_buf(),
                fingerprint,
            }))
        }
        (_, read) => read?,
    };
    let ours = cached.as_ref().map(fingerprint_of_signer);
    match bootstrap(prior, ours) {
        BootstrapVerdict::AlreadyOurs => {
            sign_with(
                durability,
                cached.expect("AlreadyOurs is answered only for a key this node holds"),
            );
            Ok(KeysetSource::Cached { file })
        }
        BootstrapVerdict::KeysetMissing => Err(KeysetError::Missing(KeysetMissing {
            data_dir: dir.to_path_buf(),
            fingerprint: prior.expect("KeysetMissing is answered only over a sealed Bootstrap"),
        })),
        BootstrapVerdict::Mint => {
            // No Bootstrap on the chain. A cache file already there is a keyset this deployment
            // minted and never sealed (the journal was lost or started over): keys are only ever
            // ADDED, so it is adopted and sealed rather than replaced. Otherwise mint.
            let key = match cached {
                Some(key) => key,
                None => {
                    // One key per deployment: a store that already keeps one is where it comes
                    // from; otherwise mint it, and keep it there too.
                    let held = match &store {
                        Some(calls) => crate::root::durability::stored_keyset(calls.as_ref())
                            .map_err(KeysetError::Store)?,
                        None => None,
                    };
                    let seed = match held {
                        Some(seed) => seed,
                        None => {
                            let seed = mint_seed_hex()?;
                            match &store {
                                Some(calls) => {
                                    crate::root::durability::keep_keyset(calls.as_ref(), &seed)
                                        .map_err(KeysetError::Store)?
                                }
                                None => seed,
                            }
                        }
                    };
                    busbar_kernel::durable::write_with(
                        &file,
                        format!("{seed}\n").as_bytes(),
                        busbar_kernel::durable::DurableOpts {
                            mode: Some(0o600),
                            exclusive: true,
                        },
                    )
                    .map_err(|e| KeysetError::Io {
                        file: file.clone(),
                        why: e.to_string(),
                    })?;
                    AuditSigningKey::from_hex_seed(&seed).map_err(|e| {
                        KeysetError::Store(format!("the deployment keyset is not one: {e}"))
                    })?
                }
            };
            let entry = Entry::new(
                RecordClass::Bootstrap,
                bootstrap_body(&fingerprint_of_signer(&key), key.key_id()),
            )
            .at(now, 0);
            durability
                .journal
                .append(token, at, &[entry])
                .map_err(|lost| KeysetError::Unsealed {
                    step: lost.step().as_str(),
                })?;
            sign_with(durability, key);
            Ok(KeysetSource::Minted { file })
        }
    }
}

/// [`bind`] with no data directory, over the configured store: the deployment keyset the store
/// keeps, minted into it by the deployment's first boot, and a `Bootstrap` sealing its fingerprint
/// on this node's chain the first time this chain is bound.
fn bind_in_store(
    durability: &mut Durability,
    calls: &dyn busbar_contract::store_calls::StoreCalls,
    token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<KeysetSource, KeysetError> {
    let prior = sealed_fingerprint(durability);
    let held = crate::root::durability::stored_keyset(calls).map_err(KeysetError::Store)?;
    let held = held
        .map(|seed| {
            AuditSigningKey::from_hex_seed(&seed).map_err(|e| {
                KeysetError::Store(format!("the store's deployment keyset is not one: {e}"))
            })
        })
        .transpose()?;
    let ours = held.as_ref().map(fingerprint_of_signer);
    match bootstrap(prior, ours) {
        BootstrapVerdict::AlreadyOurs => {
            sign_with(
                durability,
                held.expect("AlreadyOurs is answered only for a key the store holds"),
            );
            Ok(KeysetSource::Stored)
        }
        BootstrapVerdict::KeysetMissing => Err(KeysetError::StoreMissing {
            fingerprint: prior.expect("KeysetMissing is answered only over a sealed Bootstrap"),
        }),
        BootstrapVerdict::Mint => {
            // This chain has not sealed the deployment's key yet: the key another node (or a
            // predecessor whose chain the store did not keep) put in the store, or one minted now.
            let key = match held {
                Some(key) => key,
                None => {
                    let seed = crate::root::durability::keep_keyset(calls, &mint_seed_hex()?)
                        .map_err(KeysetError::Store)?;
                    AuditSigningKey::from_hex_seed(&seed).map_err(|e| {
                        KeysetError::Store(format!("the store's deployment keyset is not one: {e}"))
                    })?
                }
            };
            let entry = Entry::new(
                RecordClass::Bootstrap,
                bootstrap_body(&fingerprint_of_signer(&key), key.key_id()),
            )
            .at(now, 0);
            durability
                .journal
                .append(token, at, &[entry])
                .map_err(|lost| KeysetError::Unsealed {
                    step: lost.step().as_str(),
                })?;
            sign_with(durability, key);
            Ok(KeysetSource::Stored)
        }
    }
}

/// [`bind`] for a node with no store and no data directory: the keyset is ephemeral (PB-13).
///
/// # Errors
///
/// [`KeysetError::NoEntropy`] only.
pub fn bind_ephemeral(durability: &mut Durability) -> Result<KeysetSource, KeysetError> {
    let token = crate::root::kernel::new_kernel().durability_token();
    bind(durability, None, &token, StepName::Meter, 0)
}

#[cfg(test)]
#[path = "tests/keyset.rs"]
mod tests;
