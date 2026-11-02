// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_kernel::registry::{bootstrap, BootstrapVerdict};
use busbar_kernel_audit::{AuditSigningKey, AuditVerifyingKey};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, RecordClass};

use crate::root::durability::Durability;

pub const CALLER_REF_MATERIAL: &[u8] = b"busbar deployment keyset: caller-ref material v1";

#[must_use]
pub fn fingerprint_of(key: &AuditVerifyingKey) -> [u8; 32] {
    let raw = hex::decode(key.public_key_hex()).unwrap_or_default();
    busbar_contract::abi::sdk::digest::sha256(&raw)
}

#[must_use]
pub fn fingerprint_of_signer(key: &AuditSigningKey) -> [u8; 32] {
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex())
        .expect("a signing key's own public half is a valid key");
    fingerprint_of(&public)
}

/// Where this node's keyset came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetSource {
    /// Minted for a helper process with no Store, written nowhere.
    Ephemeral,
    /// The deployment keyset kept by the configured Store, including its first boot.
    Stored,
}

/// Why a boot could not bind the deployment keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetError {
    /// The `Bootstrap` record could not be made durable.
    Unsealed {
        /// The journal step that lost the write.
        step: &'static str,
    },
    /// The OS CSPRNG gave no bytes, so no key could be minted.
    NoEntropy,
    /// A `Bootstrap` is on the chain the Store kept, and the Store does not yield
    /// the keyset whose fingerprint it sealed.
    StoreMissing {
        /// The fingerprint the `Bootstrap` record sealed.
        fingerprint: [u8; 32],
    },
    /// The configured store would not read or keep the deployment keyset.
    Store(String),
}

impl std::fmt::Display for KeysetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

#[must_use]
pub fn bootstrap_body(fingerprint: &[u8; 32], key_id: &str) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.bytes(fingerprint).text(key_id);
    body.finish()
}

#[must_use]
pub fn bootstrap_fingerprint(body: &[u8]) -> Option<[u8; 32]> {
    BodyReader::new(body).bytes()?.try_into().ok()
}

fn mint_seed_hex() -> Result<String, KeysetError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| KeysetError::NoEntropy)?;
    let text = hex::encode(seed);
    seed.fill(0);
    std::hint::black_box(&seed);
    Ok(text)
}

fn sealed_fingerprint(durability: &Durability) -> Result<Option<[u8; 32]>, KeysetError> {
    let records = match durability.chain() {
        Ok(Ok(records)) => records,
        Ok(Err(broken)) => {
            return Err(KeysetError::Store(format!(
                "the journal does not verify: {broken}"
            )))
        }
        Err(e) => return Err(KeysetError::Store(durability.unreadable(&e))),
    };
    Ok(records
        .iter()
        .filter(|r| r.class == RecordClass::Bootstrap)
        .max_by_key(|r| r.node_seq)
        .and_then(|r| bootstrap_fingerprint(&r.body)))
}

fn sign_with(durability: &mut Durability, key: AuditSigningKey) {
    durability.record = std::mem::take(&mut durability.record).signing_with(key);
}

pub fn bind(
    durability: &mut Durability,
    _data_dir: Option<&Path>,
    token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<KeysetSource, KeysetError> {
    if let Some(calls) = durability
        .lane()
        .map(crate::root::durability::JournalLane::calls)
    {
        return bind_in_store(durability, calls.as_ref(), token, at, now);
    }
    let key = AuditSigningKey::from_hex_seed(&mint_seed_hex()?)
        .expect("a freshly minted seed is 64 hex characters");
    sign_with(durability, key);
    Ok(KeysetSource::Ephemeral)
}

fn bind_in_store(
    durability: &mut Durability,
    calls: &dyn busbar_contract::store_calls::StoreCalls,
    token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<KeysetSource, KeysetError> {
    let prior = sealed_fingerprint(durability)?;
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

#[cfg(test)]
pub fn bind_ephemeral(durability: &mut Durability) -> Result<KeysetSource, KeysetError> {
    let token = crate::root::kernel::new_kernel().durability_token();
    bind(durability, None, &token, StepName::Meter, 0)
}

#[cfg(test)]
#[path = "tests/keyset.rs"]
mod tests;
