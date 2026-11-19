// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::secure::{SecureArray, SecureString};
use busbar_kernel::persistence::boot_identity::BootIdentity;

use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_kernel::registry::{bootstrap, BootstrapVerdict};
use busbar_kernel_audit::{
    AuditKeySet, AuditSigningKey, AuditVerifyingKey, BootstrapGrant, LiveSigner, NotaryGrant,
};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, RecordClass};

use crate::root::durability::Durability;

pub(crate) const CALLER_REF_MATERIAL: &[u8] = b"busbar deployment keyset: caller-ref material v1";

#[must_use]
pub(crate) fn fingerprint_of(key: &AuditVerifyingKey) -> [u8; 32] {
    let raw = hex::decode(key.public_key_hex()).expect("AuditVerifyingKey holds valid hex");
    busbar_contract::digest::sha256(&raw)
}

#[must_use]
pub(crate) fn fingerprint_of_signer(key: &AuditSigningKey) -> [u8; 32] {
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex())
        .expect("a signing key's own public half is a valid key");
    fingerprint_of(&public)
}

/// Where this node's keyset came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetSource {
    /// Minted for a helper process with no Store, written nowhere.
    #[cfg(test)]
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
    /// An exact staged Bootstrap remains owned by this journal and may be retried.
    PendingOriginal { step: &'static str },
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
            KeysetError::PendingOriginal { step } => write!(
                f,
                "the original deployment-keyset Bootstrap remains pending at step {step}"
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
pub(crate) fn bootstrap_body(fingerprint: &[u8; 32], key_id: &str) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.bytes(fingerprint).text(key_id);
    body.finish()
}

#[must_use]
pub(crate) fn bootstrap_fingerprint(body: &[u8]) -> Option<[u8; 32]> {
    BodyReader::new(body).bytes()?.try_into().ok()
}

fn mint_seed_hex() -> Result<SecureString, KeysetError> {
    let mut seed = SecureArray::<32>::zeroed();
    busbar_contract::crypto::fill(&mut seed[..]).map_err(|_| KeysetError::NoEntropy)?;
    Ok(SecureString::from(hex::encode(&seed[..])))
}

async fn sealed_fingerprint(durability: &Durability) -> Result<Option<[u8; 32]>, KeysetError> {
    let records = match durability.chain().await {
        Ok(Ok(records)) => records,
        Ok(Err(broken)) => {
            return Err(KeysetError::Store(format!(
                "the journal does not verify: {broken}"
            )));
        }
        Err(e) => return Err(KeysetError::Store(durability.unreadable(&e))),
    };
    match records
        .iter()
        .filter(|record| record.class == RecordClass::Bootstrap)
        .max_by_key(|record| record.node_seq)
    {
        None => Ok(None),
        Some(record) => bootstrap_fingerprint(&record.body)
            .map(Some)
            .ok_or_else(|| {
                KeysetError::Store("the persisted Bootstrap has no valid keyset fingerprint".into())
            }),
    }
}

#[cfg(test)]
fn sign_with(durability: &mut Durability, key: AuditSigningKey) {
    durability.record = std::mem::take(&mut durability.record).signing_with(key);
}

fn journal_failure(
    error: busbar_kernel::persistence::journal::runtime::RuntimeError,
    at: StepName,
) -> KeysetError {
    use busbar_contract::persistence::Failure;
    use busbar_kernel::persistence::journal::runtime::RuntimeError;
    match error {
        RuntimeError::Pending
        | RuntimeError::Backend(Failure::Unavailable | Failure::Overloaded) => {
            KeysetError::PendingOriginal { step: at.as_str() }
        }
        _ => KeysetError::Unsealed { step: at.as_str() },
    }
}

/// Bind only to the configured native identity owner. Pending original journal
/// runs are resolved before reading Bootstrap, so a cancelled or unknown first
/// bind never stages a replacement Bootstrap on retry. Returns the deployment key
/// itself; the callers below decide what the book keeps of it.
async fn bind_key(
    durability: &mut Durability,
    identity: &BootIdentity,
    _token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<(KeysetSource, AuditSigningKey), KeysetError> {
    durability
        .journal
        .flush()
        .await
        .map_err(|error| journal_failure(error, at))?;
    let prior = sealed_fingerprint(durability).await?;
    let held = identity
        .stored_keyset()
        .await
        .map_err(KeysetError::Store)?
        .map(SecureString::from);
    let held = held
        .map(|seed| {
            AuditSigningKey::from_hex_seed(&seed)
                .map_err(|_| KeysetError::Store("the stored deployment keyset is invalid".into()))
        })
        .transpose()?;
    let ours = held.as_ref().map(fingerprint_of_signer);
    match bootstrap(prior, ours) {
        BootstrapVerdict::AlreadyOurs => Ok((
            KeysetSource::Stored,
            held.expect("AlreadyOurs is answered only for a key the store holds"),
        )),
        BootstrapVerdict::KeysetMissing => Err(KeysetError::StoreMissing {
            fingerprint: prior.expect("KeysetMissing is answered only over a sealed Bootstrap"),
        }),
        BootstrapVerdict::Mint => {
            let key = match held {
                Some(key) => key,
                None => {
                    let offered = mint_seed_hex()?;
                    let seed = SecureString::from(
                        identity
                            .keep_keyset(&offered)
                            .await
                            .map_err(KeysetError::Store)?,
                    );
                    AuditSigningKey::from_hex_seed(&seed).map_err(|_| {
                        KeysetError::Store("the stored deployment keyset is invalid".into())
                    })?
                }
            };
            let entry = Entry::new(
                RecordClass::Bootstrap,
                bootstrap_body(&fingerprint_of_signer(&key), key.key_id()),
            )
            .at(now, 0);
            let original = durability
                .journal
                .stage_run(&[entry])
                .map_err(|_| KeysetError::Unsealed { step: at.as_str() })?;
            durability
                .journal
                .confirm(&original)
                .await
                .map_err(|error| journal_failure(error, at))?;
            Ok((KeysetSource::Stored, key))
        }
    }
}

/// WHAT BINDING THE KEYSET HANDS THE BOOT (SEALING-FIX §5.3 layer 1): the caller-ref material
/// derived from the key before the split, and the key's whole signing power as its two grants.
/// The book keeps only the public half (`AuditChain::bound_to`); nothing on the request path can
/// reach a grant.
pub(crate) struct BoundKey {
    /// Full supported deployment history: native deployment keys are kept once and their
    /// persisted Bootstrap fingerprint is verified before this public projection is created.
    /// Audit-key replacement requires a separate historical-key lifecycle; no active-key fallback.
    pub(crate) verification_keys: AuditKeySet,
    /// `derived_secret(CALLER_REF_MATERIAL)`, for governance's deployment caller ref.
    pub(crate) caller_ref: [u8; 32],
    /// The live notary's grant.
    pub(crate) notary: NotaryGrant,
    /// The Bootstrap signer's grant.
    pub(crate) bootstrap: BootstrapGrant,
}

impl std::fmt::Debug for BoundKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundKey")
            .field("notary", &self.notary)
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

/// BIND THE DEPLOYMENT KEYSET AND SPLIT THE KEY (production): the book is bound to the public
/// half, and the key is consumed into the notary's and the Bootstrap signer's grants, after the
/// crypto backend approved the signer (a refusal stops boot).
pub(crate) async fn bind_split(
    durability: &mut Durability,
    identity: &BootIdentity,
    token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<(KeysetSource, BoundKey), KeysetError> {
    let (source, key) = bind_key(durability, identity, token, at, now).await?;
    let public = AuditVerifyingKey::from_hex(&key.public_key_hex())
        .map_err(|_| KeysetError::Store("the deployment key's public half is invalid".into()))?;
    let mut verification_keys = AuditKeySet::new();
    verification_keys.insert(public.clone());
    let caller_ref = key.derived_secret(CALLER_REF_MATERIAL);
    let deployment_id = identity
        .keep_deployment_id()
        .await
        .map_err(KeysetError::Store)?;
    super::records_capture::bind_user_key(key.derived_key(
        deployment_id.as_bytes(),
        super::records_capture::USER_KEY_INFO,
    ));
    let (notary, bootstrap) = key
        .into_grants(LiveSigner::SameAsBootstrap)
        .map_err(|e| KeysetError::Store(e.to_string()))?;
    durability.record = std::mem::take(&mut durability.record).bound_to(public);
    Ok((
        source,
        BoundKey {
            verification_keys,
            caller_ref,
            notary,
            bootstrap,
        },
    ))
}

/// Bind the keyset as a LEGACY-SIGNING book (test builds only, SEALING-FIX §3.2 "The legacy
/// builder"): the fixtures that read per-line signatures keep them. Production binds through
/// `bind_split`.
#[cfg(test)]
pub async fn bind(
    durability: &mut Durability,
    identity: &BootIdentity,
    token: &Grant<DurableWrite>,
    at: StepName,
    now: u64,
) -> Result<KeysetSource, KeysetError> {
    let (source, key) = bind_key(durability, identity, token, at, now).await?;
    sign_with(durability, key);
    Ok(source)
}

#[cfg(test)]
pub(crate) fn bind_ephemeral(durability: &mut Durability) -> Result<KeysetSource, KeysetError> {
    let seed = mint_seed_hex()?;
    let key = AuditSigningKey::from_hex_seed(&seed).expect("a freshly minted seed is valid");
    sign_with(durability, key);
    Ok(KeysetSource::Ephemeral)
}

#[cfg(test)]
#[path = "tests/keyset.rs"]
mod tests;
