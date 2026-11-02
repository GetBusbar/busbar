// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Legacy bearer and paired-credential fixtures, implemented on the kernel's existing public
//! store/cache API. A shipped kernel mints signed bindings; no fixture mint lives behind a feature.

use busbar_contract::records::{
    CredentialMeta, CredentialSecret, RecordStoreError, RecordStoreResult, SecretForm, VirtualKey,
};
use busbar_kernel::governance::{GovState, NewKeySpec};

/// Prefix of a legacy hashed bearer used only by fixtures.
pub const SK_SECRET_PREFIX: &str = "sk-bb-";
const VK_ID_PREFIX: &str = "vk_";
const VK_ID_HASH_PREFIX_LEN: usize = 16;

/// Draw the legacy bearer fixture's full 256-bit secret from the OS CSPRNG.
pub fn generate_secret() -> Result<String, getrandom::Error> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)?;
    Ok(format!("{SK_SECRET_PREFIX}{}", hex::encode(buf)))
}

trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, getrandom::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(format!("OS CSPRNG (getrandom) unavailable: {e}")))
    }
}

/// External fixture methods for an existing real governance instance.
pub trait GovStateFixtures {
    fn create_key(&self, spec: NewKeySpec, now: u64) -> RecordStoreResult<(VirtualKey, String)>;
    fn create_key_with_aws(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> RecordStoreResult<(VirtualKey, String, String, String)>;
}
impl GovStateFixtures for GovState {
    fn create_key(&self, spec: NewKeySpec, now: u64) -> RecordStoreResult<(VirtualKey, String)> {
        create_key(self, spec, now)
    }
    fn create_key_with_aws(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> RecordStoreResult<(VirtualKey, String, String, String)> {
        create_key_with_aws(self, spec, now)
    }
}

/// Seed the fixture through the real Store and refresh its real verification caches.
pub fn create_key(
    gov: &GovState,
    spec: NewKeySpec,
    now: u64,
) -> RecordStoreResult<(VirtualKey, String)> {
    // `?` converts a getrandom failure into a StoreError (see `From<getrandom::Error>`), so the
    // admin handler returns a 500 via its existing error_response path instead of panicking.
    let secret = generate_secret().store()?;
    let hash = busbar_contract::redacted::sha256_hex(secret.as_bytes());
    // `id` is a 64-bit prefix of the 256-bit secret hash, while `generation_hash` is the full hash with
    // a UNIQUE constraint. Two distinct secrets sharing the same 64-bit prefix would produce the
    // same `id` but different `generation_hash`; since `put_key` UPSERTs on the PRIMARY KEY `id`, the
    // second mint would silently OVERWRITE the first key's row (replacing its `generation_hash`),
    // invalidating the previously-issued secret with no error. Birthday-bound at ~2^32 keys, but
    // the failure is silent, so guard it explicitly: if the derived id already exists for a
    // DIFFERENT generation_hash, refuse rather than clobber an unrelated key. (A genuine retry that
    // somehow reproduces the same secret — and thus the same generation_hash — is idempotent and allowed
    // through, since it overwrites the row with identical data.)
    let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
    gov.ensure_id_free_for_hash(&id, &hash)?;
    let key = VirtualKey {
        id,
        generation_hash: hash,
        name: spec.name,
        allowed_scopes: busbar_kernel::governance::grant_scopes(
            spec.allowed_pools,
            spec.plane_scopes,
        ),
        enabled: true,
        created_at: now,
        group: spec.group,
        labels: spec.labels,
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    };
    gov.store().put_key(&key)?;
    gov.refresh()?;
    Ok((key, secret))
}

/// Seed the fixture through the real Store and refresh its real verification caches.
pub fn create_key_with_aws(
    gov: &GovState,
    spec: NewKeySpec,
    now: u64,
) -> RecordStoreResult<(VirtualKey, String, String, String)> {
    // `?` converts any getrandom failure into a StoreError (see `From<getrandom::Error>`), so the
    // admin handler returns a 500 via its existing error_response path instead of panicking.
    let secret = generate_secret().store()?;
    let hash = busbar_contract::redacted::sha256_hex(secret.as_bytes());
    let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
    gov.ensure_id_free_for_hash(&id, &hash)?;
    // The shape and kind the linked signed-request verifier states, as the test double holds
    // them (`test_support::issued`).
    let (kind, shape) = crate::test_support::issued::double();
    let (access_key_id, secret_access_key) =
        busbar_kernel::governance::issue_credential_for_test(&shape).store()?;
    let mut cred_raw = [0u8; 16];
    getrandom::fill(&mut cred_raw)
        .map_err(|e| RecordStoreError(format!("CSPRNG unavailable: {e}")))?;
    let cred_id = format!("cred_{}", hex::encode(cred_raw));
    let key = VirtualKey {
        id: id.clone(),
        generation_hash: hash,
        name: spec.name,
        allowed_scopes: busbar_kernel::governance::grant_scopes(
            spec.allowed_pools,
            spec.plane_scopes,
        ),
        enabled: true,
        created_at: now,
        group: spec.group,
        labels: spec.labels,
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    };
    // ATOMIC: persist the bearer key row and its paired credential in ONE transaction (see
    // `put_key_with_credential`). The previous two-call autocommit sequence could orphan an
    // inert key row if the credential write failed after the key write committed.
    gov.store().put_key_with_credential(
        &key,
        &CredentialSecret {
            meta: CredentialMeta {
                id: cred_id,
                key_id: id,
                kind,
                slot: 0,
                public_id: access_key_id.clone(),
                secret_form: SecretForm::Recoverable,
                created_at: now,
                updated_at: now,
                expires_at: None,
                revoked_at: None,
                revoke_reason: None,
                revision: 0,
            },
            secret: format!("v1:plain:{secret_access_key}"),
        },
    )?;
    gov.refresh()?;
    Ok((key, secret, access_key_id, secret_access_key))
}
