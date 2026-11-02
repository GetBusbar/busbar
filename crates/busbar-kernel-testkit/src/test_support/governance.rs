// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{
    CredentialMeta, CredentialSecret, RecordStoreError, RecordStoreResult, SecretForm, VirtualKey,
};
use busbar_kernel::governance::{GovState, NewKeySpec};

pub const SK_SECRET_PREFIX: &str = "sk-bb-";
const VK_ID_PREFIX: &str = "vk_";
const VK_ID_HASH_PREFIX_LEN: usize = 16;

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

pub fn create_key(
    gov: &GovState,
    spec: NewKeySpec,
    now: u64,
) -> RecordStoreResult<(VirtualKey, String)> {
    let secret = generate_secret().store()?;
    let hash = busbar_contract::redacted::sha256_hex(secret.as_bytes());

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

pub fn create_key_with_aws(
    gov: &GovState,
    spec: NewKeySpec,
    now: u64,
) -> RecordStoreResult<(VirtualKey, String, String, String)> {
    let secret = generate_secret().store()?;
    let hash = busbar_contract::redacted::sha256_hex(secret.as_bytes());
    let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
    gov.ensure_id_free_for_hash(&id, &hash)?;

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
