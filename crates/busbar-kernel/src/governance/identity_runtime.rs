// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native identity claims and confirmed, revision-ordered cache publication.
use super::*;
use crate::governance::persistence::identity::{IdentityCommit, IdentitySnapshot};
use crate::persistence::facade::CoreStore;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum IdentityClaimKey {
    Subject(String),
    Key(String),
    MintOwner(String),
    Credential(String),
}
pub type IdentityMutationGuard<'a> = claims::AsyncClaim<'a, IdentityClaimKey>;

impl GovState {
    pub(super) async fn identity_claim(&self, key: IdentityClaimKey) -> IdentityMutationGuard<'_> {
        if let Some(guard) = self.identity_claims.try_claim(key.clone()) {
            return guard;
        }
        #[cfg(test)]
        if let Some(observer) = self.identity_wait_observer.lock().unwrap().as_ref() {
            observer.store(true, std::sync::atomic::Ordering::Release);
        }
        self.identity_claims.claim_async(key).await
    }
    pub async fn identity_key_guard(&self, id: &str) -> IdentityMutationGuard<'_> {
        self.identity_claim(IdentityClaimKey::Key(id.into())).await
    }
    pub async fn identity_mint_guard(&self, minter: &str) -> IdentityMutationGuard<'_> {
        self.identity_claim(IdentityClaimKey::MintOwner(minter.into()))
            .await
    }
    #[cfg(test)]
    pub(crate) fn observe_identity_mutation_wait(&self) -> Arc<std::sync::atomic::AtomicBool> {
        let observer = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *self.identity_wait_observer.lock().unwrap() = Some(observer.clone());
        observer
    }
    pub async fn new_with_core(
        core: Arc<CoreStore>,
        admin_token: Option<String>,
        signer: Option<crate::governance::signing::TokenSigner>,
    ) -> RecordStoreResult<Self> {
        core.register_claim_scope(crate::auth::AUTH_REPLAY_OWNER, crate::auth::AUTH_REPLAY)
            .map_err(|error| {
                RecordStoreError(format!("auth replay maintenance scope: {error:?}"))
            })?;
        core.identity().settle_pending().await?;
        let snapshot = core.identity().snapshot().await?;
        let denied = snapshot.denied.iter().cloned().collect();
        let caches = Arc::new(RwLock::new(cache_snapshot(snapshot)));
        let order = Arc::new(CacheOrder::default());
        let denylist = revocation::RevocationSync::native(
            core.clone(),
            denied,
            crate::store::now(),
            caches.clone(),
            order.clone(),
        );
        Self::from_identity_cache(core, admin_token, signer, caches, order, denylist)
    }
    pub async fn refresh_async(&self) -> RecordStoreResult<()> {
        reload_native(
            self.core_store()?,
            &self.caches,
            &self.refresh_order,
            &self.denylist,
        )
        .await
    }
    pub async fn all_keys_async(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.core.identity().list_keys().await
    }

    /// Apply only exact rows returned after a native Applied decision. Tombstone
    /// revisions survive eviction, and older same-key deltas cannot resurrect it.
    pub(in crate::governance) fn publish_identity(&self, commit: IdentityCommit) {
        self.refresh_order.patch(|| {
            let mut cache = self.caches_write();
            cache.revision = cache.revision.max(commit.revision);
            for subject in commit.denied {
                self.denylist.insert(&subject);
            }
            for key in commit.keys {
                if cache
                    .key_revisions
                    .get(&key.id)
                    .is_some_and(|rev| *rev > key.revision)
                {
                    continue;
                }
                cache.key_revisions.insert(key.id.clone(), key.revision);
                if key.deleted_at.is_some() {
                    cache.by_id.remove(&key.id);
                    cache
                        .by_credential
                        .retain(|_, (owner, _)| owner.id != key.id);
                } else {
                    let key = Arc::new(key);
                    for (owner, _) in cache.by_credential.values_mut() {
                        if owner.id == key.id {
                            *owner = key.clone();
                        }
                    }
                    cache.by_id.insert(key.id.clone(), key);
                }
            }
            for credential in commit.credentials {
                if cache
                    .credential_revisions
                    .get(&credential.meta.id)
                    .is_some_and(|rev| *rev > credential.meta.revision)
                {
                    continue;
                }
                cache
                    .credential_revisions
                    .insert(credential.meta.id.clone(), credential.meta.revision);
                cache
                    .by_credential
                    .retain(|_, (_, old)| old.meta.id != credential.meta.id);
                if credential.meta.is_live(crate::store::now()) {
                    if let Some(owner) = cache.by_id.get(&credential.meta.key_id).cloned() {
                        if cache
                            .by_credential
                            .get(&(
                                credential.meta.kind.clone(),
                                credential.meta.public_id.clone(),
                            ))
                            .is_some_and(|(_, current)| {
                                current.meta.revision > credential.meta.revision
                            })
                        {
                            continue;
                        }
                        cache.by_credential.insert(
                            (
                                credential.meta.kind.clone(),
                                credential.meta.public_id.clone(),
                            ),
                            (owner, credential),
                        );
                    }
                }
            }
        });
    }
    pub async fn mint_signed_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, Secret<String>), MintError> {
        let claim = self
            .identity_mint_guard(spec.minted_by.as_deref().unwrap_or(""))
            .await;
        self.mint_signed_claimed_async(spec, exp, now, &claim).await
    }
    pub async fn mint_signed_claimed_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        _claim: &IdentityMutationGuard<'_>,
    ) -> Result<(VirtualKey, Secret<String>), MintError> {
        self.mint_signed_scoped_async(spec, exp, now, None).await
    }
    pub async fn mint_signed_for_audience_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        audience: &str,
    ) -> Result<(VirtualKey, Secret<String>), MintError> {
        let claim = self
            .identity_mint_guard(spec.minted_by.as_deref().unwrap_or(""))
            .await;
        self.mint_signed_for_audience_claimed_async(spec, exp, now, audience, &claim)
            .await
    }
    pub async fn mint_signed_for_audience_claimed_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        audience: &str,
        _claim: &IdentityMutationGuard<'_>,
    ) -> Result<(VirtualKey, Secret<String>), MintError> {
        if audience.trim().is_empty() {
            return Err(RecordStoreError("audience must be a nonempty string".into()).into());
        }
        self.mint_signed_scoped_async(spec, exp, now, Some(audience))
            .await
    }
    async fn mint_signed_scoped_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        audience: Option<&str>,
    ) -> Result<(VirtualKey, Secret<String>), MintError> {
        let material = self.signing_material().ok_or_else(|| {
            RecordStoreError(
                "signed-token minting is unavailable: no signing key is configured".into(),
            )
        })?;
        let (binding, generation) = signed_binding(spec, now)?;
        let _key = self.identity_key_guard(&binding.id).await;
        let commit = self.core.identity().compare_key(None, &binding).await?;
        let binding = committed_key(&commit, &binding.id)?;
        self.publish_identity(commit);
        let token = match audience {
            Some(a) => {
                material
                    .signer
                    .mint_for_audience(&binding.id, exp, Some(&generation), a, None)
            }
            None => material.signer.mint(&binding.id, exp, Some(&generation)),
        };
        Ok((binding, token.into()))
    }
    pub async fn mint_signed_with_credential_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        kind: &str,
        shape: &busbar_contract::auth_calls::IssuedShape,
    ) -> Result<(VirtualKey, Secret<String>, String, Secret<String>), MintError> {
        let claim = self
            .identity_mint_guard(spec.minted_by.as_deref().unwrap_or(""))
            .await;
        self.mint_signed_with_credential_claimed_async(spec, exp, now, kind, shape, &claim)
            .await
    }
    pub async fn mint_signed_with_credential_claimed_async(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        kind: &str,
        shape: &busbar_contract::auth_calls::IssuedShape,
        _claim: &IdentityMutationGuard<'_>,
    ) -> Result<(VirtualKey, Secret<String>, String, Secret<String>), MintError> {
        let material = self.signing_material().ok_or_else(|| {
            RecordStoreError(
                "signed-token minting is unavailable: no signing key is configured".into(),
            )
        })?;
        let keys = self
            .at_rest_keys()
            .ok_or_else(|| RecordStoreError(super::at_rest::NO_KEY_REFUSAL.into()))?;
        let (binding, generation) = signed_binding(spec, now)?;
        let _key = self.identity_key_guard(&binding.id).await;
        let (public_id, plain) = super::issue_credential(shape).store()?;
        let plain = Secret::new(plain);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|e| RecordStoreError(format!("CSPRNG unavailable: {e}")))?;
        let meta = CredentialMeta {
            id: format!("cred_{}", hex::encode(random)),
            key_id: binding.id.clone(),
            kind: kind.into(),
            slot: 0,
            public_id: public_id.clone(),
            secret_form: SecretForm::Recoverable,
            created_at: now,
            updated_at: now,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        };
        let secret = keys
            .seal(&meta, plain.expose(&crate::seal::lend()).as_bytes())
            .map_err(RecordStoreError)?;
        let commit = self
            .core
            .identity()
            .put_key_with_credential(
                &binding,
                &CredentialSecret {
                    meta,
                    secret: secret.into(),
                },
            )
            .await?;
        let binding = committed_key(&commit, &binding.id)?;
        self.publish_identity(commit);
        let token = material.signer.mint(&binding.id, exp, Some(&generation));
        Ok((binding, token.into(), public_id, plain))
    }
    pub async fn rotate_key_outcome_async(
        &self,
        id: &str,
        exp: u64,
    ) -> Result<Option<RotatedCredential>, KeyMutationError> {
        let claim = self.identity_key_guard(id).await;
        self.rotate_key_outcome_claimed_async(id, exp, &claim).await
    }
    pub async fn rotate_key_outcome_claimed_async(
        &self,
        id: &str,
        exp: u64,
        _claim: &IdentityMutationGuard<'_>,
    ) -> Result<Option<RotatedCredential>, KeyMutationError> {
        let Some(before) = self
            .core
            .identity()
            .get_key(id)
            .await?
            .filter(|key| key.deleted_at.is_none())
        else {
            return Ok(None);
        };
        let material = self.signing_material().ok_or_else(|| {
            RecordStoreError(
                "cannot rotate a signed-token key: no signing key is configured".into(),
            )
        })?;
        let generation = generate_binding_generation().store()?;
        let mut key = before.clone();
        key.generation_hash = binding_marker(id, &generation);
        let commit = self
            .core
            .identity()
            .compare_key(Some(&before), &key)
            .await?;
        let key = committed_key(&commit, id)?;
        self.publish_identity(commit);
        Ok(Some(RotatedCredential {
            token: material.signer.mint(id, exp, Some(&generation)).into(),
            key,
            exp,
        }))
    }
    pub async fn update_key_outcome_async(
        &self,
        id: &str,
        enabled: Option<bool>,
        group: Option<Option<String>>,
    ) -> Result<Option<VirtualKey>, KeyMutationError> {
        let claim = self.identity_key_guard(id).await;
        self.update_key_outcome_claimed_async(id, enabled, group, &claim)
            .await
    }
    pub async fn update_key_outcome_claimed_async(
        &self,
        id: &str,
        enabled: Option<bool>,
        group: Option<Option<String>>,
        _claim: &IdentityMutationGuard<'_>,
    ) -> Result<Option<VirtualKey>, KeyMutationError> {
        let Some(before) = self
            .core
            .identity()
            .get_key(id)
            .await?
            .filter(|key| key.deleted_at.is_none())
        else {
            return Ok(None);
        };
        let mut key = before.clone();
        if let Some(enabled) = enabled {
            key.enabled = enabled;
        }
        if let Some(group) = group {
            key.group = group;
        }
        let commit = self
            .core
            .identity()
            .compare_key(Some(&before), &key)
            .await?;
        let key = committed_key(&commit, id)?;
        self.publish_identity(commit);
        Ok(Some(key))
    }
    pub async fn delete_key_outcome_async(&self, id: &str) -> Result<(), KeyMutationError> {
        let claim = self.identity_key_guard(id).await;
        self.delete_key_outcome_claimed_async(id, &claim).await
    }
    pub async fn delete_key_outcome_claimed_async(
        &self,
        id: &str,
        _claim: &IdentityMutationGuard<'_>,
    ) -> Result<(), KeyMutationError> {
        let _correction = self.correction_claims.claim_async(id.into()).await;
        self.settle_correction_for_delete_async(id).await?;
        let _budget = self.hold_budget_flush_deletion(id);
        self.settle_budget_flush_for_delete_async(id).await?;
        let commit = self.core.identity().delete_key(id).await?;
        let revision = commit.revision;
        self.publish_identity(commit);
        self.refresh_order.patch(|| {
            let mut cache = self.caches_write();
            cache
                .key_revisions
                .entry(id.into())
                .and_modify(|held| *held = (*held).max(revision))
                .or_insert(revision);
            cache.by_id.remove(id);
            cache.by_credential.retain(|_, (owner, _)| owner.id != id);
        });
        // Pending money custody was settled before the confirmed tombstone.
        // Only the local memo/cell is retired; historical ledgers stay durable.
        let mut cells = self.budget.write(id);
        if !cells.get(id).is_some_and(|cell| cell.correction.is_some()) {
            cells.remove(id);
        }
        drop(cells);
        self.money_view.forget(id);
        Ok(())
    }
    pub async fn revoke_async(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        let claim = self.identity_key_guard(id).await;
        self.revoke_claimed_async(id, reason, &claim).await
    }
    pub async fn revoke_claimed_async(
        &self,
        id: &str,
        reason: &str,
        _claim: &IdentityMutationGuard<'_>,
    ) -> RecordStoreResult<()> {
        let identity = self.core.identity();
        let commit = identity.add_denylist(id, reason).await?;
        self.publish_identity(commit);
        self.refresh_order.patch(|| self.denylist.insert(id));
        for meta in identity.list_credentials(id).await? {
            if meta.revoked_at.is_none() {
                let commit = identity.revoke_credential(&meta.id, reason).await?;
                self.publish_identity(commit);
            }
        }
        if let Some(before) = identity
            .get_key(id)
            .await?
            .filter(|key| key.deleted_at.is_none())
        {
            let mut key = before.clone();
            key.enabled = false;
            key.generation_hash = binding_marker(id, &generate_binding_generation().store()?);
            let commit = identity.compare_key(Some(&before), &key).await?;
            self.publish_identity(commit);
        }
        Ok(())
    }
    pub async fn revoke_credential_async(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        let _claim = self
            .identity_claim(IdentityClaimKey::Credential(id.into()))
            .await;
        let commit = self.core.identity().revoke_credential(id, reason).await?;
        self.publish_identity(commit);
        Ok(())
    }
    pub async fn rewrap_credentials_async(
        &self,
        now: u64,
    ) -> RecordStoreResult<super::at_rest::Rewrap> {
        // A landed lost reply can already look freshly sealed. Resolve its original
        // receipt before stale filtering, and publish only the canonical snapshot.
        self.refresh_async().await?;
        if self.at_rest_keys().is_none() {
            return Ok(Default::default());
        }
        self.rewrap_rows_async(self.core.identity().list_credentials_since(0).await?, now)
            .await
    }
    pub async fn rewrap_rows_async(
        &self,
        rows: Vec<CredentialSecret>,
        _now: u64,
    ) -> RecordStoreResult<super::at_rest::Rewrap> {
        let Some(keys) = self.at_rest_keys() else {
            return Ok(Default::default());
        };
        let mut pass = super::at_rest::Rewrap::default();
        for row in rows {
            if row.meta.revoked_at.is_some() {
                continue;
            }
            let Some(plain) = super::at_rest::stale(&keys, &row.meta, &row.secret) else {
                continue;
            };
            let _claim = self.identity_key_guard(&row.meta.key_id).await;
            let sealed = keys
                .seal(&row.meta, plain.as_bytes())
                .map_err(RecordStoreError)?;
            let commit = self.core.identity().rewrap_committed(&row, &sealed).await?;
            if commit.changed {
                pass.resealed += 1;
                self.publish_identity(commit);
            } else {
                pass.pending += 1;
            }
        }
        if pass.resealed > 0 {
            crate::audit_ring::AUDIT.record_by(
                "credential.at_rest.rewrap",
                &format!("kid:{} rows:{}", keys.kid(), pass.resealed),
                crate::audit_ring::OUTCOME_APPLIED,
                "busbar",
            );
        }
        Ok(pass)
    }
}

pub(super) fn committed_key(commit: &IdentityCommit, id: &str) -> RecordStoreResult<VirtualKey> {
    commit
        .keys
        .iter()
        .find(|key| key.id == id)
        .cloned()
        .ok_or_else(|| RecordStoreError("confirmed identity change omitted its key".into()))
}

fn cache_snapshot(snapshot: IdentitySnapshot) -> GovCaches {
    let key_revisions = snapshot
        .keys
        .iter()
        .map(|key| (key.id.clone(), key.revision))
        .collect();
    let credential_revisions = snapshot
        .credentials
        .iter()
        .map(|cred| (cred.meta.id.clone(), cred.meta.revision))
        .collect();
    let by_id: HashMap<_, _> = snapshot
        .keys
        .into_iter()
        .filter(|key| key.deleted_at.is_none())
        .map(|key| (key.id.clone(), Arc::new(key)))
        .collect();
    let by_credential = snapshot
        .credentials
        .into_iter()
        .filter(|cred| cred.meta.is_live(crate::store::now()))
        .filter_map(|cred| {
            by_id.get(&cred.meta.key_id).map(|key| {
                (
                    (cred.meta.kind.clone(), cred.meta.public_id.clone()),
                    (key.clone(), cred),
                )
            })
        })
        .collect();
    GovCaches {
        revision: snapshot.revision,
        key_revisions,
        credential_revisions,
        by_id,
        by_credential,
    }
}
pub(crate) async fn reload_native(
    core: &CoreStore,
    caches: &RwLock<GovCaches>,
    order: &CacheOrder,
    denylist: &revocation::RevocationSync,
) -> RecordStoreResult<()> {
    loop {
        let ticket = order.ticket();
        let snapshot = core.identity().snapshot_for_refresh().await?;
        let denied = snapshot.denied.clone();
        let mut fresh = cache_snapshot(snapshot);
        match order.turn(ticket) {
            CacheTurn::Swap(_turn) => {
                let mut current = caches.write().unwrap_or_else(|p| p.into_inner());
                if fresh.revision < current.revision {
                    return Ok(());
                }
                for (id, revision) in &current.key_revisions {
                    fresh
                        .key_revisions
                        .entry(id.clone())
                        .and_modify(|held| *held = (*held).max(*revision))
                        .or_insert(*revision);
                }
                for (id, revision) in &current.credential_revisions {
                    fresh
                        .credential_revisions
                        .entry(id.clone())
                        .and_modify(|held| *held = (*held).max(*revision))
                        .or_insert(*revision);
                }
                for subject in denied {
                    denylist.insert(&subject);
                }
                *current = fresh;
                return Ok(());
            }
            CacheTurn::Stale => return Ok(()),
            CacheTurn::Reload => continue,
        }
    }
}
