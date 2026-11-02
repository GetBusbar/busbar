use super::*;

impl GovState {
    #[cfg(test)]
    pub(crate) fn observe_self_mint_wait(
        &self,
        user_sub: &str,
    ) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.mutation_claims
            .observe_wait(MutationKey::Subject(user_sub.to_string()))
    }

    fn derive_self_subject(seed: &[u8; 32], user_sub: &str, epoch: u64) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, seed);
        let msg = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}#{epoch}");
        let tag = ring::hmac::sign(&key, msg.as_bytes());
        format!("{VK_ID_PREFIX}{}", hex::encode(&tag.as_ref()[..16]))
    }

    fn current_self_binding(&self, user_sub: &str) -> Option<Arc<VirtualKey>> {
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        self.caches_read()
            .by_id
            .values()
            .find(|k| {
                k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str())
            })
            .cloned()
    }

    fn read_self_binding(&self, id: &str, user_sub: &str) -> RecordStoreResult<Arc<VirtualKey>> {
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        let key = self
            .store
            .get_key(id)?
            .filter(|k| {
                k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str())
            })
            .map(Arc::new)
            .ok_or_else(|| {
                RecordStoreError("self-serve binding changed; retry the request".into())
            })?;
        self.patch_key_in_caches(key.clone());
        Ok(key)
    }

    fn self_mint_refusal(&self, user_sub: &str, provider: &str) -> Option<SelfMintRefusal> {
        if !self.self_mint_holds() {
            return None;
        }
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        let caches = self.caches_read();
        let rows = caches.by_id.values().filter(|k| {
            k.deleted_at.is_none()
                && (k.group.as_deref() == Some(group.as_str())
                    || k.idp_subject.as_deref() == Some(user_sub))
        });
        let mut refusal = None;
        for k in rows {
            if !k.enabled {
                return Some(SelfMintRefusal::Disabled);
            }
            if k.idp_provider.as_deref().is_some_and(|p| p != provider) {
                refusal = Some(SelfMintRefusal::OtherProvider);
            }
        }
        refusal
    }

    fn self_mint_holds(&self) -> bool {
        self.self_mint_holds
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn hold_self_mint_state(&self) {
        self.self_mint_holds
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn first_free_self_epoch(
        &self,
        seed: &[u8; 32],
        user_sub: &str,
        from: u64,
    ) -> RecordStoreResult<(String, u64)> {
        const MAX_PROBES: u32 = 64;
        let mut stride = 0u64;
        for _ in 0..MAX_PROBES {
            let epoch = from.saturating_add(stride);
            let id = Self::derive_self_subject(seed, user_sub, epoch);

            let holds = self.self_mint_holds();
            let occupied = self
                .store
                .get_key(&id)?
                .is_some_and(|k| holds || k.deleted_at.is_some());
            if !occupied {
                return Ok((id, epoch));
            }
            stride = if stride == 0 {
                1
            } else {
                stride.saturating_mul(2)
            };
        }
        Err(RecordStoreError(format!(
            "self-serve binding: {MAX_PROBES} probes from epoch {from} all landed on existing \
             rows; refusing to write over a key id already in use"
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn write_self_binding(
        &self,
        material: &SigningMaterial,
        user_sub: &str,
        provider: &str,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        epoch: u64,
        exp: u64,
        now: u64,
    ) -> RecordStoreResult<(VirtualKey, String)> {
        let seed = material.signer.secret_bytes();
        let (id, epoch) = self.first_free_self_epoch(&seed, user_sub, epoch)?;
        let generation = epoch.to_string();
        let binding = VirtualKey {
            id: id.clone(),
            generation_hash: binding_marker(&id, &generation),
            name: format!("self-serve key ({user_sub})"),

            allowed_scopes,
            enabled: true,
            created_at: now,
            group: Some(format!("{SELF_KEY_GROUP_PREFIX}{user_sub}")),

            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 0,

            idp_subject: Some(user_sub.to_string()),
            binding_mode: Some(SELF_KEY_BINDING_MODE.to_string()),

            idp_provider: Some(provider.to_string()),
            ..Default::default()
        };
        self.store.put_key(&binding)?;
        let token = material.signer.mint(&id, exp, Some(&generation));
        Ok((binding, token))
    }

    pub fn issue_self(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let scopes = crate::governance::pool_scopes(allowed_pools);
        self.issue_self_scoped(user_sub, provider, scopes, exp, now)
    }

    pub fn issue_self_scoped(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let Some(material) = self.signing_material() else {
            return Err(RecordStoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            )
            .into());
        };

        let _mint = self
            .mutation_claims
            .claim_checked(MutationKey::Subject(user_sub.to_string()))
            .ok_or_else(|| RecordStoreError("reentrant self-serve mutation refused".into()))?;
        if let Some(refusal) = self.self_mint_refusal(user_sub, provider) {
            return Err(SelfMintError::Refused(refusal));
        }
        match self.current_self_binding(user_sub) {
            Some(existing) => {
                let _key = self.claim_key_mutation(&existing.id)?;
                let existing = self.read_self_binding(&existing.id, user_sub)?;

                let new_scopes = allowed_scopes.clone();

                let adopt = existing.idp_provider.is_none();
                if new_scopes != existing.allowed_scopes || adopt {
                    let mut updated = (*existing).clone();
                    updated.allowed_scopes = new_scopes;
                    updated.idp_provider = Some(provider.to_string());
                    self.store.put_key(&updated)?;
                    self.patch_key_in_caches(Arc::new(updated.clone()));
                    self.refresh()?;
                    let generation = binding_generation(&updated.generation_hash);
                    let token = material.signer.mint(&updated.id, exp, generation);
                    Ok((updated, token))
                } else {
                    let generation = binding_generation(&existing.generation_hash);
                    let token = material.signer.mint(&existing.id, exp, generation);
                    Ok(((*existing).clone(), token))
                }
            }
            None => {
                let out = self.write_self_binding(
                    &material,
                    user_sub,
                    provider,
                    allowed_scopes,
                    0,
                    exp,
                    now,
                )?;
                self.refresh()?;
                Ok(out)
            }
        }
    }

    pub fn refresh_self(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let scopes = crate::governance::pool_scopes(allowed_pools);
        self.refresh_self_scoped(user_sub, provider, scopes, exp, now)
    }

    pub fn refresh_self_scoped(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let Some(material) = self.signing_material() else {
            return Err(RecordStoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            )
            .into());
        };

        let _mint = self
            .mutation_claims
            .claim_checked(MutationKey::Subject(user_sub.to_string()))
            .ok_or_else(|| RecordStoreError("reentrant self-serve mutation refused".into()))?;
        if let Some(refusal) = self.self_mint_refusal(user_sub, provider) {
            return Err(SelfMintError::Refused(refusal));
        }
        let existing = self.current_self_binding(user_sub);
        let _key = existing
            .as_ref()
            .map(|key| self.claim_key_mutation(&key.id))
            .transpose()?;
        let (new_epoch, old_id) = match existing {
            Some(existing) => {
                let existing = self.read_self_binding(&existing.id, user_sub)?;
                let cur = binding_generation(&existing.generation_hash)
                    .and_then(|g| g.parse::<u64>().ok())
                    .unwrap_or(0);
                (cur.saturating_add(1), Some(existing.id.clone()))
            }
            None => (0, None),
        };
        let out = self.write_self_binding(
            &material,
            user_sub,
            provider,
            allowed_scopes,
            new_epoch,
            exp,
            now,
        )?;
        let needs_reconcile = old_id.as_ref().is_none_or(|old| old == &out.0.id);
        if let Some(old) = old_id {
            if old != out.0.id {
                if let Err(delete_err) = self.store.delete_key(&old) {
                    return Err(SelfMintError::Store(match self.delete_key(&out.0.id) {
                        Ok(()) => RecordStoreError(format!(
                            "self-serve refresh for '{user_sub}' failed to tombstone the prior \
                             binding '{old}' ({delete_err}); rolled back the newly-minted binding \
                             '{}' so the prior token remains the sole valid credential — retry the \
                             refresh",
                            out.0.id
                        )),
                        Err(rollback_err) => {
                            diag_error!(
                                REFRESH_SELF_INCONSISTENT_BINDING,
                                user_sub = %user_sub,
                                old_id = %old,
                                new_id = %out.0.id,
                                delete_err = %delete_err,
                                rollback_err = %rollback_err,
                                "refresh_self: failed to tombstone the prior self-serve binding AND \
                                 failed to roll back the newly-written one — subject may now have \
                                 TWO live bindings; manual store inspection required"
                            );
                            RecordStoreError(format!(
                                "self-serve refresh for '{user_sub}' left an INCONSISTENT store \
                                 state: the prior binding '{old}' could not be tombstoned \
                                 ({delete_err}) and the rollback of the new binding '{}' also failed \
                                 ({rollback_err}) — both bindings may still be live; manual \
                                 intervention required",
                                out.0.id
                            ))
                        }
                    }));
                }
                self.evict_key_from_caches(&old);
                if let Err(refresh_err) = self.refresh() {
                    diag_error!(
                        REFRESH_SELF_CACHE_REFRESH_FAILED,
                        user_sub = %user_sub,
                        old_id = %old,
                        new_id = %out.0.id,
                        refresh_err = %refresh_err,
                        "refresh_self: cache refresh failed after tombstoning the prior self-serve \
                         binding in the store; evicting the prior binding directly from the cache \
                         so its token stops verifying immediately"
                    );
                    return Err(SelfMintError::Store(RecordStoreError(format!(
                        "self-serve refresh for '{user_sub}' rotated the store successfully (the \
                         prior binding '{old}' is tombstoned, the new binding '{}' is live) but \
                         the cache reconcile failed ({refresh_err}); the prior binding was evicted \
                         directly from the cache as a best-effort fix so its token no longer \
                         verifies, but the cache may be stale for OTHER entries until the next \
                         successful refresh — retry is safe",
                        out.0.id
                    ))));
                }
            }
        }
        if needs_reconcile {
            self.evict_key_from_caches(&out.0.id);
            self.refresh()?;
        }
        Ok(out)
    }
}
