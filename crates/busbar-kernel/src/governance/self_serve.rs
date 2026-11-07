use super::*;

impl GovState {
    fn derive_self_subject(seed: &[u8; 32], user_sub: &str, epoch: u64) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, seed);
        let msg = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}#{epoch}");
        let tag = ring::hmac::sign(&key, msg.as_bytes());
        format!("{VK_ID_PREFIX}{}", hex::encode(&tag.as_ref()[..16]))
    }

    fn current_self_binding(rows: &[VirtualKey], user_sub: &str) -> Option<Arc<VirtualKey>> {
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        rows.iter()
            .find(|key| {
                key.enabled
                    && key.deleted_at.is_none()
                    && key.group.as_deref() == Some(group.as_str())
            })
            .cloned()
            .map(Arc::new)
    }

    fn cached_self_binding(&self, user_sub: &str) -> Option<Arc<VirtualKey>> {
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        self.caches_read()
            .by_id
            .values()
            .find(|key| {
                key.enabled
                    && key.deleted_at.is_none()
                    && key.group.as_deref() == Some(group.as_str())
            })
            .cloned()
    }

    async fn read_self_binding(
        &self,
        id: &str,
        user_sub: &str,
    ) -> RecordStoreResult<Arc<VirtualKey>> {
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        let key = self
            .core_store()?
            .identity()
            .get_key(id)
            .await?
            .filter(|k| {
                k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str())
            })
            .map(Arc::new)
            .ok_or_else(|| {
                RecordStoreError("self-serve binding changed; retry the request".into())
            })?;
        Ok(key)
    }

    fn self_mint_refusal(
        &self,
        user_sub: &str,
        provider: &str,
        rows: &[VirtualKey],
    ) -> Option<SelfMintRefusal> {
        if self
            .transition_self_holds
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains(user_sub)
        {
            return Some(SelfMintRefusal::Disabled);
        }
        if !self.self_mint_holds() {
            return None;
        }
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        let rows = rows.iter().filter(|k| {
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

    async fn first_free_self_epoch(
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

            let occupied = self.core_store()?.identity().get_key(&id).await?;
            // Default 1.5.5 issuance reused a derived live/disabled row. Only
            // tombstones force a new epoch; the explicit hold policy is stricter.
            let unavailable =
                occupied.is_some_and(|key| key.deleted_at.is_some() || self.self_mint_holds());
            if !unavailable {
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
    async fn write_self_binding(
        &self,
        material: &SigningMaterial,
        user_sub: &str,
        provider: &str,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        epoch: u64,
        exp: u64,
        now: u64,
        previous: Option<&VirtualKey>,
    ) -> RecordStoreResult<(VirtualKey, String)> {
        let seed = material.signer.secret_bytes();
        let (id, epoch) = self.first_free_self_epoch(&seed, user_sub, epoch).await?;
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
        let mut ids = vec![id.clone()];
        if let Some(previous) = previous {
            ids.push(previous.id.clone());
        }
        ids.sort();
        ids.dedup();
        let mut key_claims = Vec::new();
        for id in &ids {
            key_claims.push(self.identity_key_guard(id).await);
        }
        let identity = self.core_store()?.identity();
        let commit = match previous {
            Some(previous) => {
                if identity.is_denied(&previous.id).await? {
                    return Err(RecordStoreError("self binding is revoked".into()));
                }
                identity.replace_key(previous, &binding).await?
            }
            None => {
                let before = identity.get_key(&binding.id).await?;
                if before.as_ref().is_some_and(|key| {
                    self.self_mint_holds()
                        || key.deleted_at.is_some()
                        || (key.group.as_deref() != binding.group.as_deref()
                            && !(key.idp_subject.as_deref() == Some(user_sub)
                                && key.binding_mode.as_deref() == Some(SELF_KEY_BINDING_MODE)))
                        || key
                            .binding_mode
                            .as_deref()
                            .is_some_and(|mode| mode != SELF_KEY_BINDING_MODE)
                        || key
                            .idp_subject
                            .as_deref()
                            .is_some_and(|subject| subject != user_sub)
                }) {
                    return Err(RecordStoreError(
                        "self binding changed; retry the request".into(),
                    ));
                }
                identity.compare_self_key(before.as_ref(), &binding).await?
            }
        };
        let binding = super::identity_runtime::committed_key(&commit, &id)?;
        self.publish_identity(commit);
        let token = material.signer.mint(&id, exp, Some(&generation));
        Ok((binding, token))
    }

    pub async fn issue_self(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let scopes = crate::governance::pool_scopes(allowed_pools);
        self.issue_self_scoped(user_sub, provider, scopes, exp, now)
            .await
    }

    pub async fn issue_self_scoped(
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
            .identity_claim(IdentityClaimKey::Subject(user_sub.into()))
            .await;
        let rows = self.core_store()?.identity().self_keys(user_sub).await?;
        if let Some(refusal) = self.self_mint_refusal(user_sub, provider, &rows) {
            return Err(SelfMintError::Refused(refusal));
        }
        // A locally observed enabled binding is an expectation, not permission
        // to treat an unseen durable disable as a fresh login. Re-read it under
        // the key claim before updating scopes or issuing a token.
        let existing = self
            .cached_self_binding(user_sub)
            .or_else(|| Self::current_self_binding(&rows, user_sub));
        match existing {
            Some(existing) => {
                let _key = self.identity_key_guard(&existing.id).await;
                let existing = self.read_self_binding(&existing.id, user_sub).await?;
                if self
                    .core_store()?
                    .identity()
                    .is_denied(&existing.id)
                    .await?
                {
                    self.refresh_order
                        .patch(|| self.denylist.insert(&existing.id));
                    return Err(SelfMintError::Refused(SelfMintRefusal::Disabled));
                }
                if let Some(refusal) = self.self_mint_refusal(
                    user_sub,
                    provider,
                    std::slice::from_ref(existing.as_ref()),
                ) {
                    return Err(SelfMintError::Refused(refusal));
                }
                let new_scopes = allowed_scopes.clone();

                let adopt = existing.idp_provider.is_none();
                if new_scopes != existing.allowed_scopes || adopt {
                    let mut updated = (*existing).clone();
                    updated.allowed_scopes = new_scopes;
                    updated.idp_provider = Some(provider.to_string());
                    let commit = self
                        .core_store()?
                        .identity()
                        .compare_self_key(Some(existing.as_ref()), &updated)
                        .await?;
                    let updated = super::identity_runtime::committed_key(&commit, &updated.id)?;
                    self.publish_identity(commit);
                    let generation = binding_generation(&updated.generation_hash);
                    let token = material.signer.mint(&updated.id, exp, generation);
                    Ok((updated, token))
                } else {
                    self.publish_identity(
                        crate::governance::persistence::identity::IdentityCommit {
                            changed: false,
                            revision: existing.revision,
                            keys: vec![(*existing).clone()],
                            credentials: Vec::new(),
                            denied: Vec::new(),
                        },
                    );
                    let generation = binding_generation(&existing.generation_hash);
                    let token = material.signer.mint(&existing.id, exp, generation);
                    Ok(((*existing).clone(), token))
                }
            }
            None => {
                let out = self
                    .write_self_binding(
                        &material,
                        user_sub,
                        provider,
                        allowed_scopes,
                        0,
                        exp,
                        now,
                        None,
                    )
                    .await?;
                Ok(out)
            }
        }
    }

    pub async fn refresh_self(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let scopes = crate::governance::pool_scopes(allowed_pools);
        self.refresh_self_scoped(user_sub, provider, scopes, exp, now)
            .await
    }

    pub async fn refresh_self_scoped(
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
            .identity_claim(IdentityClaimKey::Subject(user_sub.into()))
            .await;
        let rows = self.core_store()?.identity().self_keys(user_sub).await?;
        if let Some(refusal) = self.self_mint_refusal(user_sub, provider, &rows) {
            return Err(SelfMintError::Refused(refusal));
        }
        let previous = match Self::current_self_binding(&rows, user_sub) {
            Some(existing) => Some(self.read_self_binding(&existing.id, user_sub).await?),
            None => None,
        };
        let epoch = previous
            .as_ref()
            .map(|key| {
                binding_generation(&key.generation_hash)
                    .and_then(|generation| generation.parse::<u64>().ok())
                    .unwrap_or(0)
                    .saturating_add(1)
            })
            .unwrap_or(0);
        let out = self
            .write_self_binding(
                &material,
                user_sub,
                provider,
                allowed_scopes,
                epoch,
                exp,
                now,
                previous.as_deref(),
            )
            .await?;
        Ok(out)
    }
}
