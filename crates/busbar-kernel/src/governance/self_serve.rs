use super::*;

use std::collections::BTreeSet;

/// The derived-id window every login reads: epochs `0..=SELF_EPOCH_WINDOW` (65 HMACs). It grows only
/// for a subject whose own pre-1.6.0 rows reached past epoch 32 (see [`GovState::self_epoch_window`]).
pub(crate) const SELF_EPOCH_WINDOW: u64 = 64;

/// What the epoch probe found at the first derived id it did not step over.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SelfEpoch {
    /// No row holds this derived id: a new binding may be written there.
    Free { id: String, epoch: u64 },
    /// An undeleted row already holds this derived id. It is the subject's own (the id is derived
    /// for it), so the caller judges it like any other matched row; it is never written over.
    Occupied(VirtualKey),
}

/// What [`GovState::write_self_binding`] did.
#[derive(Debug)]
pub(crate) enum SelfWrite {
    /// The binding was written and a token minted for it.
    Written(VirtualKey, String),
    /// The probe hit an undeleted derived row; nothing was written or claimed.
    Occupied(VirtualKey),
}

impl GovState {
    pub(crate) fn derive_self_subject(seed: &[u8; 32], user_sub: &str, epoch: u64) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, seed);
        let msg = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}#{epoch}");
        let tag = ring::hmac::sign(&key, msg.as_bytes());
        format!("{VK_ID_PREFIX}{}", hex::encode(&tag.as_ref()[..16]))
    }

    /// The pre-1.6.0 row shape: no subject and no binding mode recorded.
    fn legacy_shaped(key: &VirtualKey) -> bool {
        key.idp_subject.is_none() && key.binding_mode.is_none()
    }

    fn parsed_epoch(key: &VirtualKey) -> Option<u64> {
        binding_generation(&key.generation_hash).and_then(|g| g.parse::<u64>().ok())
    }

    /// The derived ids `derive_self_subject(seed, sub, e)` for every `e` in `0..=window`.
    pub(crate) fn derived_self_ids(
        seed: &[u8; 32],
        user_sub: &str,
        window: u64,
    ) -> BTreeSet<String> {
        (0..=window)
            .map(|epoch| Self::derive_self_subject(seed, user_sub, epoch))
            .collect()
    }

    /// The window a login must cover: `max(64, 2*max_e+1)`, `max_e` the highest epoch of the
    /// subject's own legacy-shaped derived rows (tombstones included). 1.6.0 rows never widen it.
    pub(crate) fn self_epoch_window(seed: &[u8; 32], user_sub: &str, rows: &[VirtualKey]) -> u64 {
        rows.iter()
            .filter(|key| Self::legacy_shaped(key))
            .filter_map(|key| {
                let epoch = Self::parsed_epoch(key)?;
                (key.id == Self::derive_self_subject(seed, user_sub, epoch)).then_some(epoch)
            })
            .max()
            .map_or(SELF_EPOCH_WINDOW, |max_e| {
                SELF_EPOCH_WINDOW.max(max_e.saturating_mul(2).saturating_add(1))
            })
    }

    /// Whether `key` is `user_sub`'s own self-serve row, wherever an admin has moved it: a 1.6.0
    /// binding (`idp_subject` and `user-bound`), or a pre-1.6.0 row whose id is derived for the
    /// subject (from its own epoch, or from the window when an admin rewrote its generation).
    /// Group plays no part: `user:` groups are not reserved for self keys.
    pub(crate) fn owned_by(
        key: &VirtualKey,
        user_sub: &str,
        seed: &[u8; 32],
        derived: &BTreeSet<String>,
    ) -> bool {
        if key.deleted_at.is_some() {
            return false;
        }
        if key.idp_subject.as_deref() == Some(user_sub)
            && key.binding_mode.as_deref() == Some(SELF_KEY_BINDING_MODE)
        {
            return true;
        }
        if !Self::legacy_shaped(key) {
            return false;
        }
        derived.contains(&key.id)
            || Self::parsed_epoch(key)
                .is_some_and(|epoch| key.id == Self::derive_self_subject(seed, user_sub, epoch))
    }

    /// The subject's live binding among its owned rows; the `user:<sub>` row wins over a moved one.
    fn live_self_binding(owned: &[VirtualKey], user_sub: &str) -> Option<VirtualKey> {
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        owned
            .iter()
            .find(|key| key.enabled && key.group.as_deref() == Some(group.as_str()))
            .or_else(|| owned.iter().find(|key| key.enabled))
            .cloned()
    }

    /// Every row a login judges: the subject's group rows, its `idp_subject` rows and its derived ids
    /// (one read, grown once when its own pre-1.6.0 rows reach past the default window).
    async fn read_self_rows(
        &self,
        seed: &[u8; 32],
        user_sub: &str,
    ) -> RecordStoreResult<(Vec<VirtualKey>, BTreeSet<String>)> {
        let mut derived = Self::derived_self_ids(seed, user_sub, SELF_EPOCH_WINDOW);
        let mut rows = self
            .core_store()?
            .identity()
            .self_keys(user_sub, &derived)
            .await?;
        let window = Self::self_epoch_window(seed, user_sub, &rows);
        if window > SELF_EPOCH_WINDOW {
            derived = Self::derived_self_ids(seed, user_sub, window);
            rows = self
                .core_store()?
                .identity()
                .self_keys(user_sub, &derived)
                .await?;
        }
        Ok((rows, derived))
    }

    async fn read_self_binding(
        &self,
        id: &str,
        user_sub: &str,
        seed: &[u8; 32],
        derived: &BTreeSet<String>,
    ) -> RecordStoreResult<Arc<VirtualKey>> {
        let key = self
            .core_store()?
            .identity()
            .get_key(id)
            .await?
            .filter(|k| k.enabled && Self::owned_by(k, user_sub, seed, derived))
            .map(Arc::new)
            .ok_or_else(|| {
                RecordStoreError("self-serve binding changed; retry the request".into())
            })?;
        Ok(key)
    }

    /// The refusal, if any, for a self-serve mint. `rows` are every row the login read (its
    /// `user:<sub>` rows feed `ForeignKeyInGroup`); `matched` are the rows owned by the subject;
    /// `revoked` the matched ids found denylisted. Order: TransitionHeld, ForeignKeyInGroup, then
    /// over every matched row Revoked > Disabled > OtherProvider > Unattributed.
    pub(crate) fn self_mint_refusal(
        &self,
        user_sub: &str,
        provider: &str,
        unattributed: UnattributedBinding,
        rows: &[VirtualKey],
        matched: &[VirtualKey],
        revoked: &BTreeSet<String>,
    ) -> Option<SelfMintRefusal> {
        if self
            .transition_self_holds
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains(user_sub)
        {
            return Some(SelfMintRefusal::TransitionHeld);
        }
        let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
        let owned: BTreeSet<&str> = matched.iter().map(|k| k.id.as_str()).collect();
        if rows.iter().any(|k| {
            k.enabled
                && k.deleted_at.is_none()
                && k.group.as_deref() == Some(group.as_str())
                && !owned.contains(k.id.as_str())
        }) {
            return Some(SelfMintRefusal::ForeignKeyInGroup);
        }
        let rank = |k: &VirtualKey| -> Option<(u8, SelfMintRefusal)> {
            if k.deleted_at.is_some() {
                return None;
            }
            if revoked.contains(&k.id) {
                return Some((0, SelfMintRefusal::Revoked));
            }
            if !k.enabled {
                return Some((1, SelfMintRefusal::Disabled));
            }
            match k.idp_provider.as_deref() {
                Some(p) if p != provider => Some((2, SelfMintRefusal::OtherProvider)),
                None if unattributed == UnattributedBinding::Refuse => {
                    Some((3, SelfMintRefusal::Unattributed))
                }
                _ => None,
            }
        };
        matched
            .iter()
            .filter_map(rank)
            .min_by_key(|(order, _)| *order)
            .map(|(_, refusal)| refusal)
    }

    /// [`Self::self_mint_refusal`] with the revoked set read for every disabled matched row (the
    /// store read keeps a node with a stale in-memory denylist truthful).
    async fn judge_self_mint(
        &self,
        user_sub: &str,
        provider: &str,
        unattributed: UnattributedBinding,
        rows: &[VirtualKey],
        matched: &[VirtualKey],
    ) -> RecordStoreResult<Option<SelfMintRefusal>> {
        let mut revoked = BTreeSet::new();
        for key in matched
            .iter()
            .filter(|k| !k.enabled && k.deleted_at.is_none())
        {
            if self.denylist.contains(&key.id)
                || self.core_store()?.identity().is_denied(&key.id).await?
            {
                revoked.insert(key.id.clone());
            }
        }
        Ok(self.self_mint_refusal(user_sub, provider, unattributed, rows, matched, &revoked))
    }

    /// Kept so the tests written against the old opt-in hold still compile: the hold is now the
    /// only policy, so this does nothing.
    #[cfg(test)]
    pub fn hold_self_mint_state(&self) {}

    /// Simulate a node whose in-memory denylist is stale (the store still holds the entry).
    #[cfg(test)]
    pub(crate) fn forget_denylisted_in_memory(&self, id: &str) {
        self.denylist.forget(id);
    }

    /// The first derived id from `from` (strides 0, 1, 2, 4, ...) that is not a tombstone and not in
    /// `cleared`: `Free` when no row holds it, `Occupied` when an undeleted row does. An undeleted
    /// derived row is never stepped over, so a revoked or disabled one is judged, not routed around.
    pub(crate) async fn first_free_self_epoch(
        &self,
        seed: &[u8; 32],
        user_sub: &str,
        from: u64,
        cleared: &BTreeSet<String>,
    ) -> RecordStoreResult<SelfEpoch> {
        const MAX_PROBES: u32 = 64;
        let mut stride = 0u64;
        for _ in 0..MAX_PROBES {
            let epoch = from.saturating_add(stride);
            let id = Self::derive_self_subject(seed, user_sub, epoch);

            match self.core_store()?.identity().get_key(&id).await? {
                None => return Ok(SelfEpoch::Free { id, epoch }),
                Some(key) if key.deleted_at.is_some() || cleared.contains(&id) => {}
                Some(key) => return Ok(SelfEpoch::Occupied(key)),
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
    pub(crate) async fn write_self_binding(
        &self,
        material: &SigningMaterial,
        user_sub: &str,
        provider: &str,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        epoch: u64,
        exp: u64,
        now: u64,
        previous: Option<&VirtualKey>,
        cleared: &BTreeSet<String>,
    ) -> Result<SelfWrite, SelfMintError> {
        let seed = material.signer.secret_bytes();
        let (id, epoch) = match self
            .first_free_self_epoch(&seed, user_sub, epoch, cleared)
            .await?
        {
            SelfEpoch::Free { id, epoch } => (id, epoch),
            SelfEpoch::Occupied(row) => return Ok(SelfWrite::Occupied(row)),
        };
        let generation = epoch.to_string();
        // A rotation stays in the group the admin chose for the previous binding.
        let group = match previous {
            Some(previous) => previous.group.clone(),
            None => Some(format!("{SELF_KEY_GROUP_PREFIX}{user_sub}")),
        };
        let binding = VirtualKey {
            id: id.clone(),
            generation_hash: binding_marker(&id, &generation),
            name: format!("self-serve key ({user_sub})"),

            allowed_scopes,
            enabled: true,
            created_at: now,
            group,

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
                    return Err(SelfMintError::Refused(SelfMintRefusal::Revoked));
                }
                identity.replace_key(previous, &binding).await?
            }
            None => {
                // The probe found this id free; a row that appeared since is a race.
                let before = identity.get_key(&binding.id).await?;
                if before.is_some() {
                    return Err(
                        RecordStoreError("self binding changed; retry the request".into()).into(),
                    );
                }
                identity.compare_self_key(None, &binding).await?
            }
        };
        let binding = super::identity_runtime::committed_key(&commit, &id)?;
        self.publish_identity(commit);
        let token = material.signer.mint(&id, exp, Some(&generation));
        Ok(SelfWrite::Written(binding, token))
    }

    /// Test-only entry: fails closed on an unattributed binding.
    pub async fn issue_self(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let scopes = crate::governance::pool_scopes(allowed_pools);
        self.issue_self_scoped(
            user_sub,
            provider,
            UnattributedBinding::Refuse,
            scopes,
            exp,
            now,
        )
        .await
    }

    /// Bind the subject's existing owned row: update scopes and stamp the provider (an adopted
    /// pre-1.6.0 row also gets its subject and binding mode), never its group.
    #[allow(clippy::too_many_arguments)]
    async fn bind_existing_self(
        &self,
        material: &SigningMaterial,
        user_sub: &str,
        provider: &str,
        unattributed: UnattributedBinding,
        allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
        exp: u64,
        existing: &VirtualKey,
        seed: &[u8; 32],
        derived: &BTreeSet<String>,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let _key = self.identity_key_guard(&existing.id).await;
        // Re-read under the key claim: a disable or move that landed since is seen here.
        let existing = self
            .read_self_binding(&existing.id, user_sub, seed, derived)
            .await?;
        if self
            .core_store()?
            .identity()
            .is_denied(&existing.id)
            .await?
        {
            self.refresh_order
                .patch(|| self.denylist.insert(&existing.id));
            return Err(SelfMintError::Refused(SelfMintRefusal::Revoked));
        }
        if let Some(refusal) = self.self_mint_refusal(
            user_sub,
            provider,
            unattributed,
            &[],
            std::slice::from_ref(existing.as_ref()),
            &BTreeSet::new(),
        ) {
            return Err(SelfMintError::Refused(refusal));
        }
        let new_scopes = allowed_scopes;
        let adopt = existing.idp_provider.is_none() || Self::legacy_shaped(&existing);
        if new_scopes != existing.allowed_scopes || adopt {
            let mut updated = (*existing).clone();
            updated.allowed_scopes = new_scopes;
            updated.idp_provider = Some(provider.to_string());
            updated.idp_subject = Some(user_sub.to_string());
            updated.binding_mode = Some(SELF_KEY_BINDING_MODE.to_string());
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
            self.publish_identity(crate::governance::persistence::identity::IdentityCommit {
                changed: false,
                revision: existing.revision,
                keys: vec![(*existing).clone()],
                credentials: Vec::new(),
                denied: Vec::new(),
            });
            let generation = binding_generation(&existing.generation_hash);
            let token = material.signer.mint(&existing.id, exp, generation);
            Ok(((*existing).clone(), token))
        }
    }

    pub async fn issue_self_scoped(
        &self,
        user_sub: &str,
        provider: &str,
        unattributed: UnattributedBinding,
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
        let seed = material.signer.secret_bytes();

        let _mint = self
            .identity_claim(IdentityClaimKey::Subject(user_sub.into()))
            .await;
        let (rows, derived) = self.read_self_rows(&seed, user_sub).await?;
        let mut owned: Vec<VirtualKey> = rows
            .iter()
            .filter(|k| Self::owned_by(k, user_sub, &seed, &derived))
            .cloned()
            .collect();
        if let Some(refusal) = self
            .judge_self_mint(user_sub, provider, unattributed, &rows, &owned)
            .await?
        {
            return Err(SelfMintError::Refused(refusal));
        }
        if let Some(existing) = Self::live_self_binding(&owned, user_sub) {
            return self
                .bind_existing_self(
                    &material,
                    user_sub,
                    provider,
                    unattributed,
                    allowed_scopes,
                    exp,
                    &existing,
                    &seed,
                    &derived,
                )
                .await;
        }
        match self
            .write_self_binding(
                &material,
                user_sub,
                provider,
                allowed_scopes.clone(),
                0,
                exp,
                now,
                None,
                &BTreeSet::new(),
            )
            .await?
        {
            SelfWrite::Written(binding, token) => Ok((binding, token)),
            SelfWrite::Occupied(row) => {
                // An undeleted derived row the window did not return: the subject's own row,
                // judged like any other; bound if nothing refuses it.
                owned.push(row.clone());
                if let Some(refusal) = self
                    .judge_self_mint(user_sub, provider, unattributed, &rows, &owned)
                    .await?
                {
                    return Err(SelfMintError::Refused(refusal));
                }
                let mut derived = derived;
                derived.insert(row.id.clone());
                self.bind_existing_self(
                    &material,
                    user_sub,
                    provider,
                    unattributed,
                    allowed_scopes,
                    exp,
                    &row,
                    &seed,
                    &derived,
                )
                .await
            }
        }
    }

    /// Test-only entry: fails closed on an unattributed binding.
    pub async fn refresh_self(
        &self,
        user_sub: &str,
        provider: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), SelfMintError> {
        let scopes = crate::governance::pool_scopes(allowed_pools);
        self.refresh_self_scoped(
            user_sub,
            provider,
            UnattributedBinding::Refuse,
            scopes,
            exp,
            now,
        )
        .await
    }

    pub async fn refresh_self_scoped(
        &self,
        user_sub: &str,
        provider: &str,
        unattributed: UnattributedBinding,
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
        let seed = material.signer.secret_bytes();

        let _mint = self
            .identity_claim(IdentityClaimKey::Subject(user_sub.into()))
            .await;
        let (rows, derived) = self.read_self_rows(&seed, user_sub).await?;
        let mut owned: Vec<VirtualKey> = rows
            .iter()
            .filter(|k| Self::owned_by(k, user_sub, &seed, &derived))
            .cloned()
            .collect();
        if let Some(refusal) = self
            .judge_self_mint(user_sub, provider, unattributed, &rows, &owned)
            .await?
        {
            return Err(SelfMintError::Refused(refusal));
        }
        let previous = match Self::live_self_binding(&owned, user_sub) {
            Some(existing) => Some(
                self.read_self_binding(&existing.id, user_sub, &seed, &derived)
                    .await?,
            ),
            None => None,
        };
        let epoch = previous
            .as_ref()
            .map(|key| Self::parsed_epoch(key).unwrap_or(0).saturating_add(1))
            .unwrap_or(0);
        let mut cleared = BTreeSet::new();
        loop {
            match self
                .write_self_binding(
                    &material,
                    user_sub,
                    provider,
                    allowed_scopes.clone(),
                    epoch,
                    exp,
                    now,
                    previous.as_deref(),
                    &cleared,
                )
                .await?
            {
                SelfWrite::Written(binding, token) => return Ok((binding, token)),
                SelfWrite::Occupied(row) => {
                    if !cleared.is_empty() {
                        return Err(RecordStoreError(
                            "self binding changed; retry the request".into(),
                        )
                        .into());
                    }
                    owned.push(row.clone());
                    if let Some(refusal) = self
                        .judge_self_mint(user_sub, provider, unattributed, &rows, &owned)
                        .await?
                    {
                        return Err(SelfMintError::Refused(refusal));
                    }
                    // A live, unrefused owned row: a pre-existing duplicate (or the previous
                    // binding's own id after an admin rewrote its generation). Step past it.
                    cleared.insert(row.id);
                }
            }
        }
    }
}
