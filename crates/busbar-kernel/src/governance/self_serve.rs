// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// The admin-log action of a refused self mint.
pub(crate) const SELF_SERVE_MINT_ACTION: &str = "self_serve.mint";

/// Whether `key` is `user_sub`'s self-serve binding, wherever an admin moved it: a user-bound row
/// for that IdP subject, or a legacy 1.5.5 row (no `idp_subject`) in the subject's own group.
pub(crate) fn is_self_binding_of(key: &VirtualKey, user_sub: &str) -> bool {
    match key.idp_subject.as_deref() {
        Some(subject) => {
            subject == user_sub && key.binding_mode.as_deref() == Some(SELF_KEY_BINDING_MODE)
        }
        None => {
            key.group
                .as_deref()
                .and_then(|group| group.strip_prefix(SELF_KEY_GROUP_PREFIX))
                == Some(user_sub)
        }
    }
}

/// The hold a live (non-tombstoned) self binding puts on a self mint through `provider`: revoked
/// (denylisted), disabled, or minted through another identity provider. A tombstone holds
/// nothing: an admin DELETE is the reset. A legacy row with no provider is adopted, not held.
pub(crate) fn hold_reason(
    key: &VirtualKey,
    denied: bool,
    provider: &str,
) -> Option<SelfMintRefusal> {
    if key.deleted_at.is_some() {
        None
    } else if denied {
        Some(SelfMintRefusal::Revoked)
    } else if !key.enabled {
        Some(SelfMintRefusal::Disabled)
    } else if key.idp_provider.as_deref().is_some_and(|p| p != provider) {
        Some(SelfMintRefusal::OtherProvider)
    } else {
        None
    }
}

impl GovState {
    fn derive_self_subject(seed: &[u8; 32], user_sub: &str, epoch: u64) -> String {
        // The epoch's decimal digits, written on the stack: the MAC input is the same text as
        // `{SELF_KEY_GROUP_PREFIX}{user_sub}#{epoch}`, fed in parts so it is never materialized.
        let mut digits = [0u8; 20];
        let mut cursor: &mut [u8] = &mut digits;
        let _ = std::io::Write::write_fmt(&mut cursor, format_args!("{epoch}"));
        let written = 20 - cursor.len();
        // PANIC: `seed` is the fixed 32-byte token-signing secret; no backend refuses a 32-byte
        // HMAC-SHA256 key (FIPS's floor is 14 bytes), so this cannot fail for a running node.
        let key = busbar_contract::crypto::HmacSha256Key::new(seed).unwrap_or_else(|e| {
            panic!("crypto backend refused HMAC-SHA256 under a 32-byte key: {e}")
        });
        let tag = key.sign_parts(&[
            SELF_KEY_GROUP_PREFIX.as_bytes(),
            user_sub.as_bytes(),
            b"#",
            &digits[..written],
        ]);
        crate::off_path::governance::runtime::self_serve_key_id(VK_ID_PREFIX, &tag[..16])
    }

    /// The subject's current self-serve binding: its live (enabled, not tombstoned) row, in
    /// whatever group an admin moved it to.
    fn current_self_binding(rows: &[VirtualKey], user_sub: &str) -> Option<Arc<VirtualKey>> {
        rows.iter()
            .find(|key| {
                key.enabled && key.deleted_at.is_none() && is_self_binding_of(key, user_sub)
            })
            .cloned()
            .map(Arc::new)
    }

    fn cached_self_binding(&self, user_sub: &str) -> Option<Arc<VirtualKey>> {
        self.caches_read()
            .by_id
            .values()
            .find(|key| {
                key.enabled && key.deleted_at.is_none() && is_self_binding_of(key, user_sub)
            })
            .cloned()
    }

    /// Re-read the durable row `id` under its key claim. A row that changed into a hold while the
    /// caller waited (an admin disable or revoke racing the login) answers that hold, never a
    /// store error; a row that stopped being the subject's binding asks for a retry.
    async fn read_self_binding(
        &self,
        id: &str,
        user_sub: &str,
        provider: &str,
    ) -> Result<Arc<VirtualKey>, SelfMintError> {
        let identity = self.core_store()?.identity();
        let Some(key) = identity
            .get_key(id)
            .await?
            .filter(|k| k.deleted_at.is_none() && is_self_binding_of(k, user_sub))
        else {
            return Err(
                RecordStoreError("self-serve binding changed; retry the request".into()).into(),
            );
        };
        let denied = identity.is_denied(id).await?;
        if denied {
            self.refresh_order.patch(|| self.denylist.insert(id));
        }
        if let Some(reason) = hold_reason(&key, denied, provider) {
            return Err(self.refuse_self_mint(user_sub, provider, reason, Some(id)));
        }
        Ok(Arc::new(key))
    }

    /// Whether the subject itself is held (pre-GA: a completed principal transition), whatever its
    /// keys say. Read by the self mint and by chain verify; the empty set is the fast path.
    pub(crate) fn subject_held(&self, user_sub: &str) -> bool {
        let holds = self
            .transition_self_holds
            .read()
            .unwrap_or_else(|p| p.into_inner());
        !holds.is_empty() && holds.contains(user_sub)
    }

    /// The hold on `user_sub`, if any, and the key that carries it. A self mint never re-enables a
    /// key, never routes around a held key with a fresh one, and never hands one provider's key
    /// to another: every hold is the admin's (or another provider's) to clear, never the user's.
    async fn self_mint_refusal(
        &self,
        user_sub: &str,
        provider: &str,
        rows: &[VirtualKey],
    ) -> RecordStoreResult<Option<(SelfMintRefusal, Option<String>)>> {
        if self.subject_held(user_sub) {
            return Ok(Some((SelfMintRefusal::Held, None)));
        }
        let identity = self.core_store()?.identity();
        let mut found: Option<(SelfMintRefusal, String)> = None;
        for key in rows
            .iter()
            .filter(|k| k.deleted_at.is_none() && is_self_binding_of(k, user_sub))
        {
            let denied = self.denylist.contains(&key.id) || identity.is_denied(&key.id).await?;
            if let Some(reason) = hold_reason(key, denied, provider) {
                if found
                    .as_ref()
                    .is_none_or(|(held, _)| reason.precedence() > held.precedence())
                {
                    found = Some((reason, key.id.clone()));
                }
            }
        }
        Ok(found.map(|(reason, id)| (reason, Some(id))))
    }

    /// Diagnose, audit and type one refusal. Every refusal of a self mint goes through here.
    fn refuse_self_mint(
        &self,
        user_sub: &str,
        provider: &str,
        reason: SelfMintRefusal,
        key_id: Option<&str>,
    ) -> SelfMintError {
        crate::diag_debug!(
            crate::diagnostics::SELF_MINT_HELD,
            subject = %user_sub,
            key_id = key_id.unwrap_or("-"),
            reason = reason.token(),
            provider = %provider,
            "self-serve mint refused: the subject's key is on hold"
        );
        let resource = crate::cold::governance::runtime::self_serve_held_resource(
            key_id,
            user_sub,
            reason.token(),
        );
        crate::audit::auditlog::emit_admin_hostless_now(
            SELF_SERVE_MINT_ACTION,
            &resource,
            crate::audit_ring::OUTCOME_REJECTED,
            user_sub,
        );
        SelfMintError::Refused(reason)
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

            let identity = self.core_store()?.identity();
            // Any existing row is occupied: a self mint only ever writes a never-used id, so it
            // can neither re-enable a disabled row nor write a generation back over a rotated one.
            let unavailable =
                identity.get_key(&id).await?.is_some() || identity.is_denied(&id).await?;
            if !unavailable {
                return Ok((id, epoch));
            }
            stride = if stride == 0 {
                1
            } else {
                stride.saturating_mul(2)
            };
        }
        Err(rendered_error(
            RecordStoreError,
            format_args!(
                "self-serve binding: {MAX_PROBES} probes from epoch {from} all landed on existing \
                 rows; refusing to write over a key id already in use"
            ),
        ))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one part of the binding a self-serve mint writes"
    )]
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
        let generation = crate::off_path::governance::runtime::self_serve_generation(epoch);
        let binding = VirtualKey {
            id: id.clone(),
            generation_hash: binding_marker(&id, &generation),
            name: crate::off_path::governance::runtime::self_serve_binding_name(user_sub),

            allowed_scopes,
            enabled: true,
            created_at: now,
            // A refresh keeps the group an admin moved the key to.
            group: previous.map_or_else(
                || {
                    Some(crate::off_path::governance::runtime::self_serve_group(
                        SELF_KEY_GROUP_PREFIX,
                        user_sub,
                    ))
                },
                |previous| previous.group.clone(),
            ),

            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 0,

            idp_subject: Some(crate::off_path::governance::runtime::self_serve_owned(
                user_sub,
            )),
            binding_mode: Some(crate::off_path::governance::runtime::self_serve_owned(
                SELF_KEY_BINDING_MODE,
            )),

            idp_provider: Some(crate::off_path::governance::runtime::self_serve_owned(
                provider,
            )),
            ..Default::default()
        };
        // Claim the one or two key ids in ascending order (the shared lock order), each once.
        let (first, second) = match previous.map(|previous| previous.id.as_str()) {
            Some(other) if other < id.as_str() => (other, Some(id.as_str())),
            Some(other) if other > id.as_str() => (id.as_str(), Some(other)),
            _ => (id.as_str(), None),
        };
        let _first_claim = self.identity_key_guard(first).await;
        let _second_claim = match second {
            Some(second) => Some(self.identity_key_guard(second).await),
            None => None,
        };
        let identity = self.core_store()?.identity();
        let commit = match previous {
            Some(previous) => {
                if identity.is_denied(&previous.id).await? {
                    return Err(RecordStoreError("self binding is revoked".into()));
                }
                identity.replace_key(previous, &binding).await?
            }
            None => {
                // A fresh binding goes only to a never-used id; the CAS on `None` holds that.
                if identity.get_key(&binding.id).await?.is_some() {
                    return Err(RecordStoreError(
                        "self binding changed; retry the request".into(),
                    ));
                }
                identity.compare_self_key(None, &binding).await?
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
            return Err(store_error(
                "signed-token minting is unavailable: no signing key is configured",
            )
            .into());
        };

        let _mint = self
            .identity_claim(IdentityClaimKey::Subject(user_sub.into()))
            .await;
        let rows = self.core_store()?.identity().self_keys(user_sub).await?;
        if let Some((reason, key_id)) = self.self_mint_refusal(user_sub, provider, &rows).await? {
            return Err(self.refuse_self_mint(user_sub, provider, reason, key_id.as_deref()));
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
                let existing = self
                    .read_self_binding(&existing.id, user_sub, provider)
                    .await?;
                let new_scopes = allowed_scopes;

                let adopt = existing.idp_provider.is_none();
                if new_scopes != existing.allowed_scopes || adopt {
                    let mut updated = (*existing).clone();
                    updated.allowed_scopes = new_scopes;
                    updated.idp_provider = Some(
                        crate::off_path::governance::runtime::self_serve_owned(provider),
                    );
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
            return Err(store_error(
                "signed-token minting is unavailable: no signing key is configured",
            )
            .into());
        };

        let _mint = self
            .identity_claim(IdentityClaimKey::Subject(user_sub.into()))
            .await;
        let rows = self.core_store()?.identity().self_keys(user_sub).await?;
        if let Some((reason, key_id)) = self.self_mint_refusal(user_sub, provider, &rows).await? {
            return Err(self.refuse_self_mint(user_sub, provider, reason, key_id.as_deref()));
        }
        let previous = match Self::current_self_binding(&rows, user_sub) {
            Some(existing) => Some(
                self.read_self_binding(&existing.id, user_sub, provider)
                    .await?,
            ),
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
