//! The self-serve (token-exchange) half of [`GovState`]: deterministic minting of the one key a
//! browser-authenticated principal is bound to, its issue and its refresh. Split out of `state.rs`
//! for `structure-lint`'s file cap: a second `impl GovState` block in a child of `state`, the
//! module that holds the rest of the impl, so every method keeps its name, visibility and callers.
//! No logic moved, only location.

use super::*;

impl GovState {
    // ── SELF-SERVE (token-exchange) deterministic keys — 1.5.2 "Model B" ─────────────────────────
    //
    // A principal that authenticates through the browser/`POST /auth/token` flow gets ONE key,
    // bound to `user:<sub>`. The mechanism is DETERMINISTIC MINTING, NOT a new credential shape:
    //
    //   subject id = vk_<hex( HMAC-SHA256(signing-key seed, "user:<sub>#<epoch>")[..16] )>
    //
    // so the same (sub, epoch) always yields the SAME id → the binding upsert is idempotent (a
    // re-login reuses the one row, never inserts a second). The credential itself is STILL a
    // standard busbar signed token — minted ONLY by `TokenSigner::mint`, exactly like every other
    // key — so `verify_token` is BYTE-FOR-BYTE unchanged: the HMAC is a mint-time id SELECTOR, never
    // a verification step, and a token whose signature segment is a literal HMAC is rejected
    // `BadSignature` like any other forgery. The `epoch` is carried as the binding GENERATION, so
    // Refresh (epoch+1) rides the existing `generation_matches` gate to invalidate the prior token.
    // Nothing recoverable is stored: the token is the credential, as today.

    /// Derive the deterministic self-serve SUBJECT id for `(user_sub, epoch)` under this node's
    /// signing-key seed. The HMAC output is a mint-time id selector (see the block comment); it is
    /// NEVER the credential and is never recomputed on the verify path.
    fn derive_self_subject(seed: &[u8; 32], user_sub: &str, epoch: u64) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(seed)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(format!("{SELF_KEY_GROUP_PREFIX}{user_sub}#{epoch}").as_bytes());
        let tag = mac.finalize().into_bytes();
        format!("{VK_ID_PREFIX}{}", hex::encode(&tag[..16]))
    }

    /// The current ENABLED self-serve binding for `user_sub` (group `user:<sub>`), if any. At most
    /// one exists — the mint is an idempotent upsert and Refresh tombstones the prior row.
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

    /// The first epoch at or after `from` whose derived id is not a tombstoned row, with that id.
    /// See [`GovState::write_self_binding`] for why a tombstoned epoch must be skipped rather than
    /// written over.
    ///
    /// The stride GROWS (0, +1, +2, +4, +8, …) rather than stepping one at a time, and that is
    /// load-bearing rather than an optimization.
    ///
    /// Every successful [`GovState::refresh_self`] tombstones its predecessor, so after N refreshes
    /// epochs `0..N-1` are a CONTIGUOUS run of tombstones with the single live binding at N. The
    /// no-live-binding paths ([`GovState::issue_self`]'s `None` branch, and `refresh_self`'s) both
    /// start from 0 — they have nothing else to start from, since the cache that would know the
    /// highest epoch filters tombstoned rows out at load. So the moment that live binding is
    /// deleted, the next login rescans the whole run from 0. A one-at-a-time scan under a fixed cap
    /// therefore fails on ordinary use: 64 refreshes plus one admin deletion and the subject can
    /// never mint again, in either door, permanently — a per-user 500 on `POST /auth/token` that
    /// only manual store surgery clears. `refresh` is client-selected per call, so 64 is not an
    /// exotic number for a long-lived account.
    ///
    /// Doubling turns that into ~log2(N) probes, and it is sound because ANY free epoch will do:
    /// the epoch's only jobs are to derive a unique id and to seed the next refresh's `cur + 1`, so
    /// nothing requires the LOWEST free one. The probe cap is now on the number of probes, not the
    /// distance covered, and 64 doublings reach past 2^63 epochs — unreachable by anything short of
    /// a corrupt store, which is the only thing the cap is still there to stop.
    fn first_free_self_epoch(
        &self,
        seed: &[u8; 32],
        user_sub: &str,
        from: u64,
    ) -> StoreResult<(String, u64)> {
        const MAX_PROBES: u32 = 64;
        let mut stride = 0u64;
        for _ in 0..MAX_PROBES {
            let epoch = from.saturating_add(stride);
            let id = Self::derive_self_subject(seed, user_sub, epoch);
            let tombstoned = self
                .store
                .get_key(&id)?
                .is_some_and(|k| k.deleted_at.is_some());
            if !tombstoned {
                return Ok((id, epoch));
            }
            stride = if stride == 0 {
                1
            } else {
                stride.saturating_mul(2)
            };
        }
        Err(StoreError(format!(
            "self-serve binding: {MAX_PROBES} probes from epoch {from} all landed on tombstoned \
             rows; refusing to reissue a deleted key id"
        )))
    }

    /// Write (upsert) a self-serve binding at `epoch` and issue the signed token over it. The id is
    /// derived (not random), so `put_key` at the same `(sub, epoch)` is idempotent by id.
    ///
    /// A derived id whose row is TOMBSTONED is skipped, and the epoch advances until one is free.
    /// Two distinct paths land on a tombstoned derived id, and reusing it would be wrong in both:
    ///
    /// - An admin deleted this user's self-serve key. The next login finds no live binding, so it
    ///   arrives here at epoch 0 — the same epoch, therefore the same id, therefore the tombstoned
    ///   row. Writing over it would silently undo the admin's deletion and revive every token
    ///   minted before it. This is the live instance of the resurrection hazard
    ///   [`busbar_api::Store::put_key`] now refuses at the row, and skipping is what makes the
    ///   refusal a correct outcome here rather than a dead end.
    /// - [`GovState::refresh_self`]'s documented rollback tombstones the just-written binding so
    ///   the client keeps its working token and can retry. The retry re-derives that very id, so
    ///   without this it would fail on every attempt, permanently.
    ///
    /// Skipping is also the semantically honest move: an epoch whose binding was tombstoned had its
    /// tokens deliberately invalidated, and re-deriving that id would put them back in play.
    fn write_self_binding(
        &self,
        material: &SigningMaterial,
        user_sub: &str,
        allowed_pools: Option<Vec<String>>,
        epoch: u64,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        let seed = material.signer.secret_bytes();
        let (id, epoch) = self.first_free_self_epoch(&seed, user_sub, epoch)?;
        let generation = epoch.to_string();
        let binding = VirtualKey {
            id: id.clone(),
            generation_hash: binding_marker(&id, &generation),
            name: format!("self-serve key ({user_sub})"),
            // Intent carried intact: None = all pools; Some([]) = none.
            allowed_scopes: allowed_pools
                .map(|list| list.into_iter().map(busbar_api::ScopeRef::pool).collect()),
            enabled: true,
            created_at: now,
            group: Some(format!("{SELF_KEY_GROUP_PREFIX}{user_sub}")),
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 0,
            // A self-serve key IS the PERSONAL (user-bound) token: record the IdP subject for
            // ATTRIBUTION (1.6.0) so per-user budget/audit resolves to a named person. This is the
            // honest, buildable half of "user-bound" — it is recorded, NOT re-checked against the
            // IdP on use (standard OIDC cannot provide a per-use subject floor; auth review C1).
            // `verify_token`/enforcement never read these fields, so stamping them is behavior-
            // preserving; they are pure attribution metadata.
            idp_subject: Some(user_sub.to_string()),
            binding_mode: Some(SELF_KEY_BINDING_MODE.to_string()),
            ..Default::default()
        };
        self.store.put_key(&binding)?;
        self.refresh()?;
        let token = material.signer.mint(&id, exp, Some(&generation));
        Ok((binding, token))
    }

    /// ISSUE the (single, idempotent) self-serve key for `user_sub`. If a binding already exists it
    /// is REUSED verbatim (same id + generation) and only a fresh-`exp` token is re-minted over it —
    /// so N logins produce exactly ONE binding row. Otherwise a fresh binding is minted at epoch 0.
    /// `exp` is the token expiry (Unix secs); `now` the mint time.
    pub fn issue_self(
        &self,
        user_sub: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        let Some(material) = self.signing_material() else {
            return Err(StoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            ));
        };
        // Serialize the check→write against a concurrent issue/refresh for the same sub.
        let _mint = self
            .self_mint_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match self.current_self_binding(user_sub) {
            Some(existing) => {
                // The pools the caller resolved THIS login (from the possibly-changed binding).
                let new_scopes = allowed_pools.clone().map(|list| {
                    list.into_iter()
                        .map(busbar_api::ScopeRef::pool)
                        .collect::<Vec<_>>()
                });
                if new_scopes != existing.allowed_scopes {
                    // allowed_pools CHANGED since the binding was created (an admin narrowed or
                    // widened the group) — update THE EXISTING ROW in place with the fresh pools,
                    // keeping its id and generation, and re-issue a token over them.
                    //
                    // It used to re-DERIVE the id by parsing an epoch back out of
                    // `generation_hash`, on the reasoning that the same epoch yields the same
                    // deterministic id and therefore still one row. That reasoning fails the moment
                    // the generation is not a u64 — and `rotate_key` writes exactly that, a random
                    // hex generation rather than an epoch counter. The parse then fell to
                    // `unwrap_or(0)`, epoch 0 derived a DIFFERENT id from the live binding's, and
                    // this wrote a SECOND enabled row: two valid self-serve tokens for one subject,
                    // each with its own group and budget accounting, breaking the at-most-one
                    // invariant `current_self_binding` depends on.
                    //
                    // Updating in place cannot reintroduce that, because it never derives an id at
                    // all: whatever the generation looks like, there is exactly one row and it stays
                    // the row that already existed.
                    let mut updated = (*existing).clone();
                    updated.allowed_scopes = new_scopes;
                    self.store.put_key(&updated)?;
                    self.refresh()?;
                    let generation = binding_generation(&updated.generation_hash);
                    let token = material.signer.mint(&updated.id, exp, generation);
                    Ok((updated, token))
                } else {
                    // Idempotent re-show: reuse the one binding, re-issue a fresh-exp token over the
                    // SAME id + generation. No new row, so the anti-sprawl cap can never trip.
                    let generation = binding_generation(&existing.generation_hash);
                    let token = material.signer.mint(&existing.id, exp, generation);
                    Ok(((*existing).clone(), token))
                }
            }
            None => self.write_self_binding(&material, user_sub, allowed_pools, 0, exp, now),
        }
    }

    /// REFRESH (rotate) the self-serve key for `user_sub`: bump the epoch, mint the new binding, and
    /// TOMBSTONE the prior one. The prior id no longer re-derives and its binding is disabled, so
    /// every token minted before the refresh stops verifying (`verify_token` → `None`) — the
    /// existing generation gate, reached through a normal delete. Returns the new (binding, token).
    pub fn refresh_self(
        &self,
        user_sub: &str,
        allowed_pools: Option<Vec<String>>,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        let Some(material) = self.signing_material() else {
            return Err(StoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            ));
        };
        // Serialize against a concurrent issue/refresh for the same sub (see `self_mint_lock`).
        let _mint = self
            .self_mint_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (new_epoch, old_id) = match self.current_self_binding(user_sub) {
            Some(existing) => {
                let cur = binding_generation(&existing.generation_hash)
                    .and_then(|g| g.parse::<u64>().ok())
                    .unwrap_or(0);
                (cur.saturating_add(1), Some(existing.id.clone()))
            }
            None => (0, None),
        };
        let out =
            self.write_self_binding(&material, user_sub, allowed_pools, new_epoch, exp, now)?;
        if let Some(old) = old_id {
            if old != out.0.id {
                // Tombstone the prior epoch's binding — its token now fails verify (disabled).
                if let Err(delete_err) = self.store.delete_key(&old) {
                    // The NEW binding is already live (written above) but the OLD one could not
                    // be tombstoned. Returning Err here as-is would leave BOTH bindings enabled — two
                    // valid tokens for one subject, and the caller-visible 500 would suggest nothing
                    // happened. ROLL BACK the just-written new binding (delete it + refresh the
                    // in-memory cache) so a failed refresh leaves EXACTLY the old binding valid: the
                    // client keeps its working token and can retry the refresh.
                    return Err(match self.delete_key(&out.0.id) {
                        Ok(()) => StoreError(format!(
                            "self-serve refresh for '{user_sub}' failed to tombstone the prior \
                             binding '{old}' ({delete_err}); rolled back the newly-minted binding \
                             '{}' so the prior token remains the sole valid credential — retry the \
                             refresh",
                            out.0.id
                        )),
                        Err(rollback_err) => {
                            // Best effort exhausted: loudly flag the inconsistent state (TWO
                            // possibly-live bindings for one subject) for operator/store inspection.
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
                            StoreError(format!(
                                "self-serve refresh for '{user_sub}' left an INCONSISTENT store \
                                 state: the prior binding '{old}' could not be tombstoned \
                                 ({delete_err}) and the rollback of the new binding '{}' also failed \
                                 ({rollback_err}) — both bindings may still be live; manual \
                                 intervention required",
                                out.0.id
                            ))
                        }
                    });
                }
                if let Err(refresh_err) = self.refresh() {
                    // The STORE already reflects the tombstone (`delete_key` above succeeded) —
                    // only the cache reconcile (a `list_keys`/`list_credentials_since` round-trip)
                    // failed. Left as a bare `?`, this would return an Err while silently leaving
                    // the cache holding BOTH the old (still `enabled`) and the new binding — the
                    // old token would keep verifying against a store that no longer agrees.
                    //
                    // Mirror the rollback discipline above: don't leave that inconsistency
                    // silent. A full `refresh()` needs store I/O and just failed, but evicting ONE
                    // known-stale id from the two cache indices needs none — it's a local map
                    // mutation under `caches_write` (whose lock is poison-recovering, so this
                    // cannot itself fail the way a store round-trip can). Do that surgical eviction
                    // so the specific hazard (the OLD token still verifying) is closed immediately,
                    // even though the rest of the cache may now be stale until the next successful
                    // refresh.
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
                    self.evict_key_from_caches(&old);
                    return Err(StoreError(format!(
                        "self-serve refresh for '{user_sub}' rotated the store successfully (the \
                         prior binding '{old}' is tombstoned, the new binding '{}' is live) but \
                         the cache reconcile failed ({refresh_err}); the prior binding was evicted \
                         directly from the cache as a best-effort fix so its token no longer \
                         verifies, but the cache may be stale for OTHER entries until the next \
                         successful refresh — retry is safe",
                        out.0.id
                    )));
                }
            }
        }
        Ok(out)
    }
}
