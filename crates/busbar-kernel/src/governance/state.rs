use super::*;
use busbar_api::{UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT};
use busbar_kernel_ledger::cost::{plane_fee_lane, split_plane_lane, Money, PER_REQUEST};
use std::collections::BTreeMap;
// The wall clock, by name: the admission path reads it and never reaches a store handle for it.
use crate::store::now_ms as wall_ms;

use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, ACCRUAL_GROUP_MISSING, BUDGET_FLUSH_PARTIAL_FAILURE,
    DELETE_KEY_CACHE_RECONCILE_FAILED, METERING_FLUSH_PARTIAL_FAILURE,
    REFRESH_SELF_CACHE_REFRESH_FAILED, REFRESH_SELF_INCONSISTENT_BINDING,
    ROTATE_KEY_CACHE_RECONCILE_FAILED,
};

/// The self-serve (token-exchange) keys: a second `impl GovState` block, split out for
/// `structure-lint`'s file cap. A child module, so it reaches this module's private helpers
/// (`caches_read`, `signing_material`, …) exactly as the methods did when they lived here.
#[path = "self_serve.rs"]
mod self_serve;

/// Prefix on the DEGRADED-BUT-APPLIED error [`GovState::delete_key`] returns when the durable
/// tombstone committed but the full cache reconcile did not. A stable, greppable marker so an
/// operator (and the admin surface, and the tests) can tell "the revocation IS durable, only the
/// cache reconcile is behind" apart from a plain failure that means nothing happened.
pub const REVOCATION_DURABLE_MARKER: &str = "REVOCATION APPLIED (cache reconcile degraded)";

/// The [`GovState::rotate_key`] twin of [`REVOCATION_DURABLE_MARKER`]: the store IS rotated (the
/// previous credential is dead) but the newly-minted secret could not be returned, so the correct
/// operator response is RE-ROTATE, not "retry, nothing happened".
pub const ROTATION_DURABLE_MARKER: &str = "ROTATION APPLIED (new secret not returned)";

impl GovState {
    /// Production never constructs a `GovState` this way -- `appbuild` always resolves a signer and
    /// calls [`GovState::new_with_signer`]. The compiler already agreed (`allow(dead_code)` outside
    /// `test`); the gate below says the same thing in the surface instead of in an attribute, so a
    /// future production caller is a build error rather than a silently-revived door.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(store: Arc<dyn Store>, admin_token: Option<String>) -> StoreResult<Self> {
        Self::new_with_signer(store, admin_token, None)
    }

    /// Construct a `GovState` with an optional TOKEN SIGNER (1.5.0 signed-token keys). `Some` at
    /// boot (a signing key resolved from `auth.signing_key`; 1.5.1 no longer generates one); `None` in
    /// tests that exercise the SigV4 path only (1.5.0 has exactly one credential shape for bearer
    /// auth — a signed token — so a signer is required for any real bearer verification). Hydrates
    /// the revocation denylist set from the store so a restart resumes with every revoked subject
    /// still denied.
    pub fn new_with_signer(
        store: Arc<dyn Store>,
        admin_token: Option<String>,
        signer: Option<crate::governance::signing::TokenSigner>,
    ) -> StoreResult<Self> {
        let by_id = Self::load(store.as_ref())?;
        let by_credential =
            Self::load_by_credential(store.as_ref(), &by_id, busbar_kernel::store::now())?;
        // Hydrate the denylist. A store with no denylist support returns empty (nothing revoked);
        // a durable one returns every persisted revoked subject.
        let denylist: std::collections::HashSet<String> =
            store.list_denylist()?.into_iter().collect();
        // The set was just read from the store, so the staleness clock starts NOW. `RevocationSync`
        // owns its own handle to the store: its refresh runs on the blocking pool and so cannot
        // borrow from `GovState`.
        let denylist = crate::governance::revocation::RevocationSync::new(
            store.clone(),
            denylist,
            busbar_kernel::store::now(),
        );
        Ok(Self {
            store,
            caches: RwLock::new(GovCaches {
                by_id,
                by_credential,
            }),
            concurrent: RwLock::new(HashMap::new()),
            admin_token_hash: RwLock::new(
                admin_token
                    .as_ref()
                    .map(|t| crate::sigv4::sha256_hex(t.as_bytes())),
            ),
            budget: Sharded::new(),
            pending_metering: PendingMetering::new(),
            signing: RwLock::new(signer.map(|s| Arc::new(SigningMaterial::new(s)))),
            denylist,
            refresh_lock: std::sync::Mutex::new(()),
            self_mint_lock: std::sync::Mutex::new(()),
        })
    }

    /// SCHEDULE a re-read of the store's revocation denylist when this node's copy is older than
    /// [`REVOCATION_SYNC_TTL_SECS`] — the check-time staleness guard that makes revocation
    /// AUTHORITATIVE rather than a boot-time snapshot.
    ///
    /// Before this existed the denylist was hydrated ONCE at `GovState` construction and thereafter
    /// only ever mutated by a revoke performed by THIS process. In a fleet sharing one durable store
    /// (or after any out-of-band revoke) a revoked key kept authenticating here for the entire life
    /// of the process — an auth bypass, not a staleness annoyance. `DELETE /keys/{id}` denylists the
    /// subject before removing the binding, so a peer's DELETE propagates through this same path.
    ///
    /// The read itself is blocking store I/O and every caller of this is on a Tokio worker, so it is
    /// SCHEDULED (blocking pool, at most one outstanding) rather than performed here. All of the
    /// single-flight, rate-limit, bound and stamping rules live in
    /// [`crate::governance::revocation::RevocationSync`] — one place, documented there.
    fn sync_revocations_if_stale(&self, now: u64) {
        self.denylist.refresh_if_stale(now);
    }

    /// Whether signed-token minting is available (a signing key was resolved at boot).
    pub fn signing_enabled(&self) -> bool {
        self.signing_material().is_some()
    }

    /// VERIFY a presented signed token (1.5.0): signature + expiry (stateless) + the `sub` not on
    /// the revocation denylist, then resolve the policy binding by `sub`. Returns the bound
    /// `VirtualKey` (the binding record: id/group/allowed_pools/labels; no inline limits) on
    /// success. `None` = not a valid+authorized busbar token OR no signer configured OR the sub
    /// resolves to no binding (a token for a deleted key). The distinction is logged, never
    /// surfaced (no enumeration oracle - the auth path maps every `None` to one opaque 401).
    ///
    /// `expected_aud` is the PLANE boundary (1.6.0 P1): the data plane passes `None`, meaning a
    /// token carrying ANY audience is rejected here; an audience-scoped plane's ingress passes its
    /// canonical URI and rejects a token whose audience is absent or different. Enforced inside
    /// [`TokenVerifier::verify`](super::signing::TokenVerifier::verify), never per handler.
    pub fn verify_token(
        &self,
        token: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Option<Arc<VirtualKey>> {
        let material = self.signing_material()?;
        let claims = match material.verifier.verify(token, now, expected_aud) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(reason = %e, "signed-token verify rejected");
                return None;
            }
        };
        // Revocation: the ONE state read on the otherwise-stateless path. The set is a bounded-TTL
        // CACHE of the store's denylist, re-read here when stale so a peer's (or an out-of-band)
        // revoke is honoured within `REVOCATION_SYNC_TTL_SECS` instead of never.
        self.sync_revocations_if_stale(now);
        if self.denylist.contains(&claims.sub) {
            tracing::debug!(sub = %claims.sub, "signed-token rejected: subject is revoked");
            return None;
        }
        // Resolve policy by `sub` (the key id). The binding lives in the `by_sub` index.
        match self.lookup_by_sub(&claims.sub) {
            // GENERATION gate: the token must name the binding's CURRENT rotation generation.
            // `POST /keys/{id}/rotate` stamps a fresh one into the durable binding row, so every
            // token issued before that rotation stops verifying here — on this node and on every
            // other node reading the same store — while the subject id (ledger bucket, budgets,
            // usage history, audit attribution) stays stable.
            Some(key)
                if key.enabled
                    && generation_matches(&key.generation_hash, claims.generation.as_deref()) =>
            {
                Some(key)
            }
            Some(key) if key.enabled => {
                tracing::debug!(
                    sub = %claims.sub,
                    "signed-token rejected: the binding was rotated after this token was minted"
                );
                None
            }
            _ => {
                tracing::debug!(sub = %claims.sub, "signed-token subject has no enabled binding");
                None
            }
        }
    }

    /// Resolve a policy binding by its subject id (the key id / token `sub`). O(1) index read — the
    /// `by_id` index (keyed by id, since 1.5.0 has exactly one credential shape for bearer keys and
    /// there is no longer a separate hashed-secret index to derive it from).
    pub fn lookup_by_sub(&self, sub: &str) -> Option<Arc<VirtualKey>> {
        self.caches_read().by_id.get(sub).cloned()
    }

    /// REVOKE a signed-token key by subject id: persist to the store denylist AND update the
    /// in-memory set so the next verify rejects it immediately. Idempotent. A store-write failure
    /// is propagated (a revoke that did not durably persist must FAIL LOUD, never report success -
    /// a "revoked" token still valid after a restart is a security hole).
    pub fn revoke(&self, sub: &str, reason: &str) -> StoreResult<()> {
        // THE FAN-OUT FIX (1.5.0 generic-credentials redesign): revoking a key used to be
        // denylist-only, which blocks the SIGNED-TOKEN plane (verify_token consults the denylist)
        // but does NOTHING to a row-looked-up credential like SigV4 — a revoked key's AWS
        // credential stayed fully live. Revocation is a PRINCIPAL-level event and must kill every
        // plane a key can authenticate through, atomically:
        //   1. revoke every live credential row (SigV4 today, whatever kind tomorrow) — independent
        //      of the denylist, since a row-looked-up credential is never checked against it;
        //   2. denylist the subject — kills outstanding signed tokens (the ONE state read on that
        //      otherwise-stateless path);
        //   3. bump `generation_hash` — belt-and-braces for the signed-token plane: even a token
        //      minted in the gap before the denylist write propagates to another node still fails
        //      `generation_matches`;
        //   4. `enabled = false` — the administrative kill switch every plane's admit check reads
        //      after resolution, regardless of which credential resolved it.
        // Order (credentials, then denylist, then generation+enabled) means a failure partway
        // leaves the STRONGER protection already in place: a half-finished revoke has already
        // killed the SigV4 credential (or was never live to begin with) before the cheaper,
        // faster-to-propagate denylist write is attempted.
        //
        // Held across BOTH the store writes above and the targeted cache patch below, same as
        // `refresh()` holds it across its own load+swap (see `refresh_lock`'s doc comment — this
        // is the same lost-update guard, extended to cover `revoke`'s targeted patch too). Without
        // this, a concurrent `refresh()` (triggered by any unrelated key mutation) can `load()` a
        // store snapshot that races these writes, then swap it in AFTER this targeted patch,
        // silently reverting the just-revoked key's cache entry back to enabled. Held for the
        // whole function, not just the final block: the store writes must also be inside the
        // mutual-exclusion window, or a `refresh()` could still slip its `load()` in between them
        // and this patch.
        let _refresh_guard = self.refresh_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut revoked_creds = Vec::new();
        for cred in self.store.list_credentials(sub)? {
            if cred.revoked_at.is_none() {
                self.store.revoke_credential(&cred.id, reason)?;
                revoked_creds.push((cred.kind, cred.public_id));
            }
        }
        self.store.add_denylist(sub, reason)?;
        let mut new_key = None;
        if let Some(mut key) = self.store.get_key(sub)? {
            if key.deleted_at.is_none() {
                let generation = generate_binding_generation().store()?;
                key.generation_hash = binding_marker(&key.id, &generation);
                key.enabled = false;
                self.store.put_key(&key)?;
                new_key = Some(Arc::new(key));
            }
        }
        // TARGETED cache update, not a full `refresh()`: a revoke is a single-key mutation, and
        // `refresh()`'s `list_keys()` + `list_credentials_since(0)` are full-table scans — the same
        // discipline `POST /revoke` is held to on the admin-handler side (one `get_key`, never a
        // table scan). Everything the caches need to reflect is already known from the writes
        // above: the (possibly) updated key row, and exactly which `(kind, public_id)` pairs were
        // just revoked.
        {
            let mut c = self.caches_write();
            self.denylist.insert(sub);
            if let Some(key) = new_key {
                c.by_id.insert(sub.to_string(), key);
            }
            for (kind, public_id) in &revoked_creds {
                c.by_credential.remove(&(kind.clone(), public_id.clone()));
            }
        }
        Ok(())
    }

    /// Whether `sub` is currently revoked. Consulted by BOTH auth paths: the signed-token path
    /// (`verify_token`) and the inbound SigV4 admit path (`verify_inbound_sigv4_and_resolve`), so a
    /// revoked subject's credentials are rejected identically regardless of which credential is presented.
    pub fn is_revoked(&self, sub: &str) -> bool {
        self.is_revoked_at(sub, busbar_kernel::store::now())
    }

    /// [`GovState::is_revoked`] against an explicit clock — the staleness guard needs a `now`, and
    /// the tests need it deterministic. Production callers use `is_revoked`.
    pub fn is_revoked_at(&self, sub: &str, now: u64) -> bool {
        self.sync_revocations_if_stale(now);
        self.denylist.contains(sub)
    }

    /// MINT a signed-token key (1.5.0): persist the policy BINDING row (subject id -> group,
    /// allowed_pools, labels; NO inline limits - keys are pure auth) and issue a busbar-SIGNED
    /// token `{sub, exp, kid}` for it. Returns `(binding, token)`; the token is shown ONCE. The
    /// subject id is a fresh unguessable `vk_<hex>` from the OS CSPRNG (its own bucket namespace).
    /// FAIL-CLOSED: no signer configured is an error (a key with no token is useless).
    pub fn mint_signed(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        let Some(material) = self.signing_material() else {
            return Err(StoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            ));
        };
        // A fresh random subject id (256-bit CSPRNG draw -> `vk_<16 hex>`). Unlike the legacy hash
        // path, the id is NOT derived from a secret (the token is the credential); it is a random
        // handle, so there is no id/hash prefix-collision hazard - but keep the `vk_` bucket
        // namespace so ledger/rate buckets stay consistent with the enforcement machinery.
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|e| StoreError(format!("CSPRNG unavailable: {e}")))?;
        let id = format!("{VK_ID_PREFIX}{}", hex::encode(raw));
        let generation = generate_binding_generation().store()?;
        let binding = VirtualKey {
            id: id.clone(),
            // Not a credential: signed tokens are stateless, so this is never looked up BY — it is
            // a rotation fingerprint, read only after the key is already resolved by `sub`, compared
            // against the token's `generation` claim to detect a stale (pre-rotation) token. The
            // trailing GENERATION is the rotation epoch (`rotate_key`), carried durably so a
            // pre-rotation token is rejected by every node reading the same store.
            generation_hash: binding_marker(&id, &generation),
            name: spec.name,
            // Intent carried intact from the mint body: None = all pools; Some([]) = none.
            allowed_scopes: spec
                .allowed_pools
                .map(|list| list.into_iter().map(busbar_api::ScopeRef::pool).collect()),
            enabled: true,
            created_at: now,
            group: spec.group,
            labels: spec.labels,
            expires_at: None,
            deleted_at: None,
            revision: 0,
            // PROVENANCE + binding mode carried from the mint spec (1.6.0): set for an admin-minted
            // APP token, `None` for a mint that named neither (byte-identical to before).
            minted_by: spec.minted_by,
            binding_mode: spec.binding_mode,
            ..Default::default()
        };
        self.store.put_key(&binding)?;
        self.refresh()?;
        let token = material.signer.mint(&id, exp, Some(&generation));
        Ok((binding, token))
    }

    /// MINT a signed-token key that ALSO carries an AWS-style credential for inbound SigV4 (the
    /// MinIO/S3-compatible model). Persists the binding + AWS credential atomically and issues the
    /// signed token. Returns `(binding, token, aws_access_key_id, aws_secret_access_key)` - the
    /// token and the AWS secret are shown ONCE. See `mint_signed` for the binding shape.
    pub fn mint_signed_with_aws(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String, String, String)> {
        let Some(material) = self.signing_material() else {
            return Err(StoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            ));
        };
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|e| StoreError(format!("CSPRNG unavailable: {e}")))?;
        let id = format!("{VK_ID_PREFIX}{}", hex::encode(raw));
        let generation = generate_binding_generation().store()?;
        let access_key_id = generate_aws_access_key_id().store()?;
        let secret_access_key = generate_aws_secret_access_key().store()?;
        let mut cred_raw = [0u8; 16];
        getrandom::fill(&mut cred_raw)
            .map_err(|e| StoreError(format!("CSPRNG unavailable: {e}")))?;
        let cred_id = format!("cred_{}", hex::encode(cred_raw));
        let binding = VirtualKey {
            id: id.clone(),
            generation_hash: binding_marker(&id, &generation),
            name: spec.name,
            allowed_scopes: spec
                .allowed_pools
                .map(|list| list.into_iter().map(busbar_api::ScopeRef::pool).collect()),
            enabled: true,
            created_at: now,
            group: spec.group,
            labels: spec.labels,
            expires_at: None,
            deleted_at: None,
            revision: 0,
            minted_by: spec.minted_by,
            binding_mode: spec.binding_mode,
            ..Default::default()
        };
        // SigV4: kind belongs to `credentials` because it IS row-looked-up (by AccessKeyId), unlike
        // the signed token above (see CredentialMeta's doc). `secret_form: Recoverable` — HMAC
        // verification needs the plaintext back, so it cannot be a one-way digest.
        let secret = CredentialSecret {
            meta: CredentialMeta {
                id: cred_id,
                key_id: id.clone(),
                kind: "sigv4".to_string(),
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
        };
        self.store.put_key_with_credential(&binding, &secret)?;
        self.refresh()?;
        let token = material.signer.mint(&id, exp, Some(&generation));
        Ok((binding, token, access_key_id, secret_access_key))
    }

    /// The signing key id (`kid`) this node stamps into minted tokens, if signing is enabled.
    pub fn signing_kid(&self) -> Option<String> {
        self.signing_material().map(|m| m.signer.kid().to_string())
    }

    /// BUSBAR'S PUBLIC AGENT-CARD ISSUER KEY (`kid` + SPKI), derived from the token signing key — the
    /// half a boot hook publishes for a caller to pin busbar by.
    ///
    /// A DERIVED SUBKEY, never the token signer itself — see
    /// [`crate::governance::signing::TokenSigner::derived_subkey_seed`] for the blast radius that
    /// buys. Derived through a registered plane's `card_signer` seam rather than by naming that
    /// plane's signer type, so this file names no specific plane's type; the plane reduces the signer
    /// to these PUBLIC halves core-side. `None` when this node has no signing key at all (the
    /// governance-off path) or no plane declaring a `card_signer` is compiled in.
    ///
    /// Built per call rather than cached, and cheap enough to be: one SHA-256 and one ed25519 key
    /// expansion, on a card read rather than on the request hot path. A cached copy would be a
    /// second place the signing key lives that a rotation has to remember to invalidate, and
    /// `set_signing_key` swapping the material underneath a stale card signer is exactly the
    /// mint-under-one-key-verify-under-another failure the material is held together to prevent.
    pub fn card_issuer(&self) -> Option<crate::plane::registry::CardIssuer> {
        let decl = crate::plane::registry::plane_decl_for_config_section("agents")?;
        let domain = decl.card_signing_domain?;
        let prefix = decl.card_kid_prefix?;
        let m = self.signing_material()?;
        Some(crate::plane::registry::CardIssuer {
            kid: format!("{prefix}{}", m.signer.kid()),
            issuer_spki_base64: m.signer.card_subkey_spki_base64(domain),
        })
    }

    /// SIGN a plane-framed card signing-input with the deployment's DOMAIN-DERIVED card subkey — the
    /// host side of the plane `card_sign` seam. Resolves the card-signing domain from the built-in
    /// plane declaration for the `agents` section (so this file names no specific plane's type), derives
    /// the subkey and signs. The subkey secret is derived and used entirely here; the caller receives
    /// only the 64 signature bytes. `None` when no signing key is configured or no plane declares a
    /// card-signing domain.
    // Reached only through the host `card_sign` vtable slot, which a plane declaring a card-signing
    // domain wires; with no such plane installed this has no caller. Unconditional allow — the neutral
    // host names no plane feature; the card-signing domain is resolved from the registry.
    #[allow(dead_code)]
    pub fn card_sign(&self, signing_input: &[u8]) -> Option<[u8; 64]> {
        let domain =
            crate::plane::registry::plane_decl_for_config_section("agents")?.card_signing_domain?;
        let m = self.signing_material()?;
        Some(m.signer.sign_with_card_subkey(domain, signing_input))
    }

    /// The RAW SIGNING SECRET, for callers that need to DERIVE a key from it rather than sign with
    /// it. `None` when no signing key is configured, which is the fail-closed answer everywhere it
    /// is read.
    ///
    /// Deliberately returns the secret rather than a ready-made HMAC, so this module keeps knowing
    /// nothing about what any consumer seals: a plane's ask-state codec
    /// ([`crate::plane::approvals::Sealer::derive`]) does its own domain-separated derivation, which is
    /// what keeps its blobs and this module's virtual-key tokens unable to verify as one another.
    /// Secret-equivalent: never log it, never put it in a `Debug`.
    ///
    /// The FLEET-SHARED property is the reason this is usable for a state seal at all. One logical
    /// caller-facing exchange spans several independent requests, which different nodes may serve;
    /// a per-process key would make the second request fail on whichever node did not mint the first.
    // Its consumer is the ask-state sealer (`crate::plane::approvals::Sealer`), driven by whichever
    // plane seals caller-facing state; with no such plane installed it has no caller. Unconditional
    // allow — the neutral seam names no plane feature.
    #[allow(dead_code)]
    pub fn signing_secret(&self) -> Option<[u8; 32]> {
        self.signing_material().map(|m| m.signer.secret_bytes())
    }

    /// Accrue one completed response's TIER-TOKEN split under `model` to EVERY bucket in the key's
    /// enforcement chain (the key's own bucket + each ancestor budget group, each in ITS OWN
    /// `budget_period` window), plus the raw total to the TPM window. Called once per request at
    /// stream end from the response usage tap. Tokens land in the AUTHORITATIVE in-memory ledger
    /// cells (marked dirty for the write-behind flusher) - NO store round-trip, NO spend math here:
    /// spend is derived from `ledger x rate_card` at check/read time.
    ///
    /// Accrual (unlike the admission charge) does not need cross-bucket atomicity: each bucket's
    /// cell is updated under its own shard lock, and enforcement always re-derives from whatever
    /// has landed.
    ///
    /// STRADDLE CASE (mirrors `add_rate_tokens`): `now` is the request's pinned `charged_at` (the
    /// window the request STARTED in), NOT a fresh clock. Per bucket:
    /// - `window > cell.window_start` → the cell is genuinely stale: reset it to `window`
    ///   (zeroed), then add.
    /// - `window <= cell.window_start` → same window OR the straddle: credit IN PLACE on the
    ///   live cell (never rewind/zero a newer window's counters). A straddling request's tokens
    ///   attribute to the live window rather than being dropped - bounded to one in-flight
    ///   request, never lost.
    /// - no cell → insert fresh (defensive; post-admission the cell exists).
    pub fn record_usage(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        if units.values().all(|v| *v == 0) {
            return; // nothing to ledger
        }
        // THE CARD ERA (Q14, #79), read as the metering row beside this accrual reads it: the
        // tokens are dated when they land, on the history's own millisecond clock.
        let era = crate::rate_apply::effective_from_at(crate::store::now_ms());
        // THE METERING SERIES CARRIES WHAT THIS BOOK HOLDS: the same counts, keyed by the same era,
        // mirrored onto the key's metering row by THIS accrual — the one place every ledgered class
        // lands — so the admin usage read prices exactly the counts this book prices.
        self.meter_classes(&key.id, model, units, era, now);
        // A missing group cannot block ACCRUAL (the request was already admitted/served);
        // degrade to the key-only bucket so the tokens are never lost.
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            Err(missing) => {
                diag_debug!(ACCRUAL_GROUP_MISSING, key = %key.id, group = missing,
                    "group missing at accrual; tokens ledgered to the key bucket only");
                self.accrue_bucket(&key.id, super::WINDOW_TOTAL, (model, era), units, now);
                return;
            }
        };
        // Tokens land only on the buckets this request's pool participates in - the same
        // predicate the admission charge used, so accrual mirrors the charge exactly.
        for bucket in chain.iter().filter(|b| b.applies_to_pool(pool)) {
            self.accrue_bucket(bucket.bucket_id, bucket.window, (model, era), units, now);
        }
    }

    /// **MIRROR A LEDGERED ACCRUAL'S CLASSES ONTO THE KEY'S METERING ROW** (#71, #47), so the admin
    /// usage read — which prices metering rows — holds every count this budget book holds: a plane's
    /// declared classes, an open class of the pools plane, a plane's session count on its fee lane.
    ///
    /// THE ROW IS THE ONE THE PLANE'S OWN SERIES ROW IS KEYED BY. A plane-qualified lane
    /// `"<plane>\u{1f}<subject>"` lands on `(model: <subject>, provider: <plane>)` — the row a plane's
    /// metered request already writes, whose provider column names the plane — and a plane's fee lane
    /// `"<plane>\u{1f}"` on `("", <plane>)`. An unqualified (pools) lane lands on `(<lane>, "")`.
    ///
    /// NOTHING IS COUNTED TWICE. On an unqualified lane the four reserved token tiers are left off:
    /// the same response's `record_metering` carries them in the row's token columns. Every other
    /// class — and every class of a plane-qualified lane, whose rows carry no token split — is
    /// carried here and nowhere else. Write-behind, like `record_metering`.
    fn meter_classes(
        &self,
        key_id: &str,
        lane: &str,
        units: &std::collections::BTreeMap<String, u64>,
        priced_from_ms: u64,
        now: u64,
    ) {
        let (plane, subject) = busbar_kernel_ledger::cost::split_plane_lane(lane);
        let usage_units: std::collections::BTreeMap<String, u64> = units
            .iter()
            .filter(|(class, n)| {
                **n != 0
                    && !(plane.is_empty() && busbar_api::RESERVED_UNITS.contains(&class.as_str()))
            })
            .map(|(class, n)| (class.clone(), *n))
            .collect();
        if usage_units.is_empty() {
            return;
        }
        let (model, provider) = if plane.is_empty() {
            (lane, "")
        } else {
            (subject, plane)
        };
        let key: MeterKey = (
            key_id.to_string(),
            metering_bucket(now),
            model.to_string(),
            provider.to_string(),
            priced_from_ms,
        );
        self.pending_metering.accrue(
            key,
            MeterCounts {
                usage_units,
                ..MeterCounts::default()
            },
        );
    }

    /// Accrue `units` under `model` to ONE bucket's current-window ledger cell (straddle-safe;
    /// see [`GovState::record_usage`]).
    fn accrue_bucket(
        &self,
        bucket_id: &str,
        budget_period: &str,
        (model, era): (&str, u64),
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        let cell = match map.get_mut(bucket_id) {
            Some(c) if window > c.window_start => {
                *c = BudgetCell::fresh(window);
                c
            }
            Some(c) => c, // same window or straddle (cell newer-or-equal) → credit in place
            None => map
                .entry(bucket_id.to_string())
                .or_insert_with(|| BudgetCell::fresh(window)),
        };
        cell.accrue(model, era, units);
        cell.dirty = true;
        cell.last_touch = now;
    }

    /// Record one completed response's RAW consumption into the per-(key, day-bucket, model,
    /// provider) metering series — observability/FinOps data, NEVER enforcement (budgets stay on
    /// `record_tokens`/`charge_within_budget`). Carries the token SPLIT (input / output /
    /// cache-read / cache-creation — each prices differently) so a consumer with its own price
    /// catalog can reconstruct cost from the raw counts; busbar's derived spend is computed at read
    /// time. Zero-token responses still count the request (a flat-fee op is a request against a
    /// model). WRITE-BEHIND: this only accumulates into `pending_metering` under a short-held
    /// `std::sync::Mutex` — no store round-trip and no task spawn on this path. `flush_metering`
    /// (ridden by the same 100ms-tick flusher that drains budgets) does the actual store write, so
    /// a response is durably reflected within one `usage_flush_interval_ms` tick, not "eventually,
    /// whenever the blocking pool gets to it".
    pub fn record_metering(
        &self,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&crate::billing::TokenUsage>,
        now: u64,
    ) {
        // THE CELL'S PRICE INSTANT (DECISION #79): when the card this response was served under
        // STARTED, not which card it is. A build with no root ledger in it answers zero, the
        // opening entry's own `effective_from`, so the cell still dates to a card that covers it
        // rather than to none.
        //
        // READ ON THE MILLISECOND SCALE THE HISTORY IS DATED ON, not lifted from `now`. `now` is
        // seconds; a card apply records `store::now_ms()`. Lifting `now * 1_000` therefore dates
        // every response in a second at that second's FIRST instant, and a card applied later in
        // the same second sorts AFTER all of them — so a request served after an edit priced at the
        // card before it. That is not a rounding nicety: it was measured, on the oracle's own
        // `billing|rate-card|history-mid-window` script, as a response landing after the second of
        // two card publishes and still resolving to the first. Two clocks of different resolution
        // cannot order two events inside one tick of the coarser one, so the accrual reads the
        // finer one, which is the one the thing it is being compared against was written on.
        let priced_from_ms = crate::rate_apply::effective_from_at(crate::store::now_ms());
        let key: MeterKey = (
            key_id.to_string(),
            metering_bucket(now),
            model.to_string(),
            provider.to_string(),
            priced_from_ms,
        );
        let add = MeterCounts {
            requests: 1,
            tokens_input: usage.map(|u| u.input).unwrap_or(0),
            tokens_output: usage.map(|u| u.output).unwrap_or(0),
            tokens_cache_read: usage.and_then(|u| u.cache_read).unwrap_or(0),
            tokens_cache_write: usage.and_then(|u| u.cache_creation).unwrap_or(0),
            usage_units: std::collections::BTreeMap::new(),
        };
        // Accrue through the sharded accumulator: this locks ONLY the shard owning `key_id`, so
        // concurrent completions for different keys no longer serialize on one process-wide mutex.
        // The bound (and the coalesce-never-drop behaviour) is enforced per shard inside `accrue`.
        self.pending_metering.accrue(key, add);
    }

    /// TEST-ONLY: how many distinct cells sit unflushed, and their SUMMED counts. The sum is the
    /// bounding invariant's other half — a cap that silently dropped usage could also look "bounded",
    /// so a test asserts BOTH that the cell count stays capped AND that the summed totals still equal
    /// everything accrued (coalescing moves counts, it never loses them).
    #[cfg(test)]
    pub fn pending_metering_totals(&self) -> (usize, MeterCounts) {
        self.pending_metering.totals()
    }

    /// Drain `pending_metering` and write each entry to the store as one `MeteringDelta`. A DRAIN,
    /// not a baseline (contrast `flush_budgets`): nothing in the tree enforces against a metering
    /// cell, so there is no authoritative running total to protect, and a successfully-flushed
    /// entry is simply gone. In steady state cardinality is bounded by arrival rate x the flush
    /// interval; under a SUSTAINED store outage the re-queue below plus fresh arrivals would grow it
    /// without bound, so the re-queue goes through `accrue_pending`, which caps the map at
    /// [`MAX_PENDING_METERING`] and coalesces the overflow into a per-bucket sentinel (totals kept,
    /// attribution collapsed) rather than dropping billable usage. On a store error the entry's
    /// counts are merged BACK into whatever
    /// accumulated meanwhile (saturating add, not overwrite) so the next tick retries the full
    /// amount exactly once — this is what makes two concurrently-running flushes safe without a
    /// gate: [`PendingMetering::drain`] `mem::take`s each shard under its own lock (an atomic
    /// per-shard swap) and a key never migrates shards, so any two calls partition the arrivals
    /// between them by construction and cannot double-send. Returns the number of deltas written.
    pub fn flush_metering(&self) -> usize {
        let taken = self.pending_metering.drain();
        let mut flushed = 0usize;
        // Aggregate failures: during a store outage EVERY pending key fails on the same tick, so a
        // per-key `warn!` spams. Emit exactly ONE throttled warn per tick carrying the failed count;
        // the per-key detail (key + error) stays at `debug!`.
        let mut failed = 0usize;
        let mut last_error: Option<String> = None;
        for ((key_id, bucket, model, provider, priced_from_ms), counts) in taken {
            if counts.is_zero() {
                continue;
            }
            let delta = MeteringDelta {
                key_id: key_id.clone(),
                bucket,
                model: model.clone(),
                provider: provider.clone(),
                tokens_input: counts.tokens_input,
                tokens_output: counts.tokens_output,
                tokens_cache_read: counts.tokens_cache_read,
                tokens_cache_write: counts.tokens_cache_write,
                requests: counts.requests,
                billable_requests: counts.requests,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                // The instant the cell's card started, carried verbatim from the accrual key so the
                // durable row can be resolved against the dated history exactly as the cell was.
                priced_from_ms,
                usage_units: counts.usage_units.clone(),
            };
            match self.store.add_metering(&delta) {
                Ok(()) => flushed += 1,
                Err(e) => {
                    failed += 1;
                    tracing::debug!(key = %key_id, error = %e, "metering flush failed for key; will retry next tick");
                    last_error = Some(e.to_string());
                    // Re-queue the failed delta through the SAME sharded, bounded accrual as the hot
                    // path (it lands back in the key's own shard). Under a sustained outage with
                    // diverse keys this is exactly where the map used to grow without bound; `accrue`
                    // now caps each shard (coalescing past the cap into the per-bucket overflow
                    // sentinel), so no billable usage is dropped and retry is preserved — a re-queued
                    // cell that still exists next tick simply accumulates.
                    self.pending_metering
                        .accrue((key_id, bucket, model, provider, priced_from_ms), counts);
                }
            }
        }
        if failed > 0 {
            diag_warn!(
                METERING_FLUSH_PARTIAL_FAILURE,
                failed,
                flushed,
                error = last_error.as_deref().unwrap_or(""),
                "metering flush: {failed} key(s) failed to persist this tick; retained and will \
                 retry next tick (per-key detail at debug)"
            );
        }
        flushed
    }

    /// Every metering row for `bucket` (a [`metering_bucket`] day start) — the raw material of the
    /// usage read's by-model / by-key aggregations. Synchronous store read; admin-plane callers run
    /// it via `spawn_blocking`.
    pub fn metering_for(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.store.list_metering(bucket)
    }

    /// READ-ONLY limit headroom for a key: the fraction `[0.0, 1.0]` of the most-constrained
    /// `requests`/`tokens` limit across the key's GROUP CHAIN still available in each limit's own
    /// current window, where `1.0` is "fully unused" and `0.0` is "at the cap". `None` when the
    /// chain carries no requests/tokens limit (nothing to be near). The routing `usage` policy
    /// ranks by this (more headroom = preferred).
    ///
    /// This is a pure observation: it NEVER mutates a cell (no charge, no stale-reset, no sweep):
    /// `try_admit` owns all of that on the admission path. A stale (older-window) cell reads as
    /// fully-available for the current window, which is correct: its counters do not carry
    /// forward. The headroom is the MINIMUM across every windowed requests/tokens cap in the chain
    /// (the tightest constraint governs how close the key is to a 429).
    // Wired into production routing: `proxy engine::decide_policy_order` calls this on the key it
    // looked up (one lookup shared with the `send_user` identity projection) to produce the
    // per-lane `usage` signal; the in-crate tests also exercise it directly.
    pub fn rate_headroom(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64> {
        let chain = cost.chain_for(key).ok()?;
        let mut headroom: Option<f64> = None;
        for bucket in chain.iter() {
            // D5 (documented no-op): the per-tier token caps (`tokens_input`/…) are deliberately
            // NOT reflected in routing headroom. Headroom is a routing-quality signal, not the
            // enforcement gate — PASS-1 in `try_admit` is what actually blocks a filling per-tier
            // bucket. A bucket carrying ONLY per-tier caps therefore reads as full headroom here
            // (skipped), which never admits traffic that enforcement would refuse; it only means
            // routing does not yet prefer away from a filling per-tier bucket.
            if bucket.requests_cap.is_none() && bucket.tokens_cap.is_none() {
                continue;
            }
            // A pool-scoped bucket constrains only its own pool's traffic: with a pool in hand
            // (the routing `usage` signal) skip other pools' buckets; with none (an admin-plane
            // key overview) skip ALL pool-scoped buckets - a per-pool cap is not a property of
            // the key as a whole.
            let applies = match pool {
                Some(p) => bucket.applies_to_pool(p),
                None => bucket.scope.is_none(),
            };
            if !applies {
                continue;
            }
            let window = budget_window(bucket.window, now);
            // Counters for THIS window only; a stale (older-window) cell contributes zero usage.
            let (requests, tokens) = match self.budget.read(bucket.bucket_id).get(bucket.bucket_id)
            {
                Some(cell) if cell.window_start == window => (cell.requests, cell.total_tokens()),
                _ => (0, 0),
            };
            let frac = |used: u64, cap: u64| -> f64 {
                // `cap == 0` is a fully-closed limit: no headroom. Avoid a divide-by-zero.
                if cap == 0 {
                    0.0
                } else {
                    1.0 - (used as f64 / cap as f64)
                }
            };
            let mut h = f64::INFINITY;
            if let Some(cap) = bucket.requests_cap {
                h = h.min(frac(requests, cap));
            }
            if let Some(cap) = bucket.tokens_cap {
                h = h.min(frac(tokens, cap));
            }
            let h = h.clamp(0.0, 1.0);
            headroom = Some(headroom.map_or(h, |cur: f64| cur.min(h)));
        }
        headroom
    }

    /// Acquire the combined key caches (`by_hash` + `by_access_key_id`) for reading, recovering from a
    /// poisoned lock instead of panicking. Mirrors `rate_write`'s rationale for the auth hot path:
    /// `lookup`/`lookup_by_access_key_id` run per request and must never panic, so a poisoned cache
    /// (from a panic in some prior `refresh`) is recovered rather than propagated. The cache content is
    /// a snapshot of the durable store, so the recovered guard yields a consistent (if possibly
    /// slightly stale) view.
    fn caches_read(&self) -> std::sync::RwLockReadGuard<'_, GovCaches> {
        self.caches.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Acquire the combined key caches for writing, recovering from a poisoned lock instead of
    /// panicking (see `caches_read`). Used by `refresh` after a management-API mutation.
    fn caches_write(&self) -> std::sync::RwLockWriteGuard<'_, GovCaches> {
        self.caches.write().unwrap_or_else(|p| p.into_inner())
    }

    /// SHA-256 hex digest of the configured admin token, pre-computed at construction.
    /// `Some` exactly when an admin token was supplied to `GovState::new` (the plaintext is hashed and discarded).
    // Only read by the `auth-admin-tokens` chain link; without that feature the getter is unused
    // (the field is still populated/validated, so keep the method rather than gate the field).
    #[cfg_attr(not(feature = "auth-admin-tokens"), allow(dead_code))]
    pub fn admin_token_hash(&self) -> Option<String> {
        self.admin_token_hash
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// RE-SET the /admin bearer credential from a freshly-resolved plaintext token (`None` disables
    /// the admin API). Called on every config apply/reload with the re-resolved `SecretRef`, so
    /// rotating the underlying secret and reloading actually changes the accepted credential — the
    /// digest used to be frozen at construction and `GovState` is reused across applies, so it never
    /// did. Only the digest is retained; the plaintext is dropped here.
    pub fn set_admin_token(&self, token: Option<&str>) {
        let hash = token.map(|t| crate::sigv4::sha256_hex(t.as_bytes()));
        *self
            .admin_token_hash
            .write()
            .unwrap_or_else(|e| e.into_inner()) = hash;
    }

    /// RE-SET the signing material (mint-side signer + the verifier derived from it, swapped as one
    /// unit so they can never drift). Called on every config apply/reload with the re-resolved
    /// `auth.signing_key`. Rotating the key invalidates every outstanding token by design — that is
    /// what a signing-key rotation MEANS — and until this existed a reload could not perform one at
    /// all.
    pub fn set_signing_key(&self, signer: Option<crate::governance::signing::TokenSigner>) {
        let next = signer.map(|s| Arc::new(SigningMaterial::new(s)));
        *self.signing.write().unwrap_or_else(|e| e.into_inner()) = next;
    }

    /// The current signing material, as a cheap `Arc` clone (the lock is held only for the clone,
    /// never across the crypto).
    fn signing_material(&self) -> Option<Arc<SigningMaterial>> {
        self.signing
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Mint a new virtual key, persist it, refresh the cache, and return `(key, plaintext
    /// secret)`. The secret is shown to the caller ONCE here and never stored (only its hash is).
    ///
    /// No production path mints through here (the admin handler goes through `mint_signed`); the
    /// compiler already agreed via `allow(dead_code)`. The gate says it in the surface instead.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_key(&self, spec: NewKeySpec, now: u64) -> StoreResult<(VirtualKey, String)> {
        // `?` converts a getrandom failure into a StoreError (see `From<getrandom::Error>`), so the
        // admin handler returns a 500 via its existing error_response path instead of panicking.
        let secret = generate_secret().store()?;
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
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
        self.ensure_id_free_for_hash(&id, &hash)?;
        let key = VirtualKey {
            id,
            generation_hash: hash,
            name: spec.name,
            allowed_scopes: spec
                .allowed_pools
                .map(|list| list.into_iter().map(busbar_api::ScopeRef::pool).collect()),
            enabled: true,
            created_at: now,
            group: spec.group,
            labels: spec.labels,
            expires_at: None,
            deleted_at: None,
            revision: 0,
            ..Default::default()
        };
        self.store.put_key(&key)?;
        self.refresh()?;
        Ok((key, secret))
    }

    /// Mint a virtual key that ALSO carries an AWS-style access-key-id + secret access key for inbound
    /// SigV4 verification (the MinIO/S3-compatible model). Returns `(key, bearer_secret,
    /// aws_access_key_id, aws_secret_access_key)`. BOTH secrets — the bearer secret and the AWS secret
    /// access key — are shown to the caller exactly ONCE here and never again (only the bearer secret's
    /// HASH is recoverable later; the AWS secret is stored in plaintext for HMAC verification but is
    /// never echoed by any read API). The AccessKeyId is not secret and IS returned by reads.
    ///
    /// The AWS secret is the SYMMETRIC SigV4 signing key: the client signs with it and busbar
    /// recomputes the signature with the same value. It is therefore stored in plaintext (a one-way
    /// hash would make verification impossible) and guarded by redaction discipline everywhere it could
    /// surface (`AwsCredential`'s Debug, and the admin read responses, which never include it).
    ///
    /// The credential lives in the separate `aws_credentials` table keyed by the key's id, NOT as
    /// columns on `VirtualKey` — this ties the credential to the key without changing the `VirtualKey`
    /// row shape. The bearer key row is persisted first, then the AWS credential; both then refresh
    /// the in-memory caches so the AccessKeyId resolves on the next request.
    ///
    /// No production path mints through here; the compiler already agreed via `allow(dead_code)`.
    /// The gate says it in the surface instead.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_key_with_aws(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> StoreResult<(VirtualKey, String, String, String)> {
        // `?` converts any getrandom failure into a StoreError (see `From<getrandom::Error>`), so the
        // admin handler returns a 500 via its existing error_response path instead of panicking.
        let secret = generate_secret().store()?;
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
        self.ensure_id_free_for_hash(&id, &hash)?;
        let access_key_id = generate_aws_access_key_id().store()?;
        let secret_access_key = generate_aws_secret_access_key().store()?;
        let mut cred_raw = [0u8; 16];
        getrandom::fill(&mut cred_raw)
            .map_err(|e| StoreError(format!("CSPRNG unavailable: {e}")))?;
        let cred_id = format!("cred_{}", hex::encode(cred_raw));
        let key = VirtualKey {
            id: id.clone(),
            generation_hash: hash,
            name: spec.name,
            allowed_scopes: spec
                .allowed_pools
                .map(|list| list.into_iter().map(busbar_api::ScopeRef::pool).collect()),
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
        self.store.put_key_with_credential(
            &key,
            &CredentialSecret {
                meta: CredentialMeta {
                    id: cred_id,
                    key_id: id,
                    kind: "sigv4".to_string(),
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
        self.refresh()?;
        Ok((key, secret, access_key_id, secret_access_key))
    }

    /// Guard against the silent UPSERT-overwrite described in `create_key`: the PRIMARY KEY `id` is
    /// only a 64-bit prefix of the full `generation_hash`, so two distinct secrets can collide on `id`
    /// while differing on `generation_hash`. If `id` already exists under a DIFFERENT `generation_hash`, refuse
    /// (rather than let `put_key` overwrite an unrelated key's row). An `id` that is free, or that
    /// already holds the SAME `generation_hash` (an idempotent re-mint of the identical secret), is allowed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn ensure_id_free_for_hash(&self, id: &str, hash: &str) -> StoreResult<()> {
        if let Some(existing) = self.store.get_key(id)? {
            if existing.generation_hash != hash {
                return Err(StoreError(format!(
                    "virtual-key id collision: derived id '{id}' already belongs to a different key; \
                     retry to mint with fresh entropy (this is a ~2^-64 birthday event)"
                )));
            }
        }
        Ok(())
    }

    /// All virtual keys (metadata; callers must strip `generation_hash` before returning).
    pub fn all_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.store.list_keys()
    }

    /// Delete a key by id and refresh the cache.
    ///
    /// REVOCATION IS DURABLE-FIRST, AND THE OUTCOME SAYS SO. `store.delete_key` commits the
    /// tombstone; only then does the in-memory cache get reconciled. A bare `self.refresh()?` here
    /// was the wrong failure mode for a REVOCATION: on a transient store blip the tombstone was
    /// already committed, the cache still resolved the key, and the operator got a 500 — from which
    /// the only reasonable reading is "the revocation did not take, the key is still live". Both
    /// halves of that were wrong (it DID take durably) and dangerous (the credential kept working).
    ///
    /// So: evict THIS id from the verify/credential caches directly — a local map mutation under
    /// `caches_write`, no store I/O, so it cannot fail the way a full `refresh()` can — which is
    /// what actually stops the credential resolving. Then report a refresh failure as
    /// DEGRADED-BUT-APPLIED ([`REVOCATION_DURABLE_MARKER`]), never as a bare error implying nothing
    /// happened. Same discipline `refresh_self` already applies to its tombstone path.
    pub fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.store.delete_key(id)?;
        // The targeted eviction FIRST and unconditionally: this is the step that stops the
        // credential resolving, and it must happen whether or not the full reconcile succeeds.
        self.evict_key_from_caches(id);
        let refreshed = self.refresh();
        // AFTER the eviction, which is what stops the credential resolving — dropping the cell
        // before it lets a request admitted in the gap re-insert. The key bucket is uncapped
        // (`cost::chain_for`), so this reclaims attribution state only and can never reset a cap.
        //
        // A still-dirty cell would also be flushed after the store cascade-deleted the key's
        // ledger rows; whether that re-creates a durable row depends on the delta being non-zero.
        self.budget.write(id).remove(id);
        if let Err(refresh_err) = refreshed {
            diag_error!(
                DELETE_KEY_CACHE_RECONCILE_FAILED,
                key_id = %id,
                refresh_err = %refresh_err,
                "delete_key: the tombstone is COMMITTED in the store and the key was evicted from \
                 the in-memory caches (it no longer authenticates), but the full cache reconcile \
                 failed; other cache entries may be stale until the next successful refresh"
            );
            return Err(StoreError(format!(
                "{REVOCATION_DURABLE_MARKER}: key '{id}' IS revoked — the tombstone is committed in \
                 the store and the credential was evicted from the in-memory cache, so it no longer \
                 authenticates. Only the full cache reconcile failed ({refresh_err}); OTHER cache \
                 entries may be stale until the next successful refresh. Do NOT re-issue this \
                 revocation expecting it to have been a no-op — it took effect."
            )));
        }
        Ok(())
    }

    /// Evict ONE key id from both in-memory verify indices. Pure local map mutation under
    /// `caches_write` (a poison-recovering lock), so — unlike [`GovState::refresh`], which needs a
    /// `list_keys`/`list_credentials_since` store round-trip — it cannot fail. That is exactly why
    /// the durable-write paths reach for it when a reconcile fails: the specific hazard (a
    /// just-revoked or just-rotated credential still verifying against a store that no longer agrees)
    /// is closed immediately, even if the rest of the cache stays stale until the next refresh.
    fn evict_key_from_caches(&self, id: &str) {
        let mut c = self.caches_write();
        c.by_id.remove(id);
        c.by_credential.retain(|_, (key, _)| key.id != id);
    }

    /// Reclaim the in-memory budget CELLS of a group that no longer exists — the group-shaped twin of
    /// the `self.budget.write(id).remove(id)` line [`GovState::delete_key`] runs, and it carries the
    /// same ordering rule: call it AFTER the deletion is durable and the new `App` (without the
    /// group) is installed, never before. Dropping the cells first would let a request still charging
    /// through the outgoing cost model re-create them in the gap.
    ///
    /// Returns the number of cells dropped. A group's cells are `group:<name>@<window>[#<scope>]`,
    /// one per (window, pool scope), so this is a sweep across every shard rather than a single-key
    /// remove. It is only reachable for a group that is GONE, so there is no cap left for the drop
    /// to reset; the write-behind flush is additive and already committed whatever spend was
    /// ledgered, so no durable data is lost either.
    ///
    /// The match is [`crate::cost::is_bucket_of_group`] — anchored at BOTH ends — not
    /// `starts_with("group:<name>@")`. A group name MAY contain `@` (nothing charset-checks it, and
    /// SSO auto-provisioning mints `user:<email>` leaves), so the prefix test was not a boundary:
    /// deleting `user:alice` also dropped `group:user:alice@corp.com@total`, resetting the spend of
    /// a DIFFERENT group that is still live and still capped. Requiring a real window word after
    /// the `@` makes the two unambiguous in both directions.
    ///
    /// Without this, a deleted group's all-time cell stayed resident for the life of the process:
    /// the amortized sweep exempts a cell that still backs an enforced cap, and nothing ever removed
    /// the ones that stopped backing one. With SSO auto-provisioning creating a group per subject,
    /// that is a monotonic leak that no admin read (`groups_registry.len()` included) can see.
    pub fn reclaim_group_cells(&self, group: &str) -> usize {
        let mut dropped = 0usize;
        for mut shard in self.budget.write_all() {
            let before = shard.len();
            shard.retain(|id, _| !crate::cost::is_bucket_of_group(id, group));
            dropped += before - shard.len();
        }
        // The per-group in-flight `concurrent` gauge is materialised on the first admission of a
        // capped group and, unlike the budget cells above, was never swept on delete — a server
        // that churns capped groups (SSO-template / operator-managed groups with a `concurrent_cap`,
        // each admitting ≥1 request) grew this map without bound. It is keyed by the plain group
        // name, so it is removed here rather than through `is_bucket_of_group`. Any request still
        // in flight against the outgoing group holds its own `Arc` to the gauge inside its
        // `AdmitGrant` and still decrements THAT on drop, so removing the shared registration entry
        // cannot strand a hold; a re-created group re-materialises a fresh gauge at zero, exactly as
        // the budget cells above are re-created. Deletion is durable and the new cost model no longer
        // knows the group before this runs, so no new admission can re-insert it in the gap.
        self.concurrent
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group);
        dropped
    }

    /// ROTATE a key's CREDENTIAL in place. The key `id` stays STABLE — budgets, rate windows, usage
    /// history and audit attribution carry over — and the previous credential stops authenticating
    /// IMMEDIATELY and fleet-wide. An attached AWS SigV4 credential (if any) is NOT rotated here;
    /// it is a separate credential with its own lifecycle. `None` for an unknown id.
    ///
    /// The rotation is credential-shaped, i.e. it rotates whatever credential the key actually has:
    ///
    /// * a 1.5.0 SIGNED-TOKEN binding (`generation_hash` is a `binding:` marker) gets a fresh binding
    ///   GENERATION stamped into the durable row plus a newly-minted token carrying it. Every
    ///   token minted before the rotation names the OLD generation and is rejected by
    ///   `verify_token` on every node reading the store. (rotation used to
    ///   leave the outstanding signed token fully valid — it minted a bearer secret the token path
    ///   never consults — so "rotate" revoked nothing at all.)
    /// * a LEGACY hashed-secret key gets a fresh bearer secret whose hash replaces `generation_hash`, so
    ///   the old secret stops resolving on the next cache refresh. That is the only credential
    ///   such a key has.
    ///
    /// A signed-token binding is NEVER downgraded into a hashed-secret key by rotation (the old
    /// behaviour did exactly that: it ARMED the weaker legacy path on a key that had deliberately
    /// been minted without one, adding a second, non-expiring credential). `generation_hash` stays a
    /// `binding:` marker, which can never equal a SHA-256 digest, so the legacy `lookup` path
    /// remains structurally unreachable for it.
    ///
    /// FAIL-CLOSED: rotating a signed-token binding with no signer configured is an error rather
    /// than a silent fallback to the legacy secret.
    pub fn rotate_key(&self, id: &str, exp: u64) -> StoreResult<Option<RotatedCredential>> {
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };
        // TOMBSTONE (1.5.0): same reasoning as `update_key` — a tombstoned row must never look
        // rotatable. Without this a concurrent DELETE-then-ROTATE race would mint a fresh, live
        // credential for a key that was just revoked, resurrecting it in every way that matters.
        if key.deleted_at.is_some() {
            return Ok(None);
        }
        let Some(material) = self.signing_material() else {
            return Err(StoreError(
                "cannot rotate a signed-token key: no signing key is configured (rotation \
                 re-mints the token)"
                    .to_string(),
            ));
        };
        let generation = generate_binding_generation().store()?;
        key.generation_hash = binding_marker(&key.id, &generation);
        self.store.put_key(&key)?;
        // Same durable-first honesty as `delete_key`: `put_key` has COMMITTED the new generation, so
        // the OLD credential is durably dead the moment this returns — a bare `self.refresh()?` here
        // returned a 500 with no new secret, from which the admin reads "rotation did not happen",
        // while the cache went on resolving the OLD credential against a store that disagreed.
        // Evict this id directly (no store I/O, cannot fail) so the old credential stops verifying
        // immediately, then say plainly that the rotation IS durable and only the new secret was
        // lost — which is a RE-ROTATE, not a retry-because-nothing-happened.
        if let Err(refresh_err) = self.refresh() {
            self.evict_key_from_caches(id);
            diag_error!(
                ROTATE_KEY_CACHE_RECONCILE_FAILED,
                key_id = %id,
                refresh_err = %refresh_err,
                "rotate_key: the new generation is COMMITTED in the store (the previous credential \
                 is dead) and the key was evicted from the in-memory caches, but the full cache \
                 reconcile failed, so the freshly-minted token could not be returned"
            );
            return Err(StoreError(format!(
                "{ROTATION_DURABLE_MARKER}: key '{id}' WAS rotated — the new generation is \
                 committed in the store, so the PREVIOUS credential is permanently dead and was \
                 evicted from the in-memory cache. Only the cache reconcile failed \
                 ({refresh_err}), so the newly-minted token could not be returned and is now \
                 unrecoverable. This was NOT a no-op: rotate this key again to obtain a usable \
                 credential."
            )));
        }
        let token = material.signer.mint(&key.id, exp, Some(&generation));
        Ok(Some(RotatedCredential { key, token, exp }))
    }

    /// Apply a partial update to an existing key. Keys are PURE AUTH, so the mutable surface
    /// is auth-shaped only: `enabled` (freeze/unfreeze the binding) and `group` (rebind the limit
    /// chain; three-state: absent = unchanged, `null` = unbind to unlimited, a value = rebind -
    /// the caller validates the named group exists). `generation_hash`/`name`/`allowed_pools`/
    /// `created_at` are preserved (the credential is never re-minted). Returns `Ok(None)` when the
    /// key does not exist (so the caller can 404), `Ok(Some(updated_metadata))` otherwise.
    pub fn update_key(
        &self,
        id: &str,
        enabled: Option<bool>,
        group: Option<Option<String>>,
    ) -> StoreResult<Option<VirtualKey>> {
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };
        // TOMBSTONE (1.5.0): `get_key` returns a deleted key's row forever (so billing/admin
        // attribution can still see it) — but a PATCH on a tombstoned key must 404, not silently
        // succeed, and must never be the thing that makes a deleted key look live again. Treat a
        // tombstoned row as not-found, the same outcome as an unknown id.
        if key.deleted_at.is_some() {
            return Ok(None);
        }
        if let Some(e) = enabled {
            key.enabled = e;
        }
        // Outer `Some` = the field was present in the request; inner `None` (JSON null) unbinds.
        if let Some(g) = group {
            key.group = g;
        }
        // `put_key` UPSERTs on the PRIMARY KEY `id` with identical `generation_hash`, so this is an in-place
        // update of the existing row (no secret rotation). Refresh the in-memory cache so the change
        // takes effect on the next request.
        self.store.put_key(&key)?;
        self.refresh()?;
        Ok(Some(key))
    }

    /// BOOT-ONLY crash-recovery of accrued token ledgers into the authoritative in-memory cells:
    /// every KEY bucket plus every configured GROUP bucket, each for its own current window. A
    /// hydrated cell seeds NON-dirty with flush baselines equal to the durable record (the store
    /// already holds those values, possibly including other nodes' accruals - the first flush must
    /// send only the LOCAL delta accrued after boot). Runs OFF the hot path exactly once per fresh
    /// `GovState` (never on a config reload/apply - the prior `Arc<GovState>` keeps its live
    /// cells).
    ///
    /// BOOT FAIL-OPEN: a store error here is FATAL, not best-effort. The old code warned and
    /// started with EMPTY cells on a `list_keys`/`get_usage` failure, which silently RESET every
    /// budget to zero - a transient store blip at boot would let a maxed-out key spend its whole cap
    /// again. Propagate any store error so boot fails loudly (the supervisor restarts) rather than
    /// resuming with an unenforced ledger. Returns `Ok(())` only when every bucket hydrated cleanly.
    pub fn hydrate_budgets(&self, cost: &crate::cost::CostModel, now: u64) -> StoreResult<()> {
        let keys = self.store.list_keys()?;
        let key_buckets = keys.iter().map(|k| (k.id.as_str(), super::WINDOW_TOTAL));
        let group_buckets = cost
            .groups()
            .iter()
            .flat_map(|g| g.buckets.iter())
            .map(|b| (b.bucket_id.as_str(), b.window));
        for (bucket_id, period) in key_buckets.chain(group_buckets) {
            let window = budget_window(period, now);
            let ledger = self.store.get_usage(bucket_id, window)?;
            if ledger.requests == 0 && ledger.models.is_empty() {
                continue;
            }
            // `billable_requests` is trusted UNCONDITIONALLY from the persisted ledger — it is
            // NEVER re-derived from `requests` here. An earlier version of this function tried to
            // detect a "pre-split legacy row" (from when the two counters were one field) via
            // `billable_requests == 0 && requests > 0` and re-seeded it from `requests` — but that
            // exact shape is ALSO what a bucket looks like when every request in the window was
            // legitimately REFUNDED (`refund_bucket` decrements `billable_requests` but
            // deliberately never touches `requests`, by design), so every restart silently
            // re-billed correctly-refunded fees, with no way to tell the two cases apart from the
            // counter values alone. Real fix: each durable store backend's own `migrate()` now
            // performs this exact backfill ONCE, ever, at its SCHEMA_VERSION 5->6 crossing (gated
            // on the schema version, not a per-boot value guess) — done while 1.5.0 had no real
            // production data yet, so there was no live refunded-to-zero row that migration could
            // have mis-fired against. From v6 onward every row is written correctly from the
            // start, so this function has nothing left to infer.
            let mut cell = BudgetCell::fresh(window);
            // Stamp as touched NOW, not 0: an unstamped hydrated cell is instantly older than any
            // TTL, so the first post-boot sweep would discard every restored key's history before
            // that key had served a single request.
            cell.last_touch = now;
            cell.requests = ledger.requests;
            cell.flushed_requests = ledger.requests;
            cell.billable_requests = ledger.billable_requests;
            cell.flushed_billable_requests = ledger.billable_requests;
            cell.models = ledger
                .models
                .iter()
                .map(|m| ModelCell {
                    model: std::sync::Arc::from(m.model.as_str()),
                    era: 0,
                    cur: m.usage_units.clone(),
                    flushed: m.usage_units.clone(),
                })
                .collect();
            self.budget
                .write(bucket_id)
                .insert(bucket_id.to_string(), cell);
        }
        Ok(())
    }

    /// Current-window DERIVED usage for a key (`None` if the key does not exist): spend is
    /// recomputed at read time from the bucket's token ledger, each era at the card IN FORCE when it
    /// was earned (+ the flat fee x requests per admission era) - OWNER RULING Q14 / #79, the same
    /// figure `GET /admin/usage` answers for the same consumption. The AUTHORITATIVE in-memory cell
    /// wins for the current
    /// window (it reflects hot-path accruals the write-behind flusher may not have persisted yet);
    /// falls back to the durable ledger for a bucket whose cell was never materialised.
    pub fn usage_for(
        &self,
        cost: &crate::cost::CostModel,
        id: &str,
        now: u64,
    ) -> StoreResult<Option<DerivedUsage>> {
        match self.store.get_key(id)? {
            Some(_) => Ok(Some(self.derived_bucket_usage(
                cost,
                id,
                super::WINDOW_TOTAL,
                true,
                now,
            )?)),
            None => Ok(None),
        }
    }

    /// The DERIVED current-window usage of one bucket (key or group): cell-authoritative, durable
    /// fallback, spend recomputed from tokens x the card in force per era (Q14; the durable row
    /// carries no era, so the fallback prices at the live card). `include_request_fee` controls whether
    /// the flat per-request fee is folded into `spend_cents`. ENFORCEMENT (`try_admit`) counts the fee
    /// for EVERY chain bucket — key AND group — so a read that wants to match what the enforcer sees
    /// must pass `true` for both. The parameter exists only for callers that deliberately want
    /// the fee-excluded figure; the usage dashboards pass `true` so they never overstate headroom.
    pub fn derived_bucket_usage(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> StoreResult<DerivedUsage> {
        self.derived_bucket_usage_priced(cost, bucket_id, budget_period, include_request_fee, now)?
            .map_err(|e| money_refusal(bucket_id, &e))
    }

    /// [`Self::derived_bucket_usage`] with the one function's refusal kept TYPED — the outer error
    /// is the store's, the inner one the `MoneyError` itself — so an admin read can NAME an
    /// unpriced class (`unpriced_class`, OWNER RULING Q25b) rather than flatten it into a store
    /// failure.
    pub fn derived_bucket_usage_priced(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> StoreResult<Result<DerivedUsage, busbar_kernel_ledger::cost::MoneyError>> {
        let window = budget_window(budget_period, now);
        let live = (self.budget.read(bucket_id).get(bucket_id))
            .filter(|c| c.window_start == window)
            .cloned();
        if let Some(mut cell) = live {
            // Q51: the counts AS CORRECTED by every sealed `adjust` landing on this bucket. Fee
            // derives from the BILLABLE (2xx-only) count; `requests` reports the admission count
            // (the requests-limit truth).
            let fixed =
                self.corrected(cost, (bucket_id, budget_period, window), &mut cell.models)?;
            let spend = fixed.and_then(|()| cell.spend(cost, include_request_fee));
            return Ok(spend
                .and_then(Money::minor_i64)
                .map(|spend_cents| DerivedUsage {
                    spend_cents,
                    tokens: cell.total_tokens(),
                    requests: cell.requests,
                }));
        }
        let ledger = self.store.get_usage(bucket_id, window)?;
        let mut models = durable_segments(ledger.models);
        let fixed = self.corrected(cost, (bucket_id, budget_period, window), &mut models)?;
        let spend = fixed.and_then(|()| {
            cost.derive_spend_cents(
                models.iter().map(|m| (&*m.model, &m.cur)),
                ledger.billable_requests,
                include_request_fee,
            )
        });
        Ok(spend.map(|spend_cents| DerivedUsage {
            spend_cents,
            tokens: super::token_total(models.iter().map(|m| &m.cur)),
            requests: ledger.requests,
        }))
    }

    /// **THE BUDGET BOOK'S COUNTS AS CORRECTED** (Q51, item 404, OWNER RULING Q9). An `adjust`
    /// corrects a recorded unit's COUNTS on the node amendment journal; every read of this book
    /// (key and group usage, the `/metrics` money gauges) prices `segments` only after this folds in
    /// Σ (now − was) of each correction that lands on the bucket: its principal's own bucket, or an
    /// UNSCOPED bucket of that key's group chain (a correction names no pool), whose window holds the
    /// unit's card epoch. The delta lands on the unit's lane in the latest era not after the epoch.
    /// A correction leaving a count fractional or below zero REFUSES (`Overflow`), never clamps.
    fn corrected(
        &self,
        cost: &crate::cost::CostModel,
        (bucket_id, period, window): (&str, &str, u64),
        segments: &mut Vec<ModelCell>,
    ) -> StoreResult<Result<(), busbar_kernel_ledger::cost::MoneyError>> {
        use crate::audit::amend::{node_corrections, AmendBody, Subject};
        for amendment in node_corrections() {
            let AmendBody::Adjust(adj) = &amendment.body else {
                continue;
            };
            let Subject::PrincipalId(p) = &adj.subject else {
                continue;
            };
            let lands = budget_window(period, adj.card_epoch_ms / 1_000) == window
                && (p == bucket_id
                    || self.store.get_key(p)?.is_some_and(|k| {
                        (cost.chain_for(&k).ok()).is_some_and(|c| {
                            c.iter()
                                .any(|b| b.bucket_id == bucket_id && b.scope.is_none())
                        })
                    }));
            if !lands {
                continue;
            }
            let at = adj.card_epoch_ms;
            let seg = (segments.iter().enumerate())
                .filter(|(_, m)| *m.model == *adj.lane && m.era <= at)
                .max_by_key(|(_, m)| m.era)
                .map(|(i, _)| i);
            let i = seg.unwrap_or_else(|| {
                segments.push(ModelCell {
                    model: std::sync::Arc::from(adj.lane.as_str()),
                    era: crate::rate_apply::effective_from_at(at),
                    cur: BTreeMap::new(),
                    flushed: BTreeMap::new(),
                });
                segments.len() - 1
            });
            let classes: std::collections::BTreeSet<&String> =
                adj.was.keys().chain(adj.now.keys()).collect();
            for class in classes {
                let (whole, frac) = (adj.delta(class) / 1_000_000, adj.delta(class) % 1_000_000);
                let slot = segments[i].cur.entry(class.clone()).or_insert(0);
                match (i128::from(*slot).checked_add(whole)).and_then(|n| u64::try_from(n).ok()) {
                    Some(n) if frac == 0 => *slot = n,
                    _ => return Ok(Err(busbar_kernel_ledger::cost::MoneyError::Overflow)),
                }
            }
        }
        Ok(Ok(()))
    }

    /// SCRAPE-TIME view of one bucket's per-(model, tier) token counters for its CURRENT window:
    /// the authoritative cell when live, else the durable ledger. Off the hot path (the /metrics
    /// scrape); allocation here is fine.
    pub fn bucket_model_tokens(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> Vec<(String, std::collections::BTreeMap<String, u64>)> {
        let window = budget_window(budget_period, now);
        let live = (self.budget.read(bucket_id).get(bucket_id))
            .filter(|c| c.window_start == window)
            .map(|c| c.models.clone());
        let read = live.map_or_else(
            || (self.store.get_usage(bucket_id, window)).map(|l| durable_segments(l.models)),
            Ok,
        );
        let Ok(mut models) = read else {
            return Vec::new();
        };
        // Q51: the counts AS CORRECTED; a refused correction skips the series, as a failed read does.
        if !matches!(
            self.corrected(cost, (bucket_id, budget_period, window), &mut models),
            Ok(Ok(()))
        ) {
            return Vec::new();
        }
        // One series per MODEL: a model's eras are one set of counts to the scrape.
        let models = models.iter().map(|m| (&*m.model, m.cur.clone()));
        busbar_kernel_ledger::usage::by_lane(models, u64::saturating_add)
    }

    /// The HOOK-SEAM projection: per-bucket budget state for the key + every ancestor group -
    /// `{bucket_id, spend_micros_at_current_rate, remaining_micros, window}`. Read-only, built off
    /// the default hot path (only routing-policy pools request it). A missing budget group yields
    /// the key-only view.
    pub fn budget_state(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        now: u64,
    ) -> Vec<busbar_api::BudgetBucketState> {
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::with_capacity(chain.len());
        for bucket in chain.iter() {
            let window = budget_window(bucket.window, now);
            let spend = {
                let map = self.budget.read(bucket.bucket_id);
                match map.get(bucket.bucket_id) {
                    Some(cell) if cell.window_start == window => {
                        cell.spend(cost, true).and_then(Money::micros_i64)
                    }
                    _ => Ok(0),
                }
            };
            // A REFUSED figure (#42: the card present and silent about a model or class the bucket
            // holds; item 28: an overflow) is not a figure, and the projection has no error channel
            // to carry it in. It reads FAIL-CLOSED: no headroom (`remaining_micros: Some(0)`), and a
            // spend at the top of the range so a policy comparing spends ranks it last. It used to
            // derive as the flat fee alone — full headroom for consumption nobody priced.
            let (spend_micros, remaining_micros) = match spend {
                Ok(spend_micros) => (
                    spend_micros,
                    bucket.budget_cap.map(|cap| {
                        cap.saturating_mul(10_000)
                            .saturating_sub(spend_micros)
                            .max(0)
                    }),
                ),
                Err(_) => (i64::MAX, Some(0)),
            };
            out.push(busbar_api::BudgetBucketState {
                bucket_id: bucket.bucket_id.to_string(),
                budget_group: bucket.group_name.map(String::from),
                pool: bucket.scope.map(|s| s.value.clone()),
                spend_micros_at_current_rate: spend_micros,
                remaining_micros,
                window_start: window,
                budget_period: bucket.window.to_string(),
            });
        }
        out
    }

    /// The in-flight gauge for `group`, materialised on first sight. Read-locked resolve on the
    /// hot path (an existing gauge mutates through the shared atomic); the write lock is taken
    /// only to insert a missing gauge (once per group per process lifetime).
    fn concurrent_gauge(&self, group: &str) -> Arc<std::sync::atomic::AtomicI64> {
        if let Some(g) = self
            .concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
        {
            return g.clone();
        }
        self.concurrent
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(group.to_string())
            .or_default()
            .clone()
    }

    /// TEST-ONLY: the current in-flight count for a group's `concurrent` gauge.
    #[cfg(test)]
    pub fn concurrent_in_flight(&self, group: &str) -> i64 {
        self.concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// ATOMIC chain ADMISSION for the request path - the generic limit engine's hard-cap
    /// primitive. Resolves the key's enforcement chain ([key attribution bucket] -> the bound
    /// group's window buckets -> parent's -> ... root) and admits ONLY if EVERY limit of EVERY
    /// group in the chain admits (AND / most-restrictive). Keys carry NO limits of their own; a
    /// key with no group is authed + unlimited (its 1-bucket chain has no caps).
    ///
    /// Order of enforcement:
    /// 1. `enabled: false` anywhere in the chain FREEZES it - rejected before anything is charged.
    /// 2. `concurrent` gauges (instantaneous): each capped group's gauge is compare-and-incremented
    ///    innermost-first; on any full gauge the already-taken holds are released and the request
    ///    is rejected naming that group. The holds ride the returned [`AdmitGrant`] (RAII release).
    /// 3. Windowed limits (`requests` / `tokens` / `budget`): every involved shard lock is
    ///    acquired in ASCENDING shard-index order (canonical = deadlock-free), every bucket is
    ///    CHECKED against each of its caps for its OWN current window, and only if all pass is
    ///    every bucket CHARGED one request in the SAME critical section - all-or-nothing. On any
    ///    blocked bucket NOTHING is charged, the concurrent holds are released, and the exact
    ///    blocking (group, metric, window) is named with a `Retry-After` for rolling windows.
    ///
    /// Metric semantics per bucket:
    /// - `requests`: precise - the +1 charge is synchronous with the check.
    /// - `tokens`: every token-family class any plane declares, not only the reserved four.
    ///   BEST-EFFORT (the old TPM posture) - tokens land post-response, so the cap
    ///   blocks the NEXT request once the ledgered total has crossed it; in-flight requests'
    ///   tokens are invisible to admissions racing them.
    /// - `budget`: derived at check time from the cell's token ledger, each era at the card in
    ///   force when it was earned, PLUS the flat per-request fee x its request count per
    ///   admission era; the prospective post-charge spend
    ///   (one more fee) must stay within the cap, and a bucket already at/over cap blocks. The
    ///   fee component is hard; token overshoot past a cap is bounded by the tokens of every
    ///   in-flight admitted request (as with TPM, a hard token cap would need admit-time
    ///   reservation - out of scope).
    ///
    /// SYNCHRONOUS and INFALLIBLE (in-memory cells; no store round-trip, no await). The flat fee
    /// is charged HERE (as +1 request per bucket; spend derives), so the caller must NOT re-charge
    /// in `finish`; a non-2xx outcome refunds via [`GovState::refund_request`]. This allocates a
    /// handful of chain-sized scratch `Vec`s per call (`chain_for`'s two Vecs, the collected bucket
    /// slice, the shard-index/order/guard Vecs sized to the chain depth) — there are no fixed
    /// scratch arrays; every one of these is a fresh heap allocation. What IS true: no store
    /// round-trip and no `await` anywhere on this path.
    ///
    /// PER-PLANE FEES (#47): a `pool` qualified `"<plane>\u{1f}<pool>"` is a request of THAT plane
    /// — the pool predicate reads the unqualified part — and it charges that plane's own
    /// `fees.per_request`, counted on the plane's fee lane (dated, durable, never the flat fee
    /// base). An unqualified pool is the pools plane's and charges `per_request_fee:`.
    pub fn try_admit(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
    ) -> Result<AdmitGrant, LimitBlocked> {
        let (plane, pool) = split_plane_lane(pool);
        // FAIL-CLOSED: a key bound to a group this node's config does not know cannot be admitted
        // under the chain's caps, so it is not admitted at all.
        let missing = |g: &str| LimitBlocked::MissingGroup(g.to_string());
        let chain = cost.chain_for(key).map_err(missing)?;
        // Pool-scoped buckets participate only when THIS request's pool matches; filtered ONCE
        // here so the check pass, the charge pass, and the shard-lock set can never disagree.
        let buckets: Vec<&crate::cost::ChainBucket<'_>> =
            chain.iter().filter(|b| b.applies_to_pool(pool)).collect();
        let groups = cost.groups();

        // 1. FREEZE check: any `enabled: false` group in the chain rejects - checked before
        // any gauge or charge so a frozen chain mutates nothing.
        for &gi in chain.group_indices() {
            if !groups[gi].enabled {
                return Err(LimitBlocked::Disabled(groups[gi].name.clone()));
            }
        }

        // 2. CONCURRENT holds, innermost-first. `fetch_update` is a CAS loop: the increment lands
        // only while strictly under the cap, so N racing admissions can never jointly overshoot.
        // On a full gauge, roll back the holds already taken (the grant drop) and name the group.
        let mut grant = AdmitGrant::default();
        for &gi in chain.group_indices() {
            let Some(cap) = groups[gi].concurrent_cap else {
                continue;
            };
            let gauge = self.concurrent_gauge(&groups[gi].name);
            let cap = i64::try_from(cap).unwrap_or(i64::MAX);
            let admitted = gauge
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    (v < cap).then_some(v + 1)
                })
                .is_ok();
            if !admitted {
                drop(grant); // release the holds taken so far
                return Err(LimitBlocked::Limit {
                    group: groups[gi].name.clone(),
                    metric: "concurrent",
                    window: None,
                    pool: None,
                    downgrade_to: None,
                    retry_after: None,
                });
            }
            grant.gauges.push(gauge);
        }

        // 3. WINDOWED limits: acquire every involved shard's write lock in ASCENDING shard order
        // (dedup) - scratch sized by the chain actually resolved. `guard_shards[j]` = the shard
        // whose guard sits at position j in `guards`.
        let fee = cost.request_fee_on(plane);
        let n = buckets.len();
        let mut shard_idx: Vec<usize> = Vec::with_capacity(n);
        for bucket in &buckets {
            shard_idx.push(self.budget.shard_index(bucket.bucket_id));
        }
        let mut order = shard_idx.clone();
        order.sort_unstable();
        let mut guards: Vec<Option<std::sync::RwLockWriteGuard<'_, HashMap<String, BudgetCell>>>> =
            Vec::new();
        guards.resize_with(n, || None);
        let mut guard_shards = vec![usize::MAX; n];
        let mut g = 0usize;
        for &sh in order.iter() {
            if g > 0 && guard_shards[g - 1] == sh {
                continue; // dedup: two buckets sharing a shard use one guard
            }
            let shard = self.budget.shard_at(sh);
            // Amortized bounded eviction of stale cells, per acquired shard - identical rationale
            // to the old rate-map sweep (POST-increment ticker; age-based, window-agnostic retain
            // so no still-current cell of ANY window is evicted; `window_start == 0` = the
            // all-time window, never aged out).
            let sweep_needed = shard
                .sweep_ticker
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
                .is_multiple_of(crate::limits::rate_sweep_interval());
            let mut map = shard.map.write().unwrap_or_else(|p| p.into_inner());
            if sweep_needed {
                let max_window = 31 * super::SECS_PER_DAY;
                map.retain(|id, c| {
                    if c.window_start != 0 {
                        return c.window_start.saturating_add(max_window) > now;
                    }
                    // The all-time window never rolls, so age these by last use instead. The
                    // `group:` exemption is NARROW, and exactly as narrow as its own rationale: a
                    // cell is exempt only while it STILL BACKS AN ENFORCED CAP ("spend that must
                    // not reset", and hydrate is boot-only so it would never come back).
                    //
                    // It used to be the blanket `id.starts_with("group:")`, which also pinned two
                    // populations the rationale never covered: cells of DELETED groups, and cells
                    // of UNCAPPED ones. With SSO auto-provisioning (`max_auto_provisioned_groups`
                    // defaults to 0 = UNLIMITED) every subject ever seen leaves a permanently
                    // resident cell behind after offboarding, and `groups_registry.len()` stays
                    // flat, so nothing on the admin surface reveals the growth — a monotonic leak
                    // on a product that advertises ~5 MB RSS. A cell whose group is gone, or whose
                    // bucket carries no cap, enforces NOTHING; it now ages out by last touch like
                    // any other attribution cell (and, like them, only while clean).
                    still_enforces_a_cap(cost, id)
                        || c.dirty
                        || c.last_touch.saturating_add(max_window) > now
                });
                // Bound the per-cell `models` Vec too: a never-rolled cell (the all-time
                // `window_start == 0` bucket) accumulates a dead `ModelCell` for every model name
                // ever seen (interned on first sight by `accrue`, including zero-token responses).
                // Prune the dead (zero-token, fully-flushed) entries on the same amortized cadence so
                // the Vec cannot grow unbounded in-process. Retained cells keep every model that still
                // carries tokens or an unacked flush delta, so enforcement is unaffected.
                for c in map.values_mut() {
                    c.prune_dead_models();
                }
            }
            guards[g] = Some(map);
            guard_shards[g] = sh;
            g += 1;
        }
        let guard_for = |shards: &[usize], target: usize| -> usize {
            shards[..g]
                .iter()
                .position(|&sh| sh == target)
                .expect("every bucket's shard was acquired")
        };

        // PASS 1 - CHECK every bucket under the held guards: resolve its cell for ITS OWN current
        // window (missing/stale cells read as empty) and test each configured cap. The blocking
        // bucket is named exactly: (group, metric, window) + retry-after for a rolling window.
        for (bi, bucket) in buckets.iter().enumerate() {
            if bucket.requests_cap.is_none()
                && bucket.tokens_cap.is_none()
                && bucket.tokens_input_cap.is_none()
                && bucket.tokens_output_cap.is_none()
                && bucket.tokens_cache_read_cap.is_none()
                && bucket.tokens_cache_write_cap.is_none()
                && bucket.budget_cap.is_none()
            {
                continue; // uncapped bucket (e.g. the key's attribution bucket) never blocks
            }
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.window, now);
            let map = guards[gi].as_deref().expect("guard held");
            // Read the LIVE cell when it holds this window OR a NEWER one (the straddle: `now` is
            // the pinned `charged_at`, so a request admitted just before a boundary can arrive
            // after a concurrent admission already rolled the cell forward - its charge lands on
            // the live cell in PASS 2, so the check must read that same cell, never treat it as a
            // fresh window). Only a genuinely STALE (older-window) or absent cell reads as empty.
            // Per-tier token counters (`tokens_input`/…): read the matching cell tier ONLY when its
            // cap is set — same best-effort post-paid shape as `tokens_cap`, mirroring the cost
            // tiers. `tokens_input` reads the `input` tier (uncached input; cache_read is a separate
            // tier), so a cache-read unit never counts against the input cap.
            // A per-tier counter is read only when its cap is set.
            let tier =
                |c: &BudgetCell, cap: Option<u64>, unit| cap.map_or(0, |_| c.total_tier(unit));
            let (requests, tokens, t_input, t_output, t_cache_read, t_cache_write, derived) =
                match map.get(bucket.bucket_id) {
                    Some(cell) if cell.window_start >= window => (
                        cell.requests,
                        bucket.tokens_cap.map_or(0, |_| cell.total_tokens()),
                        tier(cell, bucket.tokens_input_cap, UNIT_INPUT),
                        tier(cell, bucket.tokens_output_cap, UNIT_OUTPUT),
                        tier(cell, bucket.tokens_cache_read_cap, UNIT_CACHE_READ),
                        tier(cell, bucket.tokens_cache_write_cap, UNIT_CACHE_WRITE),
                        bucket.budget_cap.map_or(Ok(0), |_| {
                            (cell.spend(cost, true)).and_then(Money::minor_i64)
                        }),
                    ),
                    // stale or absent cell = fresh window = nothing used
                    _ => (0, 0, 0, 0, 0, 0, Ok(0)),
                };
            // #42 AT THE DOOR (item 124): a spend the one function REFUSES — the card present and
            // silent about a model or class this bucket holds, or an overflow — BLOCKS on the
            // budget metric. This door used to drop an unpriced model's whole consumption
            // (`if let Some(rate)`), so a model the card did not name ran uncapped on spend. A
            // refusal is never downgraded: a cheaper pool is no answer to "this cannot be priced".
            let (derived, refused) = match derived {
                Ok(d) => (d, false),
                Err(_) => (0, true),
            };
            let blocked_metric = if bucket
                .requests_cap
                .is_some_and(|cap| requests.saturating_add(1) > cap)
            {
                Some("requests")
            } else if bucket.tokens_cap.is_some_and(|cap| tokens >= cap) {
                Some("tokens")
            } else if bucket.tokens_input_cap.is_some_and(|cap| t_input >= cap) {
                Some("tokens_input")
            } else if bucket.tokens_output_cap.is_some_and(|cap| t_output >= cap) {
                Some("tokens_output")
            } else if bucket
                .tokens_cache_read_cap
                .is_some_and(|cap| t_cache_read >= cap)
            {
                Some("tokens_cache_read")
            } else if bucket
                .tokens_cache_write_cap
                .is_some_and(|cap| t_cache_write >= cap)
            {
                Some("tokens_cache_write")
            } else if bucket
                .budget_cap
                .is_some_and(|cap| refused || derived >= cap || derived.saturating_add(fee) > cap)
            {
                Some("budget")
            } else {
                None
            };
            if let Some(metric) = blocked_metric {
                drop(guards); // release the shard locks before the (cold) rejection build
                drop(grant); // release the concurrent holds - nothing was admitted
                return Err(LimitBlocked::Limit {
                    group: bucket
                        .group_name
                        .expect("only group buckets carry caps")
                        .to_string(),
                    metric,
                    window: Some(bucket.window),
                    pool: bucket.scope.map(|s| s.value.clone()),
                    // `on_exhaust` is declared on (and validated against) the BUDGET metric
                    // only; a requests/tokens block on the same bucket still blocks.
                    downgrade_to: (metric == "budget" && !refused)
                        .then(|| bucket.downgrade_to.map(|s| s.value.clone()))
                        .flatten(),
                    retry_after: super::window_end(bucket.window, now)
                        .map(|end| end.saturating_sub(now).max(1)),
                });
            }
        }

        // The arrival's card era: each bucket's fee base records the request under the card in
        // force at admission, so a card edit reprices only what follows it.
        let era = crate::rate_apply::effective_from_at(wall_ms());
        // Another plane's request is one fee unit on ITS fee lane (#47), not the flat fee base.
        let one = || BTreeMap::from([(PER_REQUEST.to_string(), 1)]);
        let plane_fee = (!plane.is_empty()).then(|| (plane_fee_lane(plane), one()));
        // PASS 2 - CHARGE every bucket (+1 request, dirty) under the SAME held guards: atomic
        // all-or-nothing with the checks above. STRADDLE-SAFE cell resolution (mirrors
        // `accrue_bucket`): reset ONLY a genuinely stale cell (this window strictly newer); a cell
        // holding the SAME or a NEWER window is charged IN PLACE.
        for (bi, bucket) in buckets.iter().enumerate() {
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.window, now);
            let map = guards[gi].as_deref_mut().expect("guard held");
            let cell = match map.get_mut(bucket.bucket_id) {
                Some(c) if window > c.window_start => {
                    *c = BudgetCell::fresh(window);
                    c
                }
                Some(c) => c, // same window or straddle (cell newer) - charge the live cell
                None => map
                    .entry(bucket.bucket_id.to_string())
                    .or_insert_with(|| BudgetCell::fresh(window)),
            };
            cell.requests = cell.requests.saturating_add(1);
            if let Some((lane, one)) = &plane_fee {
                cell.accrue(lane, era, one);
            } else {
                cell.billable_requests = cell.billable_requests.saturating_add(1);
                cell.fee_eras.charge(era);
            }
            cell.dirty = true;
            cell.last_touch = now;
        }
        Ok(grant)
    }

    /// Refund the request charged at admission across EVERY bucket of the key's chain, for a
    /// request that produced no usable upstream result (non-2xx). Keeps the flat-fee policy "bill
    /// 2xx only" intact (the fee derives from the request count, so -1 request = -1 fee on the key
    /// bucket). `now` MUST be the same `charged_at` epoch the admission charge used so the refund
    /// lands on the SAME cell per bucket the charge landed on — including the straddle, where a
    /// concurrent admission rolled the cell forward between this request's arrival and its charge
    /// and the charge landed in place on the rolled cell. Only a bucket whose cell is genuinely
    /// OLDER than this request's window is a no-op: that is a window already left behind rather
    /// than one this request reached.
    /// Floored at 0 - a refund can never drive a counter negative.
    pub fn refund_request(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
    ) {
        let Ok(chain) = cost.chain_for(key) else {
            // The charge failed closed on a missing group, so nothing was charged; refund only the
            // key bucket defensively (it floors at 0 on a no-op).
            self.refund_bucket(&key.id, super::WINDOW_TOTAL, now);
            return;
        };
        // Refund EXACTLY the buckets the admission charged: the same pool predicate, so a
        // pool-scoped bucket another pool's request never charged is never eroded by its refund.
        for bucket in chain.iter().filter(|b| b.applies_to_pool(pool)) {
            self.refund_bucket(bucket.bucket_id, bucket.window, now);
        }
    }

    fn refund_bucket(&self, bucket_id: &str, budget_period: &str, now: u64) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        if let Some(cell) = map.get_mut(bucket_id) {
            // The exact inverse of the charge's cell resolution: that lands a charge in place on a
            // cell holding this window OR a newer one, so this returns the fee from the same set.
            // An equality test here would leave the flat fee for a failed straddling request on the
            // rolled cell forever, and the derived spend the budget cap reads one fee too high for
            // the rest of that window.
            if cell.window_start >= window {
                // Refund ONLY the billable (fee-base) counter - the flat fee bills 2xx only. The
                // admission `requests` counter is NEVER refunded, so a failed request still
                // consumed its requests-limit slot (a caller cannot escape the requests cap by
                // hammering failures).
                cell.billable_requests = cell.billable_requests.saturating_sub(1);
                cell.fee_eras.refund();
                cell.dirty = true;
            }
        }
    }

    /// WRITE-BEHIND flush of the dirty in-memory budget cells to the durable store — ADDITIVE, so
    /// the shared store reflects the TRUE FLEET TOTAL. Runs OFF the request hot path (the periodic
    /// flusher + the graceful-shutdown arm).
    ///
    /// Under each shard lock, snapshot every dirty cell's DELTA since its last acknowledged flush
    /// (current - flushed baseline) and clear its dirty flag; then OFF the lock, `add_usage`
    /// (atomic accumulate in the store) each delta and advance the cell's acked baseline on
    /// success. With N nodes sharing one store, each node's deltas SUM into the durable record —
    /// where the old absolute `put_usage` overwrite made the record whichever node flushed last.
    ///
    /// On a store error, log, RE-MARK the cell dirty, and do NOT advance the baseline, so the
    /// unacked delta is retried next tick (at-least-once: an ack lost after the write landed can
    /// double-count at most one flush interval — the honest trade for fleet additivity; the
    /// in-memory admission cap is unaffected). Snapshotting under the lock but writing off it keeps
    /// the hot-path lock hold O(dirty). Returns the number of cells flushed.
    pub fn flush_budgets(&self) -> usize {
        /// Clamp a u64 counter into the signed delta domain.
        fn signed(v: u64) -> i64 {
            i64::try_from(v).unwrap_or(i64::MAX)
        }
        /// One dirty cell's snapshot: the PER-MODEL TOKEN delta payload for `Store::add_usage`
        /// plus the current absolute counters that become the acked baseline on success. No dollar
        /// figure anywhere - only tokens + requests cross the wire.
        struct DirtySnap {
            bucket_id: String,
            window: u64,
            delta: UsageDelta,
            cur_requests: u64,
            cur_billable_requests: u64,
            cur_models: Vec<ModelCell>,
        }
        // Snapshot dirty cells across ALL shards and clear their flags. One shard is locked at a
        // time (the `write_all` iterator acquires each guard lazily), so a concurrent charge
        // blocks only on the single shard the snapshot currently holds, not the whole map.
        let mut dirty: Vec<DirtySnap> = Vec::new();
        for mut map in self.budget.write_all() {
            for (id, cell) in map.iter_mut() {
                if !cell.dirty {
                    continue;
                }
                // The signed delta-since-last-ack per unit key, summed over a model's ERAS: the
                // durable row is per model (it carries no era — Q14's wire step), so the eras of one
                // model are one delta on the wire, byte-identical to an undated cell's.
                let deltas = cell.models.iter().map(|m| {
                    // The UNION of unit keys in cur+flushed (freshly accrued, or refunded away).
                    let keys = m.cur.keys().chain(m.flushed.keys());
                    let at = |side: &std::collections::BTreeMap<String, u64>, k: &String| {
                        signed(side.get(k).copied().unwrap_or(0))
                    };
                    let d = keys.map(|k| (k.clone(), at(&m.cur, k) - at(&m.flushed, k)));
                    (&*m.model, d.collect())
                });
                let models: Vec<busbar_api::ModelTokensDelta> =
                    busbar_kernel_ledger::usage::by_lane(deltas, i64::saturating_add)
                        .into_iter()
                        .map(|(model, mut usage_units)| {
                            usage_units.retain(|_, v| *v != 0);
                            busbar_api::ModelTokensDelta { model, usage_units }
                        })
                        .filter(|d| !d.usage_units.is_empty())
                        .collect();
                dirty.push(DirtySnap {
                    bucket_id: id.clone(),
                    window: cell.window_start,
                    delta: UsageDelta {
                        requests: signed(cell.requests) - signed(cell.flushed_requests),
                        billable_requests: signed(cell.billable_requests)
                            - signed(cell.flushed_billable_requests),
                        models,
                    },
                    cur_requests: cell.requests,
                    cur_billable_requests: cell.billable_requests,
                    cur_models: cell.models.clone(),
                });
                cell.dirty = false;
            }
        }
        let mut flushed = 0usize;
        // Aggregate failures: during a store outage every dirty bucket fails on the same tick, so a
        // per-bucket `warn!` spams. Emit exactly ONE throttled warn per tick with the failed count;
        // per-bucket detail (bucket + error) stays at `debug!`.
        let mut failed = 0usize;
        let mut last_error: Option<String> = None;
        for snap in dirty {
            let outcome = if snap.delta.is_zero() {
                // Nothing new since the last acked flush (e.g. a charge fully refunded back to the
                // baseline): the durable record is already correct; skip the store round-trip.
                Ok(())
            } else {
                self.store
                    .add_usage(&snap.bucket_id, snap.window, &snap.delta)
            };
            match outcome {
                Ok(()) => {
                    flushed += 1;
                    // Advance the acked baselines - only if the cell still holds the SAME window
                    // (a rollover since the snapshot reset the cell; its zeroed baselines are
                    // already correct for the new window).
                    let mut map = self.budget.write(&snap.bucket_id);
                    if let Some(cell) = map.get_mut(&snap.bucket_id) {
                        if cell.window_start == snap.window {
                            cell.flushed_requests = snap.cur_requests;
                            cell.flushed_billable_requests = snap.cur_billable_requests;
                            for s in &snap.cur_models {
                                let seg = |m: &&mut ModelCell| m.model == s.model && m.era == s.era;
                                if let Some(mc) = cell.models.iter_mut().find(seg) {
                                    mc.flushed = s.cur.clone();
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    tracing::debug!(bucket = %snap.bucket_id, error = %e, "budget flush failed for bucket; will retry next tick");
                    last_error = Some(e.to_string());
                    // RE-MARK dirty so the delta is not lost — only if the cell still exists for
                    // the SAME window (after a rollover the old window's unacked delta is dropped
                    // with the cell, exactly as the pre-additive flusher behaved).
                    let mut map = self.budget.write(&snap.bucket_id);
                    if let Some(cell) = map.get_mut(&snap.bucket_id) {
                        if cell.window_start == snap.window {
                            cell.dirty = true;
                        }
                    }
                }
            }
        }
        if failed > 0 {
            diag_warn!(
                BUDGET_FLUSH_PARTIAL_FAILURE,
                failed,
                flushed,
                error = last_error.as_deref().unwrap_or(""),
                "budget flush: {failed} bucket(s) failed to persist this tick; re-marked dirty and \
                 will retry next tick (per-bucket detail at debug)"
            );
        }
        flushed
    }

    /// Load every LIVE key, indexed by id (the token `sub` / subject id) — the sole in-memory key
    /// index since 1.5.0 has exactly one bearer-credential shape (a signed token resolved by
    /// subject id; there is no longer a hashed-secret index to key by).
    ///
    /// `store.list_keys()` is deliberately unfiltered (tombstones included, so admin listing and
    /// billing attribution can see them) — this index is NOT that: it backs `lookup_by_sub`, the
    /// auth hot path, so a tombstoned key must be structurally absent from it. Filtering here,
    /// once, at load/refresh time, is what makes a deleted key's outstanding tokens stop
    /// authenticating: `verify_token` never sees the row at all, rather than seeing it and having
    /// to remember to check `deleted_at` on every lookup.
    pub fn load(store: &dyn Store) -> StoreResult<HashMap<String, Arc<VirtualKey>>> {
        // Wrap each key in `Arc` at load time so the per-request `lookup_by_sub` on the hot path is
        // a refcount bump, not a deep clone; the values are immutable until the next `refresh` swap.
        Ok(store
            .list_keys()?
            .into_iter()
            .filter(|k| k.deleted_at.is_none())
            .map(|k| (k.id.clone(), Arc::new(k)))
            .collect())
    }

    /// Build the `(kind, public_id)` → resolved-credential index from the durable, GENERALIZED
    /// `credentials` store surface (`list_credentials_since(0)` — a full load), joined against the
    /// already-loaded `by_id` snapshot (which holds the live `VirtualKey` rows, keyed by id). A
    /// credential whose owning key is missing from `by_id`, or that is not currently live
    /// (`CredentialMeta::is_live`, checking `revoked_at`/`expires_at`), is SKIPPED — it can never
    /// authenticate, so it has no business occupying a cache slot. `(kind, public_id)` is
    /// `UNIQUE` at the store layer, so entries are unique.
    pub fn load_by_credential(
        store: &dyn Store,
        by_id: &HashMap<String, Arc<VirtualKey>>,
        now: u64,
    ) -> StoreResult<super::CredentialIndex> {
        let mut map = HashMap::new();
        for cred in store.list_credentials_since(0)? {
            if !cred.meta.is_live(now) {
                continue;
            }
            if let Some(key) = by_id.get(cred.meta.key_id.as_str()) {
                map.insert(
                    (cred.meta.kind.clone(), cred.meta.public_id.clone()),
                    (key.clone(), cred),
                );
            }
        }
        Ok(map)
    }

    /// Resolve a wire-supplied `(kind, public_id)` pair (SigV4: `kind = "sigv4"`, `public_id` = the
    /// AccessKeyId parsed in plaintext from the `Credential=` field of the `Authorization` header)
    /// to the owning virtual key plus the resolved credential secret. Used ONLY by the
    /// SigV4-credential verify path (today's sole row-looked-up kind). Returns `None` for an
    /// unknown pair — the verify path is written so an unknown identifier and a bad signature reject
    /// indistinguishably (no enumeration oracle): on the `None` branch the caller still runs a
    /// constant-time signature comparison against a dummy secret before rejecting.
    pub fn lookup_credential(
        &self,
        kind: &str,
        public_id: &str,
    ) -> Option<(Arc<VirtualKey>, CredentialSecret)> {
        self.caches_read()
            .by_credential
            .get(&(kind.to_string(), public_id.to_string()))
            .cloned()
    }

    /// Direct handle to the backing store — for tests that seed/inspect persistence AND for the boot
    /// audit wiring (the durable audit sink + restore read the configured governance store).
    pub fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    /// Reload BOTH caches (the subject-id index and the row-looked-up credential index) from the
    /// store after a management-API mutation. Rebuild `by_credential` from the SAME fresh `by_id`
    /// snapshot so the two indices can never drift (a key disabled/deleted/re-minted, or a
    /// credential revoked/rotated, is reflected in both).
    ///
    /// `pub`: every caller is inside this crate -- `revoke`/`create_key`/`update_key`/
    /// `delete_key`/`rotate_key` below, and this crate's own tests. Nothing outside busbar-core
    /// names it, so the cache-reload door is not part of the engine's public surface.
    pub fn refresh(&self) -> StoreResult<()> {
        // Serialize the whole load→swap so a slow refresh can't clobber a newer one's cache with
        // strictly-older store state (lost-update guard; see `refresh_lock`). A later refresh's
        // `load` cannot begin until an earlier refresh has swapped, so its snapshot is never older.
        let _refresh_guard = self.refresh_lock.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = Self::load(self.store.as_ref())?;
        let fresh_cred =
            Self::load_by_credential(self.store.as_ref(), &fresh, busbar_kernel::store::now())?;
        // Both indices live under the single `caches` lock, so the swap below is ONE atomic critical
        // section — a concurrent reader holding `caches_read` sees either the entire old pair or the
        // entire new pair, never a new `by_id` against a stale `by_credential` (or vice versa).
        let mut c = self.caches_write();
        c.by_id = fresh;
        c.by_credential = fresh_cred;
        Ok(())
    }
}

/// Whether an ALL-TIME (`window_start == 0`) budget cell still backs an ENFORCED cap — the exact
/// (and only) reason the amortized shard sweep exempts a cell from age-based eviction.
///
/// A cell qualifies only when its id IS the id of a live bucket that still carries at least one
/// windowed cap. Anything else — a group deleted through `DELETE /groups/{name}` or dropped from
/// config, an auto-provisioned `user:<sub>` leaf that never carried a cap at all, a bucket whose
/// limit the operator removed — enforces nothing, so pinning its cell in memory forever buys nothing
/// and leaks. Those age out by last touch (and only while clean) exactly like a key's own uncapped
/// attribution cell.
///
/// PURE IDENTITY, NEVER A PARSE. This used to strip `group:` and take everything before the FIRST
/// `@` as the group name, on the stated premise that a group name cannot contain one. THAT PREMISE
/// IS FALSE — nothing charset-checks a group name, and the SSO auto-provisioning path mints
/// `user:<idp-subject>` leaves whose subject is normally an EMAIL. So `group:user:alice@corp.com@
/// total` resolved to the group `user:alice`, which does not exist, and the cell of a live,
/// all-time, BUDGET-CAPPED group was reported as enforcing nothing: once clean and idle past the
/// window it was DROPPED, and since hydrate is boot-only its lifetime spend re-read as 0 — an
/// EXHAUSTED all-time cap silently started admitting again. That is a BUDGET BYPASS, strictly worse
/// than the leak the check was added to close. Asking the cost model whether it owns this exact id
/// removes the delimiter assumption entirely, for `@` and `#` alike.
///
/// Non-`group:` ids are never in the set (a key bucket is uncapped by construction).
fn still_enforces_a_cap(cost: &crate::cost::CostModel, bucket_id: &str) -> bool {
    cost.bucket_enforces_a_cap(bucket_id)
}

/// A money figure the one function REFUSED, carried out of a usage read through the read's own
/// error channel (#42: *"a cost request FAILS if billing-on & unpriced"*). The read fails loudly
/// rather than answering a figure nobody priced; the refusal is named in the text, which every
/// caller already logs under its own diagnostic code.
fn money_refusal(bucket_id: &str, e: &busbar_kernel_ledger::cost::MoneyError) -> StoreError {
    StoreError(format!(
        "the spend of bucket `{bucket_id}` cannot be priced: {e}"
    ))
}

/// The durable ledger's per-model rows as undated segments (the row carries no era).
fn durable_segments(rows: Vec<busbar_api::ModelTokens>) -> Vec<ModelCell> {
    let segment = |m: busbar_api::ModelTokens| ModelCell {
        model: std::sync::Arc::from(m.model),
        era: 0,
        cur: m.usage_units,
        flushed: BTreeMap::new(),
    };
    rows.into_iter().map(segment).collect()
}
