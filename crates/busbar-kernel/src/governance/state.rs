use super::*;
use busbar_contract::redacted::Secret;
use busbar_kernel_ledger::cost::{
    plane_fee_lane, split_plane_lane, History, Money, MoneyError, MICROS_PER_CENT, PER_REQUEST,
};
use std::collections::BTreeMap;

use crate::store::now_ms as wall_ms;

use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, ACCRUAL_GROUP_MISSING, BUDGET_FLUSH_PARTIAL_FAILURE,
    DELETE_KEY_CACHE_RECONCILE_FAILED, METERING_FLUSH_PARTIAL_FAILURE,
    REFRESH_SELF_CACHE_REFRESH_FAILED, REFRESH_SELF_INCONSISTENT_BINDING,
    ROTATE_KEY_CACHE_RECONCILE_FAILED,
};

#[path = "self_serve.rs"]
mod self_serve;

#[path = "ledger_adjust.rs"]
pub(super) mod ledger_adjust;
pub use ledger_adjust::{
    metering_lane, AdjustRefused, Adjustment, PricedBucket, UsageAdjustment, ADJUST_DOWN_BUCKET,
    ADJUST_UP_BUCKET,
};

pub const REVOCATION_DURABLE_MARKER: &str = "REVOCATION APPLIED (cache reconcile degraded)";

pub const ROTATION_DURABLE_MARKER: &str = "ROTATION APPLIED (new secret not returned)";

/// A mint can commit its binding before cache reconciliation fails. An applied failure
/// exposes only the public key identifier; no issued credential is returned.
#[derive(Debug)]
pub enum MintError {
    Store(RecordStoreError),
    Applied {
        key_id: String,
        reconcile: RecordStoreError,
    },
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => error.fmt(f),
            Self::Applied { key_id, .. } => write!(
                f,
                "MINT APPLIED (new secret not returned): key '{key_id}' was committed but cache reconciliation failed; revoke or delete this key before minting a replacement"
            ),
        }
    }
}

impl std::error::Error for MintError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Store(error) => error,
            Self::Applied { reconcile, .. } => reconcile,
        })
    }
}

impl From<RecordStoreError> for MintError {
    fn from(error: RecordStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<MintError> for RecordStoreError {
    fn from(error: MintError) -> Self {
        match error {
            MintError::Store(error) => error,
            applied => Self(applied.to_string()),
        }
    }
}

fn signed_binding(spec: NewKeySpec, now: u64) -> RecordStoreResult<(VirtualKey, String)> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| RecordStoreError(format!("CSPRNG unavailable: {e}")))?;
    let id = format!("{VK_ID_PREFIX}{}", hex::encode(raw));
    let generation = generate_binding_generation().store()?;
    let binding = VirtualKey {
        id: id.clone(),

        generation_hash: binding_marker(&id, &generation),
        name: spec.name,

        allowed_scopes: crate::governance::grant_scopes(spec.allowed_pools, spec.plane_scopes),
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
    Ok((binding, generation))
}

impl GovState {
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(
        store: Arc<dyn RecordStore>,
        admin_token: Option<String>,
    ) -> RecordStoreResult<Self> {
        Self::new_with_signer(store, admin_token, None)
    }

    pub fn new_with_signer(
        store: Arc<dyn RecordStore>,
        admin_token: Option<String>,
        signer: Option<crate::governance::signing::TokenSigner>,
    ) -> RecordStoreResult<Self> {
        let by_id = Self::load(store.as_ref())?;
        let by_credential =
            Self::load_by_credential(store.as_ref(), &by_id, busbar_kernel::store::now())?;

        let denylist: std::collections::HashSet<String> =
            store.list_denylist()?.into_iter().collect();
        let caches = Arc::new(RwLock::new(GovCaches {
            by_id,
            by_credential,
        }));
        let refresh_order = Arc::new(CacheOrder::default());

        let denylist = crate::governance::revocation::RevocationSync::reloading(
            store.clone(),
            denylist,
            busbar_kernel::store::now(),
            {
                let (store, caches, order) = (store.clone(), caches.clone(), refresh_order.clone());
                Box::new(move || reload_caches(store.as_ref(), &caches, &order))
            },
        );

        let mut boot_caller_ref = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(boot_caller_ref.as_mut_slice())
            .expect("OS randomness for the per-boot caller-reference key");
        Ok(Self {
            store,
            caches,
            concurrent: RwLock::new(HashMap::new()),
            admin_token_hash: RwLock::new(
                admin_token
                    .as_ref()
                    .map(|t| busbar_contract::redacted::sha256_hex(t.as_bytes())),
            ),
            budget: Sharded::new(),
            recovery_book: recovery::RecoveryBook::default(),
            correction_claims: claims::ClaimSet::new(),
            corrections: std::sync::Mutex::new(HashMap::new()),
            budget_flushes: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            budget_flush_runner: BudgetFlushRunner::default(),
            deleting_budget_buckets: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            pending_metering: PendingMetering::new(),
            money_view: money_view::MoneyView::default(),
            caller_refs: Arc::new(RwLock::new(Some(Arc::new(match signer.as_ref() {
                Some(s) => crate::auth::CallerRefKey::derive(&s.secret_bytes()),
                None => crate::auth::CallerRefKey::derive(&boot_caller_ref[..]),
            })))),
            deployment_caller_ref: RwLock::new(None),
            boot_caller_ref,
            signing: RwLock::new(signer.map(|s| Arc::new(SigningMaterial::new(s)))),
            at_rest: RwLock::new(None),
            denylist,
            refresh_order,
            mutation_claims: claims::ClaimSet::new(),
            self_mint_holds: std::sync::atomic::AtomicBool::new(
                SELF_MINT_HOLDS_ADMIN_AND_PROVIDER_STATE,
            ),
            store_calls: std::sync::OnceLock::new(),
            amendments: Arc::default(),
        })
    }

    #[must_use]
    pub fn amendments(&self) -> &Arc<crate::audit::amend::NodeAmendments> {
        &self.amendments
    }

    pub fn attach_store_calls(
        &self,
        calls: Arc<dyn busbar_contract::store_calls::StoreCalls>,
    ) -> bool {
        self.store_calls.set(calls).is_ok()
    }

    #[must_use]
    pub fn store_calls(&self) -> Option<Arc<dyn busbar_contract::store_calls::StoreCalls>> {
        self.store_calls.get().cloned()
    }

    fn sync_revocations_if_stale(&self, now: u64) {
        self.denylist.refresh_if_stale(now);
    }

    pub fn signing_enabled(&self) -> bool {
        self.signing_material().is_some()
    }

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
        self.standing_key(&claims, now)
    }

    pub(super) fn standing_key(
        &self,
        claims: &super::signing::TokenClaims,
        now: u64,
    ) -> Option<Arc<VirtualKey>> {
        self.sync_revocations_if_stale(now);
        if self.denylist.contains(&claims.sub) {
            tracing::debug!(sub = %claims.sub, "signed-token rejected: subject is revoked");
            return None;
        }

        match self.lookup_by_sub(&claims.sub) {
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

    pub fn lookup_by_sub(&self, sub: &str) -> Option<Arc<VirtualKey>> {
        self.caches_read().by_id.get(sub).cloned()
    }

    pub fn revoke(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        let _claim = self.claim_key_mutation(sub)?;
        for cred in self.store.list_credentials(sub)? {
            if cred.revoked_at.is_none() {
                self.store.revoke_credential(&cred.id, reason)?;
            }

            self.refresh_order.patch(|| {
                self.caches_write()
                    .by_credential
                    .remove(&(cred.kind, cred.public_id));
            });
        }
        self.store.add_denylist(sub, reason)?;
        self.refresh_order.patch(|| self.denylist.insert(sub));
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

        self.refresh_order.patch(|| {
            let mut c = self.caches_write();
            self.denylist.insert(sub);
            if let Some(key) = new_key {
                c.by_id.insert(sub.to_string(), key);
            }
        });
        Ok(())
    }

    pub fn is_revoked(&self, sub: &str) -> bool {
        self.is_revoked_at(sub, busbar_kernel::store::now())
    }

    pub fn is_revoked_at(&self, sub: &str, now: u64) -> bool {
        self.sync_revocations_if_stale(now);
        self.denylist.contains(sub)
    }

    pub fn mint_signed(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, Secret<String>), MintError> {
        let Some(material) = self.signing_material() else {
            return Err(RecordStoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            )
            .into());
        };
        let (binding, generation) = signed_binding(spec, now)?;
        self.store.put_key(&binding)?;
        self.refresh().map_err(|reconcile| MintError::Applied {
            key_id: binding.id.clone(),
            reconcile,
        })?;
        let token = material.signer.mint(&binding.id, exp, Some(&generation));
        Ok((binding, token.into()))
    }

    pub fn mint_signed_with_credential(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
        kind: &str,
        shape: &busbar_contract::auth_calls::IssuedShape,
    ) -> Result<(VirtualKey, Secret<String>, String, Secret<String>), MintError> {
        let Some(material) = self.signing_material() else {
            return Err(RecordStoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            )
            .into());
        };

        let Some(keys) = self.at_rest_keys() else {
            return Err(RecordStoreError(super::at_rest::NO_KEY_REFUSAL.to_string()).into());
        };
        let (binding, generation) = signed_binding(spec, now)?;
        let (public_id, secret_value) = super::issue_credential(shape).store()?;
        let secret_value = Secret::new(secret_value);
        let mut cred_raw = [0u8; 16];
        getrandom::fill(&mut cred_raw)
            .map_err(|e| RecordStoreError(format!("CSPRNG unavailable: {e}")))?;
        let cred_id = format!("cred_{}", hex::encode(cred_raw));

        let meta = CredentialMeta {
            id: cred_id,
            key_id: binding.id.clone(),
            kind: kind.to_string(),
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

        let sealed = keys
            .seal(&meta, secret_value.expose(&crate::seal::lend()).as_bytes())
            .map_err(RecordStoreError)?;
        let secret = CredentialSecret {
            meta,
            secret: sealed,
        };
        self.store.put_key_with_credential(&binding, &secret)?;
        self.refresh().map_err(|reconcile| MintError::Applied {
            key_id: binding.id.clone(),
            reconcile,
        })?;
        let token = material.signer.mint(&binding.id, exp, Some(&generation));
        Ok((binding, token.into(), public_id, secret_value))
    }

    #[must_use]
    pub fn caller_ref_slot(&self) -> crate::plane_driver::CallerRefs {
        Arc::clone(&self.caller_refs)
    }

    pub fn bind_deployment_caller_ref(&self, material: [u8; 32]) {
        *self
            .deployment_caller_ref
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(material);
        self.refresh_caller_refs();
    }

    fn refresh_caller_refs(&self) {
        let key = match self.signing_material() {
            Some(m) => crate::auth::CallerRefKey::derive(&m.signer.secret_bytes()),
            None => match *self
                .deployment_caller_ref
                .read()
                .unwrap_or_else(|e| e.into_inner())
            {
                Some(m) => crate::auth::CallerRefKey::derive(&m),
                None => crate::auth::CallerRefKey::derive(&self.boot_caller_ref[..]),
            },
        };
        *self.caller_refs.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(key));
    }

    pub fn signing_kid(&self) -> Option<String> {
        self.signing_material().map(|m| m.signer.kid().to_string())
    }

    pub fn card_issuer(&self) -> Option<crate::plane_driver::registry::CardIssuer> {
        let decl = crate::plane_driver::registry::plane_decl_for_config_section("agents")?;
        let domain = decl.card_signing_domain?;
        let prefix = decl.card_kid_prefix?;
        let m = self.signing_material()?;
        Some(crate::plane_driver::registry::CardIssuer {
            kid: format!("{prefix}{}", m.signer.kid()),
            issuer_spki_base64: m.signer.subkey_key_info_base64(domain),
        })
    }

    pub fn sign_in_domain(&self, domain: &str, input: &[u8]) -> Option<(String, [u8; 64])> {
        let m = self.signing_material()?;
        Some((
            m.signer.kid().to_string(),
            m.signer.sign_with_subkey(domain, input),
        ))
    }

    #[allow(dead_code)]
    pub fn signing_secret(&self) -> Option<[u8; 32]> {
        self.signing_material().map(|m| m.signer.secret_bytes())
    }

    pub fn record_usage(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        self.record_usage_served(cost, key, pool, model, None, units, now);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_usage_served(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        let era = crate::rate_apply::era_at(crate::store::now_ms());
        self.record_usage_served_in_era(cost, key, pool, model, provider, units, now, era);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_usage_served_in_era(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
        era: RawRateEra,
    ) {
        if units.values().all(|v| *v == 0) {
            return;
        }

        self.meter_classes(key, model, provider, units, era, now);

        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            Err(missing) => {
                diag_debug!(ACCRUAL_GROUP_MISSING, key = %key.id, group = missing,
                    "group missing at accrual; tokens ledgered to the key bucket only");
                self.accrue_bucket(&key.id, None, super::WINDOW_TOTAL, (model, era), units, now);
                return;
            }
        };

        let (_, pool) = split_plane_lane(pool);
        for bucket in chain.iter().filter(|b| b.applies_to_pool(pool)) {
            self.accrue_bucket(
                bucket.bucket_id,
                bucket.group_name,
                bucket.window,
                (model, era),
                units,
                now,
            );
        }
    }

    fn meter_classes(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        era: RawRateEra,
        now: u64,
    ) {
        let (plane, subject) = busbar_kernel_ledger::cost::split_plane_lane(lane);
        let usage_units: std::collections::BTreeMap<String, u64> = units
            .iter()
            .filter(|(class, n)| {
                **n != 0
                    && !(plane.is_empty()
                        && busbar_contract::records::RESERVED_UNITS.contains(&class.as_str()))
            })
            .map(|(class, n)| (class.clone(), *n))
            .collect();
        if usage_units.is_empty() {
            return;
        }
        let (model, provider) = if plane.is_empty() {
            (lane, provider.unwrap_or(""))
        } else {
            (subject, plane)
        };
        let key: MeterKey = (
            key.id.clone(),
            metering_bucket(now),
            model.to_string(),
            provider.to_string(),
            era.effective_from,
            key.group.clone().unwrap_or_default(),
            era.entry_id
                .map(|id| id.metering_version())
                .unwrap_or_default(),
        );
        self.pending_metering.accrue(
            key,
            MeterCounts {
                usage_units,
                ..MeterCounts::default()
            },
        );
    }

    pub fn record_lane_metering(
        &self,
        key_id: &str,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        self.record_lane_metering_attributed(
            key_id,
            "",
            lane,
            provider,
            units,
            now,
            crate::rate_apply::era_at(wall_ms()),
        );
    }

    pub fn record_lane_metering_for_key(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        self.record_lane_metering_in_era(
            key,
            lane,
            provider,
            units,
            now,
            crate::rate_apply::era_at(wall_ms()),
        );
    }

    pub fn record_lane_metering_in_era(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
        era: RawRateEra,
    ) {
        self.record_lane_metering_attributed(
            &key.id,
            key.group.as_deref().unwrap_or(""),
            lane,
            provider,
            units,
            now,
            era,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_lane_metering_attributed(
        &self,
        key_id: &str,
        key_group_at_use: &str,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
        era: RawRateEra,
    ) {
        match split_plane_lane(lane) {
            ("", _) => {
                if let Some(provider) = provider {
                    let add = MeterCounts::request(units);
                    self.record_metered_request_in_era(
                        key_id,
                        key_group_at_use,
                        lane,
                        provider,
                        add,
                        now,
                        era,
                    );
                }
            }
            (plane, subject) => {
                let add = MeterCounts::request(&std::collections::BTreeMap::new());
                self.record_metered_request_in_era(
                    key_id,
                    key_group_at_use,
                    subject,
                    plane,
                    add,
                    now,
                    era,
                );
            }
        }
    }

    fn accrue_bucket(
        &self,
        bucket_id: &str,
        group: Option<&str>,
        budget_period: &str,
        (model, era): (&str, RawRateEra),
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        let cell = match map.get_mut(bucket_id) {
            Some(c) if window > c.window_start => {
                c.roll(window);
                c
            }
            Some(c) => c,
            None => map
                .entry(bucket_id.to_string())
                .or_insert_with(|| BudgetCell::fresh(window)),
        };
        cell.mutate(|cell| {
            if let Some(group) = group {
                cell.group_owners.insert(group.to_string());
            }
            cell.accrue_raw(model, era, units);
            cell.dirty = true;
            cell.last_touch = now;
        });
    }

    pub fn record_metering(
        &self,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&busbar_contract::billing::TokenUsage>,
        now: u64,
    ) {
        let add = MeterCounts {
            requests: 1,
            tokens_input: usage.map(|u| u.input).unwrap_or(0),
            tokens_output: usage.map(|u| u.output).unwrap_or(0),
            tokens_cache_read: usage.and_then(|u| u.cache_read).unwrap_or(0),
            tokens_cache_write: usage.and_then(|u| u.cache_creation).unwrap_or(0),
            usage_units: std::collections::BTreeMap::new(),
        };
        self.record_metered_request(key_id, "", model, provider, add, now);
    }

    fn record_metered_request(
        &self,
        key_id: &str,
        key_group_at_use: &str,
        model: &str,
        provider: &str,
        add: MeterCounts,
        now: u64,
    ) {
        self.record_metered_request_dated(
            key_id,
            key_group_at_use,
            model,
            provider,
            add,
            now,
            &crate::store::now_ms,
            &crate::rate_apply::era_at,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_metered_request_dated<E: Into<RawRateEra>>(
        &self,
        key_id: &str,
        key_group_at_use: &str,
        model: &str,
        provider: &str,
        add: MeterCounts,
        now: u64,
        clock_ms: &dyn Fn() -> u64,
        dater: &dyn Fn(u64) -> E,
    ) {
        let era = dater(clock_ms()).into();
        self.record_metered_request_in_era(
            key_id,
            key_group_at_use,
            model,
            provider,
            add,
            now,
            era,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_metered_request_in_era(
        &self,
        key_id: &str,
        key_group_at_use: &str,
        model: &str,
        provider: &str,
        add: MeterCounts,
        now: u64,
        era: RawRateEra,
    ) {
        let key: MeterKey = (
            key_id.to_string(),
            metering_bucket(now),
            model.to_string(),
            provider.to_string(),
            era.effective_from,
            key_group_at_use.to_owned(),
            era.entry_id
                .map(|id| id.metering_version())
                .unwrap_or_default(),
        );

        self.pending_metering.accrue(key, add);
    }

    #[cfg(test)]
    pub fn pending_metering_totals(&self) -> (usize, MeterCounts) {
        self.pending_metering.totals()
    }

    pub fn flush_metering(&self) -> usize {
        self.flush_metering_inner(false)
    }

    pub fn flush_metering_final(&self) -> usize {
        self.flush_metering_inner(true)
    }

    fn flush_metering_inner(&self, shutdown: bool) -> usize {
        if self.store.supports_metering_batch_deduped() {
            return self.flush_metering_deduped(shutdown);
        }
        let taken = self.pending_metering.drain();
        let mut flushed = 0usize;

        let mut failed = 0usize;
        let mut unrecorded: Vec<String> = Vec::new();
        let mut last_error: Option<String> = None;
        for (
            (key_id, bucket, model, provider, priced_from_ms, key_group_at_use, pricing_version),
            counts,
        ) in taken
        {
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
                key_group_at_use: key_group_at_use.clone(),
                pricing_version: pricing_version.clone(),

                priced_from_ms,
                usage_units: counts.usage_units.clone(),
            };
            match self.store.add_metering(&delta) {
                Ok(()) => flushed += 1,
                Err(e) => {
                    failed += 1;
                    if shutdown {
                        unrecorded.push(format!("{key_id}/{model}/{provider}@{bucket}"));
                    } else {
                        tracing::debug!(key = %key_id, error = %e, "metering flush failed for key; will retry next tick");
                    }
                    last_error = Some(e.to_string());

                    self.pending_metering.accrue(
                        (
                            key_id,
                            bucket,
                            model,
                            provider,
                            priced_from_ms,
                            key_group_at_use,
                            pricing_version,
                        ),
                        counts,
                    );
                }
            }
        }
        if failed > 0 && shutdown {
            diag_error!(
                METERING_FLUSH_PARTIAL_FAILURE,
                failed,
                flushed,
                error = last_error.as_deref().unwrap_or(""),
                "shutdown metering flush: the store is unreachable and the process is exiting; \
                 {failed} metering cell(s) are NOT recorded: {}",
                unrecorded.join(", ")
            );
        } else if failed > 0 {
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

    pub fn metering_for(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.store.list_metering(bucket)
    }

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
            if bucket.requests_cap.is_none() && bucket.tokens_cap.is_none() {
                continue;
            }

            let applies = match pool {
                Some(p) => bucket.applies_to_pool(p),
                None => bucket.scope.is_none(),
            };
            if !applies {
                continue;
            }
            let window = budget_window(bucket.window, now);

            let (requests, tokens) = match self.budget.read(bucket.bucket_id).get(bucket.bucket_id)
            {
                Some(cell) if cell.window_start == window => (cell.requests, cell.total_tokens()),
                _ => (0, 0),
            };
            let frac = |used: u64, cap: u64| -> f64 {
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

    fn caches_read(&self) -> std::sync::RwLockReadGuard<'_, GovCaches> {
        self.caches.read().unwrap_or_else(|p| p.into_inner())
    }

    fn caches_write(&self) -> std::sync::RwLockWriteGuard<'_, GovCaches> {
        self.caches.write().unwrap_or_else(|p| p.into_inner())
    }

    pub fn admin_token_hash(&self) -> Option<String> {
        self.admin_token_hash
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_admin_token(&self, token: Option<&str>) {
        let hash = token.map(|t| busbar_contract::redacted::sha256_hex(t.as_bytes()));
        *self
            .admin_token_hash
            .write()
            .unwrap_or_else(|e| e.into_inner()) = hash;
    }

    pub fn set_signing_key(&self, signer: Option<crate::governance::signing::TokenSigner>) {
        let next = signer.map(|s| Arc::new(SigningMaterial::new(s)));
        *self.signing.write().unwrap_or_else(|e| e.into_inner()) = next;
        self.refresh_caller_refs();
    }

    pub fn set_at_rest_keys(&self, keys: Option<super::at_rest::AtRestKeys>) -> bool {
        let kids = |k: Option<&super::at_rest::AtRestKeys>| {
            k.map(|k| (k.kid().to_string(), k.previous_kid().map(str::to_string)))
        };
        let next = keys.map(Arc::new);
        let mut slot = self.at_rest.write().unwrap_or_else(|e| e.into_inner());
        let changed = kids(slot.as_deref()) != kids(next.as_deref());
        *slot = next;
        changed
    }

    pub fn at_rest_enabled(&self) -> bool {
        self.at_rest_keys().is_some()
    }

    fn at_rest_keys(&self) -> Option<Arc<super::at_rest::AtRestKeys>> {
        self.at_rest
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn rewrap_credentials(&self, now: u64) -> RecordStoreResult<super::at_rest::Rewrap> {
        if self.at_rest_keys().is_none() {
            return Ok(super::at_rest::Rewrap::default());
        }
        let rows = self.store.list_credentials_since(0)?;
        self.rewrap_rows(rows, now)
    }

    pub fn rewrap_rows(
        &self,
        rows: Vec<CredentialSecret>,
        now: u64,
    ) -> RecordStoreResult<super::at_rest::Rewrap> {
        let mut pass = super::at_rest::Rewrap::default();
        let Some(keys) = self.at_rest_keys() else {
            return Ok(pass);
        };
        for row in rows {
            if row.meta.revoked_at.is_some() {
                continue;
            }
            let Some(plain) = super::at_rest::stale(&keys, &row.meta, &row.secret) else {
                continue;
            };
            let digest = ring::digest::digest(&ring::digest::SHA256, row.secret.as_bytes());
            let token = format!(
                "{}:{}:{}",
                keys.kid(),
                row.meta.id,
                hex::encode(&digest.as_ref()[..16])
            );
            let claimed = self
                .store
                .redeem_plane_token(
                    super::at_rest::REWRAP_CLAIM_KIND,
                    &token,
                    now.saturating_add(super::at_rest::REWRAP_CLAIM_SECS),
                    now,
                )
                .unwrap_or(false);
            if !claimed {
                pass.pending += 1;
                continue;
            }
            let written = keys.seal(&row.meta, plain.as_bytes()).and_then(|sealed| {
                self.store
                    .rewrap_credential(&row, &sealed)
                    .map_err(|e| e.to_string())
            });
            match written {
                Ok(true) => pass.resealed += 1,
                Ok(false) => pass.pending += 1,
                Err(e) => {
                    pass.pending += 1;
                    diag_warn!(
                        crate::diagnostics::CREDENTIAL_AT_REST_REWRAP_PENDING,
                        kind = %row.meta.kind,
                        error = %e,
                        "a recoverable credential could not be re-sealed under \
                         credentials.at_rest.key; it still opens under the key it was sealed under"
                    );
                }
            }
        }
        if pass.resealed > 0 {
            self.refresh()?;
            crate::audit_ring::AUDIT.record_by(
                "credential.at_rest.rewrap",
                &format!("kid:{} rows:{}", keys.kid(), pass.resealed),
                crate::audit_ring::OUTCOME_APPLIED,
                "busbar",
            );
        }
        Ok(pass)
    }

    pub(super) fn signing_material(&self) -> Option<Arc<SigningMaterial>> {
        self.signing
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    #[cfg(test)]
    pub fn create_key(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> RecordStoreResult<(VirtualKey, String)> {
        crate::test_support::governance::create_key(self, spec, now)
    }

    #[cfg(test)]
    pub fn create_key_with_aws(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> RecordStoreResult<(VirtualKey, String, String, String)> {
        crate::test_support::governance::create_key_with_aws(self, spec, now)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn ensure_id_free_for_hash(&self, id: &str, hash: &str) -> RecordStoreResult<()> {
        if let Some(existing) = self.store.get_key(id)? {
            if existing.generation_hash != hash {
                return Err(RecordStoreError(format!(
                    "virtual-key id collision: derived id '{id}' already belongs to a different key; \
                     retry to mint with fresh entropy (this is a ~2^-64 birthday event)"
                )));
            }
        }
        Ok(())
    }

    pub fn all_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.store.list_keys()
    }

    pub fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        let _claim = self.claim_key_mutation(id)?;
        let _correction = self.correction_claims.claim(id.to_string());
        self.settle_correction_for_delete(id)?;
        let _budget_delete = self.hold_budget_flush_deletion(id);
        self.settle_budget_flush_for_delete(id)?;
        self.store.delete_key(id)?;

        self.evict_key_from_caches(id);
        let refreshed = self.refresh();

        let mut cells = self.budget.write(id);
        if !cells.get(id).is_some_and(|cell| cell.correction.is_some()) {
            cells.remove(id);
        }
        drop(cells);
        self.money_view.forget(id);
        if let Err(refresh_err) = refreshed {
            diag_error!(
                DELETE_KEY_CACHE_RECONCILE_FAILED,
                key_id = %id,
                refresh_err = %refresh_err,
                "delete_key: the tombstone is COMMITTED in the store and the key was evicted from \
                 the in-memory caches (it no longer authenticates), but the full cache reconcile \
                 failed; other cache entries may be stale until the next successful refresh"
            );
            return Err(RecordStoreError(format!(
                "{REVOCATION_DURABLE_MARKER}: key '{id}' IS revoked — the tombstone is committed in \
                 the store and the credential was evicted from the in-memory cache, so it no longer \
                 authenticates. Only the full cache reconcile failed ({refresh_err}); OTHER cache \
                 entries may be stale until the next successful refresh. Do NOT re-issue this \
                 revocation expecting it to have been a no-op — it took effect."
            )));
        }
        Ok(())
    }

    fn evict_key_from_caches(&self, id: &str) {
        self.refresh_order.patch(|| {
            let mut c = self.caches_write();
            c.by_id.remove(id);
            c.by_credential.retain(|_, (key, _)| key.id != id);
        });
    }

    fn patch_key_in_caches(&self, key: Arc<VirtualKey>) {
        self.refresh_order.patch(|| {
            let mut c = self.caches_write();
            for (owner, _) in c.by_credential.values_mut() {
                if owner.id == key.id {
                    *owner = key.clone();
                }
            }
            c.by_id.insert(key.id.clone(), key);
        });
    }

    fn claim_key_mutation(&self, id: &str) -> RecordStoreResult<claims::Claim<'_, MutationKey>> {
        self.mutation_claims
            .claim_checked(MutationKey::Key(id.to_string()))
            .ok_or_else(|| RecordStoreError("reentrant key mutation refused".into()))
    }

    pub fn reclaim_group_cells(&self, group: &str) -> usize {
        let mut dropped = 0usize;
        for mut shard in self.budget.write_all() {
            let before = shard.len();

            shard.retain(|_, cell| {
                if cell.dirty
                    || cell.flushing != 0
                    || cell.correction.is_some()
                    || !cell.group_owners.contains(group)
                {
                    return true;
                }
                cell.group_owners.remove(group);
                !cell.group_owners.is_empty()
            });
            dropped += before - shard.len();
        }

        self.concurrent
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group);
        dropped
    }

    pub fn rotate_key(&self, id: &str, exp: u64) -> RecordStoreResult<Option<RotatedCredential>> {
        let _claim = self.claim_key_mutation(id)?;
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };

        if key.deleted_at.is_some() {
            return Ok(None);
        }
        let Some(material) = self.signing_material() else {
            return Err(RecordStoreError(
                "cannot rotate a signed-token key: no signing key is configured (rotation \
                 re-mints the token)"
                    .to_string(),
            ));
        };
        let generation = generate_binding_generation().store()?;
        key.generation_hash = binding_marker(&key.id, &generation);
        self.store.put_key(&key)?;

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
            return Err(RecordStoreError(format!(
                "{ROTATION_DURABLE_MARKER}: key '{id}' WAS rotated — the new generation is \
                 committed in the store, so the PREVIOUS credential is permanently dead and was \
                 evicted from the in-memory cache. Only the cache reconcile failed \
                 ({refresh_err}), so the newly-minted token could not be returned and is now \
                 unrecoverable. This was NOT a no-op: rotate this key again to obtain a usable \
                 credential."
            )));
        }
        let token: Secret<String> = material.signer.mint(&key.id, exp, Some(&generation)).into();
        Ok(Some(RotatedCredential { key, token, exp }))
    }

    pub fn update_key(
        &self,
        id: &str,
        enabled: Option<bool>,
        group: Option<Option<String>>,
    ) -> RecordStoreResult<Option<VirtualKey>> {
        let _claim = self.claim_key_mutation(id)?;
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };

        if key.deleted_at.is_some() {
            return Ok(None);
        }
        if let Some(e) = enabled {
            key.enabled = e;
        }

        if let Some(g) = group {
            key.group = g;
        }

        self.store.put_key(&key)?;
        self.patch_key_in_caches(Arc::new(key.clone()));
        self.refresh()?;
        Ok(Some(key))
    }

    pub fn hydrate_budgets(
        &self,
        cost: &crate::cost::CostModel,
        now: u64,
    ) -> RecordStoreResult<()> {
        let keys = self.store.list_keys()?;
        let key_buckets = keys
            .iter()
            .map(|k| (k.id.as_str(), super::WINDOW_TOTAL, None));
        let group_buckets = cost.groups().iter().flat_map(|g| {
            g.buckets
                .iter()
                .map(move |b| (b.bucket_id.as_str(), b.window, Some(g.name.as_str())))
        });
        for (bucket_id, period, group) in key_buckets.chain(group_buckets) {
            let window = budget_window(period, now);
            let mut cell = self.stored_cell(bucket_id, window)?;
            if cell.requests == 0 && cell.models.is_empty() {
                continue;
            }

            cell.last_touch = now;
            let mut cells = self.budget.write(bucket_id);
            if let Some(group) = group {
                cell.group_owners.insert(group.to_string());
            }
            if let Some(previous) = cells.get(bucket_id) {
                if previous.correction.is_some() || previous.dirty || previous.flushing != 0 {
                    return Err(RecordStoreError(
                        "budget hydration has unresolved raw usage custody".into(),
                    ));
                }
                cell.group_owners
                    .extend(previous.group_owners.iter().cloned());
            }
            cells.insert(bucket_id.to_string(), cell);
        }
        Ok(())
    }

    pub fn usage_for(
        &self,
        cost: &crate::cost::CostModel,
        id: &str,
        now: u64,
    ) -> RecordStoreResult<Option<DerivedUsage>> {
        self.key_usage(id, |id| {
            self.derived_bucket_usage(cost, id, super::WINDOW_TOTAL, true, now)
        })
    }

    fn key_usage(
        &self,
        id: &str,
        read: impl FnOnce(&str) -> RecordStoreResult<DerivedUsage>,
    ) -> RecordStoreResult<Option<DerivedUsage>> {
        match self.store.get_key(id)? {
            Some(_) => read(id).map(Some),
            None => Ok(None),
        }
    }

    pub fn derived_bucket_usage(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> RecordStoreResult<DerivedUsage> {
        self.derived_bucket_usage_priced(cost, bucket_id, budget_period, include_request_fee, now)?
            .map_err(|e| money_refusal(bucket_id, &e))
    }

    pub fn derived_bucket_usage_priced(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> RecordStoreResult<Result<DerivedUsage, busbar_kernel_ledger::cost::MoneyError>> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell(bucket_id, window)?;
        self.price_cell(cost, include_request_fee, cell)
    }

    pub fn viewed_bucket_usage(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> RecordStoreResult<DerivedUsage> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell(bucket_id, window)?;
        let inputs = money_view::Inputs::of(cost, budget_period, include_request_fee, &cell);
        let priced = match self.money_view.fresh(bucket_id, &inputs) {
            Some(priced) => priced,
            None => {
                let priced = self.price_cell(cost, include_request_fee, cell)?;
                self.money_view.keep(bucket_id, inputs, priced.clone());
                priced
            }
        };
        priced.map_err(|e| money_refusal(bucket_id, &e))
    }

    pub fn viewed_usage_for(
        &self,
        cost: &crate::cost::CostModel,
        id: &str,
        now: u64,
    ) -> RecordStoreResult<Option<DerivedUsage>> {
        self.key_usage(id, |id| {
            self.viewed_bucket_usage(cost, id, super::WINDOW_TOTAL, true, now)
        })
    }

    #[cfg(test)]
    pub fn money_view_pricings(&self) -> u64 {
        self.money_view.pricings()
    }

    fn bucket_cell(&self, bucket_id: &str, window: u64) -> RecordStoreResult<BudgetCell> {
        let live = {
            let cells = self.budget.read(bucket_id);
            if cells
                .get(bucket_id)
                .is_some_and(|cell| cell.correction.is_some())
            {
                return Err(RecordStoreError(
                    "usage correction outcome unresolved".into(),
                ));
            }
            cells
                .get(bucket_id)
                .filter(|cell| cell.window_start == window)
                .cloned()
        };
        Ok(match live {
            Some(cell) => cell,
            None => self.stored_cell(bucket_id, window)?,
        })
    }

    fn stored_cell(&self, bucket_id: &str, window: u64) -> RecordStoreResult<BudgetCell> {
        let row = self.store.get_usage(bucket_id, window)?;
        let eras = if row.models.is_empty() && row.billable_requests == 0 {
            busbar_contract::records::UsageLedger::default()
        } else {
            self.store.get_usage(&era_bucket(bucket_id), window)?
        };
        durable_cell(row, eras, window)
    }

    fn price_cell(
        &self,
        cost: &crate::cost::CostModel,
        include_request_fee: bool,
        cell: BudgetCell,
    ) -> RecordStoreResult<Result<DerivedUsage, MoneyError>> {
        self.money_view.priced();

        let spend = cell.spend(cost, include_request_fee);
        Ok(spend
            .and_then(Money::minor_i64)
            .map(|spend_cents| DerivedUsage {
                spend_cents,
                tokens: cell.total_tokens(),
                requests: cell.requests,
            }))
    }

    pub fn bucket_model_tokens(
        &self,
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
        let Ok(models) = read else {
            return Vec::new();
        };

        let models = models.iter().map(|m| (&*m.model, m.cur.clone()));
        busbar_kernel_ledger::usage::by_lane(models, u64::saturating_add)
    }

    pub fn budget_state(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState> {
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

            let (spend_micros, remaining_micros) = match spend {
                Ok(spend_micros) => (
                    spend_micros,
                    bucket.budget_cap.map(|cap| {
                        cap.saturating_mul(MICROS_PER_CENT)
                            .saturating_sub(spend_micros)
                            .max(0)
                    }),
                ),
                Err(_) => (i64::MAX, Some(0)),
            };
            out.push(busbar_contract::hooks::BudgetBucketState {
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
    /// in `finish`; a non-2xx outcome refunds the grant's [`FeeCharge`] via
    /// [`GovState::refund_charge`]. This allocates a handful of chain-sized scratch `Vec`s per call
    /// (`chain_for`'s two Vecs, the collected bucket slice, the shard-index/order/guard Vecs sized
    /// to the chain depth, the grant's charged cells) — there are no fixed
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
        self.admit_checked(cost, key, pool, now, Some(0))
    }

    pub fn try_admit_estimated(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
        models: &[&str],
        expected: &BTreeMap<String, u64>,
    ) -> Result<AdmitGrant, LimitBlocked> {
        self.admit_checked(cost, key, pool, now, cost.estimate_minor(models, expected))
    }

    fn admit_checked(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
        estimate: Option<i64>,
    ) -> Result<AdmitGrant, LimitBlocked> {
        let (plane, pool) = split_plane_lane(pool);

        let missing = |g: &str| LimitBlocked::MissingGroup(g.to_string());
        let chain = cost.chain_for(key).map_err(missing)?;

        let buckets: Vec<&crate::cost::ChainBucket<'_>> =
            chain.iter().filter(|b| b.applies_to_pool(pool)).collect();
        let groups = cost.groups();

        for &gi in chain.group_indices() {
            if !groups[gi].enabled {
                return Err(LimitBlocked::Disabled(groups[gi].name.clone()));
            }
        }

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
                drop(grant);
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
                continue;
            }
            let shard = self.budget.shard_at(sh);

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
                        return c.correction.is_some()
                            || c.dirty
                            || c.flushing != 0
                            || c.window_start.saturating_add(max_window) > now;
                    }

                    c.correction.is_some()
                        || still_enforces_a_cap(cost, id)
                        || c.dirty
                        || c.flushing != 0
                        || c.last_touch.saturating_add(max_window) > now
                });

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

        for (bi, bucket) in buckets.iter().enumerate() {
            if bucket.requests_cap.is_none()
                && bucket.tokens_cap.is_none()
                && bucket.class_caps.is_empty()
                && bucket.budget_cap.is_none()
            {
                continue;
            }
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.window, now);
            let map = guards[gi].as_deref().expect("guard held");

            let (requests, tokens, live, derived) = match map.get(bucket.bucket_id) {
                Some(cell) if cell.window_start >= window => (
                    cell.correction.as_ref().map_or(cell.requests, |branch| {
                        cell.requests.max(branch.accepted.requests)
                    }),
                    bucket.tokens_cap.map_or(0, |_| {
                        cell.correction
                            .as_ref()
                            .map_or(cell.total_tokens(), |branch| {
                                cell.total_tokens().max(branch.accepted.total_tokens())
                            })
                    }),
                    Some(cell),
                    bucket.budget_cap.map_or(Ok(0), |_| {
                        let before = cell.spend(cost, true).and_then(Money::minor_i64)?;
                        match &cell.correction {
                            Some(branch) => branch
                                .accepted
                                .spend(cost, true)
                                .and_then(Money::minor_i64)
                                .map(|after| before.max(after)),
                            None => Ok(before),
                        }
                    }),
                ),

                _ => (0, 0, None, Ok(0)),
            };
            let class_blocked = (bucket.class_caps.iter())
                .find(|c| {
                    live.map_or(0, |cell| {
                        cell.correction
                            .as_ref()
                            .map_or(cell.total_tier(c.class), |branch| {
                                cell.total_tier(c.class)
                                    .max(branch.accepted.total_tier(c.class))
                            })
                    }) >= c.cap
                })
                .map(|c| c.metric.as_str());

            let (derived, refused) = match derived {
                Ok(d) => (d, false),
                Err(_) => (0, true),
            };

            let (guess, refused) = match (bucket.budget_admission, estimate) {
                (crate::config::groups::AdmissionMode::Exact, _) => (0, refused),
                (crate::config::groups::AdmissionMode::Estimate, Some(e)) => (e, refused),
                (crate::config::groups::AdmissionMode::Estimate, None) => (0, true),
            };
            let blocked_metric = if bucket
                .requests_cap
                .is_some_and(|cap| requests.saturating_add(1) > cap)
            {
                Some("requests")
            } else if bucket.tokens_cap.is_some_and(|cap| tokens >= cap) {
                Some("tokens")
            } else if class_blocked.is_some() {
                class_blocked
            } else if bucket.budget_cap.is_some_and(|cap| {
                refused || derived >= cap || derived.saturating_add(fee).saturating_add(guess) > cap
            }) {
                Some("budget")
            } else {
                None
            };
            if let Some(metric) = blocked_metric {
                drop(guards);
                drop(grant);
                return Err(LimitBlocked::Limit {
                    group: bucket
                        .group_name
                        .expect("only group buckets carry caps")
                        .to_string(),
                    metric,
                    window: Some(bucket.window),
                    pool: bucket.scope.map(|s| s.value.clone()),

                    downgrade_to: (metric == "budget" && !refused)
                        .then(|| bucket.downgrade_to.map(|s| s.value.clone()))
                        .flatten(),
                    retry_after: super::window_end(bucket.window, now)
                        .map(|end| end.saturating_sub(now).max(1)),
                });
            }
        }

        let era = crate::rate_apply::era_at(wall_ms());

        let one = || BTreeMap::from([(PER_REQUEST.to_string(), 1)]);
        let plane_fee = (!plane.is_empty()).then(|| (plane_fee_lane(plane), one()));
        grant.charge.lane = plane_fee.as_ref().map(|(lane, _)| lane.clone());
        grant.charge.era = era;

        for (bi, bucket) in buckets.iter().enumerate() {
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.window, now);
            let map = guards[gi].as_deref_mut().expect("guard held");
            let cell = match map.get_mut(bucket.bucket_id) {
                Some(c) if window > c.window_start => {
                    c.roll(window);
                    c
                }
                Some(c) => c,
                None => map
                    .entry(bucket.bucket_id.to_string())
                    .or_insert_with(|| BudgetCell::fresh(window)),
            };
            cell.mutate(|cell| {
                if let Some(group) = bucket.group_name {
                    cell.group_owners.insert(group.to_string());
                }
                cell.requests = cell.requests.saturating_add(1);
                if let Some((lane, one)) = &plane_fee {
                    cell.accrue_raw(lane, era, one);
                } else {
                    cell.billable_requests = cell.billable_requests.saturating_add(1);
                    cell.fee_eras.charge(era);
                }
                cell.dirty = true;
                cell.last_touch = now;
            });

            let reached = (bucket.bucket_id.to_string(), cell.window_start);
            grant.charge.cells.push(reached);
        }
        Ok(grant)
    }

    pub fn refund_charge(&self, charge: &FeeCharge) {
        let lane = charge.lane.as_deref().map(|l| (l, PER_REQUEST));
        for (bucket_id, window) in &charge.cells {
            let mut map = self.budget.write(bucket_id);
            let Some(cell) = map.get_mut(bucket_id) else {
                continue;
            };
            cell.mutate(|cell| {
                if cell.window_start == *window {
                    refund_in_place(cell, lane, charge.era);
                } else if cell.window_start > *window {
                    let taken_back = match lane {
                        None => UsageDelta {
                            billable_requests: -1,
                            ..UsageDelta::default()
                        },
                        Some((lane, unit)) => UsageDelta {
                            models: vec![busbar_contract::records::ModelTokensDelta {
                                model: lane.to_string(),
                                usage_units: BTreeMap::from([(unit.to_string(), -1)]),
                            }],
                            ..UsageDelta::default()
                        },
                    };
                    cell.park_eras(*window, dated_delta(&taken_back, charge.era));
                    cell.park(*window, taken_back);
                    cell.dirty = true;
                }
            });
        }
    }

    pub fn refund_fee_unit(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
        fee_unit: &str,
    ) {
        self.refund_fee_unit_in_era(cost, key, pool, now, fee_unit, None);
    }

    pub fn refund_fee_unit_in_era(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
        fee_unit: &str,
        era: Option<RawRateEra>,
    ) {
        let (plane, pool) = split_plane_lane(pool);
        if plane.is_empty() {
            return;
        }
        let fee_lane = plane_fee_lane(plane);
        let lane = (fee_lane.as_str(), fee_unit);
        let Ok(chain) = cost.chain_for(key) else {
            self.refund_bucket(&key.id, super::WINDOW_TOTAL, now, lane, era);
            return;
        };

        for bucket in chain.iter().filter(|b| b.applies_to_pool(pool)) {
            self.refund_bucket(bucket.bucket_id, bucket.window, now, lane, era);
        }
    }

    fn refund_bucket(
        &self,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
        (lane, unit): (&str, &str),
        era: Option<RawRateEra>,
    ) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        if let Some(cell) = map.get_mut(bucket_id) {
            cell.mutate(|cell| {
                if cell.window_start >= window {
                    let held = (cell.models.iter_mut())
                        .filter(|m| {
                            &*m.model == lane
                                && era.is_none_or(|era| m.era == era)
                                && m.cur.get(unit).is_some_and(|n| *n > 0)
                        })
                        .max_by_key(|m| m.era);
                    if let Some(m) = held {
                        take_one(&mut m.cur, unit);
                    }
                    cell.dirty = true;
                }
            });
        }
    }

    pub fn flush_budgets(&self) -> usize {
        self.flush_budgets_inner(false)
    }

    pub fn flush_budgets_final(&self) -> usize {
        self.flush_budgets_inner(true)
    }

    fn flush_budgets_inner(&self, shutdown: bool) -> usize {
        let _runner = match self.budget_flush_runner.enter(shutdown) {
            Ok(runner) => runner,
            Err(message) => {
                if shutdown {
                    diag_error!(BUDGET_FLUSH_PARTIAL_FAILURE, error = message, "{message}");
                }
                return 0;
            }
        };
        let mut unresolved_corrections = self.retry_usage_corrections();
        if self.recovery_enabled() {
            if let Err(error) = self.resume_raw_recovery() {
                unresolved_corrections.push(error.to_string());
            }
        }

        for mut map in self.budget.write_all() {
            for (id, cell) in map.iter_mut() {
                if cell.dirty {
                    let _ = self.capture_budget_flushes(id, cell);
                }
            }
        }
        let (mut flushed, chunk_errors) = self.resume_budget_flushes(shutdown);
        unresolved_corrections.extend(chunk_errors);

        struct Acked {
            requests: u64,
            billable_requests: u64,
            models: Vec<ModelCell>,
            fee_eras: RawFeeEras,
        }

        struct DirtySnap {
            bucket_id: String,
            window: u64,
            delta: UsageDelta,

            eras: UsageDelta,
            acked: Option<Acked>,
        }

        let mut dirty: Vec<DirtySnap> = Vec::new();
        let mut new_flights = Vec::new();
        for mut map in self.budget.write_all() {
            for (id, cell) in map.iter_mut() {
                if !cell.dirty || self.budget_bucket_deleting(id) {
                    continue;
                }

                new_flights.extend(self.capture_budget_flushes(id, cell));
                if self.store.supports_usage_batch_deduped() {
                    let correcting = cell.correction.is_some();
                    cell.mutate(|cell| {
                        cell.dirty = correcting
                            || !ExactUsageDelta::of(cell, false).is_zero()
                            || !ExactUsageDelta::of(cell, true).is_zero()
                            || !cell.rolled.is_empty()
                            || !cell.rolled_eras.is_empty();
                    });
                    continue;
                }
                let reserved_window = cell.correction.as_ref().map(|branch| branch.window);
                let mut rolled = BTreeMap::<u64, (UsageDelta, UsageDelta)>::new();
                let mut drained_plain = std::collections::BTreeSet::new();
                let mut drained_dated = std::collections::BTreeSet::new();
                for (window, delta) in std::mem::take(&mut cell.rolled) {
                    if Some(window) == reserved_window
                        || cell.flushing_windows.contains_key(&window)
                    {
                        cell.rolled.push((window, delta));
                    } else {
                        drained_plain.insert(window);
                        rolled.entry(window).or_default().0 =
                            delta.signed().expect("checked representability");
                    }
                }
                for (window, eras) in std::mem::take(&mut cell.rolled_eras) {
                    if Some(window) == reserved_window
                        || cell.flushing_windows.contains_key(&window)
                    {
                        cell.rolled_eras.push((window, eras));
                    } else {
                        drained_dated.insert(window);
                        rolled.entry(window).or_default().1 =
                            eras.signed().expect("checked representability");
                    }
                }
                let flush_current = Some(cell.window_start) != reserved_window
                    && !cell.flushing_windows.contains_key(&cell.window_start);
                cell.flushing += rolled.len() + usize::from(flush_current);
                for window in rolled.keys() {
                    *cell.flushing_windows.entry(*window).or_default() += 1;
                }
                if flush_current {
                    *cell.flushing_windows.entry(cell.window_start).or_default() += 1;
                }
                if let Some(branch) = cell.correction.as_mut() {
                    branch
                        .accepted
                        .rolled
                        .retain(|(window, _)| !drained_plain.contains(window));
                    branch
                        .accepted
                        .rolled_eras
                        .retain(|(window, _)| !drained_dated.contains(window));
                    branch.accepted.flushing = cell.flushing;
                    branch.accepted.flushing_windows = cell.flushing_windows.clone();
                    branch.accepted.dirty = true;
                }
                for (window, (delta, eras)) in rolled {
                    dirty.push(DirtySnap {
                        bucket_id: id.clone(),
                        window,
                        delta,
                        eras,
                        acked: None,
                    });
                }
                if flush_current {
                    dirty.push(DirtySnap {
                        bucket_id: id.clone(),
                        window: cell.window_start,
                        delta: cell.unflushed(),
                        eras: cell.unflushed_eras(),
                        acked: Some(Acked {
                            requests: cell.requests,
                            billable_requests: cell.billable_requests,
                            models: cell.models.clone(),
                            fee_eras: cell.fee_eras.clone(),
                        }),
                    });
                }
                cell.dirty = cell.correction.is_some()
                    || !cell.rolled.is_empty()
                    || !cell.rolled_eras.is_empty()
                    || !flush_current;
            }
        }

        let mut failed = unresolved_corrections.len();
        let mut unrecorded: Vec<String> = if shutdown {
            unresolved_corrections.clone()
        } else {
            Vec::new()
        };
        let mut last_error: Option<String> = unresolved_corrections.last().cloned();
        for snap in dirty {
            let outcome = if snap.delta.is_zero() {
                Ok(())
            } else {
                self.store
                    .add_usage(&snap.bucket_id, snap.window, &snap.delta)
            };
            let era_outcome = if outcome.is_err() {
                None
            } else if snap.eras.is_zero() {
                Some(Ok(()))
            } else {
                Some(
                    self.store
                        .add_usage(&era_bucket(&snap.bucket_id), snap.window, &snap.eras),
                )
            };
            let mut map = self.budget.write(&snap.bucket_id);
            if let Some(cell) = map.get_mut(&snap.bucket_id) {
                cell.mutate(|cell| {
                    if cell.flushing != 0 {
                        cell.flushing -= 1;
                    }
                    if let Some(count) = cell.flushing_windows.get_mut(&snap.window) {
                        *count -= 1;
                        if *count == 0 {
                            cell.flushing_windows.remove(&snap.window);
                        }
                    }
                });
            }
            let plain_ok = outcome.is_ok();
            let era_ok = matches!(era_outcome, Some(Ok(())));
            if let Some(cell) = map.get_mut(&snap.bucket_id) {
                cell.mutate(|cell| {
                    if let Some(acked) = &snap.acked {
                        if cell.window_start == snap.window {
                            if plain_ok {
                                cell.flushed_requests = acked.requests;
                                cell.flushed_billable_requests = acked.billable_requests;
                                cell.advance_model_baselines(&acked.models, false);
                            }
                            if era_ok {
                                cell.flushed_fee_eras = acked.fee_eras.clone();
                                cell.advance_model_baselines(&acked.models, true);
                            }
                        } else if cell.window_start > snap.window {
                            if plain_ok {
                                cell.park(snap.window, negated(&snap.delta));
                            }
                            if era_ok {
                                cell.park_eras(snap.window, negated(&snap.eras));
                            }
                            cell.dirty = true;
                        }
                    } else {
                        if !plain_ok {
                            cell.park(snap.window, snap.delta.clone());
                        }
                        if !era_ok {
                            cell.park_eras(snap.window, snap.eras.clone());
                        }
                    }
                    cell.dirty |= !plain_ok || !era_ok;
                });
            } else if !plain_ok || !era_ok {
                let mut cell = BudgetCell::fresh(snap.window);
                if !plain_ok {
                    cell.park(snap.window, snap.delta.clone());
                }
                if !era_ok {
                    cell.park_eras(snap.window, snap.eras.clone());
                }
                cell.dirty = true;
                map.insert(snap.bucket_id.clone(), cell);
            }
            if plain_ok && era_ok {
                flushed += 1;
            } else {
                failed += 1;
                let error = outcome.err().or_else(|| era_outcome.and_then(Result::err));
                if shutdown {
                    unrecorded.push(format!("{}@{}", snap.bucket_id, snap.window));
                } else if let Some(error) = &error {
                    tracing::debug!(bucket = %snap.bucket_id, %error, "budget flush failed for bucket; will retry next tick");
                }
                last_error = error.map(|error| error.to_string());
            }
        }
        let (late_flushed, late_errors) = if shutdown {
            self.resume_budget_flushes(true)
        } else {
            self.resume_budget_flush_list(new_flights, false)
        };
        flushed += late_flushed;
        failed += late_errors.len();
        if let Some(error) = late_errors.last() {
            last_error = Some(error.clone());
        }
        if shutdown {
            unrecorded.extend(late_errors);
        }
        if failed > 0 && shutdown {
            diag_error!(
                BUDGET_FLUSH_PARTIAL_FAILURE,
                failed,
                flushed,
                error = last_error.as_deref().unwrap_or(""),
                "shutdown budget flush: the store is unreachable and the process is exiting; \
                 {failed} bucket window(s) are NOT recorded: {}",
                unrecorded.join(", ")
            );
        } else if failed > 0 {
            diag_warn!(
                BUDGET_FLUSH_PARTIAL_FAILURE,
                failed,
                flushed,
                error = last_error.as_deref().unwrap_or(""),
                "budget flush: {failed} bucket(s) failed to persist this tick; retained for \
                 retry next tick (per-bucket detail at debug)"
            );
        }
        flushed
    }

    pub fn load(store: &dyn RecordStore) -> RecordStoreResult<HashMap<String, Arc<VirtualKey>>> {
        Ok(store
            .list_keys()?
            .into_iter()
            .filter(|k| k.deleted_at.is_none())
            .map(|k| (k.id.clone(), Arc::new(k)))
            .collect())
    }

    pub fn load_by_credential(
        store: &dyn RecordStore,
        by_id: &HashMap<String, Arc<VirtualKey>>,
        now: u64,
    ) -> RecordStoreResult<super::CredentialIndex> {
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

    pub fn credential_secret(
        &self,
        kind: &str,
        public_id: &str,
        now: u64,
    ) -> (busbar_contract::redacted::Secret<String>, bool) {
        let keys = self.at_rest_keys();

        let (key, plain, enabled) = match self.lookup_credential(kind, public_id) {
            Some((key, cred)) => {
                let plain = if cred.meta.is_live(now) {
                    super::at_rest::open(keys.as_deref(), &cred.meta, &cred.secret)
                        .map(|p| p.to_string())
                } else {
                    None
                };
                (key.id.clone(), plain, key.enabled)
            }
            None => (String::new(), None, false),
        };
        let revoked = self.is_revoked_at(&key, now);
        let live = enabled && plain.is_some() && !revoked;
        let secret = plain.unwrap_or_default();
        (busbar_contract::redacted::Secret::new(secret), live)
    }

    pub fn store(&self) -> Arc<dyn RecordStore> {
        self.store.clone()
    }

    pub fn refresh(&self) -> RecordStoreResult<()> {
        reload_caches(self.store.as_ref(), &self.caches, &self.refresh_order)
    }
}

fn reload_caches(
    store: &dyn RecordStore,
    caches: &RwLock<GovCaches>,
    order: &CacheOrder,
) -> RecordStoreResult<()> {
    loop {
        let ticket = order.ticket();
        let fresh = GovState::load(store)?;
        let fresh_cred = GovState::load_by_credential(store, &fresh, busbar_kernel::store::now())?;
        match order.turn(ticket) {
            CacheTurn::Swap(_turn) => {
                let mut c = caches.write().unwrap_or_else(|p| p.into_inner());
                c.by_id = fresh;
                c.by_credential = fresh_cred;
                return Ok(());
            }
            CacheTurn::Stale => return Ok(()),
            CacheTurn::Reload => continue,
        }
    }
}

fn still_enforces_a_cap(cost: &crate::cost::CostModel, bucket_id: &str) -> bool {
    cost.bucket_enforces_a_cap(bucket_id)
}

fn refund_in_place(cell: &mut BudgetCell, lane: Option<(&str, &str)>, era: RawRateEra) {
    cell.mutate(|cell| {
        match lane {
            None => {
                cell.billable_requests = cell.billable_requests.saturating_sub(1);
                cell.fee_eras.refund(era);
            }

            Some((lane, unit)) => {
                let charged = (cell.models.iter_mut()).find(|m| &*m.model == lane && m.era == era);
                if let Some(m) = charged {
                    take_one(&mut m.cur, unit);
                }
            }
        }
        cell.dirty = true;
    });
}

fn take_one(counts: &mut BTreeMap<String, u64>, unit: &str) {
    if let Some(n) = counts.get_mut(unit) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            counts.remove(unit);
        }
    }
}

fn negated(delta: &UsageDelta) -> UsageDelta {
    UsageDelta {
        requests: delta.requests.saturating_neg(),
        billable_requests: delta.billable_requests.saturating_neg(),
        models: (delta.models.iter())
            .map(|m| busbar_contract::records::ModelTokensDelta {
                model: m.model.clone(),
                usage_units: (m.usage_units.iter())
                    .map(|(k, v)| (k.clone(), v.saturating_neg()))
                    .collect(),
            })
            .collect(),
    }
}

fn money_refusal(bucket_id: &str, e: &busbar_kernel_ledger::cost::MoneyError) -> RecordStoreError {
    RecordStoreError(format!(
        "the spend of bucket `{bucket_id}` cannot be priced: {e}"
    ))
}

fn durable_cell(
    row: busbar_contract::records::UsageLedger,
    eras: busbar_contract::records::UsageLedger,
    window: u64,
) -> RecordStoreResult<BudgetCell> {
    let mut cell = BudgetCell::fresh(window);
    cell.requests = row.requests;
    cell.billable_requests = row.billable_requests;
    cell.flushed_requests = row.requests;
    cell.flushed_billable_requests = row.billable_requests;
    cell.models = durable_segments(row.models);
    let (mut fees, mut undated_fees) = (Vec::new(), row.billable_requests);
    for e in eras.models {
        let (era, model) = match e.model.split_once(ERA_MODEL_SEP) {
            Some((era, model)) => (era, Some(model)),
            None => (e.model.as_str(), None),
        };
        let Some(era) = parse_era_tag(era)? else {
            continue;
        };
        if era == RawRateEra::legacy(0) {
            continue;
        }
        let Some(model) = model else {
            let n = (e.usage_units.get(ERA_FEE_UNIT).copied().unwrap_or(0)).min(undated_fees);
            undated_fees -= n;
            fees.push((era, n));
            continue;
        };
        let rest =
            (cell.models.iter_mut()).find(|m| m.era == RawRateEra::legacy(0) && *m.model == *model);
        let Some(rest) = rest else {
            continue;
        };
        let mut cur = BTreeMap::new();
        for (unit, n) in e.usage_units {
            let left = rest.cur.get(&unit).copied().unwrap_or(0);
            let n = n.min(left);
            if n == 0 {
                continue;
            }
            if left == n {
                rest.cur.remove(&unit);
            } else {
                rest.cur.insert(unit.clone(), left - n);
            }
            cur.insert(unit, n);
        }
        let model = rest.model.clone();
        let flushed = BTreeMap::new();
        cell.models.push(ModelCell {
            model,
            era,
            cur,
            flushed,
            flushed_era: BTreeMap::new(),
        });
    }
    for m in &mut cell.models {
        m.flushed = m.cur.clone();
        m.flushed_era = m.cur.clone();
    }
    cell.fee_eras = busbar_kernel_ledger::usage::FeeEras::of(fees);
    cell.flushed_fee_eras = cell.fee_eras.clone();
    Ok(cell)
}

fn durable_segments(rows: Vec<busbar_contract::records::ModelTokens>) -> Vec<ModelCell> {
    let segment = |m: busbar_contract::records::ModelTokens| ModelCell {
        model: std::sync::Arc::from(m.model),
        era: RawRateEra::legacy(0),
        cur: m.usage_units,
        flushed: BTreeMap::new(),
        flushed_era: BTreeMap::new(),
    };
    rows.into_iter().map(segment).collect()
}

#[path = "money_view.rs"]
pub(super) mod money_view;
