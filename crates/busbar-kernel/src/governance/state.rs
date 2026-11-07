use super::*;
use busbar_contract::redacted::Secret;
use busbar_kernel_ledger::cost::{
    History, MICROS_PER_CENT, Money, MoneyError, PER_REQUEST, plane_fee_lane, split_plane_lane,
};
use std::collections::BTreeMap;

use crate::store::now_ms as wall_ms;

use crate::diagnostics::{
    ACCRUAL_GROUP_MISSING, BUDGET_FLUSH_PARTIAL_FAILURE, diag_debug, diag_error, diag_warn,
};

#[path = "native_runtime.rs"]
pub(super) mod native_runtime;

#[path = "identity_runtime.rs"]
pub(super) mod identity_runtime;

#[path = "self_serve.rs"]
mod self_serve;

#[path = "ledger_adjust.rs"]
pub(super) mod ledger_adjust;
pub use ledger_adjust::{
    ADJUST_DOWN_BUCKET, ADJUST_UP_BUCKET, AdjustRefused, Adjustment, PricedBucket, UsageAdjustment,
    metering_lane,
};

pub const REVOCATION_DURABLE_MARKER: &str = "REVOCATION APPLIED (cache reconcile degraded)";

pub const ROTATION_DURABLE_MARKER: &str = "ROTATION APPLIED (new secret not returned)";

/// Typed commit boundary for credential mutations. Store failures carry no claim of rejection;
/// Applied identifies a completed durable write whose cache reconciliation failed.
#[derive(Debug)]
pub enum KeyMutationError {
    Store(RecordStoreError),
    Applied {
        key_id: String,
        operation: &'static str,
        reconcile: RecordStoreError,
    },
}
impl From<RecordStoreError> for KeyMutationError {
    fn from(error: RecordStoreError) -> Self {
        Self::Store(error)
    }
}
impl std::fmt::Display for KeyMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => error.fmt(f),
            Self::Applied {
                key_id, operation, ..
            } => write!(
                f,
                "{operation} applied to key '{key_id}'; cache reconciliation incomplete"
            ),
        }
    }
}
impl std::error::Error for KeyMutationError {}
impl From<KeyMutationError> for RecordStoreError {
    fn from(error: KeyMutationError) -> Self {
        match error {
            KeyMutationError::Store(error) => error,
            KeyMutationError::Applied {
                key_id,
                operation,
                reconcile,
            } => Self(format!(
                "{}: {operation} applied to key '{key_id}'; cache reconciliation incomplete ({reconcile})",
                if operation == "key.rotate" {
                    ROTATION_DURABLE_MARKER
                } else {
                    REVOCATION_DURABLE_MARKER
                }
            )),
        }
    }
}

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
    pub fn core_store(&self) -> RecordStoreResult<&crate::persistence::facade::CoreStore> {
        Ok(self.core.as_ref())
    }

    pub fn core_store_handle(
        &self,
    ) -> RecordStoreResult<Arc<crate::persistence::facade::CoreStore>> {
        Ok(self.core.clone())
    }

    fn from_identity_cache(
        core: Arc<crate::persistence::facade::CoreStore>,
        admin_token: Option<String>,
        signer: Option<crate::governance::signing::TokenSigner>,
        caches: Arc<RwLock<GovCaches>>,
        refresh_order: Arc<CacheOrder>,
        denylist: Arc<revocation::RevocationSync>,
    ) -> RecordStoreResult<Self> {
        let mut boot_caller_ref = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(boot_caller_ref.as_mut_slice())
            .expect("OS randomness for the per-boot caller-reference key");
        Ok(Self {
            core,
            identity_claims: claims::AsyncClaimSet::new(),
            caches,
            concurrent: RwLock::new(HashMap::new()),
            admin_token_hash: RwLock::new(
                admin_token
                    .as_ref()
                    .map(|t| busbar_contract::redacted::sha256_hex(t.as_bytes())),
            ),
            budget: Sharded::new(),
            recovery_book: recovery::RecoveryBook::default(),
            correction_claims: claims::AsyncClaimSet::new(),
            corrections: std::sync::Mutex::new(HashMap::new()),
            ticket_operations: tickets::TicketOperations::default(),
            budget_flushes: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            budget_flush_runner: BudgetFlushRunner::default(),
            deleting_budget_buckets: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            pending_metering: PendingMetering::new(),
            unit_checkpoints: unit_checkpoint::UnitCheckpointBook::default(),
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
            #[cfg(test)]
            identity_wait_observer: std::sync::Mutex::new(None),
            self_mint_holds: std::sync::atomic::AtomicBool::new(
                SELF_MINT_HOLDS_ADMIN_AND_PROVIDER_STATE,
            ),
            transition_self_holds: RwLock::new(Default::default()),
            amendments: Arc::default(),
        })
    }

    #[must_use]
    pub fn amendments(&self) -> &Arc<crate::audit::amend::NodeAmendments> {
        &self.amendments
    }

    /// Installed only from the durable completed transition receipt before this state is served.
    pub fn install_transition_self_holds(&self, holds: std::collections::BTreeSet<String>) {
        *self
            .transition_self_holds
            .write()
            .unwrap_or_else(|p| p.into_inner()) = holds;
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
            Some(key) if key_row_expired(&key, now) => {
                tracing::debug!(
                    sub = %claims.sub,
                    "signed-token rejected: the key row's expires_at has passed"
                );
                None
            }
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

    pub fn is_revoked(&self, sub: &str) -> bool {
        self.is_revoked_at(sub, busbar_kernel::store::now())
    }

    pub fn is_revoked_at(&self, sub: &str, now: u64) -> bool {
        self.sync_revocations_if_stale(now);
        self.denylist.contains(sub)
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
        self.record_counts_served_in_era(
            cost,
            key,
            pool,
            model,
            provider,
            &whole_counts(units),
            now,
            era,
        )
        .expect("whole usage accrual exceeds Count range");
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_counts_served_in_era(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, Count>,
        now: u64,
        era: RawRateEra,
    ) -> Result<(), CountError> {
        if units.values().all(|v| v.is_zero()) {
            return Ok(());
        }

        if units.values().any(|n| n.is_negative()) {
            return Err(CountError::Negative);
        }

        let (_, pool) = split_plane_lane(pool);
        let targets = match cost.chain_for(key) {
            Ok(chain) => chain
                .iter()
                .filter(|b| b.applies_to_pool(pool))
                .map(|b| {
                    (
                        b.bucket_id.to_string(),
                        budget_window(b.window, now),
                        b.group_name.map(str::to_owned),
                    )
                })
                .collect::<Vec<_>>(),
            Err(missing) => {
                diag_debug!(ACCRUAL_GROUP_MISSING, key = %key.id, group = missing,
                    "group missing at accrual; tokens ledgered to the key bucket only");
                vec![(key.id.clone(), 0, None)]
            }
        };
        self.accrue_count_targets(&targets, model, era, units, now, false, || {
            self.meter_classes(key, model, provider, units, era, now)
        })
    }

    fn meter_classes(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, Count>,
        era: RawRateEra,
        now: u64,
    ) -> Result<(), CountError> {
        let (plane, subject) = busbar_kernel_ledger::cost::split_plane_lane(lane);
        let usage_units: std::collections::BTreeMap<String, Count> = units
            .iter()
            .filter(|(class, n)| {
                !n.is_zero()
                    && !(plane.is_empty()
                        && busbar_contract::records::RESERVED_UNITS.contains(&class.as_str()))
            })
            .map(|(class, n)| (class.clone(), *n))
            .collect();
        if usage_units.is_empty() {
            return Ok(());
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
        self.pending_metering.try_accrue(
            key,
            MeterCounts {
                usage_units,
                ..MeterCounts::default()
            },
        )
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
            &whole_counts(units),
            now,
            crate::rate_apply::era_at(wall_ms()),
        )
        .expect("whole metering accumulation exceeds Count range");
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
        self.record_lane_counts_in_era(key, lane, provider, &whole_counts(units), now, era)
            .expect("whole metering accrual exceeds Count range");
    }

    pub fn record_lane_counts_in_era(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, Count>,
        now: u64,
        era: RawRateEra,
    ) -> Result<(), CountError> {
        if units.values().any(|n| n.is_negative()) {
            return Err(CountError::Negative);
        }
        self.record_lane_metering_attributed(
            &key.id,
            key.group.as_deref().unwrap_or(""),
            lane,
            provider,
            units,
            now,
            era,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record_lane_metering_attributed(
        &self,
        key_id: &str,
        key_group_at_use: &str,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, Count>,
        now: u64,
        era: RawRateEra,
    ) -> Result<(), CountError> {
        match split_plane_lane(lane) {
            ("", _) => {
                if let Some(provider) = provider {
                    let add = MeterCounts::request(units);
                    self.try_record_metered_request_in_era(
                        key_id,
                        key_group_at_use,
                        lane,
                        provider,
                        add,
                        now,
                        era,
                    )?;
                }
            }
            (plane, subject) => {
                let add = MeterCounts::request(&std::collections::BTreeMap::new());
                self.try_record_metered_request_in_era(
                    key_id,
                    key_group_at_use,
                    subject,
                    plane,
                    add,
                    now,
                    era,
                )?;
            }
        }
        Ok(())
    }

    pub fn record_metering(
        &self,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&busbar_contract::billing::TokenUsage>,
        now: u64,
    ) {
        if usage.is_some_and(|u| !u.refused_counts.is_empty()) {
            tracing::warn!(
                key = key_id,
                "metering refused: provider reported invalid exact counts"
            );
            return;
        }
        let add = if let Some(exact) = usage.and_then(|u| u.exact_counts.as_ref()) {
            if exact.values().any(|n| n.is_negative()) {
                tracing::warn!(key = key_id, "metering refused: negative exact count");
                return;
            }
            MeterCounts::request(exact)
        } else {
            MeterCounts {
                requests: 1,
                tokens_input: whole_count(usage.map(|u| u.input).unwrap_or(0)),
                tokens_output: whole_count(usage.map(|u| u.output).unwrap_or(0)),
                tokens_cache_read: whole_count(usage.and_then(|u| u.cache_read).unwrap_or(0)),
                tokens_cache_write: whole_count(usage.and_then(|u| u.cache_creation).unwrap_or(0)),
                usage_units: std::collections::BTreeMap::new(),
            }
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
        self.try_record_metered_request_in_era(
            key_id,
            key_group_at_use,
            model,
            provider,
            add,
            now,
            era,
        )
        .expect("metering accumulation exceeds Count range");
    }

    #[allow(clippy::too_many_arguments)]
    fn try_record_metered_request_in_era(
        &self,
        key_id: &str,
        key_group_at_use: &str,
        model: &str,
        provider: &str,
        add: MeterCounts,
        now: u64,
        era: RawRateEra,
    ) -> Result<(), CountError> {
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

        self.pending_metering.try_accrue(key, add)
    }

    #[cfg(test)]
    pub fn pending_metering_totals(&self) -> (usize, MeterCounts) {
        self.pending_metering.totals()
    }

    /// Inspect retained domain custody after request admission has stopped and
    /// the final drivers have returned. This is an owner-state observation, not
    /// a claim that a backend transaction or another process has quiesced.
    pub fn has_unsettled_persistence(&self) -> bool {
        if self.budget_flush_runner.is_running()
            || !self
                .budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
            || !self
                .deleting_budget_buckets
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
        {
            return true;
        }
        for index in 0..GOV_SHARDS {
            let map = self
                .budget
                .shard_at(index)
                .map
                .read()
                .unwrap_or_else(|p| p.into_inner());
            if map.values().any(|cell| {
                cell.dirty
                    || cell.flushing != 0
                    || cell.correction.is_some()
                    || !cell.rolled.is_empty()
                    || !cell.rolled_eras.is_empty()
            }) {
                return true;
            }
        }
        let metering = &self.pending_metering;
        if metering.flush_runner.is_running()
            || !metering
                .flight
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty()
            || metering.shards.iter().any(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .values()
                    .any(|counts| !counts.is_zero())
            })
        {
            return true;
        }
        let corrections: Vec<_> = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        corrections
            .iter()
            .any(|pending| pending.has_unsettled_persistence())
            || self.has_unsettled_recovery()
            || self.has_unsettled_unit_checkpoints()
            || self.has_unsettled_ticket_operations()
    }

    pub async fn flush_metering(&self) -> usize {
        self.flush_metering_deduped(false).await
    }

    pub async fn flush_metering_final(&self) -> usize {
        self.flush_metering_deduped(true).await
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
                _ => (0, Count::ZERO),
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
                h = h.min(if cap == 0 {
                    0.0
                } else {
                    1.0 - tokens.micros() as f64 / whole_count(cap).micros() as f64
                });
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

    pub(super) fn signing_material(&self) -> Option<Arc<SigningMaterial>> {
        self.signing
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub async fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.delete_key_outcome_async(id).await.map_err(Into::into)
    }

    pub async fn delete_key_outcome(&self, id: &str) -> Result<(), KeyMutationError> {
        self.delete_key_outcome_async(id).await
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

    pub async fn hydrate_budgets_async(
        &self,
        cost: &crate::cost::CostModel,
        now: u64,
    ) -> RecordStoreResult<()> {
        let keys = self.core_store()?.identity().list_keys().await?;
        let mut buckets = Vec::new();
        for key in &keys {
            buckets.push((key.id.clone(), super::WINDOW_TOTAL, None));
        }
        for group in cost.groups() {
            for bucket in &group.buckets {
                buckets.push((
                    bucket.bucket_id.clone(),
                    bucket.window,
                    Some(group.name.clone()),
                ));
            }
        }
        for (bucket_id, period, group) in buckets {
            let window = budget_window(period, now);
            let mut cell = self.stored_cell_async(&bucket_id, window).await?;
            if cell.requests == 0 && cell.models.is_empty() {
                continue;
            }

            cell.last_touch = now;
            let mut cells = self.budget.write(&bucket_id);
            if let Some(group) = group {
                cell.group_owners.insert(group);
            }
            if let Some(previous) = cells.get(&bucket_id) {
                if previous.correction.is_some() || previous.dirty || previous.flushing != 0 {
                    return Err(RecordStoreError(
                        "budget hydration has unresolved raw usage custody".into(),
                    ));
                }
                cell.group_owners
                    .extend(previous.group_owners.iter().cloned());
            }
            cells.insert(bucket_id, cell);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn money_view_pricings(&self) -> u64 {
        self.money_view.pricings()
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
        self.try_admit_estimated_counts(cost, key, pool, now, models, &whole_counts(expected))
    }

    pub fn try_admit_estimated_counts(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        now: u64,
        models: &[&str],
        expected: &BTreeMap<String, Count>,
    ) -> Result<AdmitGrant, LimitBlocked> {
        self.admit_checked(
            cost,
            key,
            pool,
            now,
            cost.estimate_counts_minor(models, expected),
        )
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

        // A recovered unit may have sent only part of its raw custody. Admit against exact
        // hydrated rows only after that custody settles and its targets have been refreshed.
        for bucket in &buckets {
            let window = budget_window(bucket.window, now);
            if self.unresolved_unit_target(bucket.bucket_id, window) {
                return Err(LimitBlocked::Limit {
                    group: bucket.group_name.unwrap_or(bucket.bucket_id).to_string(),
                    metric: "budget",
                    window: Some(bucket.window),
                    pool: bucket.scope.map(|scope| scope.value.clone()),
                    downgrade_to: None,
                    retry_after: None,
                });
            }
        }

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
                    bucket.tokens_cap.map_or(Count::ZERO, |_| {
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

                _ => (0, Count::ZERO, None, Ok(0)),
            };
            let class_blocked = (bucket.class_caps.iter())
                .find(|c| {
                    live.map_or(Count::ZERO, |cell| {
                        cell.correction
                            .as_ref()
                            .map_or(cell.total_tier(c.class), |branch| {
                                cell.total_tier(c.class)
                                    .max(branch.accepted.total_tier(c.class))
                            })
                    }) >= whole_count(c.cap)
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
            } else if bucket
                .tokens_cap
                .is_some_and(|cap| tokens >= whole_count(cap))
            {
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

        let one = || BTreeMap::from([(PER_REQUEST.to_string(), Count::ONE)]);
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
                    cell.accrue_raw(lane, era, one)
                        .expect("fee count exceeds Count range");
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
                                scale: COUNT_SCALE,
                                model: lane.to_string(),
                                usage_units: BTreeMap::from([(unit.to_string(), -1_000_000)]),
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

    pub fn release_request(&self, charge: &FeeCharge) {
        for (bucket_id, window) in &charge.cells {
            let mut map = self.budget.write(bucket_id);
            let Some(cell) = map.get_mut(bucket_id) else {
                continue; // swept: nothing in memory holds the count any more
            };
            if cell.window_start == *window {
                cell.requests = cell.requests.saturating_sub(1);
                cell.dirty = true;
            } else if cell.window_start > *window {
                cell.park(
                    *window,
                    UsageDelta {
                        requests: -1,
                        ..UsageDelta::default()
                    },
                );
                cell.dirty = true;
            }
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
                                && m.cur.get(unit).is_some_and(|n| *n >= Count::ONE)
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

    pub async fn flush_budgets(&self) -> usize {
        self.flush_budgets_inner(false).await
    }

    pub async fn flush_budgets_final(&self) -> usize {
        self.flush_budgets_inner(true).await
    }

    async fn flush_budgets_inner(&self, shutdown: bool) -> usize {
        let runner = match self.budget_flush_runner.enter(shutdown).await {
            Ok(runner) => runner,
            Err(message) => {
                if shutdown {
                    diag_error!(BUDGET_FLUSH_PARTIAL_FAILURE, error = message, "{message}");
                }
                return 0;
            }
        };
        runner
            .scope(async {
                let _ = self.settle_ticket_operations().await;
                let mut errors = self.retry_usage_corrections().await;
                if self.recovery_enabled() {
                    if let Err(error) = self.resume_raw_recovery().await {
                        errors.push(error.to_string());
                    }
                }

                let foreign_settled = self.capture_foreign_settled_snapshot().await;
                {
                    for mut map in self.budget.write_all() {
                        for (id, cell) in map.iter_mut() {
                            if cell.dirty {
                                let _ = self.capture_budget_flushes(id, cell, &foreign_settled);
                            }
                        }
                    }
                }
                let (mut flushed, retained_errors) = self.resume_budget_flushes(shutdown).await;
                errors.extend(retained_errors);

                // Include accrual that arrived while retained operations were awaiting their
                // receipts. Capture is entirely in memory; each immutable flight owns its debt
                // before any Store call can suspend this future.
                let mut new_flights = Vec::new();
                {
                    for mut map in self.budget.write_all() {
                        for (id, cell) in map.iter_mut() {
                            if !cell.dirty || self.budget_bucket_deleting(id) {
                                continue;
                            }
                            new_flights.extend(self.capture_budget_flushes(
                                id,
                                cell,
                                &foreign_settled,
                            ));
                            cell.mutate(|cell| {
                                cell.dirty = cell.correction.is_some()
                                    || !ExactUsageDelta::of(cell, false).is_zero()
                                    || !ExactUsageDelta::of(cell, true).is_zero()
                                    || !cell.rolled.is_empty()
                                    || !cell.rolled_eras.is_empty();
                            });
                        }
                    }
                }
                let (late_flushed, late_errors) = if shutdown {
                    self.resume_budget_flushes(true).await
                } else {
                    self.resume_budget_flush_list(new_flights, false).await
                };
                flushed += late_flushed;
                errors.extend(late_errors);
                if !errors.is_empty() {
                    let failed = errors.len();
                    if shutdown {
                        diag_error!(
                            BUDGET_FLUSH_PARTIAL_FAILURE,
                            failed,
                            flushed,
                            "shutdown budget flush retains unresolved raw custody: {}",
                            errors.join(", ")
                        );
                    } else {
                        diag_warn!(
                            BUDGET_FLUSH_PARTIAL_FAILURE,
                            failed,
                            flushed,
                            "budget flush retains exact operations for retry: {}",
                            errors.join(", ")
                        );
                    }
                }
                flushed
            })
            .await
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
                (
                    key.id.clone(),
                    plain,
                    key.enabled && !key_row_expired(&key, now),
                )
            }
            None => (String::new(), None, false),
        };
        let revoked = self.is_revoked_at(&key, now);
        let live = enabled && plain.is_some() && !revoked;
        let secret = plain.unwrap_or_default();
        (busbar_contract::redacted::Secret::new(secret), live)
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

fn take_one(counts: &mut BTreeMap<String, Count>, unit: &str) {
    if let Some(n) = counts.get_mut(unit) {
        if *n < Count::ONE {
            return;
        }
        *n = n
            .checked_sub(Count::ONE)
            .expect("fee refund count overflow");
        if n.is_zero() {
            counts.remove(unit);
        }
    }
}

fn money_refusal(bucket_id: &str, e: &busbar_kernel_ledger::cost::MoneyError) -> RecordStoreError {
    RecordStoreError(format!(
        "the spend of bucket `{bucket_id}` cannot be priced: {e}"
    ))
}

pub(super) fn durable_cell(
    row: busbar_contract::records::UsageLedger,
    eras: busbar_contract::records::UsageLedger,
    window: u64,
) -> RecordStoreResult<BudgetCell> {
    let mut cell = BudgetCell::fresh(window);
    cell.requests = row.requests;
    cell.billable_requests = row.billable_requests;
    cell.flushed_requests = row.requests;
    cell.flushed_billable_requests = row.billable_requests;
    cell.models = durable_segments(row.models)?;
    let (mut fees, mut undated_fees) = (Vec::new(), row.billable_requests);
    for e in eras.models {
        for raw in e.usage_units.values() {
            let count =
                Count::from_stored(*raw, e.scale).map_err(|e| RecordStoreError(e.to_string()))?;
            if count.is_negative() {
                return Err(RecordStoreError("negative durable era usage total".into()));
            }
        }
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
            let count = Count::from_stored(
                e.usage_units.get(ERA_FEE_UNIT).copied().unwrap_or(0),
                e.scale,
            )
            .map_err(|e| RecordStoreError(e.to_string()))?;
            if count.micros() % 1_000_000 != 0 {
                return Err(RecordStoreError("fractional fee count".into()));
            }
            let n = u64::try_from(count.micros() / 1_000_000)
                .map_err(|e| RecordStoreError(e.to_string()))?
                .min(undated_fees);
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
            let left = rest.cur.get(&unit).copied().unwrap_or_default();
            let n = Count::from_stored(n, e.scale).map_err(|e| RecordStoreError(e.to_string()))?;
            let n = n.min(left);
            if n.is_zero() {
                continue;
            }
            if left == n {
                rest.cur.remove(&unit);
            } else {
                rest.cur.insert(
                    unit.clone(),
                    left.checked_sub(n)
                        .map_err(|e| RecordStoreError(e.to_string()))?,
                );
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

fn durable_segments(
    rows: Vec<busbar_contract::records::ModelTokens>,
) -> RecordStoreResult<Vec<ModelCell>> {
    rows.into_iter()
        .map(|m| {
            Ok(ModelCell {
                model: m.model.into(),
                era: RawRateEra::legacy(0),
                cur: m
                    .usage_units
                    .into_iter()
                    .map(|(unit, n)| {
                        let count = Count::from_stored(n, m.scale)
                            .map_err(|e| RecordStoreError(e.to_string()))?;
                        if count.is_negative() {
                            return Err(RecordStoreError("negative durable usage total".into()));
                        }
                        Ok((unit, count))
                    })
                    .collect::<RecordStoreResult<_>>()?,
                flushed: BTreeMap::new(),
                flushed_era: BTreeMap::new(),
            })
        })
        .collect()
}

#[path = "money_view.rs"]
pub(super) mod money_view;

/// Whether `key`'s stored `expires_at` has passed as of `now` (owner-signed 2026-10-30, SEC-VKEY):
/// `expires_at == now` is already expired, as a token's `exp == now` is.
pub(crate) fn key_row_expired(key: &VirtualKey, now: u64) -> bool {
    key.expires_at.is_some_and(|exp| exp <= now)
}
