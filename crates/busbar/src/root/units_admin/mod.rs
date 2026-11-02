// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::authz::Scope;
use busbar_contract::caps::{Grant, Outcome, PrincipalId, ReasonCode};
use busbar_contract::UnitKey;
use busbar_core_admin::admin_codec::verbs::ResolvedVerb;
use busbar_kernel_audit::{expose, AuditChain, AuditKeySet, AuditRecord};

use busbar_core_admin::rate::{MutationClass, CONFIG_CLASS_RULES};
use busbar_core_admin::{KernelVerb, VerbScope, NEW_VERBS};
#[cfg(test)]
use busbar_core_admin::{AUDIT_VERBS, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES};
use busbar_kernel_ledger::cost::{Money, MoneyError};

/// One admin request, exactly as it arrived.
///
/// Owned, because it crosses to the task the operation's body runs on ([`AdminDispatch`]).
///
/// NO derived `Debug` — see the hand-written impl below. This value holds the operator's LIVE
/// credential, twice.
#[derive(Clone, PartialEq, Eq)]
pub struct AdminRequest {
    /// The request method.
    pub method: String,
    /// The request path, query string and all.
    pub path: String,
    /// The credential the caller presented, where one was.
    pub credential: Option<String>,
    /// The request headers, in arrival order, names lowercased.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
    /// The wall clock, in seconds, pinned at arrival. Every step reads this rather than the clock:
    /// a unit that read the clock twice could be admitted in one window and rate-classed in the
    /// next.
    pub at: u64,
    /// The key of the unit this request is answered as.
    ///
    /// Carried on the request because it has to cross the seam WITH it: the operation's body runs on
    /// a task the seam spawned, and the one effect a body can ask to outlive its own response — the
    /// drain — is attributed to the unit that asked for it. Without the key travelling here the
    /// attribution would have to be re-derived on the far side of a task boundary, which is another
    /// way of saying it would be guessed.
    pub unit: u64,
}

impl std::fmt::Debug for AdminRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "<redacted>";
        let presented = self.credential.as_deref().filter(|c| !c.is_empty());
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let shown = match presented {
                    Some(credential) if value.contains(credential) => REDACTED,
                    _ => value.as_str(),
                };
                (name.as_str(), shown)
            })
            .collect();
        f.debug_struct("AdminRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("credential", &self.credential.as_ref().map(|_| REDACTED))
            .field("headers", &headers)
            .field("body", &self.body)
            .field("at", &self.at)
            .field("unit", &self.unit)
            .finish()
    }
}

/// One admin answer, exactly as the surface that owns the operation produced it.
///
/// Status, headers and body together, because all three are pinned and none of them is derivable
/// from the others. An answer that carried only a body would force a status to be re-derived here,
/// and a re-derived status is a status that can differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAnswer {
    /// The status code.
    pub status: u16,
    /// The response headers, in emission order.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

pub trait AdminDispatch: Send + Sync {
    fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer;
}

/// The dispatch a node has before it has mounted an admin surface.
///
/// It refuses every operation, which is the correct answer rather than a placeholder: a root that
/// has composed the loop but not yet mounted the surface has genuinely nowhere to send an admin
/// request, and answering `503` says exactly that. Building the units against this is what lets the
/// composition be tested without a listener.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingDispatch;

impl AdminDispatch for RefusingDispatch {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 503,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"error":{"code":"unavailable","message":"no administrative surface is mounted"}}"#
                .to_vec(),
        }
    }
}

/// One row of the one ledger, priced: a bucket's current window, its counts priced at the card each
/// was earned under (MONEY-DESIGN §3: money is counts x the card, computed in core).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    /// The bucket: a key's id.
    pub bucket: String,
    /// The window the counts are in, as the unix second it opens at (`0` = the all-time window).
    pub day: u64,
    /// The priced figure, in nano-units: the one function's figure (scale six) at nano scale.
    pub priced_nanos: u128,
    /// Billable requests in the window: the fee base.
    pub fee_count: u64,
}

/// A row the card refused to price (#42): it is withheld from the figures and named, never served
/// as the priced remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedRow {
    /// The bucket.
    pub bucket: String,
    /// The window, as the unix second it opens at.
    pub day: u64,
    /// The refusal, in the one function's own words.
    pub refusal: String,
}

/// The one ledger as the views read it, as of one read: every priced row, and every refused one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PricedLedger {
    /// The priced rows, in bucket order. A row nothing was counted in is not a row.
    pub rows: Vec<LedgerRow>,
    /// The rows the card refused to price.
    pub refused: Vec<RefusedRow>,
}

pub trait LedgerView: Send + Sync {
    fn priced(&self) -> Result<PricedLedger, String>;
}

/// The view a node has before a ledger is bound behind it: no rows, which is the truth about a node
/// composed with no governance store.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnopenedLedger;

impl LedgerView for UnopenedLedger {
    fn priced(&self) -> Result<PricedLedger, String> {
        Ok(PricedLedger::default())
    }
}

pub struct CountsLedger {
    app: Arc<busbar_kernel::state::AppHandle>,
}

impl std::fmt::Debug for CountsLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountsLedger").finish_non_exhaustive()
    }
}

impl CountsLedger {
    #[must_use]
    pub fn new(app: Arc<busbar_kernel::state::AppHandle>) -> Self {
        CountsLedger { app }
    }
}

impl LedgerView for CountsLedger {
    fn priced(&self) -> Result<PricedLedger, String> {
        let app = self.app.load();
        let Some(gov) = app.governance.clone() else {
            return Ok(PricedLedger::default());
        };
        let now = busbar_kernel::store::now();

        crate::root::durability::off_runtime(|| priced_keys(&gov, &app.cost, now))
    }
}

pub fn priced_keys(
    gov: &busbar_kernel::governance::GovState,
    cost: &busbar_kernel::cost::CostModel,
    now: u64,
) -> Result<PricedLedger, String> {
    let mut keys = gov.all_keys().map_err(|e| e.to_string())?;
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    let mut ledger = PricedLedger::default();
    for key in keys {
        let bucket = gov
            .priced_bucket(cost, &key.id, busbar_kernel::governance::WINDOW_TOTAL, now)
            .map_err(|e| e.to_string())?;
        match bucket.spend {
            Ok(spend) => {
                let micros = u128::try_from(spend.micros()).unwrap_or(0);
                if micros == 0 && bucket.billable_requests == 0 {
                    continue;
                }
                ledger.rows.push(LedgerRow {
                    bucket: key.id,
                    day: bucket.window_start,
                    priced_nanos: micros.saturating_mul(1_000),
                    fee_count: bucket.billable_requests,
                });
            }
            Err(refusal) => ledger.refused.push(RefusedRow {
                bucket: key.id,
                day: bucket.window_start,
                refusal: refusal.to_string(),
            }),
        }
    }
    Ok(ledger)
}

pub trait AuditView: Send + Sync {
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>));

    fn read_window(
        &self,
        _from: u64,
        _to: u64,
        take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>),
    ) {
        self.read(take);
    }

    fn keys(&self) -> AuditKeySet;

    fn restart_findings(&self) -> Vec<String> {
        Vec::new()
    }

    fn retained_audit_findings(&self) -> Vec<String> {
        Vec::new()
    }

    fn stored_chain_findings(&self) -> Vec<String> {
        Vec::new()
    }
}

pub struct NodeAudit {
    durability: Arc<Mutex<crate::root::durability::Durability>>,
}

impl std::fmt::Debug for NodeAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeAudit").finish_non_exhaustive()
    }
}

impl NodeAudit {
    #[must_use]
    pub fn new(durability: Arc<Mutex<crate::root::durability::Durability>>) -> Self {
        NodeAudit { durability }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, crate::root::durability::Durability> {
        self.durability.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl AuditView for NodeAudit {
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>)) {
        let durability = self.lock();
        take(&durability.record, Some(&durability.audit_records));
    }

    fn read_window(
        &self,
        from: u64,
        to: u64,
        take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>),
    ) {
        use crate::root::durability::AuditWindowAt;
        loop {
            let (chain, sealed_before) = {
                let durability = self.lock();
                match durability.audit_window_at(from, to) {
                    AuditWindowAt::Cached(records) => {
                        take(&durability.record, Some(&records));
                        return;
                    }
                    AuditWindowAt::OnChain {
                        chain,
                        sealed_before,
                    } => (chain, sealed_before),
                }
            };

            let Some(mut records) = chain.audit_window(from, to) else {
                return;
            };
            let durability = self.lock();
            if durability.audit_window_since(&mut records, sealed_before, from, to) {
                take(&durability.record, Some(&records));
                return;
            }
        }
    }

    fn keys(&self) -> AuditKeySet {
        crate::root::durability::keyset_of(&self.lock().record)
    }

    fn restart_findings(&self) -> Vec<String> {
        self.lock().restart_findings.clone()
    }

    fn retained_audit_findings(&self) -> Vec<String> {
        self.lock().retained_audit_findings()
    }

    fn stored_chain_findings(&self) -> Vec<String> {
        let Some((lane, own, keys)) = self.lock().stored_walk_inputs() else {
            return Vec::new();
        };
        crate::root::durability::walk_stored_chains(&lane, own, &keys).findings
    }
}

fn audit_window(target: &str) -> Option<(u64, u64)> {
    let (_, query) = target.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    let (mut from, mut to) = (None, None);
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        match name {
            "from" => from = Some(value.parse::<u64>().ok()?),
            "to" => to = Some(value.parse::<u64>().ok()?),
            _ => {}
        }
    }
    let (from, to) = (from?, to?);
    (from <= to).then_some((from, to))
}

fn render_audit_view(
    verb: KernelVerb,
    target: &str,
    view: &dyn AuditView,
) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
    use busbar_core_admin::GovernanceError;
    match verb {
        KernelVerb::GetAuditHead => {
            let mut body = None;
            view.read(&mut |chain, _records| {
                body = Some(expose::head_body(chain));
            });
            body.map(String::into_bytes).ok_or(GovernanceError::Store)
        }
        KernelVerb::GetAuditRange => {
            let (from, to) = audit_window(target).ok_or(GovernanceError::Validation)?;

            let mut answered: Option<Option<String>> = None;
            view.read_window(from, to, &mut |chain, records| {
                answered =
                    Some(records.map(|records| expose::range_body(chain, records, from, to)));
            });
            match answered {
                None => Err(GovernanceError::Store),
                Some(None) => Err(GovernanceError::NotFound),
                Some(Some(body)) => Ok(body.into_bytes()),
            }
        }
        KernelVerb::GetAuditKeys => Ok(expose::keys_body(&view.keys()).into_bytes()),

        _ => Err(GovernanceError::NotFound),
    }
}

pub type PoolKnown = Arc<dyn Fn(&str) -> bool + Send + Sync>;

fn no_pools() -> PoolKnown {
    Arc::new(|_| false)
}

pub struct CoreGovernance {
    dispatch: Arc<dyn AdminDispatch>,

    ledger: Arc<dyn LedgerView>,

    audit: Option<Arc<dyn AuditView>>,

    request: AdminRequest,
    verb: KernelVerb,

    amendments: Option<Arc<AmendmentJournal>>,

    node_amendments: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,

    attribution: AmendAttribution,

    granted: VerbScope,

    pools: PoolKnown,

    adjuster: adjust::UsageAdjuster,

    planes: PlaneLookup,

    records: Option<PlaneRecordSink>,

    replays: Arc<bound::ReplayCache>,

    replay_store: Option<bound::ReplayStore>,

    trust: TrustDesk,
}

impl CoreGovernance {
    #[must_use]
    pub fn new(
        dispatch: Arc<dyn AdminDispatch>,
        ledger: Arc<dyn LedgerView>,
        audit: Option<Arc<dyn AuditView>>,
        verb: KernelVerb,
        request: AdminRequest,
    ) -> Self {
        CoreGovernance {
            dispatch,
            ledger,
            audit,
            request,
            verb,
            amendments: None,
            node_amendments: None,
            attribution: AmendAttribution {
                principal: String::new(),
            },
            granted: VerbScope::ReadOnly,
            pools: no_pools(),
            adjuster: adjust::no_ledger(),
            planes: no_planes(),
            records: None,
            replays: Arc::new(bound::ReplayCache::new()),
            replay_store: None,
            trust: no_trust(),
        }
    }

    #[must_use]
    pub fn trusting(mut self, trust: TrustDesk) -> Self {
        self.trust = trust;
        self
    }

    #[must_use]
    pub fn replaying(
        mut self,
        replays: Arc<bound::ReplayCache>,
        store: Option<bound::ReplayStore>,
    ) -> Self {
        self.replays = replays;
        self.replay_store = store;
        self
    }

    #[must_use]
    pub fn noting(
        mut self,
        journal: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,
    ) -> Self {
        self.node_amendments = journal;
        self
    }

    #[must_use]
    pub fn planed(mut self, planes: PlaneLookup, records: Option<PlaneRecordSink>) -> Self {
        self.planes = planes;
        self.records = records;
        self
    }

    #[must_use]
    pub fn pooled(mut self, pools: PoolKnown) -> Self {
        self.pools = pools;
        self
    }

    #[must_use]
    pub fn adjusting(mut self, adjuster: adjust::UsageAdjuster) -> Self {
        self.adjuster = adjuster;
        self
    }

    #[must_use]
    pub fn granted(mut self, granted: VerbScope) -> Self {
        self.granted = granted;
        self
    }

    #[must_use]
    pub fn amending(
        mut self,
        amendments: Option<Arc<AmendmentJournal>>,
        attribution: AmendAttribution,
    ) -> Self {
        self.amendments = amendments;
        self.attribution = attribution;
        self
    }

    fn run(&self) -> AdminAnswer {
        self.dispatch.execute(self.verb, &self.request)
    }
}

impl busbar_core_admin::Governance for CoreGovernance {
    type Answer = AdminAnswer;

    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        Ok(self.run())
    }

    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        if verb == KernelVerb::AmendRateHistory {
            return amend_rate_history_effect(
                &crate::root::kernel::ROOT_CARD,
                self.amendments.as_deref(),
                request,
                self.request.at,
                &self.attribution,
            );
        }

        if verb == KernelVerb::Adjust {
            let scope = match self.granted {
                VerbScope::Full => busbar_contract::authz::Scope::Full,
                VerbScope::ReadOnly => busbar_contract::authz::Scope::ReadOnly,
            };
            return adjust::adjust_effect(request, scope, &*self.pools, &self.adjuster);
        }

        match verb {
            KernelVerb::Verify => {
                return bound::verify_effect(
                    self.ledger.as_ref(),
                    self.audit.as_deref(),
                    self.node_amendments.as_deref(),
                );
            }
            KernelVerb::PlaneFacts => {
                return bound::plane_facts_effect(&self.request.path, &*self.planes);
            }

            KernelVerb::GetTrust => {
                return bound::trust_list_effect(&self.trust);
            }
            KernelVerb::TrustApprove | KernelVerb::TrustRevoke => {
                let ruling = if verb == KernelVerb::TrustApprove {
                    busbar_kernel::trust::book::Ruling::Approve
                } else {
                    busbar_kernel::trust::book::Ruling::Revoke
                };
                return bound::trust_decide_effect(request, ruling, &self.trust);
            }

            KernelVerb::PlaneRecordWrite => {
                return bound::replayable(
                    &self.replays,
                    self.replay_store.as_ref(),
                    bound::ReplayScope {
                        verb,
                        actor: &self.attribution.principal,
                    },
                    &self.request,
                    request,
                    self.amendments.as_deref(),
                    || {
                        bound::plane_record_write_effect(
                            request,
                            self.request.at,
                            &*self.planes,
                            self.records.as_ref(),
                        )
                    },
                );
            }
            KernelVerb::CommitUpgrade => {
                return bound::replayable(
                    &self.replays,
                    self.replay_store.as_ref(),
                    bound::ReplayScope {
                        verb,
                        actor: &self.attribution.principal,
                    },
                    &self.request,
                    request,
                    self.amendments.as_deref(),
                    || {
                        bound::commit_upgrade_effect(
                            request,
                            self.request.at,
                            &self.attribution.principal,
                            self.amendments.as_deref(),
                        )
                    },
                );
            }
            _ => {}
        }
        Ok(self.run())
    }

    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        let body = render_ledger_view(verb, self.ledger.as_ref())?;
        Ok(json_answer(body))
    }

    fn execute_audit_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        let view = self
            .audit
            .as_deref()
            .ok_or(busbar_core_admin::GovernanceError::NotFound)?;
        render_audit_view(verb, &self.request.path, view).map(json_answer)
    }
}

fn json_answer(body: Vec<u8>) -> AdminAnswer {
    AdminAnswer {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
    }
}

fn already_applied(
    view: busbar_kernel_ledger::cost::HistoryView<'_>,
    correction: &crate::root::kernel::Correction,
) -> bool {
    view.entries().iter().any(|entry| {
        matches!(
            entry.author(),
            busbar_kernel_ledger::cost::Author::Amend { .. }
        ) && entry.author() == &correction.author
            && entry.effective_from() == correction.effective_from
            && entry.effective_until() == correction.effective_until
            && correction.fee.is_none_or(|fee| entry.card().fee() == fee)
            && correction.cells.iter().all(|(cell, nanos)| {
                entry
                    .card()
                    .lane_rates(&cell.lane)
                    .filter(|rates| rates.class_priced(&cell.class))
                    .map(|rates| rates.nanos_per_unit(&cell.class))
                    == Some(*nanos)
            })
    })
}

fn amend_rate_history_effect(
    history: &crate::root::kernel::RootHistory,
    journal: Option<&AmendmentJournal>,
    body: &[u8],
    arrival_secs: u64,
    attribution: &AmendAttribution,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    use busbar_contract::abi::sdk::digest::sha256;
    use busbar_core_admin::GovernanceError;

    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;

    let effective_from = obj
        .get("effective_from")
        .and_then(serde_json::Value::as_u64)
        .ok_or(GovernanceError::Validation)?;
    let effective_until = match obj.get("effective_until") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or(GovernanceError::Validation)?),
    };
    if effective_until.is_some_and(|until| until <= effective_from) {
        return Err(GovernanceError::Validation);
    }

    if effective_from > arrival_secs.saturating_mul(1000) {
        return Err(GovernanceError::Validation);
    }

    match effective_until {
        None => return Err(GovernanceError::Validation),
        Some(until) if until > arrival_secs.saturating_mul(1000) => {
            return Err(GovernanceError::Validation)
        }
        Some(_) => {}
    }

    let reason = obj
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(GovernanceError::Validation)?;
    let reason_hash: [u8; 32] = sha256(reason.as_bytes());

    if obj.contains_key("currency") {
        return Err(GovernanceError::Validation);
    }

    let per_request_fee = match obj.get("per_request_fee") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let fee = v.as_i64().ok_or(GovernanceError::Validation)?;
            if fee < 0 {
                return Err(GovernanceError::Validation);
            }
            Some(fee)
        }
    };
    let mut entries: Vec<(busbar_kernel_ledger::cost::LaneClass, u64)> = Vec::new();
    if let Some(rates) = obj.get("rates") {
        for row in rates.as_array().ok_or(GovernanceError::Validation)? {
            let r = row.as_object().ok_or(GovernanceError::Validation)?;
            let lane = r
                .get("lane")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(GovernanceError::Validation)?;
            let class = r
                .get("class")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(GovernanceError::Validation)?;

            let nanos = match r.get("micro_per_unit") {
                Some(serde_json::Value::Number(n)) => exact_nano_rate(&n.to_string()),
                _ => None,
            }
            .ok_or(GovernanceError::Validation)?;
            entries.push((
                busbar_kernel_ledger::cost::LaneClass::new(lane, class),
                nanos,
            ));
        }
    }
    if entries.is_empty() && per_request_fee.is_none() {
        return Err(GovernanceError::Validation);
    }

    let appended_at_ms = arrival_secs.saturating_mul(1000);

    if history.is_empty() {
        return Err(GovernanceError::NotFound);
    }

    let in_store = history.keeps_store();
    let journal = if in_store {
        None
    } else {
        Some(journal.ok_or(GovernanceError::Store)?)
    };

    if let Some(Err(why)) = journal.map(AmendmentJournal::admit) {
        return Ok(bound::journal_unavailable(&why));
    }
    let sealed_at: std::cell::Cell<Option<u64>> = std::cell::Cell::new(None);
    let correction = crate::root::kernel::Correction {
        effective_from,
        effective_until,
        appended_at: appended_at_ms,
        author: busbar_kernel_ledger::cost::Author::Amend { reason_hash },
        cells: entries,
        fee: per_request_fee,
    };
    let seq = history
        .amend_by(&correction, &attribution.principal, |card, base| {
            if history
                .pin()
                .is_some_and(|pinned| already_applied(pinned.view(), &correction))
            {
                return Err(GovernanceError::Conflict);
            }
            let record = AmendmentRecord {
                effective_from,
                effective_until,
                amended_at_ms: appended_at_ms,
                sealed_over: Some(base),
                sealed_fee: card.fee(),
                rates: correction
                    .cells
                    .iter()
                    .map(|(cell, _)| (cell.lane.clone(), cell.class.clone()))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .map(|(lane, class)| {
                        let nanos = card
                            .lane_rates(&lane)
                            .filter(|rates| rates.class_priced(&class))
                            .map(|rates| rates.nanos_per_unit(&class));
                        (lane, class, nanos)
                    })
                    .collect(),
                operator_fingerprint: String::new(),
                reason_hash,
                principal: attribution.principal.clone(),

                dual_control: "single".to_string(),
                signed_payload: canonical_amend_payload(obj),
                signature: String::new(),
            };
            match journal {
                Some(journal) => journal
                    .seal_policy(amendment_body(&record), arrival_secs)
                    .map(|(node_seq, _)| sealed_at.set(Some(node_seq))),
                None => Ok(()),
            }
        })
        .map_err(|refused| match refused {
            crate::root::kernel::AmendRefused::NoHistory => GovernanceError::NotFound,
            crate::root::kernel::AmendRefused::NoSoleCard => GovernanceError::Validation,
            crate::root::kernel::AmendRefused::CutsRow(boundary) => {
                tracing::warn!(
                    boundary,
                    "amend_rate_history refused: the correction's boundary falls inside a metering \
                     row (a UTC day per price era) and would reprice all of it or none of it; \
                     correct from a UTC day boundary or the start of the card in force"
                );
                GovernanceError::Validation
            }
            crate::root::kernel::AmendRefused::Seal(e) => e,
            crate::root::kernel::AmendRefused::Store(why) => {
                tracing::warn!("amend_rate_history refused: {why}");
                GovernanceError::Store
            }
        })?;

    if let (Some(node_seq), Some(journal)) = (sealed_at.get(), journal) {
        if let Err(why) = journal.acked(node_seq) {
            return Ok(bound::journal_unavailable(&format!(
                "the correction is sealed at journal position {node_seq} and not yet kept by the \
                 store: {why}; do not re-submit"
            )));
        }
    }

    let mut out = String::new();
    out.push_str("{\"history_seq\":");
    out.push_str(&seq.get().to_string());
    out.push_str(",\"effective_from\":");
    out.push_str(&effective_from.to_string());
    out.push_str(",\"effective_until\":");
    match effective_until {
        Some(until) => out.push_str(&until.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"amended_at\":");
    out.push_str(&appended_at_ms.to_string());
    out.push_str(",\"reason_sha256\":");
    json_string(&hex::encode(reason_hash), &mut out);
    out.push('}');
    Ok(json_answer(out.into_bytes()))
}

/// Who asked for a correction — the fact the verbs unit resolved at Route and the durable amendment
/// record states.
#[derive(Debug, Clone)]
pub struct AmendAttribution {
    /// The authenticated principal that submitted the correction.
    pub principal: String,
}

pub const AMENDMENT_RECORD_TAG: &str = "busbar/rate-amendment/v3";

const AMENDMENT_RECORD_TAG_V2: &str = "busbar/rate-amendment/v2";

const AMENDMENT_RECORD_TAG_V1: &str = "busbar/rate-amendment/v1";

/// One sealed rate-card amendment, as the node's journal keeps it: every figure the correction put
/// on the history, who submitted it, and the canonical bytes of the correction.
///
/// The `operator_fingerprint`, `dual_control` and `signature` slots keep the `v3` shape a record
/// already on a journal was written in. Under #77(9) (OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md`
/// l.2279: no verb carries dual control or operator signatures) this node writes them as the empty
/// fingerprint, `single` and the empty signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendmentRecord {
    /// Start of the corrected window, milliseconds.
    pub effective_from: u64,
    /// End of the corrected window, milliseconds; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When the correction was admitted, milliseconds.
    pub amended_at_ms: u64,
    /// `Some` (every record this node writes, `v3`): the cells are set OVER the card in force for
    /// the window, and this is that card's entry number and digest, written at amend time. A
    /// restart rebuilds the entry over the entry at that number holding that card, or refuses it
    /// ([`crate::root::kernel::CorrectionRefused`]). `None` for a `v1`/`v2` record, whose cells
    /// and fee were the whole card it sealed.
    pub sealed_over: Option<crate::root::kernel::CorrectionBase>,
    /// THE SEALED CARD'S FEE, MINOR UNITS — named `sealed_fee` and not the wire spelling.
    ///
    /// This is the journal's own internal record shape, not the wire: it stores what the sealed
    /// [`busbar_kernel_ledger::cost::RateCard`] already resolved (`card.fee()`), never the
    /// operator's raw JSON field. Kept off the `per_request_fee`/`fee_cents` spellings on purpose —
    /// `[rules.one-pricing-site.fee_allowed.amend-rate-history]` reviews exactly four reads of that
    /// wire name in this file (the parse, the shape refusal, the relay to the `Correction`, and
    /// the signed payload's own key literal); a durable record's encode/decode is not one of them,
    /// and giving it the wire's own name would silently spend two of the grant's four slots on a
    /// binary journal format that was never reviewed as a wire reader.
    pub sealed_fee: i64,
    /// `(lane, class, nanos_per_unit)` for every cell the correction named, as the card sealed it.
    /// `None` is a cell the card could not represent: UNPRICED, so a hit on it refuses (#42) — never
    /// a zero.
    pub rates: Vec<(String, String, Option<u64>)>,
    /// Empty on every record this node writes (#77(9): no operator signs a correction); a record
    /// written before that ruling holds `sha256(operator key)`, hex.
    pub operator_fingerprint: String,
    /// `sha256(reason)`.
    pub reason_hash: [u8; 32],
    /// The authenticated principal that submitted it.
    pub principal: String,
    /// `single` on every record this node writes (#77(9): no verb carries dual control).
    pub dual_control: String,
    /// The canonical payload of the correction ([`canonical_amend_payload`]).
    pub signed_payload: Vec<u8>,
    /// Empty on every record this node writes (#77(9)); a record written before that ruling holds
    /// the detached ed25519 signature, hex.
    pub signature: String,
}

#[must_use]
pub fn amendment_body(record: &AmendmentRecord) -> Vec<u8> {
    let mut body = busbar_kernel_wal::BodyWriter::new();
    body.text(if record.sealed_over.is_some() {
        AMENDMENT_RECORD_TAG
    } else {
        AMENDMENT_RECORD_TAG_V2
    });
    body.num(record.effective_from);
    body.num(u64::from(record.effective_until.is_some()));
    body.num(record.effective_until.unwrap_or(0));
    body.num(record.amended_at_ms);
    if let Some(base) = &record.sealed_over {
        body.num(base.seq.get());
        body.bytes(&base.card_digest);
    }
    body.figure(i128::from(record.sealed_fee));
    body.num(record.rates.len() as u64);
    for (lane, class, nanos) in &record.rates {
        body.text(lane);
        body.text(class);
        body.num(u64::from(nanos.is_some()));
        body.num(nanos.unwrap_or(0));
    }
    body.text(&record.operator_fingerprint);
    body.bytes(&record.reason_hash);
    body.text(&record.principal);
    body.text(&record.dual_control);
    body.bytes(&record.signed_payload);
    body.text(&record.signature);
    body.finish()
}

#[must_use]
pub fn amendment_from_body(body: &[u8]) -> Option<AmendmentRecord> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            Some(head)
        }
        fn num(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        fn figure(&mut self) -> Option<i128> {
            Some(i128::from_le_bytes(self.take(16)?.try_into().ok()?))
        }
        fn bytes(&mut self) -> Option<&'a [u8]> {
            let len = usize::try_from(self.num()?).ok()?;
            self.take(len)
        }
        fn text(&mut self) -> Option<String> {
            String::from_utf8(self.bytes()?.to_vec()).ok()
        }
    }
    let mut r = Reader(body);
    let (v2, v3) = match r.text()?.as_str() {
        AMENDMENT_RECORD_TAG => (true, true),
        AMENDMENT_RECORD_TAG_V2 => (true, false),
        AMENDMENT_RECORD_TAG_V1 => (false, false),
        _ => return None,
    };
    let effective_from = r.num()?;
    let has_until = r.num()?;
    let until = r.num()?;
    let amended_at_ms = r.num()?;
    let sealed_over = if v3 {
        Some(crate::root::kernel::CorrectionBase {
            seq: busbar_kernel_ledger::cost::HistorySeq(r.num()?),
            card_digest: r.bytes()?.try_into().ok()?,
        })
    } else {
        None
    };
    let sealed_fee = i64::try_from(r.figure()?).ok()?;
    let n = r.num()?;
    let mut rates = Vec::new();
    for _ in 0..n {
        let (lane, class) = (r.text()?, r.text()?);
        let priced = if v2 { r.num()? } else { 1 };
        let nanos = r.num()?;
        let nanos = match priced {
            0 => None,
            1 => Some(nanos),
            _ => return None,
        };
        rates.push((lane, class, nanos));
    }
    let record = AmendmentRecord {
        effective_from,
        effective_until: (has_until == 1).then_some(until),
        amended_at_ms,
        sealed_over,
        sealed_fee,
        rates,
        operator_fingerprint: r.text()?,
        reason_hash: r.bytes()?.try_into().ok()?,
        principal: r.text()?,
        dual_control: r.text()?,
        signed_payload: r.bytes()?.to_vec(),
        signature: r.text()?,
    };
    r.0.is_empty().then_some(record)
}

pub struct AmendmentJournal {
    book: Arc<Mutex<crate::root::durability::Durability>>,
    token: Grant<busbar_contract::caps::DurableWrite>,
}

impl std::fmt::Debug for AmendmentJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmendmentJournal").finish_non_exhaustive()
    }
}

impl AmendmentJournal {
    #[must_use]
    pub fn new(
        book: Arc<Mutex<crate::root::durability::Durability>>,
        token: Grant<busbar_contract::caps::DurableWrite>,
    ) -> Self {
        AmendmentJournal { book, token }
    }

    pub fn record(
        &self,
        record: &AmendmentRecord,
        wall_secs: u64,
    ) -> Result<(), busbar_core_admin::GovernanceError> {
        self.seal_policy(amendment_body(record), wall_secs)
            .map(|_| ())
    }

    pub fn admit(&self) -> Result<(), String> {
        let lane = {
            let durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
            if !durability.durable_in_store() {
                return Ok(());
            }
            durability.lane().cloned()
        };
        lane.map_or(Ok(()), |lane| lane.healthy())
    }

    pub fn acked(&self, node_seq: u64) -> Result<(), String> {
        let (lane, node) = {
            let durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
            let node = durability.journal.node();
            let owed = durability.journal.log().owed().iter().any(|record| {
                let (of, seq) = record.identity();
                of == node && seq <= node_seq
            });
            if owed {
                return Err(
                    "the journal could not make the record durable; it is retained on \
                     this node's journal and written ahead of the next record"
                        .to_string(),
                );
            }
            if !durability.durable_in_store() {
                return Ok(());
            }
            (durability.lane().cloned(), node)
        };
        lane.map_or(Ok(()), |lane| {
            lane.wait_acked(node, node_seq, crate::root::durability::ACK_DEADLINE)
        })
    }

    pub fn seal_policy(
        &self,
        body: Vec<u8>,
        wall_secs: u64,
    ) -> Result<(u64, [u8; 32]), busbar_core_admin::GovernanceError> {
        let entry = busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Policy, body)
            .at(wall_secs, 0);
        let mut durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
        match durability.journal.append(
            &self.token,
            busbar_contract::caps::StepName::Route,
            &[entry],
        ) {
            Ok(ack) => {
                let sealed = ack
                    .sealed
                    .last()
                    .ok_or(busbar_core_admin::GovernanceError::Store)?;
                Ok((sealed.node_seq, sealed.hash))
            }
            Err(_lost) => {
                let journal = &durability.journal;
                let sealed = (journal.node(), journal.next_seq().saturating_sub(1));
                let log = journal.log();
                if log.holds(sealed.0, sealed.1)
                    || log.owed().iter().any(|r| r.identity() == sealed)
                {
                    Ok((sealed.1, journal.head()))
                } else {
                    Err(busbar_core_admin::GovernanceError::Store)
                }
            }
        }
    }

    #[must_use]
    pub fn sealed_through(&self) -> u64 {
        self.book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .next_seq()
            .saturating_sub(1)
    }
}

fn exact_nano_rate(text: &str) -> Option<u64> {
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (text, 0),
    };
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mantissa),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some(0);
    }
    if negative {
        return None;
    }

    let shift = i64::from(exponent) + 3 - i64::try_from(fraction.len()).ok()?;
    let digits = if shift < 0 {
        let cut = usize::try_from(-shift).ok()?;
        let keep = digits.len().checked_sub(cut)?;
        if !digits[keep..].bytes().all(|b| b == b'0') {
            return None;
        }
        &digits[..keep]
    } else {
        digits
    };
    let mut value: u64 = if digits.is_empty() {
        0
    } else {
        digits.parse().ok()?
    };
    for _ in 0..shift.max(0) {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

fn canonical_amend_payload(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
    let mut payload = String::from("busbar/amend-rate-history/v1\n");

    for key in [
        "effective_from",
        "effective_until",
        "per_request_fee",
        "reason",
        "rates",
    ] {
        payload.push_str(key);
        payload.push('=');
        let value = obj.get(key).unwrap_or(&serde_json::Value::Null);
        payload.push_str(&serde_json::to_string(value).unwrap_or_default());
        payload.push('\n');
    }
    payload.into_bytes()
}

fn render_ledger_view(
    verb: KernelVerb,
    view: &dyn LedgerView,
) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
    let priced = || {
        view.priced().map_err(|why| {
            tracing::warn!(why = %why, "a ledger view could not read the ledger's counts");
            busbar_core_admin::GovernanceError::Store
        })
    };
    Ok(match verb {
        KernelVerb::GetLedgerTotals => render_totals(&priced()?)
            .map_err(|_| busbar_core_admin::GovernanceError::Store)?
            .into_bytes(),

        KernelVerb::GetLedgerCheckpoints => b"{\"checkpoints\":[]}".to_vec(),
        KernelVerb::GetLedgerReconciliation => render_reconciliation(&priced()?).into_bytes(),

        KernelVerb::GetLedgerMigration => b"{\"migrated\":false,\"marker\":null}".to_vec(),

        KernelVerb::GetLedgerOpenapiJson => {
            busbar_core_admin::v1::json::openapi_document().into_bytes()
        }
        _ => return Err(busbar_core_admin::GovernanceError::NotFound),
    })
}

fn json_string(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_amount(value: i128, out: &mut String) {
    out.push('"');
    out.push_str(&value.to_string());
    out.push('"');
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn render_refused(refused: &[RefusedRow], out: &mut String) {
    out.push_str(",\"refused\":[");
    for (i, row) in refused.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"bucket\":");
        json_string(&row.bucket, out);
        out.push_str(",\"dimension\":\"nano-units\",\"scope\":\"all\",\"day\":");
        out.push_str(&row.day.to_string());
        out.push_str(",\"lane\":\"\",\"refusal\":");
        json_string(&row.refusal, out);
        out.push('}');
    }
    out.push(']');
}

fn render_totals(ledger: &PricedLedger) -> Result<String, MoneyError> {
    let mut out = String::from("{\"rows\":[");
    for (i, row) in ledger.rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"bucket\":");
        json_string(&row.bucket, &mut out);
        out.push_str(",\"day\":");
        out.push_str(&row.day.to_string());
        out.push_str(",\"lane\":\"\",\"provider\":\"\",\"priced_nanos\":\"");
        out.push_str(&row.priced_nanos.to_string());
        out.push_str("\",\"priced_micros\":");
        json_amount(
            i128::from(Money::of_nanos(row.priced_nanos)?.micros_i64()?),
            &mut out,
        );
        out.push_str(",\"fee_count\":");
        out.push_str(&row.fee_count.to_string());
        out.push('}');
    }
    out.push(']');
    render_refused(&ledger.refused, &mut out);
    out.push('}');
    Ok(out)
}

fn render_reconciliation(ledger: &PricedLedger) -> String {
    let mut out = String::from("{\"holds\":");
    out.push_str(if ledger.refused.is_empty() {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"discrepancies\":[]");
    render_refused(&ledger.refused, &mut out);
    out.push('}');
    out
}

/// ONE ADMIN REQUEST, AS ITS STEPS WALK IT: the request, and what each step decided about it.
///
/// Owned by the one call that answers the request ([`AdminNode::answer`]) and handed to each step in
/// turn, so a step reads exactly the field it needs and nothing outlives the request: there is no
/// node-wide table for an entry to leak from.
#[derive(Debug)]
pub(crate) struct AdminWalk {
    request: AdminRequest,
    verb: Option<ResolvedVerb>,
    granted: Option<VerbScope>,
    /// The per-verb allow-list the door identified the caller with, when its bindings grant verbs
    /// BY NAME (#77(9) l.2279); `None` = the rung alone decides, as it did in 1.5.5.
    listed: Option<busbar_kernel::auth::VerbAllowList>,
    /// Who the auth step said is calling, kept from Verify on. The credential that was presented is
    /// NOT the identity that was resolved: the identity is what a record attributes to, and the
    /// credential is a secret that must not travel past the step that verified it.
    principal: Option<PrincipalId>,
    /// The replay claim the door's identity asks for, UNWON until every step that may still refuse
    /// the request has passed ([`claim`]).
    claim: Option<busbar_kernel::auth::PendingClaim>,
    answer: Option<AdminAnswer>,
}

impl AdminWalk {
    #[must_use]
    pub(crate) fn new(request: AdminRequest) -> Self {
        AdminWalk {
            request,
            verb: None,
            granted: None,
            listed: None,
            principal: None,
            claim: None,
            answer: None,
        }
    }
}

pub type AdminDoorFn =
    Arc<dyn Fn(&AdminRequest) -> busbar_kernel::auth::AdminVerdict + Send + Sync>;

#[cfg(test)]
pub(crate) fn open_door() -> AdminDoorFn {
    Arc::new(|_: &AdminRequest| {
        busbar_kernel::auth::AdminVerdict::from(busbar_kernel::auth::AdminDoor::Open)
    })
}

#[cfg(test)]
pub(crate) fn door_of_chain(chain: busbar_kernel_identity::AuthChain) -> AdminDoorFn {
    use busbar_kernel::auth::AdminDoor;
    use busbar_kernel_identity::chain::ChainVerdict;
    Arc::new(
        move |request: &AdminRequest| -> busbar_kernel::auth::AdminVerdict {
            match chain.run_chain(request.credential.as_deref()) {
                ChainVerdict::Open => AdminDoor::Open,
                ChainVerdict::Denied => AdminDoor::Denied,
                ChainVerdict::Identified { principal, .. } => {
                    let grants = if principal.id == crate::root::auth_bindings::ADMIN_PRINCIPAL_ID {
                        busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full)
                    } else {
                        busbar_contract::authz::Grants::default()
                    };
                    let principal = busbar_contract::auth::Principal::from_id(principal.id);
                    AdminDoor::Identified(principal, grants)
                }
            }
            .into()
        },
    )
}

pub struct AdminBinding {
    pub dispatch: Arc<dyn AdminDispatch>,

    pub door: AdminDoorFn,

    pub ledger: Arc<dyn LedgerView>,

    pub audit: Option<Arc<dyn AuditView>>,

    pub amendments: Option<Arc<AmendmentJournal>>,

    pub node_amendments: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,

    pub replay_store: Option<bound::ReplayStore>,

    pub pools: PoolKnown,

    pub adjuster: adjust::UsageAdjuster,

    pub planes: PlaneLookup,

    pub records: Option<PlaneRecordSink>,

    pub trust: TrustDesk,

    pub replays: Arc<std::sync::OnceLock<Arc<bound::ReplayCache>>>,

    pub mutations: Arc<busbar_core_admin::rate::MutationLimiter>,
}

impl std::fmt::Debug for AdminBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminBinding").finish_non_exhaustive()
    }
}

impl AdminBinding {
    #[must_use]
    pub fn new(dispatch: Arc<dyn AdminDispatch>, door: AdminDoorFn) -> Self {
        AdminBinding {
            dispatch,
            door,
            ledger: Arc::new(UnopenedLedger),
            audit: None,
            amendments: None,
            node_amendments: None,
            replay_store: None,
            pools: no_pools(),
            adjuster: adjust::no_ledger(),
            planes: no_planes(),
            records: None,
            trust: no_trust(),
            replays: Arc::new(std::sync::OnceLock::new()),
            mutations: Arc::new(busbar_core_admin::rate::MutationLimiter::new()),
        }
    }

    #[must_use]
    pub fn with_pools(mut self, pools: PoolKnown) -> Self {
        self.pools = pools;
        self
    }

    #[must_use]
    pub fn with_ledger_view(mut self, ledger: Arc<dyn LedgerView>) -> Self {
        self.ledger = ledger;
        self
    }

    #[must_use]
    pub fn with_audit_view(mut self, audit: Arc<dyn AuditView>) -> Self {
        self.audit = Some(audit);
        self
    }

    #[must_use]
    pub fn with_amendment_journal(mut self, journal: Arc<AmendmentJournal>) -> Self {
        self.amendments = Some(journal);
        self
    }

    #[must_use]
    pub fn with_node_amendments(
        mut self,
        journal: Arc<busbar_kernel_audit::amend::NodeAmendments>,
    ) -> Self {
        self.node_amendments = Some(journal);
        self
    }
}

#[must_use]
pub fn kernel_verb(resolved: &ResolvedVerb) -> Option<KernelVerb> {
    busbar_core_admin::verb::verb_for(resolved.method, resolved.template)
}

#[must_use]
pub fn mutation_class(verb: KernelVerb) -> MutationClass {
    MutationClass::for_verb(verb, CONFIG_CLASS_RULES)
}

pub(crate) fn decide(
    units: &crate::root::kernel::ProductionUnits,
    walk: &mut AdminWalk,
) -> Outcome {
    use busbar_contract::caps::StepName;
    let at = |step: StepName| move |reason: ReasonCode| Outcome::Refused(step, reason);
    let ran = decode(walk)
        .map_err(at(StepName::Decode))
        .and_then(|()| {
            authenticate(&units.admin, &units.auth_bindings, walk)
                .map_err(at(StepName::Authenticate))
        })
        .and_then(|principal| verify(walk, &principal).map_err(at(StepName::Verify)))
        .and_then(|()| approve(walk).map_err(at(StepName::Approve)))
        .and_then(|()| admit(walk).map_err(at(StepName::Admit)))
        .and_then(|()| claim(walk).map_err(at(StepName::Authenticate)))
        .and_then(|()| {
            route(&units.admin, units.store.clone(), &units.admin_token, walk)
                .map_err(|reason| Outcome::Failed(StepName::Route, reason))
        });
    match ran {
        Ok(()) => Outcome::Completed,
        Err(ended) => ended,
    }
}

pub(crate) fn decode(walk: &mut AdminWalk) -> Result<(), ReasonCode> {
    match busbar_core_admin::admin_codec::verbs::resolve(&walk.request.method, &walk.request.path) {
        None => Err(ReasonCode::DecodeFailed),
        Some(resolved) => {
            walk.verb = Some(resolved);
            Ok(())
        }
    }
}

pub(crate) fn authenticate(
    binding: &AdminBinding,
    bindings: &crate::root::auth_bindings::AuthBindings,
    walk: &mut AdminWalk,
) -> Result<PrincipalId, ReasonCode> {
    let request = &walk.request;
    let revoked = || {
        bindings
            .revocations()
            .zip(request.credential.as_deref())
            .is_some_and(|(set, credential)| set.is_revoked(credential))
    };
    let verdict = (binding.door)(request);
    let (principal, grants, listed) = match verdict.door {
        busbar_kernel::auth::AdminDoor::Open => (
            busbar_kernel_identity::principal::ANONYMOUS.to_string(),
            busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
            None,
        ),
        busbar_kernel::auth::AdminDoor::Identified(principal, grants) => {
            if revoked() {
                return Err(ReasonCode::Revoked);
            }
            (principal.id, grants, None)
        }
        busbar_kernel::auth::AdminDoor::Listed(principal, grants, list) => {
            if revoked() {
                return Err(ReasonCode::Revoked);
            }
            (principal.id, grants, Some(list))
        }
        busbar_kernel::auth::AdminDoor::Denied => return Err(ReasonCode::Unauthenticated),
        busbar_kernel::auth::AdminDoor::Unavailable(_) => {
            walk.answer = Some(authentication_unavailable_answer());
            return Err(ReasonCode::Internal);
        }
    };

    use busbar_contract::authz::Scope as Rung;
    if grants.allows(Rung::Full) {
        walk.granted = Some(VerbScope::Full);
    } else if grants.allows(Rung::ReadOnly) {
        walk.granted = Some(VerbScope::ReadOnly);
    }

    if listed.is_some() {
        walk.listed = listed;
    }
    walk.claim = verdict.claim;
    Ok(PrincipalId::new(principal))
}

pub(crate) fn claim(walk: &mut AdminWalk) -> Result<(), ReasonCode> {
    match walk.claim.take() {
        Some(pending) if !pending.win_now() => Err(ReasonCode::Unauthenticated),
        _ => Ok(()),
    }
}

pub(crate) fn verify(walk: &mut AdminWalk, principal: &PrincipalId) -> Result<(), ReasonCode> {
    walk.principal = Some(principal.clone());
    match walk.verb {
        None => Err(ReasonCode::NoDestination),
        Some(_resolved) => Ok(()),
    }
}

pub(crate) fn approve(walk: &AdminWalk) -> Result<(), ReasonCode> {
    let Some(granted) = walk.granted else {
        return Err(ReasonCode::ScopeDenied);
    };
    let needed =
        busbar_kernel::admin::scope::admin_required_scope(&walk.request.method, &walk.request.path);
    if !granted.allows(scope_as_verb_scope(needed)) {
        return Err(ReasonCode::ScopeDenied);
    }

    if let Some(list) = &walk.listed {
        let verb = walk.verb.map(|resolved| resolved.verb);
        if !list.admits(verb, needed) {
            return Err(ReasonCode::ScopeDenied);
        }
    }
    Ok(())
}

fn scope_as_verb_scope(scope: Scope) -> VerbScope {
    match scope {
        Scope::ReadOnly => VerbScope::ReadOnly,
        Scope::Full => VerbScope::Full,
    }
}

pub(crate) fn admit(walk: &AdminWalk) -> Result<(), ReasonCode> {
    let verb = walk
        .verb
        .as_ref()
        .and_then(kernel_verb)
        .ok_or(ReasonCode::NoDestination)?;

    let _class = mutation_class(verb);
    Ok(())
}

pub(crate) fn route(
    binding: &AdminBinding,
    store: crate::root::kernel::VerbStoreHandle,
    admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    walk: &mut AdminWalk,
) -> Result<(), ReasonCode> {
    let verb = walk
        .verb
        .as_ref()
        .and_then(kernel_verb)
        .ok_or(ReasonCode::NoDestination)?;

    let granted = walk.granted.ok_or(ReasonCode::ScopeDenied)?;
    let request = &walk.request;

    if mints_its_own_identity(verb) {
        walk.answer = Some(binding.dispatch.execute(verb, request));
        return Ok(());
    }

    let actor = actor_of(walk);

    let verbs = busbar_core_admin::Verbs::new(
        CoreGovernance::new(
            Arc::clone(&binding.dispatch),
            Arc::clone(&binding.ledger),
            binding.audit.clone(),
            verb,
            request.clone(),
        )
        .amending(
            binding.amendments.clone(),
            AmendAttribution {
                principal: actor.clone(),
            },
        )
        .noting(binding.node_amendments.clone())
        .granted(granted)
        .pooled(Arc::clone(&binding.pools))
        .adjusting(Arc::clone(&binding.adjuster))
        .planed(Arc::clone(&binding.planes), binding.records.clone())
        .trusting(Arc::clone(&binding.trust))
        .replaying(
            Arc::clone(
                binding
                    .replays
                    .get_or_init(|| Arc::new(bound::ReplayCache::new())),
            ),
            binding.replay_store.clone(),
        ),
        store,
        CONFIG_CLASS_RULES,
        Arc::clone(&binding.mutations),
    );

    let answer = if let Some(recovery) = recovery_verb(verb) {
        let ran = match recovery {
            RecoveryVerb::ChainBreak => verbs.chain_break(admin, &actor, granted, request.at),
            RecoveryVerb::StoreRestore => {
                let backup_ref = backup_ref_of(&request.body).ok_or(ReasonCode::DecodeFailed)?;
                verbs.store_restore(admin, &actor, granted, request.at, &backup_ref)
            }
        };
        ran.map(|()| applied_answer())
    } else {
        verbs.execute(verb, admin, &actor, granted, request.at, &request.body)
    };
    walk.answer = Some(answer.map_err(|refusal| verbs_reason(refusal.reason))?);
    Ok(())
}

/// The two verbs whose effect lands on the store rather than on a handler.
///
/// Named as a closed enumeration of its own rather than matched inline, so "these two and no
/// others" is a fact with a test on it. The verbs unit draws the same line from the other side: it
/// gives each of them a method, and gives `execute` no arm that could reach one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryVerb {
    ChainBreak,
    StoreRestore,
}

fn recovery_verb(verb: KernelVerb) -> Option<RecoveryVerb> {
    match verb {
        KernelVerb::ChainBreak => Some(RecoveryVerb::ChainBreak),
        KernelVerb::StoreRestore => Some(RecoveryVerb::StoreRestore),
        _ => None,
    }
}

fn applied_answer() -> AdminAnswer {
    AdminAnswer {
        status: 204,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn backup_ref_of(body: &[u8]) -> Option<String> {
    const FIELD: &str = "\"backup_ref\"";
    let text = std::str::from_utf8(body).ok()?;
    let after = &text[text.find(FIELD)? + FIELD.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let mut chars = after.strip_prefix('"')?.chars();
    let mut value = String::new();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                '/' => value.push('/'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'b' => value.push('\u{08}'),
                'f' => value.push('\u{0c}'),
                'u' => {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    value.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }

                _ => return None,
            },
            c => value.push(c),
        }
    }

    (!value.is_empty()).then_some(value)
}

fn mints_its_own_identity(verb: KernelVerb) -> bool {
    matches!(verb, KernelVerb::PostKeys | KernelVerb::PostKeysIdRotate)
}

fn resolved_actor(walk: &AdminWalk) -> Option<String> {
    walk.principal.as_ref().map(|p| p.as_str().to_string())
}

const UNRESOLVED_ACTOR: &str = "admin";

fn actor_of(walk: &AdminWalk) -> String {
    resolved_actor(walk).unwrap_or_else(|| UNRESOLVED_ACTOR.to_string())
}

fn verbs_reason(reason: busbar_core_admin::ReasonCode) -> ReasonCode {
    use busbar_core_admin::ReasonCode as V;
    match reason {
        V::Unauthorized => ReasonCode::ScopeDenied,
        V::RateLimited => ReasonCode::RateLimited,
        V::NotFound => ReasonCode::NoDestination,
        V::IdempotencyInFlight | V::Conflict => ReasonCode::OpenSlotBusy,
        V::Validation => ReasonCode::DecodeFailed,
        V::StoreError | V::Internal => ReasonCode::DurabilityUnavailable,
    }
}

pub(crate) fn audit(walk: &AdminWalk, ended: &Outcome) -> busbar_contract::AuditFacts {
    let Some(resolved) = walk.verb else {
        return unresolved_facts(Some(&walk.request.method), ended);
    };
    let applied = matches!(ended, Outcome::Completed)
        && walk
            .answer
            .as_ref()
            .is_some_and(|answer| (200..300).contains(&answer.status));
    seal_root_only(walk, &resolved, applied);
    busbar_contract::AuditFacts {
        op_class: resolved.op_class(),
        finish: finish_of(ended),
    }
}

fn seal_root_only(walk: &AdminWalk, resolved: &ResolvedVerb, applied: bool) {
    let root_only =
        !resolved.read_only && kernel_verb(resolved).is_some_and(|v| NEW_VERBS.contains(&v));
    if let (true, Some(actor)) = (root_only, resolved_actor(walk)) {
        let outcome = if applied {
            busbar_kernel::audit_ring::OUTCOME_APPLIED
        } else {
            busbar_kernel::audit_ring::OUTCOME_REJECTED
        };
        busbar_kernel::audit_ring::AUDIT.record_by(
            resolved.verb,
            resolved.template,
            outcome,
            &actor,
        );
    }
}

pub(crate) fn unresolved_facts(
    method: Option<&str>,
    outcome: &Outcome,
) -> busbar_contract::AuditFacts {
    busbar_contract::AuditFacts {
        op_class: busbar_contract::OpClassId::new(match method {
            Some(method) if !is_read_method(method) => OP_UNRESOLVED_WRITE,
            _ => OP_UNRESOLVED_READ,
        }),
        finish: finish_of(outcome),
    }
}

const OP_UNRESOLVED_READ: &str = "admin_read";

const OP_UNRESOLVED_WRITE: &str = "admin_write";

fn is_read_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn finish_of(outcome: &Outcome) -> busbar_contract::FinishClass {
    match outcome {
        Outcome::Completed => busbar_contract::FinishClass::Complete,
        _ => busbar_contract::FinishClass::Error,
    }
}

mod admin_mount;
pub(crate) use admin_mount::*;

mod adjust;
pub use adjust::live_adjuster;
pub(crate) mod bound;
pub use bound::{
    live_admin_door, live_planes, live_records, live_replay_store, no_planes, no_trust,
    PlaneLookup, PlaneRecordSink, TrustDesk,
};

#[cfg(test)]
#[path = "tests/units_admin.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/admin_unit_records.rs"]
mod admin_unit_records;
