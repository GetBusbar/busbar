// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::authz::Scope;
use busbar_contract::caps::{Grant, Outcome, PrincipalId, ReasonCode};
use busbar_contract::UnitKey;
use busbar_core_admin::admin_codec::verbs::ResolvedVerb;
use busbar_kernel_audit::{expose, AuditChain, AuditKeySet, AuditRecord};

use busbar_core_admin::{KernelVerb, VerbScope, NEW_VERBS};
#[cfg(test)]
use busbar_core_admin::{AUDIT_VERBS, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES};
use busbar_kernel_ledger::cost::{Money, MoneyError};

/// Immutable original request custody, shared across the operation task and HTTP projection.
#[derive(Clone)]
pub(crate) struct AdminRequest {
    snapshot: Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot>,
    pub unit: u64,
}

impl AdminRequest {
    pub(crate) fn from_snapshot(
        snapshot: Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot>,
        unit: u64,
    ) -> Self {
        Self { snapshot, unit }
    }
    pub(crate) fn snapshot(
        &self,
    ) -> &Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot> {
        &self.snapshot
    }
    pub(crate) fn method(&self) -> &str {
        self.snapshot.method()
    }
    pub(crate) fn path(&self) -> &str {
        self.snapshot.target()
    }
    pub(crate) fn body(&self) -> &[u8] {
        self.snapshot.body()
    }
    pub(crate) fn at(&self) -> u64 {
        self.snapshot.now_s()
    }
    pub(crate) fn headers(&self) -> impl Clone + ExactSizeIterator<Item = (&str, &[u8])> {
        self.snapshot.headers()
    }
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
    }
    pub(crate) fn credential(&self) -> Option<&str> {
        self.header("authorization")
            .map(|value| {
                let trimmed = value.trim_start();
                match trimmed.split_once(' ') {
                    Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => {
                        rest.trim_start()
                    }
                    _ => trimmed,
                }
            })
            .filter(|credential| !credential.is_empty())
            .or_else(|| {
                self.header(ADMIN_TOKEN_HEADER)
                    .filter(|credential| !credential.is_empty())
            })
    }
    pub(crate) fn http_headers(&self) -> Result<axum::http::HeaderMap, ()> {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in self.headers() {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?,
                axum::http::HeaderValue::from_bytes(value).map_err(|_| ())?,
            );
        }
        Ok(headers)
    }
}

impl PartialEq for AdminRequest {
    fn eq(&self, other: &Self) -> bool {
        self.unit == other.unit && Arc::ptr_eq(&self.snapshot, &other.snapshot)
    }
}
impl Eq for AdminRequest {}

impl std::fmt::Debug for AdminRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminRequest")
            .field("snapshot", &self.snapshot)
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestAdminRequest {
    pub method: String,
    pub path: String,
    pub credential: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub at: u64,
    pub unit: u64,
}

#[cfg(test)]
impl AdminRequest {
    pub(crate) fn test_fixture(input: TestAdminRequest) -> Self {
        use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
        let process = ProcessAdmission::new(2);
        let lease = process.try_enter(AdmissionClass::Operator).unwrap();
        Self::capture_test(input, &lease)
    }
    fn capture_test(
        mut input: TestAdminRequest,
        lease: &busbar_kernel::limits::process_admission::RequestLease,
    ) -> Self {
        use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
        if let Some(credential) = &input.credential {
            if !input.headers.iter().any(|(name, _)| {
                name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case(ADMIN_TOKEN_HEADER)
            }) {
                input
                    .headers
                    .push((ADMIN_TOKEN_HEADER.to_owned(), credential.clone()));
            }
        }
        let (path, query) = input.path.split_once('?').unwrap_or((&input.path, ""));
        let snapshot = ChargedRequestSnapshot::capture(
            SnapshotInput {
                method: &input.method,
                path,
                query,
                query_present: input.path.contains('?'),
                authority: "",
                headers: input
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
                peer: "",
                tls_peer_cert: &[],
                body: &input.body,
                now_s: input.at,
            },
            lease,
        )
        .unwrap();
        Self::from_snapshot(snapshot, input.unit)
    }
    pub(crate) fn edit_for_test(&mut self, edit: impl FnOnce(&mut TestAdminRequest)) {
        let mut input = TestAdminRequest {
            method: self.method().to_owned(),
            path: self.path().to_owned(),
            credential: self.credential().map(str::to_owned),
            headers: self
                .headers()
                .map(|(name, value)| (name.to_owned(), String::from_utf8(value.to_vec()).unwrap()))
                .collect(),
            body: self.body().to_vec(),
            at: self.at(),
            unit: self.unit,
        };
        let before = input.credential.clone();
        edit(&mut input);
        if input.credential != before {
            input.headers.retain(|(name, _)| {
                !name.eq_ignore_ascii_case("authorization")
                    && !name.eq_ignore_ascii_case(ADMIN_TOKEN_HEADER)
            });
        }
        *self = Self::capture_test(input, self.snapshot.request());
    }
}

/// One admin answer, exactly as the surface that owns the operation produced it.
///
/// Status, headers and body together, because all three are pinned and none of them is derivable
/// from the others. An answer that carried only a body would force a status to be re-derived here,
/// and a re-derived status is a status that can differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdminAnswer {
    /// The status code.
    pub status: u16,
    /// The response headers, in emission order.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

#[async_trait::async_trait]
pub(crate) trait AdminDispatch: Send + Sync {
    async fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer;

    async fn execute_admitted(
        &self,
        verb: KernelVerb,
        request: &AdminRequest,
        _admission: &busbar_kernel::inbound::RequestAdmission,
    ) -> AdminAnswer {
        self.execute(verb, request).await
    }

    async fn execute_authorized(
        &self,
        verb: KernelVerb,
        request: &AdminRequest,
        admission: Option<&busbar_kernel::inbound::RequestAdmission>,
        _execution: Option<&Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
    ) -> AdminAnswer {
        match admission {
            Some(admission) => self.execute_admitted(verb, request, admission).await,
            None => self.execute(verb, request).await,
        }
    }
}

/// Host-owned request context, never part of the serialized administrative request.
struct AdmittedDispatch {
    inner: Arc<dyn AdminDispatch>,
    admission: Option<busbar_kernel::inbound::RequestAdmission>,
    execution: Option<Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
}

#[async_trait::async_trait]
impl AdminDispatch for AdmittedDispatch {
    async fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        self.inner
            .execute_authorized(
                verb,
                request,
                self.admission.as_ref(),
                self.execution.as_ref(),
            )
            .await
    }
}

#[cfg(test)]
/// The dispatch a node has before it has mounted an admin surface.
///
/// It refuses every operation, which is the correct answer rather than a placeholder: a root that
/// has composed the loop but not yet mounted the surface has genuinely nowhere to send an admin
/// request, and answering `503` says exactly that. Building the units against this is what lets the
/// composition be tested without a listener.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RefusingDispatch;

#[cfg(test)]
#[async_trait::async_trait]
impl AdminDispatch for RefusingDispatch {
    async fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
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
pub(crate) struct LedgerRow {
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
pub(crate) struct RefusedRow {
    /// The bucket.
    pub bucket: String,
    /// The window, as the unix second it opens at.
    pub day: u64,
    /// The refusal, in the one function's own words.
    pub refusal: String,
}

/// The one ledger as the views read it, as of one read: every priced row, and every refused one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PricedLedger {
    /// The priced rows, in bucket order. A row nothing was counted in is not a row.
    pub rows: Vec<LedgerRow>,
    /// The rows the card refused to price.
    pub refused: Vec<RefusedRow>,
}

#[async_trait::async_trait]
pub(crate) trait LedgerView: Send + Sync {
    async fn priced(&self) -> Result<PricedLedger, String>;
}

/// The view a node has before a ledger is bound behind it: no rows, which is the truth about a node
/// composed with no governance store.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnopenedLedger;

#[async_trait::async_trait]
impl LedgerView for UnopenedLedger {
    async fn priced(&self) -> Result<PricedLedger, String> {
        Ok(PricedLedger::default())
    }
}

pub(crate) struct CountsLedger {
    app: Arc<busbar_kernel::state::AppHandle>,
}

impl std::fmt::Debug for CountsLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountsLedger").finish_non_exhaustive()
    }
}

impl CountsLedger {
    #[must_use]
    pub(crate) fn new(app: Arc<busbar_kernel::state::AppHandle>) -> Self {
        CountsLedger { app }
    }
}

#[async_trait::async_trait]
impl LedgerView for CountsLedger {
    async fn priced(&self) -> Result<PricedLedger, String> {
        let app = self.app.snapshot();
        let Some(gov) = app.governance.clone() else {
            return Ok(PricedLedger::default());
        };
        let now = busbar_kernel::store::now();

        priced_keys(&gov, &app.cost, now).await
    }
}

pub(crate) async fn priced_keys(
    gov: &busbar_kernel::governance::GovState,
    cost: &busbar_kernel::cost::CostModel,
    now: u64,
) -> Result<PricedLedger, String> {
    let mut keys = gov.all_keys_async().await.map_err(|e| e.to_string())?;
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    let mut ledger = PricedLedger::default();
    for key in keys {
        let bucket = gov
            .priced_bucket_async(cost, &key.id, busbar_kernel::governance::WINDOW_TOTAL, now)
            .await
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

#[async_trait::async_trait]
pub(crate) trait AuditView: Send + Sync {
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>));

    async fn read_window(
        &self,
        _from: u64,
        _to: u64,
        take: &mut (dyn for<'chain, 'records> FnMut(&'chain AuditChain, Option<&'records [AuditRecord]>)
                  + Send),
    ) {
        self.read(take);
    }

    async fn range_page(
        &self,
        from: u64,
        to: u64,
        cursor: Option<&str>,
    ) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
        if cursor.is_some() {
            return Err(busbar_core_admin::GovernanceError::Validation);
        }
        let mut answer = Err(busbar_core_admin::GovernanceError::Store);
        self.read_window(from, to, &mut |chain, records| {
            answer = records
                .map(|records| expose::range_body(chain, records, from, to).into_bytes())
                .ok_or(busbar_core_admin::GovernanceError::NotFound);
        })
        .await;
        answer
    }

    fn keys(&self) -> AuditKeySet;

    fn restart_findings(&self) -> Vec<String> {
        Vec::new()
    }

    fn retained_audit_findings(&self) -> Vec<String> {
        Vec::new()
    }

    async fn stored_chain_findings(&self) -> Vec<String> {
        Vec::new()
    }
}

pub(crate) struct NodeAudit {
    durability: Arc<Mutex<crate::root::durability::Durability>>,
}

impl std::fmt::Debug for NodeAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeAudit").finish_non_exhaustive()
    }
}

impl NodeAudit {
    #[must_use]
    pub(crate) fn new(durability: Arc<Mutex<crate::root::durability::Durability>>) -> Self {
        NodeAudit { durability }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, crate::root::durability::Durability> {
        self.durability.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[async_trait::async_trait]
impl AuditView for NodeAudit {
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>)) {
        let durability = self.lock();
        take(&durability.record, Some(durability.audit_records()));
    }

    async fn read_window(
        &self,
        from: u64,
        to: u64,
        take: &mut (dyn for<'chain, 'records> FnMut(&'chain AuditChain, Option<&'records [AuditRecord]>)
                  + Send),
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

            let Some(mut records) = chain.audit_window(from, to).await else {
                return;
            };
            let durability = self.lock();
            if durability.audit_window_since(&mut records, sealed_before, from, to) {
                take(&durability.record, Some(&records));
                return;
            }
        }
    }

    async fn range_page(
        &self,
        from: u64,
        to: u64,
        cursor: Option<&str>,
    ) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
        let plan = self.lock().prepare_audit_page(from, to, cursor)?;
        plan.finish().await
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

    async fn stored_chain_findings(&self) -> Vec<String> {
        let (journal, own, keys, budget) = self.lock().stored_walk_inputs();
        crate::root::durability::walk_stored_chains(&journal, own, &keys, budget)
            .await
            .findings
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

async fn render_audit_view(
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

            let cursor = target
                .split_once('?')
                .and_then(|(_, query)| query.split('#').next())
                .and_then(|query| {
                    query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("cursor="))
                });
            view.range_page(from, to, cursor).await
        }
        _ => Err(GovernanceError::NotFound),
    }
}

pub(crate) type PoolKnown = Arc<dyn Fn(&str) -> bool + Send + Sync>;

fn no_pools() -> PoolKnown {
    Arc::new(|_| false)
}

pub(crate) struct CoreGovernance {
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
    effect: Option<(busbar_kernel::auth::effect::Context, EffectAdmission)>,
}

impl CoreGovernance {
    #[must_use]
    pub(crate) fn new(
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
            effect: None,
        }
    }

    #[must_use]
    pub(crate) fn trusting(mut self, trust: TrustDesk) -> Self {
        self.trust = trust;
        self
    }

    #[must_use]
    pub(crate) fn replaying(
        mut self,
        replays: Arc<bound::ReplayCache>,
        store: Option<bound::ReplayStore>,
    ) -> Self {
        self.replays = replays;
        self.replay_store = store;
        self
    }

    #[must_use]
    pub(crate) fn noting(
        mut self,
        journal: Option<Arc<busbar_kernel_audit::amend::NodeAmendments>>,
    ) -> Self {
        self.node_amendments = journal;
        self
    }

    #[must_use]
    pub(crate) fn planed(mut self, planes: PlaneLookup, records: Option<PlaneRecordSink>) -> Self {
        self.planes = planes;
        self.records = records;
        self
    }

    #[must_use]
    pub(crate) fn pooled(mut self, pools: PoolKnown) -> Self {
        self.pools = pools;
        self
    }

    #[must_use]
    pub(crate) fn adjusting(mut self, adjuster: adjust::UsageAdjuster) -> Self {
        self.adjuster = adjuster;
        self
    }

    #[must_use]
    pub(crate) fn granted(mut self, granted: VerbScope) -> Self {
        self.granted = granted;
        self
    }

    #[must_use]
    pub(crate) fn amending(
        mut self,
        amendments: Option<Arc<AmendmentJournal>>,
        attribution: AmendAttribution,
    ) -> Self {
        self.amendments = amendments;
        self.attribution = attribution;
        self
    }

    fn fenced(
        mut self,
        context: Option<busbar_kernel::auth::effect::Context>,
        admission: Option<EffectAdmission>,
    ) -> Self {
        self.effect = context.zip(admission);
        self
    }

    async fn admit_effect(
        &self,
    ) -> Result<Option<busbar_kernel::config::transaction::EffectGuard>, AdminAnswer> {
        match self.effect.as_ref() {
            None => Ok(None),
            Some((context, admit)) => admit(context).await.map(Some).map_err(|_| {
                admin_mount::error_answer_with_message(
                    403,
                    "forbidden",
                    "current authority does not admit this effect",
                )
            }),
        }
    }

    async fn run(&self) -> AdminAnswer {
        self.dispatch.execute(self.verb, &self.request).await
    }
}

impl busbar_core_admin::Governance for CoreGovernance {
    type Answer = AdminAnswer;

    async fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        Ok(self.run().await)
    }

    async fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        let _effect = if matches!(
            verb,
            KernelVerb::AmendRateHistory
                | KernelVerb::Adjust
                | KernelVerb::TrustApprove
                | KernelVerb::TrustRevoke
        ) {
            match self.admit_effect().await {
                Ok(guard) => guard,
                Err(answer) => return Ok(answer),
            }
        } else {
            None
        };
        if verb == KernelVerb::AmendRateHistory {
            return amend_rate_history_effect(
                &crate::root::kernel::ROOT_CARD,
                self.amendments.as_deref(),
                request,
                self.request.at(),
                &self.attribution,
            )
            .await;
        }

        if verb == KernelVerb::Adjust {
            let scope = match self.granted {
                VerbScope::Full => busbar_contract::authz::Scope::Full,
                VerbScope::ReadOnly => busbar_contract::authz::Scope::ReadOnly,
            };
            return adjust::adjust_request(
                &self.request,
                request,
                scope,
                &self.attribution.principal,
                self.replay_store.as_ref(),
                &*self.pools,
                &self.adjuster,
            )
            .await;
        }

        match verb {
            KernelVerb::Verify => {
                return bound::verify_effect(
                    self.ledger.as_ref(),
                    self.audit.as_deref(),
                    self.node_amendments.as_deref(),
                )
                .await;
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
                return bound::trust_decide_effect(request, ruling, &self.trust).await;
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
                    || async {
                        let _effect = match self.admit_effect().await {
                            Ok(guard) => guard,
                            Err(answer) => return Ok(bound::EffectAnswer::unapplied(answer)),
                        };
                        bound::plane_record_write_effect(
                            request,
                            self.request.at(),
                            &*self.planes,
                            self.records.as_ref(),
                        )
                        .await
                    },
                )
                .await;
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
                    || async {
                        let _effect = match self.admit_effect().await {
                            Ok(guard) => guard,
                            Err(answer) => return Ok(bound::EffectAnswer::unapplied(answer)),
                        };
                        bound::commit_upgrade_effect(
                            request,
                            self.request.at(),
                            &self.attribution.principal,
                            self.amendments.as_deref(),
                        )
                        .await
                    },
                )
                .await;
            }
            _ => {}
        }
        Ok(self.run().await)
    }

    async fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        let body = render_ledger_view(verb, self.ledger.as_ref()).await?;
        Ok(json_answer(body))
    }

    async fn execute_audit_read(
        &self,
        verb: KernelVerb,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _request: &[u8],
    ) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
        let view = self
            .audit
            .as_deref()
            .ok_or(busbar_core_admin::GovernanceError::NotFound)?;
        if verb == KernelVerb::GetAuditKeys {
            return audit_keys_page(&self.request.path, view).await;
        }
        if verb == KernelVerb::GetRecords {
            return Ok(records::records_answer(view, &*self.planes, self.request.path()).await);
        }
        render_audit_view(verb, self.request.path(), view)
            .await
            .map(json_answer)
    }
}

async fn audit_keys_page(
    target: &str,
    view: &dyn AuditView,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
    use busbar_core_admin::v1::contract::LIST_LIMIT_DEFAULT;
    use busbar_core_admin::v1::json::cursor;

    let uri = target
        .parse()
        .map_err(|_| busbar_core_admin::GovernanceError::Validation)?;
    let axum::extract::Query(query) =
        axum::extract::Query::<std::collections::HashMap<String, String>>::try_from_uri(&uri)
            .map_err(|_| busbar_core_admin::GovernanceError::Validation)?;
    let window = match cursor::window(&query, "audit-keys", "", LIST_LIMIT_DEFAULT) {
        Ok(window) => window,
        Err(response) => {
            let (parts, body) = (*response).into_parts();
            let bytes = axum::body::to_bytes(body, 64 * 1024)
                .await
                .map_err(|_| busbar_core_admin::GovernanceError::Store)?;
            return Ok(AdminAnswer {
                status: parts.status.as_u16(),
                headers: parts
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_string(),
                            value.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect(),
                body: bytes.to_vec(),
            });
        }
    };
    let body: json::Value = json::parse_value(expose::keys_body(&view.keys()).as_bytes())
        .map_err(|_| busbar_core_admin::GovernanceError::Store)?;
    let mut body = body
        .into_object()
        .ok_or(busbar_core_admin::GovernanceError::Store)?;
    let keys = body
        .remove(&"keys")
        .and_then(|keys| keys.as_array().map(|keys| keys.to_vec()))
        .ok_or(busbar_core_admin::GovernanceError::Store)?;
    let page = cursor::keyset(
        keys,
        &window,
        "audit-keys",
        "",
        |key| key["key_id"].as_str().unwrap_or_default().to_string(),
        false,
    );
    body.insert("items", json::Value::from(page.items));
    body.insert(
        "next_cursor",
        page.next_cursor
            .map_or_else(json::Value::new_null, json::Value::from),
    );
    json::to_vec(&json::Value::from(body))
        .map(json_answer)
        .map_err(|_| busbar_core_admin::GovernanceError::Store)
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

async fn amend_rate_history_effect(
    history: &crate::root::kernel::RootHistory,
    journal: Option<&AmendmentJournal>,
    body: &[u8],
    arrival_secs: u64,
    attribution: &AmendAttribution,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    use busbar_contract::abi::sdk::digest::sha256;
    use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
    use busbar_core_admin::GovernanceError;

    let doc: json::Value = json::parse_value(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;

    let effective_from = obj
        .get(&"effective_from")
        .and_then(json::Value::as_u64)
        .ok_or(GovernanceError::Validation)?;
    let effective_until = match obj.get(&"effective_until") {
        None => None,
        Some(v) if v.is_null() => None,
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
            return Err(GovernanceError::Validation);
        }
        Some(_) => {}
    }

    let reason = obj
        .get(&"reason")
        .and_then(json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(GovernanceError::Validation)?;
    let reason_hash: [u8; 32] = sha256(reason.as_bytes());

    if obj.contains_key(&"currency") {
        return Err(GovernanceError::Validation);
    }

    let per_request_fee = match obj.get(&"per_request_fee") {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => {
            let fee = v.as_i64().ok_or(GovernanceError::Validation)?;
            if fee < 0 {
                return Err(GovernanceError::Validation);
            }
            Some(fee)
        }
    };
    let mut entries: Vec<(busbar_kernel_ledger::cost::LaneClass, u64)> = Vec::new();
    if let Some(rates) = obj.get(&"rates") {
        for row in rates.as_array().ok_or(GovernanceError::Validation)? {
            let r = row.as_object().ok_or(GovernanceError::Validation)?;
            let lane = r
                .get(&"lane")
                .and_then(json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(GovernanceError::Validation)?;
            let class = r
                .get(&"class")
                .and_then(json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(GovernanceError::Validation)?;

            let nanos = match r.get(&"micro_per_unit") {
                Some(n) if n.is_number() => {
                    json::number_text(n).and_then(|text| exact_nano_rate(&text))
                }
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

    if let Some(journal) = journal {
        if let Err(why) = journal.admit().await {
            return Ok(bound::journal_unavailable(&why));
        }
    }
    let sealed_at = Mutex::new(None);
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
                version: AmendmentVersion::V4,
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
                    .seal_policy(amendment_body(&record)?, arrival_secs)
                    .map(|(node_seq, _)| {
                        *sealed_at.lock().unwrap_or_else(|p| p.into_inner()) = Some(node_seq)
                    }),
                None => Ok(()),
            }
        })
        .await
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

    // Copy the position before awaiting persistence; the mutex protects only staging state.
    let sealed_position = *sealed_at.lock().unwrap_or_else(|p| p.into_inner());
    if let (Some(node_seq), Some(journal)) = (sealed_position, journal) {
        if let Err(why) = journal.acked(node_seq).await {
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
pub(crate) struct AmendAttribution {
    /// The authenticated principal that submitted the correction.
    pub principal: String,
}

pub(crate) const AMENDMENT_RECORD_TAG: &str = "busbar/rate-amendment/v4";

#[cfg(test)]
const AMENDMENT_RECORD_TAG_V3: &str = "busbar/rate-amendment/v3";

#[cfg(test)]
const AMENDMENT_RECORD_TAG_V2: &str = "busbar/rate-amendment/v2";

const AMENDMENT_RECORD_TAG_V1: &str = "busbar/rate-amendment/v1";

/// The original durable encoding retained when an old record is read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AmendmentVersion {
    /// Unbased records with implicitly priced cells.
    V1,
    /// Unbased records with explicit cell pricing markers.
    #[cfg(test)]
    V2,
    /// Records sealed over an original chain-local ordinal.
    #[cfg(test)]
    V3,
    /// Records sealed over an actual fleet entry key.
    V4,
}

/// One sealed rate-card amendment, as the node's journal keeps it: every figure the correction put
/// on the history, who submitted it, and the canonical bytes of the correction.
///
/// The `operator_fingerprint`, `dual_control` and `signature` slots keep the `v3` shape a record
/// already on a journal was written in. No verb carries dual control or operator signatures;
/// this node writes them as the empty
/// fingerprint, `single` and the empty signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AmendmentRecord {
    /// The durable format to preserve when this record is encoded again.
    pub version: AmendmentVersion,
    /// Start of the corrected window, milliseconds.
    pub effective_from: u64,
    /// End of the corrected window, milliseconds; `None` is open-ended.
    pub effective_until: Option<u64>,
    /// When the correction was admitted, milliseconds.
    pub amended_at_ms: u64,
    /// `Some` on new v4 records: the cells are set over the exact keyed card and digest resolved
    /// at amend time. Old v3 records retain a distinct original-chain ordinal. A restart rebuilds
    /// only over the resolved identity holding that card, or refuses it
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

pub(crate) fn amendment_body(
    record: &AmendmentRecord,
) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
    use crate::root::kernel::CorrectionBase;
    let tag = match (record.version, record.sealed_over) {
        (AmendmentVersion::V1, None) if record.rates.iter().all(|(_, _, rate)| rate.is_some()) => {
            AMENDMENT_RECORD_TAG_V1
        }
        #[cfg(test)]
        (AmendmentVersion::V2, None) => AMENDMENT_RECORD_TAG_V2,
        #[cfg(test)]
        (AmendmentVersion::V3, Some(CorrectionBase::LegacyOrdinal { .. })) => {
            AMENDMENT_RECORD_TAG_V3
        }
        (AmendmentVersion::V4, Some(CorrectionBase::Key { .. })) => AMENDMENT_RECORD_TAG,
        _ => return Err(busbar_core_admin::GovernanceError::Validation),
    };
    let mut body = busbar_kernel_wal::BodyWriter::new();
    body.text(tag);
    body.num(record.effective_from);
    body.num(u64::from(record.effective_until.is_some()));
    body.num(record.effective_until.unwrap_or(0));
    body.num(record.amended_at_ms);
    match record.sealed_over {
        Some(CorrectionBase::Key { key, card_digest }) => {
            body.bytes(key.as_bytes());
            body.bytes(&card_digest);
        }
        #[cfg(test)]
        Some(CorrectionBase::LegacyOrdinal { seq, card_digest }) => {
            body.num(seq.get());
            body.bytes(&card_digest);
        }
        None => {}
    }
    body.figure(i128::from(record.sealed_fee));
    body.num(record.rates.len() as u64);
    for (lane, class, nanos) in &record.rates {
        body.text(lane);
        body.text(class);
        if record.version != AmendmentVersion::V1 {
            body.num(u64::from(nanos.is_some()));
        }
        body.num(nanos.unwrap_or(0));
    }
    body.text(&record.operator_fingerprint);
    body.bytes(&record.reason_hash);
    body.text(&record.principal);
    body.text(&record.dual_control);
    body.bytes(&record.signed_payload);
    body.text(&record.signature);
    Ok(body.finish())
}

#[cfg(test)]
#[must_use]
pub(crate) fn amendment_from_body(body: &[u8]) -> Option<AmendmentRecord> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        #[cfg(test)]
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            Some(head)
        }
        #[cfg(test)]
        fn num(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        #[cfg(test)]
        fn figure(&mut self) -> Option<i128> {
            Some(i128::from_le_bytes(self.take(16)?.try_into().ok()?))
        }
        #[cfg(test)]
        fn bytes(&mut self) -> Option<&'a [u8]> {
            let len = usize::try_from(self.num()?).ok()?;
            self.take(len)
        }
        #[cfg(test)]
        fn text(&mut self) -> Option<String> {
            String::from_utf8(self.bytes()?.to_vec()).ok()
        }
    }
    let mut r = Reader(body);
    let version = match r.text()?.as_str() {
        AMENDMENT_RECORD_TAG => AmendmentVersion::V4,
        AMENDMENT_RECORD_TAG_V3 => AmendmentVersion::V3,
        AMENDMENT_RECORD_TAG_V2 => AmendmentVersion::V2,
        AMENDMENT_RECORD_TAG_V1 => AmendmentVersion::V1,
        _ => return None,
    };
    let effective_from = r.num()?;
    let has_until = r.num()?;
    let until = r.num()?;
    let amended_at_ms = r.num()?;
    if has_until > 1 || has_until == 0 && until != 0 {
        return None;
    }
    let sealed_over = match version {
        AmendmentVersion::V4 => Some(crate::root::kernel::CorrectionBase::Key {
            key: busbar_kernel_ledger::cost::EntryKey::from_slice(r.bytes()?)?,
            card_digest: r.bytes()?.try_into().ok()?,
        }),
        AmendmentVersion::V3 => Some(crate::root::kernel::CorrectionBase::LegacyOrdinal {
            seq: busbar_kernel_ledger::cost::HistorySeq(r.num()?),
            card_digest: r.bytes()?.try_into().ok()?,
        }),
        AmendmentVersion::V1 | AmendmentVersion::V2 => None,
    };
    let sealed_fee = i64::try_from(r.figure()?).ok()?;
    let n = r.num()?;
    let mut rates = Vec::new();
    for _ in 0..n {
        let (lane, class) = (r.text()?, r.text()?);
        let priced = if version == AmendmentVersion::V1 {
            1
        } else {
            r.num()?
        };
        let nanos = r.num()?;
        let nanos = match priced {
            0 => None,
            1 => Some(nanos),
            _ => return None,
        };
        rates.push((lane, class, nanos));
    }
    let record = AmendmentRecord {
        version,
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

pub(crate) struct AmendmentJournal {
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
    pub(crate) fn new(
        book: Arc<Mutex<crate::root::durability::Durability>>,
        token: Grant<busbar_contract::caps::DurableWrite>,
    ) -> Self {
        AmendmentJournal { book, token }
    }

    #[cfg(test)]
    pub(crate) async fn record(
        &self,
        record: &AmendmentRecord,
        wall_secs: u64,
    ) -> Result<(), busbar_core_admin::GovernanceError> {
        let (sequence, _) = self.seal_policy(amendment_body(record)?, wall_secs)?;
        self.acked(sequence)
            .await
            .map_err(|_| busbar_core_admin::GovernanceError::Store)
    }

    pub(crate) async fn admit(&self) -> Result<(), String> {
        let journal = Arc::clone(&self.book.lock().unwrap_or_else(|p| p.into_inner()).journal);
        journal.flush().await.map_err(|error| format!("{error:?}"))
    }

    pub(crate) async fn acked(&self, node_seq: u64) -> Result<(), String> {
        let journal = Arc::clone(&self.book.lock().unwrap_or_else(|p| p.into_inner()).journal);
        if node_seq >= journal.next_seq() {
            return Err("the requested journal record has not been staged".into());
        }
        journal.flush().await.map_err(|error| format!("{error:?}"))
    }

    pub(crate) fn seal_policy(
        &self,
        body: Vec<u8>,
        wall_secs: u64,
    ) -> Result<(u64, [u8; 32]), busbar_core_admin::GovernanceError> {
        let entry = busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Policy, body)
            .at(wall_secs, 0);
        let journal = Arc::clone(&self.book.lock().unwrap_or_else(|p| p.into_inner()).journal);
        // The grant is held by this trusted root facade; staging reserves originals
        // only. acked must confirm their native publication before durable success.
        let _capability = &self.token;
        let run = journal
            .stage_run(&[entry])
            .map_err(|_| busbar_core_admin::GovernanceError::Store)?;
        let records = busbar_kernel_wal::decode_run(run.records())
            .map_err(|_| busbar_core_admin::GovernanceError::Store)?;
        let sealed = records
            .last()
            .ok_or(busbar_core_admin::GovernanceError::Store)?;
        Ok((sealed.node_seq, sealed.hash))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn sealed_through(&self) -> u64 {
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

/// The correction's canonical bytes, as the policy journal keeps them. The reason is named by its
/// SHA-256 (`reason_sha256`), never its text: the API keeps the hash, not the operator's words.
fn canonical_amend_payload(obj: &busbar_contract::json::Map) -> Vec<u8> {
    use busbar_contract::json::{self, JsonValueTrait};
    let mut payload = String::from("busbar/amend-rate-history/v2\n");

    for key in ["effective_from", "effective_until", "per_request_fee"] {
        push_payload_field(&mut payload, key, obj.get(&key));
    }
    let reason = obj
        .get(&"reason")
        .and_then(json::Value::as_str)
        .unwrap_or_default();
    let reason_sha256 = json::Value::from(
        hex::encode(busbar_contract::abi::sdk::digest::sha256(reason.as_bytes())).as_str(),
    );
    push_payload_field(&mut payload, "reason_sha256", Some(&reason_sha256));
    push_payload_field(&mut payload, "rates", obj.get(&"rates"));
    payload.into_bytes()
}

fn push_payload_field(
    payload: &mut String,
    key: &str,
    value: Option<&busbar_contract::json::Value>,
) {
    payload.push_str(key);
    payload.push('=');
    let null = busbar_contract::json::Value::new();
    let value = value.unwrap_or(&null);
    payload.push_str(&busbar_contract::json::to_string(value).unwrap_or_default());
    payload.push('\n');
}

async fn render_ledger_view(
    verb: KernelVerb,
    view: &dyn LedgerView,
) -> Result<Vec<u8>, busbar_core_admin::GovernanceError> {
    let priced = || async {
        view.priced().await.map_err(|why| {
            tracing::warn!(why = %why, "a ledger view could not read the ledger's counts");
            busbar_core_admin::GovernanceError::Store
        })
    };
    Ok(match verb {
        KernelVerb::GetLedgerTotals => render_totals(&priced().await?)
            .map_err(|_| busbar_core_admin::GovernanceError::Store)?
            .into_bytes(),

        KernelVerb::GetLedgerCheckpoints => b"{\"checkpoints\":[]}".to_vec(),
        KernelVerb::GetLedgerReconciliation => render_reconciliation(&priced().await?).into_bytes(),

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
pub(crate) struct AdminWalk {
    admission: Option<busbar_kernel::inbound::RequestAdmission>,
    effect_context: Option<busbar_kernel::auth::effect::Context>,
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
    execution: Option<Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
    answer: Option<AdminAnswer>,
}

impl AdminWalk {
    #[must_use]
    pub(crate) fn new(request: AdminRequest) -> Self {
        AdminWalk {
            admission: None,
            effect_context: None,
            request,
            verb: None,
            granted: None,
            listed: None,
            principal: None,
            claim: None,
            execution: None,
            answer: None,
        }
    }
}

pub(crate) type AdminDoorFuture =
    busbar_plugin_abi::host_side::caller::BoxFut<'static, busbar_kernel::auth::AdminVerdict>;
pub(crate) type AdminDoorFn = Arc<dyn Fn(&AdminRequest) -> AdminDoorFuture + Send + Sync>;

#[cfg(test)]
pub(crate) fn open_door() -> AdminDoorFn {
    Arc::new(|_: &AdminRequest| {
        Box::pin(std::future::ready(busbar_kernel::auth::AdminVerdict::from(
            busbar_kernel::auth::AdminDoor::Open,
        )))
    })
}

/// A test door answering each presented credential (`None` = none presented) through `f`.
#[cfg(test)]
pub(crate) fn door_of(
    f: impl Fn(Option<&str>) -> busbar_kernel::auth::AdminDoor + Send + Sync + 'static,
) -> AdminDoorFn {
    Arc::new(move |request: &AdminRequest| {
        Box::pin(std::future::ready(f(request.credential()).into()))
    })
}

/// A test door that identifies exactly one credential as `id` and denies everything else; the
/// operator principal is granted `Full`, any other identity no scope.
#[cfg(test)]
pub(crate) fn door_identifying(token: &'static str, id: &'static str) -> AdminDoorFn {
    door_of(move |credential| {
        if credential != Some(token) {
            return busbar_kernel::auth::AdminDoor::Denied;
        }
        let grants = if id == busbar_kernel::config::operator_principal_id() {
            busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full)
        } else {
            busbar_contract::authz::Grants::default()
        };
        busbar_kernel::auth::AdminDoor::Identified(
            busbar_contract::auth::Principal::from_id(id),
            grants,
        )
    })
}

pub(crate) type EffectAdmission = Arc<
    dyn for<'a> Fn(
            &'a busbar_kernel::auth::effect::Context,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            busbar_kernel::config::transaction::EffectGuard,
                            busbar_kernel::config::transaction::TxnError,
                        >,
                    > + Send
                    + 'a,
            >,
        > + Send
        + Sync,
>;

pub(crate) struct AdminBinding {
    pub effect_admission: Option<EffectAdmission>,
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

    pub mutations: Arc<busbar_kernel::ratelimit::MutationLimiter>,
}

impl std::fmt::Debug for AdminBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminBinding").finish_non_exhaustive()
    }
}

impl AdminBinding {
    #[must_use]
    pub(crate) fn new(dispatch: Arc<dyn AdminDispatch>, door: AdminDoorFn) -> Self {
        AdminBinding {
            effect_admission: None,
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
            mutations: Arc::new(busbar_kernel::ratelimit::MutationLimiter::new()),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_pools(mut self, pools: PoolKnown) -> Self {
        self.pools = pools;
        self
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ledger_view(mut self, ledger: Arc<dyn LedgerView>) -> Self {
        self.ledger = ledger;
        self
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_audit_view(mut self, audit: Arc<dyn AuditView>) -> Self {
        self.audit = Some(audit);
        self
    }
}

#[must_use]
pub(crate) fn kernel_verb(resolved: &ResolvedVerb) -> Option<KernelVerb> {
    busbar_core_admin::verb::verb_for(resolved.method, resolved.template)
}

pub(crate) async fn decide(
    units: &crate::root::kernel::ProductionUnits,
    walk: &mut AdminWalk,
) -> Outcome {
    use busbar_contract::caps::StepName;
    let at = |step: StepName| move |reason: ReasonCode| Outcome::Refused(step, reason);
    let ran = match decode(walk).map_err(at(StepName::Decode)) {
        Ok(()) => authenticate(&units.admin, &units.auth_bindings, walk)
            .await
            .map_err(at(StepName::Authenticate)),
        Err(ended) => Err(ended),
    }
    .and_then(|principal| verify(walk, &principal).map_err(at(StepName::Verify)))
    .and_then(|()| approve(walk).map_err(at(StepName::Approve)))
    .and_then(|()| admit(walk).map_err(at(StepName::Admit)));
    let ran = match ran {
        Ok(()) => claim(walk).await.map_err(at(StepName::Authenticate)),
        Err(ended) => Err(ended),
    };
    let ran = match ran {
        Ok(()) => route(&units.admin, units.store.clone(), &units.admin_token, walk)
            .await
            .map_err(|reason| Outcome::Failed(StepName::Route, reason)),
        Err(ended) => Err(ended),
    };
    match ran {
        Ok(()) => Outcome::Completed,
        Err(ended) => ended,
    }
}

pub(crate) fn decode(walk: &mut AdminWalk) -> Result<(), ReasonCode> {
    match busbar_core_admin::admin_codec::verbs::resolve(walk.request.method(), walk.request.path())
    {
        None => Err(ReasonCode::DecodeFailed),
        Some(resolved) => {
            walk.verb = Some(resolved);
            Ok(())
        }
    }
}

pub(crate) async fn authenticate(
    binding: &AdminBinding,
    bindings: &crate::root::auth_bindings::AuthBindings,
    walk: &mut AdminWalk,
) -> Result<PrincipalId, ReasonCode> {
    let request = &walk.request;
    let revoked = || {
        bindings
            .revocations()
            .zip(request.credential())
            .is_some_and(|(set, credential)| set.is_revoked(credential))
    };
    let verdict = match &walk.admission {
        Some(admission) => admission.admin_verdict(),
        None => (binding.door)(request).await,
    };
    let headers = request
        .http_headers()
        .map_err(|_| ReasonCode::DecodeFailed)?;
    walk.effect_context = Some(walk.admission.as_ref().map_or_else(
        || {
            busbar_kernel::auth::effect::Context::new(
                request.method(),
                request.path(),
                headers,
                &verdict.door,
            )
        },
        busbar_kernel::inbound::RequestAdmission::effect_context,
    ));
    let (principal, grants, listed) = match verdict.door {
        busbar_kernel::auth::AdminDoor::Open => (
            busbar_kernel_identity::principal::ANONYMOUS.to_string(),
            busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
            None,
        ),
        busbar_kernel::auth::AdminDoor::Identified(principal, grants) => {
            if walk.admission.is_none() && revoked() {
                return Err(ReasonCode::Revoked);
            }
            (principal.id, grants, None)
        }
        busbar_kernel::auth::AdminDoor::Listed(principal, grants, list) => {
            if walk.admission.is_none() && revoked() {
                return Err(ReasonCode::Revoked);
            }
            (principal.id, grants, Some(list))
        }
        busbar_kernel::auth::AdminDoor::Denied | busbar_kernel::auth::AdminDoor::Rejected(_) => {
            return Err(ReasonCode::Unauthenticated)
        }
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

pub(crate) async fn claim(walk: &mut AdminWalk) -> Result<(), ReasonCode> {
    if let Some(admission) = &walk.admission {
        if !admission.claim_admin_replay().await {
            return Err(ReasonCode::Unauthenticated);
        }
        if let Some(execution) = admission.admin_execution() {
            if let Some(context) = &mut walk.effect_context {
                context
                    .attach_execution(execution.clone())
                    .map_err(|_| ReasonCode::Unauthenticated)?;
            }
            walk.execution = Some(execution);
        }
        return Ok(());
    }
    if let Some(pending) = walk.claim.take() {
        let execution = Arc::new(
            pending
                .complete_admin()
                .await
                .map_err(|_| ReasonCode::Unauthenticated)?,
        );
        if let Some(context) = &mut walk.effect_context {
            context
                .attach_execution(execution.clone())
                .map_err(|_| ReasonCode::Unauthenticated)?;
        }
        walk.execution = Some(execution);
    }
    Ok(())
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
    let needed = busbar_kernel::admin::scope::admin_required_scope(
        walk.request.method(),
        walk.request.path(),
    );
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
    walk.verb
        .as_ref()
        .and_then(kernel_verb)
        .map(|_| ())
        .ok_or(ReasonCode::NoDestination)
}

pub(crate) async fn route(
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

    let dispatch: Arc<dyn AdminDispatch> = if walk.admission.is_some() || walk.execution.is_some() {
        Arc::new(AdmittedDispatch {
            inner: Arc::clone(&binding.dispatch),
            admission: walk.admission.clone(),
            execution: walk.execution.clone(),
        })
    } else {
        Arc::clone(&binding.dispatch)
    };

    if mints_its_own_identity(verb) {
        walk.answer = Some(dispatch.execute(verb, request).await);
        return Ok(());
    }

    let actor = actor_of(walk);

    let verbs = busbar_core_admin::Verbs::new(
        CoreGovernance::new(
            dispatch,
            Arc::clone(&binding.ledger),
            binding.audit.clone(),
            verb,
            request.clone(),
        )
        .fenced(
            walk.effect_context.clone(),
            binding.effect_admission.clone(),
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
        Arc::clone(&binding.mutations),
    );

    let answer = if let Some(recovery) = recovery_verb(verb) {
        // A recovery verb is a durable write like every other mutating verb: current authority
        // must still admit it, and the guard is held until the store call resolves.
        let _effect = match walk
            .effect_context
            .as_ref()
            .zip(binding.effect_admission.as_ref())
        {
            Some((context, admit)) => match admit(context).await {
                Ok(guard) => Some(guard),
                Err(_) => {
                    walk.answer = Some(admin_mount::error_answer_with_message(
                        403,
                        "forbidden",
                        "current authority does not admit this effect",
                    ));
                    return Ok(());
                }
            },
            None => None,
        };
        let ran = match recovery {
            RecoveryVerb::ChainBreak => {
                verbs
                    .chain_break(admin, &actor, granted, request.at())
                    .await
            }
            RecoveryVerb::StoreRestore => {
                let backup_ref = backup_ref_of(request.body()).ok_or(ReasonCode::DecodeFailed)?;
                verbs
                    .store_restore(admin, &actor, granted, request.at(), &backup_ref)
                    .await
            }
        };
        ran.map(|()| applied_answer())
    } else {
        verbs
            .execute(verb, admin, &actor, granted, request.at(), request.body())
            .await
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
        return unresolved_facts(Some(walk.request.method()), ended);
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
        let outcome = if kernel_verb(resolved) == Some(KernelVerb::Adjust) {
            // Only the host-owned adjustment handler constructs this response. Never consult
            // incoming request headers or a plugin's response to classify another operation.
            adjustment_audit_outcome(walk.answer.as_ref(), applied)
        } else if applied {
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

fn adjustment_audit_outcome(answer: Option<&AdminAnswer>, applied: bool) -> &'static str {
    let effect = answer.and_then(|answer| {
        answer
            .headers
            .iter()
            .find(|(name, _)| name == "x-busbar-adjust-effect")
            .map(|(_, value)| value.as_str())
    });
    match effect {
        Some("unknown") => busbar_kernel::audit_ring::OUTCOME_DEGRADED,
        Some("applied") => busbar_kernel::audit_ring::OUTCOME_APPLIED,
        Some("not_applied") => busbar_kernel::audit_ring::OUTCOME_REJECTED,
        _ if applied => busbar_kernel::audit_ring::OUTCOME_APPLIED,
        _ => busbar_kernel::audit_ring::OUTCOME_REJECTED,
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
pub(crate) use adjust::live_adjuster;
pub(crate) mod bound;
pub(crate) mod records;
pub(crate) use bound::{
    live_admin_door, live_planes, live_records, live_replay_store, no_planes, no_trust,
    PlaneLookup, PlaneRecordSink, TrustDesk,
};

#[cfg(test)]
#[path = "tests/units_admin.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/admin_unit_records.rs"]
mod admin_unit_records;

#[cfg(test)]
#[path = "tests/records.rs"]
mod records_tests;

#[cfg(test)]
#[path = "tests/ledger_recovery_actual.rs"]
mod ledger_recovery_actual;

/// Test transport boundary: use actual process admission and gathering, never a fabricated lease.
/// These service fixtures exercise the Admin consumer, not native socket/physical admission.
#[cfg(test)]
pub(crate) async fn charged_http_for_test(
    request: axum::http::Request<axum::body::Body>,
) -> axum::http::Request<axum::body::Body> {
    use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    use busbar_kernel::limits::{
        input_body,
        process_admission::{AdmissionClass, ProcessAdmission},
    };
    let process = ProcessAdmission::new(2);
    let lease = process.try_enter(AdmissionClass::Operator).unwrap();
    let (mut parts, body) = request.into_parts();
    let bytes = input_body::gather(body, &lease, 1 << 24).await.unwrap();
    let snapshot = ChargedRequestSnapshot::capture_header_map(
        SnapshotInput {
            method: parts.method.as_str(),
            path: parts.uri.path(),
            query: parts.uri.query().unwrap_or(""),
            query_present: parts.uri.query().is_some(),
            authority: parts
                .uri
                .authority()
                .map_or("", |authority| authority.as_str()),
            headers: &parts.headers,
            peer: "",
            tls_peer_cert: &[],
            body: &bytes,
            now_s: busbar_kernel::store::now(),
        },
        &lease,
    )
    .unwrap();
    drop(bytes);
    parts.extensions.insert(lease);
    parts.extensions.insert(snapshot.clone());
    axum::http::Request::from_parts(parts, axum::body::Body::from(snapshot.body_bytes()))
}
