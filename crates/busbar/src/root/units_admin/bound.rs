// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord};
use busbar_core_admin::GovernanceError;
use busbar_kernel::host_services::{KernelServices, TrustRefused};
use busbar_kernel::trust::book::{KeyRow, Ruling};

use super::{AdminAnswer, AmendmentJournal, AuditView, LedgerView};

pub type PlaneLookup = Arc<dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync>;

#[must_use]
pub fn no_planes() -> PlaneLookup {
    Arc::new(|_| None)
}

pub type PlaneRecordSink = Arc<
    dyn Fn(&PlaneRecord) -> Result<(), busbar_contract::store_calls::StoreFailure> + Send + Sync,
>;

/// The operation already sealed, or submitted with an unknown Store outcome. These bytes and
/// metadata belong to the first request; reconciliation must never reconstruct them from a retry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum EffectReceipt {
    CommitUpgrade {
        node: u64,
        seq: u64,
        hash: [u8; 32],
        body: Vec<u8>,
    },
    PlaneRecordWrite {
        record: PlaneRecord,
    },
}

/// Whether an answered write definitely did nothing, completed, or still owns an effect receipt.
#[derive(Debug, Clone)]
enum EffectDisposition {
    Unapplied,
    Applied,
    /// A sealed journal operation is waiting for acknowledgement.
    Pending(EffectReceipt),
    /// Store submission crossed the boundary but its outcome is unknown.
    Unknown(EffectReceipt),
}

#[derive(Debug, Clone)]
pub(crate) struct EffectAnswer {
    pub(crate) answer: AdminAnswer,
    disposition: EffectDisposition,
}

impl EffectAnswer {
    pub(crate) fn applied(answer: AdminAnswer) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Applied,
        }
    }

    fn unapplied(answer: AdminAnswer) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Unapplied,
        }
    }

    fn pending(answer: AdminAnswer, receipt: EffectReceipt) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Pending(receipt),
        }
    }

    fn unknown(answer: AdminAnswer, receipt: EffectReceipt) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Unknown(receipt),
        }
    }
}

impl std::ops::Deref for EffectAnswer {
    type Target = AdminAnswer;

    fn deref(&self) -> &AdminAnswer {
        &self.answer
    }
}

fn refused_effect(status: u16, code: &str, message: &str) -> EffectAnswer {
    EffectAnswer::unapplied(refused(status, code, message))
}

pub type TrustDesk = Arc<dyn Fn() -> Option<Arc<KernelServices>> + Send + Sync>;

#[must_use]
pub fn no_trust() -> TrustDesk {
    Arc::new(|| None)
}

pub const COMMIT_UPGRADE_RECORD_TAG: &str = "busbar/commit-upgrade/v1";

pub const RUNNING_RELEASE: &str = env!("CARGO_PKG_VERSION");

fn refused(status: u16, code: &str, message: &str) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(code, message).into_bytes(),
    }
}

pub(crate) fn journal_unavailable(why: &str) -> AdminAnswer {
    refused(503, "service_unavailable", why)
}

fn answer(value: &serde_json::Value) -> Result<AdminAnswer, GovernanceError> {
    serde_json::to_vec(value)
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store)
}

fn query_param<'t>(target: &'t str, name: &str) -> Option<&'t str> {
    let (_, query) = target.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

pub(crate) fn verify_effect(
    ledger: &dyn LedgerView,
    audit: Option<&dyn AuditView>,
    journal: Option<&busbar_kernel_audit::amend::NodeAmendments>,
) -> Result<AdminAnswer, GovernanceError> {
    let priced = ledger.priced().map_err(|why| {
        tracing::warn!(why = %why, "verify could not read the ledger's counts");
        GovernanceError::Store
    })?;
    let identity_holds = priced.refused.is_empty();
    let mut findings: Vec<String> = priced
        .refused
        .iter()
        .map(|row| {
            format!(
                "refused counts: {} in the window opening at {}: {}",
                row.bucket, row.day, row.refusal
            )
        })
        .collect();

    if let Some(audit) = audit {
        findings.extend(
            audit
                .restart_findings()
                .into_iter()
                .map(|finding| format!("restart: {finding}")),
        );
    }

    if let Some(Err(broken)) = journal.map(crate::root::durability::verify_held) {
        findings.push(format!("amendment chain: {broken}"));
    }
    if let Some(audit) = audit {
        findings.extend(
            audit
                .retained_audit_findings()
                .into_iter()
                .map(|finding| format!("audit chain: {finding}")),
        );

        findings.extend(
            audit
                .stored_chain_findings()
                .into_iter()
                .map(|finding| format!("stored chain: {finding}")),
        );
    }
    answer(&serde_json::json!({
        "checkpoints": 0,
        "since": null,
        "book_verified": false,
        "findings": findings,
        "identity_holds": identity_holds,
        "discrepancies": 0,
        "ok": findings.is_empty() && identity_holds,
    }))
}

pub(crate) fn plane_facts_effect(
    target: &str,
    planes: &dyn Fn(&str) -> Option<PlaneDeclaration>,
) -> Result<AdminAnswer, GovernanceError> {
    let Some(key) = query_param(target, "plane").filter(|k| !k.is_empty()) else {
        return Ok(refused(400, "invalid_request", "plane is required"));
    };
    let Some(decl) = planes(key) else {
        return Ok(refused(
            404,
            "not_found",
            &format!("plane `{key}` not found"),
        ));
    };
    answer(&serde_json::json!({
        "plane": decl.key,
        "fallback": decl.fallback,
        "config_section": decl.config_section,
        "owned_config_sections": decl.owned_config_sections,
        "scope_kinds": decl.scope_kinds,
        "subject_noun": decl.subject_noun,
        "admin_noun": decl.admin_noun,
        "audit_kind": decl.audit_kind,
        "billable_classes": decl
            .billable_classes
            .iter()
            .map(|c| serde_json::json!({"class": c.class, "family": c.family}))
            .collect::<Vec<_>>(),
        "fee_units": decl.fee_units,
        "metric_families": decl
            .metric_families
            .iter()
            .map(|m| serde_json::json!({"name": m.name, "kind": m.kind, "label_keys": m.label_keys}))
            .collect::<Vec<_>>(),
        "served_op_classes": decl
            .served_op_classes
            .iter()
            .map(|s| serde_json::json!({"op": s.op.as_str(), "name": s.name}))
            .collect::<Vec<_>>(),
        "record_kinds": decl.record_kinds,
    }))
}

pub(crate) fn plane_record_write_effect(
    body: &[u8],
    at: u64,
    planes: &dyn Fn(&str) -> Option<PlaneDeclaration>,
    sink: Option<&PlaneRecordSink>,
) -> Result<EffectAnswer, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let text = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
    };
    let Some(plane) = text("plane") else {
        return Ok(refused_effect(400, "invalid_request", "plane is required"));
    };
    let Some(kind) = text("kind") else {
        return Ok(refused_effect(400, "invalid_request", "kind is required"));
    };
    let Some(id) = text("id") else {
        return Ok(refused_effect(400, "invalid_request", "id is required"));
    };
    let row = match obj.get("body") {
        None | Some(serde_json::Value::Null) => {
            return Ok(refused_effect(400, "invalid_request", "body is required"));
        }
        Some(row) => row,
    };
    let parent = match obj.get("parent") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(p)) if !p.trim().is_empty() => Some(p.clone()),
        Some(_) => {
            return Ok(refused_effect(
                400,
                "invalid_request",
                "parent must be a non-empty string or null",
            ));
        }
    };
    let terminal = match obj.get("terminal") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => {
            return Ok(refused_effect(
                400,
                "invalid_request",
                "terminal must be a boolean",
            ));
        }
    };
    let Some(decl) = planes(plane) else {
        return Ok(refused_effect(
            404,
            "not_found",
            &format!("plane `{plane}` not found"),
        ));
    };

    if !busbar_contract::plane::declares_record_kind(&decl, kind) {
        return Ok(refused_effect(
            403,
            "forbidden",
            &format!("plane `{plane}` may not write record kind `{kind}`"),
        ));
    }

    if busbar_kernel::store::plane_view::KERNEL_RECORD_KINDS.contains(&kind) {
        busbar_kernel::diagnostics::diag_warn!(
            busbar_kernel::diagnostics::PLANE_RECORD_WRITE_KERNEL_KIND,
            plane = %plane,
            kind = %kind,
            "an admin plane record write named a record kind the kernel keeps its own records \
             under: refused, nothing written"
        );
        return Ok(refused_effect(
            403,
            "forbidden",
            &format!(
                "record kind `{kind}` is kept by the kernel: plane `{plane}` may not write it"
            ),
        ));
    }

    let Some(owned) = busbar_kernel::store::plane_view::plane_owned_kind(plane, kind) else {
        return Ok(refused_effect(
            400,
            "invalid_request",
            "plane and kind must not hold a control character",
        ));
    };
    let sink = sink.ok_or(GovernanceError::Store)?;
    let record = PlaneRecord {
        kind: owned,
        id: id.to_string(),
        parent,
        seq: 0,
        ts: at,
        disposition: if terminal {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: serde_json::to_vec(row).map_err(|_| GovernanceError::Validation)?,
    };

    let applied = answer(&serde_json::json!({
        "plane": plane,
        "kind": kind,
        "id": record.id,
        "parent": record.parent,
        "terminal": terminal,
        "written_at": at,
    }))?;
    use busbar_contract::store_calls::StoreFailure;
    match sink(&record) {
        Ok(()) => Ok(EffectAnswer::applied(applied)),
        Err(
            why @ (StoreFailure::Refused(_) | StoreFailure::Overloaded | StoreFailure::Conflict),
        ) => Ok(EffectAnswer::unapplied(journal_unavailable(
            &why.to_string(),
        ))),
        Err(why @ (StoreFailure::Failed(_) | StoreFailure::Fault(_))) => {
            tracing::error!(reason = %why, "the plane record write has an unknown outcome; its exact record remains in custody");
            Ok(EffectAnswer::unknown(
                journal_unavailable("the store did not acknowledge this record write; its outcome is unknown; do not re-submit"),
                EffectReceipt::PlaneRecordWrite { record },
            ))
        }
    }
}

pub(crate) fn commit_upgrade_effect(
    body: &[u8],
    at: u64,
    principal: &str,
    journal: Option<&AmendmentJournal>,
) -> Result<EffectAnswer, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(version) = obj
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(refused_effect(
            400,
            "invalid_request",
            "version is required",
        ));
    };
    if version != RUNNING_RELEASE {
        return Ok(refused_effect(
            409,
            "conflict",
            &format!("this node runs `{RUNNING_RELEASE}`; it cannot commit `{version}`"),
        ));
    }
    let journal = journal.ok_or(GovernanceError::Store)?;
    if let Err(why) = journal.admit() {
        return Ok(EffectAnswer::unapplied(journal_unavailable(&why)));
    }
    let mut record = busbar_kernel_wal::BodyWriter::new();
    record.text(COMMIT_UPGRADE_RECORD_TAG);
    record.text(version);
    record.num(at);
    record.text(principal);
    let body = record.finish();
    let node = journal
        .book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .journal
        .node();
    let (node_seq, hash) = journal.seal_policy(body.clone(), at)?;
    let receipt = EffectReceipt::CommitUpgrade {
        node,
        seq: node_seq,
        hash,
        body,
    };
    if let Err(why) = journal.acked(node_seq) {
        return Ok(EffectAnswer::pending(
            journal_unavailable(&format!(
            "the commit is sealed at journal position {node_seq} and not yet kept by the store: \
             {why}; do not re-submit"
        )),
            receipt,
        ));
    }
    match answer(&serde_json::json!({
        "committed": version,
        "committed_at": at,
        "seq": node_seq,
        "hash": hex::encode(hash),
    })) {
        Ok(answer) => Ok(EffectAnswer::applied(answer)),
        Err(_) => Ok(EffectAnswer::pending(
            journal_unavailable(
                "the commit is sealed but its answer could not be encoded; do not re-submit",
            ),
            receipt,
        )),
    }
}

fn trust_row(row: &KeyRow) -> serde_json::Value {
    serde_json::json!({
        "key": row.key(),
        "instance": row.instance,
        "counterparty": row.counterparty,
        "item": row.item,
        "state": row.state.word(),
        "approved": row.approved,
        "seen": row.seen,
    })
}

pub(crate) fn trust_list_effect(desk: &TrustDesk) -> Result<AdminAnswer, GovernanceError> {
    let rows = desk().map(|k| k.trust_rows()).unwrap_or_default();
    answer(&serde_json::json!({
        "keys": rows.iter().map(trust_row).collect::<Vec<_>>(),
    }))
}

pub(crate) fn trust_decide_effect(
    body: &[u8],
    ruling: Ruling,
    desk: &TrustDesk,
) -> Result<AdminAnswer, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(key) = obj
        .get("key")
        .and_then(serde_json::Value::as_str)
        .filter(|k| !k.trim().is_empty())
    else {
        return Ok(refused(400, "invalid_request", "key is required"));
    };
    let not_found = || {
        Ok(refused(
            404,
            "not_found",
            &format!("trust key `{key}` not found"),
        ))
    };
    let Some(kernel) = desk() else {
        return not_found();
    };
    match kernel.trust_rule(key, ruling) {
        Ok(row) => answer(&trust_row(&row)),
        Err(TrustRefused::NoSuchKey) => not_found(),
        Err(TrustRefused::NothingSighted) => Ok(refused(
            409,
            "conflict",
            &format!("trust key `{key}` was never sighted"),
        )),

        Err(TrustRefused::Stale) => Ok(refused(
            409,
            "conflict",
            &format!("trust key `{key}` changed or has another decision in progress; retry"),
        )),

        Err(TrustRefused::Unverified) => Ok(refused(
            409,
            "conflict",
            &format!(
                "trust key `{key}` was last sighted unverified: its document failed \
                 verification, so there is nothing to approve"
            ),
        )),
        Err(TrustRefused::Rootless) => Ok(refused(
            409,
            "conflict",
            &format!("trust key `{key}` has no authenticity root"),
        )),
        Err(TrustRefused::Store(why)) => {
            tracing::error!(key = %key, error = %why, "a trust ruling could not be kept");
            Err(GovernanceError::Store)
        }
    }
}

#[must_use]
pub fn live_planes(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneLookup {
    Arc::new(move |key: &str| {
        let snapshot = app.load();
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .map(|decl| decl.declaration)
            .find(|decl| decl.key == key && snapshot.plane_configured(decl))
    })
}

#[must_use]
pub fn live_admin_door(app: Arc<busbar_kernel::state::AppHandle>) -> super::AdminDoorFn {
    Arc::new(move |request: &super::AdminRequest| {
        let headers: axum::http::HeaderMap = (request.headers.iter())
            .filter_map(|(name, value)| Some((name.parse().ok()?, value.parse().ok()?)))
            .collect();
        let snapshot = app.snapshot();
        busbar_kernel::auth::admin_verdict(&snapshot, &request.method, &request.path, &headers)
    })
}

#[must_use]
pub fn live_records(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneRecordSink {
    Arc::new(move |record: &PlaneRecord| {
        let snapshot = app.load();
        let calls = snapshot
            .governance
            .as_ref()
            .and_then(|gov| gov.store_calls())
            .ok_or_else(|| {
                busbar_contract::store_calls::StoreFailure::Refused(
                    "no record store is configured".to_string(),
                )
            })?;
        crate::root::durability::off_runtime(|| {
            crate::root::durability::wait_for(calls.upsert_plane_record(record.view()))
        })
    })
}

/// THE REPLAY CACHE the two Q71(2) writes share (contract D-3): per `(actor, "<verb>:<key>")`, the
/// SHA-256 of the body the first call carried and the answer it produced. Unresolved receipts
/// have separate custody: the ordinary answer TTL cannot release an effect still owed or unknown.
#[derive(Default)]
pub struct ReplayCache {
    answers: busbar_core_admin::idempotency::IdempotencyCache<ReplayValue>,
    retained: Mutex<HashMap<(String, String), HeldReplay>>,
}

impl ReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn retain(&self, key: (String, String), held: HeldReplay) {
        let previous = self
            .retained
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, held);
        drop(previous);
    }
}

#[derive(Clone)]
struct ReplayValue {
    digest: [u8; 32],
    answer: AdminAnswer,
    receipt: Option<EffectReceipt>,
}

#[derive(Clone)]
struct HeldReplay {
    value: ReplayValue,
    settlement: Option<Arc<HeldSettlement>>,
}

struct HeldSettlement {
    store: Arc<dyn busbar_contract::records::RecordStore>,
    claim: busbar_core_admin::idempotency::durable::Claim,
    at: u64,
    settled: busbar_core_admin::idempotency::durable::Settled,
}

impl HeldSettlement {
    fn retry(&self) {
        if let Err(why) = busbar_core_admin::idempotency::durable::settle(
            &*self.store,
            &self.claim,
            self.at,
            &self.settled,
        ) {
            tracing::error!(reason = %why, "the store did not acknowledge the retained Idempotency-Key receipt; its original claim remains held");
        }
    }
}

impl HeldReplay {
    fn replay(&self, journal: Option<&AmendmentJournal>) -> AdminAnswer {
        if let Some(settlement) = &self.settlement {
            settlement.retry();
        }
        if let (
            Some(EffectReceipt::CommitUpgrade {
                node,
                seq,
                hash,
                body,
            }),
            Some(journal),
        ) = (&self.value.receipt, journal)
        {
            let chain = {
                let book = journal.book.lock().unwrap_or_else(|p| p.into_inner());
                (book.journal.node() == *node).then(|| book.chain_at())
            };
            if let Some(Ok(Ok(records))) = chain.map(|chain| chain.read()) {
                if records.iter().any(|record| {
                    record.node == *node
                        && record.node_seq == *seq
                        && record.hash == *hash
                        && record.class == busbar_kernel_wal::RecordClass::Policy
                        && record.body == *body
                }) {
                    let _acknowledged = journal.acked(*seq);
                }
            }
        }

        self.value.answer.clone()
    }
}

pub type ReplayStore =
    Arc<dyn Fn() -> Option<Arc<dyn busbar_contract::records::RecordStore>> + Send + Sync>;

#[must_use]
pub fn live_replay_store(app: Arc<busbar_kernel::state::AppHandle>) -> ReplayStore {
    Arc::new(move || app.load().governance.as_ref().map(|gov| gov.store()))
}

fn stored_answer(value: &ReplayValue) -> Vec<u8> {
    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&bytes[..len as usize]);
    }
    let answer = &value.answer;
    let mut out = Vec::with_capacity(32 + 6 + answer.body.len() + 64);
    out.extend_from_slice(&value.digest);
    out.extend_from_slice(&answer.status.to_be_bytes());
    let count = u32::try_from(answer.headers.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (name, value) in answer.headers.iter().take(count as usize) {
        push(&mut out, name.as_bytes());
        push(&mut out, value.as_bytes());
    }
    push(&mut out, &answer.body);
    if let Some(receipt) = &value.receipt {
        let receipt = serde_json::to_vec(receipt)
            .expect("an effect receipt contains only serializable strings, integers and bytes");
        push(&mut out, &receipt);
    }
    out
}

fn kept_answer(kept: &[u8]) -> Option<ReplayValue> {
    fn take<'b>(bytes: &'b [u8], cursor: &mut usize, n: usize) -> Option<&'b [u8]> {
        let end = cursor.checked_add(n)?;
        let slice = bytes.get(*cursor..end)?;
        *cursor = end;
        Some(slice)
    }
    fn pull<'b>(bytes: &'b [u8], cursor: &mut usize) -> Option<&'b [u8]> {
        let len = u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().ok()?);
        take(bytes, cursor, usize::try_from(len).ok()?)
    }
    let mut cursor = 0usize;
    let digest: [u8; 32] = take(kept, &mut cursor, 32)?.try_into().ok()?;
    let status = u16::from_be_bytes(take(kept, &mut cursor, 2)?.try_into().ok()?);
    let count = u32::from_be_bytes(take(kept, &mut cursor, 4)?.try_into().ok()?);
    let mut headers = Vec::new();
    for _ in 0..count {
        let name = String::from_utf8(pull(kept, &mut cursor)?.to_vec()).ok()?;
        let value = String::from_utf8(pull(kept, &mut cursor)?.to_vec()).ok()?;
        headers.push((name, value));
    }
    let body = pull(kept, &mut cursor)?.to_vec();
    let receipt = if cursor == kept.len() {
        None
    } else {
        Some(serde_json::from_slice(pull(kept, &mut cursor)?).ok()?)
    };
    if cursor != kept.len() {
        return None;
    }
    Some(ReplayValue {
        digest,
        answer: AdminAnswer {
            status,
            headers,
            body,
        },
        receipt,
    })
}

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub(crate) struct ReplayScope<'a> {
    pub verb: busbar_core_admin::KernelVerb,
    pub actor: &'a str,
}

pub(crate) fn replayable(
    cache: &ReplayCache,
    store: Option<&ReplayStore>,
    scope: ReplayScope<'_>,
    unit: &super::AdminRequest,
    body: &[u8],
    journal: Option<&AmendmentJournal>,
    effect: impl FnOnce() -> Result<EffectAnswer, GovernanceError>,
) -> Result<AdminAnswer, GovernanceError> {
    use busbar_core_admin::idempotency::Probe;

    let ReplayScope { verb, actor } = scope;
    let Some(header) = unit
        .headers
        .iter()
        .find(|(name, _)| name == IDEMPOTENCY_KEY_HEADER)
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
    else {
        return effect().map(|outcome| outcome.answer);
    };
    let name = busbar_core_admin::verb_name(verb).unwrap_or_default();
    let digest: [u8; 32] = busbar_contract::abi::sdk::digest::sha256(body);

    use busbar_core_admin::idempotency::durable::{self, Refused, Settled};

    let other_body = || {
        Ok(refused(
            409,
            "conflict",
            "this Idempotency-Key was already used with a different request body",
        ))
    };
    let in_flight = || {
        Ok(refused(
            409,
            "conflict",
            "a request with this Idempotency-Key is already in flight",
        ))
    };
    let key = (actor.to_string(), format!("{name}:{header}"));
    let held = cache
        .retained
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&key)
        .cloned();
    if let Some(held) = held {
        return if held.value.digest == digest {
            Ok(held.replay(journal))
        } else {
            other_body()
        };
    }
    match cache.answers.probe(key.clone(), unit.at) {
        Probe::Replay(value) if value.digest == digest => Ok(value.answer),
        Probe::Replay(_) => other_body(),
        Probe::InFlight => in_flight(),
        Probe::NoKey => effect().map(|outcome| outcome.answer),
        Probe::Reserved(mut reservation) => {
            let store = store.and_then(|store| store());
            let claim = match &store {
                Some(store) => match durable::claim_held(&**store, reservation.key(), unit.at) {
                    Ok(claim) => Some(claim),
                    Err(Refused::Answer(kept) | Refused::Retained(kept)) => {
                        return match kept_answer(&kept) {
                            Some(value) if value.digest == digest => {
                                if value.receipt.is_some() {
                                    let held = HeldReplay {
                                        value,
                                        settlement: None,
                                    };
                                    cache.retain(key, held.clone());
                                    reservation.in_flight();
                                    Ok(held.replay(journal))
                                } else {
                                    let answer = value.answer.clone();
                                    reservation.commit(value, unit.at);
                                    Ok(answer)
                                }
                            }
                            Some(_) => other_body(),
                            None => {
                                tracing::error!("the store keeps an Idempotency-Key's first answer in a form this node cannot read");
                                Ok(journal_unavailable(
                                    "the first answer to this Idempotency-Key cannot be read back; nothing was done",
                                ))
                            }
                        };
                    }
                    Err(Refused::Unavailable(why)) => {
                        tracing::error!(reason = %why, "an Idempotency-Key could not be claimed in the store");
                        return Ok(journal_unavailable(
                            "the store could not record this Idempotency-Key; nothing was done",
                        ));
                    }
                    Err(Refused::InFlight | Refused::Applied(_)) => {
                        return in_flight();
                    }
                },
                None => None,
            };

            reservation.in_flight();
            let (answer, settled) = match effect() {
                Ok(EffectAnswer {
                    answer,
                    disposition: EffectDisposition::Applied,
                }) => {
                    let value = ReplayValue {
                        digest,
                        answer: answer.clone(),
                        receipt: None,
                    };
                    let settled = Settled::Answer(stored_answer(&value));
                    reservation.commit(value, unit.at);
                    (Ok(answer), settled)
                }
                Ok(EffectAnswer {
                    answer,
                    disposition:
                        EffectDisposition::Pending(receipt) | EffectDisposition::Unknown(receipt),
                }) => {
                    let value = ReplayValue {
                        digest,
                        answer: answer.clone(),
                        receipt: Some(receipt),
                    };
                    let settled = Settled::Retained(stored_answer(&value));
                    let settlement = store.as_ref().zip(claim.as_ref()).map(|(store, claim)| {
                        Arc::new(HeldSettlement {
                            store: Arc::clone(store),
                            claim: claim.clone(),
                            at: unit.at,
                            settled: settled.clone(),
                        })
                    });
                    cache.retain(key, HeldReplay { value, settlement });
                    (Ok(answer), settled)
                }
                Ok(EffectAnswer {
                    answer,
                    disposition: EffectDisposition::Unapplied,
                }) => {
                    reservation.clear();
                    (Ok(answer), Settled::Released)
                }
                Err(error) => {
                    reservation.clear();
                    (Err(error), Settled::Released)
                }
            };
            if let (Some(store), Some(claim)) = (&store, &claim) {
                if let Err(why) = durable::settle(&**store, claim, unit.at, &settled) {
                    tracing::error!(reason = %why, "the store did not keep an Idempotency-Key's outcome; its original claim remains held");
                }
            }
            answer
        }
    }
}

#[cfg(test)]
#[path = "tests/bound_tests.rs"]
mod bound_tests;
