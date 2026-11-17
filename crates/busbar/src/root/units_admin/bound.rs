// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord};
use busbar_core_admin::GovernanceError;
use busbar_kernel::host_services::{KernelServices, TrustRefused};
use busbar_kernel::trust::book::{KeyRow, Ruling};

use super::{AdminAnswer, AmendmentJournal, AuditView, LedgerView};

pub(crate) type PlaneLookup = Arc<dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync>;

#[must_use]
pub(crate) fn no_planes() -> PlaneLookup {
    Arc::new(|_| None)
}

#[derive(Debug)]
pub(crate) enum PlaneWriteFailure {
    /// Native refusal or conflict proves this submission did not publish.
    Unapplied,
    /// The exact native attempt remains held; never replan it from the record.
    Unknown(Option<[u8; 16]>),
}

pub(crate) type PlaneRecordSink = Arc<
    dyn for<'a> Fn(
            &'a PlaneDeclaration,
            &'a PlaneRecord,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), PlaneWriteFailure>> + Send + 'a>,
        > + Send
        + Sync,
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
        #[serde(default)]
        pending: Option<[u8; 16]>,
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

    pub(super) fn unapplied(answer: AdminAnswer) -> Self {
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

pub(crate) type TrustDesk = Arc<dyn Fn() -> Option<Arc<KernelServices>> + Send + Sync>;

#[must_use]
pub(crate) fn no_trust() -> TrustDesk {
    Arc::new(|| None)
}

pub(crate) const COMMIT_UPGRADE_RECORD_TAG: &str = "busbar/commit-upgrade/v1";

pub(crate) const RUNNING_RELEASE: &str = env!("CARGO_PKG_VERSION");

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

fn answer(value: &json::Value) -> Result<AdminAnswer, GovernanceError> {
    json::to_vec(value)
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store)
}

pub(crate) async fn verify_effect(
    ledger: &dyn LedgerView,
    audit: Option<&dyn AuditView>,
    journal: Option<&busbar_kernel_audit::amend::NodeAmendments>,
) -> Result<AdminAnswer, GovernanceError> {
    let priced = ledger.priced().await.map_err(|why| {
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
                .await
                .into_iter()
                .map(|finding| format!("stored chain: {finding}")),
        );
    }
    answer(&json::json!({
        "checkpoints": 0,
        "since": null,
        "book_verified": false,
        "findings": findings,
        "identity_holds": identity_holds,
        "discrepancies": 0,
        "ok": findings.is_empty() && identity_holds,
    }))
}

pub(crate) async fn plane_record_write_effect(
    body: &[u8],
    at: u64,
    planes: &(dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync),
    sink: Option<&PlaneRecordSink>,
) -> Result<EffectAnswer, GovernanceError> {
    let doc: json::Value = json::parse_value(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let text = |key: &str| {
        obj.get(&key)
            .and_then(json::Value::as_str)
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
    let row = match obj.get(&"body") {
        Some(row) if !row.is_null() => row,
        _ => {
            return Ok(refused_effect(400, "invalid_request", "body is required"));
        }
    };
    let parent = match obj.get(&"parent") {
        None => None,
        Some(p) if p.is_null() => None,
        Some(p) if p.as_str().is_some_and(|p| !p.trim().is_empty()) => {
            p.as_str().map(str::to_string)
        }
        Some(_) => {
            return Ok(refused_effect(
                400,
                "invalid_request",
                "parent must be a non-empty string or null",
            ));
        }
    };
    let terminal = match obj.get(&"terminal") {
        None => false,
        Some(b) if b.is_null() => false,
        Some(b) if b.is_boolean() => b.as_bool() == Some(true),
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
        body: json::to_vec(row).map_err(|_| GovernanceError::Validation)?,
    };

    let applied = answer(&json::json!({
        "plane": plane,
        "kind": kind,
        "id": record.id,
        "parent": record.parent,
        "terminal": terminal,
        "written_at": at,
    }))?;
    match sink(&decl, &record).await {
        Ok(()) => Ok(EffectAnswer::applied(applied)),
        Err(PlaneWriteFailure::Unapplied) => Ok(EffectAnswer::unapplied(journal_unavailable(
            "the store refused this record write; nothing was published",
        ))),
        Err(PlaneWriteFailure::Unknown(pending)) => {
            tracing::error!(
                "the plane record write has an unknown outcome; its exact record and native attempt remain in custody"
            );
            Ok(EffectAnswer::unknown(
                journal_unavailable(
                    "the store did not acknowledge this record write; its outcome is unknown; do not re-submit",
                ),
                EffectReceipt::PlaneRecordWrite { record, pending },
            ))
        }
    }
}

pub(crate) async fn commit_upgrade_effect(
    body: &[u8],
    at: u64,
    principal: &str,
    journal: Option<&AmendmentJournal>,
) -> Result<EffectAnswer, GovernanceError> {
    let doc: json::Value = json::parse_value(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(version) = obj
        .get(&"version")
        .and_then(json::Value::as_str)
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
    if let Err(why) = journal.admit().await {
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
    if let Err(why) = journal.acked(node_seq).await {
        return Ok(EffectAnswer::pending(
            journal_unavailable(&format!(
                "the commit is sealed at journal position {node_seq} and not yet kept by the store: \
             {why}; do not re-submit"
            )),
            receipt,
        ));
    }
    match answer(&json::json!({
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

fn trust_row(row: &KeyRow) -> json::Value {
    json::json!({
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
    answer(&json::json!({
        "keys": rows.iter().map(trust_row).collect::<Vec<_>>(),
    }))
}

pub(crate) async fn trust_decide_effect(
    body: &[u8],
    ruling: Ruling,
    desk: &TrustDesk,
) -> Result<AdminAnswer, GovernanceError> {
    let doc: json::Value = json::parse_value(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(key) = obj
        .get(&"key")
        .and_then(json::Value::as_str)
        .filter(|k| !k.trim().is_empty())
    else {
        return Ok(refused(400, "invalid_request", "key is required"));
    };
    let expected_digest = match obj.get(&"expected_digest") {
        None => None,
        Some(digest) if digest.as_str().is_some_and(|d| !d.trim().is_empty()) => digest.as_str(),
        Some(_) => {
            return Ok(refused(
                400,
                "invalid_request",
                "expected_digest must be a non-empty string when supplied",
            ));
        }
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
    match kernel
        .trust_rule_if_seen(key, ruling, expected_digest)
        .await
    {
        Ok(row) => answer(&trust_row(&row)),
        Err(TrustRefused::NoSuchKey) => not_found(),
        Err(TrustRefused::Ambiguous) => Ok(refused(
            409,
            "conflict",
            &format!(
                "trust key `{key}` names more than one trust row; a registration name \
                 containing `/` makes it ambiguous, so rename the registration"
            ),
        )),
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
pub(crate) fn live_planes(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneLookup {
    Arc::new(move |key: &str| {
        let snapshot = app.load();
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .map(|decl| decl.declaration)
            .find(|decl| decl.key == key && snapshot.plane_configured(decl))
    })
}

#[must_use]
pub(crate) fn live_admin_door(app: Arc<busbar_kernel::state::AppHandle>) -> super::AdminDoorFn {
    Arc::new(
        move |request: &super::AdminRequest| -> super::AdminDoorFuture {
            let Ok(headers) = request.http_headers() else {
                return Box::pin(std::future::ready(
                    busbar_kernel::auth::AdminDoor::Denied.into(),
                ));
            };
            let (handle, snapshot, id, cx) = if let Some(binding) = &request.binding {
                if !Arc::ptr_eq(binding.handle(), &app)
                    || binding.check_live().is_err()
                    || binding.invocation().request_id().get() != request.unit
                    || !binding
                        .snapshot()
                        .is_ok_and(|original| Arc::ptr_eq(&original, request.snapshot()))
                {
                    return Box::pin(std::future::ready(
                        busbar_kernel::auth::AdminDoor::Denied.into(),
                    ));
                }
                let id = binding.invocation();
                let mut cx = busbar_kernel::auth::admin_call_context(id);
                if let Some(deadline) = binding.deadline() {
                    cx.deadline = cx.deadline.min(deadline);
                }
                (binding.handle().clone(), binding.app().clone(), id, cx)
            } else {
                let selected = app.load();
                if selected.native_admin.is_some() {
                    return Box::pin(std::future::ready(
                        busbar_kernel::auth::AdminDoor::Unavailable(
                            busbar_kernel::auth::VerifierUnavailable::NoVerdict,
                        )
                        .into(),
                    ));
                }
                let Some(request_id) = std::num::NonZeroU64::new(request.unit) else {
                    return Box::pin(std::future::ready(
                        busbar_kernel::auth::AdminDoor::Denied.into(),
                    ));
                };
                let id = busbar_kernel::state::InvocationId::from_request_id(request_id);
                (
                    app.clone(),
                    selected,
                    id,
                    busbar_kernel::auth::admin_call_context(id),
                )
            };
            let invocation = busbar_kernel::auth::native_admin::Invocation {
                handle,
                selected: snapshot,
                id,
                cx,
                request: Arc::clone(request.snapshot()),
            };
            Box::pin(
                async move { busbar_kernel::auth::admin_verdict_for(invocation, &headers).await },
            )
        },
    )
}

#[must_use]
pub(crate) fn live_records(
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
) -> PlaneRecordSink {
    Arc::new(move |decl, record| {
        let core = Arc::clone(&core);
        Box::pin(async move {
            use busbar_kernel::host_records_async::{AsyncHistory, HistoryError, HistoryOutcome};
            // This administrative envelope seam has always upserted seq=0 records. Its
            // objects are separate from raw plugin HostRecords; opaque parent metadata
            // never declares a parent collection or authorizes a cascade.
            let kinds = decl
                .record_kinds
                .iter()
                .map(|kind| {
                    busbar_kernel::store::plane_view::plane_owned_kind(decl.key, kind)
                        .ok_or(PlaneWriteFailure::Unapplied)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let owner = format!("busbar.admin.envelopes/{}", decl.key);
            let history = AsyncHistory::authorized_upserts(core, &owner, kinds)
                .map_err(|_| PlaneWriteFailure::Unapplied)?;
            match history
                .upsert(record.view())
                .await
                .map_err(|error| match error {
                    HistoryError::Unauthorized
                    | HistoryError::Invalid
                    | HistoryError::MissingParent => PlaneWriteFailure::Unapplied,
                    _ => PlaneWriteFailure::Unknown(None),
                })? {
                HistoryOutcome::Applied => Ok(()),
                HistoryOutcome::Pending(id)
                | HistoryOutcome::Reconcile(id)
                | HistoryOutcome::Busy(id) => Err(PlaneWriteFailure::Unknown(Some(id.0))),
                HistoryOutcome::Conflict
                | HistoryOutcome::OpIdConflict
                | HistoryOutcome::NoEffect(_) => Err(PlaneWriteFailure::Unapplied),
            }
        })
    })
}

/// THE REPLAY CACHE the two Q71(2) writes share (contract D-3): per `(actor, "<verb>:<key>")`, the
/// SHA-256 of the body the first call carried and the answer it produced. Unresolved receipts
/// have separate custody: the ordinary answer TTL cannot release an effect still owed or unknown.
#[derive(Default)]
pub(crate) struct ReplayCache {
    answers: busbar_core_admin::idempotency::IdempotencyCache<ReplayValue>,
    retained: Mutex<HashMap<(String, String), HeldReplay>>,
}

impl ReplayCache {
    #[must_use]
    pub(crate) fn new() -> Self {
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
    store: Arc<busbar_kernel::persistence::scoped::ScopedStore>,
    claim: busbar_core_admin::idempotency::durable::Claim,
    at: u64,
    settled: busbar_core_admin::idempotency::durable::Settled,
}

impl HeldSettlement {
    async fn retry(&self) {
        if let Err(why) = busbar_core_admin::idempotency::durable::settle(
            &self.store,
            &self.claim,
            self.at,
            &self.settled,
        )
        .await
        {
            tracing::error!(reason = %why, "the store did not acknowledge the retained Idempotency-Key receipt; its original claim remains held");
        }
    }
}

impl HeldReplay {
    async fn replay(&self, journal: Option<&AmendmentJournal>) -> AdminAnswer {
        if let Some(settlement) = &self.settlement {
            if let Some(EffectReceipt::PlaneRecordWrite {
                pending: Some(id), ..
            }) = &self.value.receipt
            {
                // Only this live retained entry carries the original CoreStore handle.
                // A receipt loaded after restart has no settlement and cannot restore
                // an in-memory operation from its ID. Never replan the saved record.
                if let Err(error) = settlement
                    .store
                    .retry(busbar_kernel::persistence::facade::PendingId(*id))
                    .await
                {
                    tracing::warn!(
                        ?error,
                        "the exact retained record attempt could not be reconciled"
                    );
                }
            }
            settlement.retry().await;
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
            let records = match chain {
                Some(chain) => Some(chain.read().await),
                None => None,
            };
            if let Some(Ok(Ok(records))) = records {
                if records.iter().any(|record| {
                    record.node == *node
                        && record.node_seq == *seq
                        && record.hash == *hash
                        && record.class == busbar_kernel_wal::RecordClass::Policy
                        && record.body == *body
                }) {
                    let _acknowledged = journal.acked(*seq).await;
                }
            }
        }

        self.value.answer.clone()
    }
}

pub(crate) type ReplayStore =
    Arc<dyn Fn() -> Option<Arc<busbar_kernel::persistence::scoped::ScopedStore>> + Send + Sync>;

pub(crate) fn live_replay_store(
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
) -> Result<ReplayStore, busbar_kernel::persistence::scoped::Error> {
    let store = Arc::new(busbar_core_admin::idempotency::durable::scoped_store(core)?);
    Ok(Arc::new(move || Some(Arc::clone(&store))))
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
        let receipt = json::to_vec(receipt)
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
        Some(json::parse(pull(kept, &mut cursor)?).ok()?)
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

pub(crate) async fn replayable<F, Fut>(
    cache: &ReplayCache,
    store: Option<&ReplayStore>,
    scope: ReplayScope<'_>,
    unit: &super::AdminRequest,
    body: &[u8],
    journal: Option<&AmendmentJournal>,
    effect: F,
) -> Result<AdminAnswer, GovernanceError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<EffectAnswer, GovernanceError>>,
{
    use busbar_core_admin::idempotency::Probe;

    let ReplayScope { verb, actor } = scope;
    let Some(header) = unit
        .header(IDEMPOTENCY_KEY_HEADER)
        .filter(|value| !value.is_empty())
    else {
        return effect().await.map(|outcome| outcome.answer);
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
            Ok(held.replay(journal).await)
        } else {
            other_body()
        };
    }
    match cache.answers.probe(key.clone(), unit.at()) {
        Probe::Replay(value) if value.digest == digest => Ok(value.answer),
        Probe::Replay(_) => other_body(),
        Probe::InFlight => in_flight(),
        Probe::NoKey => effect().await.map(|outcome| outcome.answer),
        Probe::Reserved(mut reservation) => {
            let store = store.and_then(|store| store());
            let claim = match &store {
                Some(store) => match durable::claim_held(store, reservation.key(), unit.at()).await
                {
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
                                    Ok(held.replay(journal).await)
                                } else {
                                    let answer = value.answer.clone();
                                    reservation.commit(value, unit.at());
                                    Ok(answer)
                                }
                            }
                            Some(_) => other_body(),
                            None => {
                                tracing::error!(
                                        "the store keeps an Idempotency-Key's first answer in a form this node cannot read"
                                    );
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
            let (answer, settled) = match effect().await {
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
                    reservation.commit(value, unit.at());
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
                            at: unit.at(),
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
                if let Err(why) = durable::settle(store, claim, unit.at(), &settled).await {
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
